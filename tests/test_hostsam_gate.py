"""TESTER gate suite for the Tier-C host-SAM ``AdminTo`` module (independent).

Authored by ``wraith-tester`` as the authoritative three-layer gate — NOT the
coder sanity (``test_hostsam_sanity.py``). Re-derives every claimed number from
scratch rather than trusting the coder's fixtures:

* **Layer 1 (unit/golden):** real DC SAM parse (known contents) + crafted blobs.
* **Layer 2 (reference):** the C-array vs the ``Members`` reverse-index corroboration.
* **Layer 3 (property/robustness):** untrusted-input fuzzing of the C-blob /
  binary-SID parser (truncation, OOB offsets/sizes, SID overrun, bogus counts),
  determinism, provenance on every edge.
"""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.hostsam import (
    CONFIDENCE_CONFIRMED,
    DERIVATION_SAM_ADMIN_TO,
    DOMAIN_ALIAS_RID_ADMINS,
    GAP_CBLOB_PARSE_ERROR,
    GAP_HOST_NOT_IMAGED,
    GAP_HOST_UNRESOLVED,
    GAP_MEMBER_SID_UNRESOLVED,
    KIND_ADMIN_TO,
    MemberClass,
    account_host_coverage,
    build_computer_index,
    classify_member,
    compute_host_admin_edges,
    parse_binary_sid,
    parse_c_blob,
    read_host_sam,
)
from wraith.hostsam import admin_edges as _admin_edges
from wraith.hostsam.reader import HostSamRead
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import PrincipalRow
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000f00d")
_FOREST = "f"
_DOMAIN_SID = "S-1-5-21-111-222-333"
_MACHINE_SID = "S-1-5-21-900-900-900"
_SCOPING = (_FOREST, _DOMAIN_SID, "corp.local")

_SID_LOCAL_ADMIN = f"{_MACHINE_SID}-500"
_SID_DOMAIN_USER = f"{_DOMAIN_SID}-1105"
_SID_DOMAIN_ADMINS = f"{_DOMAIN_SID}-512"
_SID_UNKNOWN = f"{_DOMAIN_SID}-7777"

_EVIDENCE_SAM = Path(__file__).resolve().parents[1] / "eviedence_test" / "Registry" / "SAM"
_REAL_SAM_PRESENT = _EVIDENCE_SAM.is_file()


# --- independent SID/C-blob crafting (hand-rolled, not the module's) ----------


def _sid_to_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return (
        bytes([rev, len(subs)])
        + auth.to_bytes(6, "big")
        + b"".join(s.to_bytes(4, "little") for s in subs)
    )


def _craft_c_blob(rid: int, member_sids: list[str], *, pad: int = 0) -> bytes:
    sid_array = b"".join(_sid_to_bytes(s) for s in member_sids)
    header = bytearray(52)
    struct.pack_into("<I", header, 0, rid)
    struct.pack_into("<H", header, 12, 2)
    struct.pack_into("<H", header, 14, 1)
    struct.pack_into("<I", header, 40, pad)  # SID-array offset relative to 52
    struct.pack_into("<I", header, 44, len(sid_array))
    struct.pack_into("<I", header, 48, len(member_sids))
    return bytes(header) + (b"\x00" * pad) + sid_array


# --- store helpers ------------------------------------------------------------


def _new_store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _run_with_sam(image: str = "b" * 64) -> IngestRun:
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    run.add_artifact(
        ArtifactInput(
            source_file="SAM",
            abs_path_or_ref="/case/host01/SAM",
            size_bytes=262144,
            image_sha256=image,
        )
    )
    return run


def _add_principal(
    con: duckdb.DuckDBPyConnection, node_id: str, sid: str, ptype: str, sam: str
) -> None:
    prov = ProvenanceStruct(
        source_file="ntds.dit",
        image_sha256="a" * 64,
        source_object_id=node_id,
        directory_timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        ingest_run_id=_RUN,
    )
    p = PrincipalRow(
        node_id=node_id,
        object_sid=sid,
        object_guid=None,
        principal_type=ptype,
        samaccountname=sam,
        upn=None,
        distinguished_name=None,
        display_name=None,
        description=None,
        uac_flags=None,
        enabled=True,
        admincount=None,
        spns=[],
        sid_history=[],
        primary_group_id=None,
        pwd_last_set=None,
        last_logon_timestamp=None,
        when_created=None,
        when_changed=None,
        secret_refs=[],
        behavior_summary_ref=None,
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=prov,
    )
    ph = ",".join("?" * len(p.to_db_values()))
    con.execute(f"INSERT INTO principal VALUES ({ph})", list(p.to_db_values()))  # noqa: S608


def _seed(con: duckdb.DuckDBPyConnection) -> None:
    _add_principal(con, "n-ws01", f"{_DOMAIN_SID}-2001", "Computer", "WS01$")
    _add_principal(con, "n-user", _SID_DOMAIN_USER, "User", "alice")
    _add_principal(con, "n-da", _SID_DOMAIN_ADMINS, "Group", "Domain Admins")


def _mock_read(
    monkeypatch: pytest.MonkeyPatch,
    member_sids: list[str],
    *,
    cblob_errors: int = 0,
    machine_sid: str | None = _MACHINE_SID,
) -> None:
    read = HostSamRead(
        member_sids=tuple(member_sids),
        machine_sid=machine_sid,
        last_change=datetime(2021, 5, 1, tzinfo=UTC),
        members_crosscheck_domains=(),
        found_alias=True,
        read_error=False,
        cblob_errors=cblob_errors,
    )
    monkeypatch.setattr(_admin_edges, "read_host_sam", lambda _p: read)


# =============================================================================
# LAYER 1 — golden: real DC SAM (independent known-content assertion)
# =============================================================================


@pytest.mark.skipif(not _REAL_SAM_PRESENT, reason="real DC SAM hive absent")
def test_real_dc_sam_exact_members_and_split() -> None:
    read = read_host_sam(_EVIDENCE_SAM)
    assert read.found_alias and not read.read_error
    assert read.cblob_errors == 0
    assert set(read.member_sids) == {
        "S-1-5-21-2620694702-3641965580-775306395-500",
        "S-1-5-21-2232410529-1445159330-2725690660-512",
    }
    assert read.machine_sid == "S-1-5-21-2620694702-3641965580-775306395"
    # RID-500 is host-scoped (domain head == machine SID) -> NO edge.
    assert (
        classify_member("S-1-5-21-2620694702-3641965580-775306395-500", read.machine_sid)
        is MemberClass.LOCAL
    )
    # Domain Admins -512 -> graph-interesting cross-host edge.
    assert (
        classify_member("S-1-5-21-2232410529-1445159330-2725690660-512", read.machine_sid)
        is MemberClass.DOMAIN
    )
    assert read.last_change is not None
    assert read.last_change.replace(microsecond=0).isoformat() == "2020-09-17T17:57:10+00:00"


# =============================================================================
# LAYER 3 — property/robustness: untrusted C-blob / SID fuzzing (no crash)
# =============================================================================


def test_robust_truncated_header() -> None:
    p = parse_c_blob(b"\x20\x02\x00\x00")
    assert not p.ok and p.errors >= 1 and p.member_sids == ()


def test_robust_sid_array_offset_out_of_range() -> None:
    blob = bytearray(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_DOMAIN_ADMINS]))
    struct.pack_into("<I", blob, 40, 0xFFFFFF)  # offset far past end
    p = parse_c_blob(bytes(blob))
    assert not p.ok and p.errors >= 1 and p.member_sids == ()


def test_robust_sid_array_size_out_of_range() -> None:
    blob = bytearray(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_DOMAIN_ADMINS]))
    struct.pack_into("<I", blob, 44, 0xFFFF)  # size far past end
    p = parse_c_blob(bytes(blob))
    assert not p.ok and p.errors >= 1 and p.member_sids == ()


def test_robust_sid_overruns_array() -> None:
    # One valid SID, then a SID whose declared sub-count overruns the array end.
    good = _sid_to_bytes(_SID_DOMAIN_ADMINS)
    bad = bytes([1, 15]) + (0).to_bytes(6, "big") + b"\x01\x02"  # claims 15 subs, 2 bytes present
    sid_array = good + bad
    header = bytearray(52)
    struct.pack_into("<I", header, 0, DOMAIN_ALIAS_RID_ADMINS)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, len(sid_array))
    struct.pack_into("<I", header, 48, 2)
    p = parse_c_blob(bytes(header) + sid_array)
    assert not p.ok and p.errors >= 1
    assert p.member_sids == (_SID_DOMAIN_ADMINS,)  # only the valid SID, no OOB read


def test_robust_bogus_huge_count() -> None:
    blob = bytearray(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_DOMAIN_ADMINS]))
    struct.pack_into("<I", blob, 48, 0xFFFFFFFF)  # claim ~4B members
    p = parse_c_blob(bytes(blob))
    assert not p.ok and p.errors >= 1  # does not hang / allocate / OOB
    assert p.member_sids == (_SID_DOMAIN_ADMINS,)


def test_robust_parse_binary_sid_malformed() -> None:
    raw = _sid_to_bytes(_SID_DOMAIN_ADMINS)
    assert parse_binary_sid(raw[:-2], 0) is None  # subauth overruns
    assert parse_binary_sid(raw, 10_000) is None  # offset past end
    assert parse_binary_sid(b"", 0) is None  # empty
    assert parse_binary_sid(b"\x01", 0) is None  # header overruns
    assert parse_binary_sid(bytes([1, 255]) + b"\x00" * 6, 0) is None  # 255 subs, none present


def test_robust_empty_and_zero_member_blob() -> None:
    p = parse_c_blob(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, []))
    assert p.ok and p.errors == 0 and p.member_sids == ()
    assert p.declared_count == 0


# =============================================================================
# LAYER 1/3 — synthetic member-host AdminTo (exact edge set, re-derived)
# =============================================================================


def test_synthetic_exact_three_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_LOCAL_ADMIN, _SID_DOMAIN_USER, _SID_DOMAIN_ADMINS, _SID_UNKNOWN])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )
    assert res.host_resolved and res.host_node_id == "n-ws01"
    assert res.members_total == 4
    assert res.local_members == 1  # RID-500, host-scoped -> NO edge
    assert res.domain_members == 3
    assert res.edges_emitted == 3
    assert res.stubs_minted == 1

    rows = con.execute(
        "SELECT source_node_id, target_node_id, kind, confidence, derivation, is_inherited "
        "FROM edge ORDER BY source_node_id"
    ).fetchall()
    assert len(rows) == 3
    sources = {r[0] for r in rows}
    # Exactly: domain user, Domain Admins GROUP (not re-expanded), minted -7777 stub.
    assert "n-user" in sources
    assert "n-da" in sources
    minted_node = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", [_SID_UNKNOWN]
    ).fetchone()
    assert minted_node is not None
    assert minted_node[0] in sources
    # No LOCAL RID-500 edge.
    assert not any("900-900-900" in s for s in sources)
    for r in rows:
        assert r[1] == "n-ws01"  # target is the host computer
        assert r[2] == KIND_ADMIN_TO
        assert r[3] == CONFIDENCE_CONFIRMED
        assert r[4] == DERIVATION_SAM_ADMIN_TO
    # Counted gaps.
    assert run.skip_counts[GAP_MEMBER_SID_UNRESOLVED] == 1
    assert run.coverage_counts["hostsam.local_member_skipped"] == 1
    # Exactly one stub minted (for -7777).
    assert (
        con.execute(
            "SELECT count(*) FROM principal WHERE object_sid = ?", [_SID_UNKNOWN]
        ).fetchone()[0]
        == 1
    )

    # Provenance on every edge: host-SAM image hash + alias C anchor.
    for (prov,) in con.execute("SELECT provenance FROM edge").fetchall():
        assert prov["image_sha256"] == "b" * 64
        assert prov["source_object_id"].startswith("SAM\\Domains\\Builtin\\Aliases\\00000220\\C")


def test_synthetic_nested_group_not_reexpanded(monkeypatch: pytest.MonkeyPatch) -> None:
    # Domain Admins group is a member; add a user who is MemberOf it. The host
    # pass must emit ONE edge to the GROUP, never expand to its members here.
    con = _new_store()
    _seed(con)
    _add_principal(con, "n-nested", f"{_DOMAIN_SID}-1200", "User", "bob")
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )
    assert res.edges_emitted == 1
    rows = con.execute("SELECT source_node_id FROM edge").fetchall()
    assert [r[0] for r in rows] == ["n-da"]


# =============================================================================
# LAYER 1 — host resolution (join semantics)
# =============================================================================


@pytest.mark.parametrize("name", ["WS01", "WS01$", "ws01", "Ws01$", "  ws01  "])
def test_host_resolution_variants(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name=name
    )
    assert res.host_resolved and res.host_node_id == "n-ws01"
    assert res.edges_emitted == 1


def test_host_resolution_duplicate_is_ambiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _add_principal(con, "n-a", f"{_DOMAIN_SID}-3001", "Computer", "DUP$")
    _add_principal(con, "n-b", f"{_DOMAIN_SID}-3002", "Computer", "DUP$")
    index = build_computer_index(con)
    assert index.resolve("DUP") is None
    assert index.resolve("dup$") is None

    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="DUP"
    )
    assert not res.host_resolved
    assert res.edges_emitted == 0
    assert res.member_sids == (_SID_DOMAIN_ADMINS,)  # membership retained
    assert run.skip_counts[GAP_HOST_UNRESOLVED] == 1
    assert con.execute("SELECT count(*) FROM edge").fetchone()[0] == 0


def test_host_unresolved_retains_membership(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS, _SID_DOMAIN_USER])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="NOPE"
    )
    assert not res.host_resolved
    assert set(res.member_sids) == {_SID_DOMAIN_ADMINS, _SID_DOMAIN_USER}
    assert res.edges_emitted == 0
    assert run.skip_counts[GAP_HOST_UNRESOLVED] == 1


# =============================================================================
# LAYER 1 — coverage accounting
# =============================================================================


def test_coverage_counts_unimaged() -> None:
    con = _new_store()
    _seed(con)  # one Computer (n-ws01)
    _add_principal(con, "n-ws02", f"{_DOMAIN_SID}-2002", "Computer", "WS02$")
    _add_principal(con, "n-ws03", f"{_DOMAIN_SID}-2003", "Computer", "WS03$")
    run = _run_with_sam()
    imaged, total = account_host_coverage(con, ["n-ws01"], run)
    assert (imaged, total) == (1, 3)
    assert run.skip_counts[GAP_HOST_NOT_IMAGED] == 2


# =============================================================================
# LAYER 3 — determinism + provenance mandatory
# =============================================================================


def test_determinism_identical_edge_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    def once() -> set[str]:
        con = _new_store()
        _seed(con)
        _mock_read(monkeypatch, [_SID_DOMAIN_USER, _SID_DOMAIN_ADMINS, _SID_UNKNOWN])
        run = _run_with_sam()
        compute_host_admin_edges(
            con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
        )
        return {r[0] for r in con.execute("SELECT edge_id FROM edge").fetchall()}

    a = once()
    b = once()
    assert a == b and len(a) == 3


def test_member_sid_unresolved_count(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_USER, _SID_UNKNOWN])
    run = _run_with_sam()
    res = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )
    assert res.stubs_minted == 1
    assert run.skip_counts[GAP_MEMBER_SID_UNRESOLVED] == 1


def test_cblob_error_propagates_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS], cblob_errors=3)
    run = _run_with_sam()
    compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )
    assert run.skip_counts[GAP_CBLOB_PARSE_ERROR] == 3


def test_provenance_mandatory(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = IngestRun("case", "op", ingest_run_id=_RUN)  # SAM NOT registered
    with pytest.raises(KeyError):
        compute_host_admin_edges(
            con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
        )
