"""Coder-side sanity for the Tier-C host-SAM ``AdminTo`` module — not the gate.

Two layers:

* **Real DC SAM parser validation** (``test_real_dc_sam_*``): drives the actual
  Impacket-``winregistry`` reader against the committed DC hives at
  ``eviedence_test/Registry/{SAM,SYSTEM}``. A DC's local SAM is sparse (Builtin
  domain-local groups live in the directory), so few members are expected — the
  point is that the reader opens a REAL on-disk ``C`` blob and parses it cleanly
  (resolves the doc-09 "verify against a real hive" prerequisite).
* **Synthetic member-host AdminTo** (``test_synthetic_*``): crafts an alias ``C``
  blob (local RID-500 + a domain user + Domain Admins) and drives the full
  orchestrator against an in-memory canonical store, asserting the member->computer
  edges, the local/domain split, nested-group-to-group semantics, mint-on-miss,
  the unresolved-host gap, and determinism.

The authoritative three-layer gate is the tester's; these are coder sanity.
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
    GAP_MACHINE_SID_UNRESOLVED,
    GAP_MEMBER_SID_UNRESOLVED,
    GAP_MEMBER_UNCLASSIFIABLE,
    KIND_ADMIN_TO,
    MemberClass,
    account_host_coverage,
    build_computer_index,
    classify_member,
    compute_host_admin_edges,
    parse_binary_sid,
    parse_c_blob,
    read_computer_name,
    read_host_sam,
)
from wraith.hostsam import admin_edges as _admin_edges
from wraith.hostsam.reader import HostSamRead
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import PrincipalRow

# --- synthetic fixture constants ---------------------------------------------
_RUN = uuid.UUID("00000000-0000-0000-0000-0000005a4d00")
_FOREST = "f"
_DOMAIN_SID = "S-1-5-21-111-222-333"
_MACHINE_SID = "S-1-5-21-900-900-900"  # the host's own local SAM domain
_SCOPING = (_FOREST, _DOMAIN_SID, "corp.local")

_SID_LOCAL_ADMIN = f"{_MACHINE_SID}-500"  # LOCAL built-in admin (host-scoped)
_SID_DOMAIN_USER = f"{_DOMAIN_SID}-1105"  # a domain user, known node
_SID_DOMAIN_ADMINS = f"{_DOMAIN_SID}-512"  # Domain Admins group, known node
_SID_UNKNOWN = f"{_DOMAIN_SID}-7777"  # a domain SID with no node -> mint-on-miss

_EVIDENCE_SAM = Path(__file__).resolve().parents[1] / "eviedence_test" / "Registry" / "SAM"
_EVIDENCE_SYSTEM = Path(__file__).resolve().parents[1] / "eviedence_test" / "Registry" / "SYSTEM"


# --- C-blob crafting (mirrors the on-disk libyal layout) ---------------------


def _sid_to_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    return out + b"".join(s.to_bytes(4, "little") for s in subs)


def _craft_c_blob(rid: int, member_sids: list[str]) -> bytes:
    """Build an alias ``C`` blob with the SID array placed immediately after header."""
    sid_array = b"".join(_sid_to_bytes(s) for s in member_sids)
    header = bytearray(52)
    struct.pack_into("<I", header, 0, rid)
    struct.pack_into("<H", header, 12, 2)  # major version
    struct.pack_into("<H", header, 14, 1)  # minor version
    struct.pack_into("<I", header, 40, 0)  # SID-array offset (relative to 52)
    struct.pack_into("<I", header, 44, len(sid_array))  # SID-array size
    struct.pack_into("<I", header, 48, len(member_sids))  # member count
    return bytes(header) + sid_array


# --- store helpers -----------------------------------------------------------


def _new_store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _run_with_sam() -> IngestRun:
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    run.add_artifact(
        ArtifactInput(
            source_file="SAM",
            abs_path_or_ref="/case/host01/SAM",
            size_bytes=262144,
            image_sha256="b" * 64,
        )
    )
    return run


def _add_principal(
    con: duckdb.DuckDBPyConnection, node_id: str, sid: str, ptype: str, sam: str
) -> None:
    from wraith.provenance.models import ProvenanceStruct

    prov = ProvenanceStruct(
        source_file="ntds.dit",
        image_sha256="a" * 64,
        source_object_id=node_id,
        directory_timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        ingest_run_id=_RUN,
    )
    principal = PrincipalRow(
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
    placeholders = ",".join("?" * len(principal.to_db_values()))
    con.execute(
        f"INSERT INTO principal VALUES ({placeholders})",  # noqa: S608 - fixed literal
        list(principal.to_db_values()),
    )


def _seed_graph(con: duckdb.DuckDBPyConnection) -> None:
    """A host computer + a domain user + Domain Admins group (known nodes)."""
    _add_principal(con, "n-ws01", f"{_DOMAIN_SID}-2001", "Computer", "WS01$")
    _add_principal(con, "n-user", _SID_DOMAIN_USER, "User", "alice")
    _add_principal(con, "n-da", _SID_DOMAIN_ADMINS, "Group", "Domain Admins")


# =============================================================================
# Pure parser unit tests (crafted + bounds-checks)
# =============================================================================


def test_parse_binary_sid_roundtrip() -> None:
    raw = _sid_to_bytes(_SID_DOMAIN_ADMINS)
    parsed = parse_binary_sid(raw, 0)
    assert parsed is not None
    sid, consumed = parsed
    assert sid == _SID_DOMAIN_ADMINS
    assert consumed == len(raw)


def test_parse_binary_sid_truncated_returns_none() -> None:
    raw = _sid_to_bytes(_SID_DOMAIN_ADMINS)
    assert parse_binary_sid(raw[:-2], 0) is None  # sub-authority overruns buffer
    assert parse_binary_sid(raw, 999) is None  # offset past end
    assert parse_binary_sid(b"\x01", 0) is None  # header overruns


def test_parse_c_blob_roundtrip() -> None:
    blob = _craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_LOCAL_ADMIN, _SID_DOMAIN_ADMINS])
    parsed = parse_c_blob(blob)
    assert parsed.ok
    assert parsed.errors == 0
    assert parsed.rid == DOMAIN_ALIAS_RID_ADMINS
    assert parsed.declared_count == 2
    assert parsed.member_sids == (_SID_LOCAL_ADMIN, _SID_DOMAIN_ADMINS)


def test_parse_c_blob_truncated_header_counts_gap() -> None:
    parsed = parse_c_blob(b"\x20\x02\x00\x00")  # < 52-byte header
    assert not parsed.ok
    assert parsed.errors >= 1
    assert parsed.member_sids == ()


def test_parse_c_blob_out_of_range_array_counts_gap() -> None:
    blob = bytearray(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_DOMAIN_ADMINS]))
    struct.pack_into("<I", blob, 44, 0xFFFF)  # SID-array size far past buffer end
    parsed = parse_c_blob(bytes(blob))
    assert not parsed.ok
    assert parsed.errors >= 1
    assert parsed.member_sids == ()  # nothing read out of bounds


def test_parse_c_blob_count_mismatch_counts_gap() -> None:
    blob = bytearray(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, [_SID_DOMAIN_ADMINS]))
    struct.pack_into("<I", blob, 48, 5)  # claim 5 members, only 1 present
    parsed = parse_c_blob(bytes(blob))
    assert not parsed.ok
    assert parsed.errors >= 1
    assert parsed.member_sids == (_SID_DOMAIN_ADMINS,)  # the one real SID kept


# =============================================================================
# Classification unit tests
# =============================================================================


def test_classify_member_local_vs_domain_vs_wellknown() -> None:
    assert classify_member(_SID_LOCAL_ADMIN, _MACHINE_SID) is MemberClass.LOCAL
    assert classify_member(_SID_DOMAIN_ADMINS, _MACHINE_SID) is MemberClass.DOMAIN
    assert classify_member("S-1-5-9", _MACHINE_SID) is MemberClass.WELLKNOWN


def test_classify_member_machine_sid_none_uses_positive_signals() -> None:
    # machine_sid is None: a domain-specific SID is NOT defaulted to DOMAIN.
    # (a) the member's head equals the known domain SID -> DOMAIN.
    assert (
        classify_member(_SID_DOMAIN_USER, None, known_domain_sid=_DOMAIN_SID) is MemberClass.DOMAIN
    )
    # (b) a well-known DOMAIN group RID (512) confirms DOMAIN even on a foreign head.
    assert (
        classify_member("S-1-5-21-7-7-7-512", None, known_domain_sid=_DOMAIN_SID)
        is MemberClass.DOMAIN
    )
    # (c) the host's own likely-local RID-500 (foreign head, no machine_sid to
    #     rule out, not a well-known DOMAIN RID) -> UNCLASSIFIABLE, never DOMAIN.
    assert (
        classify_member(_SID_LOCAL_ADMIN, None, known_domain_sid=_DOMAIN_SID)
        is MemberClass.UNCLASSIFIABLE
    )
    # (d) a non-domain-specific well-known SID stays WELLKNOWN (domain-independent).
    assert classify_member("S-1-5-32-544", None, known_domain_sid=_DOMAIN_SID) is (
        MemberClass.WELLKNOWN
    )


# =============================================================================
# Synthetic orchestrator tests (membership mocked at the reader seam)
# =============================================================================


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


def test_synthetic_admin_to_edges_and_split(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_LOCAL_ADMIN, _SID_DOMAIN_USER, _SID_DOMAIN_ADMINS, _SID_UNKNOWN])
    run = _run_with_sam()

    result = compute_host_admin_edges(
        con,
        sam_hive_path=_EVIDENCE_SAM,
        run=run,
        scoping=_SCOPING,
        computer_name="WS01",
    )

    assert result.host_resolved
    assert result.host_node_id == "n-ws01"
    assert result.members_total == 4
    assert result.local_members == 1  # RID-500 local admin, host-scoped, NO edge
    assert result.domain_members == 3  # user + Domain Admins + the unknown SID
    assert result.edges_emitted == 3
    assert result.stubs_minted == 1  # the unknown domain SID

    rows = con.execute(
        "SELECT source_node_id, target_node_id, kind, confidence, derivation "
        "FROM edge WHERE kind = ? ORDER BY source_node_id",
        [KIND_ADMIN_TO],
    ).fetchall()
    sources = {r[0] for r in rows}
    assert "n-user" in sources  # domain user -> AdminTo
    assert "n-da" in sources  # Domain Admins GROUP -> AdminTo (nested, not expanded)
    assert all(r[1] == "n-ws01" for r in rows)  # all target the host computer
    assert all(r[2] == KIND_ADMIN_TO for r in rows)
    assert all(r[3] == CONFIDENCE_CONFIRMED for r in rows)
    assert all(r[4] == DERIVATION_SAM_ADMIN_TO for r in rows)

    # The LOCAL RID-500 admin produced NO cross-host edge.
    assert not any("900-900-900" in r[0] for r in rows)

    # Mint-on-miss stub for the unknown SID was materialized + counted.
    assert run.skip_counts[GAP_MEMBER_SID_UNRESOLVED] == 1
    minted = con.execute(
        "SELECT count(*) FROM principal WHERE object_sid = ?", [_SID_UNKNOWN]
    ).fetchone()
    assert minted is not None and minted[0] == 1

    # Provenance on every edge (own-artifact image hash + alias C anchor).
    prov_rows = con.execute(
        "SELECT provenance FROM edge WHERE kind = ?", [KIND_ADMIN_TO]
    ).fetchall()
    for (prov,) in prov_rows:
        assert prov["image_sha256"] == "b" * 64
        assert "00000220" in prov["source_object_id"]


def test_synthetic_host_unresolved_no_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = _run_with_sam()

    result = compute_host_admin_edges(
        con,
        sam_hive_path=_EVIDENCE_SAM,
        run=run,
        scoping=_SCOPING,
        computer_name="NOSUCHHOST",
    )

    assert not result.host_resolved
    assert result.member_sids == (_SID_DOMAIN_ADMINS,)  # membership retained
    assert result.edges_emitted == 0
    assert run.skip_counts[GAP_HOST_UNRESOLVED] == 1
    assert con.execute("SELECT count(*) FROM edge").fetchone()[0] == 0  # type: ignore[index]


def test_synthetic_cblob_error_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS], cblob_errors=2)
    run = _run_with_sam()

    compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )
    assert run.skip_counts[GAP_CBLOB_PARSE_ERROR] == 2


def test_machine_sid_none_known_domain_head_still_emits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # (i) machine_sid unresolved, but the member's head IS the known domain SID
    # -> still emitted + resolved as today; machine_sid_unresolved counted.
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_USER], machine_sid=None)
    run = _run_with_sam()

    result = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )

    assert not result.machine_sid_resolved
    assert run.skip_counts[GAP_MACHINE_SID_UNRESOLVED] == 1
    assert result.domain_members == 1
    assert result.edges_emitted == 1
    rows = con.execute("SELECT source_node_id FROM edge WHERE kind = ?", [KIND_ADMIN_TO]).fetchall()
    assert [r[0] for r in rows] == ["n-user"]


def test_machine_sid_none_foreign_head_is_unclassifiable_no_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # (ii) machine_sid unresolved + a foreign/likely-local S-1-5-21 head that is
    # neither the known domain nor a well-known DOMAIN RID -> NO edge, NO stub;
    # member_unclassifiable AND machine_sid_unresolved both counted. This is the
    # false-DOMAIN-leak the fix prevents (the host's own local accounts).
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_LOCAL_ADMIN], machine_sid=None)
    run = _run_with_sam()

    result = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )

    assert not result.machine_sid_resolved
    assert result.unclassifiable_members == 1
    assert result.domain_members == 0
    assert result.edges_emitted == 0
    assert run.skip_counts[GAP_MACHINE_SID_UNRESOLVED] == 1
    assert run.skip_counts[GAP_MEMBER_UNCLASSIFIABLE] == 1
    # No edge, no minted stub leaked for the unclassifiable local account.
    assert con.execute("SELECT count(*) FROM edge").fetchone()[0] == 0  # type: ignore[index]
    minted = con.execute(
        "SELECT count(*) FROM principal WHERE object_sid = ?", [_SID_LOCAL_ADMIN]
    ).fetchone()
    assert minted is not None and minted[0] == 0
    # Raw membership retained for operator mapping.
    assert result.member_sids == (_SID_LOCAL_ADMIN,)


def test_machine_sid_known_rid500_still_local_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # (iii) machine_sid KNOWN -> behavior unchanged: the host's RID-500 (head ==
    # machine_sid) is LOCAL (no edge); the domain member emits; no new gaps.
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_LOCAL_ADMIN, _SID_DOMAIN_USER])  # machine_sid known
    run = _run_with_sam()

    result = compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )

    assert result.machine_sid_resolved
    assert result.local_members == 1
    assert result.domain_members == 1
    assert result.unclassifiable_members == 0
    assert result.edges_emitted == 1
    assert GAP_MACHINE_SID_UNRESOLVED not in run.skip_counts
    assert GAP_MEMBER_UNCLASSIFIABLE not in run.skip_counts
    rows = con.execute("SELECT source_node_id FROM edge").fetchall()
    assert [r[0] for r in rows] == ["n-user"]  # RID-500 local -> no edge


def test_synthetic_determinism(monkeypatch: pytest.MonkeyPatch) -> None:
    def _edges_once() -> list[tuple[str, str, str]]:
        con = _new_store()
        _seed_graph(con)
        _mock_read(monkeypatch, [_SID_DOMAIN_USER, _SID_DOMAIN_ADMINS, _SID_UNKNOWN])
        run = _run_with_sam()
        compute_host_admin_edges(
            con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
        )
        return con.execute(
            "SELECT edge_id, source_node_id, target_node_id FROM edge ORDER BY edge_id"
        ).fetchall()

    assert _edges_once() == _edges_once()


def test_account_host_coverage_counts_unimaged() -> None:
    con = _new_store()
    _seed_graph(con)  # exactly one Computer node (n-ws01)
    _add_principal(con, "n-ws02", f"{_DOMAIN_SID}-2002", "Computer", "WS02$")
    run = _run_with_sam()

    imaged, total = account_host_coverage(con, ["n-ws01"], run)
    assert (imaged, total) == (1, 2)
    assert run.skip_counts[GAP_HOST_NOT_IMAGED] == 1


def test_computer_index_ambiguous_not_resolved() -> None:
    con = _new_store()
    _add_principal(con, "n-a", f"{_DOMAIN_SID}-3001", "Computer", "DUP$")
    _add_principal(con, "n-b", f"{_DOMAIN_SID}-3002", "Computer", "DUP$")
    index = build_computer_index(con)
    assert index.resolve("DUP") is None  # duplicate hostname -> no guessed edge


def test_compute_requires_registered_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed_graph(con)
    _mock_read(monkeypatch, [_SID_DOMAIN_ADMINS])
    run = IngestRun("case", "op", ingest_run_id=_RUN)  # SAM NOT registered
    with pytest.raises(KeyError):
        compute_host_admin_edges(
            con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
        )


# =============================================================================
# Real DC SAM parser validation (resolves the doc-09 prerequisite)
# =============================================================================

_REAL_SAM_PRESENT = _EVIDENCE_SAM.is_file()
_REAL_SYSTEM_PRESENT = _EVIDENCE_SYSTEM.is_file()


@pytest.mark.skipif(not _REAL_SAM_PRESENT, reason="real DC SAM hive not present")
def test_real_dc_sam_parses_cleanly() -> None:
    read = read_host_sam(_EVIDENCE_SAM)
    assert read.found_alias
    assert not read.read_error
    assert read.cblob_errors == 0
    # The real DC SAM's Administrators alias has exactly two members.
    assert len(read.member_sids) == 2
    assert read.machine_sid == "S-1-5-21-2620694702-3641965580-775306395"
    assert "S-1-5-21-2620694702-3641965580-775306395-500" in read.member_sids
    assert "S-1-5-21-2232410529-1445159330-2725690660-512" in read.member_sids
    # Members reverse-index corroborates both member domains.
    assert set(read.members_crosscheck_domains) == {
        "S-1-5-21-2620694702-3641965580-775306395",
        "S-1-5-21-2232410529-1445159330-2725690660",
    }


@pytest.mark.skipif(not _REAL_SAM_PRESENT, reason="real DC SAM hive not present")
def test_real_dc_sam_local_vs_domain_split() -> None:
    read = read_host_sam(_EVIDENCE_SAM)
    classes = {sid: classify_member(sid, read.machine_sid) for sid in read.member_sids}
    assert classes["S-1-5-21-2620694702-3641965580-775306395-500"] is MemberClass.LOCAL
    assert classes["S-1-5-21-2232410529-1445159330-2725690660-512"] is MemberClass.DOMAIN


@pytest.mark.skipif(not _REAL_SYSTEM_PRESENT, reason="real DC SYSTEM hive not present")
def test_real_dc_system_computer_name() -> None:
    name, errors = read_computer_name(_EVIDENCE_SYSTEM)
    assert errors == 0
    assert name == "CITADEL-DC01"
