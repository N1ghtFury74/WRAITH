"""TESTER gate suite for the host-SAM ALIAS extension (CanRDP/ExecuteDCOM/CanPSRemote).

Authored by ``wraith-tester`` as the authoritative three-layer gate for the
extension that adds the three additional built-in local-group lanes alongside the
gated ``AdminTo`` lane (Gate 09). Independent of the coder sanity suite: every
claimed number is re-derived here.

Layers:

* **Layer 1 (unit/golden):** the four ``(8-hex-RID, kind)`` lanes — correct kind +
  derivation strings, member->host edge direction, per-lane provenance subkey, and
  that ``parse_c_blob`` decodes all three new aliases byte-identically to
  Administrators (only the RID header field differs).
* **Layer 2 (reference/parity):** the four kinds round-trip through the UNCHANGED
  BloodHound export to the four computer-node local-group fields
  (LocalAdmins/RemoteDesktopUsers/DcomUsers/PSRemoteUsers) — no export regression.
* **Layer 3 (property/robustness):** per-alias gap taxonomy (absent vs
  present-empty vs malformed-C-blob — three DISTINCT counted tokens), local-only
  skip, reflexive self-skip, mint-on-miss, determinism (incl. reversed member
  order), mixed local+domain membership.
* **Layer 4 (regression):** the real DC SAM reads the three extra aliases without
  error, and the AdminTo lane / its ORIGINAL (un-laned) gap tokens are untouched.

UNTESTED-ON-REAL: there is no real member-host SAM with non-empty RDP/DCOM/PSRemote
aliases in the evidence set (research 27 §5: GOAD/BadBlood hosts commonly ship them
empty). The three new lanes are synthetic-validated end-to-end; the real DC SAM
confirms only the ABSENT path for these aliases.
"""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.export.bloodhound import build_export
from wraith.hostsam import (
    ALIAS_GAP_TOKENS,
    CONFIDENCE_CONFIRMED,
    DERIVATION_SAM_CAN_PSREMOTE,
    DERIVATION_SAM_CAN_RDP,
    DERIVATION_SAM_EXECUTE_DCOM,
    DOMAIN_ALIAS_RID_ADMINS,
    DOMAIN_ALIAS_RID_DCOM_USERS,
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
    DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    KIND_CAN_PSREMOTE,
    KIND_CAN_RDP,
    KIND_EXECUTE_DCOM,
    compute_host_admin_edges,
    parse_c_blob,
    read_host_sam,
)
from wraith.hostsam import admin_edges as _admin_edges
from wraith.hostsam.reader import AliasRead, HostSamRead
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import PrincipalRow
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000abba")
_FOREST = "f"
_DOMAIN_SID = "S-1-5-21-111-222-333"
_MACHINE_SID = "S-1-5-21-900-900-900"
_SCOPING = (_FOREST, _DOMAIN_SID, "corp.local")

_SID_LOCAL_ADMIN = f"{_MACHINE_SID}-500"
_SID_DOMAIN_USER = f"{_DOMAIN_SID}-1105"
_SID_DOMAIN_ADMINS = f"{_DOMAIN_SID}-512"
_SID_RDP = f"{_DOMAIN_SID}-1201"
_SID_DCOM = f"{_DOMAIN_SID}-1202"
_SID_PSR = f"{_DOMAIN_SID}-1203"
_SID_UNKNOWN = f"{_DOMAIN_SID}-7777"
_SID_HOST = f"{_DOMAIN_SID}-2001"  # the host computer WS01$'s own SID

_SUBKEY_RDP = "0000022B"
_SUBKEY_DCOM = "00000232"
_SUBKEY_PSR = "00000244"

_EVIDENCE_SAM = Path(__file__).resolve().parents[1] / "eviedence_test" / "Registry" / "SAM"
_REAL_SAM_PRESENT = _EVIDENCE_SAM.is_file()

_LAST_CHANGE = datetime(2021, 5, 1, tzinfo=UTC)


# --- hand-rolled C-blob crafting (independent of the module) ------------------


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


def _craft_c_blob(rid: int, member_sids: list[str]) -> bytes:
    sid_array = b"".join(_sid_to_bytes(s) for s in member_sids)
    header = bytearray(52)
    struct.pack_into("<I", header, 0, rid)
    struct.pack_into("<H", header, 12, 2)
    struct.pack_into("<H", header, 14, 1)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, len(sid_array))
    struct.pack_into("<I", header, 48, len(member_sids))
    return bytes(header) + sid_array


# --- store + run helpers ------------------------------------------------------


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
    _add_principal(con, "n-ws01", _SID_HOST, "Computer", "WS01$")
    _add_principal(con, "n-user", _SID_DOMAIN_USER, "User", "alice")
    _add_principal(con, "n-da", _SID_DOMAIN_ADMINS, "Group", "Domain Admins")
    _add_principal(con, "n-rdp", _SID_RDP, "User", "rdpguy")
    _add_principal(con, "n-dcom", _SID_DCOM, "User", "dcomguy")
    _add_principal(con, "n-psr", _SID_PSR, "User", "psrguy")


def _alias(
    rid: int,
    subkey: str,
    members: list[str],
    *,
    found: bool = True,
    cblob_errors: int = 0,
) -> AliasRead:
    return AliasRead(
        rid=rid,
        subkey=subkey,
        member_sids=tuple(members),
        last_change=_LAST_CHANGE,
        found=found,
        cblob_errors=cblob_errors,
    )


def _mock_read(
    monkeypatch: pytest.MonkeyPatch,
    admin_members: list[str],
    aliases: list[AliasRead],
    *,
    machine_sid: str | None = _MACHINE_SID,
    cblob_errors: int = 0,
) -> None:
    read = HostSamRead(
        member_sids=tuple(admin_members),
        machine_sid=machine_sid,
        last_change=_LAST_CHANGE,
        members_crosscheck_domains=(),
        found_alias=True,
        read_error=False,
        cblob_errors=cblob_errors,
        aliases=tuple(aliases),
    )
    monkeypatch.setattr(_admin_edges, "read_host_sam", lambda _p: read)


def _compute(con: duckdb.DuckDBPyConnection, run: IngestRun) -> _admin_edges.HostSamResult:
    return compute_host_admin_edges(
        con, sam_hive_path=_EVIDENCE_SAM, run=run, scoping=_SCOPING, computer_name="WS01"
    )


def _count(con: duckdb.DuckDBPyConnection, sql: str, params: list[object]) -> int:
    """Return a scalar ``count(*)`` (asserts the row is present — typed helper)."""
    row = con.execute(sql, params).fetchone()
    assert row is not None
    return int(row[0])


# =============================================================================
# LAYER 1 — unit / golden: the four lanes, kinds, derivations, direction, prov
# =============================================================================


def test_alias_gap_tokens_exact_keys() -> None:
    # Lock the exact per-lane token convention the coder exported, so downstream
    # coverage reporting can rely on these literals (no re-derivation).
    assert set(ALIAS_GAP_TOKENS) == {KIND_CAN_RDP, KIND_EXECUTE_DCOM, KIND_CAN_PSREMOTE}
    rdp = ALIAS_GAP_TOKENS[KIND_CAN_RDP]
    assert rdp.alias_absent == "hostsam.canrdp.alias_absent"
    assert rdp.alias_present == "hostsam.canrdp.alias_present"
    assert rdp.alias_present_empty == "hostsam.canrdp.alias_present_empty"
    assert rdp.cblob_parse_error == "hostsam.canrdp.cblob_parse_error"
    assert rdp.local_member_skipped == "hostsam.canrdp.local_member_skipped"
    assert rdp.self_skipped == "hostsam.canrdp.self_skipped"
    assert rdp.member_sid_unresolved == "hostsam.canrdp.member_sid_unresolved"
    assert rdp.member_unclassifiable == "hostsam.canrdp.member_unclassifiable"
    assert ALIAS_GAP_TOKENS[KIND_EXECUTE_DCOM].alias_absent == "hostsam.executedcom.alias_absent"
    assert ALIAS_GAP_TOKENS[KIND_CAN_PSREMOTE].alias_absent == "hostsam.canpsremote.alias_absent"


def test_parse_c_blob_decodes_all_aliases_identically() -> None:
    # The on-disk C-blob layout is alias-agnostic: only the header RID differs.
    # Parsing the SAME member array under each of the four RIDs yields the SAME
    # member SIDs, and the parsed RID echoes the subkey it came from.
    members = [_SID_LOCAL_ADMIN, _SID_DOMAIN_ADMINS, _SID_DOMAIN_USER]
    admin = parse_c_blob(_craft_c_blob(DOMAIN_ALIAS_RID_ADMINS, members))
    for rid in (
        DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
        DOMAIN_ALIAS_RID_DCOM_USERS,
        DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    ):
        parsed = parse_c_blob(_craft_c_blob(rid, members))
        assert parsed.ok and parsed.errors == 0
        assert parsed.member_sids == admin.member_sids  # byte-identical membership
        assert parsed.member_sids == (_SID_LOCAL_ADMIN, _SID_DOMAIN_ADMINS, _SID_DOMAIN_USER)
        assert parsed.rid == rid  # the only per-alias variable
    # The RIDs themselves are the SID-anchored well-known values (research 27 §2.1).
    assert (
        DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
        DOMAIN_ALIAS_RID_DCOM_USERS,
        DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    ) == (0x22B, 0x232, 0x244)


def test_four_lanes_exact_kinds_direction_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[_SID_LOCAL_ADMIN, _SID_DOMAIN_USER],
        aliases=[
            _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_RDP]),
            _alias(DOMAIN_ALIAS_RID_DCOM_USERS, _SUBKEY_DCOM, [_SID_DCOM]),
            _alias(DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS, _SUBKEY_PSR, [_SID_PSR]),
        ],
    )
    run = _run_with_sam()
    res = _compute(con, run)
    assert res.host_resolved and res.host_node_id == "n-ws01"

    # Expected (kind, derivation, source_node, subkey) per lane.
    expected = {
        "n-user": ("AdminTo", "SAM:AdminTo", "00000220"),
        "n-rdp": (KIND_CAN_RDP, DERIVATION_SAM_CAN_RDP, _SUBKEY_RDP),
        "n-dcom": (KIND_EXECUTE_DCOM, DERIVATION_SAM_EXECUTE_DCOM, _SUBKEY_DCOM),
        "n-psr": (KIND_CAN_PSREMOTE, DERIVATION_SAM_CAN_PSREMOTE, _SUBKEY_PSR),
    }
    rows = con.execute(
        "SELECT source_node_id, target_node_id, kind, confidence, derivation, is_inherited, "
        "provenance FROM edge ORDER BY source_node_id"
    ).fetchall()
    assert {r[0] for r in rows} == set(expected)
    for src, tgt, kind, conf, deriv, inh, prov in rows:
        exp_kind, exp_deriv, exp_subkey = expected[src]
        assert tgt == "n-ws01"  # member -> host direction (source=member, target=host)
        assert kind == exp_kind
        assert deriv == exp_deriv
        assert conf == CONFIDENCE_CONFIRMED
        assert inh is False
        assert prov["image_sha256"] == "b" * 64
        anchor = f"SAM\\Domains\\Builtin\\Aliases\\{exp_subkey}\\C:"
        assert prov["source_object_id"].startswith(anchor)

    # Per-lane result tallies.
    assert res.alias_results[KIND_CAN_RDP].edges_emitted == 1
    assert res.alias_results[KIND_EXECUTE_DCOM].edges_emitted == 1
    assert res.alias_results[KIND_CAN_PSREMOTE].edges_emitted == 1
    # Each present-with-members lane bumped its alias_present coverage counter.
    for kind in (KIND_CAN_RDP, KIND_EXECUTE_DCOM, KIND_CAN_PSREMOTE):
        assert run.coverage_counts[ALIAS_GAP_TOKENS[kind].alias_present] == 1


def test_lane_provenance_timestamp_is_alias_last_change(monkeypatch: pytest.MonkeyPatch) -> None:
    # The per-lane provenance carries THIS alias's directory timestamp.
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[_alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_RDP])],
    )
    run = _run_with_sam()
    _compute(con, run)
    row = con.execute("SELECT provenance FROM edge WHERE kind = ?", [KIND_CAN_RDP]).fetchone()
    assert row is not None
    prov = row[0]
    # DuckDB returns the stored TIMESTAMP tz-naive (UTC wall clock); compare values.
    assert prov["directory_timestamp"].replace(tzinfo=UTC) == _LAST_CHANGE


# =============================================================================
# LAYER 2 — reference/parity: round-trip through the UNCHANGED BloodHound export
# =============================================================================


def test_export_roundtrip_four_localgroup_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[_SID_LOCAL_ADMIN, _SID_DOMAIN_USER],
        aliases=[
            _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_RDP]),
            _alias(DOMAIN_ALIAS_RID_DCOM_USERS, _SUBKEY_DCOM, [_SID_DCOM]),
            _alias(DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS, _SUBKEY_PSR, [_SID_PSR]),
        ],
    )
    run = _run_with_sam()
    _compute(con, run)

    payloads, result = build_export(con)
    computers = cast("list[dict[str, Any]]", payloads["computers"]["data"])
    host = next(c for c in computers if c["ObjectIdentifier"] == _SID_HOST.upper())

    def _oids(field: str) -> set[str]:
        return {e["ObjectIdentifier"] for e in host[field]["Results"]}

    # Each WRAITH kind round-trips to its BH computer-node local-group field.
    assert _oids("LocalAdmins") == {_SID_DOMAIN_USER.upper()}
    assert _oids("RemoteDesktopUsers") == {_SID_RDP.upper()}
    assert _oids("DcomUsers") == {_SID_DCOM.upper()}
    assert _oids("PSRemoteUsers") == {_SID_PSR.upper()}

    # Export accounting: all four lanes fully exported, nothing unmapped/dropped.
    disp = {d.kind: d for d in result.dispositions}
    for kind, field in (
        ("AdminTo", "LocalAdmins"),
        (KIND_CAN_RDP, "RemoteDesktopUsers"),
        (KIND_EXECUTE_DCOM, "DcomUsers"),
        (KIND_CAN_PSREMOTE, "PSRemoteUsers"),
    ):
        assert disp[kind].count == 1
        assert disp[kind].exported == 1
        assert disp[kind].dropped == {}
        assert field in disp[kind].bh_repr
    assert result.unmapped_kinds == {}


# =============================================================================
# LAYER 3 — property/robustness: per-alias gap taxonomy (3 distinct states)
# =============================================================================


def test_gap_taxonomy_absent_vs_empty_vs_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    # RDP absent, DCOM present-but-empty, PSRemote present-but-malformed C-blob.
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[
            _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [], found=False),
            _alias(DOMAIN_ALIAS_RID_DCOM_USERS, _SUBKEY_DCOM, [], found=True),
            _alias(
                DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
                _SUBKEY_PSR,
                [],
                found=True,
                cblob_errors=2,
            ),
        ],
    )
    run = _run_with_sam()
    res = _compute(con, run)

    cov = run.coverage_counts
    skips = run.skip_counts
    # 1) absent -> coverage alias_absent, NOT a skip gap.
    assert cov[ALIAS_GAP_TOKENS[KIND_CAN_RDP].alias_absent] == 1
    assert ALIAS_GAP_TOKENS[KIND_CAN_RDP].alias_present not in cov
    # 2) present-but-empty -> coverage alias_present_empty, distinct token.
    assert cov[ALIAS_GAP_TOKENS[KIND_EXECUTE_DCOM].alias_present_empty] == 1
    assert ALIAS_GAP_TOKENS[KIND_EXECUTE_DCOM].alias_absent not in cov
    # 3) malformed C-blob -> skip cblob_parse_error (the real gap), counted by N.
    assert skips[ALIAS_GAP_TOKENS[KIND_CAN_PSREMOTE].cblob_parse_error] == 2
    # The three tokens are DISTINCT keys (no collapsing).
    assert (
        len(
            {
                ALIAS_GAP_TOKENS[KIND_CAN_RDP].alias_absent,
                ALIAS_GAP_TOKENS[KIND_EXECUTE_DCOM].alias_present_empty,
                ALIAS_GAP_TOKENS[KIND_CAN_PSREMOTE].cblob_parse_error,
            }
        )
        == 3
    )
    # No edges from any of these degraded/empty lanes.
    assert res.alias_results[KIND_CAN_RDP].edges_emitted == 0
    assert res.alias_results[KIND_EXECUTE_DCOM].edges_emitted == 0
    assert res.alias_results[KIND_CAN_PSREMOTE].edges_emitted == 0
    assert res.alias_results[KIND_CAN_PSREMOTE].cblob_errors == 2


def test_local_only_member_skipped_per_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        # RDP alias holds ONLY the host's own local RID-500 -> LOCAL, no edge.
        aliases=[_alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_LOCAL_ADMIN])],
    )
    run = _run_with_sam()
    res = _compute(con, run)
    assert res.alias_results[KIND_CAN_RDP].edges_emitted == 0
    assert res.alias_results[KIND_CAN_RDP].local_members == 1
    assert run.coverage_counts[ALIAS_GAP_TOKENS[KIND_CAN_RDP].local_member_skipped] == 1
    assert _count(con, "SELECT count(*) FROM edge WHERE kind = ?", [KIND_CAN_RDP]) == 0


def test_mixed_local_and_domain_membership(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[
            _alias(
                DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
                _SUBKEY_RDP,
                [_SID_LOCAL_ADMIN, _SID_RDP, _SID_DOMAIN_ADMINS],
            )
        ],
    )
    run = _run_with_sam()
    res = _compute(con, run)
    lane = res.alias_results[KIND_CAN_RDP]
    assert lane.local_members == 1  # RID-500 skipped
    assert lane.domain_members == 2  # rdpguy + Domain Admins
    assert lane.edges_emitted == 2
    srcs = {
        r[0]
        for r in con.execute(
            "SELECT source_node_id FROM edge WHERE kind = ?", [KIND_CAN_RDP]
        ).fetchall()
    }
    assert srcs == {"n-rdp", "n-da"}


def test_reflexive_self_member_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # The host computer's OWN SID appears in the RDP alias -> resolves to the host
    # node -> reflexive self-edge is skipped (counted), never emitted.
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[_alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_HOST, _SID_RDP])],
    )
    run = _run_with_sam()
    res = _compute(con, run)
    lane = res.alias_results[KIND_CAN_RDP]
    assert lane.self_skipped == 1
    assert lane.edges_emitted == 1  # only n-rdp
    assert run.coverage_counts[ALIAS_GAP_TOKENS[KIND_CAN_RDP].self_skipped] == 1
    srcs = [
        r[0]
        for r in con.execute(
            "SELECT source_node_id FROM edge WHERE kind = ?", [KIND_CAN_RDP]
        ).fetchall()
    ]
    assert srcs == ["n-rdp"]


def test_mint_on_miss_per_lane_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[
            _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_UNKNOWN, _SID_RDP])
        ],
    )
    run = _run_with_sam()
    res = _compute(con, run)
    lane = res.alias_results[KIND_CAN_RDP]
    assert lane.stubs_minted == 1
    assert run.skip_counts[ALIAS_GAP_TOKENS[KIND_CAN_RDP].member_sid_unresolved] == 1
    # Exactly one stub materialized for the unknown SID.
    assert _count(con, "SELECT count(*) FROM principal WHERE object_sid = ?", [_SID_UNKNOWN]) == 1
    assert lane.edges_emitted == 2  # minted stub + n-rdp


def test_shared_resolver_dedupes_stub_across_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    # The SAME unknown SID in two lanes mints ONE stub (one shared resolver).
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[
            _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [_SID_UNKNOWN]),
            _alias(DOMAIN_ALIAS_RID_DCOM_USERS, _SUBKEY_DCOM, [_SID_UNKNOWN]),
        ],
    )
    run = _run_with_sam()
    _compute(con, run)
    assert _count(con, "SELECT count(*) FROM principal WHERE object_sid = ?", [_SID_UNKNOWN]) == 1
    # Both lanes still emit their edge to the one shared stub node.
    assert _count(con, "SELECT count(*) FROM edge WHERE kind = ?", [KIND_CAN_RDP]) == 1
    assert _count(con, "SELECT count(*) FROM edge WHERE kind = ?", [KIND_EXECUTE_DCOM]) == 1


def test_unclassifiable_member_no_leak_per_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    # machine_sid unknown + a foreign S-1-5-21 head (not known-domain, not a
    # well-known DOMAIN RID) -> UNCLASSIFIABLE: no edge, no stub, counted per lane.
    con = _new_store()
    _seed(con)
    foreign = "S-1-5-21-7-8-9-1500"
    _mock_read(
        monkeypatch,
        admin_members=[],
        aliases=[_alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, [foreign])],
        machine_sid=None,
    )
    run = _run_with_sam()
    res = _compute(con, run)
    lane = res.alias_results[KIND_CAN_RDP]
    assert lane.unclassifiable_members == 1
    assert lane.edges_emitted == 0
    assert run.skip_counts[ALIAS_GAP_TOKENS[KIND_CAN_RDP].member_unclassifiable] == 1
    assert _count(con, "SELECT count(*) FROM edge WHERE kind = ?", [KIND_CAN_RDP]) == 0
    assert _count(con, "SELECT count(*) FROM principal WHERE object_sid = ?", [foreign]) == 0


def test_determinism_reversed_member_order(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run_once(order: list[str]) -> list[tuple[str, str, str, str]]:
        con = _new_store()
        _seed(con)
        _mock_read(
            monkeypatch,
            admin_members=[_SID_DOMAIN_USER],
            aliases=[
                _alias(DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, _SUBKEY_RDP, order),
                _alias(DOMAIN_ALIAS_RID_DCOM_USERS, _SUBKEY_DCOM, [_SID_DCOM, _SID_UNKNOWN]),
            ],
        )
        run = _run_with_sam()
        _compute(con, run)
        return con.execute(
            "SELECT edge_id, source_node_id, target_node_id, kind FROM edge ORDER BY edge_id"
        ).fetchall()

    forward = _run_once([_SID_RDP, _SID_DOMAIN_ADMINS, _SID_UNKNOWN])
    reversed_ = _run_once([_SID_UNKNOWN, _SID_DOMAIN_ADMINS, _SID_RDP])
    assert forward == reversed_  # identical edges regardless of on-disk member order
    # AdminTo(n-user)=1 + RDP(n-rdp,n-da,stub)=3 + DCOM(n-dcom,stub)=2 = 6 edges.
    assert len(forward) == 6


# =============================================================================
# LAYER 4 — regression: AdminTo lane + Gate-09 tokens untouched; real DC SAM
# =============================================================================


def test_admin_to_original_tokens_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    # AdminTo uses its ORIGINAL (un-laned) gap tokens, NOT the hostsam.<lane>.* set.
    con = _new_store()
    _seed(con)
    _mock_read(
        monkeypatch,
        admin_members=[_SID_LOCAL_ADMIN, _SID_DOMAIN_USER, _SID_UNKNOWN],
        aliases=[],  # no extra aliases present
    )
    run = _run_with_sam()
    res = _compute(con, run)
    # AdminTo tallies unchanged (Gate 09 shape).
    assert res.local_members == 1
    assert res.domain_members == 2
    assert res.edges_emitted == 2
    assert res.stubs_minted == 1
    # Original un-laned tokens.
    assert run.skip_counts[_admin_edges.GAP_MEMBER_SID_UNRESOLVED] == 1
    assert run.coverage_counts["hostsam.local_member_skipped"] == 1
    # No laned AdminTo token exists (AdminTo is NOT in ALIAS_GAP_TOKENS).
    assert "AdminTo" not in ALIAS_GAP_TOKENS
    assert not any(k.startswith("hostsam.adminto.") for k in run.skip_counts)
    assert not any(k.startswith("hostsam.adminto.") for k in run.coverage_counts)


@pytest.mark.skipif(not _REAL_SAM_PRESENT, reason="real DC SAM hive absent")
def test_real_dc_sam_reads_extra_aliases_cleanly() -> None:
    # The reader reads the three ADDITIONAL aliases from the real DC SAM without
    # error. The DC SAM is sparse, so they are expected ABSENT (found=False) — a
    # real-on-real validation of the absence path (research 27 §5). Whatever the
    # found state, each parse is error-free and carries the correct RID/subkey.
    read = read_host_sam(_EVIDENCE_SAM)
    assert not read.read_error and read.found_alias
    assert len(read.aliases) == 3
    by_rid = {a.rid: a for a in read.aliases}
    assert set(by_rid) == {
        DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
        DOMAIN_ALIAS_RID_DCOM_USERS,
        DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    }
    assert by_rid[DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS].subkey == _SUBKEY_RDP
    assert by_rid[DOMAIN_ALIAS_RID_DCOM_USERS].subkey == _SUBKEY_DCOM
    assert by_rid[DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS].subkey == _SUBKEY_PSR
    for a in read.aliases:
        assert a.cblob_errors == 0
        if not a.found:
            assert a.member_sids == ()
