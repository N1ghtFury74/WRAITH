"""Tester gate for the Tier-B GPO/SYSVOL module (wraith/gpo).

Authoritative three-layer gate (independent of the coder's sanity files):

* Layer 1 (unit/golden): all four local-group alias mappings
  (544->AdminTo, 555->CanRDP, 562->ExecuteDCOM, 580->CanPSRemote) via both
  Members and Memberof; privilege-edge WRAITH: prefix + GPO: derivation +
  baseline suppression + non-SID-holder-counted-not-edged.
* Layer 2 (reference/real-data): the real SYSVOL true negative re-derived through
  the engine (24 privilege lines -> 57 derived_rights, 0 AdminTo, 0 privilege
  edges), the fDenyTSConnections + SMB-signing signals, EFS blob survived.
* Layer 3 (property/robustness): garbage GptTmpl.inf and truncated Registry.pol
  degrade to COUNTED gaps (no crash, prior records retained); determinism of the
  synthetic edge_id set + the real signal/derived-rights counts; and the GPP
  cpassword plaintext never appears in the result object.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.gpo.edges import privilege_edge_kind
from wraith.gpo.engine import process_sysvol
from wraith.gpo.models import GpoProcessResult
from wraith.model.store import create_canonical_tables, create_edge_tables

_REPO = Path(__file__).resolve().parents[1]
_REAL_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_FOREST = "f1"
_DOMAIN = "S-1-5-21-1-2-3"
_FQDN = "c137.local"
_IMG = "a" * 64

# The plaintext behind the test cpassword fixture (used ONLY to assert it never
# leaks into the result object; never logged by the module).
_CPASSWORD = "Xpk4DyKDjYQQ/EUHClHlP2oQjgNneSFq7H7+yjl/xNw"
_CPASSWORD_PLAINTEXT = "Passw0rd!2024"


def _run() -> IngestRun:
    return IngestRun(
        "case",
        "op",
        ingest_run_id=uuid.UUID("00000000-0000-0000-0000-0000000000c0"),
    )


def _store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _add_principal(con: duckdb.DuckDBPyConnection, node_id: str, sid: str, ptype: str) -> None:
    con.execute(
        "INSERT INTO principal (node_id, object_sid, principal_type, forest_id) VALUES (?,?,?,?)",
        [node_id, sid, ptype, _FOREST],
    )


def _add_gpo(con: duckdb.DuckDBPyConnection, node_id: str, folder_guid: str) -> None:
    path = rf"\\{_FQDN}\SysVol\{_FQDN}\Policies\{{{folder_guid}}}"
    con.execute(
        "INSERT INTO gpo (node_id, gpc_file_sys_path, forest_id) VALUES (?,?,?)",
        [node_id, path, _FOREST],
    )


def _add_container(con: duckdb.DuckDBPyConnection, node_id: str) -> None:
    con.execute(
        "INSERT INTO container (node_id, container_type, forest_id) VALUES (?,?,?)",
        [node_id, "OU", _FOREST],
    )


def _add_edge(con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str) -> None:
    con.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id) "
        "VALUES (?,?,?,?,?)",
        [f"{kind}:{src}:{tgt}", kind, src, tgt, _FOREST],
    )


def _utf16_inf(body: str) -> bytes:
    return ("\ufeff" + body).encode("utf-16-le")


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _process(con: duckdb.DuckDBPyConnection, sysvol: Path, **kw: object) -> GpoProcessResult:
    return process_sysvol(
        con,
        _run(),
        sysvol_root=sysvol,
        sysvol_image_sha256=_IMG,
        forest_id=_FOREST,
        domain_id=_DOMAIN,
        domain_fqdn=_FQDN,
        **kw,  # type: ignore[arg-type]
    )


# =============================================================================
# LAYER 1 — all four local-group alias mappings (Members + Memberof)
# =============================================================================


def test_all_four_local_group_mappings(tmp_path: Path) -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000001"
    con = _store()
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")

    base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    inf = (
        "[Unicode]\r\nUnicode=yes\r\n"
        "[Group Membership]\r\n"
        # 544 -> AdminTo (Members), 555 -> CanRDP (Members),
        # 562 -> ExecuteDCOM (Memberof form), 580 -> CanPSRemote (Memberof form).
        "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1101\r\n"
        "*S-1-5-32-555__Members = *S-1-5-21-1-2-3-1102\r\n"
        "*S-1-5-21-1-2-3-1103__Memberof = *S-1-5-32-562\r\n"
        "*S-1-5-21-1-2-3-1104__Memberof = *S-1-5-32-580\r\n"
    )
    _write(
        base / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf", _utf16_inf(inf)
    )

    result = _process(con, tmp_path / "SYSVOL")
    rows = con.execute(
        "SELECT kind, source_node_id, target_node_id, derivation, confidence "
        "FROM edge WHERE derivation LIKE 'GPO:%' ORDER BY kind"
    ).fetchall()
    by_kind = {r[0]: r for r in rows}
    assert set(by_kind) == {"AdminTo", "CanRDP", "ExecuteDCOM", "CanPSRemote"}
    # Direction is principal -> computer for every mapping; all inferred.
    for kind, (_, src, tgt, deriv, conf) in by_kind.items():
        assert tgt == "C1", (kind, tgt)
        assert src != "C1"
        assert deriv == f"GPO:{kind}"
        assert conf == "inferred"
    assert result.admin_to_edges == 1  # only 544 counts as AdminTo


# =============================================================================
# LAYER 1 — privilege edge: WRAITH: prefix, baseline suppression, non-SID
# =============================================================================


def test_privilege_edge_prefix_suppression_and_nonsid(tmp_path: Path) -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000002"
    con = _store()
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")

    base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    inf = (
        "[Unicode]\r\nUnicode=yes\r\n"
        "[Privilege Rights]\r\n"
        # non-baseline SID holder -> ONE WRAITH-native edge.
        # baseline 544 -> suppressed. bare-name holder -> counted, not edged.
        "SeBackupPrivilege = *S-1-5-21-1-2-3-1313,*S-1-5-32-544,CORP\\customadmins\r\n"
        # domain RID 512 (Domain Admins) is baseline -> suppressed.
        "SeDebugPrivilege = *S-1-5-21-1-2-3-512\r\n"
    )
    _write(
        base / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf", _utf16_inf(inf)
    )

    result = _process(con, tmp_path / "SYSVOL")
    priv_kind = privilege_edge_kind("SeBackupPrivilege")
    rows = con.execute(
        "SELECT kind, source_node_id, target_node_id, derivation, confidence FROM edge "
        "WHERE derivation LIKE 'GPO:Se%' ORDER BY kind"
    ).fetchall()
    # Exactly one privilege edge: the non-baseline 1313 holder on SeBackup.
    assert len(rows) == 1
    kind, src, tgt, deriv, conf = rows[0]
    assert kind == priv_kind == "WRAITH:SeBackupPrivilege"
    assert kind.startswith("WRAITH:")  # non-BH-native marker
    assert deriv == "GPO:SeBackupPrivilege"
    assert conf == "inferred"
    assert tgt == "C1"
    assert result.privilege_edges == 1
    # SeDebug 512 is baseline -> no edge.
    assert (
        con.execute("SELECT count(*) FROM edge WHERE kind='WRAITH:SeDebugPrivilege'").fetchone()[0]
        == 0
    )
    # The bare-name holder was counted as a member-name gap, not edged.
    assert result.skip_counts.get("gpo.member_name_unresolved", 0) >= 1
    # ALL (priv,holder) pairs are in derived_rights regardless of edge/suppression.
    rights = con.execute("SELECT derived_rights FROM gpo WHERE node_id='G'").fetchone()[0]
    pairs = {(e["right"], e["target_scope"]) for e in rights}
    assert ("SeBackupPrivilege", "S-1-5-21-1-2-3-1313") in pairs
    assert ("SeBackupPrivilege", "S-1-5-32-544") in pairs
    assert ("SeBackupPrivilege", "CORP\\customadmins") in pairs
    assert ("SeDebugPrivilege", "S-1-5-21-1-2-3-512") in pairs


# =============================================================================
# LAYER 2 — REAL SYSVOL true negative re-derived through the engine
# =============================================================================


def test_real_sysvol_true_negative_through_engine() -> None:
    con = _store()
    _add_gpo(con, "G_DC", "6AC1786C-016F-11D2-945F-00C04fB984F9")
    _add_gpo(con, "G_DEF", "31B2F340-016D-11D2-945F-00C04FB984F9")
    _add_gpo(con, "G_RDP", "D4FC302A-E668-4E39-B591-8727A952E04C")
    _add_container(con, "DCOU")
    _add_principal(con, "DC1", "S-1-5-21-1-2-3-1000", "Computer")
    # Link the Default DC Policy to a DC OU with a real computer in scope: proves
    # that even WITH a computer in scope the baseline-only privileges yield 0 edges.
    _add_edge(con, "GPLink", "G_DC", "DCOU")
    _add_edge(con, "Contains", "DCOU", "DC1")

    result = _process(con, _REAL_SYSVOL)

    assert result.gpos_matched == 3
    assert result.admin_to_edges == 0
    assert result.privilege_edges == 0
    assert con.execute("SELECT count(*) FROM edge WHERE derivation LIKE 'GPO:%'").fetchone()[0] == 0

    # 24 privilege lines -> 57 (priv,holder) derived_rights (independently re-derived).
    rights = con.execute("SELECT derived_rights FROM gpo WHERE node_id='G_DC'").fetchone()[0]
    assert len(rights) == 57
    assert result.derived_rights_written == 57
    assert len({e["right"] for e in rights}) == 24
    assert "SeEnableDelegationPrivilege" in {e["right"] for e in rights}

    # Signals: RDP-enable from {D4FC302A}; SMB-signing from {6AC1786C} [Registry Values].
    signal_names = {s.signal for s in result.signals}
    assert "fDenyTSConnections" in signal_names
    assert "SmbRequireSecuritySignature" in signal_names
    # EFS binary blob survived: no preg parse error on any of the three GPOs.
    assert result.skip_counts.get("gpo.preg_parse_error", 0) == 0


# =============================================================================
# LAYER 3 — robustness: garbage inf + truncated preg -> counted gaps, no crash
# =============================================================================


def test_robustness_garbage_inf_and_truncated_preg(tmp_path: Path) -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000003"
    con = _store()
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")

    base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    # Garbage, non-UTF16 GptTmpl that configparser cannot section-parse.
    _write(
        base / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf",
        bytes(range(256)) * 4,
    )

    # A Registry.pol with one valid record then a truncated second one.
    def rec(k: str, v: str, t: int, data: bytes) -> bytes:
        return (
            b"[\x00"
            + k.encode("utf-16-le")
            + b"\x00\x00"
            + b";\x00"
            + v.encode("utf-16-le")
            + b"\x00\x00"
            + b";\x00"
            + t.to_bytes(4, "little")
            + b";\x00"
            + len(data).to_bytes(4, "little")
            + b";\x00"
            + data
            + b"]\x00"
        )

    blob = (
        b"PReg"
        + (1).to_bytes(4, "little")
        + rec("SOFTWARE\\X", "fDenyTSConnections", 4, b"\x00\x00\x00\x00")
        + rec("SOFTWARE\\Y", "RunAsPPL", 4, b"\x01\x00\x00\x00")
    )
    _write(base / "MACHINE" / "Registry.pol", blob[:-6])  # truncate last record

    result = _process(con, tmp_path / "SYSVOL")  # must not raise
    assert result.skip_counts.get("gpo.inf_parse_error", 0) == 1
    assert result.skip_counts.get("gpo.preg_parse_error", 0) == 1
    # The record parsed before the truncation is retained -> its signal surfaces.
    assert "fDenyTSConnections" in {s.signal for s in result.signals}
    # No GPO edges from a garbage inf.
    assert result.admin_to_edges == 0
    assert result.privilege_edges == 0


# =============================================================================
# LAYER 3 — GPP cpassword: redacted finding, never an edge, plaintext never leaks
# =============================================================================


def test_cpassword_finding_never_edge_never_leaks(tmp_path: Path) -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000004"
    con = _store()
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")

    base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    groups_xml = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Groups><User name="svc_backup"><Properties userName="svc_backup" '
        b'cpassword="' + _CPASSWORD.encode() + b'"/></User></Groups>'
    )
    _write(base / "MACHINE" / "Preferences" / "Groups" / "Groups.xml", groups_xml)

    result = _process(con, tmp_path / "SYSVOL")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.redacted == "<redacted>"
    assert finding.user_name == "svc_backup"
    assert finding.secret_ref is None  # no store wired
    assert result.skip_counts.get("gpo.gpp_cpassword_finding", 0) == 1
    # NEVER an edge.
    assert con.execute("SELECT count(*) FROM edge WHERE derivation LIKE 'GPO:%'").fetchone()[0] == 0
    # The decrypted plaintext NEVER appears anywhere in the result object.
    assert _CPASSWORD_PLAINTEXT not in repr(result)
    assert _CPASSWORD_PLAINTEXT not in repr(finding)


# =============================================================================
# LAYER 3 — determinism: synthetic edge_id set + real signal/derived counts
# =============================================================================


def test_determinism_synthetic_edge_ids(tmp_path: Path) -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000005"

    def once() -> list[str]:
        con = _store()
        _add_gpo(con, "G", guid)
        _add_container(con, "OU")
        _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
        _add_principal(con, "C2", "S-1-5-21-1-2-3-2002", "Computer")
        _add_edge(con, "GPLink", "G", "OU")
        _add_edge(con, "Contains", "OU", "C1")
        _add_edge(con, "Contains", "OU", "C2")
        base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
        inf = (
            "[Unicode]\r\nUnicode=yes\r\n"
            "[Group Membership]\r\n"
            "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1101\r\n"
            "*S-1-5-32-555__Members = *S-1-5-21-1-2-3-1102\r\n"
            "[Privilege Rights]\r\n"
            "SeBackupPrivilege = *S-1-5-21-1-2-3-1313\r\n"
        )
        _write(
            base / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf",
            _utf16_inf(inf),
        )
        _process(con, tmp_path / "SYSVOL")
        return [r[0] for r in con.execute("SELECT edge_id FROM edge ORDER BY edge_id").fetchall()]

    first = once()
    assert first == once()
    assert len(first) > 0


def test_determinism_real_signals_and_rights() -> None:
    def once() -> tuple[int, int]:
        con = _store()
        _add_gpo(con, "G_DC", "6AC1786C-016F-11D2-945F-00C04fB984F9")
        _add_gpo(con, "G_DEF", "31B2F340-016D-11D2-945F-00C04FB984F9")
        _add_gpo(con, "G_RDP", "D4FC302A-E668-4E39-B591-8727A952E04C")
        result = _process(con, _REAL_SYSVOL)
        return result.derived_rights_written, len(result.signals)

    assert once() == once()
