"""Coder-side sanity for the Tier-B GPO engine end to end (not the gate).

Builds a minimal canonical store (principal / container / gpo / edge with the M5
Contains + GPLink edges already present) and runs :func:`process_sysvol` against:

* a SYNTHETIC SYSVOL with a `[Group Membership]` 544 push, a non-baseline
  privilege grant, and a GPP `Groups.xml` + cpassword — proving AdminTo,
  WRAITH-native privilege edges, GPP AdminTo, and the redacted cpassword finding;
* the REAL SYSVOL mapped onto the real folder GUIDs — proving the scope-
  resolution reuse of M5 Contains/GPLink, the privilege-rights true negative (all
  holders admin-baseline -> zero edges), the derived_rights facts, and the
  Registry.pol signals (incl. surviving the EFS blob) with determinism.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.gpo.edges import privilege_edge_kind
from wraith.gpo.engine import process_sysvol
from wraith.model.store import create_canonical_tables, create_edge_tables

_REPO = Path(__file__).resolve().parents[1]
_REAL_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_FOREST = "f1"
_DOMAIN = "S-1-5-21-1-2-3"
_FQDN = "c137.local"
_IMG = "e" * 64


def _run() -> IngestRun:
    return IngestRun(
        "case",
        "op",
        ingest_run_id=uuid.UUID("00000000-0000-0000-0000-0000000000b0"),
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


# =============================================================================
# SYNTHETIC: AdminTo + privilege edge + GPP + cpassword finding
# =============================================================================


def _synthetic_sysvol(tmp: Path, guid: str) -> Path:
    base = tmp / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    inf = (
        "[Unicode]\r\nUnicode=yes\r\n"
        "[Group Membership]\r\n"
        "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1107\r\n"
        "*S-1-5-32-555__Members = *S-1-5-21-1-2-3-1200\r\n"
        "[Privilege Rights]\r\n"
        # one non-baseline holder (delta -> edge) + one baseline (suppressed).
        "SeBackupPrivilege = *S-1-5-21-1-2-3-1313,*S-1-5-32-544\r\n"
        "SeChangeNotifyPrivilege = *S-1-1-0\r\n"
    )
    _write(
        base / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf",
        _utf16_inf(inf),
    )
    groups_xml = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Groups><Group name="Administrators">'
        b'<Properties action="U" groupSid="S-1-5-32-544">'
        b'<Members><Member action="ADD" sid="S-1-5-21-1-2-3-1500"/></Members>'
        b"</Properties></Group>"
        b'<User name="localadmin"><Properties userName="localadmin" '
        b'cpassword="Xpk4DyKDjYQQ/EUHClHlP2oQjgNneSFq7H7+yjl/xNw"/></User>'
        b"</Groups>"
    )
    _write(base / "MACHINE" / "Preferences" / "Groups" / "Groups.xml", groups_xml)
    return tmp / "SYSVOL"


def test_synthetic_admin_to_privilege_and_gpp(tmp_path: Path) -> None:
    guid = "11111111-1111-1111-1111-111111111111"
    con = _store()
    # topology: GPO -> OU (GPLink); OU contains two computers (Contains*).
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_principal(con, "C2", "S-1-5-21-1-2-3-2002", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")
    _add_edge(con, "Contains", "OU", "C2")

    sysvol = _synthetic_sysvol(tmp_path, guid)
    run = _run()
    result = process_sysvol(
        con,
        run,
        sysvol_root=sysvol,
        sysvol_image_sha256=_IMG,
        forest_id=_FOREST,
        domain_id=_DOMAIN,
        domain_fqdn=_FQDN,
    )

    # Restricted-groups 544 push -> AdminTo for 1107 to both computers.
    admin = con.execute(
        "SELECT target_node_id FROM edge WHERE kind='AdminTo' ORDER BY target_node_id"
    ).fetchall()
    assert [r[0] for r in admin] == ["C1", "C2"]
    assert result.admin_to_edges == 2

    # 555 push -> CanRDP for 1200 to both computers.
    rdp = con.execute("SELECT count(*) FROM edge WHERE kind='CanRDP'").fetchone()
    assert rdp is not None and rdp[0] == 2

    # GPP Administrators ADD (1500) also -> AdminTo (restricted groups present for
    # 544 too, so GPP for 544 is SUPERSEDED -> no duplicate, counted gap).
    assert result.skip_counts.get("gpo.gpp_superseded_by_restricted_groups", 0) == 1

    # Non-baseline SeBackupPrivilege holder 1313 -> WRAITH-native edges to both
    # computers; the baseline 544 holder is suppressed (no edge).
    priv_kind = privilege_edge_kind("SeBackupPrivilege")
    priv = con.execute("SELECT count(*) FROM edge WHERE kind=?", [priv_kind]).fetchone()
    assert priv is not None and priv[0] == 2
    assert result.privilege_edges == 2

    # Every GPO edge is INFERRED.
    confs = con.execute(
        "SELECT DISTINCT confidence FROM edge WHERE derivation LIKE 'GPO:%'"
    ).fetchall()
    assert {r[0] for r in confs} == {"inferred"}

    # derived_rights hold ALL privilege-right (priv, holder) pairs incl baseline.
    rights = con.execute("SELECT derived_rights FROM gpo WHERE node_id='G'").fetchone()
    assert rights is not None
    entries = rights[0]
    pairs = {(e["right"], e["target_scope"]) for e in entries}
    assert ("SeBackupPrivilege", "S-1-5-21-1-2-3-1313") in pairs
    assert ("SeBackupPrivilege", "S-1-5-32-544") in pairs
    assert ("SeChangeNotifyPrivilege", "S-1-1-0") in pairs

    # GPP cpassword -> a redacted finding, NEVER an edge or logged plaintext.
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.redacted == "<redacted>"
    assert finding.user_name == "localadmin"
    # No secret store wired here -> no secret_ref, but the finding still surfaces.
    assert finding.secret_ref is None
    assert result.skip_counts.get("gpo.gpp_cpassword_finding", 0) == 1


def test_malformed_groups_xml_is_counted_gap_not_silent(tmp_path: Path) -> None:
    # A corrupt/truncated Groups.xml must be a COUNTED gap (gpo.gpp_parse_error=1),
    # not a silent drop: no crash, no edges, no cpassword finding slip through.
    guid = "33333333-3333-3333-3333-333333333333"
    con = _store()
    _add_gpo(con, "G", guid)
    _add_container(con, "OU")
    _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
    _add_edge(con, "GPLink", "G", "OU")
    _add_edge(con, "Contains", "OU", "C1")

    base = tmp_path / "SYSVOL" / "domain" / "Policies" / f"{{{guid}}}"
    # Truncated mid-element: well-formed start, abrupt EOF -> ET.ParseError.
    _write(
        base / "MACHINE" / "Preferences" / "Groups" / "Groups.xml",
        b'<?xml version="1.0"?><Groups><Group name="Admins"><Properties '
        b'groupSid="S-1-5-32-544" cpassword="Xpk4DyKDjYQQ',
    )
    run = _run()
    result = process_sysvol(
        con,
        run,
        sysvol_root=tmp_path / "SYSVOL",
        sysvol_image_sha256=_IMG,
        forest_id=_FOREST,
        domain_id=_DOMAIN,
        domain_fqdn=_FQDN,
    )

    assert result.skip_counts.get("gpo.gpp_parse_error", 0) == 1
    assert result.edges_written == 0
    assert result.findings == []
    assert result.skip_counts.get("gpo.gpp_cpassword_finding", 0) == 0
    # No GPO-derived edge slipped through (the only edges are the seeded topology).
    gpo_edges = con.execute("SELECT count(*) FROM edge WHERE derivation LIKE 'GPO:%'").fetchone()
    assert gpo_edges is not None and gpo_edges[0] == 0


def test_synthetic_determinism(tmp_path: Path) -> None:
    guid = "22222222-2222-2222-2222-222222222222"

    def once() -> list[str]:
        con = _store()
        _add_gpo(con, "G", guid)
        _add_container(con, "OU")
        _add_principal(con, "C1", "S-1-5-21-1-2-3-2001", "Computer")
        _add_edge(con, "GPLink", "G", "OU")
        _add_edge(con, "Contains", "OU", "C1")
        sysvol = _synthetic_sysvol(tmp_path, guid)
        process_sysvol(
            con,
            _run(),
            sysvol_root=sysvol,
            sysvol_image_sha256=_IMG,
            forest_id=_FOREST,
            domain_id=_DOMAIN,
            domain_fqdn=_FQDN,
        )
        return [r[0] for r in con.execute("SELECT edge_id FROM edge ORDER BY edge_id").fetchall()]

    assert once() == once()


# =============================================================================
# REAL SYSVOL: scope reuse + privilege true negative + signals
# =============================================================================


def test_real_sysvol_true_negative_and_signals() -> None:
    con = _store()
    # Map all three REAL folder GUIDs onto GPO nodes; link the Default DC Policy
    # to a DC OU that contains a DC computer (the real topology shape) so scope
    # resolution has a computer to (not) push to.
    dc_policy = "6AC1786C-016F-11D2-945F-00C04fB984F9"
    default_policy = "31B2F340-016D-11D2-945F-00C04FB984F9"
    rdp_policy = "D4FC302A-E668-4E39-B591-8727A952E04C"
    _add_gpo(con, "G_DC", dc_policy)
    _add_gpo(con, "G_DEF", default_policy)
    _add_gpo(con, "G_RDP", rdp_policy)
    _add_container(con, "DCOU")
    _add_principal(con, "DC1", "S-1-5-21-1-2-3-1000", "Computer")
    _add_edge(con, "GPLink", "G_DC", "DCOU")
    _add_edge(con, "Contains", "DCOU", "DC1")

    run = _run()
    result = process_sysvol(
        con,
        run,
        sysvol_root=_REAL_SYSVOL,
        sysvol_image_sha256=_IMG,
        forest_id=_FOREST,
        domain_id=_DOMAIN,
        domain_fqdn=_FQDN,
    )

    # All three real folders matched to GPO nodes.
    assert result.gpos_matched == 3

    # TRUE NEGATIVE: no restricted groups / GPP anywhere -> 0 AdminTo; all
    # privilege holders are admin-baseline -> 0 privilege edges, even though DC1
    # is a computer in scope of the Default DC Policy.
    assert result.admin_to_edges == 0
    assert result.privilege_edges == 0
    total = con.execute("SELECT count(*) FROM edge WHERE derivation LIKE 'GPO:%'").fetchone()
    assert total is not None and total[0] == 0

    # The {6AC1786C} Default DC Policy's 24 privilege lines -> 57 (priv, holder)
    # derived_rights facts, including the Tier-0 SeEnableDelegationPrivilege.
    rights = con.execute("SELECT derived_rights FROM gpo WHERE node_id='G_DC'").fetchone()
    assert rights is not None
    entries = rights[0]
    assert len(entries) == 57
    names = {e["right"] for e in entries}
    assert "SeEnableDelegationPrivilege" in names
    assert "SeBackupPrivilege" in names
    assert result.derived_rights_written == 57

    # Registry.pol signals: the RDP-enable signal from {D4FC302A} is surfaced,
    # and the {31B2F340} EFS binary cert blob is survived (no crash, no signal).
    signal_names = {s.signal for s in result.signals}
    assert "fDenyTSConnections" in signal_names
    # The GptTmpl [Registry Values] SMB-signing signal is surfaced too.
    assert "SmbRequireSecuritySignature" in signal_names
    assert result.skip_counts.get("gpo.preg_parse_error", 0) == 0


def test_real_sysvol_determinism() -> None:
    def once() -> tuple[int, int]:
        con = _store()
        _add_gpo(con, "G_DC", "6AC1786C-016F-11D2-945F-00C04fB984F9")
        _add_gpo(con, "G_DEF", "31B2F340-016D-11D2-945F-00C04FB984F9")
        _add_gpo(con, "G_RDP", "D4FC302A-E668-4E39-B591-8727A952E04C")
        result = process_sysvol(
            con,
            _run(),
            sysvol_root=_REAL_SYSVOL,
            sysvol_image_sha256=_IMG,
            forest_id=_FOREST,
            domain_id=_DOMAIN,
            domain_fqdn=_FQDN,
        )
        return result.derived_rights_written, len(result.signals)

    assert once() == once()
