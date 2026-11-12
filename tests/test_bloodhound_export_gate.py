"""M6 BloodHound CE export — the TESTER gate (independent of coder sanity).

Three layers, authored by ``wraith-tester`` to re-derive (not trust) the adapter:

* **Synthetic (``test_gate_syn_*``)** — fast in-memory stores that independently
  exercise the Point-5 branches the real DC has zero of: trust-family
  ``trust_postprocess`` drops + the ``hastrustkeys_user_absent`` counter,
  WRAITH-native ``native`` drops, ``WraithESC4TemplateControl`` composed/no-CA
  split, and special-identity single-emission.
* **Real DC (``test_gate_real_*``, skipped without ``eviedence_test``)** — the
  full analysis pipeline on the committed c137.local ``ntds.dit``, asserting the
  LOCKED disposition numbers, the ``target_not_bh_node`` cross-check against
  ``staging_object``, the DCSync holder set (==gate-05), BH CE v6 structural
  conformance, and byte-level determinism (including the zip).

The real-DC numbers are the structural self-validation oracle (doc 12 §A: no
public SharpHound baseline for this DC exists). These are the gate's assertions.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast
from uuid import UUID

import duckdb
import pytest

from wraith.common.determinism import canonical_json
from wraith.export.bloodhound import FILE_TYPES, build_export, export_bloodhound
from wraith.model.store import create_canonical_tables, create_edge_tables

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

FOREST = "f"
DOM = "S-1-5-21-10-20-30"

_Payload = dict[str, dict[str, object]]


def _data(payloads: _Payload, ftype: str) -> list[dict[str, object]]:
    """Typed accessor for a per-type file's node list (``payload[ftype]["data"]``)."""
    return cast("list[dict[str, object]]", payloads[ftype]["data"])


def _meta(payloads: _Payload, ftype: str) -> dict[str, object]:
    """Typed accessor for a per-type file's ``meta`` block."""
    return cast("dict[str, object]", payloads[ftype]["meta"])


# Locked real-DC (c137.local) oracle — re-derived by the tester 2026-10-26.
_EXPECT_TOTAL = 30303
_EXPECT_EXPORTED = 4931
_EXPECT_DROPPED = 25372
_EXPECT_TARGET_NOT_BH_NODE = 25369
_EXPECT_DCSYNC_COMPOSED = 3
_DCSYNC_HOLDER_SUFFIXES = ("-544", "-512", "-519")


# ---------------------------------------------------------------------------
# synthetic fixture for the Point-5 branches
# ---------------------------------------------------------------------------
def _mk_synth() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)

    def principal(node: str, sid: str, ptype: str) -> None:
        con.execute(
            "INSERT INTO principal (node_id,object_sid,object_guid,principal_type,"
            "samaccountname,uac_flags,forest_id,domain_id,domain_fqdn) VALUES (?,?,?,?,?,?,?,?,?)",
            [node, sid, None, ptype, node, 0, FOREST, DOM, "t.local"],
        )

    def container(node: str, ctype: str, sid: str | None, guid: str | None) -> None:
        con.execute(
            "INSERT INTO container (node_id,object_sid,object_guid,container_type,"
            "forest_id,domain_id,domain_fqdn) VALUES (?,?,?,?,?,?,?)",
            [node, sid, guid, ctype, FOREST, DOM, "t.local"],
        )

    def adcs(node: str, guid: str, atype: str) -> None:
        con.execute(
            "INSERT INTO adcs (node_id,object_guid,name,adcs_type,forest_id,domain_id) "
            "VALUES (?,?,?,?,?,?)",
            [node, guid, node, atype, FOREST, DOM],
        )

    def edge(kind: str, src: str, tgt: str) -> None:
        con.execute(
            "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,forest_id,domain_id)"
            " VALUES (?,?,?,?,?,?)",
            [f"{kind}:{src}:{tgt}", kind, src, tgt, FOREST, DOM],
        )

    principal("dc", DOM + "-500", "Computer")
    principal("everyone", "S-1-1-0", "Group")
    container("dom", "Domain", DOM, "00000000-0000-0000-0000-0000000000d0")
    adcs("tmpl", "33333333-3333-3333-3333-333333333333", "CertTemplate")
    adcs("ca", "44444444-4444-4444-4444-444444444444", "EnterpriseCA")
    adcs("nts", "55555555-5555-5555-5555-555555555555", "NTAuthStore")

    edge("SameForestTrust", "dom", "dom")
    edge("CrossForestTrust", "dom", "dom")
    edge("HasTrustKeys", "dom", "ghost_trust_user")  # trust-account node absent
    edge("WritePublicInformation", "everyone", "dc")
    edge("WRAITH:SeEnableDelegationPrivilege", "everyone", "dc")
    edge("PublishedTo", "tmpl", "ca")
    edge("TrustedForNTAuth", "ca", "nts")
    edge("WraithESC4TemplateControl", "everyone", "tmpl")
    edge("GenericAll", "everyone", "dc")
    return con


@pytest.fixture()
def synth() -> Iterator[duckdb.DuckDBPyConnection]:
    con = _mk_synth()
    yield con
    con.close()


# ---------------------------------------------------------------------------
# LAYER 1/3 — synthetic Point-5 branches + invariants
# ---------------------------------------------------------------------------
def test_gate_syn_trust_family_postprocess(synth: duckdb.DuckDBPyConnection) -> None:
    _, result = build_export(synth)
    byk = {d.kind: d for d in result.dispositions}
    assert byk["SameForestTrust"].dropped == {"trust_postprocess": 1}
    assert byk["CrossForestTrust"].dropped == {"trust_postprocess": 1}
    assert byk["HasTrustKeys"].dropped == {"trust_postprocess": 1}
    assert result.skip_counts.get("hastrustkeys_user_absent") == 1


def test_gate_syn_native_drops(synth: duckdb.DuckDBPyConnection) -> None:
    _, result = build_export(synth)
    byk = {d.kind: d for d in result.dispositions}
    assert byk["WritePublicInformation"].dropped == {"native": 1}
    assert byk["WRAITH:SeEnableDelegationPrivilege"].dropped == {"native": 1}


def test_gate_syn_esc4_composed_and_no_ca(synth: duckdb.DuckDBPyConnection) -> None:
    _, result = build_export(synth)
    byk = {d.kind: d for d in result.dispositions}
    assert byk["WraithESC4TemplateControl"].dropped == {"esc4_composed": 1}
    # remove the NTAuth trust -> the composite drops as esc4_no_ca instead
    synth.execute("DELETE FROM edge WHERE kind='TrustedForNTAuth'")
    _, result2 = build_export(synth)
    byk2 = {d.kind: d for d in result2.dispositions}
    assert byk2["WraithESC4TemplateControl"].dropped == {"esc4_no_ca": 1}


def test_gate_syn_special_identity_once(synth: duckdb.DuckDBPyConnection) -> None:
    payloads, _ = build_export(synth)
    everyone = [n for n in _data(payloads, "groups") if n["ObjectIdentifier"] == "S-1-1-0"]
    assert len(everyone) == 1  # emitted once, not folded into concrete principals
    dc = next(n for n in _data(payloads, "computers") if n["ObjectIdentifier"] == DOM + "-500")
    aces = {(a["PrincipalSID"], a["RightName"]) for a in cast("list[dict[str, str]]", dc["Aces"])}
    assert ("S-1-1-0", "GenericAll") in aces  # ACE kept pointing AT the special identity


def test_gate_syn_invariants(synth: duckdb.DuckDBPyConnection) -> None:
    _, result = build_export(synth)
    assert result.edges_exported + result.edges_dropped == result.edges_total
    for d in result.dispositions:
        assert d.exported + sum(d.dropped.values()) == d.count
    assert not result.unmapped_kinds


# ---------------------------------------------------------------------------
# LAYER 2 — real DC (structural self-validation oracle)
# ---------------------------------------------------------------------------
def _run_real(con: duckdb.DuckDBPyConnection, out: Path):  # type: ignore[no-untyped-def]  # noqa: ANN202
    from wraith.case.ingest_run import IngestRun
    from wraith.export.pipeline import PipelineInputs, SamHostInput, run_analysis_pipeline

    run = IngestRun("GATE", "tester", ingest_run_id=UUID(int=0x6A7E))
    inputs = PipelineInputs(
        ntds_path=_NTDS,
        forest_id="forest-c137",
        system_hive_path=_SYSTEM if _SYSTEM.is_file() else None,
        sam_hosts=(
            (SamHostInput(sam_path=_SAM, system_hive_path=_SYSTEM),) if _SAM.is_file() else ()
        ),
        sysvol_root=_SYSVOL if _SYSVOL.is_dir() else None,
    )
    return run_analysis_pipeline(con, run, inputs, output_dir=out)


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_gate_real_locked_dispositions(tmp_path: Path) -> None:
    """Re-derive the LOCKED c137.local disposition numbers and the target cross-check."""
    con = duckdb.connect(":memory:")
    try:
        res = _run_real(con, tmp_path / "bh")
        er = res.export_result
        assert er.edges_total == _EXPECT_TOTAL
        assert er.edges_exported == _EXPECT_EXPORTED
        assert er.edges_dropped == _EXPECT_DROPPED
        assert er.edges_exported + er.edges_dropped == er.edges_total
        assert not er.unmapped_kinds
        for d in er.dispositions:
            assert d.exported + sum(d.dropped.values()) == d.count

        # target_not_bh_node cross-check: every such target is a REAL directory
        # object (present in staging_object) but not a BH-modeled node type.
        node_ids = {
            r[0]
            for r in con.execute(
                "SELECT node_id FROM principal UNION ALL SELECT node_id FROM container "
                "UNION ALL SELECT node_id FROM gpo UNION ALL SELECT node_id FROM adcs"
            ).fetchall()
        }
        staging_ids = {r[0] for r in con.execute("SELECT node_id FROM staging_object").fetchall()}
        tnb = sum(d.dropped.get("target_not_bh_node", 0) for d in er.dispositions)
        tur = sum(d.dropped.get("target_unresolved", 0) for d in er.dispositions)
        assert tnb == _EXPECT_TARGET_NOT_BH_NODE
        assert tur == 0  # nothing genuinely unresolved
        # spot-prove: a sample of target_not_bh_node targets ARE staged, non-node objects
        gw_targets = {
            r[0]
            for r in con.execute(
                "SELECT DISTINCT target_node_id FROM edge WHERE kind='GenericWrite'"
            ).fetchall()
        }
        offnode = [t for t in gw_targets if t not in node_ids]
        assert offnode  # there are such targets
        assert all(t in staging_ids for t in offnode)  # all real directory objects
    finally:
        con.close()


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_gate_real_dcsync_set_and_v6(tmp_path: Path) -> None:
    """DCSync holders == gate-05 set (-544/-512/-519) re-added; BH CE v6 conformance."""
    con = duckdb.connect(":memory:")
    try:
        res = _run_real(con, tmp_path / "bh")
        payloads, er = build_export(con)

        # --- DCSync: the 3 holders carry AllExtendedRights+GetChanges+GetChangesAll
        dom_oid = (res.domain_id or "").upper()
        dom = next(n for n in _data(payloads, "domains") if n["ObjectIdentifier"] == dom_oid)
        holder_rights: dict[str, set[str]] = {}
        for a in cast("list[dict[str, str]]", dom["Aces"]):
            holder_rights.setdefault(str(a["PrincipalSID"]), set()).add(str(a["RightName"]))
        for suffix in _DCSYNC_HOLDER_SUFFIXES:
            holder = next(s for s in holder_rights if s.endswith(suffix))
            assert {"AllExtendedRights", "GetChanges", "GetChangesAll"} <= holder_rights[holder]
        dcsync = next(d for d in er.dispositions if d.kind == "DCSync")
        assert dcsync.count == _EXPECT_DCSYNC_COMPOSED
        assert dcsync.exported == 0
        assert dcsync.dropped == {"composed_by_bhce": _EXPECT_DCSYNC_COMPOSED}

        # --- BH CE v6 structural conformance of all 13 files
        assert set(payloads) == set(FILE_TYPES)
        for ftype in FILE_TYPES:
            meta = _meta(payloads, ftype)
            data = _data(payloads, ftype)
            assert set(meta) == {"methods", "type", "count", "version"}
            assert meta["version"] == 6
            assert meta["type"] == ftype
            assert meta["count"] == len(data)
            for n in data:
                assert "ObjectIdentifier" in n and "Properties" in n
                for ace in cast("list[dict[str, object]]", n.get("Aces", [])):
                    assert set(ace) == {"PrincipalSID", "PrincipalType", "RightName", "IsInherited"}

        # --- ObjectIdentifier keying. SID-keyed types (User/Computer/Group/
        # Domain) use the uppercased objectSID when present; a SID-LESS such
        # object falls back to its braced uppercased {objectGUID} rather than
        # being silently dropped (doc 12 §B.3). Every oid is uppercased and is
        # either a SID or a braced GUID.
        #
        # On c137.local every User/Computer/Group is SID-keyed. The only SID-less
        # fallbacks are the TWO DNS application partitions M3 classifies as
        # container_type=Domain (the real domain has a SID; the two partitions do
        # not) -> they land in domains.json keyed by {GUID}. This is the
        # documented, counted M3 carry-forward, NOT a silent bug.
        for ftype in ("users", "computers", "groups"):
            for n in _data(payloads, ftype):
                oid = str(n["ObjectIdentifier"])
                assert oid == oid.upper() and oid.startswith("S-1-"), (ftype, oid)
        domain_guid_fallbacks = 0
        for n in _data(payloads, "domains"):
            oid = str(n["ObjectIdentifier"])
            assert oid == oid.upper()
            is_sid = oid.startswith("S-1-")
            is_guid = oid.startswith("{") and oid.endswith("}")
            assert is_sid or is_guid, oid
            if is_guid:
                domain_guid_fallbacks += 1
        assert domain_guid_fallbacks == 2  # the two DNS app-partitions
        # GUID-keyed types are always braced, uppercased GUIDs.
        for ftype in ("ous", "containers", "gpos"):
            for n in _data(payloads, ftype):
                oid = str(n["ObjectIdentifier"])
                assert oid.startswith("{") and oid.endswith("}") and oid == oid.upper()
    finally:
        con.close()


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_gate_real_determinism_incl_zip(tmp_path: Path) -> None:
    """Two exports of the same store are byte-identical, including the zip."""
    con = duckdb.connect(":memory:")
    try:
        _run_real(con, tmp_path / "pipe")
        export_bloodhound(con, tmp_path / "a")
        export_bloodhound(con, tmp_path / "b")
        for ft in FILE_TYPES:
            assert (tmp_path / "a" / f"{ft}.json").read_bytes() == (
                tmp_path / "b" / f"{ft}.json"
            ).read_bytes()
        assert (tmp_path / "a" / "bloodhound.zip").read_bytes() == (
            tmp_path / "b" / "bloodhound.zip"
        ).read_bytes()
        p1, _ = build_export(con)
        p2, _ = build_export(con)
        assert canonical_json(p1) == canonical_json(p2)
    finally:
        con.close()
