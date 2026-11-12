"""Coder-side sanity for the AD CS / ESC query-surfacing slice (doc 16 §D).

CI-safe: small in-memory DuckDB stores, no real DC. Proves the three AD CS hunter
queries (``set-adcs-topology`` / ``set-enrollment-rights`` / ``paths-to-adcs-esc``)
now resolve + run with the correct source sets, carry the ``synthetic-only`` badge
on BOTH the catalog listing and the run output, count their degraded branches, and
are deterministic. The tester hardens this (full ``run_analysis_pipeline`` end-to-end
+ GOAD/Certipy parity are the tester's / a later spike's job).
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from wraith.api.queries import (
    ADCS_ENROLLMENT_KINDS,
    ADCS_ESC_KINDS,
    ADCS_TOPOLOGY_KINDS,
    PATHS_TO_ADCS_ESC,
    SET_ADCS_TOPOLOGY,
    SET_ENROLLMENT_RIGHTS,
    list_queries,
    resolve_source_sets,
    run_query,
)
from wraith.api.store import StoreReader
from wraith.model.store import create_canonical_tables, create_edge_tables

FOREST = "f"
DOM = "S-1-5-21-10-20-30"
PROV = {"source_file": "ntds.dit", "image_sha256": "a" * 64}
_RUN = "00000000-0000-0000-0000-000000000000"


def _prov(node: str | None) -> dict[str, object]:
    return {**PROV, "source_object_id": node, "directory_timestamp": None, "ingest_run_id": _RUN}


def _mem_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con, StoreReader(con, Path(":memory:"))


def _principal(con: duckdb.DuckDBPyConnection, node: str, sid: str, ptype: str = "User") -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
        "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [node, sid, ptype, node, 512, True, 0, [], [], FOREST, DOM, "t.local", _prov(node)],
    )


def _container(con: duckdb.DuckDBPyConnection, node: str, ctype: str, sid: str | None) -> None:
    con.execute(
        "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
        "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
        [node, sid, node, ctype, FOREST, DOM, "t.local", _prov(node)],
    )


def _adcs(con: duckdb.DuckDBPyConnection, node: str, adcs_type: str, name: str) -> None:
    con.execute(
        "INSERT INTO adcs (node_id,name,adcs_type,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?)",
        [node, name, adcs_type, FOREST, DOM, "t.local", _prov(node)],
    )


def _edge(
    con: duckdb.DuckDBPyConnection,
    kind: str,
    src: str,
    tgt: str,
    confidence: str = "confirmed",
) -> None:
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            f"{kind}:{src}:{tgt}",
            kind,
            src,
            tgt,
            confidence,
            FOREST,
            DOM,
            "t.local",
            _prov(None),
        ],
    )


def _adcs_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    """A synthetic AD CS fixture: topology + enrollment + one inferred ESC1 edge.

    * topology (3): PublishedTo tpl->ca, TrustedForNTAuth ca->ntauth, EnterpriseCAFor
      ca->domain.
    * enrollment (2 holders): Enroll attacker->tpl, AutoEnroll climber->tpl.
    * ESC composite (1): ADCSESC1 attacker->domain (confidence=inferred).
    * control: GenericAll climber->attacker (so climber reaches the ESC sink in 2 hops).
    """
    con, reader = _mem_store()
    _container(con, "n-domain", "Domain", DOM)
    _principal(con, "n-attacker", f"{DOM}-1105")
    _principal(con, "n-climber", f"{DOM}-1106")
    _adcs(con, "n-tpl", "CertTemplate", "VulnTpl")
    _adcs(con, "n-ca", "EnterpriseCA", "CA")
    _adcs(con, "n-ntauth", "NTAuthStore", "NTAuth")
    # topology
    _edge(con, "PublishedTo", "n-tpl", "n-ca")
    _edge(con, "TrustedForNTAuth", "n-ca", "n-ntauth")
    _edge(con, "EnterpriseCAFor", "n-ca", "n-domain")
    # enrollment rights
    _edge(con, "Enroll", "n-attacker", "n-tpl")
    _edge(con, "AutoEnroll", "n-climber", "n-tpl")
    # inferred ESC composite + a control hop into the attacker
    _edge(con, "ADCSESC1", "n-attacker", "n-domain", confidence="inferred")
    _edge(con, "GenericAll", "n-climber", "n-attacker")
    return con, reader


# --- kind-set truth contract (imported, one source of truth) -----------------


def test_kind_sets_are_disjoint_and_use_engine_constants() -> None:
    assert ADCS_ENROLLMENT_KINDS == {"Enroll", "AutoEnroll"}
    assert "PublishedTo" in ADCS_TOPOLOGY_KINDS and "TrustedForNTAuth" in ADCS_TOPOLOGY_KINDS
    assert "ADCSESC1" in ADCS_ESC_KINDS and "GoldenCert" in ADCS_ESC_KINDS
    # enrollment rights are NOT topology and NOT ESC composites (no overlap).
    assert ADCS_ENROLLMENT_KINDS.isdisjoint(ADCS_TOPOLOGY_KINDS)
    assert ADCS_ENROLLMENT_KINDS.isdisjoint(ADCS_ESC_KINDS)
    assert ADCS_TOPOLOGY_KINDS.isdisjoint(ADCS_ESC_KINDS)


# --- source sets --------------------------------------------------------------


def test_resolve_source_sets_adcs() -> None:
    con, reader = _adcs_store()
    try:
        sets = resolve_source_sets(reader)
        assert sets.adcs_topology_edge_count == 3
        assert set(sets.adcs_topology_endpoint_ids) == {"n-tpl", "n-ca", "n-ntauth", "n-domain"}
        assert set(sets.enrollment_rights_holders) == {"n-attacker", "n-climber"}
        assert set(sets.enrollment_endpoint_ids) == {"n-attacker", "n-climber", "n-tpl"}
        assert set(sets.esc_target_ids) == {"n-domain"}
        assert sets.esc_edge_count == 1
    finally:
        con.close()


# --- catalog listing (badge + live source_count) -----------------------------


def test_catalog_lists_three_adcs_supported_synthetic_only() -> None:
    con, reader = _adcs_store()
    try:
        by_id = {q.id: q for q in list_queries(reader)}
        for qid, expected_count in (
            (SET_ADCS_TOPOLOGY, 3),
            (SET_ENROLLMENT_RIGHTS, 2),
            (PATHS_TO_ADCS_ESC, 1),
        ):
            spec = by_id[qid]
            assert spec.supported is True, qid
            assert spec.data_confidence == "synthetic-only", qid
            assert spec.source_count == expected_count, qid
    finally:
        con.close()


# --- run: non-empty bounded results + badge surfaces on the run output --------


def test_run_set_adcs_topology() -> None:
    con, reader = _adcs_store()
    try:
        res = run_query(reader, SET_ADCS_TOPOLOGY, max_hops=8, max_paths=25)
        assert res.kind == "set" and res.slice is not None
        assert res.data_confidence == "synthetic-only"
        assert res.counted_gaps == {}
        node_ids = {n.node_id for n in res.slice.nodes}
        assert {"n-tpl", "n-ca"} <= node_ids
        kinds = {e.kind for e in res.slice.edges}
        assert kinds <= ADCS_TOPOLOGY_KINDS and "PublishedTo" in kinds
    finally:
        con.close()


def test_run_set_enrollment_rights() -> None:
    con, reader = _adcs_store()
    try:
        res = run_query(reader, SET_ENROLLMENT_RIGHTS, max_hops=8, max_paths=25)
        assert res.kind == "set" and res.slice is not None
        assert res.data_confidence == "synthetic-only"
        assert res.counted_gaps == {}
        node_ids = {n.node_id for n in res.slice.nodes}
        assert {"n-attacker", "n-climber"} <= node_ids
        assert {e.kind for e in res.slice.edges} <= ADCS_ENROLLMENT_KINDS
    finally:
        con.close()


def test_run_paths_to_adcs_esc() -> None:
    con, reader = _adcs_store()
    try:
        res = run_query(reader, PATHS_TO_ADCS_ESC, max_hops=8, max_paths=25)
        assert res.kind == "path" and res.paths is not None
        assert res.data_confidence == "synthetic-only"
        assert res.counted_gaps == {}
        # target is the ESC sink (the Domain), NEVER the Tier-0 default.
        assert set(res.paths.target_node_ids) == {"n-domain"}
        starts = {p.nodes[0].node_id for p in res.paths.paths}
        assert "n-attacker" in starts  # the direct ESC holder reaches the sink
        assert res.paths.paths_found >= 1
    finally:
        con.close()


# --- counted gaps on degraded (non-ADCS) stores ------------------------------


def test_adcs_queries_count_gaps_on_empty_store() -> None:
    con, reader = _mem_store()
    _container(con, "n-domain", "Domain", DOM)
    try:
        topo = run_query(reader, SET_ADCS_TOPOLOGY, max_hops=8, max_paths=25)
        assert topo.counted_gaps == {"no_adcs_topology": 1}
        assert topo.slice is not None and topo.slice.returned == 0

        enroll = run_query(reader, SET_ENROLLMENT_RIGHTS, max_hops=8, max_paths=25)
        assert enroll.counted_gaps == {"no_enrollment_rights": 1}
        assert enroll.slice is not None and enroll.slice.returned == 0

        esc = run_query(reader, PATHS_TO_ADCS_ESC, max_hops=8, max_paths=25)
        assert esc.counted_gaps == {"empty_target_set": 1}
        assert esc.paths is not None and esc.paths.paths_found == 0
        # honesty: a counted gap, NEVER a silent whole-graph fallback.
        assert esc.data_confidence == "synthetic-only"
    finally:
        con.close()


# --- determinism / idempotent re-run -----------------------------------------


def test_adcs_queries_are_deterministic() -> None:
    con, reader = _adcs_store()
    try:
        for qid in (SET_ADCS_TOPOLOGY, SET_ENROLLMENT_RIGHTS, PATHS_TO_ADCS_ESC):
            a = run_query(reader, qid, max_hops=8, max_paths=25).model_dump()
            b = run_query(reader, qid, max_hops=8, max_paths=25).model_dump()
            assert a == b, qid
    finally:
        con.close()
