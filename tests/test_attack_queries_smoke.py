"""Smoke checks for the attack-path analysis layer (find_paths_to + catalog).

CI-safe: small in-memory DuckDB stores, no real DC. The authoritative
``find_paths_to`` parity gate (inbound distances == risk reverse BFS; per-node
outbound(A->B) == inbound(A->B); H2 in reverse) is the tester's job — this only
guards the obvious wiring so a regression fails fast.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from wraith.api.paths import find_paths, find_paths_to
from wraith.api.queries import (
    PATHS_FROM_KERBEROASTABLE,
    PATHS_TO_TIER0,
    SET_KERBEROASTABLE,
    list_queries,
    run_query,
)
from wraith.api.store import StoreReader
from wraith.model.store import create_canonical_tables, create_edge_tables

FOREST = "f"
DOM = "S-1-5-21-10-20-30"
PROV = {"source_file": "ntds.dit", "image_sha256": "a" * 64}
_RUN = "00000000-0000-0000-0000-000000000000"


def _mem_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con, StoreReader(con, Path(":memory:"))


def _principal(con: duckdb.DuckDBPyConnection, node: str, sid: str, **kw: object) -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
        "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            node,
            sid,
            kw.get("ptype", "User"),
            kw.get("sam", node),
            kw.get("uac", 512),
            kw.get("enabled", True),
            kw.get("admincount", 0),
            kw.get("spns", []),
            kw.get("sid_history", []),
            FOREST,
            DOM,
            "t.local",
            {**PROV, "source_object_id": node, "directory_timestamp": None, "ingest_run_id": _RUN},
        ],
    )


def _container(con: duckdb.DuckDBPyConnection, node: str, ctype: str, sid: str | None) -> None:
    con.execute(
        "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
        "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
        [
            node,
            sid,
            node,
            ctype,
            FOREST,
            DOM,
            "t.local",
            {**PROV, "source_object_id": node, "directory_timestamp": None, "ingest_run_id": _RUN},
        ],
    )


def _edge(con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str) -> None:
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            f"{kind}:{src}:{tgt}",
            kind,
            src,
            tgt,
            "confirmed",
            FOREST,
            DOM,
            "t.local",
            {**PROV, "source_object_id": None, "directory_timestamp": None, "ingest_run_id": _RUN},
        ],
    )


def test_find_paths_to_parity_with_outbound_single_pair() -> None:
    """Per-pair parity: outbound(A->DA) and inbound(DA<-A) agree on length/target."""
    con, reader = _mem_store()
    try:
        _principal(con, "u", "S-1-5-21-10-20-30-1104", sam="user")
        _principal(con, "g1", "S-1-5-21-10-20-30-1200", ptype="Group", sam="mid")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _edge(con, "MemberOf", "u", "g1")
        _edge(con, "MemberOf", "g1", "da")

        out = find_paths(reader, source_node_ids=["u"], target="tier0")
        inb = find_paths_to(reader, target="tier0", source_filter=["u"])
        assert out.paths_found == inb.paths_found == 1
        assert out.paths[0].length == inb.paths[0].length == 2
        assert out.paths[0].target_node_id == inb.paths[0].target_node_id == "da"
        assert inb.source_node_ids == ["u"]
        assert [e.kind for e in inb.paths[0].edges] == ["MemberOf", "MemberOf"]
    finally:
        con.close()


def test_find_paths_to_global_and_budget_honesty() -> None:
    """Global inbound finds every reachable source; over-budget is not unreachable."""
    con, reader = _mem_store()
    try:
        _principal(con, "u", "S-1-5-21-10-20-30-1104", sam="user")
        _principal(con, "g1", "S-1-5-21-10-20-30-1200", ptype="Group", sam="mid")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _edge(con, "MemberOf", "u", "g1")
        _edge(con, "MemberOf", "g1", "da")

        g = find_paths_to(reader, target="tier0", source_filter=None)
        assert {p.nodes[0].node_id for p in g.paths} == {"u", "g1"}

        tight = find_paths_to(reader, target="tier0", source_filter=["u"], max_hops=1)
        assert tight.paths_found == 0
        assert "da" in tight.over_budget_targets
        assert "da" not in tight.unreachable_targets
    finally:
        con.close()


def test_find_paths_to_h2_reverse_blocks_structural_into_tier0_group() -> None:
    """H2 holds in the reverse BFS: Contains into a Tier-0 group is not a path."""
    con, reader = _mem_store()
    try:
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _container(con, "ou", "OU", None)
        _principal(con, "ctrl", "S-1-5-21-10-20-30-1500", sam="ctrl")
        _edge(con, "Contains", "ou", "da")
        _edge(con, "GenericAll", "ctrl", "da")

        g = find_paths_to(reader, target="tier0", source_filter=None)
        starts = {p.nodes[0].node_id for p in g.paths}
        assert "ctrl" in starts  # real control hop reaches
        assert "ou" not in starts  # structural Contains into the group is dropped
    finally:
        con.close()


def test_catalog_run_and_counted_gaps() -> None:
    """Catalog lists entries, runs a path query, and counts an empty source set."""
    con, reader = _mem_store()
    try:
        _principal(con, "svc", "S-1-5-21-10-20-30-1150", sam="svc", spns=["HTTP/web"])
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _edge(con, "GenericAll", "svc", "da")

        catalog = list_queries(reader)
        by_id = {q.id: q for q in catalog}
        assert by_id[PATHS_TO_TIER0].supported is True
        assert by_id[SET_KERBEROASTABLE].source_count == 1  # svc has an SPN
        assert by_id["paths-to-adcs-esc"].supported is True  # ESC pass is pipeline-wired
        assert by_id["paths-to-adcs-esc"].data_confidence == "synthetic-only"

        res = run_query(reader, PATHS_FROM_KERBEROASTABLE, max_hops=8, max_paths=25)
        assert res.kind == "path"
        assert res.paths is not None and res.paths.paths_found == 1
        assert res.counted_gaps == {}

        # a store with no kerberoastable account -> empty source set is a counted gap
        con2, reader2 = _mem_store()
        try:
            _principal(con2, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
            gap = run_query(reader2, PATHS_FROM_KERBEROASTABLE, max_hops=8, max_paths=25)
            assert gap.counted_gaps == {"empty_source_set": 1}
            assert gap.paths is not None and gap.paths.paths_found == 0
        finally:
            con2.close()
    finally:
        con.close()
