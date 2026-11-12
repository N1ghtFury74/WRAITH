"""M-MS2 — per-source scoping + standalone per-source views (coder-side tests).

All synthetic (contract §6 M-MS2 "needs a real capture to validate: nothing
critical"). Four layers:

* **Single-source parity + zero overhead** — a reader scoped to the only source
  returns results IDENTICAL to the unscoped base reader (nodes, edges, counts,
  graph slice, dossier), and the unscoped reader issues no ``source_observation``
  join (byte-identical SQL path, proven by the untouched existing suite).
* **2-source partition / ZERO bleed** — a store holding two sources' objects
  returns, per source, EXACTLY that source's nodes/edges/gaps; no endpoint leaks
  the other source's rows.
* **Source listing** — ``list_sources`` returns each source + its per-source
  node/edge counts, deterministically ordered by ``dc_label``.
* **Unknown source -> counted empty** — a ``source_id`` that matches no
  observations returns an honest empty view with a counted ``source.unknown_or_empty``
  gap, never a silent empty. Plus per-source coverage aggregation + its gaps.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from wraith.api.dossier import build_dossier
from wraith.api.graph import build_slice
from wraith.api.sources import (
    GAP_COVERAGE_SHA_UNMATCHED,
    list_sources,
    resolve_scoped_reader,
    source_coverage,
)
from wraith.api.store import GAP_UNKNOWN_SOURCE, ScopedStoreReader, StoreReader
from wraith.model.store import (
    create_canonical_tables,
    create_edge_tables,
    create_ledger_table,
)

FOREST = "f"
DOM = "S-1-5-21-10-20-30"
PROV = {
    "source_file": "ntds.dit",
    "image_sha256": "a" * 64,
    "source_object_id": None,
    "directory_timestamp": None,
    "ingest_run_id": "00000000-0000-0000-0000-000000000000",
}


def _mem_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    create_ledger_table(con)
    return con, StoreReader(con, Path(":memory:"))


def _principal(con: duckdb.DuckDBPyConnection, node: str, sid: str, ptype: str = "User") -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
        "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [node, sid, ptype, node, 512, True, 0, [], [], FOREST, DOM, "t.local", PROV],
    )


def _edge(con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str) -> str:
    edge_id = f"{kind}:{src}:{tgt}"
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [edge_id, kind, src, tgt, "confirmed", FOREST, DOM, "t.local", PROV],
    )
    return edge_id


def _observe(
    con: duckdb.DuckDBPyConnection, source_id: str, nodes: list[str], edges: list[str]
) -> None:
    for n in nodes:
        con.execute(
            "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
            "VALUES ('node',?,?,FALSE)",
            [n, source_id],
        )
    for e in edges:
        con.execute(
            "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
            "VALUES ('edge',?,?,FALSE)",
            [e, source_id],
        )


def _source_row(
    con: duckdb.DuckDBPyConnection,
    *,
    source_id: str,
    dc_label: str,
    domain_fqdn: str,
    ntds_sha: str = "ab" * 32,
    system_sha: str | None = None,
) -> None:
    con.execute(
        "INSERT INTO source (source_id,case_id,dc_label,forest_id,domain_id,domain_fqdn,"
        "declared_domain,ntds_image_sha256,system_image_sha256,is_global_catalog,"
        "ingest_run_id,ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,now())",
        [
            source_id,
            "case1",
            dc_label,
            FOREST,
            DOM,
            domain_fqdn,
            domain_fqdn,
            ntds_sha,
            system_sha,
            False,
            "00000000-0000-0000-0000-000000000000",
        ],
    )


def _scoped(base: StoreReader, source_id: str) -> ScopedStoreReader:
    return ScopedStoreReader(base._con, base.db_path, source_id)  # noqa: SLF001


# --------------------------------------------------------------------------- #
#  Layer 1 — single-source parity + zero overhead                              #
# --------------------------------------------------------------------------- #
def test_single_source_scoped_equals_full_view() -> None:
    con, base = _mem_store()
    _principal(con, "n1", f"{DOM}-1001")
    _principal(con, "n2", f"{DOM}-512", ptype="Group")
    e1 = _edge(con, "MemberOf", "n1", "n2")
    # The only source observed EVERY canonical node + edge (Phase-1 shape).
    _observe(con, "src-A", ["n1", "n2"], [e1])
    scoped = _scoped(base, "src-A")

    # Node/edge projections + counts are IDENTICAL to the unscoped reader.
    assert scoped.canonical_nodes() == base.canonical_nodes()
    assert scoped.all_edges() == base.all_edges()
    assert scoped.node_count() == base.node_count() == 2
    assert scoped.edge_count() == base.edge_count() == 1
    assert scoped.node_kind_counts() == base.node_kind_counts()
    assert scoped.edge_kind_counts() == base.edge_kind_counts()
    assert scoped.nodes_page().rows == base.nodes_page().rows
    assert scoped.scope_gaps == {}

    # A whole graph slice + a dossier match the unscoped build exactly.
    assert build_slice(scoped).model_dump() == build_slice(base).model_dump()
    assert build_dossier(scoped, "n2") == build_dossier(base, "n2")


def test_unscoped_base_reader_adds_no_scope_predicate() -> None:
    # The base reader's hook returns None -> no source filter id, so the read methods
    # take their byte-identical pre-M-MS2 path (zero overhead on the common case).
    _, base = _mem_store()
    assert base._source_filter_id() is None  # noqa: SLF001
    assert base._node_pred("node_id") == ("", [])  # noqa: SLF001
    assert base._edge_pred("edge_id") == ("", [])  # noqa: SLF001
    assert base.scope_gaps == {}


# --------------------------------------------------------------------------- #
#  Layer 2 — 2-source partition / ZERO bleed                                   #
# --------------------------------------------------------------------------- #
def _two_source_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con, base = _mem_store()
    # Source A: n1,n2 + edge eA. Source B: n3,n4 + edge eB. Disjoint id-spaces.
    _principal(con, "n1", f"{DOM}-1001")
    _principal(con, "n2", f"{DOM}-512", ptype="Group")
    _principal(con, "n3", f"{DOM}-1002")
    _principal(con, "n4", f"{DOM}-519", ptype="Group")
    ea = _edge(con, "MemberOf", "n1", "n2")
    eb = _edge(con, "MemberOf", "n3", "n4")
    _observe(con, "src-A", ["n1", "n2"], [ea])
    _observe(con, "src-B", ["n3", "n4"], [eb])
    _source_row(con, source_id="src-A", dc_label="DC-A", domain_fqdn="a.local")
    _source_row(con, source_id="src-B", dc_label="DC-B", domain_fqdn="b.local")
    return con, base


def test_two_source_partition_zero_bleed() -> None:
    con, base = _two_source_store()
    a = _scoped(base, "src-A")
    b = _scoped(base, "src-B")

    a_nodes = {n.node_id for n in a.canonical_nodes()}
    b_nodes = {n.node_id for n in b.canonical_nodes()}
    assert a_nodes == {"n1", "n2"}
    assert b_nodes == {"n3", "n4"}
    assert a_nodes.isdisjoint(b_nodes)

    a_edges = {e.edge_id for e in a.all_edges()}
    b_edges = {e.edge_id for e in b.all_edges()}
    assert a_edges == {"MemberOf:n1:n2"}
    assert b_edges == {"MemberOf:n3:n4"}
    assert a_edges.isdisjoint(b_edges)

    # Counts are per-source; the unscoped reader still sees the whole store.
    assert a.node_count() == 2 and a.edge_count() == 1
    assert b.node_count() == 2 and b.edge_count() == 1
    assert base.node_count() == 4 and base.edge_count() == 2


def test_two_source_graph_slice_has_no_foreign_nodes() -> None:
    con, base = _two_source_store()
    a = _scoped(base, "src-A")
    sl = build_slice(a)
    ids = {n.node_id for n in sl.nodes}
    assert ids <= {"n1", "n2"}  # never n3/n4
    assert all(e.source in ids and e.target in ids for e in sl.edges)
    assert all(e.edge_id == "MemberOf:n1:n2" for e in sl.edges)


def test_two_source_dossier_is_source_bound() -> None:
    con, base = _two_source_store()
    a = _scoped(base, "src-A")
    # n1 is source A's -> present; n3 is source B's -> 404 (None) under scope A.
    assert build_dossier(a, "n1") is not None
    assert build_dossier(a, "n3") is None
    # The group n2's inbound MemberOf is only n1 (source A), never a B member.
    d2 = build_dossier(a, "n2")
    assert d2 is not None
    inbound_sources = {e.other.node_id for e in d2.inbound_edges}
    assert inbound_sources == {"n1"}


# --------------------------------------------------------------------------- #
#  Layer 3 — source listing                                                    #
# --------------------------------------------------------------------------- #
def test_list_sources_with_per_source_counts() -> None:
    con, base = _two_source_store()
    result = list_sources(base)
    assert result.count == 2
    # Deterministic order by dc_label.
    assert [s.dc_label for s in result.sources] == ["DC-A", "DC-B"]
    by_id = {s.source_id: s for s in result.sources}
    assert by_id["src-A"].node_count == 2 and by_id["src-A"].edge_count == 1
    assert by_id["src-B"].node_count == 2 and by_id["src-B"].edge_count == 1
    assert by_id["src-A"].domain_fqdn == "a.local"


def test_list_sources_empty_on_pre_multisource_store() -> None:
    _, base = _mem_store()
    # No source rows written.
    assert list_sources(base).count == 0


# --------------------------------------------------------------------------- #
#  Layer 4 — unknown source -> counted empty; per-source coverage              #
# --------------------------------------------------------------------------- #
def test_unknown_source_is_counted_empty_not_silent() -> None:
    con, base = _two_source_store()
    ghost = _scoped(base, "does-not-exist")
    assert ghost.canonical_nodes() == []
    assert ghost.all_edges() == []
    assert ghost.node_count() == 0
    assert ghost.scope_gaps == {GAP_UNKNOWN_SOURCE: 1}
    # The gap rides through the graph slice's counted_gaps (never a silent empty).
    sl = build_slice(ghost)
    assert sl.nodes == []
    # resolve_scoped_reader: omitted source_id -> the base reader unchanged.
    assert resolve_scoped_reader(base, None) is base
    scoped = resolve_scoped_reader(base, "does-not-exist")
    assert scoped.scope_gaps == {GAP_UNKNOWN_SOURCE: 1}


def test_source_coverage_aggregates_ledger_by_sha() -> None:
    con, base = _two_source_store()
    # Give src-A a distinct ntds sha and ledger coverage for it.
    con.execute("UPDATE source SET ntds_image_sha256 = ? WHERE source_id = 'src-A'", ["aa" * 32])
    con.execute(
        "INSERT INTO provenance_ledger "
        "(ingest_run_id,source_file,image_sha256,coverage_counts,skip_counts,ingested_at) "
        "VALUES (?,?,?,?,?,now())",
        [
            "00000000-0000-0000-0000-000000000000",
            "ntds.dit",
            "aa" * 32,
            '{"objects": 5}',
            '{"link_unresolved": 2}',
        ],
    )
    cov = source_coverage(base, "src-A")
    assert cov.coverage_counts == {"objects": 5}
    assert cov.skip_counts == {"link_unresolved": 2}
    assert cov.counted_gaps == {}  # the one sha matched a ledger row
    assert len(cov.artifacts) == 1


def test_source_coverage_unmatched_sha_is_counted() -> None:
    con, base = _two_source_store()
    # src-B's sha has no ledger row -> a counted gap, honest empty coverage.
    cov = source_coverage(base, "src-B")
    assert cov.coverage_counts == {}
    assert cov.counted_gaps.get(GAP_COVERAGE_SHA_UNMATCHED, 0) >= 1


def test_source_coverage_unknown_source_counted() -> None:
    _, base = _mem_store()
    cov = source_coverage(base, "ghost")
    assert cov.coverage_counts == {}
    assert cov.counted_gaps.get(GAP_UNKNOWN_SOURCE) == 1
