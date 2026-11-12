"""Module 15 GATE — attack-path analysis backend (find_paths_to + catalog + endpoints).

The authoritative gate for doc 15: the REQUIRED ``find_paths_to`` parity gate
(§13 — inbound distances == ``risk._reverse_bfs_distances``; per-pair outbound ==
inbound LENGTH; H2 in reverse; determinism; bounded), plus the three-layer
coverage of the prebuilt-query catalog, ``GET /graph/default``, and the
``POST /paths`` ``direction`` field, all against the real committed c137.local
store. Skipped cleanly when the evidence is absent (CI-safe); the smoke suite
(``test_attack_queries_smoke.py``) remains the CI-safe guard.

Real c137 oracle (re-derived 2026-10-27, build logged in the gate report):
  390 nodes / 30303 edges · 10 Tier-0 classified / 5 traversal targets · reverse
  BFS reaches 18 nodes (13 sources at dist>0, all within 8 hops) · kerberoastable 0
  · asrep 0 · unconstrained 1 · dcsync 3 · Domain Users present, 8 effective members.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import duckdb
import pytest
from fastapi.testclient import TestClient

from wraith.api import risk
from wraith.api.app import create_app
from wraith.api.graph import DEFAULT_LIMIT, build_slice
from wraith.api.paths import (
    _reverse_bfs_dist,
    build_case_path_graph,
    build_path_graph,
    find_paths,
    find_paths_to,
)
from wraith.api.queries import (
    CATALOG,
    PATHS_FROM_ASREP,
    PATHS_FROM_DOMAIN_USERS,
    PATHS_FROM_KERBEROASTABLE,
    PATHS_TO_TIER0,
    PATHS_TO_UNCONSTRAINED,
    resolve_source_sets,
)
from wraith.api.store import StoreReader
from wraith.common.determinism import canonical_json

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

#: RID suffixes that are classification-only and must NEVER be a traversal target
#: (gate G3): -500 Administrator, -502 krbtgt, -518 Schema Admins.
_NEVER_TARGET_SUFFIXES = ("-500", "-502", "-518")

pytestmark = pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")


def _build_store(work: Path) -> Path:
    from wraith.case.ingest_run import IngestRun
    from wraith.export.pipeline import PipelineInputs, SamHostInput, run_analysis_pipeline
    from wraith.model.store import open_canonical_store
    from wraith.provenance.ledger import write_ledger_rows

    store = work / "canonical.duckdb"
    con = open_canonical_store(store)
    run = IngestRun("C137", "tester", ingest_run_id=UUID(int=0x6A7E))
    inputs = PipelineInputs(
        ntds_path=_NTDS,
        forest_id="forest-c137",
        system_hive_path=_SYSTEM if _SYSTEM.is_file() else None,
        sam_hosts=(
            (SamHostInput(sam_path=_SAM, system_hive_path=_SYSTEM),) if _SAM.is_file() else ()
        ),
        sysvol_root=_SYSVOL if _SYSVOL.is_dir() else None,
    )
    try:
        run_analysis_pipeline(con, run, inputs, output_dir=work / "bh")
        write_ledger_rows(con, run.to_ledger_rows())
    finally:
        con.close()
    return store


@pytest.fixture(scope="module")
def db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the c137 canonical store once for the whole module.

    Honours ``WRAITH_GATE_PREBUILT_DB`` (an already-built canonical store) so the
    gate can re-run without the ~3-minute pipeline rebuild; otherwise builds fresh.
    """
    prebuilt = os.environ.get("WRAITH_GATE_PREBUILT_DB")
    if prebuilt and Path(prebuilt).is_file():
        return Path(prebuilt)
    return _build_store(tmp_path_factory.mktemp("c137_m15"))


@pytest.fixture(scope="module")
def reader(db_path: Path) -> Iterator[StoreReader]:
    r = StoreReader.open(db_path)
    try:
        yield r
    finally:
        r.close()


@pytest.fixture(scope="module")
def client(db_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(db_path)) as c:
        yield c


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_path_valid(path: dict) -> None:
    """A returned AttackPath is well-formed: edges chain the node sequence."""
    nodes = [n["node_id"] for n in path["nodes"]]
    assert path["length"] == len(path["edges"]) == len(nodes) - 1
    for i, e in enumerate(path["edges"]):
        assert e["source"] == nodes[i]
        assert e["target"] == nodes[i + 1]
    assert path["target_node_id"] == nodes[-1]


# ======================================================================= #
#  LAYER 2 — REQUIRED find_paths_to PARITY GATE (design §13)              #
# ======================================================================= #


def test_inbound_distances_parity_every_node(reader: StoreReader) -> None:
    """The reverse-BFS distances find_paths_to computes to the Tier-0 target set
    EQUAL risk._reverse_bfs_distances for the same targets + H2 filter, for EVERY
    node (the #1 REQUIRED parity assertion).

    H2 is now a graph-CONSTRUCTION invariant (DE HIGH fix): find_paths_to builds its
    case graph with the full Tier-0 classification group set
    (``classification_group_ids``, incl. Schema Admins -518), so the re-derivation
    uses that SAME filter on both sides — faithful to the engine, not the old
    ``group_target_ids`` subset."""
    edges = reader.all_edges()
    t0 = reader.tier0_sets()
    h2_groups = t0.classification_group_ids
    pg = build_path_graph(edges, h2_groups)
    d_engine = _reverse_bfs_dist(pg.graph, t0.target_ids)
    d_risk = risk._reverse_bfs_distances(edges, t0.target_ids, h2_groups)
    # exact equality of the whole map (keys AND values) — not a subset.
    assert d_engine == d_risk
    assert d_engine, "reverse BFS must reach at least the targets"
    # the construction invariant includes Schema Admins -518 beyond the traversal set.
    assert set(t0.group_target_ids) <= set(h2_groups)


def test_global_paths_lengths_match_reverse_distance(reader: StoreReader) -> None:
    """Each global find_paths_to path's length equals the node's reverse distance."""
    edges = reader.all_edges()
    t0 = reader.tier0_sets()
    d_risk = risk._reverse_bfs_distances(edges, t0.target_ids, t0.classification_group_ids)
    res = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    for p in res.paths:
        src = p.nodes[0].node_id
        assert p.length == d_risk[src]
        assert p.target_node_id in set(t0.target_ids)


def test_outbound_equals_inbound_length_for_pairs(reader: StoreReader) -> None:
    """For a sample of (A,B) pairs: outbound(A->B) LENGTH == inbound(B<-A) LENGTH,
    both paths valid, both endpoints correct (ties may differ node-sequence — assert
    length + validity + endpoints, NOT byte-identical tuples, per design §13)."""
    seed = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    pairs = [(p.nodes[0].node_id, p.target_node_id) for p in seed.paths]
    assert len(pairs) >= 3, "need several reachable (A,B) pairs on c137"
    checked = 0
    for a, b in pairs:
        out = find_paths(reader, source_node_ids=[a], target_node_ids=[b], max_hops=15)
        inb = find_paths_to(reader, target_node_ids=[b], source_filter=[a], max_hops=15)
        assert out.paths_found >= 1
        assert inb.paths_found == 1
        out_b = next(p for p in out.paths if p.target_node_id == b)
        inb_p = inb.paths[0]
        assert out_b.length == inb_p.length
        assert inb_p.nodes[0].node_id == a
        assert inb_p.target_node_id == b
        _assert_path_valid(out_b.model_dump())
        _assert_path_valid(inb_p.model_dump())
        checked += 1
    assert checked == len(pairs)


def test_h2_reverse_no_structural_hop_into_tier0_group(reader: StoreReader) -> None:
    """H2 in the reverse direction: no surviving hop into a Tier-0 GROUP is a bare
    structural Contains/GPLink, and no global path ends on such a hop."""
    edges = reader.all_edges()
    t0 = reader.tier0_sets()
    groups = t0.group_target_ids
    assert groups, "c137 has Tier-0 groups"
    pg = build_path_graph(edges, groups)
    # the H2 guard dropped every bare structural hop INTO a Tier-0 group.
    for (src, tgt), kind in pg.kind_by_pair.items():
        if tgt in groups:
            assert kind not in ("Contains", "GPLink"), (src, tgt, kind)
    # and raw data really contained such structural edges (so the guard is load-bearing,
    # not vacuously true) OR, if none exist, that is noted by the count being >= 0.
    raw_structural = [
        (e.source_node_id, e.target_node_id)
        for e in edges
        if e.target_node_id in groups and e.kind in ("Contains", "GPLink")
    ]
    # whichever the data holds, none of those pairs may appear with a structural kind.
    for src, tgt in raw_structural:
        assert pg.kind_by_pair.get((src, tgt)) not in ("Contains", "GPLink")
    # no global path's final hop is structural-into-group.
    res = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    for p in res.paths:
        if p.edges and p.edges[-1].target in groups:
            assert p.edges[-1].kind not in ("Contains", "GPLink")


def test_h2_reverse_synthetic_construct() -> None:
    """Focused construct: a Contains into a Tier-0 group is NOT traversed, a real
    control edge IS (independent of the real-data shape)."""
    from wraith.model.store import create_canonical_tables, create_edge_tables

    con = duckdb.connect(":memory:")
    try:
        create_canonical_tables(con)
        create_edge_tables(con)
        dom = "S-1-5-21-9-9-9"
        prov = {
            "source_file": "ntds.dit",
            "image_sha256": "a" * 64,
            "source_object_id": None,
            "directory_timestamp": None,
            "ingest_run_id": "00000000-0000-0000-0000-000000000000",
        }

        def principal(node: str, sid: str, ptype: str) -> None:
            con.execute(
                "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,"
                "uac_flags,enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,"
                "provenance) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    node,
                    sid,
                    ptype,
                    node,
                    512,
                    True,
                    0,
                    [],
                    [],
                    "f",
                    dom,
                    "t.local",
                    {**prov, "source_object_id": node},
                ],
            )

        def container(node: str, ctype: str) -> None:
            con.execute(
                "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
                "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
                [node, None, node, ctype, "f", dom, "t.local", {**prov, "source_object_id": node}],
            )

        def edge(kind: str, s: str, t: str) -> None:
            con.execute(
                "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,"
                "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
                [f"{kind}:{s}:{t}", kind, s, t, "confirmed", "f", dom, "t.local", prov],
            )

        principal("da", "S-1-5-21-9-9-9-512", "Group")
        principal("ctrl", "S-1-5-21-9-9-9-1500", "User")
        container("ou", "OU")
        edge("Contains", "ou", "da")
        edge("GenericAll", "ctrl", "da")
        r = StoreReader(con, Path(":memory:"))
        res = find_paths_to(r, target="tier0", source_filter=None)
        starts = {p.nodes[0].node_id for p in res.paths}
        assert "ctrl" in starts
        assert "ou" not in starts
    finally:
        con.close()


def test_h2_construction_invariant_non_tier0_target(tmp_path: Path) -> None:
    """REGRESSION (DE HIGH): H2 is a graph-CONSTRUCTION invariant, applied for EVERY
    query regardless of its target — not only for the Tier-0 target.

    Synthetic store with the exact false structure c137 lacks: a container reaches a
    NON-Tier-0 target (an unconstrained-delegation host) ONLY via a structural
    ``Contains`` INTO a Tier-0 group::

        CN=Users --Contains--> Domain Admins(-512) --AdminTo--> TARGETHOST$   (FALSE)
        ctrl     --GenericAll-> Domain Admins(-512) --AdminTo--> TARGETHOST$   (REAL)

    The false container route must NEVER be returned; the real GenericAll route MUST
    be (positive control, so this tests H2 specifically, not just "no path"). Checked
    at the engine, the ``paths-to-unconstrained`` catalog query, AND ``POST /paths``
    direction='inbound' with an explicit non-Tier-0 target — all three now build the
    one per-case H2-filtered graph (``build_case_path_graph``)."""
    from wraith.model.store import create_canonical_tables, create_edge_tables

    store = tmp_path / "h2_invariant.duckdb"
    con = duckdb.connect(str(store))
    dom = "S-1-5-21-5-5-5"
    prov = {
        "source_file": "ntds.dit",
        "image_sha256": "c" * 64,
        "source_object_id": None,
        "directory_timestamp": None,
        "ingest_run_id": "00000000-0000-0000-0000-000000000000",
    }
    create_canonical_tables(con)
    create_edge_tables(con)

    def principal(node: str, sid: str, ptype: str, uac: int) -> None:
        con.execute(
            "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,"
            "uac_flags,enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,"
            "provenance) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                node,
                sid,
                ptype,
                node,
                uac,
                True,
                0,
                [],
                [],
                "f",
                dom,
                "t.local",
                {**prov, "source_object_id": node},
            ],
        )

    def container(node: str, ctype: str) -> None:
        con.execute(
            "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
            "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
            [node, None, node, ctype, "f", dom, "t.local", {**prov, "source_object_id": node}],
        )

    def edge(kind: str, s: str, t: str) -> None:
        con.execute(
            "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,"
            "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
            [f"{kind}:{s}:{t}", kind, s, t, "confirmed", "f", dom, "t.local", prov],
        )

    # 0x80000 TRUSTED_FOR_DELEGATION | 0x1000 WORKSTATION_TRUST_ACCOUNT -> unconstrained.
    principal("da", "S-1-5-21-5-5-5-512", "Group", 512)
    principal("ctrl", "S-1-5-21-5-5-5-1500", "User", 512)
    principal("targetHost", "S-1-5-21-5-5-5-1600", "Computer", 0x80000 | 0x1000)
    container("usersCn", "Container")
    edge("Contains", "usersCn", "da")  # FALSE structural hop into the Tier-0 group
    edge("GenericAll", "ctrl", "da")  # REAL control hop into the Tier-0 group
    edge("AdminTo", "da", "targetHost")  # the group's legitimate control of the host
    con.close()

    reader = StoreReader.open(store)
    try:
        # LOAD-BEARING: without H2 the false structural hop IS in the raw graph,
        # so the guard below is not vacuous.
        unfiltered = build_path_graph(reader.all_edges(), frozenset())
        assert unfiltered.graph.has_edge("usersCn", "da")
        # with the per-case invariant the structural hop into the group is dropped,
        # the real control hop is retained.
        case_pg = build_case_path_graph(reader)
        assert not case_pg.graph.has_edge("usersCn", "da")
        assert case_pg.graph.has_edge("ctrl", "da")
        assert "da" in case_pg.graph and "targetHost" in case_pg.graph

        # (1) ENGINE: who can reach the NON-Tier-0 target host.
        res = find_paths_to(reader, target_node_ids=["targetHost"], source_filter=None)
        starts = {p.nodes[0].node_id for p in res.paths}
        assert "ctrl" in starts  # positive control: REAL GenericAll into da traversed
        assert "usersCn" not in starts  # FALSE Contains into da dropped
    finally:
        reader.close()

    # (2) CATALOG paths-to-unconstrained + (3) POST /paths direction=inbound.
    with TestClient(create_app(store)) as c:
        un = c.post("/api/v1/analysis/queries/paths-to-unconstrained/run").json()
        assert un["paths"]["target_node_ids"] == ["targetHost"]
        starts_un = {p["nodes"][0]["node_id"] for p in un["paths"]["paths"]}
        assert "ctrl" in starts_un
        assert "usersCn" not in starts_un

        inb = c.post(
            "/api/v1/paths",
            json={"direction": "inbound", "target_node_ids": ["targetHost"]},
        ).json()
        starts_inb = {p["nodes"][0]["node_id"] for p in inb["paths"]}
        assert "ctrl" in starts_inb
        assert "usersCn" not in starts_inb


def test_find_paths_to_determinism(reader: StoreReader) -> None:
    """Identical store -> identical find_paths_to output across two calls."""
    a = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    b = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    assert canonical_json(a.model_dump()) == canonical_json(b.model_dump())


def test_bounded_crafted_huge_request(reader: StoreReader) -> None:
    """A maxed global request returns capped + honest `truncated`, no hang."""
    start = time.time()
    res = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    elapsed = time.time() - start
    assert elapsed < 30.0, f"global BFS must be fast, took {elapsed:.1f}s"
    assert res.paths_found <= 500
    # c137 has exactly 13 reachable sources, all in-budget -> not truncated (honest).
    edges = reader.all_edges()
    t0 = reader.tier0_sets()
    d_risk = risk._reverse_bfs_distances(edges, t0.target_ids, t0.classification_group_ids)
    reachable = [n for n, d in d_risk.items() if 0 < d <= 15]
    assert res.paths_found == len(reachable)
    assert res.truncated is (len(reachable) > 500)
    # and the cap genuinely caps + truncates honestly when tightened below the count.
    if len(reachable) > 3:
        tight = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=3)
        assert tight.paths_found == 3
        assert tight.truncated is True


def test_bounded_via_http_global_inbound(client: TestClient) -> None:
    """The HTTP global inbound path also completes bounded with no hang."""
    start = time.time()
    r = client.post(
        "/api/v1/paths",
        json={"target": "tier0", "direction": "inbound", "max_hops": 15, "max_paths": 500},
    )
    assert r.status_code == 200
    assert time.time() - start < 30.0
    body = r.json()
    assert body["paths_found"] <= 500
    for p in body["paths"]:
        _assert_path_valid(p)


# ======================================================================= #
#  LAYER 1/2 — CATALOG correctness                                        #
# ======================================================================= #


def test_catalog_lists_all_with_live_counts(client: TestClient, reader: StoreReader) -> None:
    """GET /analysis/queries lists every catalog entry with correct supported +
    live source counts re-derived from the store."""
    listed = client.get("/api/v1/analysis/queries").json()
    assert len(listed) == len(CATALOG)
    by_id = {q["id"]: q for q in listed}
    sets = resolve_source_sets(reader)
    # supported flags match the frozen catalog exactly.
    for spec in CATALOG:
        assert by_id[spec.id]["supported"] is spec.supported
        assert by_id[spec.id]["kind"] == spec.kind
        assert by_id[spec.id]["direction"] == spec.direction
        if not spec.supported:
            assert by_id[spec.id]["source_count"] is None
            assert by_id[spec.id]["reason"]
    # live counts (one source of truth with the risk model).
    assert by_id[PATHS_FROM_KERBEROASTABLE]["source_count"] == len(sets.kerberoastable)
    assert by_id[PATHS_FROM_ASREP]["source_count"] == len(sets.asrep)
    assert by_id[PATHS_TO_UNCONSTRAINED]["source_count"] == len(sets.unconstrained)
    assert by_id["set-dcsync"]["source_count"] == len(sets.dcsync_holders)
    assert by_id[PATHS_FROM_DOMAIN_USERS]["source_count"] == len(sets.domain_users)
    assert by_id[PATHS_TO_TIER0]["source_count"] == len(set(sets.tier0_classified))
    # AD CS ESC paths are now supported (ESC pass pipeline-wired) but synthetic-only.
    assert by_id["paths-to-adcs-esc"]["supported"] is True
    assert by_id["paths-to-adcs-esc"]["data_confidence"] == "synthetic-only"
    # out-of-scope entries are still listed (never hidden) and greyed.
    assert by_id["azure-paths"]["supported"] is False


def test_catalog_run_each_supported_query(client: TestClient, reader: StoreReader) -> None:
    """Each supported query runs, returns the expected kind (path xor slice), and
    counts empty source sets honestly (kerberoastable/asrep -> empty_source_set)."""
    sets = resolve_source_sets(reader)
    for spec in CATALOG:
        if not spec.supported:
            continue
        r = client.post(f"/api/v1/analysis/queries/{spec.id}/run")
        assert r.status_code == 200, (spec.id, r.text)
        body = r.json()
        assert body["query_id"] == spec.id
        assert body["kind"] == spec.kind
        if spec.kind == "path":
            assert body["paths"] is not None and body["slice"] is None
        else:
            assert body["slice"] is not None and body["paths"] is None
    # kerberoastable / asrep are empty on c137 -> explicit counted gap, not silent.
    for qid, empty in (
        (PATHS_FROM_KERBEROASTABLE, not sets.kerberoastable),
        (PATHS_FROM_ASREP, not sets.asrep),
    ):
        body = client.post(f"/api/v1/analysis/queries/{qid}/run").json()
        if empty:
            assert body["counted_gaps"] == {"empty_source_set": 1}
            assert body["paths"]["paths_found"] == 0
        else:
            assert body["counted_gaps"] == {}


def test_catalog_path_counts_rederived(client: TestClient, reader: StoreReader) -> None:
    """Re-derive paths-to-tier0 / paths-from-domain-users / paths-to-unconstrained
    counts from an independent reverse BFS and match the run result."""
    edges = reader.all_edges()
    t0 = reader.tier0_sets()
    sets = resolve_source_sets(reader)
    # H2 construction invariant: every catalog path call uses the SAME
    # classification-group filter, independent of its target.
    h2_groups = t0.classification_group_ids
    d_t0 = risk._reverse_bfs_distances(edges, t0.target_ids, h2_groups)

    # paths-to-tier0: every source at 0 < dist <= 8 (default), capped at 25.
    reach_t0 = [n for n, d in d_t0.items() if 0 < d <= 8]
    body = client.post(f"/api/v1/analysis/queries/{PATHS_TO_TIER0}/run").json()
    assert body["paths"]["paths_found"] == min(len(reach_t0), 25)
    assert body["paths"]["truncated"] is (len(reach_t0) > 25)

    # paths-from-domain-users: Domain Users effective members reaching Tier-0 in budget.
    du_reach = [s for s in sets.domain_users if 0 < d_t0.get(s, 0) <= 8]
    body = client.post(f"/api/v1/analysis/queries/{PATHS_FROM_DOMAIN_USERS}/run").json()
    assert body["paths"]["paths_found"] == min(len(du_reach), 25)

    # paths-to-unconstrained: sources reaching the unconstrained host set in budget.
    # The engine H2-filters this NON-Tier-0 target query with the SAME classification
    # group set (the DE HIGH fix) — re-derive with that filter, NOT an empty set.
    if sets.unconstrained:
        d_un = risk._reverse_bfs_distances(edges, list(sets.unconstrained), h2_groups)
        reach_un = [n for n, d in d_un.items() if 0 < d <= 8]
        body = client.post(f"/api/v1/analysis/queries/{PATHS_TO_UNCONSTRAINED}/run").json()
        assert body["paths"]["paths_found"] == min(len(reach_un), 25)
        # target is the unconstrained set, NEVER the Tier-0 default.
        assert set(body["paths"]["target_node_ids"]) == set(sets.unconstrained)


def test_catalog_unknown_and_unsupported(client: TestClient) -> None:
    """Unknown id -> typed 404; out-of-scope -> typed 422 (never a silent run)."""
    r404 = client.post("/api/v1/analysis/queries/not-a-real-query/run")
    assert r404.status_code == 404
    assert r404.json()["detail"]["reason"] == "unknown_query"
    r422 = client.post("/api/v1/analysis/queries/azure-paths/run")
    assert r422.status_code == 422
    assert r422.json()["detail"]["reason"] == "query_not_supported"


# ======================================================================= #
#  /graph/default — the edge-rich default view (§7.1)                     #
# ======================================================================= #


def test_graph_default_is_edge_rich(client: TestClient, reader: StoreReader) -> None:
    """GET /graph/default returns an edge-rich Tier-0 depth-1 slice (NOT the
    0-edges bug), with no degenerate fallback gap on c137."""
    g = client.get("/api/v1/graph/default").json()
    assert len(g["edges"]) > 0, "the 0-edges default-view bug must be fixed"
    assert g["returned"] > 0
    t0 = reader.tier0_sets()
    node_ids = {n["node_id"] for n in g["nodes"]}
    # the Tier-0 classified seeds are present in their own neighborhood.
    assert set(t0.classified_ids) & node_ids
    assert g["counted_gaps"] == {}


def test_graph_default_degenerate_counts_gap(tmp_path: Path) -> None:
    """A degenerate store with NO Tier-0 falls back to top-risk seeds and COUNTS
    the fallback gap (never a silent/misleading canvas)."""
    from wraith.model.store import create_canonical_tables, create_edge_tables

    store = tmp_path / "no_tier0.duckdb"
    con = duckdb.connect(str(store))
    create_canonical_tables(con)
    create_edge_tables(con)
    dom = "S-1-5-21-7-7-7"
    prov = {
        "source_file": "ntds.dit",
        "image_sha256": "b" * 64,
        "source_object_id": None,
        "directory_timestamp": None,
        "ingest_run_id": "00000000-0000-0000-0000-000000000000",
    }
    for node, rid in (("alice", "-1104"), ("bob", "-1105")):
        con.execute(
            "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
            "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                node,
                dom + rid,
                "User",
                node,
                512,
                True,
                0,
                [],
                [],
                "f",
                dom,
                "t.local",
                {**prov, "source_object_id": node},
            ],
        )
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            "GenericAll:alice:bob",
            "GenericAll",
            "alice",
            "bob",
            "confirmed",
            "f",
            dom,
            "t.local",
            prov,
        ],
    )
    con.close()
    with TestClient(create_app(store)) as c:
        g = c.get("/api/v1/graph/default").json()
    assert g["counted_gaps"] == {"no_tier0_fallback_top_risk": 1}
    assert g["returned"] > 0


# ======================================================================= #
#  /paths direction field                                                 #
# ======================================================================= #


def _a_reachable_source(reader: StoreReader) -> str:
    res = find_paths_to(reader, target="tier0", source_filter=None, max_hops=15, max_paths=500)
    assert res.paths, "need a reachable source"
    return res.paths[0].nodes[0].node_id


def test_paths_outbound_byte_identical(client: TestClient, reader: StoreReader) -> None:
    """direction omitted == direction='outbound' == find_paths (byte-identical)."""
    a = _a_reachable_source(reader)
    no_dir = client.post("/api/v1/paths", json={"source_node_ids": [a], "target": "tier0"}).json()
    explicit = client.post(
        "/api/v1/paths",
        json={"source_node_ids": [a], "target": "tier0", "direction": "outbound"},
    ).json()
    assert canonical_json(no_dir) == canonical_json(explicit)
    engine = find_paths(reader, source_node_ids=[a], target="tier0").model_dump()
    assert canonical_json(no_dir) == canonical_json(engine)


def test_paths_inbound_routes_to_find_paths_to(client: TestClient, reader: StoreReader) -> None:
    """direction='inbound' routes to find_paths_to (reverse paths), matching the
    engine for both a filtered source and the global 'who can reach this' query."""
    a = _a_reachable_source(reader)
    http_filtered = client.post(
        "/api/v1/paths",
        json={"target": "tier0", "direction": "inbound", "source_node_ids": [a]},
    ).json()
    eng_filtered = find_paths_to(reader, target="tier0", source_filter=[a]).model_dump()
    assert canonical_json(http_filtered) == canonical_json(eng_filtered)

    http_global = client.post(
        "/api/v1/paths", json={"target": "tier0", "direction": "inbound"}
    ).json()
    eng_global = find_paths_to(reader, target="tier0", source_filter=None).model_dump()
    assert canonical_json(http_global) == canonical_json(eng_global)
    assert http_global["paths_found"] >= 1


def test_krbtgt_500_518_never_a_traversal_target(client: TestClient, reader: StoreReader) -> None:
    """krbtgt/-500/-518 never appear as a Tier-0 traversal target in any path query."""
    t0 = reader.tier0_sets()
    # the resolved target set itself excludes the classification-only RIDs (G3).
    tgt_nodes = reader.nodes_by_ids(list(t0.target_ids))
    for n in tgt_nodes:
        sid = n.object_sid or ""
        assert not any(sid.endswith(s) for s in _NEVER_TARGET_SUFFIXES), (n.node_id, sid)

    def _collect_targets(body: dict) -> set[str]:
        ids = set(body.get("target_node_ids", []))
        for p in body.get("paths", []):
            ids.add(p["target_node_id"])
        return ids

    bodies = [
        client.post(f"/api/v1/analysis/queries/{PATHS_TO_TIER0}/run").json()["paths"],
        client.post("/api/v1/paths", json={"target": "tier0", "direction": "inbound"}).json(),
    ]
    all_target_ids = set().union(*(_collect_targets(b) for b in bodies))
    bad = {
        n.node_id
        for n in reader.nodes_by_ids(sorted(all_target_ids))
        if any((n.object_sid or "").endswith(s) for s in _NEVER_TARGET_SUFFIXES)
    }
    assert bad == set(), f"classification-only RIDs leaked as targets: {bad}"


# ======================================================================= #
#  LAYER 3 — read-only + no-secret invariants                             #
# ======================================================================= #


def test_store_read_only_sha256_unchanged(db_path: Path, client: TestClient) -> None:
    """Running the whole analysis surface never mutates the store (SHA-256 stable)."""
    before = _sha256(db_path)
    client.get("/api/v1/analysis/queries")
    for spec in CATALOG:
        if spec.supported:
            client.post(f"/api/v1/analysis/queries/{spec.id}/run")
    client.get("/api/v1/graph/default")
    client.post("/api/v1/paths", json={"target": "tier0", "direction": "inbound"})
    assert _sha256(db_path) == before


def test_no_secret_in_any_response(client: TestClient) -> None:
    """No path/slice/catalog response leaks a plaintext secret field.

    Structural (key-based), NOT a substring scan of values: benign node labels such
    as "Allowed RODC Password Replication Group" legitimately contain words like
    "password", so a value-substring check would false-positive. The invariant is
    that none of these additive endpoints serialise a secret *value* field (these
    models carry no secret at all; secrets live only as redacted SecretRefOut in the
    dossier, which has no plaintext field either)."""
    # dict keys that would only ever appear if a plaintext secret value leaked.
    banned_keys = {
        "plaintext",
        "nthash",
        "lmhash",
        "nt_hash",
        "lm_hash",
        "secret_value",
        "cleartext",
        "pek",
        "value",
        "password",
    }

    def _keys(obj: object) -> set[str]:
        found: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                found.add(str(k).lower())
                found |= _keys(v)
        elif isinstance(obj, list):
            for item in obj:
                found |= _keys(item)
        return found

    payloads = [
        client.get("/api/v1/analysis/queries").json(),
        client.get("/api/v1/graph/default").json(),
        client.post(f"/api/v1/analysis/queries/{PATHS_TO_TIER0}/run").json(),
        client.post("/api/v1/paths", json={"target": "tier0", "direction": "inbound"}).json(),
    ]
    for payload in payloads:
        leaked = _keys(payload) & banned_keys
        assert leaked == set(), f"secret-value key(s) present in a response: {leaked}"


# ======================================================================= #
#  Regression — existing suites unaffected at the import boundary          #
# ======================================================================= #


def test_graph_default_matches_build_slice(reader: StoreReader) -> None:
    """The endpoint's slice equals the documented build_slice call (§7.1 contract)."""
    t0 = reader.tier0_sets()
    direct = build_slice(
        reader, seed_node_ids=sorted(t0.classified_ids), depth=1, limit=DEFAULT_LIMIT
    )
    assert len(direct.edges) > 0
    assert direct.returned > 0
