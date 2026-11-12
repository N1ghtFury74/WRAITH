"""Round-1 C GATE — connect-the-dots connector, behavioural on the REAL c137 store.

The coder's :mod:`tests.test_connector_unit` proves the pure core on synthetic edge
rows. THIS suite closes the real-store/behavioural gap the coder flagged: it builds
the SAME committed c137.local canonical store the Module-15 gate uses
(:mod:`tests.test_attack_path_analysis_gate`), then gates the seven behaviours the
feature promises against real AD data:

  1. DETERMINISM   — identical request -> byte-identical ``ConnectorResult``.
  2. H2 INVARIANT  — no returned chain hops ``Contains``/``GPLink`` INTO a Tier-0
                     group, asserted where such raw edges genuinely exist (load-bearing).
  3. DUAL-LANE     — a User+GPO connected via Domain/OU yields a scope chain (RSoP
                     caveat + ``rsop_not_resolvable``); where a real control chain
                     exists it ranks ABOVE scope; pure co-location yields NO chain.
  4. NOISE         — pure Container/OU ``Contains`` chains suppressed
                     (``structural_only_suppressed`` counted).
  5. BOUNDS/PERF   — ``max_hops``/``max_paths``/``max_pairs`` respected,
                     ``representatives_capped`` counted, bounded wall-clock on 30k edges.
  6. HONESTY       — "no connection" is an explicit ``note`` + ``no_connection`` gap,
                     never a silent empty.
  7. HTTP          — the ``POST /api/v1/graph/connector`` route round-trips + is
                     deterministic end-to-end.

Skipped cleanly when the evidence is absent (CI-safe); the unit suite remains the
CI guard. Honours ``WRAITH_GATE_PREBUILT_DB`` so the gate re-runs without the
~3-minute pipeline rebuild.

Real c137 oracle (observed 2026-10-28): 390 nodes / 30303 edges · 3 GPOs, 12 Users,
291 Containers, 1 OU · 5 Tier-0 classification groups · 5 raw ``Contains`` edges INTO
a Tier-0 group (so H2 is load-bearing) · 2 ``GPLink`` edges.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from wraith.api.app import create_app
from wraith.api.connector import (
    DENY_CAVEAT,
    RSOP_CAVEAT,
    build_connector_graph,
    build_connectors,
    compute_connectors,
)
from wraith.api.store import StoreReader
from wraith.common.determinism import canonical_json

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

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
    prebuilt = os.environ.get("WRAITH_GATE_PREBUILT_DB")
    if prebuilt and Path(prebuilt).is_file():
        return Path(prebuilt)
    return _build_store(tmp_path_factory.mktemp("c137_connector"))


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


def _id_by_label(reader: StoreReader, label: str, kind: str | None = None) -> str:
    """Resolve a UNIQUE node id by its display label (fails loudly if ambiguous).

    ``kind`` disambiguates labels that are legitimately shared across object kinds —
    e.g. "Default Domain Policy" names BOTH the modern groupPolicyContainer (kind
    ``GPO``) and the legacy ``domainPolicy`` leaf (surfaced as a ``Base`` object).
    """
    hits = [
        n.node_id
        for n in reader.all_nodes()
        if n.label == label and (kind is None or n.kind == kind)
    ]
    assert len(hits) == 1, f"label {label!r} (kind={kind}) not unique on c137: {len(hits)} hits"
    return hits[0]


def _node_info(reader: StoreReader) -> dict[str, tuple[str, str]]:
    return {n.node_id: (n.kind, n.label) for n in reader.all_nodes()}


# ======================================================================= #
#  1. DETERMINISM                                                          #
# ======================================================================= #


def test_determinism_byte_identical(reader: StoreReader) -> None:
    """Identical request (node order flipped) -> byte-identical ConnectorResult."""
    ricks = _id_by_label(reader, "ricksanchez")
    ddp = _id_by_label(reader, "Default Domain Policy", kind="GPO")
    a = build_connectors(reader, [ricks, ddp])
    b = build_connectors(reader, [ddp, ricks])
    c = build_connectors(reader, [ricks, ddp])
    assert canonical_json(a.model_dump()) == canonical_json(b.model_dump())
    assert canonical_json(a.model_dump()) == canonical_json(c.model_dump())


# ======================================================================= #
#  2. H2 INVARIANT (load-bearing on real data)                            #
# ======================================================================= #


def test_h2_structural_hop_into_tier0_group_dropped(reader: StoreReader) -> None:
    """The 5 raw ``Contains`` edges INTO a Tier-0 group are present in the UNFILTERED
    connector graph (so the guard is not vacuous) and absent from the H2-filtered
    graph. No chain returned for a broad real selection hops structurally into a
    Tier-0 group."""
    edges = reader.all_edges()
    grp = reader.tier0_sets().classification_group_ids
    assert grp, "c137 has Tier-0 classification groups"
    raw_h2 = [
        (e.source_node_id, e.target_node_id)
        for e in edges
        if e.target_node_id in grp and e.kind in ("Contains", "GPLink")
    ]
    assert raw_h2, "c137 must contain raw structural edges INTO a Tier-0 group (load-bearing)"

    cg_unfiltered = build_connector_graph(edges, frozenset())
    assert all((s, t) in cg_unfiltered.pairs for s, t in raw_h2)

    cg = build_connector_graph(edges, grp)
    assert all((s, t) not in cg.pairs for s, t in raw_h2)
    assert not any(cg.graph.has_edge(s, t) for s, t in raw_h2)

    # No returned chain over a broad real selection hops structurally into a Tier-0 group.
    ninfo = _node_info(reader)
    sel = [
        n.node_id
        for n in reader.all_nodes()
        if n.kind in ("User", "GPO", "Group", "OU", "Container")
    ][:40]
    res = compute_connectors(cg, sel, ninfo, max_pairs=40, max_paths=500)
    bad = [
        (e.source, e.target, e.kind)
        for p in res.paths
        for e in p.edges
        if e.target in grp and e.kind in ("Contains", "GPLink")
    ]
    assert bad == [], f"H2 violated: structural hop(s) into a Tier-0 group: {bad}"


# ======================================================================= #
#  3. DUAL-LANE                                                            #
# ======================================================================= #


def test_dual_lane_control_ranked_above_scope(reader: StoreReader) -> None:
    """A User+GPO where BOTH a real control chain and a GPO scope chain exist:
    control is ranked FIRST, scope carries the RSoP caveat + ``rsop_not_resolvable``,
    and the feature-level caveats include both DENY and RSoP."""
    ricks = _id_by_label(reader, "ricksanchez")
    ddp = _id_by_label(reader, "Default Domain Policy", kind="GPO")
    res = build_connectors(reader, [ricks, ddp])

    assert res.control_count >= 1 and res.scope_count >= 1
    # control-lane chains all sort before scope-lane chains.
    lanes = [p.lane for p in res.paths]
    assert lanes == sorted(lanes, key=lambda x: 0 if x == "control" else 1)
    assert res.paths[0].lane == "control"
    assert res.paths[0].source_node_id == ricks and res.paths[0].target_node_id == ddp
    assert res.paths[0].caveat is None

    scope_paths = [p for p in res.paths if p.lane == "scope"]
    for p in scope_paths:
        assert p.caveat == RSOP_CAVEAT
        assert p.source_node_id == ddp  # scope flows GPO -> principal
        assert p.target_node_id == ricks
    assert res.counted_gaps.get("rsop_not_resolvable") == res.scope_count
    assert RSOP_CAVEAT in res.caveats and DENY_CAVEAT in res.caveats
    assert res.note is None


def test_pure_scope_user_gpo_via_domain(reader: StoreReader) -> None:
    """A User with NO control over the GPO, connected only via the Domain/OU scope,
    yields a scope-only chain with the RSoP caveat + gap (never silently empty)."""
    jerry = _id_by_label(reader, "jerrysmith")
    ddp = _id_by_label(reader, "Default Domain Policy", kind="GPO")
    res = build_connectors(reader, [jerry, ddp])

    assert res.control_count == 0
    assert res.scope_count >= 1
    assert all(p.lane == "scope" for p in res.paths)
    scope = res.paths[0]
    assert scope.source_node_id == ddp and scope.target_node_id == jerry
    assert scope.caveat == RSOP_CAVEAT
    # chain inserts hidden intermediates (Domain/containers) as via nodes.
    assert res.via_node_ids
    assert res.counted_gaps.get("rsop_not_resolvable") == res.scope_count


def test_user_user_colocation_is_not_a_relationship(reader: StoreReader) -> None:
    """Two users sharing only containment (same Domain/OU) are co-located, NOT
    connected: no chain, explicit ``no_connection`` note."""
    jerry = _id_by_label(reader, "jerrysmith")
    beth = _id_by_label(reader, "bethsmith")
    res = build_connectors(reader, [jerry, beth])
    assert res.paths == []
    assert res.counted_gaps.get("no_connection") == 1
    assert res.note is not None


# ======================================================================= #
#  4. NOISE SUPPRESSION                                                    #
# ======================================================================= #


def test_pure_containment_chain_suppressed(reader: StoreReader) -> None:
    """A pure Container/OU ``Contains`` chain between two containers is suppressed as
    structural noise (``structural_only_suppressed`` counted; no chain returned)."""
    import networkx as nx

    edges = reader.all_edges()
    grp = reader.tier0_sets().classification_group_ids
    ninfo = _node_info(reader)
    cg = build_connector_graph(edges, grp)
    containers = [n.node_id for n in reader.all_nodes() if n.kind in ("Container", "OU")]

    # Find a deterministic container->container chain of length 2..4 that is pure
    # containment (every node on it is a Container/OU).
    pair: tuple[str, str] | None = None
    for a in sorted(containers):
        for b in sorted(containers):
            if a == b or a not in cg.graph or b not in cg.graph:
                continue
            try:
                node_path = nx.shortest_path(cg.graph, a, b)
            except nx.NetworkXNoPath:
                continue
            if 2 <= len(node_path) - 1 <= 4 and all(
                ninfo[x][0] in ("Container", "OU") for x in node_path
            ):
                pair = (a, b)
                break
        if pair:
            break
    assert pair is not None, "c137 must have a pure container->container Contains chain"

    res = compute_connectors(cg, list(pair), ninfo)
    assert res.paths == []
    assert res.counted_gaps.get("structural_only_suppressed", 0) >= 1
    assert res.counted_gaps.get("no_connection") == 1
    assert res.note is not None


# ======================================================================= #
#  5. BOUNDS / PERF                                                        #
# ======================================================================= #


def test_representatives_capped_counted(reader: StoreReader) -> None:
    """A retained set larger than ``max_pairs`` is capped deterministically and the
    cap is counted (``representatives_capped``)."""
    everyone = sorted(
        n.node_id
        for n in reader.all_nodes()
        if n.kind in ("User", "GPO", "Group", "Container", "OU")
    )
    assert len(everyone) > 5
    res = build_connectors(reader, everyone, max_pairs=5)
    assert res.counted_gaps.get("representatives_capped") == 1


def test_bounds_max_paths_and_wallclock(reader: StoreReader) -> None:
    """max_paths is honoured (honest ``truncated``) and the pairwise BFS on the 30k
    store completes well within budget."""
    sel = sorted(n.node_id for n in reader.all_nodes() if n.kind in ("User", "GPO"))
    edges = reader.all_edges()
    grp = reader.tier0_sets().classification_group_ids
    ninfo = _node_info(reader)
    cg = build_connector_graph(edges, grp)

    start = time.time()
    res = compute_connectors(cg, sel, ninfo, max_pairs=50, max_paths=5)
    elapsed = time.time() - start
    assert elapsed < 10.0, f"connector BFS must be fast on 30k edges, took {elapsed:.2f}s"
    assert len(res.paths) <= 5
    # tightening below the available chain count truncates honestly.
    full = compute_connectors(cg, sel, ninfo, max_pairs=50, max_paths=500)
    assert res.truncated is (len(full.paths) > 5)


def test_max_hops_respected(reader: StoreReader) -> None:
    """No returned chain exceeds ``max_hops``; a tighter budget drops longer chains."""
    ddp = _id_by_label(reader, "Default Domain Policy", kind="GPO")
    jerry = _id_by_label(reader, "jerrysmith")
    res = build_connectors(reader, [ddp, jerry], max_hops=2)
    assert all(p.length <= 2 for p in res.paths)
    # the known scope chain is length 3 -> excluded at max_hops=2, present at >=3.
    wide = build_connectors(reader, [ddp, jerry], max_hops=6)
    assert any(p.length == 3 for p in wide.paths)
    assert all(p.length <= 6 for p in wide.paths)


# ======================================================================= #
#  6. HONESTY — no silent empty + empty-input gap                         #
# ======================================================================= #


def test_unknown_nodes_count_empty_node_set(reader: StoreReader) -> None:
    """All-unknown node ids -> explicit ``empty_node_set`` gap + note, never a
    silent whole-graph walk."""
    res = build_connectors(reader, ["not-a-real-node", "also-fake"])
    assert res.paths == []
    assert res.counted_gaps.get("empty_node_set") == 1
    assert res.note is not None
    assert res.retained_node_ids == []


# ======================================================================= #
#  7. HTTP round-trip via the real route                                  #
# ======================================================================= #


def test_http_connector_endpoint_roundtrip(client: TestClient, reader: StoreReader) -> None:
    """POST /api/v1/graph/connector returns the dual-lane result and is deterministic
    end-to-end (two identical posts -> byte-identical bodies)."""
    ricks = _id_by_label(reader, "ricksanchez")
    ddp = _id_by_label(reader, "Default Domain Policy", kind="GPO")
    body = {"node_ids": [ricks, ddp]}
    r1 = client.post("/api/v1/graph/connector", json=body)
    r2 = client.post("/api/v1/graph/connector", json=body)
    assert r1.status_code == 200, r1.text
    j1 = r1.json()
    assert canonical_json(j1) == canonical_json(r2.json())
    assert j1["control_count"] >= 1 and j1["scope_count"] >= 1
    assert j1["paths"][0]["lane"] == "control"
    assert any(p["lane"] == "scope" and p["caveat"] for p in j1["paths"])
    assert j1["counted_gaps"].get("rsop_not_resolvable") == j1["scope_count"]
