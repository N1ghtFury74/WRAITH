"""Unit tests for the connect-the-dots engine (Round 1 C, pure core).

Exercises :func:`wraith.api.connector.compute_connectors` over synthetic edge rows
(no store/DuckDB), proving the two-lane split (control ranked above scope), the
mandatory RSoP caveat + ``rsop_not_resolvable`` gap on scope chains, structural-noise
suppression, the H2 guard, weakest-hop confidence, and determinism.
"""

from __future__ import annotations

from wraith.api.connector import (
    DENY_CAVEAT,
    RSOP_CAVEAT,
    build_connector_graph,
    build_connectors,
    compute_connectors,
)
from wraith.api.store import EdgeRow, NodeRow, Tier0Sets


def _edge(edge_id: str, kind: str, src: str, tgt: str, confidence: str = "confirmed") -> EdgeRow:
    return EdgeRow(
        edge_id=edge_id,
        kind=kind,
        source_node_id=src,
        target_node_id=tgt,
        confidence=confidence,
        is_inherited=False,
        access_mask=None,
        object_type_guid=None,
    )


_NODE_INFO = {
    "u": ("User", "alice"),
    "g": ("GPO", "Workstation-Hardening"),
    "ou": ("OU", "OU=Workstations"),
    "ou2": ("OU", "OU=Child"),
    "ou3": ("OU", "OU=Leaf"),
    "grp": ("Group", "GPO-Editors"),
    "dom": ("Domain", "c137.local"),
}


def test_scope_lane_gpo_to_user_carries_rsop_caveat() -> None:
    edges = [
        _edge("e1", "GPLink", "g", "ou"),
        _edge("e2", "Contains", "ou", "u"),
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["u", "g"], _NODE_INFO)

    assert res.scope_count == 1
    assert res.control_count == 0
    scope = res.paths[0]
    assert scope.lane == "scope"
    assert scope.source_node_id == "g" and scope.target_node_id == "u"
    assert scope.caveat == RSOP_CAVEAT
    assert res.via_node_ids == ["ou"]
    assert res.counted_gaps.get("rsop_not_resolvable") == 1
    assert RSOP_CAVEAT in res.caveats and DENY_CAVEAT in res.caveats
    assert res.note is None


def test_control_lane_ranked_above_scope() -> None:
    edges = [
        # control: u -> grp (MemberOf) -> g (GenericAll)
        _edge("c1", "MemberOf", "u", "grp"),
        _edge("c2", "GenericAll", "grp", "g"),
        # scope: g -> ou (GPLink) -> u (Contains)
        _edge("s1", "GPLink", "g", "ou"),
        _edge("s2", "Contains", "ou", "u"),
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["u", "g"], _NODE_INFO)

    assert res.control_count == 1 and res.scope_count == 1
    # Control lane first.
    assert res.paths[0].lane == "control"
    assert res.paths[0].source_node_id == "u" and res.paths[0].target_node_id == "g"
    assert res.paths[0].caveat is None
    assert res.paths[1].lane == "scope"


def test_pure_containment_is_suppressed_as_structural_noise() -> None:
    edges = [
        _edge("e1", "Contains", "ou", "ou2"),
        _edge("e2", "Contains", "ou2", "ou3"),
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["ou", "ou3"], _NODE_INFO)

    assert res.paths == []
    assert res.counted_gaps.get("structural_only_suppressed", 0) >= 1
    assert res.counted_gaps.get("no_connection") == 1
    assert res.note is not None


def test_domain_colocation_not_a_relationship() -> None:
    # Domain contains both a user and a GPO: co-location, never a User<->GPO edge.
    edges = [
        _edge("e1", "Contains", "dom", "u"),
        _edge("e2", "Contains", "dom", "g"),
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["u", "g"], _NODE_INFO)
    # dom->u and dom->g exist, but u->...->g needs reverse Contains which is absent.
    assert res.paths == []
    assert res.counted_gaps.get("no_connection") == 1


def test_h2_blocks_contains_into_tier0_group() -> None:
    # A Contains edge INTO a Tier-0 group must never manufacture a path to it.
    edges = [
        _edge("e1", "Contains", "ou", "grp"),  # grp is Tier-0 group here
        _edge("e2", "Contains", "ou", "u"),
    ]
    cg = build_connector_graph(edges, tier0_group_ids=frozenset({"grp"}))
    assert ("ou", "grp") not in cg.pairs
    res = compute_connectors(cg, ["u", "grp"], _NODE_INFO)
    assert res.paths == []


def test_weakest_hop_confidence_taints_chain() -> None:
    edges = [
        _edge("c1", "MemberOf", "u", "grp", confidence="confirmed"),
        _edge("c2", "AdminTo", "grp", "g", confidence="inferred"),
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["u", "g"], _NODE_INFO)
    assert res.paths[0].confidence == "inferred"


def test_deterministic() -> None:
    edges = [
        _edge("c1", "MemberOf", "u", "grp"),
        _edge("c2", "GenericAll", "grp", "g"),
        _edge("s1", "GPLink", "g", "ou"),
        _edge("s2", "Contains", "ou", "u"),
    ]
    cg = build_connector_graph(edges)
    a = compute_connectors(cg, ["u", "g"], _NODE_INFO)
    b = compute_connectors(cg, ["g", "u"], _NODE_INFO)
    assert a.model_dump() == b.model_dump()


def test_representatives_capped_is_counted() -> None:
    edges = [_edge(f"e{i}", "Contains", "dom", f"n{i}") for i in range(20)]
    node_info = {"dom": ("Domain", "d")} | {f"n{i}": ("User", f"u{i}") for i in range(20)}
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["dom", *(f"n{i}" for i in range(20))], node_info, max_pairs=5)
    assert res.counted_gaps.get("representatives_capped") == 1


def test_mixed_gpo_to_user_chain_is_not_scope() -> None:
    # GPLink + Contains (scope) threaded with a GenericAll (control) hop is NOT a GPO
    # "applies-to" chain: it must be suppressed as structural noise, never labelled
    # scope and stamped with the RSoP caveat. (Caught on real test-1 data: a len-6
    # GPLink->...->GetChangesAll->...->user chain was mis-classified as scope.)
    edges = [
        _edge("e1", "GPLink", "g", "ou"),
        _edge("e2", "Contains", "ou", "grp"),
        _edge("e3", "GenericAll", "grp", "u"),  # control hop in the middle
    ]
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["g", "u"], _NODE_INFO)
    assert res.scope_count == 0
    assert res.paths == []
    assert res.counted_gaps.get("structural_only_suppressed", 0) >= 1
    assert res.counted_gaps.get("no_connection") == 1


def test_over_hop_budget_pair_is_counted_not_dropped() -> None:
    # A reachable control chain longer than max_hops must be COUNTED, never silent.
    edges = [
        _edge("c1", "MemberOf", "u", "n1"),
        _edge("c2", "GenericAll", "n1", "n2"),
        _edge("c3", "GenericAll", "n2", "n3"),
        _edge("c4", "GenericAll", "n3", "g"),
    ]
    node_info = dict(_NODE_INFO) | {
        "n1": ("Group", "g1"),
        "n2": ("Group", "g2"),
        "n3": ("Group", "g3"),
    }
    cg = build_connector_graph(edges)
    res = compute_connectors(cg, ["u", "g"], node_info, max_hops=2)
    assert res.paths == []
    assert res.counted_gaps.get("over_hop_budget") == 1
    assert res.counted_gaps.get("no_connection") == 1


class _StubReader:
    """Minimal duck-typed StoreReader for the build_connectors wrapper (drop counting)."""

    def __init__(self, nodes: list[NodeRow], edges: list[EdgeRow]) -> None:
        self._nodes = nodes
        self._edges = edges

    def all_nodes(self) -> list[NodeRow]:
        return self._nodes

    def all_edges(self) -> list[EdgeRow]:
        return self._edges

    def tier0_sets(self) -> Tier0Sets:
        empty: frozenset[str] = frozenset()
        return Tier0Sets(
            classified_ids=empty,
            target_ids=empty,
            group_target_ids=empty,
            domain_object_ids=empty,
            member_ids=empty,
            gpo_creator_ids=empty,
            classification_group_ids=empty,
        )


def _node(node_id: str, kind: str, label: str) -> NodeRow:
    return NodeRow(
        node_id=node_id,
        kind=kind,
        label=label,
        object_sid=None,
        domain_id=None,
        domain_fqdn=None,
    )


def test_partial_unknown_node_ids_are_counted() -> None:
    # Two of four requested ids are stale (not in the store): malformed input must be
    # counted (unknown_node_ids_dropped), never silently under-represented.
    reader = _StubReader(
        nodes=[_node("u", "User", "alice"), _node("g", "GPO", "GPO1"), _node("ou", "OU", "OU=W")],
        edges=[_edge("e1", "GPLink", "g", "ou"), _edge("e2", "Contains", "ou", "u")],
    )
    res = build_connectors(reader, ["u", "g", "stale1", "stale2"])
    assert res.counted_gaps.get("unknown_node_ids_dropped") == 2
    assert res.retained_node_ids == ["g", "u"]


def test_all_unknown_node_ids_is_empty_set_gap() -> None:
    reader = _StubReader(nodes=[_node("u", "User", "alice")], edges=[])
    res = build_connectors(reader, ["ghost1", "ghost2"])
    assert res.counted_gaps.get("empty_node_set") == 1
    assert "unknown_node_ids_dropped" not in res.counted_gaps  # whole-input drop is its own gap
    assert res.paths == []
