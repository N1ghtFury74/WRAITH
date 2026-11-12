"""Forward-wiring #2 — gate ``CrossForestTrust`` traversal in the attack-path engine.

WRAITH must NEVER invent a false cross-forest attack path. Cross-forest access is
blocked by SID filtering BY DEFAULT, so a ``CrossForestTrust`` hop is made
NON-traversable in pathfinding unless the decoded trust facts affirmatively indicate
the SID-filtering guard is down. ``SameForestTrust`` stays fully traversable (no SID
filtering within a forest by default).

These are SYNTHETIC-only tests (the dev store has 0 trusts): they exercise the pure
gating predicate and the ``build_path_graph`` construction gate directly with
constructed edge rows + decoded facts. The production pathfinder currently suppresses
EVERY ``CrossForestTrust`` (M-MS3 does not persist the SID-filtering facts on the §4
edge row yet — see the fact-persistence follow-on), which is the safe conservative
default these tests also pin.
"""

from __future__ import annotations

import networkx as nx

from wraith.api.paths import (
    CROSS_FOREST_TRUST_KIND,
    build_path_graph,
    cross_forest_trust_traversable,
)
from wraith.api.store import EdgeRow
from wraith.edges.cross_domain import decode_trust_attribute_facts
from wraith.edges.derivations import KIND_CROSS_FOREST_TRUST, KIND_SAME_FOREST_TRUST
from wraith.normalize.decoders import (
    TRUST_ATTR_FOREST_TRANSITIVE,
    TRUST_ATTR_QUARANTINED_DOMAIN,
    TRUST_ATTR_TREAT_AS_EXTERNAL,
)


def _edge(edge_id: str, kind: str, src: str, tgt: str) -> EdgeRow:
    """Build a minimal attacker-direction edge row for the pathfinder."""
    return EdgeRow(
        edge_id=edge_id,
        kind=kind,
        source_node_id=src,
        target_node_id=tgt,
        confidence="confirmed",
        is_inherited=False,
        access_mask=None,
        object_type_guid=None,
        derivation=None,
    )


# --- the API literal matches the authoritative edge-derivation kind --------------
def test_cross_forest_kind_literal_matches_derivation() -> None:
    """The API-local kind literal equals the edge module's CrossForestTrust kind."""
    assert CROSS_FOREST_TRUST_KIND == KIND_CROSS_FOREST_TRUST == "CrossForestTrust"
    assert KIND_SAME_FOREST_TRUST == "SameForestTrust"


# --- pure predicate: cross_forest_trust_traversable ------------------------------
def test_predicate_unknown_facts_not_traversable() -> None:
    """No facts at all (None) -> NOT traversable (safe default; never invent a path)."""
    assert cross_forest_trust_traversable(None) is False


def test_predicate_absent_bitmask_not_traversable() -> None:
    """Facts present but raw bitmask absent (None) -> unknown -> NOT traversable."""
    facts = decode_trust_attribute_facts(None)
    assert facts.raw is None
    assert cross_forest_trust_traversable(facts) is False


def test_predicate_quarantined_sid_filtering_on_not_traversable() -> None:
    """SID filtering ON (QUARANTINED_DOMAIN 0x4) -> NOT traversable."""
    facts = decode_trust_attribute_facts(
        TRUST_ATTR_FOREST_TRANSITIVE | TRUST_ATTR_QUARANTINED_DOMAIN
    )
    assert facts.quarantined_sid_filtering is True
    assert cross_forest_trust_traversable(facts) is False


def test_predicate_treat_as_external_not_traversable() -> None:
    """TREAT_AS_EXTERNAL (0x40) applies SID filtering -> NOT traversable."""
    facts = decode_trust_attribute_facts(
        TRUST_ATTR_FOREST_TRANSITIVE | TRUST_ATTR_TREAT_AS_EXTERNAL
    )
    assert facts.treat_as_external is True
    assert cross_forest_trust_traversable(facts) is False


def test_predicate_sid_filtering_off_is_traversable() -> None:
    """Facts present + SID filtering NOT indicated (no quarantine, no treat-as-external)
    -> AFFIRMATIVELY abusable -> traversable."""
    facts = decode_trust_attribute_facts(TRUST_ATTR_FOREST_TRANSITIVE)
    assert facts.raw is not None
    assert facts.quarantined_sid_filtering is False
    assert facts.treat_as_external is False
    assert cross_forest_trust_traversable(facts) is True


# --- build_path_graph construction gate ------------------------------------------
def test_graph_cross_forest_suppressed_by_default() -> None:
    """With no facts map (the production default), a CrossForestTrust is DROPPED from
    the graph and recorded as a suppressed (honest, counted) non-path."""
    edges = [_edge("xf1", KIND_CROSS_FOREST_TRUST, "domA", "domB")]
    pg = build_path_graph(edges)
    assert not pg.graph.has_edge("domA", "domB")
    assert pg.suppressed_cross_forest_trust_ids == frozenset({"xf1"})
    assert ("domA", "domB") not in pg.kind_by_pair


def test_graph_cross_forest_quarantined_suppressed() -> None:
    """A CrossForestTrust whose facts say SID filtering ON is NOT traversed."""
    facts = decode_trust_attribute_facts(TRUST_ATTR_QUARANTINED_DOMAIN)
    edges = [_edge("xf1", KIND_CROSS_FOREST_TRUST, "domA", "domB")]
    pg = build_path_graph(edges, frozenset(), {"xf1": facts})
    assert not pg.graph.has_edge("domA", "domB")
    assert "xf1" in pg.suppressed_cross_forest_trust_ids


def test_graph_cross_forest_abusable_is_traversed() -> None:
    """A CrossForestTrust whose facts say SID filtering OFF IS traversed (edge kept)."""
    facts = decode_trust_attribute_facts(TRUST_ATTR_FOREST_TRANSITIVE)
    edges = [_edge("xf1", KIND_CROSS_FOREST_TRUST, "domA", "domB")]
    pg = build_path_graph(edges, frozenset(), {"xf1": facts})
    assert pg.graph.has_edge("domA", "domB")
    assert pg.suppressed_cross_forest_trust_ids == frozenset()
    assert pg.kind_by_pair[("domA", "domB")] == KIND_CROSS_FOREST_TRUST


def test_graph_same_forest_trust_always_traversed() -> None:
    """SameForestTrust is never gated (no SID filtering within a forest by default)."""
    edges = [_edge("sf1", KIND_SAME_FOREST_TRUST, "domA", "domB")]
    pg = build_path_graph(edges)
    assert pg.graph.has_edge("domA", "domB")
    assert pg.suppressed_cross_forest_trust_ids == frozenset()
    assert pg.kind_by_pair[("domA", "domB")] == KIND_SAME_FOREST_TRUST


def test_no_false_path_through_suppressed_cross_forest() -> None:
    """End-to-end over the built graph: attacker -> domA -CrossForestTrust-> domB.

    With SID filtering unknown/ON the cross-forest hop is absent, so there is NO path
    from the attacker into the foreign domain (no invented cross-forest path). With
    the trust affirmatively abusable the path exists.
    """
    chain = [
        _edge("c1", "GenericAll", "attacker", "domA"),
        _edge("xf1", KIND_CROSS_FOREST_TRUST, "domA", "domB"),
    ]
    # default (unknown facts): no cross-forest path into domB — the foreign domain
    # is never even introduced into the graph (its only in-edge was suppressed).
    suppressed = build_path_graph(chain)
    assert nx.has_path(suppressed.graph, "attacker", "domA")
    assert "domB" not in suppressed.graph
    assert "xf1" in suppressed.suppressed_cross_forest_trust_ids
    # abusable facts: the path now exists.
    facts = decode_trust_attribute_facts(TRUST_ATTR_FOREST_TRANSITIVE)
    abusable = build_path_graph(chain, frozenset(), {"xf1": facts})
    assert nx.has_path(abusable.graph, "attacker", "domB")


def test_mixed_cross_forest_facts_gate_independently() -> None:
    """Each CrossForestTrust edge is gated by its OWN facts (per-edge, deterministic)."""
    on = decode_trust_attribute_facts(TRUST_ATTR_QUARANTINED_DOMAIN)
    off = decode_trust_attribute_facts(TRUST_ATTR_FOREST_TRANSITIVE)
    edges = [
        _edge("xf_on", KIND_CROSS_FOREST_TRUST, "a", "b"),
        _edge("xf_off", KIND_CROSS_FOREST_TRUST, "c", "d"),
        _edge("xf_unknown", KIND_CROSS_FOREST_TRUST, "e", "f"),
    ]
    pg = build_path_graph(edges, frozenset(), {"xf_on": on, "xf_off": off})
    assert pg.graph.has_edge("c", "d")  # abusable -> traversed
    assert not pg.graph.has_edge("a", "b")  # quarantined -> suppressed
    assert not pg.graph.has_edge("e", "f")  # unknown -> suppressed
    assert pg.suppressed_cross_forest_trust_ids == frozenset({"xf_on", "xf_unknown"})


# --- regression: non-trust pathfinding is byte-identical -------------------------
def test_regression_non_trust_graph_unchanged() -> None:
    """A graph with NO trust edges is identical with or without a facts map, and
    nothing is ever suppressed (single-domain pathfinding is untouched)."""
    edges = [
        _edge("e1", "GenericAll", "u", "g"),
        _edge("e2", "MemberOf", "g", "da"),
        _edge("e3", "DCSync", "da", "dom"),
    ]
    a = build_path_graph(edges)
    b = build_path_graph(edges, frozenset(), {"irrelevant": decode_trust_attribute_facts(0x8)})
    assert a.suppressed_cross_forest_trust_ids == frozenset()
    assert b.suppressed_cross_forest_trust_ids == frozenset()
    assert set(a.graph.edges()) == set(b.graph.edges()) == {("u", "g"), ("g", "da"), ("da", "dom")}
    assert a.kind_by_pair == b.kind_by_pair
    assert nx.has_path(a.graph, "u", "dom")


def test_determinism_suppressed_set_stable() -> None:
    """Identical input -> identical suppressed set + graph (determinism)."""
    edges = [
        _edge("xf2", KIND_CROSS_FOREST_TRUST, "a", "b"),
        _edge("xf1", KIND_CROSS_FOREST_TRUST, "c", "d"),
    ]
    first = build_path_graph(edges)
    second = build_path_graph(edges)
    assert first.suppressed_cross_forest_trust_ids == second.suppressed_cross_forest_trust_ids
    assert set(first.graph.edges()) == set(second.graph.edges())
