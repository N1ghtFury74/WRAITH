"""Affected-computers resolution — the REUSE of M5 ``Contains`` + ``GPLink``.

A GPO's affected computers are every computer in the transitive ``Contains*``
closure of each container the GPO is linked to (skipping disabled links). This
module does NOT recompute containment or re-parse ``gPLink``: it consumes the
``Contains`` and ``GPLink`` edges Module 5 already emitted (research 10 §2 — the
reuse that made ``Contains`` load-bearing), so the offline-RSoP union is derived
from one authoritative topology.

All functions here are pure (adjacency maps in, node-id sets out) so the closure
is independently testable and deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def build_contains_adjacency(contains_edges: Iterable[tuple[str, str]]) -> dict[str, set[str]]:
    """Build the ``parent -> {children}`` map from M5 ``Contains`` edges.

    Inputs:
        contains_edges: ``(source_node_id, target_node_id)`` pairs where source
            is the containing object (BloodHound ``Contains`` direction).

    Returns:
        A ``parent_node_id -> set(child_node_id)`` adjacency map.

    Failure modes:
        Never raises.
    """
    adjacency: dict[str, set[str]] = {}
    for parent, child in contains_edges:
        adjacency.setdefault(parent, set()).add(child)
    return adjacency


def descendants(root: str, adjacency: Mapping[str, set[str]]) -> set[str]:
    """Return every node reachable from ``root`` via ``Contains*`` (exclusive).

    Iterative DFS with a visited set, so a (pathological) cycle in the tree
    terminates instead of recursing forever. ``root`` itself is NOT included.

    Inputs:
        root: the container node id to expand from.
        adjacency: the ``parent -> {children}`` map from
            :func:`build_contains_adjacency`.

    Returns:
        The set of all transitive child node ids.

    Failure modes:
        Never raises.
    """
    seen: set[str] = set()
    stack: list[str] = list(adjacency.get(root, ()))
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(adjacency.get(node, ()))
    return seen


def affected_computers(
    container_ids: Iterable[str],
    adjacency: Mapping[str, set[str]],
    computer_nodes: frozenset[str],
) -> set[str]:
    """Return the computer nodes in the ``Contains*`` closure of ``container_ids``.

    The union over each linked container of the transitive-child set, filtered to
    computer principals. A container that contains no computer contributes
    nothing (parity with SharpHound skipping a gPLink with no computer).

    Inputs:
        container_ids: the containers the GPO is (non-disabled) linked to.
        adjacency: the ``Contains`` parent->children map.
        computer_nodes: the set of ``node_id`` that are ``Computer`` principals.

    Returns:
        The set of affected computer node ids.

    Failure modes:
        Never raises.
    """
    affected: set[str] = set()
    for container_id in container_ids:
        for node in descendants(container_id, adjacency):
            if node in computer_nodes:
                affected.add(node)
    return affected
