"""Deterministic server-side graph layout for large slices.

The spike proved client-side force layout stalls past ~2k nodes, so for slices
above a threshold the server precomputes node ``x``/``y`` and the client renders
positioned nodes. The layout is a **deterministic radial / BFS-shell layout**
(O(n + e)): a root is chosen deterministically, nodes are placed on concentric
rings by hop-distance from the root, and ordered by ``node_id`` within each ring.

Why radial-shell rather than a force simulation: it is cheap enough for forest
scale (no O(n^2) per-iteration physics), it is fully deterministic (no RNG, no
numpy), and distance-from-root is meaningful for attack graphs (the seed sits at
the centre; reachable objects fan outward). Small slices skip this and lay out
on the client; the client may re-run a force layout on the already-sliced set.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from collections.abc import Sequence

#: Node-count threshold at/above which ``layout="auto"`` precomputes positions.
LAYOUT_THRESHOLD: int = 250

#: Radius increment between BFS shells.
_RING_STEP: float = 120.0


def _choose_root(node_ids: Sequence[str], degree: dict[str, int]) -> str:
    """Pick a deterministic layout root: highest degree, ties broken by node_id."""
    return min(node_ids, key=lambda n: (-degree.get(n, 0), n))


def radial_layout(
    node_ids: Sequence[str],
    edges: Sequence[tuple[str, str]],
    *,
    root: str | None = None,
) -> dict[str, tuple[float, float]]:
    """Compute deterministic ``node_id -> (x, y)`` positions via a BFS shell layout.

    Inputs:
        node_ids: the nodes to place (only these receive positions).
        edges: ``(source, target)`` pairs; treated as UNDIRECTED for adjacency so
            the shells reflect reachability regardless of attacker direction.
        root: optional explicit centre; otherwise the highest-degree node
            (ties broken by ``node_id``) is chosen deterministically.

    Returns:
        A ``{node_id: (x, y)}`` map with rounded coordinates. Disconnected nodes
        are placed on an outer ring after the connected shells. Empty input ->
        empty map.

    Failure modes:
        Never raises. Edges referencing nodes outside ``node_ids`` are ignored
        for placement (they only affect which in-set nodes are adjacent).
    """
    ids = sorted(set(node_ids))
    if not ids:
        return {}
    idset = set(ids)
    adj: dict[str, set[str]] = defaultdict(set)
    degree: dict[str, int] = defaultdict(int)
    for s, t in edges:
        if s in idset and t in idset and s != t:
            adj[s].add(t)
            adj[t].add(s)
            degree[s] += 1
            degree[t] += 1

    start = root if (root in idset) else _choose_root(ids, degree)

    # BFS shells from the root (deterministic: neighbours visited in sorted order).
    depth: dict[str, int] = {start: 0}
    queue: deque[str] = deque([start])
    while queue:
        cur = queue.popleft()
        for nxt in sorted(adj[cur]):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                queue.append(nxt)

    # Unreached nodes go to one extra outer shell, ordered by node_id.
    max_depth = max(depth.values()) if depth else 0
    for n in ids:
        if n not in depth:
            depth[n] = max_depth + 1

    shells: dict[int, list[str]] = defaultdict(list)
    for n in ids:
        shells[depth[n]].append(n)

    positions: dict[str, tuple[float, float]] = {}
    for d in sorted(shells):
        members = sorted(shells[d])
        count = len(members)
        radius = d * _RING_STEP
        if d == 0:
            positions[members[0]] = (0.0, 0.0)
            # if multiple at depth 0 (shouldn't happen), spread them
            for i, n in enumerate(members[1:], start=1):
                positions[n] = (
                    round(math.cos(i) * _RING_STEP, 3),
                    round(math.sin(i) * _RING_STEP, 3),
                )
            continue
        for i, n in enumerate(members):
            angle = (2.0 * math.pi * i) / count
            positions[n] = (round(radius * math.cos(angle), 3), round(radius * math.sin(angle), 3))
    return positions
