"""Server-side graph slicing for the canvas (M7).

The full forest is NEVER returned. A slice is a bounded, deterministic subgraph
selected by node-kind / edge-kind / tier filters and/or a BFS neighbourhood
around seed nodes (search hits or explicit ids). For slices at/above
:data:`~wraith.api.layout.LAYOUT_THRESHOLD` nodes the server precomputes node
x/y (the spike proved client-side layout stalls past ~2k nodes); small slices
omit positions so the client can lay them out.

Honest truncation (the "never silent" rule at the UI boundary): the slice always
reports ``total_matched`` (the canonical candidate matches before the ``limit`` cap,
plus any ``Base`` endpoints materialized into the returned slice) and ``truncated``
(``returned < total_matched``) so the canvas can show "214 / 390 shown — refine
filters". Determinism: nodes are selected and capped in ``node_id`` order; edges in a
total order.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Sequence

from wraith.api.layout import LAYOUT_THRESHOLD, radial_layout
from wraith.api.models import GraphEdge, GraphNode, GraphSlice
from wraith.api.store import (
    GAP_FOREIGN_SOURCE_ENDPOINT,
    GAP_UNRESOLVED_EDGE_ENDPOINT,
    EdgeRow,
    NodeRow,
    StoreReader,
)

#: Default / maximum node cap for one slice (keeps the canvas fluid).
DEFAULT_LIMIT: int = 1000
MAX_LIMIT: int = 5000
#: Maximum BFS depth around seed nodes.
MAX_DEPTH: int = 6


def _select_slice_edges(
    edges: Sequence[EdgeRow],
    *,
    retained_ids: set[str],
    canonical_ids: set[str],
    edge_kinds: Sequence[str] | None,
    materialize_base: bool,
) -> tuple[list[EdgeRow], set[str]]:
    """Choose the edges for a slice and collect Base endpoints to materialize on demand.

    An edge is always kept when BOTH endpoints are retained (both already visible in
    the slice) — the baseline "edges fully inside the slice" rule. An edge with only
    one retained endpoint is dropped, EXCEPT:

    * when ``materialize_base`` is set AND the non-retained endpoint is NOT a canonical
      node (i.e. a ``Base``-projected / non-modeled ``staging_object`` leaf). Then the
      edge is kept and that endpoint id is returned for on-demand materialization, so a
      drill-in (seeded) expansion shows what the seed controls WITHOUT the endpoint
      dangling (owner decision 2026-10-29: a ``Base`` node renders only as the endpoint
      of an already-included edge, and only on explicit expansion — never in the
      default/bulk canvas).

    An edge whose non-retained endpoint is itself a *canonical* node (filtered or capped
    out of the retained set) is dropped — ordinary slicing, not a dangling-endpoint case
    (that node was deliberately excluded, like any other out-of-slice node).

    Inputs:
        edges: the full edge projection (attacker-direction ``source -> target``).
        retained_ids: the node ids kept in the slice (canonical + any valid seed).
        canonical_ids: the full canonical node id-space (tells a filtered-out canonical
            node apart from a ``Base``/non-canonical endpoint).
        edge_kinds: keep only these edge kinds; all kinds if ``None``/empty.
        materialize_base: when ``True`` (a seeded drill-in), pull ``Base`` endpoints of
            retained nodes' edges into the slice; when ``False`` (default/bulk canvas),
            never — so ``Base`` leaves do not flood a Tier-0-dense view.

    Returns:
        ``(kept_edges, endpoints_to_materialize)`` — the kept edges in input order and
        the set of non-canonical endpoint ids to resolve for materialization (empty when
        ``materialize_base`` is ``False``).

    Failure modes:
        Pure; never raises on content.
    """
    ekind_filter = {k for k in (edge_kinds or [])}
    kept: list[EdgeRow] = []
    to_materialize: set[str] = set()
    for e in edges:
        if ekind_filter and e.kind not in ekind_filter:
            continue
        src, tgt = e.source_node_id, e.target_node_id
        src_ret, tgt_ret = src in retained_ids, tgt in retained_ids
        if src_ret and tgt_ret:
            kept.append(e)
        elif not materialize_base:
            continue  # default/bulk slice: edges fully inside the slice only
        elif src_ret and tgt not in canonical_ids:
            kept.append(e)
            to_materialize.add(tgt)
        elif tgt_ret and src not in canonical_ids:
            kept.append(e)
            to_materialize.add(src)
        # else: the sole non-retained endpoint is a deliberately-excluded canonical
        # node -> drop (ordinary slicing, not a dangling-endpoint case).
    return kept, to_materialize


def _known_adjacency(edges: Sequence[EdgeRow], known: set[str]) -> dict[str, set[str]]:
    """Build an UNDIRECTED adjacency map among known nodes only (for BFS expand)."""
    adj: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        if e.source_node_id in known and e.target_node_id in known:
            if e.source_node_id != e.target_node_id:
                adj[e.source_node_id].add(e.target_node_id)
                adj[e.target_node_id].add(e.source_node_id)
    return adj


def _bfs_neighbourhood(seeds: Sequence[str], adj: dict[str, set[str]], depth: int) -> set[str]:
    """Return the set of nodes within ``depth`` undirected hops of any seed."""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for s in seeds:
        if s not in visited:
            visited.add(s)
            queue.append((s, 0))
    while queue:
        node, d = queue.popleft()
        if d >= depth:
            continue
        for nb in sorted(adj.get(node, ())):
            if nb not in visited:
                visited.add(nb)
                queue.append((nb, d + 1))
    return visited


def build_slice(
    reader: StoreReader,
    *,
    seed_node_ids: Sequence[str] | None = None,
    search: str | None = None,
    node_kinds: Sequence[str] | None = None,
    edge_kinds: Sequence[str] | None = None,
    tier0_only: bool = False,
    depth: int = 1,
    limit: int = DEFAULT_LIMIT,
    layout: str = "auto",
    expand_base_endpoints: bool = True,
) -> GraphSlice:
    """Build one bounded, deterministic graph slice for the canvas.

    The candidate node pool is the CANONICAL id-space only (principal / container /
    gpo / adcs); ``Base``-projected ``staging_object`` leaves are endpoint-only +
    on-demand (owner decision 2026-10-29) and never enter the pool in bulk. On an
    genuine UNFILTERED drill-in (``seed_node_ids`` present, ``expand_base_endpoints``
    set, and NO ``tier0_only``/``node_kinds`` narrowing), a ``Base`` object
    materializes IFF it is the endpoint of an edge whose other end is a retained node
    — so the expansion shows what the seed controls without the edge dangling, yet the
    default/bulk/filtered/narrowed canvas stays canonical.

    Inputs:
        reader: the read-only store accessor.
        seed_node_ids: explicit seed node ids to expand from (BFS). Their presence
            also enables ``Base`` endpoint materialization (a drill-in).
        search: a search string whose hits become additional seeds.
        node_kinds: keep only these node kinds (``User``/``Group``/... ); all if
            omitted.
        edge_kinds: keep only these edge kinds; all if omitted.
        tier0_only: keep only Tier-0 nodes.
        depth: BFS hop radius around the seeds (ignored when no seeds). Clamped to
            ``[0, MAX_DEPTH]``.
        limit: maximum CANONICAL nodes returned (clamped to ``[1, MAX_LIMIT]``);
            materialized ``Base`` endpoints are added beyond this cap so a kept edge
            never dangles.
        layout: ``"auto"`` (positions when node count >= threshold), ``"server"``
            (always precompute), or ``"none"`` (never; client lays out).
        expand_base_endpoints: when ``True`` (default) a seeded, UNFILTERED drill-in
            materializes ``Base`` edge endpoints; set ``False`` for result/filtered
            views (seeded SET queries / hunts, the default canvas) so a seed set does
            not pull in the whole ``Base`` leaf population. Note: ``tier0_only`` and
            ``node_kinds`` ALSO suppress materialization unconditionally (a narrowed
            view is never a drill-in), so only the plain unfiltered
            ``/nodes/{id}/neighbors`` path materializes.

    Returns:
        A :class:`GraphSlice` whose ``total_matched`` is the pre-cap canonical match
        count PLUS any ``Base`` endpoints materialized into the returned slice (so
        ``returned <= total_matched`` always holds and ``truncated`` means exactly
        ``returned < total_matched``), optional
        precomputed node positions, and ``counted_gaps`` surfacing any edge endpoint
        that could not be resolved even via the ``Base`` projection.

    Failure modes:
        Never raises on content; unknown seed/search ids simply yield a small or
        empty slice. Invalid ``layout`` falls back to ``"auto"``. An unresolvable
        materialization endpoint is counted (never a silent drop / dangling node).
    """
    depth = max(0, min(int(depth), MAX_DEPTH))
    limit = max(1, min(int(limit), MAX_LIMIT))

    # The candidate pool is the CANONICAL node id-space only (first-class graph
    # citizens). Base-projected staging_object leaves are endpoint-only + on-demand
    # (owner decision 2026-10-29): they NEVER enter the pool in bulk — on a seeded
    # drill-in they may be materialized below as edge endpoints (so no visible edge
    # dangles), but the default/bulk canvas stays canonical.
    canonical = reader.canonical_nodes()
    node_by_id: dict[str, NodeRow] = {n.node_id: n for n in canonical}
    canonical_ids = set(node_by_id)
    # One Tier-0 classification set drives both the tier0-only filter and the
    # high-value marking (gates G1/G2/H1): RID-suffix principals + the Domain root
    # object + effective members of a Tier-0 group; GPCO (-520) is excluded.
    tier0_ids = set(reader.tier0_sets().classified_ids)

    edges = reader.all_edges()

    # 1) resolve the seeds against the FULL node space so an explicit seed that is a
    # Base object still seeds its own neighbourhood (explicit expansion stays valid).
    requested: list[str] = list(seed_node_ids or [])
    if search:
        requested.extend(h.node_id for h in reader.search(search, MAX_LIMIT))
    seed_rows = reader.nodes_by_ids(sorted(set(requested))) if requested else []
    for n in seed_rows:
        node_by_id.setdefault(n.node_id, n)  # admit a Base seed into the pool
    seeds = sorted(n.node_id for n in seed_rows)
    known = set(node_by_id)  # canonical + any valid (possibly Base) explicit seed

    # 2) resolve the candidate node set
    if seeds:
        adj = _known_adjacency(edges, known)
        candidate_ids = _bfs_neighbourhood(seeds, adj, depth)
    else:
        candidate_ids = set(canonical_ids)  # default canvas: canonical only, no Base

    # 3) apply node-kind / tier filters, then cap
    kind_filter = {k for k in (node_kinds or [])}
    candidates = [
        node_by_id[nid]
        for nid in candidate_ids
        if (not kind_filter or node_by_id[nid].kind in kind_filter)
        and (not tier0_only or nid in tier0_ids)
    ]
    candidates.sort(key=lambda n: n.node_id)

    # ``canonical_total`` is the pre-cap count of CANONICAL candidate matches; it alone
    # drives ``truncated`` (a canonical match was dropped by the cap). The materialized
    # Base endpoints added below are NOT subject to the cap, so they are folded into
    # ``total_matched`` afterwards — keeping the slice's node accounting consistent
    # (``returned <= total_matched``) and ``truncated == returned < total_matched``.
    canonical_total = len(candidates)
    truncated = canonical_total > limit
    retained = candidates[:limit]
    retained_ids = {n.node_id for n in retained}

    # 4) select the slice's edges. On a genuine UNFILTERED drill-in (seeds present,
    # materialization enabled, and NO narrowing filter), also pull in the Base/
    # non-canonical endpoint of a kept edge so it is a real, clickable, dossier-backed
    # node (never dangling). A NARROWED view (``tier0_only`` or ``node_kinds``) is a
    # result/filtered view, not a drill-in: materializing Base there would FLOOD a
    # view the user explicitly narrowed (e.g. a tier0_only slice must not pull the
    # whole Base leaf population back in) and would contradict the filter contract, so
    # it stays canonical-only. The default/bulk canvas (no seeds) is canonical too.
    materialize_base = bool(seeds) and expand_base_endpoints and not tier0_only and not kind_filter
    kept_edges, to_materialize = _select_slice_edges(
        edges,
        retained_ids=retained_ids,
        canonical_ids=canonical_ids,
        edge_kinds=edge_kinds,
        materialize_base=materialize_base,
    )
    # SCOPE GATE (M-MS3): on a source-scoped drill-in, a cross-source edge's far
    # endpoint can be a FOREIGN-source node (not in this scope's id-space). It must
    # never be materialized into a scoped view as a result row, so restrict the
    # materialization set to the reader's scope FIRST (the unscoped reader is a
    # no-op — byte-identical). A foreign endpoint drops out here and is counted
    # separately from a genuinely-unresolvable one.
    in_scope = reader.in_scope_node_ids(sorted(to_materialize))
    foreign_scoped_out = to_materialize - in_scope
    resolved: dict[str, NodeRow] = {n.node_id: n for n in reader.nodes_by_ids(sorted(in_scope))}
    # Counted gap (never a silent drop): an endpoint that cannot be resolved even via
    # the Base projection (post-Fix-A this should be impossible) is counted and its
    # edge is dropped rather than rendered as a dangling / mislabeled node. A
    # foreign-source endpoint (scoped out above) is folded into the same drop so the
    # kept edge never dangles, but is counted under its own honest gap key.
    unresolved = (in_scope - resolved.keys()) | foreign_scoped_out
    if unresolved:
        kept_edges = [
            e
            for e in kept_edges
            if e.source_node_id not in unresolved and e.target_node_id not in unresolved
        ]

    # Fold the materialized Base endpoints (added BEYOND the cap, never truncated) into
    # ``total_matched`` so the slice's node accounting is honest and consistent: every
    # rendered node is counted exactly once. ``resolved`` holds only endpoints actually
    # admitted (unresolved ones are dropped + counted as a gap) and is disjoint from
    # ``retained`` (``_select_slice_edges`` only materializes non-retained, non-canonical
    # endpoints), so ``total_matched == returned`` when nothing was capped and
    # ``returned < total_matched`` iff a canonical match was capped (``truncated``).
    total_matched = canonical_total + len(resolved)

    slice_edges = [
        GraphEdge(
            edge_id=e.edge_id,
            kind=e.kind,
            source=e.source_node_id,
            target=e.target_node_id,
            confidence=e.confidence,
            is_inherited=e.is_inherited,
        )
        for e in kept_edges
    ]
    slice_edges.sort(key=lambda ge: (ge.source, ge.target, ge.kind, ge.edge_id))

    # The rendered node set: retained canonical/seed nodes + materialized Base
    # endpoints, deduplicated and deterministically ordered by node_id.
    out_rows = sorted(
        {**{n.node_id: n for n in retained}, **resolved}.values(),
        key=lambda n: n.node_id,
    )

    # 5) layout decision (over the full rendered node + edge set)
    mode = layout if layout in ("auto", "server", "none") else "auto"
    do_layout = mode == "server" or (mode == "auto" and len(out_rows) >= LAYOUT_THRESHOLD)
    positions: dict[str, tuple[float, float]] = {}
    if do_layout:
        positions = radial_layout(
            [n.node_id for n in out_rows],
            [(ge.source, ge.target) for ge in slice_edges],
        )

    out_nodes = [
        GraphNode(
            node_id=n.node_id,
            kind=n.kind,
            label=n.label,
            object_sid=n.object_sid,
            tier=0 if n.node_id in tier0_ids else None,
            highvalue=n.node_id in tier0_ids,
            x=positions.get(n.node_id, (None, None))[0] if do_layout else None,
            y=positions.get(n.node_id, (None, None))[1] if do_layout else None,
        )
        for n in out_rows
    ]

    # Split the two honest drop reasons: a truly-unresolvable endpoint vs a
    # foreign-source endpoint deliberately scoped out of a per-source view.
    genuinely_unresolved = unresolved - foreign_scoped_out
    counted_gaps: dict[str, int] = {}
    if genuinely_unresolved:
        counted_gaps[GAP_UNRESOLVED_EDGE_ENDPOINT] = len(genuinely_unresolved)
    if foreign_scoped_out:
        counted_gaps[GAP_FOREIGN_SOURCE_ENDPOINT] = len(foreign_scoped_out)
    return GraphSlice(
        nodes=out_nodes,
        edges=slice_edges,
        total_matched=total_matched,
        returned=len(out_nodes),
        truncated=truncated,
        layout="server" if do_layout else "none",
        seed_node_ids=seeds,
        depth=depth,
        counted_gaps=counted_gaps,
    )
