"""Attack-path finding with networkx over the DuckDB §4 edge table (M7).

Owner-approved: pathfinding runs in **networkx** built from the canonical edge
table — there is NO Neo4j dependency. Edge direction is the *attacker traversal*
direction (``source_node_id -> target_node_id``): a ``MemberOf`` edge points
member -> group, an ACL control edge points controller -> controlled, so a path
from a principal to Domain Admins is a chain of "can act as / can control" steps.

The graph includes ALL edge endpoints (not only modeled nodes) because an
attacker can traverse through directory objects BloodHound does not model; the
returned path nodes are resolved back to labels where known. Cost is capped
(``max_hops`` cutoff, ``max_paths`` cap) and truncation is reported (never
silent). Determinism: the edge read is totally ordered and results are sorted by
(length, node-id tuple), so identical stores yield identical paths.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import networkx as nx

from wraith.api.models import AttackPath, NodeRef, PathEdge, PathResult
from wraith.api.store import EdgeRow, StoreReader
from wraith.api.tiering import (
    MAX_PATH_HOPS,
    MAX_PATH_RESULTS,
    is_false_group_control_edge,
)
from wraith.edges.cross_domain import TrustAttributeFacts

#: Default ceilings so a query over a forest-scale graph cannot hang the server.
DEFAULT_MAX_HOPS: int = 8
DEFAULT_MAX_PATHS: int = 25

#: Enumeration bound (reviewer MAJOR): the all-simple-paths walk is halted once
#: this many paths have been collected, so the cap limits WORK (not just output)
#: and a crafted request cannot hang/OOM the server. We over-sample ``max_paths``
#: so the shortest-first ranking still has candidates, bounded by a hard ceiling.
ENUM_OVERSAMPLE: int = 4
HARD_ENUM_CEILING: int = 2000

#: When choosing a single kind to label a hop, prefer these first (traversal
#: readability) then fall back to the lexicographically-first kind.
_KIND_PRIORITY: tuple[str, ...] = ("MemberOf", "DCSync", "AdminTo", "GenericAll", "Owns")

#: The attack-direction cross-forest trust edge kind (``wraith.edges.derivations.
#: KIND_CROSS_FOREST_TRUST``). Kept as a local literal so the API layer need not
#: depend on the edge-derivation kind catalogue; asserted equal in tests. A
#: ``CrossForestTrust`` hop is gated at graph construction (never traversed by
#: default — see :func:`cross_forest_trust_traversable`); ``SameForestTrust`` has
#: no such guard (no SID filtering within a forest by default) and stays fully
#: traversable.
CROSS_FOREST_TRUST_KIND: str = "CrossForestTrust"


@dataclass(frozen=True)
class PathGraph:
    """A built directed attack graph plus the per-edge kind/id lookups.

    ``suppressed_cross_forest_trust_ids`` records the ``edge_id`` of every
    ``CrossForestTrust`` edge that was EXCLUDED from traversal by the SID-filtering
    guard (:func:`cross_forest_trust_traversable`). Those are honest, counted
    non-paths — a cross-forest hop SID filtering blocks must never become a path —
    not silent drops; callers can surface the count. Defaults to the empty set so
    existing constructors keep working.
    """

    graph: nx.DiGraph
    kind_by_pair: dict[tuple[str, str], str]
    edge_id_by_pair: dict[tuple[str, str], str]
    suppressed_cross_forest_trust_ids: frozenset[str] = frozenset()


def cross_forest_trust_traversable(facts: TrustAttributeFacts | None) -> bool:
    """Decide whether a ``CrossForestTrust`` edge may be WALKED in pathfinding.

    Forensically conservative default (the single most important rule here):
    cross-forest access is blocked by **SID filtering BY DEFAULT**, so a
    ``CrossForestTrust`` is NON-traversable unless the decoded trust facts
    AFFIRMATIVELY indicate the SID-filtering guard is down. Walking it
    unconditionally would manufacture a FALSE cross-forest attack path — the worst
    possible output for a hunter — because SID filtering actually blocks that access.

    Inputs:
        facts: the decoded :class:`~wraith.edges.cross_domain.TrustAttributeFacts`
            for this trust (its ``trustAttributes`` bitmask), or ``None`` when the
            facts are unknown / not available to the pathfinder.

    Returns:
        ``True`` ONLY when a ``trustAttributes`` bitmask was actually observed AND it
        does NOT indicate SID filtering — i.e. ``quarantined_sid_filtering`` (``0x4``)
        is clear AND ``treat_as_external`` (``0x40``) is clear. ``False`` for:

        * ``facts is None`` or ``facts.raw is None`` — unknown/absent facts (the safe
          default; never invent a path);
        * ``quarantined_sid_filtering`` set — SID filtering is ON (external quarantine);
        * ``treat_as_external`` set — the trust is treated as external, SID filtering
          applied.

    Failure modes:
        Never raises. Pure; deterministic.

    FORENSIC CAVEAT (flagged for the domain-expert): the ``trustAttributes`` bits
    alone do not carry a positive "SID history filtering disabled" signal for a
    forest trust (the ``netdom /enablesidhistory`` state is not encoded here), so the
    "not-quarantined => abusable" reading is the weaker end of safe. This branch is
    DORMANT in production today: M-MS3 does NOT persist these facts on the §4 edge
    row, so the pathfinder sees ``None`` for every cross-forest trust and suppresses
    them all. The exact affirmative-abusable predicate must be re-locked with a
    domain-expert once the facts are persisted on the edge and real forest captures
    exist (see the M-MS3 fact-persistence follow-on).
    """
    if facts is None or facts.raw is None:
        return False
    if facts.quarantined_sid_filtering or facts.treat_as_external:
        return False
    return True


def _pick_kind(kinds: Sequence[str]) -> str:
    """Pick a deterministic representative kind for a multi-kind hop."""
    for preferred in _KIND_PRIORITY:
        if preferred in kinds:
            return preferred
    return sorted(kinds)[0]


def build_path_graph(
    edges: Sequence[EdgeRow],
    tier0_group_ids: frozenset[str] = frozenset(),
    cross_forest_trust_facts: Mapping[str, TrustAttributeFacts] | None = None,
) -> PathGraph:
    """Build the attacker-direction :class:`PathGraph` from edge rows.

    Parallel edges between the same pair collapse to one directed edge; the hop's
    display kind/id is chosen deterministically (:func:`_pick_kind`, lowest
    ``edge_id``). Self-loops are dropped (they never advance a path).

    Gate H2: a ``Contains``/``GPLink`` edge INTO a Tier-0 *group*
    (``tier0_group_ids``) is dropped — containing or GP-linking a group does not
    grant control of its membership, so such a hop would manufacture a false path
    to Tier-0. Those edges are retained everywhere else (push-down onto
    computer/user children, structure between non-group nodes).

    Cross-forest-trust gate (forensic): a ``CrossForestTrust`` edge is dropped
    UNLESS the decoded trust facts for that ``edge_id`` affirmatively say the
    SID-filtering guard is down (:func:`cross_forest_trust_traversable`). Cross-forest
    access is SID-filtered by default, so an ungated walk would invent a FALSE
    cross-forest path. ``cross_forest_trust_facts`` maps ``edge_id -> TrustAttributeFacts``;
    an ``edge_id`` absent from the map (or a ``None`` facts value) is treated as
    unknown facts -> NOT traversable. ``SameForestTrust`` is NEVER gated here (no SID
    filtering within a forest by default). Suppressed cross-forest edge ids are
    recorded on the returned :class:`PathGraph` (honest, counted non-paths).

    Inputs:
        edges: the §4 edge rows (attacker direction ``source -> target``).
        tier0_group_ids: Tier-0 group node ids whose inbound structural edges are
            false control hops (H2).
        cross_forest_trust_facts: optional ``edge_id -> TrustAttributeFacts`` map
            gating ``CrossForestTrust`` traversal. ``None``/empty (the current
            production default, since M-MS3 does not yet persist these facts on the
            edge row) suppresses EVERY ``CrossForestTrust`` edge — the safe
            conservative default.

    Returns:
        A :class:`PathGraph`. Never raises.
    """
    facts_by_edge = cross_forest_trust_facts or {}
    graph = nx.DiGraph()
    pair_kinds: dict[tuple[str, str], list[str]] = {}
    pair_edge_ids: dict[tuple[str, str], str] = {}
    suppressed_cross_forest: set[str] = set()
    for e in edges:
        if e.source_node_id == e.target_node_id:
            continue
        if is_false_group_control_edge(e.kind, e.target_node_id, tier0_group_ids):
            continue
        if e.kind == CROSS_FOREST_TRUST_KIND and not cross_forest_trust_traversable(
            facts_by_edge.get(e.edge_id)
        ):
            # SID filtering blocks (or is unproven on) this cross-forest trust ->
            # never traverse it (never invent a false cross-forest path). Counted.
            suppressed_cross_forest.add(e.edge_id)
            continue
        pair = (e.source_node_id, e.target_node_id)
        pair_kinds.setdefault(pair, []).append(e.kind)
        prev = pair_edge_ids.get(pair)
        if prev is None or e.edge_id < prev:
            pair_edge_ids[pair] = e.edge_id
        graph.add_edge(e.source_node_id, e.target_node_id)
    kind_by_pair = {pair: _pick_kind(ks) for pair, ks in pair_kinds.items()}
    return PathGraph(
        graph=graph,
        kind_by_pair=kind_by_pair,
        edge_id_by_pair=pair_edge_ids,
        suppressed_cross_forest_trust_ids=frozenset(suppressed_cross_forest),
    )


def build_case_path_graph(reader: StoreReader) -> PathGraph:
    """Build the ONE per-case H2-filtered attack graph (design §6 / §14 [HIGH]).

    H2 is a graph-CONSTRUCTION invariant, not a per-query option: the H2-protected
    group set is ALWAYS the full Tier-0 classification group set
    (:data:`~wraith.api.tiering.TIER0_GROUP_SUFFIXES`, i.e. -512/-519/-544/-516 +
    Schema Admins -518), independent of any query's target. Callers build this once
    per case and pass it via the ``path_graph`` param to :func:`find_paths` /
    :func:`find_paths_to` so a structural ``Contains``/``GPLink`` into a Tier-0
    group can never manufacture a false path — even for a non-Tier-0 target
    (``paths-to-unconstrained``, node-to-node, per-node inbound). Also removes the
    redundant per-call graph rebuild.

    Cross-forest-trust gate (forensic, M-MS3 follow-on): this builds the graph with
    NO ``cross_forest_trust_facts`` map, so EVERY ``CrossForestTrust`` edge is
    suppressed from traversal (the safe conservative default — never invent a false
    cross-forest path that SID filtering actually blocks). This is deliberate: the
    §4 ``edge`` row the reader projects (``StoreReader.all_edges``) does NOT carry the
    decoded SID-filtering facts (``quarantined_sid_filtering`` / ``treat_as_external``)
    — M-MS3 surfaced them only on ``CrossDomainResult`` counters, not on the edge. To
    ENABLE fact-gated cross-forest traversal, those facts must first be persisted on
    (or joinable to) the ``CrossForestTrust`` edge row, after which this function
    would build and pass the ``edge_id -> TrustAttributeFacts`` map. Until then the
    only correct behaviour is full suppression. ``SameForestTrust`` is unaffected.

    Inputs:
        reader: the read-only store accessor.

    Returns:
        The H2-filtered :class:`PathGraph` for the whole case (with every
        ``CrossForestTrust`` suppressed from traversal). Never raises.
    """
    return build_path_graph(reader.all_edges(), reader.tier0_sets().classification_group_ids)


def _resolve_targets(
    reader: StoreReader,
    target: str | None,
    explicit_ids: Sequence[str] | None,
) -> list[str]:
    """Resolve the pathfinding TARGET node-id set (the sink of a query).

    The default ``"tier0"`` target resolves to the Tier-0 traversal set — the
    Tier-0 groups (-512/-519/-544/-516) PLUS the Domain root object (gates G1/G3).
    Explicit ids / a specific node id resolve to themselves.

    NOTE (design §14 [HIGH]): the H2-protected group set is NO LONGER derived here
    from the query target — H2 is a graph-CONSTRUCTION invariant applied over the
    full Tier-0 classification group set (:func:`build_case_path_graph`), so this
    function resolves ONLY the targets. Never raises.
    """
    if explicit_ids:
        return sorted(set(explicit_ids))
    if target and target not in ("tier0", "tier-0", "t0"):
        return [target]
    return list(reader.tier0_sets().target_ids)


def _path_to_model(
    pg: PathGraph,
    node_path: list[str],
    labels: dict[str, NodeRef],
    target_node_id: str,
) -> AttackPath:
    """Convert a node-id path into an :class:`AttackPath` with hop kinds."""
    refs = [labels.get(n, NodeRef(node_id=n, kind="Unknown", label=n)) for n in node_path]
    hops: list[PathEdge] = []
    for a, b in zip(node_path, node_path[1:], strict=False):
        hops.append(
            PathEdge(
                source=a,
                target=b,
                kind=pg.kind_by_pair.get((a, b), "Unknown"),
                edge_id=pg.edge_id_by_pair.get((a, b)),
            )
        )
    tgt_ref = labels.get(target_node_id)
    return AttackPath(
        nodes=refs,
        edges=hops,
        length=len(hops),
        target_node_id=target_node_id,
        target_label=tgt_ref.label if tgt_ref else target_node_id,
    )


def find_paths(
    reader: StoreReader,
    *,
    source_node_ids: Sequence[str],
    target: str | None = "tier0",
    target_node_ids: Sequence[str] | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_paths: int = DEFAULT_MAX_PATHS,
    all_simple: bool = False,
    path_graph: PathGraph | None = None,
) -> PathResult:
    """Find attacker paths from source principal(s) to Tier-0 (or a chosen) target.

    Inputs:
        reader: the read-only store accessor.
        source_node_ids: one or more starting principal node ids.
        target: ``"tier0"`` (the default headline query: the Tier-0 groups
            Domain/Enterprise Admins + builtin Administrators + Domain Controllers,
            PLUS the Domain root object) or a specific target node id.
        target_node_ids: explicit target id set (overrides ``target``).
        max_hops: cutoff path length (hop count); clamped to ``[1, MAX_PATH_HOPS]``.
        max_paths: maximum number of paths returned (ranked shortest-first);
            clamped to ``[1, MAX_PATH_RESULTS]``.
        all_simple: when ``True`` enumerate simple paths up to ``max_hops`` (the
            enumeration itself is bounded — see :data:`HARD_ENUM_CEILING` — so the
            cap limits WORK, not just output); otherwise return one shortest path
            per reachable source/target.
        path_graph: a prebuilt :class:`PathGraph` (else built from the store with
            the H2 Tier-0-group filter applied).

    Returns:
        A :class:`PathResult`; ``truncated`` is ``True`` if more paths existed than
        were returned (ranking cap) OR the enumeration ceiling was hit.
        ``unreachable_targets`` are targets with no path at all;
        ``over_budget_targets`` are targets that ARE reachable but only beyond
        ``max_hops`` (honestly distinct — a reachable Tier-0 is never mislabeled
        unreachable).

    Failure modes:
        Never raises on graph content; unknown source/target ids simply yield no
        paths. ``max_hops``/``max_paths`` are clamped into their bounds.
    """
    max_hops = min(max(1, int(max_hops)), MAX_PATH_HOPS)
    max_paths = min(max(1, int(max_paths)), MAX_PATH_RESULTS)
    enum_ceiling = min(HARD_ENUM_CEILING, max(max_paths * ENUM_OVERSAMPLE, max_paths))
    sources = sorted(set(source_node_ids))
    targets = _resolve_targets(reader, target, target_node_ids)

    # H2 is a construction invariant (design §14): the fallback graph is built over
    # the full Tier-0 classification group set, not a per-target group subset.
    pg = path_graph or build_case_path_graph(reader)
    graph = pg.graph

    found: list[AttackPath] = []
    truncated = False
    reached: set[str] = set()
    over_budget: set[str] = set()
    unreachable: set[str] = set()

    raw_paths: list[tuple[int, list[str], str]] = []
    hit_ceiling = False

    def _reachable_beyond_budget(tgt: str) -> bool:
        """Is ``tgt`` reachable from some source at all (ignoring the hop budget)?"""
        return any(src in graph and src != tgt and nx.has_path(graph, src, tgt) for src in sources)

    for tgt in targets:
        if tgt not in graph:
            unreachable.add(tgt)
            continue
        tgt_reached = False
        tgt_reachable = False
        for src in sources:
            if src not in graph or src == tgt:
                continue
            if all_simple:
                for p in nx.all_simple_paths(graph, src, tgt, cutoff=max_hops):
                    raw_paths.append((len(p) - 1, p, tgt))
                    tgt_reached = True
                    if len(raw_paths) >= enum_ceiling:
                        hit_ceiling = True
                        truncated = True
                        break
                if hit_ceiling:
                    break
            else:
                try:
                    p = nx.shortest_path(graph, src, tgt)
                except nx.NetworkXNoPath:
                    continue
                tgt_reachable = True
                if len(p) - 1 <= max_hops:
                    raw_paths.append((len(p) - 1, p, tgt))
                    tgt_reached = True
        if tgt_reached:
            reached.add(tgt)
        elif all_simple and _reachable_beyond_budget(tgt):
            over_budget.add(tgt)
        elif tgt_reachable:
            over_budget.add(tgt)
        else:
            unreachable.add(tgt)
        if hit_ceiling:
            break

    # Deterministic ranking: shortest first, then by the node-id tuple.
    raw_paths.sort(key=lambda item: (item[0], item[1]))
    if len(raw_paths) > max_paths:
        truncated = True
        raw_paths = raw_paths[:max_paths]

    all_node_ids = sorted({n for _, p, _ in raw_paths for n in p})
    labels = {
        nr.node_id: NodeRef(node_id=nr.node_id, kind=nr.kind, label=nr.label)
        for nr in reader.nodes_by_ids(all_node_ids)
    }
    for _length, node_path, tgt in raw_paths:
        found.append(_path_to_model(pg, node_path, labels, tgt))

    return PathResult(
        source_node_ids=sources,
        target_node_ids=targets,
        paths=found,
        paths_found=len(found),
        truncated=truncated,
        max_hops=max_hops,
        unreachable_targets=sorted(unreachable - reached),
        over_budget_targets=sorted(over_budget - reached),
    )


def _reverse_bfs_dist(graph: nx.DiGraph, targets: Sequence[str]) -> dict[str, int]:
    """Return ``node_id -> min hop distance`` to ANY target over the reverse graph.

    Mirrors :func:`wraith.api.risk._reverse_bfs_distances` but walks the already
    H2-filtered :class:`PathGraph` (so ``Contains``/``GPLink`` into a Tier-0 group
    is already absent): a multi-source BFS seeded at the targets, following
    ``graph.predecessors`` (the attacker predecessors that can reach a node). Every
    node that can reach a target gets its true shortest hop count; targets get 0.
    Shortest distances are unique, so the result is order-independent (determinism).

    Inputs:
        graph: the attacker-direction :class:`PathGraph.graph`.
        targets: the resolved target node ids (reverse-BFS seeds).

    Returns:
        A ``node_id -> distance`` map. Never raises; a target absent from the graph
        still gets distance 0 (isolated) and simply has no predecessors.
    """
    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for t in targets:
        if t not in dist:
            dist[t] = 0
            queue.append(t)
    while queue:
        cur = queue.popleft()
        if cur not in graph:
            continue
        for pred in sorted(graph.predecessors(cur)):
            if pred not in dist:
                dist[pred] = dist[cur] + 1
                queue.append(pred)
    return dist


def _forward_dist(graph: nx.DiGraph, sources: Sequence[str]) -> dict[str, int]:
    """Return ``node_id -> min forward hop distance`` from ANY source (multi-source BFS).

    Used ONLY for honest per-target status in :func:`find_paths_to`: a target is
    *reached* when some considered source reaches it within budget, *over budget*
    when reachable only beyond ``max_hops``, and *unreachable* when no source
    reaches it at all. One O(V+E) pass regardless of how many sources seed it.

    Inputs:
        graph: the attacker-direction :class:`PathGraph.graph`.
        sources: the considered source node ids (BFS seeds, distance 0).

    Returns:
        A ``node_id -> distance`` map (sources at 0). Never raises; a source absent
        from the graph is skipped.
    """
    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for s in sources:
        if s in graph and s not in dist:
            dist[s] = 0
            queue.append(s)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(graph.successors(cur)):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                queue.append(nxt)
    return dist


def _reconstruct_to_target(
    graph: nx.DiGraph, dist: dict[str, int], source: str
) -> list[str] | None:
    """Reconstruct one deterministic shortest path ``source -> nearest target``.

    Greedily follows, at each node, the minimum-``node_id`` forward successor whose
    reverse-BFS ``dist`` is exactly one less (the next hop toward a target), until a
    ``dist == 0`` node (a target) is reached. Determinism comes from the
    min-``node_id`` successor rule (design §6), so identical stores yield identical
    paths. Returns ``None`` if ``source`` has no finite distance.
    """
    d = dist.get(source)
    if d is None or d == 0:
        return None
    path = [source]
    cur = source
    cur_d = d
    while cur_d > 0:
        nxt = min(
            (succ for succ in graph.successors(cur) if dist.get(succ, -1) == cur_d - 1),
            default=None,
        )
        if nxt is None:  # pragma: no cover - BFS invariant guarantees a successor
            return None
        path.append(nxt)
        cur = nxt
        cur_d -= 1
    return path


def find_paths_to(
    reader: StoreReader,
    *,
    target: str | None = "tier0",
    target_node_ids: Sequence[str] | None = None,
    source_filter: Sequence[str] | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_paths: int = DEFAULT_MAX_PATHS,
    path_graph: PathGraph | None = None,
) -> PathResult:
    """Find one shortest attacker path from every source TO a target set (reverse).

    The single bounded primitive the forward :func:`find_paths` could not do
    without one BFS per source (design §6): ONE reverse multi-source BFS from the
    resolved target set (reusing :func:`build_path_graph` + the H2
    :func:`is_false_group_control_edge` guard, so a structural ``Contains``/``GPLink``
    hop into a Tier-0 group is dropped in the reverse direction too), yielding each
    source's shortest hop distance, then a predecessor reconstruction of one
    shortest path per source. Sources are ranked ``(distance, node_id)`` and only
    the top ``max_paths`` are reconstructed, so the call is bounded by construction
    regardless of how many sources match.

    Inputs:
        reader: the read-only store accessor.
        target: ``"tier0"`` (the Tier-0 traversal set: Tier-0 groups + the Domain
            root object, G1/G3) or a specific target node id.
        target_node_ids: explicit target id set (overrides ``target``).
        source_filter: restrict reconstructed/ranked sources to this set (e.g. the
            Kerberoastable set); ``None`` = every source that can reach the target
            (the global query).
        max_hops: cutoff path length (hop count); clamped to ``[1, MAX_PATH_HOPS]``.
            A source whose shortest distance exceeds this is reported honestly (the
            target becomes ``over_budget``), not reconstructed.
        max_paths: maximum number of paths returned (ranked shortest-first);
            clamped to ``[1, MAX_PATH_RESULTS]``. ``truncated`` is set when more
            in-budget sources exist than were returned.
        path_graph: a prebuilt :class:`PathGraph` (else built from the store with
            the H2 Tier-0-group filter applied).

    Returns:
        A :class:`PathResult`. ``paths`` holds one shortest path per source
        (shortest-first). ``source_node_ids`` is the input ``source_filter`` when
        given (so a fully-unreachable filtered query still names its inputs), else
        the sources actually returned (global). ``unreachable_targets`` are resolved
        targets no considered source reaches; ``over_budget_targets`` are targets
        reachable only beyond ``max_hops`` — honestly distinct, never conflated.

    Failure modes:
        Never raises on graph content; unknown source/target ids simply yield no
        paths. ``max_hops``/``max_paths`` are clamped into their bounds.
    """
    max_hops = min(max(1, int(max_hops)), MAX_PATH_HOPS)
    max_paths = min(max(1, int(max_paths)), MAX_PATH_RESULTS)
    targets = _resolve_targets(reader, target, target_node_ids)
    target_set = set(targets)

    # H2 is a construction invariant (design §14): the fallback graph is built over
    # the full Tier-0 classification group set, not a per-target group subset.
    pg = path_graph or build_case_path_graph(reader)
    graph = pg.graph

    # (1) reverse BFS from the targets -> shortest distance to the NEAREST target.
    dist = _reverse_bfs_dist(graph, targets)

    # (2) candidate sources: reachable (distance > 0), restricted to the filter.
    if source_filter is not None:
        filter_ids = sorted(set(source_filter))
        candidate_sources = [s for s in filter_ids if dist.get(s, 0) > 0]
        honesty_seeds: list[str] = [s for s in filter_ids if s in graph]
    else:
        candidate_sources = sorted(n for n, d in dist.items() if d > 0)
        honesty_seeds = candidate_sources

    # (3) honest per-target status via ONE bounded forward reachability pass from
    #     the considered sources: reached (<= budget) / over-budget / unreachable.
    fdist = _forward_dist(graph, honesty_seeds)
    unreachable: set[str] = set()
    over_budget: set[str] = set()
    for t in target_set:
        ft = fdist.get(t)
        if ft is None or ft == 0:
            unreachable.add(t)
        elif ft > max_hops:
            over_budget.add(t)

    # (4) rank in-budget sources shortest-first, reconstruct only the top max_paths.
    in_budget = sorted(
        (s for s in candidate_sources if dist[s] <= max_hops),
        key=lambda s: (dist[s], s),
    )
    truncated = len(in_budget) > max_paths
    selected = in_budget[:max_paths]

    node_paths: list[list[str]] = []
    for s in selected:
        p = _reconstruct_to_target(graph, dist, s)
        if p is not None:
            node_paths.append(p)

    all_node_ids = sorted({n for p in node_paths for n in p})
    labels = {
        nr.node_id: NodeRef(node_id=nr.node_id, kind=nr.kind, label=nr.label)
        for nr in reader.nodes_by_ids(all_node_ids)
    }
    found = [_path_to_model(pg, p, labels, p[-1]) for p in node_paths]

    if source_filter is not None:
        result_sources = sorted(set(source_filter))
    else:
        result_sources = sorted(p[0] for p in node_paths)

    return PathResult(
        source_node_ids=result_sources,
        target_node_ids=targets,
        paths=found,
        paths_found=len(found),
        truncated=truncated,
        max_hops=max_hops,
        unreachable_targets=sorted(unreachable),
        over_budget_targets=sorted(over_budget),
    )
