"""Connect-the-dots: minimal labelled connecting chains for the canvas (Round 1 C).

When the canvas is filtered to >=2 node kinds that share NO direct edge (the
``noEdges`` state — the owner's User+GPO example), the honest edge set is empty and
analytically useless: a GPO never points at a user. The real relationship is a
multi-hop chain through hidden intermediate objects. This module computes those
chains over the ONE H2-filtered attack graph and returns them in TWO never-conflated
lanes (doc 09 §0/§1):

* **control** (``principal -> object``) — a real attacker capability, ranked first;
* **scope** (``GPO -> container -> principal``) — only *potential* application
  offline (RSoP is not computable dead-disk), so every scope chain carries the
  mandatory RSoP caveat and counts ``rsop_not_resolvable``.

Guardrails (doc 09 §3): H2 is enforced by reusing the H2-filtered graph (a
``Contains``/``GPLink`` edge INTO a Tier-0 group can never be a control hop);
pure-containment / co-location chains are suppressed as structural noise; a chain's
confidence is its WEAKEST hop (an inferred hop taints the whole chain); DENY ACEs
are out of scope in v1 (control chains are grant-based and may over-state — surfaced
once at the feature level). Everything is bounded (``max_hops`` / ``max_paths`` /
``max_pairs``) and deterministic (sorted representatives + ordered pairs + a
``(lane, length, node-id tuple)`` tie-break), so identical stores yield identical
chains.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import networkx as nx

from wraith.api.models import ConnectorPath, ConnectorResult, NodeRef, PathEdge
from wraith.api.paths import _pick_kind
from wraith.api.store import EdgeRow, StoreReader
from wraith.api.tiering import NON_CONTROL_EDGE_KINDS, is_false_group_control_edge

#: Default ceilings (mirrored by the pydantic ``ConnectorRequest`` ``Field`` bounds).
DEFAULT_MAX_HOPS: int = 6
DEFAULT_MAX_PATHS: int = 12
DEFAULT_MAX_PAIRS: int = 12
#: Hard upper bound on representative nodes regardless of the request (bounded work).
HARD_MAX_PAIRS: int = 50

#: Structural "applies-to" / containment edge kinds (the scope lane). A hop whose
#: available kinds are a subset of this set is NOT a control capability.
_SCOPE_EDGE_KINDS: frozenset[str] = frozenset({"Contains", "GPLink"})

#: Principal node kinds a GPO scope path may legitimately terminate at.
_PRINCIPAL_KINDS: frozenset[str] = frozenset({"User", "Computer", "Group"})

#: Confidence ordering for the weakest-hop rule (higher = more trustworthy).
_CONFIDENCE_RANK: dict[str, int] = {
    "unknown": 0,
    "synthetic-only": 1,
    "inferred": 2,
    "confirmed": 3,
}
_RANK_TO_CONFIDENCE: dict[int, str] = {v: k for k, v in _CONFIDENCE_RANK.items()}

#: The mandatory RSoP caveat on every scope chain (doc 09 §1.1 / handbook 11 §1).
RSOP_CAVEAT: str = (
    "GPO potentially applies to this principal — actual effect is subject to security "
    "filtering, WMI filters, block-inheritance/enforcement and disabled sections, which "
    "cannot be resolved from a dead-disk image (RSoP)."
)
#: Feature-level caveat shown once (doc 09 §3.9): control chains are grant-based.
DENY_CAVEAT: str = (
    "Control chains are grant-based: DENY ACEs are not evaluated in v1, so a control "
    "chain may over-state capability where an explicit DENY would cancel it."
)


@dataclass(frozen=True)
class _PairInfo:
    """Aggregated info for one directed node pair (collapsed parallel edges)."""

    kinds: tuple[str, ...]
    #: Best (most-confirmed) confidence available on this hop; the attacker uses the
    #: strongest edge, so the hop is as good as its best parallel edge.
    best_confidence: str
    edge_id: str | None
    #: True iff a control/membership edge is available (any kind outside the
    #: structural/identity NON_CONTROL set).
    is_control: bool
    #: True iff this hop is purely structural scope (all kinds in {Contains, GPLink}).
    is_scope_only: bool


@dataclass
class _ConnectorGraph:
    """The H2-filtered directed graph plus the per-pair hop lookup (pure build)."""

    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    pairs: dict[tuple[str, str], _PairInfo] = field(default_factory=dict)


def _best_confidence(confidences: Sequence[str | None]) -> tuple[str, bool]:
    """Return the best (most-confirmed) confidence and whether any value was unknown.

    Inputs:
        confidences: the per-parallel-edge confidence strings (``None`` allowed).

    Returns:
        ``(confidence, had_unknown)`` — the highest-ranked confidence string and a
        flag set when at least one edge carried a ``None``/unrecognised confidence.
        Per-chain unknown detection for the ``hop_confidence_unknown`` gap is done by
        :func:`_chain_confidence` (weakest hop), not from this flag. Never raises.
    """
    had_unknown = False
    best = 0
    for c in confidences:
        rank = _CONFIDENCE_RANK.get(c or "", -1)
        if rank < 0:
            had_unknown = True
            rank = _CONFIDENCE_RANK["unknown"]
        best = max(best, rank)
    return _RANK_TO_CONFIDENCE.get(best, "unknown"), had_unknown


def build_connector_graph(
    edges: Sequence[EdgeRow], tier0_group_ids: frozenset[str] = frozenset()
) -> _ConnectorGraph:
    """Build the H2-filtered connector graph + per-pair hop lookup (pure, deterministic).

    Mirrors :func:`wraith.api.paths.build_path_graph`'s H2 construction invariant
    (self-loops dropped; a ``Contains``/``GPLink`` edge INTO a Tier-0 group dropped)
    but additionally records, per directed pair, the full kind set, the best
    confidence, the lowest ``edge_id``, and the control/scope lane flags needed to
    classify a chain.

    Inputs:
        edges: the §4 edge rows (attacker direction ``source -> target``), already
            deterministically ordered by the store reader.
        tier0_group_ids: Tier-0 group node ids whose inbound structural edges are
            false control hops (H2).

    Returns:
        A :class:`_ConnectorGraph`. Never raises.
    """
    cg = _ConnectorGraph()
    raw_kinds: dict[tuple[str, str], list[str]] = {}
    raw_confs: dict[tuple[str, str], list[str | None]] = {}
    raw_edge_id: dict[tuple[str, str], str] = {}
    for e in edges:
        if e.source_node_id == e.target_node_id:
            continue
        if is_false_group_control_edge(e.kind, e.target_node_id, tier0_group_ids):
            continue
        pair = (e.source_node_id, e.target_node_id)
        raw_kinds.setdefault(pair, []).append(e.kind)
        raw_confs.setdefault(pair, []).append(e.confidence)
        prev = raw_edge_id.get(pair)
        if prev is None or e.edge_id < prev:
            raw_edge_id[pair] = e.edge_id
        cg.graph.add_edge(*pair)
    for pair, kinds in raw_kinds.items():
        kind_set = frozenset(kinds)
        best_conf, _ = _best_confidence(raw_confs[pair])
        is_scope_only = kind_set.issubset(_SCOPE_EDGE_KINDS)
        is_control = any(k not in NON_CONTROL_EDGE_KINDS for k in kind_set)
        cg.pairs[pair] = _PairInfo(
            kinds=tuple(sorted(kind_set)),
            best_confidence=best_conf,
            edge_id=raw_edge_id[pair],
            is_control=is_control,
            is_scope_only=is_scope_only,
        )
    return cg


def _classify_lane(
    node_path: Sequence[str],
    cg: _ConnectorGraph,
    node_kind: Mapping[str, str],
) -> str | None:
    """Classify a connecting chain as ``"control"``, ``"scope"`` or ``None`` (noise).

    Rules (doc 09 §1.5):
        * every hop is a control/membership edge (no structural hop) -> ``control``;
        * every hop is a structural scope edge (``GPLink``/``Contains``) AND the chain
          runs ``GPO -> ... -> principal`` -> ``scope`` (a *pure* GPO application chain;
          potential offline, hence the mandatory RSoP caveat);
        * a MIXED chain (structural + control hops), or a pure-containment chain that is
          not a GPO->principal application (``OU->OU``, ``Domain->principal``
          co-location) -> ``None`` (structural noise, suppressed).

    The scope lane is deliberately restricted to pure ``GPLink``/``Contains``
    application chains: a chain that threads a control edge (e.g. ``GetChangesAll``,
    ``MemberOf``) between GPO and principal is NOT the GPO "applying to" that principal,
    so it must not be labelled scope and stamped with the applies-to caveat.

    Never raises; an unknown endpoint kind degrades to structural noise (suppressed),
    never a false control claim.
    """
    all_control = True  # no structural (scope-only) hop anywhere
    all_scope = True  # every hop is a scope-only GPLink/Contains hop
    for a, b in zip(node_path, node_path[1:], strict=False):
        info = cg.pairs.get((a, b))
        if info is None:  # pragma: no cover - path edges always have pair info
            return None
        if info.is_scope_only:
            all_control = False
        else:
            all_scope = False
    if all_control:
        return "control"
    if all_scope:
        start_kind = node_kind.get(node_path[0], "")
        end_kind = node_kind.get(node_path[-1], "")
        if start_kind == "GPO" and end_kind in _PRINCIPAL_KINDS:
            return "scope"
    return None


def _chain_confidence(node_path: Sequence[str], cg: _ConnectorGraph) -> tuple[str, bool]:
    """Return the chain's WEAKEST-hop confidence + whether any hop was unknown."""
    worst = _CONFIDENCE_RANK["confirmed"]
    had_unknown = False
    for a, b in zip(node_path, node_path[1:], strict=False):
        info = cg.pairs.get((a, b))
        if info is None:  # pragma: no cover
            return "unknown", True
        rank = _CONFIDENCE_RANK.get(info.best_confidence, _CONFIDENCE_RANK["unknown"])
        if info.best_confidence == "unknown":
            had_unknown = True
        worst = min(worst, rank)
    return _RANK_TO_CONFIDENCE.get(worst, "unknown"), had_unknown


def _build_hops(node_path: Sequence[str], cg: _ConnectorGraph) -> list[PathEdge]:
    """Build the labelled per-hop edge list for a chain (deterministic kind pick)."""
    hops: list[PathEdge] = []
    for a, b in zip(node_path, node_path[1:], strict=False):
        info = cg.pairs.get((a, b))
        kind = _pick_kind(info.kinds) if info else "Unknown"
        hops.append(PathEdge(source=a, target=b, kind=kind, edge_id=info.edge_id if info else None))
    return hops


def compute_connectors(
    cg: _ConnectorGraph,
    retained_ids: Sequence[str],
    node_info: Mapping[str, tuple[str, str]],
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_pairs: int = DEFAULT_MAX_PAIRS,
) -> ConnectorResult:
    """Compute the two-lane connector result over a prebuilt graph (pure, deterministic).

    Inputs:
        cg: the H2-filtered :class:`_ConnectorGraph` (see :func:`build_connector_graph`).
        retained_ids: the canvas slice node ids to connect.
        node_info: ``node_id -> (kind, label)`` for every node that may appear on a
            chain (retained + possible intermediates).
        max_hops: maximum connecting-chain length (clamped to ``[1, 15]``).
        max_paths: maximum chains returned, control lane first (clamped to ``[1, 500]``).
        max_pairs: representative-node cap (clamped to ``[2, HARD_MAX_PAIRS]``); a
            larger retained set is capped deterministically and counts
            ``representatives_capped``.

    Returns:
        A :class:`ConnectorResult`. Chains are ranked ``(lane, length, node tuple)``;
        ``via_node_ids`` are intermediate nodes NOT in ``retained_ids`` across the
        SELECTED chains. Every suppressed/degraded branch is a counted gap, and an
        empty result carries an explicit ``note`` (never a silent blank).

    Failure modes:
        Never raises on content; nodes absent from the graph are skipped. Bounds are
        clamped. A missing ``node_info`` label falls back to the node id.
    """
    max_hops = min(max(1, int(max_hops)), 15)
    max_paths = min(max(1, int(max_paths)), 500)
    max_pairs = min(max(2, int(max_pairs)), HARD_MAX_PAIRS)

    gaps: dict[str, int] = {}
    retained_set = set(retained_ids)
    reps = sorted(r for r in retained_set if r in cg.graph)
    representatives_capped = len(reps) > max_pairs
    if representatives_capped:
        gaps["representatives_capped"] = 1
        reps = reps[:max_pairs]

    # Candidate chains: one shortest path per ordered representative pair (both
    # directions distinct → scope GPO->user AND control user->GPO are both covered).
    node_kind = {k: v[0] for k, v in node_info.items()}
    raw: list[tuple[int, int, tuple[str, ...], str]] = []
    structural_suppressed = 0
    over_budget = 0
    for a in reps:
        for b in reps:
            if a == b:
                continue
            try:
                node_path = nx.shortest_path(cg.graph, a, b)
            except nx.NetworkXNoPath:
                continue
            if len(node_path) < 2:  # pragma: no cover - a == b already skipped above
                continue
            if len(node_path) - 1 > max_hops:
                # Reachable but beyond the hop budget: count it, never drop silently
                # (mirrors PathResult's over_budget vs unreachable distinction).
                over_budget += 1
                continue
            lane = _classify_lane(node_path, cg, node_kind)
            if lane is None:
                structural_suppressed += 1
                continue
            lane_rank = 0 if lane == "control" else 1
            raw.append((lane_rank, len(node_path) - 1, tuple(node_path), lane))

    raw.sort(key=lambda item: (item[0], item[1], item[2]))
    truncated = len(raw) > max_paths
    selected = raw[:max_paths]

    if structural_suppressed:
        gaps["structural_only_suppressed"] = structural_suppressed
    if over_budget:
        gaps["over_hop_budget"] = over_budget

    paths: list[ConnectorPath] = []
    via: set[str] = set()
    scope_count = 0
    control_count = 0
    unknown_conf_hops = 0
    for _lane_rank, length, node_path, lane in selected:
        hops = _build_hops(node_path, cg)
        confidence, had_unknown = _chain_confidence(node_path, cg)
        if had_unknown:
            unknown_conf_hops += 1
        refs = [
            NodeRef(
                node_id=n,
                kind=node_info.get(n, ("Unknown", n))[0],
                label=node_info.get(n, ("", n))[1],
            )
            for n in node_path
        ]
        for n in node_path[1:-1]:
            if n not in retained_set:
                via.add(n)
        is_scope = lane == "scope"
        if is_scope:
            scope_count += 1
        else:
            control_count += 1
        paths.append(
            ConnectorPath(
                lane=lane,  # type: ignore[arg-type]
                nodes=refs,
                edges=hops,
                length=length,
                confidence=confidence,
                source_node_id=node_path[0],
                target_node_id=node_path[-1],
                caveat=RSOP_CAVEAT if is_scope else None,
            )
        )

    if scope_count:
        gaps["rsop_not_resolvable"] = scope_count
    if unknown_conf_hops:
        gaps["hop_confidence_unknown"] = unknown_conf_hops

    caveats = [DENY_CAVEAT]
    if scope_count:
        caveats.append(RSOP_CAVEAT)

    note: str | None = None
    if not paths:
        gaps["no_connection"] = 1
        note = (
            "No attack-relevant control chain and no GPO scope path connects the "
            "selected entities in this data (within the hop budget)."
        )

    return ConnectorResult(
        paths=paths,
        control_count=control_count,
        scope_count=scope_count,
        retained_node_ids=sorted(retained_set),
        via_node_ids=sorted(via),
        truncated=truncated,
        max_hops=max_hops,
        caveats=caveats,
        counted_gaps=gaps,
        note=note,
    )


def build_connectors(
    reader: StoreReader,
    node_ids: Sequence[str],
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_pairs: int = DEFAULT_MAX_PAIRS,
) -> ConnectorResult:
    """Resolve the connector result for a retained node set from the store (wrapper).

    Pulls the edge rows + Tier-0 group set + node labels/kinds from the read-only
    store, builds the H2-filtered connector graph once, and delegates to the pure
    :func:`compute_connectors`. Unknown node ids are dropped and counted
    (``unknown_node_ids_dropped`` for a partial drop; ``empty_node_set`` when the
    whole input is unknown — never a silent whole-graph walk).

    Inputs:
        reader: the read-only store accessor.
        node_ids: the retained slice node ids to connect.
        max_hops / max_paths / max_pairs: bounds (see :func:`compute_connectors`).

    Returns:
        A :class:`ConnectorResult`. Never raises on content.
    """
    edges = reader.all_edges()
    tier0_group_ids = reader.tier0_sets().classification_group_ids
    cg = build_connector_graph(edges, tier0_group_ids)

    requested = set(node_ids)
    # Node labels/kinds for every node that may appear on a chain (requested +
    # every graph node, so intermediates resolve). Bounded by the store size.
    node_info: dict[str, tuple[str, str]] = {
        n.node_id: (n.kind, n.label) for n in reader.all_nodes()
    }
    retained = sorted(nid for nid in requested if nid in node_info)

    if not retained:
        return ConnectorResult(
            paths=[],
            control_count=0,
            scope_count=0,
            retained_node_ids=[],
            via_node_ids=[],
            truncated=False,
            max_hops=min(max(1, int(max_hops)), 15),
            caveats=[DENY_CAVEAT],
            counted_gaps={"empty_node_set": 1},
            note="No valid nodes were supplied to connect.",
        )

    result = compute_connectors(
        cg,
        retained,
        node_info,
        max_hops=max_hops,
        max_paths=max_paths,
        max_pairs=max_pairs,
    )
    # Partially-unknown input (stale ids from an old canvas) is malformed input: count
    # the drop so it is never silently under-represented (whole-input drop →
    # empty_node_set above).
    dropped = len(requested) - len(retained)
    if dropped:
        result.counted_gaps["unknown_node_ids_dropped"] = dropped
    return result
