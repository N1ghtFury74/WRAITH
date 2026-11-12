"""Transparent, explainable per-node risk scoring (M7).

No black-box weights: a node's score is the SUM of itemized
:class:`~wraith.api.models.RiskFactor` contributions, each with a code, a human
label, a detail string, and an integer weight — so an operator sees exactly WHY
a node scored as it did (the domain-expert validates the factor set at the gate).

Factors (all documented as module constants):
  * ``TIER0``                 — the node itself is Tier-0 (SID RID in the Tier-0
                                set / the domain). Owning it IS domain compromise.
  * ``DCSYNC_HOLDER``         — holds a ``DCSync`` edge to the domain (can pull
                                every secret / forge a Golden Ticket).
  * ``TIER0_REACHABLE``       — a non-Tier-0 node with at least one attacker path
                                to a Tier-0 target.
  * ``CLOSE_TO_TIER0``        — that path is short (<= 2 hops) — low-effort.
  * ``UNCONSTRAINED_DELEG``   — trusted for unconstrained Kerberos delegation.
  * ``KERBEROASTABLE``        — enabled user with an SPN (crackable service ticket).
  * ``ASREP_ROASTABLE``       — pre-auth not required (crackable AS-REP).
  * ``SID_HISTORY``           — carries sIDHistory (possible privilege smuggling).
  * ``ADMINCOUNT``            — AdminSDHolder-protected (was/is privileged).
  * ``INBOUND_CONTROL``       — how many principals can control this node (it is a
                                high-value *target*); 1 pt per controller, capped.
  * ``OUTBOUND_CONTROL``      — how many objects this node can control (it is
                                *powerful*); 1 pt per controlled object, capped.

The reachability factors are computed once via a reverse multi-source BFS from
the Tier-0 targets (O(n + e)); everything else is a local predicate. Pure and
deterministic: identical inputs -> identical scores and factor ordering.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping, Sequence

from wraith.api.models import NodeRisk, RiskFactor, RiskSummary
from wraith.api.store import EdgeRow, Tier0Sets
from wraith.api.tiering import is_control_edge, is_false_group_control_edge, sid_is_tier0
from wraith.edges.node_flags import (
    is_asrep_roastable_account,
    is_kerberoastable,
    is_unconstrained_delegation,
)

# --- documented factor weights (transparent; no hidden tuning) ---------------
W_TIER0: int = 100
W_DCSYNC_HOLDER: int = 60
W_TIER0_REACHABLE: int = 25
W_CLOSE_TO_TIER0: int = 15
W_UNCONSTRAINED_DELEG: int = 30
W_KERBEROASTABLE: int = 20
W_ASREP_ROASTABLE: int = 20
W_SID_HISTORY: int = 20
W_ADMINCOUNT: int = 10
#: GPO Creator Owners (-520): creates (not links) GPOs — a minor privilege, not
#: Tier-0 (gate G2). A small, documented factor so the signal is not lost.
W_GPO_CREATOR: int = 10
#: 1 point per distinct inbound controller / outbound controlled object, capped.
CONTROL_POINT_CAP: int = 25
#: "close to Tier-0" means the shortest attacker path is this many hops or fewer.
CLOSE_HOPS: int = 2


def _reverse_bfs_distances(
    edges: Sequence[EdgeRow],
    targets: Sequence[str],
    group_targets: frozenset[str] = frozenset(),
) -> dict[str, int]:
    """Return ``node_id -> min hop distance`` to ANY target (reverse BFS).

    Builds the reverse adjacency once and does a multi-source BFS seeded at the
    targets, so every node that can reach a target gets its shortest hop count.
    Targets themselves get distance 0 and are excluded by the caller as needed.

    Gate H2: a ``Contains``/``GPLink`` edge INTO a Tier-0 *group* (``group_targets``)
    is a false control hop and is excluded, so "containing" a Tier-0 group does not
    count as reaching it.
    """
    rev: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        if e.source_node_id == e.target_node_id:
            continue
        if is_false_group_control_edge(e.kind, e.target_node_id, group_targets):
            continue
        rev[e.target_node_id].add(e.source_node_id)
    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for t in targets:
        if t not in dist:
            dist[t] = 0
            queue.append(t)
    while queue:
        cur = queue.popleft()
        for pred in sorted(rev.get(cur, ())):
            if pred not in dist:
                dist[pred] = dist[cur] + 1
                queue.append(pred)
    return dist


def _control_counts(
    edges: Sequence[EdgeRow],
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return ``(inbound_controllers, outbound_controlled)`` sets per node.

    Only control/privilege edges count (:func:`is_control_edge`), de-duplicated by
    the other endpoint so repeated parallel ACEs do not inflate the tally.
    """
    inbound: dict[str, set[str]] = defaultdict(set)
    outbound: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        if e.source_node_id == e.target_node_id or not is_control_edge(e.kind):
            continue
        inbound[e.target_node_id].add(e.source_node_id)
        outbound[e.source_node_id].add(e.target_node_id)
    return inbound, outbound


def score_nodes(
    principals: Sequence[Mapping[str, object]],
    edges: Sequence[EdgeRow],
    tier0: Tier0Sets,
) -> list[NodeRisk]:
    """Score every principal with an itemized, transparent factor list.

    Inputs:
        principals: the per-principal risk inputs
            (:meth:`~wraith.api.store.StoreReader.principal_risk_inputs`) plus the
            Domain root object (:meth:`~wraith.api.store.StoreReader.domain_risk_inputs`).
        edges: the §4 edge rows (used for reachability + control counts).
        tier0: the resolved Tier-0 classification/target/member sets
            (:meth:`~wraith.api.store.StoreReader.tier0_sets`).

    Tier-0 classification (the ``TIER0`` factor) fires when a node's own SID is a
    Tier-0 RID (gate), when it IS the Domain root object (gate G1), or when it is a
    current effective member of a Tier-0 group (gate H1: possession, not an
    exploitable hop — it inherits Tier-0 rather than scoring merely "reachable").
    Reachability uses the Tier-0 *target* set, with the H2 structural-hop filter.

    Returns:
        A list of :class:`NodeRisk`, sorted by ``score`` descending then
        ``node_id`` (deterministic).

    Failure modes:
        Never raises; missing/None fields degrade to inactive factors.
    """
    dist = _reverse_bfs_distances(edges, tier0.target_ids, tier0.group_target_ids)
    inbound, outbound = _control_counts(edges)
    dcsync_holders = {e.source_node_id for e in edges if e.kind == "DCSync"}

    out: list[NodeRisk] = []
    for p in principals:
        node_id = str(p["node_id"])
        ptype = str(p["principal_type"])
        object_sid = p.get("object_sid")
        sid = str(object_sid) if object_sid is not None else None
        uac = p.get("uac_flags")
        uac_int = int(uac) if isinstance(uac, int) else None
        enabled = p.get("enabled")
        enabled_b = bool(enabled) if enabled is not None else None
        sam_val = p.get("samaccountname")
        sam = str(sam_val) if sam_val is not None else None
        spns_val = p.get("spns")
        spns = [str(s) for s in spns_val] if isinstance(spns_val, (list, tuple)) else []
        sidh_val = p.get("sid_history")
        sid_history = [str(s) for s in sidh_val] if isinstance(sidh_val, (list, tuple)) else []
        admincount = p.get("admincount")
        label = str(p.get("label") or node_id)

        factors: list[RiskFactor] = []
        is_sid_t0 = sid_is_tier0(sid)
        is_domain_obj = node_id in tier0.domain_object_ids
        is_member_t0 = node_id in tier0.member_ids
        is_t0 = is_sid_t0 or is_domain_obj or is_member_t0 or node_id in tier0.classified_ids
        if is_t0:
            if is_domain_obj:
                t0_detail = (
                    "the Domain root object — WriteDacl/GenericAll/Owns on it "
                    "self-grants DCSync (full domain compromise)"
                )
            elif is_sid_t0:
                t0_detail = f"object_sid {sid} is a Tier-0 (domain-admin-equivalent) identity"
            elif is_member_t0:
                t0_detail = (
                    "current effective member of a Tier-0 group "
                    "(Tier-0 by possession — no exploit required)"
                )
            else:
                t0_detail = "classified Tier-0 (domain-compromise-equivalent)"
            factors.append(
                RiskFactor(
                    code="TIER0",
                    label="Tier-0 principal",
                    detail=t0_detail,
                    weight=W_TIER0,
                )
            )
        if node_id in dcsync_holders:
            factors.append(
                RiskFactor(
                    code="DCSYNC_HOLDER",
                    label="DCSync rights",
                    detail="holds GetChanges/GetChangesAll -> can replicate all domain secrets",
                    weight=W_DCSYNC_HOLDER,
                )
            )
        d = dist.get(node_id)
        if not is_t0 and d is not None and d > 0:
            factors.append(
                RiskFactor(
                    code="TIER0_REACHABLE",
                    label="Can reach Tier-0",
                    detail=f"shortest attacker path to a Tier-0 target is {d} hop(s)",
                    weight=W_TIER0_REACHABLE,
                )
            )
            if d <= CLOSE_HOPS:
                factors.append(
                    RiskFactor(
                        code="CLOSE_TO_TIER0",
                        label="Short path to Tier-0",
                        detail=f"only {d} hop(s) from a Tier-0 target (low-effort escalation)",
                        weight=W_CLOSE_TO_TIER0,
                    )
                )
        if is_unconstrained_delegation(uac_int):
            factors.append(
                RiskFactor(
                    code="UNCONSTRAINED_DELEG",
                    label="Unconstrained delegation",
                    detail="TRUSTED_FOR_DELEGATION set -> can capture TGTs of authenticating users",
                    weight=W_UNCONSTRAINED_DELEG,
                )
            )
        if is_kerberoastable(ptype, enabled_b, spns, sam):
            factors.append(
                RiskFactor(
                    code="KERBEROASTABLE",
                    label="Kerberoastable",
                    detail="enabled user with an SPN -> service ticket is offline-crackable",
                    weight=W_KERBEROASTABLE,
                )
            )
        if is_asrep_roastable_account(ptype, enabled_b, uac_int):
            factors.append(
                RiskFactor(
                    code="ASREP_ROASTABLE",
                    label="AS-REP roastable",
                    detail="enabled user with DONT_REQ_PREAUTH -> AS-REP is offline-crackable",
                    weight=W_ASREP_ROASTABLE,
                )
            )
        if sid_history:
            factors.append(
                RiskFactor(
                    code="SID_HISTORY",
                    label="Has sIDHistory",
                    detail=f"carries {len(sid_history)} sIDHistory value(s) "
                    "(possible privilege smuggling)",
                    weight=W_SID_HISTORY,
                )
            )
        if isinstance(admincount, int) and admincount:
            factors.append(
                RiskFactor(
                    code="ADMINCOUNT",
                    label="AdminSDHolder-protected",
                    detail="adminCount set -> is or was a protected/privileged principal",
                    weight=W_ADMINCOUNT,
                )
            )
        if node_id in tier0.gpo_creator_ids:
            factors.append(
                RiskFactor(
                    code="GPO_CREATOR",
                    label="GPO Creator Owner",
                    detail="Group Policy Creator Owners (-520): can create (not link) GPOs "
                    "-> minor privilege, NOT domain-compromise-equivalent",
                    weight=W_GPO_CREATOR,
                )
            )
        in_n = len(inbound.get(node_id, ()))
        if in_n:
            factors.append(
                RiskFactor(
                    code="INBOUND_CONTROL",
                    label="Controlled by others",
                    detail=f"{in_n} principal(s) hold a control edge over this node",
                    weight=min(in_n, CONTROL_POINT_CAP),
                )
            )
        out_n = len(outbound.get(node_id, ()))
        if out_n:
            factors.append(
                RiskFactor(
                    code="OUTBOUND_CONTROL",
                    label="Controls other objects",
                    detail=f"this node holds a control edge over {out_n} object(s)",
                    weight=min(out_n, CONTROL_POINT_CAP),
                )
            )

        score = sum(f.weight for f in factors)
        # Promote the shortest Tier-0 hop count (doc 21 add #3): only for a non-Tier-0
        # node that can actually reach a Tier-0 target (d > 0). ``None`` otherwise, so
        # "reaches Tier-0 in K hops" needs no string-parsing of the factor detail.
        tier0_hops = d if (not is_t0 and d is not None and d > 0) else None
        out.append(
            NodeRisk(
                node_id=node_id,
                kind=ptype,
                label=label,
                object_sid=sid,
                score=score,
                tier=0 if is_t0 else None,
                tier0_hops=tier0_hops,
                factors=factors,
            )
        )

    out.sort(key=lambda nr: (-nr.score, nr.node_id))
    return out


def summarize_risk(scored: Sequence[NodeRisk], top_n: int) -> RiskSummary:
    """Aggregate scored nodes into a dashboard :class:`RiskSummary` (top ``top_n``)."""

    def has(nr: NodeRisk, code: str) -> bool:
        return any(f.code == code for f in nr.factors)

    return RiskSummary(
        scored_nodes=len(scored),
        tier0_nodes=sum(1 for nr in scored if has(nr, "TIER0")),
        dcsync_holders=sum(1 for nr in scored if has(nr, "DCSYNC_HOLDER")),
        tier0_reachable=sum(1 for nr in scored if has(nr, "TIER0_REACHABLE")),
        unconstrained_delegation=sum(1 for nr in scored if has(nr, "UNCONSTRAINED_DELEG")),
        kerberoastable=sum(1 for nr in scored if has(nr, "KERBEROASTABLE")),
        asrep_roastable=sum(1 for nr in scored if has(nr, "ASREP_ROASTABLE")),
        has_sid_history=sum(1 for nr in scored if has(nr, "SID_HISTORY")),
        top=list(scored[: max(0, top_n)]),
    )
