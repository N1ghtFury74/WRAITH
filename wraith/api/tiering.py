"""Tier-0 definition and edge-classification constants (public AD facts).

These are the well-known RIDs and edge-kind groupings the risk model and
pathfinder reason over. All values are public [MS-DTYP]/[MS-ADTS]/BloodHound
facts (well-known SIDs, rights names) — reused, not copied from any codebase.
The sets are frozen and documented so the scoring is transparent and auditable.

There are TWO distinct Tier-0 notions, deliberately kept apart (domain-expert
gate G1/G3):

* **Classification** (:data:`TIER0_SID_SUFFIXES` + the Domain root object + any
  effective member of a Tier-0 group): "owning this IS domain compromise".
  Drives the ``TIER0`` risk factor and the high-value marking on the canvas.
* **Traversal targets** (:data:`TIER0_TARGET_SUFFIXES` + the Domain root object):
  the destinations a path/reachability query must *reach*. krbtgt/-500/-518 are
  high-value CLASSIFICATION but NOT traversal destinations — you DCSync krbtgt,
  you do not "reach" it — so they are intentionally absent from the target set.
"""

from __future__ import annotations

#: Well-known RID/SID suffixes whose principal is Tier-0 by CLASSIFICATION:
#: owning any of these is full-domain compromise. Matched as an ``object_sid``
#: suffix so they apply across any domain SID.
#:   -512 Domain Admins · -519 Enterprise Admins · -544 builtin Administrators
#:   -516 Domain Controllers · -518 Schema Admins · -502 krbtgt
#:   -500 built-in Administrator account
#: NOTE (G2): Group Policy Creator Owners (-520) is intentionally NOT here — it
#: only *creates* GPOs (cannot link them), so it is not domain-compromise
#: equivalent. It is kept as a small, separate risk factor (see
#: :data:`GPO_CREATOR_OWNER_SID_SUFFIX`), never Tier-0.
TIER0_SID_SUFFIXES: tuple[str, ...] = (
    "-512",
    "-519",
    "-544",
    "-516",
    "-518",
    "-502",
    "-500",
)

#: The Tier-0 *traversal targets* for pathfinding/reachability (the "paths to
#: Tier-0" query). These are the destinations whose capture — reached via a
#: chain of real control/escalation hops — constitutes domain compromise:
#:   -512 Domain Admins · -519 Enterprise Admins · -544 builtin Administrators
#:   -516 Domain Controllers (RBCD / coercion-to-DC / unconstrained-deleg paths)
#: The Domain root object is added as a target at the store layer (G1/G3): it
#: carries the bare domain SID, so it cannot be matched by a RID suffix.
TIER0_TARGET_SUFFIXES: tuple[str, ...] = ("-512", "-519", "-544", "-516")

#: The Tier-0 classification *group* suffixes — every group whose membership is
#: Tier-0 by possession. These are the groups whose inbound structural
#: ``Contains``/``GPLink`` is a FALSE control hop (gate H2): containing or
#: GP-linking such a group does not grant control of its membership. H2 is a graph-
#: CONSTRUCTION invariant, so this full set (NOT just the traversal targets) is the
#: H2-protected set for EVERY query, independent of the query's target. It adds
#: Schema Admins (-518) to the traversal-target groups — -518 is classification-only
#: (never a traversal target, G3) yet must still be H2-protected. The user accounts
#: -500 (Administrator) and -502 (krbtgt) are NOT groups and are excluded.
TIER0_GROUP_SUFFIXES: tuple[str, ...] = ("-512", "-519", "-544", "-516", "-518")

#: Group Policy Creator Owners. Can create (not link) GPOs — a minor privilege,
#: surfaced as a small risk factor, deliberately NOT part of the Tier-0 set (G2).
GPO_CREATOR_OWNER_SID_SUFFIX: str = "-520"

#: The sensitive-group RID suffixes the hunter analysis library (doc 20 §7) treats
#: as "privileged": every well-known group whose effective membership is a standing
#: privilege a hunter wants to enumerate and whose members are EXCLUDED when hunting
#: hidden (shadow) admins. Matched as an ``object_sid`` suffix (works across any
#: domain SID) via ``StoreReader.tier0_node_ids((suffix,))`` then expanded with the
#: M4 ``effective_membership`` closure (nested + primary-group). This is a SUPERSET
#: of the Tier-0 classification set — it adds operator/key/cert/GPCO groups that are
#: OFFENSIVELY privileged but not domain-compromise-equivalent (so NOT Tier-0).
#: Source: Microsoft Learn *Security Identifiers* well-known SID table (2025-06-26).
#:   -512 Domain Admins        -516 Domain Controllers    -517 Cert Publishers
#:   -518 Schema Admins        -519 Enterprise Admins      -520 GPO Creator Owners
#:   -526 Key Admins           -527 Enterprise Key Admins  -544 builtin Administrators
#:   -548 Account Operators    -549 Server Operators       -550 Print Operators
#:   -551 Backup Operators     -552 Replicators
#: NOTE (DE gate): Protected Users (-525) is DELIBERATELY EXCLUDED — it is a
#: DEFENSIVE hardening group, not an offensive privilege. Including it would both
#: inflate "all privileged" with hardened non-admins AND, worse, EXCLUDE Protected-
#: Users members from the shadow-admin hunt (which subtracts the privileged union),
#: hiding a hidden ACL backdoor held by a Protected-Users member from the very query
#: meant to expose it. Its standalone hygiene query ``set-protected-users`` resolves
#: -525 directly via ``tier0_node_ids``, so it still works.
#: NOTE: DnsAdmins has no fixed RID (created on DNS-role install) and is resolved by
#: NAME, not by this suffix set (doc 20 §7 / §8).
PRIVILEGED_GROUP_SID_SUFFIXES: tuple[str, ...] = (
    "-512",
    "-516",
    "-517",
    "-518",
    "-519",
    "-520",
    "-526",
    "-527",
    "-544",
    "-548",
    "-549",
    "-550",
    "-551",
    "-552",
)

#: Edge kinds that are NOT a control/privilege grant for the inbound/outbound
#: control counters — structural/containment/identity edges. Every other edge
#: kind (GenericAll, WriteDacl, Owns, AllExtendedRights, DCSync, ...) is counted
#: as a control edge. This is the SINGLE source of truth for :func:`is_control_edge`,
#: consumed by the risk model's ``_control_counts`` (INBOUND/OUTBOUND_CONTROL) and by
#: the ``controls-many-principals`` hunt — so all three agree.
#: ``MemberOf`` is here (DE hunt-audit defect #1): being a member of a group is NOT
#: control OVER it — the group grants rights to the member, not the other way round —
#: so counting ``MemberOf`` as outbound control falsely flagged ordinary users who sit
#: in many groups as high-blast-radius shadow admins. BloodHound object-control metrics
#: never count ``MemberOf`` either.
NON_CONTROL_EDGE_KINDS: frozenset[str] = frozenset(
    {"Contains", "GPLink", "HasSIDHistory", "MemberOf"}
)

#: Structural edge kinds that must NOT be traversed INTO a Tier-0 *group* node
#: (domain-expert gate H2): containing or GP-linking a group does not grant
#: control of that group's membership, so such a hop is a false path to Tier-0.
#: These are kept everywhere else (push-down onto computer/user children, and as
#: non-terminal structure between non-group nodes).
STRUCTURAL_EDGE_KINDS: frozenset[str] = frozenset({"Contains", "GPLink"})

#: Hard upper bounds on a pathfinding request so a crafted request cannot hang or
#: OOM the server (reviewer MAJOR). Enforced both as pydantic ``Field`` ceilings
#: and as a clamp inside the pathfinder.
MAX_PATH_HOPS: int = 15
MAX_PATH_RESULTS: int = 500


def sid_is_tier0(object_sid: str | None, suffixes: tuple[str, ...] = TIER0_SID_SUFFIXES) -> bool:
    """Return whether ``object_sid`` ends in a Tier-0 RID suffix.

    Inputs:
        object_sid: the principal/domain SID, or ``None``.
        suffixes: the Tier-0 suffix set (defaults to :data:`TIER0_SID_SUFFIXES`).

    Returns:
        ``True`` iff the SID is present and ends in one of the suffixes.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    if not object_sid:
        return False
    return any(object_sid.endswith(s) for s in suffixes)


def sid_is_gpo_creator(object_sid: str | None) -> bool:
    """Return whether ``object_sid`` is the Group Policy Creator Owners group (-520)."""
    if not object_sid:
        return False
    return object_sid.endswith(GPO_CREATOR_OWNER_SID_SUFFIX)


def is_control_edge(kind: str) -> bool:
    """Return whether an edge kind is a control/privilege grant (not structural)."""
    return kind not in NON_CONTROL_EDGE_KINDS


def is_false_group_control_edge(
    kind: str, target_node_id: str, tier0_group_ids: frozenset[str]
) -> bool:
    """Return whether an edge is a structural hop INTO a Tier-0 group (gate H2).

    A ``Contains``/``GPLink`` edge whose target is a Tier-0 *group* does not grant
    control of that group's membership, so traversing it would manufacture a false
    path to Tier-0. Such edges are dropped from the pathfinding graph and the
    reachability BFS (but retained for non-group targets / push-down elsewhere).

    Inputs:
        kind: the edge kind.
        target_node_id: the edge's traversal target.
        tier0_group_ids: the Tier-0 *group* node ids.

    Returns:
        ``True`` iff this edge must be excluded from traversal. Never raises.
    """
    return kind in STRUCTURAL_EDGE_KINDS and target_node_id in tier0_group_ids
