"""Cross-domain edge derivation (M-MS3) — trust / FSP / sIDHistory.

The forensic core of Phase-1 multi-domain support (``docs/schema/
multi-source-contract.md`` §4, ``docs/research/25-multi-dc-multi-domain.md`` §2c).
This module derives the THREE cross-domain bridges an operator reasons about —
**trusts**, **sIDHistory**, and **ForeignSecurityPrincipal memberships** — over a
multi-source canonical store, with the per-source discipline that is the single
most important correctness rule of the whole contract (§3.5 / research 25 §6):

* **Derive PER SOURCE.** Every edge originates from exactly one source's object
  (its ``trustedDomain`` object, its FSP stub, its principal's ``sIDHistory``).
  The edge is tagged with that originating ``source_id`` (a ``source_observation``
  row), so a per-source scoped view shows exactly that source's edges.
* **Resolve a cross-source endpoint only when BOTH sources are ingested.** A
  foreign SID is resolved to the REAL principal node in its owning domain IFF that
  domain was also ingested (its ``domain_sid`` is known); otherwise the edge
  targets a COUNTED stub — never a guessed concrete principal.
* **Never re-derive over a merged object set** (that fabricates paths; it is
  M-MS4's concern anyway). Each edge comes from a single source's object.

Everything here is pure or a thin single-store orchestrator so the edge logic is
independently testable. The orchestrator is NOT yet wired into the real N-source
ingest loop (tracked separately); it is exercised on synthetic 2-domain fixtures
and, as a regression, on the single real single-domain store (where it MUST emit
zero cross-domain edges).

Public-fact reuse (no foreign source code copied): ``trustAttributes`` bits and
``trustType`` values ([MS-ADTS] 6.1.6.7.9/.12), well-known SID shapes ([MS-DTYP]),
the attack-direction trust convention (``docs/modules/10-bloodhound-export.md``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.common.determinism import stable_id
from wraith.edges.derivations import (
    DERIVATION_CROSS_FOREST,
    DERIVATION_SAME_FOREST,
    DERIVATION_SID_HISTORY,
    DERIVATION_TRUST_KEYS,
    KIND_CROSS_FOREST_TRUST,
    KIND_HAS_SID_HISTORY,
    KIND_HAS_TRUST_KEYS,
    KIND_SAME_FOREST_TRUST,
)
from wraith.edges.models import EdgeRow
from wraith.normalize.decoders import (
    TRUST_ATTR_CROSS_ORGANIZATION,
    TRUST_ATTR_FOREST_TRANSITIVE,
    TRUST_ATTR_NON_TRANSITIVE,
    TRUST_ATTR_QUARANTINED_DOMAIN,
    TRUST_ATTR_TREAT_AS_EXTERNAL,
    TRUST_ATTR_WITHIN_FOREST,
    TRUST_TYPE_DCE,
    TRUST_TYPE_DOWNLEVEL,
    TRUST_TYPE_MIT,
    TRUST_TYPE_UPLEVEL,
)
from wraith.normalize.identity import is_domain_specific_sid, node_id_for_sid
from wraith.provenance.models import ProvenanceStruct

CONFIDENCE_CONFIRMED: str = "confirmed"

# --- WRAITH-native cross-domain edge kind + derivations ----------------------
#: FSP alias edge: the REAL foreign principal -> its local ``ForeignSecurityPrincipal``
#: stub, so the foreign principal's control flows into the stub's local position
#: (local group membership / ACLs attached to the FSP). WRAITH-native: BloodHound
#: collapses the FSP and the foreign principal onto one SID-keyed ``ObjectIdentifier``,
#: but WRAITH keys both by their own ``objectGUID`` (distinct ``node_id``s), so this
#: edge is what makes the canonical graph traversable across the FSP boundary.
KIND_FOREIGN_IDENTITY: str = "ForeignIdentity"
DERIVATION_FOREIGN_IDENTITY: str = "FSP:ForeignIdentity"

#: Inferred intra-forest ``trust_type`` labels (§4.3). ``parent_child`` /
#: ``tree_root`` are only distinguishable by reconstructed-FQDN topology, never by a
#: single attribute, so ``undetermined`` is a first-class, COUNTED outcome.
TRUST_TYPE_PARENT_CHILD: str = "parent_child"
TRUST_TYPE_TREE_ROOT: str = "tree_root"
TRUST_TYPE_UNDETERMINED: str = "undetermined"

#: ``trustType`` integer -> label ([MS-ADTS] 6.1.6.7.9).
_TRUST_TYPE_LABELS: Mapping[int, str] = {
    TRUST_TYPE_DOWNLEVEL: "downlevel",
    TRUST_TYPE_UPLEVEL: "uplevel",
    TRUST_TYPE_MIT: "mit",
    TRUST_TYPE_DCE: "dce",
}

# --- counted coverage / gap keys (counted-gap on every degraded branch) -------
COV_TRUST: str = "edges.xd_trust"
COV_TRUST_KEYS: str = "edges.xd_trust_keys"
COV_TRUST_PARENT_CHILD: str = "edges.xd_trust_parent_child"
COV_TRUST_TREE_ROOT: str = "edges.xd_trust_tree_root"
COV_TRUST_PARTNER_RESOLVED: str = "edges.xd_trust_partner_resolved"
#: A present-but-DISABLED trust (``trustDirection`` disabled) — no traversal edge,
#: but a disabled trust is forensically interesting (it existed), so it is counted
#: rather than a silent no-op.
COV_TRUST_DISABLED: str = "edges.xd_trust_disabled"
COV_FSP_RESOLVED: str = "edges.xd_fsp_resolved"
COV_SIDHISTORY_CROSS_DOMAIN: str = "edges.xd_sidhistory_cross_domain"
COV_SIDHISTORY_SAME_DOMAIN: str = "edges.xd_sidhistory_same_domain"

GAP_TRUST_TYPE_UNDETERMINED: str = "edges.xd_trust_type_undetermined"
#: A trust object with NO partner (``target_domain_id``) SID — un-wireable, NOT a
#: subtype ambiguity. Kept distinct from :data:`GAP_TRUST_TYPE_UNDETERMINED`.
GAP_TRUST_PARTNER_SID_MISSING: str = "edges.xd_trust_partner_sid_missing"
#: The partner (other) domain of a trust was not ingested -> its node is a stub.
GAP_TRUST_PARTNER_NOT_INGESTED: str = "edges.xd_trust_partner_not_ingested"
#: The LOCAL domain of a trust could not be resolved (no SID / no node) -> the
#: trust cannot be wired. Distinct from the PARTNER-not-ingested case.
GAP_TRUST_LOCAL_DOMAIN_UNRESOLVED: str = "edges.xd_trust_local_domain_unresolved"
GAP_FSP_OWNING_DOMAIN_NOT_INGESTED: str = "edges.xd_fsp_owning_domain_not_ingested"
#: The FSP's owning domain WAS ingested but the foreign SID resolved to NO live
#: principal (GC-shadow-only / orphaned / stale) — a real hunt signal (a dangling
#: cross-domain ACE / stale foreign SID), NOT the same as "domain not ingested".
GAP_FSP_PRINCIPAL_UNRESOLVED_IN_INGESTED_DOMAIN: str = (
    "edges.xd_fsp_principal_unresolved_in_ingested_domain"
)
GAP_FSP_PRINCIPAL_TYPE_UNKNOWN: str = "edges.xd_fsp_principal_type_unknown"
GAP_SIDHISTORY_OWNING_DOMAIN_NOT_INGESTED: str = "edges.xd_sidhistory_owning_domain_not_ingested"
GAP_GC_PARTIAL_REPLICA: str = "edges.xd_gc_partial_replica"

#: The ``principal_type`` of an unresolved foreign principal — NEVER blindly
#: ``Group`` (the logged single-DC blind spot, §4.2). ``Foreign`` says exactly what
#: is known: a cross-domain principal whose owning domain was not ingested.
FOREIGN_PRINCIPAL_TYPE: str = "Foreign"


# =============================================================================
# Pure decoders / inference (public [MS-ADTS] facts; no foreign code)
# =============================================================================
@dataclass(frozen=True)
class TrustAttributeFacts:
    """The decoded ``trustAttributes`` bitmask ([MS-ADTS] 6.1.6.7.12).

    Attributes:
        non_transitive: ``0x1`` NON_TRANSITIVE — the trust does not chain.
        quarantined_sid_filtering: ``0x4`` QUARANTINED_DOMAIN — SID filtering on.
        forest_transitive: ``0x8`` FOREST_TRANSITIVE — a forest trust root.
        cross_organization: ``0x10`` CROSS_ORGANIZATION — selective authentication.
        within_forest: ``0x20`` WITHIN_FOREST — both domains share this forest.
        treat_as_external: ``0x40`` TREAT_AS_EXTERNAL — SID filtering applied even
            though WITHIN_FOREST would normally exempt it.
        raw: the original bitmask (or ``None`` when absent).
    """

    non_transitive: bool
    quarantined_sid_filtering: bool
    forest_transitive: bool
    cross_organization: bool
    within_forest: bool
    treat_as_external: bool
    raw: int | None


def decode_trust_attribute_facts(trust_attributes: int | None) -> TrustAttributeFacts:
    """Decode the six attack-relevant ``trustAttributes`` bits (§4.3).

    Inputs:
        trust_attributes: the RAW ``trustAttributes`` bitmask, or ``None``.

    Returns:
        A :class:`TrustAttributeFacts`; every bit is ``False`` when the mask is
        ``None`` (unknown), ``raw`` preserved for provenance.

    Failure modes:
        Never raises.
    """
    bits = trust_attributes or 0
    return TrustAttributeFacts(
        non_transitive=bool(bits & TRUST_ATTR_NON_TRANSITIVE),
        quarantined_sid_filtering=bool(bits & TRUST_ATTR_QUARANTINED_DOMAIN),
        forest_transitive=bool(bits & TRUST_ATTR_FOREST_TRANSITIVE),
        cross_organization=bool(bits & TRUST_ATTR_CROSS_ORGANIZATION),
        within_forest=bool(bits & TRUST_ATTR_WITHIN_FOREST),
        treat_as_external=bool(bits & TRUST_ATTR_TREAT_AS_EXTERNAL),
        raw=trust_attributes,
    )


def trust_type_label(trust_type: int | None) -> str:
    """Return the ``trustType`` label (``downlevel``/``uplevel``/``mit``/``dce``).

    Inputs:
        trust_type: raw ``trustType`` (1 downlevel/NT4, 2 uplevel/AD, 3 MIT realm,
            4 DCE), or ``None``.

    Returns:
        The label, or ``"unknown"`` for an absent/unrecognized value.

    Failure modes:
        Never raises.
    """
    if trust_type is None:
        return "unknown"
    return _TRUST_TYPE_LABELS.get(trust_type, "unknown")


def infer_intra_forest_trust_type(
    local_fqdn: str | None,
    other_fqdn: str | None,
) -> str:
    """Infer parent-child vs tree-root for an intra-forest trust by FQDN (§4.3).

    Parent-child and tree-root trusts are both ``WITHIN_FOREST`` and are NOT
    distinguishable from any single attribute; the distinction is topological —
    a **contiguous DNS namespace** (one FQDN is the other's parent/child suffix,
    e.g. ``child.parent.tld`` under ``parent.tld``) is a parent-child trust, while
    a **new tree root** (sibling namespaces sharing only the forest, or disjoint
    namespaces) is a tree-root trust. This is a REAL multi-domain capability a
    single-DC case cannot have, and it is honest about its limits:

    * Both FQDNs known + contiguous -> :data:`TRUST_TYPE_PARENT_CHILD`.
    * Both FQDNs known + non-contiguous -> :data:`TRUST_TYPE_TREE_ROOT`.
    * Either FQDN unknown -> :data:`TRUST_TYPE_UNDETERMINED` (COUNTED, never guessed).

    Inputs:
        local_fqdn: the local domain's reconstructed FQDN, or ``None``.
        other_fqdn: the partner domain's reconstructed FQDN, or ``None``.

    Returns:
        One of the three ``TRUST_TYPE_*`` labels.

    Failure modes:
        Never raises.
    """
    if not local_fqdn or not other_fqdn:
        return TRUST_TYPE_UNDETERMINED
    a = local_fqdn.strip().lower().rstrip(".")
    b = other_fqdn.strip().lower().rstrip(".")
    if not a or not b or a == b:
        # Equal FQDNs are degenerate for this inference (same namespace, no tree
        # edge) — report undetermined rather than invent a relationship.
        return TRUST_TYPE_UNDETERMINED
    if _is_parent_child(a, b):
        return TRUST_TYPE_PARENT_CHILD
    return TRUST_TYPE_TREE_ROOT


def _is_parent_child(a: str, b: str) -> bool:
    """Return whether one lowercased FQDN is a direct DNS parent of the other.

    Contiguous namespace: ``a`` endswith ``.b`` (a is a child of b) or vice-versa.
    A dotted-label suffix match (``.`` guard) prevents ``notcorp.com`` matching
    ``corp.com``.
    """
    return a.endswith("." + b) or b.endswith("." + a)


def domain_sid_of(sid: str | None) -> str | None:
    """Return the domain portion of an ``S-1-5-21-a-b-c[-RID]`` SID, else ``None``.

    The domain SID is the first four sub-authorities after ``S-1-5`` (``21`` + the
    three 32-bit domain identifiers): ``S-1-5-21-a-b-c``. A SID already in that
    form returns itself; a SID with a trailing RID is truncated to it; any
    non-domain SID (well-known, BUILTIN, malformed) returns ``None``.

    Inputs:
        sid: a SID string, or ``None``.

    Returns:
        The ``S-1-5-21-a-b-c`` domain SID, or ``None``.

    Failure modes:
        Never raises.
    """
    if not sid:
        return None
    parts = sid.split("-")
    # S,1,5,21,a,b,c -> 7 parts is the bare domain SID; >7 carries a RID.
    if len(parts) < 7 or parts[:4] != ["S", "1", "5", "21"]:
        return None
    return "-".join(parts[:7])


# =============================================================================
# Domain registry — the cross-source resolution index
# =============================================================================
@dataclass(frozen=True)
class IngestedDomain:
    """One ingested domain the registry can resolve a foreign SID against.

    Attributes:
        domain_sid: the ``domainDNS`` objectSID (``S-1-5-21-a-b-c``).
        domain_fqdn: the reconstructed FQDN, or ``None``.
        forest_id: the scoping forest id.
        domain_node_id: the ``container_type='Domain'`` node id, or ``None``.
        is_global_catalog: whether the source that carried this domain is a GC
            (its cross-domain shadows must never win — §4.4).
    """

    domain_sid: str
    domain_fqdn: str | None
    forest_id: str
    domain_node_id: str | None
    is_global_catalog: bool


@dataclass
class DomainRegistry:
    """The cross-source resolution index over a multi-source canonical store.

    Holds every ingested domain (keyed by ``domain_sid``) and a SID -> (node_id,
    principal_type) index of the AUTHORITATIVE (full-domain, non-GC-shadow)
    principals, so a foreign SID resolves to the REAL principal node in its owning
    domain IFF that domain was ingested with a full copy. A Global-Catalog partial
    shadow is EXCLUDED from the authoritative index (§4.4 "never win over a
    full-domain copy") and counted.

    Attributes:
        domains: ``domain_sid`` -> :class:`IngestedDomain`.
        principal_by_sid: ``object_sid`` -> (``node_id``, ``principal_type``) for
            authoritative principals only.
        gc_shadow_count: the number of GC partial-replica principals excluded.
    """

    domains: dict[str, IngestedDomain] = field(default_factory=dict)
    principal_by_sid: dict[str, tuple[str, str]] = field(default_factory=dict)
    gc_shadow_count: int = 0

    def owning_domain(self, sid: str | None) -> IngestedDomain | None:
        """Return the ingested domain owning ``sid``, or ``None`` if not ingested."""
        dsid = domain_sid_of(sid)
        if dsid is None:
            return None
        return self.domains.get(dsid)

    def resolve_principal(self, sid: str) -> tuple[str, str] | None:
        """Return the authoritative (node_id, principal_type) for ``sid``, or ``None``."""
        return self.principal_by_sid.get(sid)


@dataclass(frozen=True)
class ForeignResolution:
    """The outcome of resolving a foreign SID to a principal node (§3.5 / §4.2).

    Attributes:
        node_id: the resolved real principal node, or a minted cross-domain stub.
        principal_type: the RESOLVED principal's type, or :data:`FOREIGN_PRINCIPAL_TYPE`
            when unresolved — NEVER a blind ``Group`` default.
        resolved: ``True`` when the owning domain was ingested (real node),
            ``False`` when it was a counted stub.
        owning_domain_ingested: whether the SID's domain is in the case at all.
    """

    node_id: str
    principal_type: str
    resolved: bool
    owning_domain_ingested: bool


def resolve_foreign_principal(
    sid: str,
    registry: DomainRegistry,
    forest_id: str,
) -> ForeignResolution:
    """Resolve a foreign SID to a real principal node, else a counted stub (§3.5).

    Resolution order:

    1. The SID matches an AUTHORITATIVE principal in the registry -> the real
       node + its real ``principal_type`` (``resolved=True``).
    2. The SID's owning domain is ingested but no authoritative principal matched
       (e.g. only a GC shadow existed, or the principal was not emitted) -> a
       minted stub keyed by :func:`node_id_for_sid`, typed
       :data:`FOREIGN_PRINCIPAL_TYPE`, ``resolved=False`` but
       ``owning_domain_ingested=True``.
    3. The SID's owning domain is NOT in the case -> the same minted stub with
       ``owning_domain_ingested=False`` (the caller counts
       ``*_owning_domain_not_ingested``).

    The stub ``node_id`` is deterministic and forest-scoped for a domain SID
    (globally unique), so repeated references dedup; it is NEVER a guessed concrete
    principal — it is an explicit placeholder the caller counts.

    Inputs:
        sid: the foreign SID (FSP RDN SID, trust partner, or historical SID).
        registry: the cross-source :class:`DomainRegistry`.
        forest_id: the scoping forest id for the stub ``node_id``.

    Returns:
        A :class:`ForeignResolution`.

    Failure modes:
        Never raises.
    """
    hit = registry.resolve_principal(sid)
    if hit is not None:
        node_id, ptype = hit
        return ForeignResolution(
            node_id=node_id,
            principal_type=ptype,
            resolved=True,
            owning_domain_ingested=True,
        )
    owning = registry.owning_domain(sid)
    stub_node = node_id_for_sid(forest_id, domain_sid_of(sid), sid)
    return ForeignResolution(
        node_id=stub_node,
        principal_type=FOREIGN_PRINCIPAL_TYPE,
        resolved=False,
        owning_domain_ingested=owning is not None,
    )


# =============================================================================
# Trust edges (ATTACK direction = trusted -> trusting) with FQDN inference
# =============================================================================
@dataclass(frozen=True)
class TrustEdgeFacts:
    """The decoded + inferred facts of one trust, for the result/report (§6).

    Attributes:
        local_domain_sid: the trust's local (source) domain SID.
        other_domain_sid: the partner domain SID, or ``None`` when absent.
        attributes: the decoded :class:`TrustAttributeFacts`.
        type_label: the ``trustType`` label.
        inferred_intra_forest_type: parent-child / tree-root / undetermined (§4.3).
        partner_ingested: whether the partner domain was in the case.
    """

    local_domain_sid: str | None
    other_domain_sid: str | None
    attributes: TrustAttributeFacts
    type_label: str
    inferred_intra_forest_type: str
    partner_ingested: bool


def classify_trust(
    local_domain_sid: str | None,
    other_domain_sid: str | None,
    trust_type: int | None,
    trust_attributes: int | None,
    local_fqdn: str | None,
    other_fqdn: str | None,
    partner_ingested: bool,
) -> TrustEdgeFacts:
    """Decode + infer the full fact set for one trust (pure; §4.3).

    Combines :func:`decode_trust_attribute_facts`, :func:`trust_type_label`, and
    (for ``WITHIN_FOREST`` trusts) :func:`infer_intra_forest_trust_type`. A trust
    that is not intra-forest reports :data:`TRUST_TYPE_UNDETERMINED` for the
    intra-forest subtype (the parent-child/tree-root distinction does not apply to
    an external/forest trust) — the caller only COUNTS the undetermined subtype for
    intra-forest trusts.

    Inputs:
        local_domain_sid / other_domain_sid: the trust endpoints' domain SIDs.
        trust_type / trust_attributes: the raw ``trustType`` / ``trustAttributes``.
        local_fqdn / other_fqdn: the reconstructed FQDNs for inference.
        partner_ingested: whether the partner domain is in the case.

    Returns:
        A :class:`TrustEdgeFacts`.

    Failure modes:
        Never raises.
    """
    attrs = decode_trust_attribute_facts(trust_attributes)
    if attrs.within_forest:
        inferred = infer_intra_forest_trust_type(local_fqdn, other_fqdn)
    else:
        inferred = TRUST_TYPE_UNDETERMINED
    return TrustEdgeFacts(
        local_domain_sid=local_domain_sid,
        other_domain_sid=other_domain_sid,
        attributes=attrs,
        type_label=trust_type_label(trust_type),
        inferred_intra_forest_type=inferred,
        partner_ingested=partner_ingested,
    )


def _trust_direction_pairs(direction: str | None, local: str, other: str) -> list[tuple[str, str]]:
    """Return the attack-direction (trusted -> trusting) endpoint pairs.

    ``inbound`` (the partner trusts local) -> local is TRUSTED -> ``local -> other``;
    ``outbound`` (local trusts the partner) -> ``other -> local``; ``bidirectional``
    -> both; ``disabled`` / ``None`` -> no traversal edge. (Mirrors the existing
    single-domain ``build_trust_edges`` convention, consistent with module 10.)
    """
    if direction == "inbound":
        return [(local, other)]
    if direction == "outbound":
        return [(other, local)]
    if direction == "bidirectional":
        return [(local, other), (other, local)]
    return []


# =============================================================================
# Thin orchestrator over a multi-source canonical store
# =============================================================================
@dataclass(frozen=True)
class CrossDomainResult:
    """Counts-only outcome of a cross-domain derivation pass (never secrets)."""

    trust_edges: int
    trust_keys: int
    trust_parent_child: int
    trust_tree_root: int
    trust_type_undetermined: int
    trust_partner_resolved: int
    trust_partner_not_ingested: int
    trust_partner_sid_missing: int
    trust_local_domain_unresolved: int
    trust_disabled: int
    fsp_edges: int
    fsp_resolved: int
    fsp_owning_domain_not_ingested: int
    fsp_principal_unresolved_in_ingested_domain: int
    fsp_principal_type_by_kind: Mapping[str, int]
    sidhistory_cross_domain: int
    sidhistory_same_domain: int
    sidhistory_owning_domain_not_ingested: int
    gc_partial_replica: int
    edges_written: int


def build_domain_registry(con: duckdb.DuckDBPyConnection) -> DomainRegistry:
    """Build the :class:`DomainRegistry` from a multi-source canonical store.

    Reads the ``source`` dimension (which domains / GC flags are ingested), the
    ``container`` Domain rows (domain node ids + FQDNs), and the ``principal``
    table (the SID -> node resolution index). A principal observed ONLY as a GC
    partial shadow — observed by a GC source whose home domain differs from the
    principal's domain, with NO full-domain source for that domain — is EXCLUDED
    from the authoritative index and counted (§4.4).

    Inputs:
        con: an open canonical store (``source``, ``container``, ``principal``,
            ``source_observation`` present).

    Returns:
        A populated :class:`DomainRegistry`.

    Failure modes:
        Raises ``duckdb.Error`` only if the required tables are absent.
    """
    registry = DomainRegistry()

    # Which domains are ingested, and by which GC sources? Each source's HOME
    # domain (``source.domain_id``) is a FULL copy of that domain (a GC is a full
    # DC for its own domain); a GC's CROSS-domain shadows never win (``_is_gc_shadow``).
    gc_sources: set[str] = set()
    source_home: dict[str, str] = {}
    for sid_, domain_id, is_gc in con.execute(
        "SELECT source_id, domain_id, is_global_catalog FROM source ORDER BY source_id"
    ).fetchall():
        if domain_id is None:
            continue
        source_home[str(sid_)] = str(domain_id)
        if is_gc:
            gc_sources.add(str(sid_))

    # Domain node ids + FQDNs + forest from the container Domain rows.
    domain_nodes: dict[str, tuple[str | None, str | None, str]] = {}
    for node_id, object_sid, fqdn, forest in con.execute(
        "SELECT node_id, object_sid, domain_fqdn, forest_id FROM container "
        "WHERE container_type = 'Domain' AND object_sid IS NOT NULL ORDER BY node_id"
    ).fetchall():
        domain_nodes[str(object_sid)] = (str(node_id), fqdn, str(forest))

    # Register every ingested domain (prefer a container Domain node for metadata).
    # A domain is a GC-only SHADOW iff NO source (GC or not) has it as its HOME
    # domain — a GC is a FULL copy of its own home domain, so a GC's home is never
    # a shadow. (Cosmetic/report-honesty only; resolution gates on ``_is_gc_shadow``
    # per-principal, not this flag.)
    home_domains = set(source_home.values())
    all_domain_sids = home_domains | set(domain_nodes)
    for dsid in sorted(all_domain_sids):
        node_id, fqdn, forest = domain_nodes.get(dsid, (None, None, ""))
        registry.domains[dsid] = IngestedDomain(
            domain_sid=dsid,
            domain_fqdn=fqdn,
            forest_id=forest,
            domain_node_id=node_id,
            is_global_catalog=dsid not in home_domains,
        )

    # The authoritative principal index: object_sid -> (node_id, principal_type),
    # EXCLUDING (a) ForeignSecurityPrincipal stubs — they CARRY a foreign SID but are
    # local placeholders, never the real principal, so they must not resolve their
    # own SID — and (b) principals that exist only as a GC partial shadow (§4.4).
    # The DN ``LIKE`` filter catches DN-bearing FSPs; the STRUCTURAL guard below
    # (``pdomain != row domain_id``) closes the NULL-DN case — a local object whose
    # SID's domain differs from the domain it lives in is foreign-SID-bearing (an
    # FSP-shaped row) and must not resolve its own SID either.
    node_to_sources = _node_source_map(con)
    for node_id, object_sid, ptype, row_domain_id in con.execute(
        "SELECT node_id, object_sid, principal_type, domain_id FROM principal "
        "WHERE object_sid IS NOT NULL "
        "AND (distinguished_name IS NULL "
        "OR upper(distinguished_name) NOT LIKE '%CN=FOREIGNSECURITYPRINCIPALS%') "
        "ORDER BY node_id"
    ).fetchall():
        sid = str(object_sid)
        pdomain = domain_sid_of(sid)
        if pdomain is None:
            continue
        # Structural NULL-DN hardening: a foreign SID sitting in a KNOWN local
        # domain is an FSP-shaped stub -> never authoritative. (Only applied when
        # ``domain_id`` is known, so a real principal with an unresolved domain is
        # not wrongly excluded.)
        if row_domain_id is not None and pdomain != str(row_domain_id):
            continue
        if _is_gc_shadow(str(node_id), pdomain, node_to_sources, source_home, gc_sources):
            registry.gc_shadow_count += 1
            continue
        registry.principal_by_sid[sid] = (str(node_id), str(ptype))

    return registry


def _is_gc_shadow(
    node_id: str,
    principal_domain: str,
    node_to_sources: Mapping[str, set[str]],
    source_home: Mapping[str, str],
    gc_sources: set[str],
) -> bool:
    """Return whether a principal exists ONLY as a GC partial shadow (§4.4).

    True when every source that observed the node is a GC whose home domain is
    NOT the principal's own domain (a cross-domain partial-attribute shadow), i.e.
    there is no full-domain or home-domain observation of this principal.
    """
    observers = node_to_sources.get(node_id)
    if not observers:
        return False
    for src in observers:
        is_gc = src in gc_sources
        home = source_home.get(src)
        # A full (non-GC) observation, or a GC observing its OWN home domain,
        # is an authoritative copy -> not a shadow.
        if not is_gc or home == principal_domain:
            return False
    return True


def _node_source_map(con: duckdb.DuckDBPyConnection) -> dict[str, set[str]]:
    """Return ``node_id -> {source_id}`` from ``source_observation`` (obj_kind='node')."""
    out: dict[str, set[str]] = {}
    for obj_id, source_id in con.execute(
        "SELECT obj_id, source_id FROM source_observation WHERE obj_kind = 'node'"
    ).fetchall():
        out.setdefault(str(obj_id), set()).add(str(source_id))
    return out


def _edge_provenance(obj_prov: ProvenanceStruct, edge_tag: str) -> ProvenanceStruct:
    """Derive a cross-domain edge's provenance from its originating object.

    Keeps the originating object's ``image_sha256`` / ``source_file`` /
    ``directory_timestamp`` (so the edge is bound to the exact artifact + object
    version) and stamps ``source_object_id = "<original>:<edge_tag>"``.
    """
    base_oid = obj_prov.source_object_id or ""
    return ProvenanceStruct(
        source_file=obj_prov.source_file,
        image_sha256=obj_prov.image_sha256,
        source_object_id=f"{base_oid}:{edge_tag}",
        directory_timestamp=obj_prov.directory_timestamp,
        ingest_run_id=obj_prov.ingest_run_id,
    )


def _make_edge(
    kind: str,
    derivation: str,
    source_node_id: str,
    target_node_id: str,
    provenance: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow:
    """Build one cross-domain §4 edge (NULL mask/object_type_guid, confirmed)."""
    forest_id, domain_id, domain_fqdn = scoping
    return EdgeRow(
        edge_id=stable_id(kind, source_node_id, target_node_id, derivation),
        kind=kind,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        is_inherited=False,
        derivation=derivation,
        access_mask=None,
        object_type_guid=None,
        confidence=CONFIDENCE_CONFIRMED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=provenance,
    )


def derive_cross_domain_edges(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
) -> CrossDomainResult:
    """Derive + persist the cross-domain edges over a multi-source store (§4).

    PER-SOURCE discipline: every edge originates from one source's object (trust
    object, FSP stub, or a principal's ``sIDHistory``); the edge is written to the
    frozen ``edge`` table AND registered in ``source_observation`` under that
    originating ``source_id`` so a scoped view surfaces exactly that source's
    edges. A cross-source endpoint is resolved to the real foreign principal IFF
    its owning domain was ingested, else a COUNTED stub (never a guess). On a
    single-domain store (no trusts, no cross-domain FSPs/sIDHistory) this emits
    ZERO cross-domain edges — the regression guarantee.

    Inputs:
        con: an open, writable, multi-source canonical store (canonical tables +
            ``source`` / ``source_observation`` populated by the prior passes).
        run: the :class:`~wraith.case.ingest_run.IngestRun` the counted coverage /
            gap counters are surfaced on.

    Returns:
        A :class:`CrossDomainResult` (counts only; never secrets).

    Failure modes:
        Raises ``duckdb.Error`` if the required tables are absent; a malformed
        individual row degrades to a counted gap, never a crash or silent drop.
    """
    registry = build_domain_registry(con)
    node_to_source = _primary_node_source(con)
    edges: list[tuple[EdgeRow, str | None]] = []  # (edge, originating_source_id)

    trust_counts = _derive_trusts(con, registry, node_to_source, edges)
    fsp_counts, fsp_by_type = _derive_fsps(con, registry, node_to_source, edges)
    sh_counts = _derive_sid_history(con, registry, node_to_source, edges)

    edges_written = _write_edges(con, edges)

    result = CrossDomainResult(
        trust_edges=trust_counts["edges"],
        trust_keys=trust_counts["keys"],
        trust_parent_child=trust_counts["parent_child"],
        trust_tree_root=trust_counts["tree_root"],
        trust_type_undetermined=trust_counts["undetermined"],
        trust_partner_resolved=trust_counts["partner_resolved"],
        trust_partner_not_ingested=trust_counts["partner_not_ingested"],
        trust_partner_sid_missing=trust_counts["partner_sid_missing"],
        trust_local_domain_unresolved=trust_counts["local_unresolved"],
        trust_disabled=trust_counts["disabled"],
        fsp_edges=fsp_counts["edges"],
        fsp_resolved=fsp_counts["resolved"],
        fsp_owning_domain_not_ingested=fsp_counts["not_ingested"],
        fsp_principal_unresolved_in_ingested_domain=fsp_counts["unresolved_in_ingested"],
        fsp_principal_type_by_kind=fsp_by_type,
        sidhistory_cross_domain=sh_counts["cross_domain"],
        sidhistory_same_domain=sh_counts["same_domain"],
        sidhistory_owning_domain_not_ingested=sh_counts["not_ingested"],
        gc_partial_replica=registry.gc_shadow_count,
        edges_written=edges_written,
    )
    _bump_run(run, result)
    return result


def _primary_node_source(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """Return ``node_id -> originating source_id`` (lowest ``source_id`` on a tie).

    In Phase 1 each node has exactly one observation, so the tie-break never fires;
    it only guarantees determinism if a node were ever multiply observed.
    """
    out: dict[str, str] = {}
    for obj_id, source_id in con.execute(
        "SELECT obj_id, source_id FROM source_observation "
        "WHERE obj_kind = 'node' ORDER BY obj_id, source_id"
    ).fetchall():
        out.setdefault(str(obj_id), str(source_id))
    return out


def _derive_trusts(
    con: duckdb.DuckDBPyConnection,
    registry: DomainRegistry,
    node_to_source: Mapping[str, str],
    edges: list[tuple[EdgeRow, str | None]],
) -> dict[str, int]:
    """Derive attack-direction trust edges with FQDN-inferred ``trust_type`` (§4.3)."""
    counts = {
        "edges": 0,
        "keys": 0,
        "parent_child": 0,
        "tree_root": 0,
        "undetermined": 0,
        "partner_resolved": 0,
        "partner_not_ingested": 0,
        "partner_sid_missing": 0,
        "local_unresolved": 0,
        "disabled": 0,
    }
    rows = con.execute(
        "SELECT node_id, source_domain_id, target_domain_id, direction, trust_type, "
        "trust_attributes, trust_key_ref, forest_id, domain_id, domain_fqdn, provenance "
        "FROM trust ORDER BY node_id"
    ).fetchall()
    for (
        trust_node_id,
        local_sid,
        other_sid,
        direction,
        trust_type,
        attrs_bits,
        trust_key_ref,
        forest_id,
        domain_id,
        domain_fqdn,
        provenance,
    ) in rows:
        obj_prov = ProvenanceStruct.model_validate(provenance)
        scoping = (str(forest_id), domain_id, domain_fqdn)
        attrs = decode_trust_attribute_facts(attrs_bits)
        origin_source = node_to_source.get(str(trust_node_id))

        # A present-but-disabled trust is forensically interesting (it existed) —
        # count it even though no traversal edge is produced (never a silent no-op).
        if direction == "disabled":
            counts["disabled"] += 1

        if other_sid is None:
            # No partner SID -> un-wireable trust, NOT a subtype ambiguity.
            counts["partner_sid_missing"] += 1
            continue

        # Local + partner domain node resolution (prefer the real ingested Domain).
        local_dom = registry.domains.get(str(local_sid)) if local_sid else None
        other_dom = registry.domains.get(str(other_sid))
        local_node: str | None
        if local_dom is not None and local_dom.domain_node_id:
            local_node = local_dom.domain_node_id
        elif local_sid is not None:
            local_node = node_id_for_sid(str(forest_id), str(local_sid), str(local_sid))
        else:
            local_node = None
        if local_node is None:
            # The LOCAL side failed to resolve (no SID / no node) -> un-wireable;
            # labelled distinctly from a partner-not-ingested gap.
            counts["local_unresolved"] += 1
            continue
        partner_ingested = other_dom is not None
        if other_dom is not None and other_dom.domain_node_id:
            other_node = other_dom.domain_node_id
            counts["partner_resolved"] += 1
        else:
            other_node = node_id_for_sid(str(forest_id), str(other_sid), str(other_sid))
            counts["partner_not_ingested"] += 1

        # Decode + infer the full fact set (parent-child vs tree-root by FQDN).
        facts = classify_trust(
            local_domain_sid=str(local_sid) if local_sid else None,
            other_domain_sid=str(other_sid),
            trust_type=trust_type,
            trust_attributes=attrs_bits,
            local_fqdn=local_dom.domain_fqdn if local_dom else domain_fqdn,
            other_fqdn=other_dom.domain_fqdn if other_dom else None,
            partner_ingested=partner_ingested,
        )
        if attrs.within_forest:
            inferred = facts.inferred_intra_forest_type
            if inferred == TRUST_TYPE_PARENT_CHILD:
                counts["parent_child"] += 1
            elif inferred == TRUST_TYPE_TREE_ROOT:
                counts["tree_root"] += 1
            else:
                counts["undetermined"] += 1

        kind = KIND_SAME_FOREST_TRUST if attrs.within_forest else KIND_CROSS_FOREST_TRUST
        derivation = DERIVATION_SAME_FOREST if attrs.within_forest else DERIVATION_CROSS_FOREST
        for src_node, tgt_node in _trust_direction_pairs(direction, local_node, other_node):
            edges.append(
                (
                    _make_edge(
                        kind,
                        derivation,
                        src_node,
                        tgt_node,
                        _edge_provenance(obj_prov, "trust"),
                        scoping,
                    ),
                    origin_source,
                )
            )
            counts["edges"] += 1
        if trust_key_ref is not None:
            edges.append(
                (
                    _make_edge(
                        KIND_HAS_TRUST_KEYS,
                        DERIVATION_TRUST_KEYS,
                        local_node,
                        other_node,
                        _edge_provenance(obj_prov, "trustkeys"),
                        scoping,
                    ),
                    origin_source,
                )
            )
            counts["keys"] += 1
    return counts


def _derive_fsps(
    con: duckdb.DuckDBPyConnection,
    registry: DomainRegistry,
    node_to_source: Mapping[str, str],
    edges: list[tuple[EdgeRow, str | None]],
) -> tuple[dict[str, int], dict[str, int]]:
    """Resolve FSP stubs to the real foreign principal, else a counted stub (§4.2).

    Returns ``(counts, principal_type_by_kind)`` — the scalar counters and the
    RESOLVED principal_type distribution (``Foreign`` for every counted stub, never
    a blind ``Group``).
    """
    counts = {"edges": 0, "resolved": 0, "not_ingested": 0, "unresolved_in_ingested": 0}
    by_type: dict[str, int] = {}
    rows = con.execute(
        "SELECT node_id, object_sid, forest_id, domain_id, domain_fqdn, provenance "
        "FROM principal "
        "WHERE distinguished_name IS NOT NULL "
        "AND upper(distinguished_name) LIKE '%CN=FOREIGNSECURITYPRINCIPALS%' "
        "AND object_sid IS NOT NULL ORDER BY node_id"
    ).fetchall()
    for fsp_node_id, object_sid, forest_id, domain_id, domain_fqdn, provenance in rows:
        sid = str(object_sid)
        # A well-known / BUILTIN FSP (e.g. S-1-5-11 Authenticated Users) is NOT a
        # cross-domain principal — skip it (it is a local special identity).
        if not is_domain_specific_sid(sid):
            continue
        obj_prov = ProvenanceStruct.model_validate(provenance)
        scoping = (str(forest_id), domain_id, domain_fqdn)
        res = resolve_foreign_principal(sid, registry, str(forest_id))
        if res.resolved:
            # Edge: REAL foreign principal -> local FSP stub (control flows in).
            edges.append(
                (
                    _make_edge(
                        KIND_FOREIGN_IDENTITY,
                        DERIVATION_FOREIGN_IDENTITY,
                        res.node_id,
                        str(fsp_node_id),
                        _edge_provenance(obj_prov, "fsp"),
                        scoping,
                    ),
                    node_to_source.get(str(fsp_node_id)),
                )
            )
            counts["edges"] += 1
            counts["resolved"] += 1
            by_type[res.principal_type] = by_type.get(res.principal_type, 0) + 1
        elif res.owning_domain_ingested:
            # Owning domain WAS ingested but the foreign SID resolved to no live
            # principal (GC-shadow-only / orphaned / stale) -> a real hunt signal
            # (a dangling cross-domain ACE / stale foreign SID), kept DISTINCT from
            # "domain not ingested". Counted stub, never a blind Group type.
            counts["unresolved_in_ingested"] += 1
            by_type[FOREIGN_PRINCIPAL_TYPE] = by_type.get(FOREIGN_PRINCIPAL_TYPE, 0) + 1
        else:
            # Owning domain not ingested -> counted stub, NEVER a blind Group type.
            counts["not_ingested"] += 1
            by_type[FOREIGN_PRINCIPAL_TYPE] = by_type.get(FOREIGN_PRINCIPAL_TYPE, 0) + 1
    return counts, by_type


def _derive_sid_history(
    con: duckdb.DuckDBPyConnection,
    registry: DomainRegistry,
    node_to_source: Mapping[str, str],
    edges: list[tuple[EdgeRow, str | None]],
) -> dict[str, int]:
    """Emit ``HasSIDHistory`` edges; resolve cross-domain far ends when ingested (§4.1)."""
    counts = {"cross_domain": 0, "same_domain": 0, "not_ingested": 0}
    rows = con.execute(
        "SELECT node_id, object_sid, sid_history, forest_id, domain_id, domain_fqdn, provenance "
        "FROM principal WHERE sid_history IS NOT NULL AND length(sid_history) > 0 ORDER BY node_id"
    ).fetchall()
    for node_id, object_sid, sid_history, forest_id, domain_id, domain_fqdn, provenance in rows:
        obj_prov = ProvenanceStruct.model_validate(provenance)
        scoping = (str(forest_id), domain_id, domain_fqdn)
        own_domain = domain_sid_of(str(object_sid)) if object_sid else None
        origin_source = node_to_source.get(str(node_id))
        for old_sid in sid_history:
            old_sid = str(old_sid)
            old_domain = domain_sid_of(old_sid)
            is_cross = old_domain is not None and old_domain != own_domain
            if is_cross:
                res = resolve_foreign_principal(old_sid, registry, str(forest_id))
                target = res.node_id
                counts["cross_domain"] += 1
                if not res.owning_domain_ingested:
                    counts["not_ingested"] += 1
            else:
                # Same-domain history: resolve to the real principal if present,
                # else a forest/domain-scoped stub (the pre-existing behaviour).
                hit = registry.resolve_principal(old_sid)
                target = (
                    hit[0]
                    if hit is not None
                    else node_id_for_sid(str(forest_id), domain_id, old_sid)
                )
                counts["same_domain"] += 1
            if target == str(node_id):
                continue
            edges.append(
                (
                    _make_edge(
                        KIND_HAS_SID_HISTORY,
                        DERIVATION_SID_HISTORY,
                        str(node_id),
                        target,
                        _edge_provenance(obj_prov, "sidhistory"),
                        scoping,
                    ),
                    origin_source,
                )
            )
    return counts


def _write_edges(
    con: duckdb.DuckDBPyConnection,
    edges: Sequence[tuple[EdgeRow, str | None]],
) -> int:
    """Write the cross-domain edges + per-edge ``source_observation`` tags.

    Dedup by ``edge_id`` (``INSERT OR IGNORE``) so a re-run is idempotent and two
    sources asserting the identical fact collapse to one row. Each edge's
    originating ``source_id`` is registered as a ``source_observation`` edge row so
    a scoped view surfaces exactly that source's cross-domain edges (§3.5).

    Returns:
        The number of DISTINCT cross-domain edge ids written.
    """
    seen: set[str] = set()
    written = 0
    for edge, origin_source in edges:
        if edge.edge_id not in seen:
            con.execute(
                "INSERT OR IGNORE INTO edge "
                "(edge_id, kind, source_node_id, target_node_id, is_inherited, derivation, "
                "access_mask, object_type_guid, confidence, forest_id, domain_id, domain_fqdn, "
                "provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                list(edge.to_db_values()),
            )
            seen.add(edge.edge_id)
            written += 1
        if origin_source is not None:
            con.execute(
                "INSERT OR IGNORE INTO source_observation "
                "(obj_kind, obj_id, source_id, directory_timestamp, when_created, "
                "usn_local, is_deleted, attr_metadata_blob) "
                "VALUES ('edge', ?, ?, NULL, NULL, NULL, FALSE, NULL)",
                [edge.edge_id, origin_source],
            )
    return written


def _bump_run(run: IngestRun, result: CrossDomainResult) -> None:
    """Surface every cross-domain coverage + counted-gap counter on the run."""
    run.bump_coverage(COV_TRUST, result.trust_edges)
    run.bump_coverage(COV_TRUST_KEYS, result.trust_keys)
    run.bump_coverage(COV_TRUST_PARENT_CHILD, result.trust_parent_child)
    run.bump_coverage(COV_TRUST_TREE_ROOT, result.trust_tree_root)
    run.bump_coverage(COV_TRUST_PARTNER_RESOLVED, result.trust_partner_resolved)
    run.bump_coverage(COV_TRUST_DISABLED, result.trust_disabled)
    run.bump_coverage(COV_FSP_RESOLVED, result.fsp_resolved)
    run.bump_coverage(COV_SIDHISTORY_CROSS_DOMAIN, result.sidhistory_cross_domain)
    run.bump_coverage(COV_SIDHISTORY_SAME_DOMAIN, result.sidhistory_same_domain)
    run.bump_skip(GAP_TRUST_TYPE_UNDETERMINED, result.trust_type_undetermined)
    run.bump_skip(GAP_TRUST_PARTNER_SID_MISSING, result.trust_partner_sid_missing)
    run.bump_skip(GAP_TRUST_PARTNER_NOT_INGESTED, result.trust_partner_not_ingested)
    run.bump_skip(GAP_TRUST_LOCAL_DOMAIN_UNRESOLVED, result.trust_local_domain_unresolved)
    run.bump_skip(GAP_FSP_OWNING_DOMAIN_NOT_INGESTED, result.fsp_owning_domain_not_ingested)
    run.bump_skip(
        GAP_FSP_PRINCIPAL_UNRESOLVED_IN_INGESTED_DOMAIN,
        result.fsp_principal_unresolved_in_ingested_domain,
    )
    run.bump_skip(
        GAP_SIDHISTORY_OWNING_DOMAIN_NOT_INGESTED,
        result.sidhistory_owning_domain_not_ingested,
    )
    run.bump_skip(GAP_GC_PARTIAL_REPLICA, result.gc_partial_replica)
    # FSP principal_type distribution: a stub (unresolved) type is a counted gap.
    unknown = result.fsp_principal_type_by_kind.get(FOREIGN_PRINCIPAL_TYPE, 0)
    if unknown:
        run.bump_skip(GAP_FSP_PRINCIPAL_TYPE_UNKNOWN, unknown)


__all__ = [
    "COV_FSP_RESOLVED",
    "COV_SIDHISTORY_CROSS_DOMAIN",
    "COV_SIDHISTORY_SAME_DOMAIN",
    "COV_TRUST",
    "COV_TRUST_KEYS",
    "COV_TRUST_PARENT_CHILD",
    "COV_TRUST_DISABLED",
    "COV_TRUST_PARTNER_RESOLVED",
    "COV_TRUST_TREE_ROOT",
    "DERIVATION_FOREIGN_IDENTITY",
    "FOREIGN_PRINCIPAL_TYPE",
    "GAP_FSP_OWNING_DOMAIN_NOT_INGESTED",
    "GAP_FSP_PRINCIPAL_TYPE_UNKNOWN",
    "GAP_FSP_PRINCIPAL_UNRESOLVED_IN_INGESTED_DOMAIN",
    "GAP_GC_PARTIAL_REPLICA",
    "GAP_SIDHISTORY_OWNING_DOMAIN_NOT_INGESTED",
    "GAP_TRUST_LOCAL_DOMAIN_UNRESOLVED",
    "GAP_TRUST_PARTNER_NOT_INGESTED",
    "GAP_TRUST_PARTNER_SID_MISSING",
    "GAP_TRUST_TYPE_UNDETERMINED",
    "KIND_FOREIGN_IDENTITY",
    "TRUST_TYPE_PARENT_CHILD",
    "TRUST_TYPE_TREE_ROOT",
    "TRUST_TYPE_UNDETERMINED",
    "CrossDomainResult",
    "DomainRegistry",
    "ForeignResolution",
    "IngestedDomain",
    "TrustAttributeFacts",
    "TrustEdgeFacts",
    "build_domain_registry",
    "classify_trust",
    "decode_trust_attribute_facts",
    "derive_cross_domain_edges",
    "domain_sid_of",
    "infer_intra_forest_trust_type",
    "resolve_foreign_principal",
    "trust_type_label",
]
