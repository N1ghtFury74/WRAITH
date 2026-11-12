"""Non-SD / attribute- and flag-derived edge builders (slice 5B).

The edges here do not come from the object DACL (that is slice 5A). They derive
from specific attributes and from the M3 ``trust`` / ``adcs`` tables, reusing the
slice-5A seams unchanged: the shared :class:`~wraith.edges.acl.NodeResolver`
(mint-on-miss), :func:`~wraith.edges.acl.parse_sd` (the RBCD / gMSA attribute
values are themselves security descriptors), the :class:`~wraith.edges.models.EdgeRow`
writer, and the GUID classifier (for ADCS object-control / enrollment facts).

Builders (all pure; the orchestrator does the DB I/O):

* **Constrained delegation** — ``msDS-AllowedToDelegateTo`` SPN list -> one
  ``AllowedToDelegate`` edge per resolved target-service host.
* **RBCD** — ``msDS-AllowedToActOnBehalfOfOtherIdentity`` (an SD) -> one
  ``AllowedToAct`` edge per ALLOW trustee.
* **ReadGMSAPassword** — ``msDS-GroupMSAMembership`` (an SD) -> one
  ``ReadGMSAPassword`` edge per ALLOW trustee.
* **HasSIDHistory** — ``principal.sid_history`` -> one ``HasSIDHistory`` edge per
  historical SID.
* **Trust** — the M3 ``trust`` table -> ``SameForestTrust`` / ``CrossForestTrust``
  in the ATTACK direction (+ optional ``HasTrustKeys``).
* **ADCS base facts** — ``adcs`` + staged SD -> ``Enroll`` / ``AutoEnroll`` /
  ``WritePKI*Flag`` / ``PublishedTo`` (ESC composition stays BloodHound's).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from wraith.common.determinism import stable_id
from wraith.edges.acl import NodeResolver, _sd_provenance, parse_sd
from wraith.edges.guid_map import (
    KIND_PUBLISHED_TO,
    PkiFlagGuids,
    classify_adcs_ace,
)
from wraith.edges.models import EdgeRow
from wraith.normalize.decoders import (
    TRUST_ATTR_QUARANTINED_DOMAIN,
    TRUST_ATTR_WITHIN_FOREST,
)
from wraith.provenance.models import ProvenanceStruct

CONFIDENCE_CONFIRMED: str = "confirmed"

# --- §4 kinds + derivation tags (5B) -----------------------------------------
KIND_ALLOWED_TO_DELEGATE: str = "AllowedToDelegate"
KIND_ALLOWED_TO_ACT: str = "AllowedToAct"
KIND_READ_GMSA_PASSWORD: str = "ReadGMSAPassword"  # noqa: S105 - edge-kind name
KIND_HAS_SID_HISTORY: str = "HasSIDHistory"
KIND_SAME_FOREST_TRUST: str = "SameForestTrust"
KIND_CROSS_FOREST_TRUST: str = "CrossForestTrust"
KIND_HAS_TRUST_KEYS: str = "HasTrustKeys"
KIND_CONTAINS: str = "Contains"
KIND_GPLINK: str = "GPLink"
KIND_COERCE_TO_TGT: str = "CoerceToTGT"  # noqa: S105 - edge-kind name, not a secret

DERIVATION_ALLOWED_TO_DELEGATE: str = "ATTR:AllowedToDelegate"
DERIVATION_RBCD: str = "ATTR:RBCD"
DERIVATION_GMSA: str = "ATTR:gMSAMembership"
DERIVATION_SID_HISTORY: str = "ATTR:SIDHistory"
DERIVATION_SAME_FOREST: str = "TRUST:SameForest"
DERIVATION_CROSS_FOREST: str = "TRUST:CrossForest"
DERIVATION_TRUST_KEYS: str = "ATTR:TrustKeys"
DERIVATION_PUBLISHED_TO: str = "ADCS:PublishedTo"
DERIVATION_CONTAINS: str = "STRUCT:parent"
DERIVATION_GPLINK: str = "ATTR:gPLink"
DERIVATION_COERCE_TGT: str = "FLAG:unconstrained"

# --- attribute names (lDAPDisplayName, as keyed in staging_object.attributes) -
ATTR_ALLOWED_TO_DELEGATE_TO: str = "msDS-AllowedToDelegateTo"
ATTR_ALLOWED_TO_ACT: str = "msDS-AllowedToActOnBehalfOfOtherIdentity"
ATTR_GROUP_MSA_MEMBERSHIP: str = "msDS-GroupMSAMembership"


def _edge(
    kind: str,
    derivation: str,
    source_node_id: str,
    target_node_id: str,
    provenance: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow:
    """Build one non-ACL §4 edge (NULL mask/object_type_guid, confidence confirmed)."""
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


def _stamped_provenance(obj_prov: ProvenanceStruct, source_object_id: str) -> ProvenanceStruct:
    """Copy ``obj_prov`` keeping file/image/timestamp but re-stamping the object id."""
    return ProvenanceStruct(
        source_file=obj_prov.source_file,
        image_sha256=obj_prov.image_sha256,
        source_object_id=source_object_id,
        directory_timestamp=obj_prov.directory_timestamp,
        ingest_run_id=obj_prov.ingest_run_id,
    )


def _attr_provenance(obj_prov: ProvenanceStruct, node_id: str, attr: str) -> ProvenanceStruct:
    """Provenance for an attribute-derived edge (``<node_id>:attr:<attr>``)."""
    return _stamped_provenance(obj_prov, f"{node_id}:attr:{attr}")


# =============================================================================
# SPN -> service-host resolution (constrained delegation)
# =============================================================================


@dataclass(frozen=True)
class SpnIndex:
    """Lookup from a target SPN to the node running that service.

    Attributes:
        spn_to_node: full SPN (lowercase) -> ``node_id`` (exact match first).
        host_to_node: service host (lowercase, port stripped) -> ``node_id``
            (fallback when the exact SPN is not advertised verbatim).
    """

    spn_to_node: Mapping[str, str]
    host_to_node: Mapping[str, str]


def spn_host(spn: str) -> str | None:
    """Return the lowercase host component of an SPN (``class/host[:port][/svc]``).

    ``cifs/dc01.corp.local:1433/svc`` -> ``dc01.corp.local``. Returns ``None`` for
    a malformed SPN with no host component.
    """
    parts = spn.split("/")
    if len(parts) < 2 or not parts[1]:
        return None
    return parts[1].split(":")[0].lower()


def build_spn_index(principals: Sequence[tuple[str, Sequence[str]]]) -> SpnIndex:
    """Build the SPN/host -> node index from ``(node_id, spns)`` pairs.

    Deterministic: a host advertised by multiple nodes keeps the first in
    ``node_id`` order (callers pass rows ordered by ``node_id``).

    Inputs:
        principals: ``(node_id, spns)`` for every principal carrying SPNs.

    Returns:
        A populated :class:`SpnIndex`.

    Failure modes:
        Never raises.
    """
    spn_to_node: dict[str, str] = {}
    host_to_node: dict[str, str] = {}
    for node_id, spns in principals:
        for spn in spns:
            spn_to_node.setdefault(spn.lower(), node_id)
            host = spn_host(spn)
            if host is not None:
                host_to_node.setdefault(host, node_id)
    return SpnIndex(spn_to_node=spn_to_node, host_to_node=host_to_node)


def resolve_spn_target(spn: str, index: SpnIndex) -> str | None:
    """Resolve a target SPN to the node running it: exact SPN, else by host."""
    node = index.spn_to_node.get(spn.lower())
    if node is not None:
        return node
    host = spn_host(spn)
    return index.host_to_node.get(host) if host is not None else None


@dataclass(frozen=True)
class _CountGap:
    """A simple (edges, skipped) builder result."""

    edges: tuple[EdgeRow, ...]
    skipped: int


def build_constrained_delegation_edges(
    source_node_id: str,
    allowed_to: Sequence[str],
    index: SpnIndex,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> _CountGap:
    """Build ``AllowedToDelegate`` edges for one principal's ``msDS-AllowedToDelegateTo``.

    source = the delegating account; target = the node running each listed target
    SPN's service (resolved exact-then-host). An SPN that resolves to no node is
    skipped and counted (``delegation_target_unresolved``). A target resolving to
    the source itself is skipped (reflexive).

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    skipped = 0
    seen: set[str] = set()
    for spn in allowed_to:
        target = resolve_spn_target(spn, index)
        if target is None:
            skipped += 1
            continue
        if target == source_node_id or target in seen:
            continue
        seen.add(target)
        edges.append(
            _edge(
                KIND_ALLOWED_TO_DELEGATE,
                DERIVATION_ALLOWED_TO_DELEGATE,
                source_node_id,
                target,
                _attr_provenance(obj_prov, source_node_id, ATTR_ALLOWED_TO_DELEGATE_TO),
                scoping,
            )
        )
    return _CountGap(tuple(edges), skipped)


# =============================================================================
# RBCD + gMSA (the attribute value IS a security descriptor)
# =============================================================================


def _sd_trustee_edges(
    sd_bytes: bytes,
    target_node_id: str,
    kind: str,
    derivation: str,
    attr_name: str,
    resolver: NodeResolver,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], bool]:
    """Parse an attribute-SD and build one edge per ALLOW trustee (trustee -> object).

    Returns ``(edges, parse_failed)``. A malformed SD yields ``([], True)`` so the
    caller counts an ``sd_parse_error``. Reflexive trustee==object is skipped.
    """
    parsed = parse_sd(sd_bytes)
    if parsed is None:
        return [], True
    edges: list[EdgeRow] = []
    prov = _attr_provenance(obj_prov, target_node_id, attr_name)
    for ace in parsed.aces:
        source_node_id = resolver.resolve_or_mint(ace.trustee_sid)
        if source_node_id == target_node_id:
            continue
        edges.append(_edge(kind, derivation, source_node_id, target_node_id, prov, scoping))
    return edges, False


def build_rbcd_edges(
    computer_node_id: str,
    sd_bytes: bytes,
    resolver: NodeResolver,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], bool]:
    """Build ``AllowedToAct`` edges from ``msDS-AllowedToActOnBehalfOfOtherIdentity``.

    Each ALLOW trustee in the attribute SD may act on behalf of (impersonate into)
    the computer carrying the attribute: edge trustee -> computer.
    """
    return _sd_trustee_edges(
        sd_bytes,
        computer_node_id,
        KIND_ALLOWED_TO_ACT,
        DERIVATION_RBCD,
        ATTR_ALLOWED_TO_ACT,
        resolver,
        obj_prov,
        scoping,
    )


def build_gmsa_read_edges(
    gmsa_node_id: str,
    sd_bytes: bytes,
    resolver: NodeResolver,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], bool]:
    """Build ``ReadGMSAPassword`` edges from ``msDS-GroupMSAMembership``.

    Each ALLOW trustee in the attribute SD may read the gMSA's managed password:
    edge trustee -> gMSA account.
    """
    return _sd_trustee_edges(
        sd_bytes,
        gmsa_node_id,
        KIND_READ_GMSA_PASSWORD,
        DERIVATION_GMSA,
        ATTR_GROUP_MSA_MEMBERSHIP,
        resolver,
        obj_prov,
        scoping,
    )


# =============================================================================
# SID history
# =============================================================================


def build_sid_history_edges(
    principal_node_id: str,
    sid_history: Sequence[str],
    resolver: NodeResolver,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> list[EdgeRow]:
    """Build ``HasSIDHistory`` edges: principal -> each historical-SID node.

    The historical SID is resolved via mint-on-miss (a foreign/past SID usually
    has no object). A SID resolving to the principal itself is skipped.

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    for sid in sid_history:
        target = resolver.resolve_or_mint(sid)
        if target == principal_node_id:
            continue
        edges.append(
            _edge(
                KIND_HAS_SID_HISTORY,
                DERIVATION_SID_HISTORY,
                principal_node_id,
                target,
                _attr_provenance(obj_prov, principal_node_id, "sIDHistory"),
                scoping,
            )
        )
    return edges


# =============================================================================
# Trust edges (ATTACK direction = trusted -> trusting)
# =============================================================================


@dataclass(frozen=True)
class TrustInput:
    """One M3 ``trust`` row as the trust builder reads it.

    Attributes:
        local_domain_node_id: node id of THIS (local) domain object.
        other_domain_sid: the partner domain SID (``target_domain_id``), or ``None``.
        direction: the §3.4 ``direction`` enum (``inbound``/``outbound``/
            ``bidirectional``/``disabled``).
        trust_attributes: the RAW ``trustAttributes`` bitmask (authoritative).
        has_trust_key: whether a trust-account key secret was recovered.
        provenance: the trust object's provenance.
    """

    local_domain_node_id: str
    other_domain_sid: str | None
    direction: str | None
    trust_attributes: int | None
    has_trust_key: bool
    provenance: ProvenanceStruct


def is_within_forest(trust_attributes: int | None) -> bool:
    """Return whether the ``WITHIN_FOREST`` (``0x20``) attribute bit is set."""
    return trust_attributes is not None and bool(trust_attributes & TRUST_ATTR_WITHIN_FOREST)


def is_sid_filtered(trust_attributes: int | None) -> bool:
    """Return whether ``QUARANTINED_DOMAIN`` (``0x04``, SID filtering) is set."""
    return trust_attributes is not None and bool(trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN)


def build_trust_edges(
    trust: TrustInput,
    resolver: NodeResolver,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], int]:
    """Build the attack-direction trust edges for one TDO (+ optional HasTrustKeys).

    Classification uses the RAW ``trust_attributes`` bitmask (M3's best-effort
    booleans are not trusted): ``WITHIN_FOREST (0x20)`` -> ``SameForestTrust``,
    else ``CrossForestTrust``. Direction per [MS-ADTS] 6.1.6.7.12, where the attack
    flows **trusted -> trusting** (the §4 source is the attacker direction):

    * ``inbound`` (``trustDirection`` 0x1) = the partner trusts the local domain,
      so **local is TRUSTED**, partner is trusting -> edge local -> other.
    * ``outbound`` (0x2) = the local domain trusts the partner, so **local is
      TRUSTING**, partner is trusted -> edge other -> local.
    * ``bidirectional`` -> both.
    * ``disabled`` / ``None`` -> no edge.

    The other domain is resolved via mint-on-miss (a foreign domain SID has no
    local object); the local endpoint is the passed Domain node. ``HasTrustKeys``
    (local -> other, ``ATTR:TrustKeys``) is emitted when a trust key was recovered.

    Returns:
        ``(edges, unresolved)`` — the trust edges and the count of TDOs whose
        partner SID was absent (no edge could be built).

    Failure modes:
        Never raises.
    """
    if trust.other_domain_sid is None:
        return [], 1
    other = resolver.resolve_or_mint(trust.other_domain_sid)
    local = trust.local_domain_node_id
    kind = (
        KIND_SAME_FOREST_TRUST
        if is_within_forest(trust.trust_attributes)
        else KIND_CROSS_FOREST_TRUST
    )
    derivation = (
        DERIVATION_SAME_FOREST
        if is_within_forest(trust.trust_attributes)
        else DERIVATION_CROSS_FOREST
    )

    pairs: list[tuple[str, str]] = []
    if trust.direction == "inbound":
        pairs.append((local, other))  # local is TRUSTED -> attack local -> other
    elif trust.direction == "outbound":
        pairs.append((other, local))  # local is TRUSTING -> attack other -> local
    elif trust.direction == "bidirectional":
        pairs.append((local, other))
        pairs.append((other, local))
    # disabled / None -> no traversal edge

    edges: list[EdgeRow] = []
    for source_node_id, target_node_id in pairs:
        edges.append(
            _edge(kind, derivation, source_node_id, target_node_id, trust.provenance, scoping)
        )
    if trust.has_trust_key:
        edges.append(
            _edge(
                KIND_HAS_TRUST_KEYS,
                DERIVATION_TRUST_KEYS,
                local,
                other,
                trust.provenance,
                scoping,
            )
        )
    return edges, 0


# =============================================================================
# ADCS base-fact edges
# =============================================================================


def build_adcs_enrollment_edges(
    adcs_node_id: str,
    sd_bytes: bytes | None,
    pki_flag_guids: PkiFlagGuids,
    noise_sids: frozenset[str],
    resolver: NodeResolver,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], bool]:
    """Build the ADCS-scoped edges (Enroll/AutoEnroll/WritePKI*Flag) from the SD.

    source = the right-holding trustee; target = the template/CA object. Whole-
    object control edges on this object are produced by the 5A generic DACL pass
    and are NOT re-emitted here (see :func:`classify_adcs_ace`). Noise/self
    trustees are skipped (same policy as 5A). Returns ``(edges, parse_failed)``.

    Failure modes:
        Never raises.
    """
    if not sd_bytes:
        return [], False
    parsed = parse_sd(sd_bytes)
    if parsed is None:
        return [], True
    edges: list[EdgeRow] = []
    prov = _sd_provenance(obj_prov, adcs_node_id)
    for ace in parsed.aces:
        if ace.trustee_sid in noise_sids:
            continue
        result = classify_adcs_ace(ace.mask, ace.object_type_guid, pki_flag_guids)
        if not result.facts:
            continue
        source_node_id = resolver.resolve_or_mint(ace.trustee_sid)
        if source_node_id == adcs_node_id:
            continue
        for fact in result.facts:
            edges.append(
                EdgeRow(
                    edge_id=stable_id(fact.kind, source_node_id, adcs_node_id, fact.derivation),
                    kind=fact.kind,
                    source_node_id=source_node_id,
                    target_node_id=adcs_node_id,
                    is_inherited=ace.is_inherited,
                    derivation=fact.derivation,
                    access_mask=None,
                    object_type_guid=ace.object_type_guid,
                    confidence=CONFIDENCE_CONFIRMED,
                    forest_id=scoping[0],
                    domain_id=scoping[1],
                    domain_fqdn=scoping[2],
                    provenance=prov,
                )
            )
    return edges, False


def build_published_to_edges(
    ca_node_id: str,
    published_templates: Sequence[str],
    template_name_to_node: Mapping[str, str],
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], int]:
    """Build ``PublishedTo`` edges (template -> CA) from a CA's published list.

    Each published template name is resolved (case-insensitively) to a
    CertTemplate node; an unresolved name is skipped and counted.

    Returns:
        ``(edges, unresolved)``.

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    unresolved = 0
    prov = _attr_provenance(obj_prov, ca_node_id, "certificateTemplates")
    for name in published_templates:
        template_node = template_name_to_node.get(name.lower())
        if template_node is None:
            unresolved += 1
            continue
        edges.append(
            _edge(
                KIND_PUBLISHED_TO, DERIVATION_PUBLISHED_TO, template_node, ca_node_id, prov, scoping
            )
        )
    return edges, unresolved


# =============================================================================
# Structural edges: Contains (container -> child) + GPLink (GPO -> container)
# =============================================================================


def parent_dn(dn: str) -> str | None:
    """Return the parent DN of ``dn`` (its leading RDN removed), or ``None``.

    Splits off the first RDN at the first *unescaped* comma (RFC 4514: a comma is
    escaped when preceded by an odd number of backslashes), so an RDN value that
    itself contains an escaped comma is handled. Returns ``None`` when ``dn`` has a
    single RDN component (a root with no parent in the DIT).

    Inputs:
        dn: a reconstructed distinguished name (M3 output).

    Returns:
        The parent DN string, or ``None`` if there is no parent component.

    Failure modes:
        Never raises.
    """
    i = 0
    n = len(dn)
    while i < n:
        c = dn[i]
        if c == "\\":
            i += 2  # skip the escaped character
            continue
        if c == ",":
            parent = dn[i + 1 :].strip()
            return parent or None
        i += 1
    return None


def build_contains_edge(
    parent_node_id: str,
    child_node_id: str,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow | None:
    """Build one ``Contains`` edge (container -> child), or ``None`` if reflexive.

    Direction (BloodHound parity): the containing object (Domain / OU / Container)
    is the source and the contained object is the target, so that control of a
    container (e.g. an OU ``GenericAll``) reaches the objects inside it by
    traversing ``Contains``. Derived from M3's already-computed parent link
    (``container.parent_node_id`` for containers; a parent-DN lookup for other
    objects) — the DN tree is NOT re-walked here.

    Inputs:
        parent_node_id: the containing object's node id (already resolved).
        child_node_id: the contained object's node id.
        obj_prov: the CHILD object's provenance (the fact is "this child's parent").
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        A ``Contains`` :class:`EdgeRow`, or ``None`` when parent == child. The
        reflexive case is SILENTLY dropped (not counted): it is a defensive guard
        against a self-referential parent link, not an expected gap, so the caller
        does not increment a skip counter for it.

    Failure modes:
        Never raises.
    """
    if parent_node_id == child_node_id:
        return None
    return _edge(
        KIND_CONTAINS,
        DERIVATION_CONTAINS,
        parent_node_id,
        child_node_id,
        _stamped_provenance(obj_prov, f"{child_node_id}:parent"),
        scoping,
    )


def build_gplink_edges(
    container_node_id: str,
    gplinks: Sequence[Mapping[str, object]],
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> list[EdgeRow]:
    """Build ``GPLink`` edges (GPO -> linked container) from a container's ``gplinks``.

    Direction (BloodHound parity, CONFIRMED): the GPO is the source and the linked
    OU / Domain / Container is the target, because an attacker controlling the GPO
    affects every object the GPO is linked to (and, via ``Contains``, the objects
    inside the linked container). Reuses the M3-resolved ``gplinks`` STRUCT list
    directly (the ``gPLink`` blob is NOT re-parsed); M3 has already dropped
    disabled links (counted there) and resolved each GPC to a ``gpo_node_id``.

    Inputs:
        container_node_id: the OU/Domain/Container the GPOs are linked to (target).
        gplinks: the resolved ``{gpo_node_id, enforced, link_order}`` STRUCT list.
        obj_prov: the container's provenance (it carries the ``gPLink`` attribute).
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        One ``GPLink`` :class:`EdgeRow` per resolved link (a missing/empty
        ``gpo_node_id`` link is skipped — M3 only emits resolved links).

    Failure modes:
        Never raises.
    """
    prov = _attr_provenance(obj_prov, container_node_id, "gPLink")
    edges: list[EdgeRow] = []
    seen: set[str] = set()
    for link in gplinks:
        gpo_node = link.get("gpo_node_id")
        if not isinstance(gpo_node, str) or not gpo_node or gpo_node in seen:
            continue
        seen.add(gpo_node)
        edges.append(
            _edge(KIND_GPLINK, DERIVATION_GPLINK, gpo_node, container_node_id, prov, scoping)
        )
    return edges


def build_coerce_to_tgt_edge(
    principal_node_id: str,
    domain_node_id: str,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow | None:
    """Build one ``CoerceToTGT`` edge (unconstrained host -> domain), or ``None``.

    BloodHound CE promoted unconstrained delegation from a node property to a
    traversable edge: a non-DC account trusted for unconstrained Kerberos
    delegation can coerce a Domain Controller to authenticate to it and capture
    the DC's TGT, compromising the domain. Source = the unconstrained-delegation
    principal; target = the domain node. The DC-self case is suppressed by the
    caller (see :func:`wraith.edges.node_flags.is_coercible_unconstrained`).

    Inputs:
        principal_node_id: the (non-DC) unconstrained-delegation principal.
        domain_node_id: the domain object's node id (target).
        obj_prov: the principal's provenance (the fact is its ``userAccountControl``).
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        A ``CoerceToTGT`` :class:`EdgeRow`, or ``None`` when the principal resolves
        to the domain node itself (defensive reflexive guard).

    Failure modes:
        Never raises.
    """
    if principal_node_id == domain_node_id:
        return None
    return _edge(
        KIND_COERCE_TO_TGT,
        DERIVATION_COERCE_TGT,
        principal_node_id,
        domain_node_id,
        _attr_provenance(obj_prov, principal_node_id, "userAccountControl"),
        scoping,
    )
