"""SD/ACE parsing seam + mint-on-miss resolver + ACL edge builders (slice 5A).

The correctness-critical security-descriptor / ACE parsing is delegated to
``impacket.ldap.ldaptypes`` (CLAUDE.md: never hand-roll an SD parser). This
module wraps that library in a pure, typed, crash-free seam and turns the
resulting ACEs into §4 ``edge`` rows via :mod:`wraith.edges.guid_map`.

Four concerns:

* :func:`parse_sd` — parse one ``nTSecurityDescriptor`` BLOB into an owner SID +
  the ALLOW ACEs we act on (v1 policy: ALLOW ``0x00`` / ``0x05`` only; DENY and
  ``INHERIT_ONLY`` are counted-and-skipped). Malformed input -> ``None`` (a
  counted gap), never a crash.
* :class:`NodeResolver` — the shared mint-on-miss contract (research item 7):
  resolve a SID to a node by ``principal.object_sid`` first, else the shared
  ``node_id_for_sid`` (minting a deduped stub Principal with synthetic
  provenance). Reused unchanged by slice 5B.
* :func:`build_owner_edge` / :func:`build_ace_edges` — the pure edge builders
  (source = right-holder, target = controlled object).

The RBCD / gMSA attribute values are themselves security descriptors; slice 5B
reuses :func:`parse_sd` on those bytes. This slice parses only the object DACL.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field, replace

from wraith.common.determinism import stable_id
from wraith.edges.guid_map import (
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    KIND_ALL_EXTENDED_RIGHTS,
    KIND_GET_CHANGES,
    KIND_GET_CHANGES_ALL,
    WHOLE_OBJECT_KINDS,
    AceEdgeFact,
    classify_ace,
)
from wraith.edges.models import EdgeRow
from wraith.normalize.builders import BuildContext, build_stub_principal
from wraith.normalize.identity import (
    WELLKNOWN_IMAGE_SHA256,
    WELLKNOWN_SOURCE_FILE,
    DirectoryIndex,
    node_id_for_sid,
    wellknown_source_object_id,
)
from wraith.normalize.models import PrincipalRow
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

# --- §4 confidence + derivation literals -------------------------------------
CONFIDENCE_CONFIRMED: str = "confirmed"
KIND_OWNS: str = "Owns"
DERIVATION_OWNER: str = "SD:Owner"
KIND_DCSYNC: str = "DCSync"
DERIVATION_DCSYNC: str = "SYNTH:DCSync"
#: ``ACE:<kind>`` derivation for the two replication base facts expanded from an
#: all-extended-rights ACE on the Domain object (DE ISSUE-2).
_DERIVATION_GET_CHANGES: str = f"ACE:{KIND_GET_CHANGES}"
_DERIVATION_GET_CHANGES_ALL: str = f"ACE:{KIND_GET_CHANGES_ALL}"

# --- Impacket ACE header / type constants (public [MS-DTYP] facts) -----------
# Mirrored as named ints so the parser reads intent, not magic numbers. They are
# validated against Impacket's own class attributes on first parse by
# :func:`_verify_ace_constants` (catches a library-version drift loudly).
_ACE_TYPE_ALLOWED: int = 0x00
_ACE_TYPE_ALLOWED_OBJECT: int = 0x05
_ACE_TYPE_DENIED: int = 0x01
_ACE_TYPE_DENIED_OBJECT: int = 0x06
_ACE_FLAG_INHERIT_ONLY: int = 0x08
_ACE_FLAG_INHERITED: int = 0x10
_ACE_OBJECT_TYPE_PRESENT: int = 0x01

#: Trustees whose grants are pure default/host noise, not attack identities
#: (research item 2.5 rule 4): Creator Owner, Owner Rights, Local System.
NOISE_TRUSTEE_SIDS: frozenset[str] = frozenset({"S-1-3-0", "S-1-3-4", "S-1-5-18"})

#: One-shot guard flag: the mirrored ACE constants are verified against Impacket
#: on the first :func:`parse_sd` call (not at import, so the module stays
#: offline-import-cheap and Impacket is loaded lazily).
_ace_constants_verified: bool = False


@dataclass(frozen=True)
class AceView:
    """A flattened, decoded view of one ALLOW ACE (what the classifier needs).

    Attributes:
        mask: the raw integer access mask.
        trustee_sid: the ACE trustee SID (``S-1-...``), canonical form.
        object_type_guid: the ObjectType GUID (lowercase dashed string) when the
            ACE carries one, else ``None``.
        is_inherited: ``True`` if the ACE has the ``INHERITED_ACE`` flag.
    """

    mask: int
    trustee_sid: str
    object_type_guid: str | None
    is_inherited: bool


@dataclass(frozen=True)
class ParsedSd:
    """The result of parsing one security descriptor.

    Attributes:
        owner_sid: the SD owner SID, or ``None`` if absent/unreadable.
        aces: the ALLOW ACEs we act on (DENY + ``INHERIT_ONLY`` already removed).
        had_dacl: ``True`` when the SD carried a readable DACL (even if empty);
            ``False`` for the Impacket missing-DACL quirk (owner edge only).
        deny_skipped: count of DENY ACEs skipped (v1 policy, informational).
        inherit_only_skipped: count of ``INHERIT_ONLY`` ACEs skipped.
        ace_errors: count of ACEs that could not be decoded (counted gap).
    """

    owner_sid: str | None
    aces: tuple[AceView, ...]
    had_dacl: bool
    deny_skipped: int
    inherit_only_skipped: int
    ace_errors: int


def _guid_from_object_type(raw: object) -> str | None:
    """Decode an ACE ObjectType field (16 raw bytes) to a lowercase GUID string.

    Returns ``None`` when the field is absent (``b''``) or not 16 bytes. Uses
    ``uuid.UUID(bytes_le=...)`` — the same little-endian GUID layout that 2a's
    ``decode_guid`` uses for ``schemaIDGUID``, so an ACE GUID and a schema GUID
    compare equal for the same bytes.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=bytes(raw)))


def parse_sd(raw_sd: bytes) -> ParsedSd | None:
    """Parse one ``nTSecurityDescriptor`` BLOB into owner + ALLOW ACEs.

    Delegates the binary parse to ``impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR``
    (never hand-rolled). v1 policy: process ALLOW ACEs only (types ``0x00`` and
    ``0x05``); DENY (``0x01`` / ``0x06``) and ``INHERIT_ONLY`` (``0x08``) ACEs are
    counted and skipped. The ``INHERITED_ACE`` (``0x10``) flag maps to
    :attr:`AceView.is_inherited`.

    Inputs:
        raw_sd: the raw self-relative security-descriptor bytes.

    Returns:
        A :class:`ParsedSd`, or ``None`` if the descriptor could not be parsed at
        all (the caller counts this as ``sd_parse_error`` and skips the object —
        both its owner and ACE edges are lost for that object only).

    Failure modes:
        Never raises; a top-level parse failure returns ``None`` and a per-ACE
        decode failure increments :attr:`ParsedSd.ace_errors`.
    """
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    _verify_ace_constants()
    try:
        sd = SR_SECURITY_DESCRIPTOR(data=raw_sd)
    except Exception as exc:  # malformed/truncated SD -> counted gap, never crash
        # DEBUG, not WARNING: a hostile DIT must not log-flood the hot path; the
        # caller counts every failure as a surfaced `sd_parse_error`.
        _log.debug("edges: unparseable security descriptor: %s", type(exc).__name__)
        return None

    owner_sid = _read_owner(sd)
    # Impacket quirk: OffsetDacl == 0 populates 'Sacl' instead of 'Dacl'; a
    # missing/zero-ACE DACL yields b'' / no `.aces`. Treat as "no DACL". The
    # fetch itself is guarded too (close the hostile-SD asymmetry with the owner).
    try:
        dacl = sd["Dacl"]
    except Exception as exc:
        _log.debug("edges: unreadable DACL: %s", type(exc).__name__)
        return ParsedSd(owner_sid, (), False, 0, 0, 0)
    if not dacl or not hasattr(dacl, "aces"):
        return ParsedSd(owner_sid, (), False, 0, 0, 0)

    aces: list[AceView] = []
    deny = inherit_only = errors = 0
    for ace in dacl.aces:
        try:
            ace_type = int(ace["AceType"])
            flags = int(ace["AceFlags"])
            if ace_type in (_ACE_TYPE_DENIED, _ACE_TYPE_DENIED_OBJECT):
                deny += 1
                continue
            if ace_type not in (_ACE_TYPE_ALLOWED, _ACE_TYPE_ALLOWED_OBJECT):
                continue  # audit/alarm/callback ACE types are not v1-relevant
            if flags & _ACE_FLAG_INHERIT_ONLY:
                inherit_only += 1
                continue
            body = ace["Ace"]
            mask = int(body["Mask"]["Mask"])
            trustee_sid = body["Sid"].formatCanonical()
            object_type_guid: str | None = None
            if ace_type == _ACE_TYPE_ALLOWED_OBJECT and (
                int(body["Flags"]) & _ACE_OBJECT_TYPE_PRESENT
            ):
                object_type_guid = _guid_from_object_type(body["ObjectType"])
            aces.append(
                AceView(
                    mask=mask,
                    trustee_sid=trustee_sid,
                    object_type_guid=object_type_guid,
                    is_inherited=bool(flags & _ACE_FLAG_INHERITED),
                )
            )
        except Exception as exc:  # one malformed ACE -> counted gap, skip it only
            errors += 1
            _log.debug("edges: undecodable ACE: %s", type(exc).__name__)
            continue
    return ParsedSd(owner_sid, tuple(aces), True, deny, inherit_only, errors)


def _verify_ace_constants() -> None:
    """Assert the mirrored ACE-type / header-flag ints still equal Impacket's.

    The parser hard-codes the public [MS-DTYP] ACE constants (so it reads named
    ints, not magic numbers); this one-shot guard verifies they still match the
    Impacket classes on the first parse, so a library-version drift fails loudly
    instead of silently mis-classifying every ACE. Cheap after the first call.

    Failure modes:
        Raises ``RuntimeError`` if a mirrored constant disagrees with Impacket.
    """
    global _ace_constants_verified
    if _ace_constants_verified:
        return
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_DENIED_OBJECT_ACE,
        ACE,
    )

    expected: list[tuple[str, int, int]] = [
        ("ACCESS_ALLOWED_ACE", ACCESS_ALLOWED_ACE.ACE_TYPE, _ACE_TYPE_ALLOWED),
        ("ACCESS_ALLOWED_OBJECT_ACE", ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, _ACE_TYPE_ALLOWED_OBJECT),
        ("ACCESS_DENIED_ACE", ACCESS_DENIED_ACE.ACE_TYPE, _ACE_TYPE_DENIED),
        ("ACCESS_DENIED_OBJECT_ACE", ACCESS_DENIED_OBJECT_ACE.ACE_TYPE, _ACE_TYPE_DENIED_OBJECT),
        ("INHERIT_ONLY_ACE", ACE.INHERIT_ONLY_ACE, _ACE_FLAG_INHERIT_ONLY),
        ("INHERITED_ACE", ACE.INHERITED_ACE, _ACE_FLAG_INHERITED),
        (
            "ACE_OBJECT_TYPE_PRESENT",
            ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT,
            _ACE_OBJECT_TYPE_PRESENT,
        ),
    ]
    for name, impacket_value, mirrored in expected:
        if int(impacket_value) != mirrored:
            raise RuntimeError(
                f"Impacket ACE constant drift: {name}={int(impacket_value):#x} "
                f"!= mirrored {mirrored:#x}; update wraith.edges.acl"
            )
    _ace_constants_verified = True


def _read_owner(sd: object) -> str | None:
    """Return the SD owner SID canonical string, or ``None`` if absent/unreadable."""
    try:
        owner = sd["OwnerSid"]  # type: ignore[index]
    except Exception:
        return None
    if not owner or not hasattr(owner, "formatCanonical"):
        return None
    try:
        return str(owner.formatCanonical())
    except Exception:
        return None


@dataclass
class NodeResolver:
    """The shared mint-on-miss SID -> node resolver (research item 7).

    Resolve a SID to a node by ``principal.object_sid`` FIRST (real objects and
    M3 stubs), else by the shared :func:`node_id_for_sid` — minting a deduped
    stub Principal there with synthetic provenance if no node exists yet. This is
    the SAME scheme M3/M4 use, so ids align; slice 5B reuses this unchanged.

    Attributes:
        forest_id/domain_id/domain_fqdn: the scoping block.
        sid_to_node: ``object_sid`` -> ``node_id`` (seeded from ``principal``).
        all_nodes: every known ``node_id`` (principals + minted stubs).
        ingest_run_id: the run id stamped on minted-stub provenance.
        minted: ``node_id`` -> stub :class:`PrincipalRow` (deduped, written once).
    """

    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    sid_to_node: dict[str, str]
    all_nodes: set[str]
    ingest_run_id: uuid.UUID
    minted: dict[str, PrincipalRow] = field(default_factory=dict)

    def resolve_or_mint(self, sid: str) -> str:
        """Resolve ``sid`` to a node id, minting a stub Principal on a miss.

        Inputs:
            sid: the SID to resolve (ACE trustee / SD owner).

        Returns:
            The resolved (or freshly minted) ``node_id``. Never a dangling target.

        Failure modes:
            Never raises.
        """
        node = self.sid_to_node.get(sid)
        if node is not None:
            return node
        node = node_id_for_sid(self.forest_id, self.domain_id, sid)
        if node not in self.all_nodes:
            self._mint_stub(node, sid)
            self.all_nodes.add(node)
        # Cache the SID so repeat references dedup to the same node.
        self.sid_to_node.setdefault(sid, node)
        return node

    def _mint_stub(self, node_id: str, sid: str) -> None:
        """Materialize (once) a stub Principal for an objectless ACE-referenced SID."""
        provenance = ProvenanceStruct(
            source_file=WELLKNOWN_SOURCE_FILE,
            image_sha256=WELLKNOWN_IMAGE_SHA256,
            source_object_id=wellknown_source_object_id(sid),
            directory_timestamp=None,
            ingest_run_id=self.ingest_run_id,
        )
        ctx = BuildContext(
            forest_id=self.forest_id,
            domain_id=self.domain_id,
            domain_fqdn=self.domain_fqdn,
            index=DirectoryIndex(),
            node_secret_refs={},
            gpc_cn_to_node={},
        )
        self.minted[node_id] = build_stub_principal(sid, node_id, provenance, ctx)


def _unsigned_mask(mask: int) -> int:
    """Return the 32-bit access mask as a CLEAN UNSIGNED value (0..4294967295).

    Schema v1.1 (owner-approved 2026-10-26 at M6) widened the §4 ``access_mask``
    column to ``BIGINT``, which holds the full unsigned 32-bit range directly.
    An AD access mask is an unsigned 32-bit value whose high bit (``GENERIC_READ``,
    ``0x80000000``) exceeds ``INT32_MAX``; masking with ``0xFFFFFFFF`` drops any
    stray high bits and yields the non-negative value stored verbatim — no
    two's-complement reinterpretation, so readers need no recovery step.
    """
    return mask & 0xFFFFFFFF


def _sd_provenance(object_provenance: ProvenanceStruct, node_id: str) -> ProvenanceStruct:
    """Derive an edge's provenance from the controlled object's SD provenance.

    Keeps the object's ``image_sha256`` / ``source_file`` / ``directory_timestamp``
    (the ``whenChanged`` of the object whose DACL this is) and stamps
    ``source_object_id = "<node_id>:sd"`` so the fact points at the exact SD.
    """
    return ProvenanceStruct(
        source_file=object_provenance.source_file,
        image_sha256=object_provenance.image_sha256,
        source_object_id=f"{node_id}:sd",
        directory_timestamp=object_provenance.directory_timestamp,
        ingest_run_id=object_provenance.ingest_run_id,
    )


def build_owner_edge(
    owner_sid: str,
    object_node_id: str,
    object_sid: str | None,
    resolver: NodeResolver,
    object_provenance: ProvenanceStruct,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> EdgeRow | None:
    """Build the ``Owns`` edge (owner -> object), or ``None`` if skipped.

    Resolves the owner SID via mint-on-miss. Skips (returns ``None``) when the
    owner is a noise trustee (``S-1-5-18`` etc.) or the object's own SID (a
    reflexive self-owner), so the caller can count it.

    Inputs:
        owner_sid: the SD owner SID.
        object_node_id: the controlled object's node id.
        object_sid: the controlled object's own SID (for the self-owner guard).
        resolver: the shared :class:`NodeResolver`.
        object_provenance: the object's SD provenance.
        forest_id/domain_id/domain_fqdn: the scoping block.

    Returns:
        An ``Owns`` :class:`EdgeRow`, or ``None`` if the owner is skip-listed /
        self.

    Failure modes:
        Never raises.
    """
    if owner_sid in NOISE_TRUSTEE_SIDS:
        return None
    if object_sid is not None and owner_sid == object_sid:
        return None
    source_node_id = resolver.resolve_or_mint(owner_sid)
    if source_node_id == object_node_id:
        return None  # reflexive self-owner (resolved to the same node) -> skip
    return EdgeRow(
        edge_id=stable_id(KIND_OWNS, source_node_id, object_node_id, DERIVATION_OWNER),
        kind=KIND_OWNS,
        source_node_id=source_node_id,
        target_node_id=object_node_id,
        is_inherited=False,
        derivation=DERIVATION_OWNER,
        access_mask=None,
        object_type_guid=None,
        confidence=CONFIDENCE_CONFIRMED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=_sd_provenance(object_provenance, object_node_id),
    )


@dataclass(frozen=True)
class _AceGaps:
    """Counted gaps from classifying one object's ACEs."""

    noise_trustee_skipped: int
    unmapped_objecttype: int


def build_ace_edges(
    aces: tuple[AceView, ...],
    object_node_id: str,
    object_sid: str | None,
    laps_guids: frozenset[str],
    resolver: NodeResolver,
    object_provenance: ProvenanceStruct,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
    *,
    is_domain_target: bool = False,
    handled_elsewhere: frozenset[str] = frozenset(),
) -> tuple[list[EdgeRow], _AceGaps]:
    """Build the ACL-derived §4 edges for one object's DACL.

    For each ALLOW ACE: skip noise/self trustees (counted), classify the mask +
    ObjectType via :func:`~wraith.edges.guid_map.classify_ace`, and emit one edge
    per fact (source = trustee via mint-on-miss, target = the object). Scoped
    facts carry the ACE's ObjectType GUID in ``object_type_guid``; whole-object
    facts carry ``NULL``. Group trustees are NOT expanded to members (the edge
    stays on the named trustee — path expansion is M4's job).

    DCSync expansion (DE ISSUE-2): a no-ObjectType ``DS_CONTROL_ACCESS`` ACE on
    the **Domain** object confers the replication rights, so when
    ``is_domain_target`` is set an ``AllExtendedRights`` fact is expanded into the
    two replication base facts ``GetChanges`` + ``GetChangesAll`` (SharpHound
    parity) instead of emitting ``AllExtendedRights`` → Domain, so DCSync
    synthesis fires and the export re-composes cleanly.

    Inputs:
        aces: the ALLOW ACEs from :func:`parse_sd`.
        object_node_id: the controlled object's node id (edge target).
        object_sid: the object's own SID (self-trustee guard).
        laps_guids: resolved LAPS ``schemaIDGUID``s (for ``ReadLAPSPassword``).
        resolver: the shared :class:`NodeResolver`.
        object_provenance: the object's SD provenance.
        forest_id/domain_id/domain_fqdn: the scoping block.
        is_domain_target: whether this object is the Domain head (enables the
            all-extended-rights → replication expansion).
        handled_elsewhere: scoped GUIDs mapped by another pass (ADCS 5B) that must
            NOT inflate the ``unmapped_objecttype`` counter.

    Returns:
        ``(edges, gaps)`` — the ACL edges and the counted gaps (noise-trustee
        skips, unmapped-ObjectType skips).

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    noise = unmapped = 0
    prov = _sd_provenance(object_provenance, object_node_id)
    for ace in aces:
        if ace.trustee_sid in NOISE_TRUSTEE_SIDS or (
            object_sid is not None and ace.trustee_sid == object_sid
        ):
            noise += 1
            continue
        result = classify_ace(ace.mask, ace.object_type_guid, laps_guids, handled_elsewhere)
        if result.unmapped_objecttype:
            unmapped += 1
        if not result.facts:
            continue
        source_node_id = resolver.resolve_or_mint(ace.trustee_sid)
        if source_node_id == object_node_id:
            continue  # reflexive self-grant resolved to the same node -> skip
        for fact in result.facts:
            if is_domain_target and fact.kind == KIND_ALL_EXTENDED_RIGHTS:
                # All-extended-rights on the Domain head == the replication rights
                # -> expand to the two base facts so DCSync synthesis fires.
                edges.extend(
                    _replication_edges(
                        ace, source_node_id, object_node_id, prov, forest_id, domain_id, domain_fqdn
                    )
                )
                continue
            edges.append(
                _ace_edge(
                    fact,
                    ace,
                    source_node_id,
                    object_node_id,
                    prov,
                    forest_id,
                    domain_id,
                    domain_fqdn,
                )
            )
    return edges, _AceGaps(noise, unmapped)


def _replication_edges(
    ace: AceView,
    source_node_id: str,
    target_node_id: str,
    provenance: ProvenanceStruct,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> list[EdgeRow]:
    """Build the ``GetChanges`` + ``GetChangesAll`` base edges for a domain ACE.

    Emitted when an all-extended-rights ACE lands on the Domain head (DE ISSUE-2):
    the two edges carry the canonical replication rights-GUIDs so they are
    indistinguishable from explicit replication ACEs and DCSync synthesis fires.
    """
    return [
        EdgeRow(
            edge_id=stable_id(kind, source_node_id, target_node_id, derivation),
            kind=kind,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            is_inherited=ace.is_inherited,
            derivation=derivation,
            access_mask=_unsigned_mask(ace.mask),
            object_type_guid=guid,
            confidence=CONFIDENCE_CONFIRMED,
            forest_id=forest_id,
            domain_id=domain_id,
            domain_fqdn=domain_fqdn,
            provenance=provenance,
        )
        for kind, derivation, guid in (
            (KIND_GET_CHANGES, _DERIVATION_GET_CHANGES, GUID_GET_CHANGES),
            (KIND_GET_CHANGES_ALL, _DERIVATION_GET_CHANGES_ALL, GUID_GET_CHANGES_ALL),
        )
    ]


def _ace_edge(
    fact: AceEdgeFact,
    ace: AceView,
    source_node_id: str,
    target_node_id: str,
    provenance: ProvenanceStruct,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> EdgeRow:
    """Build one ACL-derived §4 :class:`EdgeRow` from a classified fact."""
    object_type_guid = (
        None if fact.kind in WHOLE_OBJECT_KINDS or not fact.scoped else ace.object_type_guid
    )
    return EdgeRow(
        edge_id=stable_id(fact.kind, source_node_id, target_node_id, fact.derivation),
        kind=fact.kind,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        is_inherited=ace.is_inherited,
        derivation=fact.derivation,
        access_mask=_unsigned_mask(ace.mask),
        object_type_guid=object_type_guid,
        confidence=CONFIDENCE_CONFIRMED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=provenance,
    )


def merge_mask(existing: EdgeRow, incoming: EdgeRow) -> EdgeRow:
    """Return ``existing`` with ``incoming``'s ``access_mask`` bits OR-ed in.

    Used on an ``edge_id`` collision (two ACEs yielding the same
    ``(kind, source, target, derivation)`` but different masks): keep the
    deterministic-first row and union the raw mask bits (audit trail), per
    research item 8 / Open Risk 6. Masks are stored as CLEAN UNSIGNED values
    (schema v1.1 ``BIGINT`` column), so the OR result is stored unsigned. The
    ``& 0xFFFFFFFF`` on the inputs is defensive — it also normalizes any legacy
    signed-form value to unsigned before the union.
    """
    a = (existing.access_mask or 0) & 0xFFFFFFFF
    b = (incoming.access_mask or 0) & 0xFFFFFFFF
    if existing.access_mask is None and incoming.access_mask is None:
        return existing
    return replace(existing, access_mask=_unsigned_mask(a | b))


def build_dcsync_edge(
    source_node_id: str,
    domain_node_id: str,
    provenance: ProvenanceStruct,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> EdgeRow:
    """Build the synthesized ``DCSync`` edge (principal -> domain).

    Emitted for a principal holding BOTH ``GetChanges`` and ``GetChangesAll`` on
    the domain object (research item 3). The base ``GetChanges*`` ACL facts are
    kept alongside this synthesis. ``access_mask`` / ``object_type_guid`` are
    NULL; ``derivation = "SYNTH:DCSync"``.

    Failure modes:
        Never raises.
    """
    return EdgeRow(
        edge_id=stable_id(KIND_DCSYNC, source_node_id, domain_node_id, DERIVATION_DCSYNC),
        kind=KIND_DCSYNC,
        source_node_id=source_node_id,
        target_node_id=domain_node_id,
        is_inherited=False,
        derivation=DERIVATION_DCSYNC,
        access_mask=None,
        object_type_guid=None,
        confidence=CONFIDENCE_CONFIRMED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=provenance,
    )
