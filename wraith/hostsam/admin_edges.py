"""Tier-C host-SAM ``AdminTo`` edge emission (orchestrator + pure builders).

Given a member host's ``SAM`` hive (and, for the computer-node join, its
``SYSTEM`` hive), this pass derives the host's local-Administrators membership and
emits BloodHound-faithful ``AdminTo`` edges: ``source = member principal ->
target = the host's Computer node``, ``confidence="confirmed"``,
``derivation="SAM:AdminTo"`` (read directly from the host's authoritative SAM, so
confirmed — unlike the GPO-pushed subset which is ``inferred``). Research:
``docs/research/09-host-sam-adminto-reference.md`` §2.4/§2.7; schema §4 (``edge.kind``
is a free string -> ``AdminTo``; NO schema change).

Design (quality bar):

* **Each host SAM is its OWN artifact** — its own ``image_sha256`` + provenance
  ledger row (research §2.7). Provenance is stamped per edge from that artifact.
* **Reuse, not reinvent.** Membership comes from the plaintext alias ``C`` array
  (:mod:`wraith.hostsam.reader`); SID->node resolution reuses the M5 mint-on-miss
  :class:`~wraith.edges.acl.NodeResolver` and the shared
  :func:`~wraith.normalize.identity.node_id_for_sid`, so ids align with M3/M4/M5.
* **Local vs domain split.** A member in the host's own machine-SID domain is
  LOCAL (host-scoped only — recorded, NO fabricated cross-host edge); DOMAIN /
  well-known members are the graph-interesting cross-host edges. Local members
  are classified by SID (RID 500 = built-in admin), never by renamed display name.
* **Nested groups are NOT re-expanded.** A domain group (e.g. Domain Admins) in
  local Administrators yields one ``AdminTo`` edge to the GROUP node; the M4
  ``MemberOf`` closure expands it transitively (BloodHound parity).
* **Counted gaps, never silent.** Every skip / miss / degraded fallback increments
  a counted gap: ``hostsam.cblob_parse_error`` (malformed alias blob),
  ``hostsam.host_unresolved`` (ComputerName -> no computer node -> NO guessed edge),
  ``hostsam.member_sid_unresolved`` (mint-on-miss for an unknown domain SID),
  ``hostsam.sam_hive_unreadable`` / ``hostsam.sam_alias_absent`` (the two distinct
  read failures), ``hostsam.machine_sid_unresolved`` (``Account\\V`` tail
  unresolvable -> the LOCAL/DOMAIN ruler is lost), ``hostsam.member_unclassifiable``
  (a domain SID that can be neither confirmed DOMAIN nor ruled out LOCAL -> NO
  edge, NO stub), ``hostsam.local_member_skipped`` / ``hostsam.self_skipped``
  (coverage info), and (coverage) ``hostsam.host_not_imaged``.
* **Deterministic.** Members processed in sorted order; edges written in
  ``edge_id`` order; minted stubs written in ``node_id`` order.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.common.determinism import stable_id
from wraith.edges.acl import NodeResolver
from wraith.edges.models import EdgeRow
from wraith.hostsam.cblob import (
    DOMAIN_ALIAS_RID_DCOM_USERS,
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
    DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
)
from wraith.hostsam.reader import (
    READ_ERROR_ALIAS_ABSENT,
    AliasRead,
    HostSamRead,
    read_computer_name,
    read_host_sam,
)
from wraith.normalize.identity import is_domain_specific_sid
from wraith.normalize.models import PrincipalRow
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

# --- §4 edge literals (additive free-VARCHAR values; NO schema change) --------
KIND_ADMIN_TO: str = "AdminTo"
KIND_CAN_RDP: str = "CanRDP"
KIND_EXECUTE_DCOM: str = "ExecuteDCOM"
KIND_CAN_PSREMOTE: str = "CanPSRemote"
DERIVATION_SAM_ADMIN_TO: str = "SAM:AdminTo"
DERIVATION_SAM_CAN_RDP: str = "SAM:CanRDP"
DERIVATION_SAM_EXECUTE_DCOM: str = "SAM:ExecuteDCOM"
DERIVATION_SAM_CAN_PSREMOTE: str = "SAM:CanPSRemote"
CONFIDENCE_CONFIRMED: str = "confirmed"

#: Provenance ``source_object_id`` anchor: the exact Administrators alias ``C``
#: value parsed (the ``CanRDP`` / ``ExecuteDCOM`` / ``CanPSRemote`` lanes anchor on
#: their own alias subkey, built per-lane from the read's :class:`AliasRead`).
_SOURCE_OBJECT_PREFIX: str = "SAM\\Domains\\Builtin\\Aliases\\00000220\\C"
_SOURCE_OBJECT_PREFIX_TEMPLATE: str = "SAM\\Domains\\Builtin\\Aliases\\{subkey}\\C"

#: The three ADDITIONAL local-group lanes, keyed by alias RID — identical edge
#: model to ``AdminTo`` (member principal -> host Computer), differing only in the
#: ``kind`` + ``derivation`` strings (research 27 §2.1, SID-anchored BloodHound
#: mapping). Administrators (0x220) is handled by the legacy top-level path and is
#: deliberately NOT in this table. Order is fixed for determinism.
_EXTRA_LANE_BY_RID: Mapping[int, tuple[str, str]] = {
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS: (KIND_CAN_RDP, DERIVATION_SAM_CAN_RDP),
    DOMAIN_ALIAS_RID_DCOM_USERS: (KIND_EXECUTE_DCOM, DERIVATION_SAM_EXECUTE_DCOM),
    DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS: (KIND_CAN_PSREMOTE, DERIVATION_SAM_CAN_PSREMOTE),
}

# --- counted-gap / coverage keys (surfaced on the IngestRun ledger) -----------
GAP_CBLOB_PARSE_ERROR: str = "hostsam.cblob_parse_error"
GAP_HOST_UNRESOLVED: str = "hostsam.host_unresolved"
GAP_MEMBER_SID_UNRESOLVED: str = "hostsam.member_sid_unresolved"
#: Distinct read-error gaps (split from the former single ``hostsam.sam_read_error``):
#: the hive was missing / unopenable vs the hive was present but the Administrators
#: alias ``C`` value was absent — an operator can tell "no hive" from "no data".
GAP_SAM_HIVE_UNREADABLE: str = "hostsam.sam_hive_unreadable"
GAP_SAM_ALIAS_ABSENT: str = "hostsam.sam_alias_absent"
#: The hive + alias were read but the host's local machine SID (``Account\\V``)
#: was unresolvable, so the LOCAL/DOMAIN split falls back to the known-domain-SID
#: positive signal. Never silent — a member we cannot confirm is counted below.
GAP_MACHINE_SID_UNRESOLVED: str = "hostsam.machine_sid_unresolved"
#: A domain-specific member SID that, with no machine SID to rule out LOCAL and no
#: known-domain match to confirm DOMAIN, cannot be classified: NO edge, NO stub,
#: membership retained for operator mapping (never leaked as a false DOMAIN edge).
GAP_MEMBER_UNCLASSIFIABLE: str = "hostsam.member_unclassifiable"
GAP_HOST_NOT_IMAGED: str = "hostsam.host_not_imaged"
GAP_MEMBERS_CROSSCHECK_MISMATCH: str = "hostsam.members_crosscheck_mismatch"
COV_LOCAL_MEMBER: str = "hostsam.local_member_skipped"
COV_SELF_SKIPPED: str = "hostsam.self_skipped"
COV_HOSTS_IMAGED: str = "hostsam.hosts_imaged"


@dataclass(frozen=True)
class AliasGapTokens:
    """The PER-ALIAS counted-gap / coverage keys for one extra local-group lane.

    Keeping these per lane (keyed ``hostsam.<lane>.*``, lane = the lower-cased edge
    kind) lets coverage report each alias independently — e.g. "CanRDP present on
    3/5 hosts, 1 unreadable, 1 absent" — rather than collapsing the four aliases
    into one number. ``AdminTo`` deliberately keeps its original (un-laned) tokens
    so Gate 09 does not regress; only the three new lanes use this taxonomy.

    Benign states (``alias_absent`` / ``alias_present`` / ``alias_present_empty`` /
    ``local_member_skipped`` / ``self_skipped``) are bumped as COVERAGE counters;
    real gaps (``cblob_parse_error`` / ``member_sid_unresolved`` /
    ``member_unclassifiable``) are bumped as SKIP gaps — mirroring the AdminTo path.
    """

    alias_absent: str
    alias_present: str
    alias_present_empty: str
    cblob_parse_error: str
    local_member_skipped: str
    self_skipped: str
    member_sid_unresolved: str
    member_unclassifiable: str


def _alias_gap_tokens(kind: str) -> AliasGapTokens:
    """Build the fixed per-lane gap/coverage token set for an edge ``kind``."""
    lane = kind.lower()
    return AliasGapTokens(
        alias_absent=f"hostsam.{lane}.alias_absent",
        alias_present=f"hostsam.{lane}.alias_present",
        alias_present_empty=f"hostsam.{lane}.alias_present_empty",
        cblob_parse_error=f"hostsam.{lane}.cblob_parse_error",
        local_member_skipped=f"hostsam.{lane}.local_member_skipped",
        self_skipped=f"hostsam.{lane}.self_skipped",
        member_sid_unresolved=f"hostsam.{lane}.member_sid_unresolved",
        member_unclassifiable=f"hostsam.{lane}.member_unclassifiable",
    )


#: ``edge kind -> AliasGapTokens`` for the three additional lanes (deterministic
#: insertion order: RDP, DCOM, PSRemote). Exposed so the tester can assert the
#: exact per-alias keys without re-deriving the ``hostsam.<lane>.*`` convention.
ALIAS_GAP_TOKENS: Mapping[str, AliasGapTokens] = {
    kind: _alias_gap_tokens(kind) for kind, _derivation in _EXTRA_LANE_BY_RID.values()
}

#: Well-known DOMAIN group RIDs ([MS-DTYP] §2.4.2.4): a member bearing one of
#: these is a domain group/identity even when its domain head is not the known
#: forest domain (e.g. a trusted domain's Domain Admins), so it classifies DOMAIN
#: as a positive signal. RID 500/501 are deliberately EXCLUDED — they also name
#: LOCAL SAM accounts, so they only count as DOMAIN when the head matches the
#: known domain SID (handled separately below).
_WELLKNOWN_DOMAIN_RIDS: frozenset[int] = frozenset({498, 502, 512, 513, 516, 518, 519, 520, 521})


class MemberClass(StrEnum):
    """Classification of a SAM Administrators-alias member SID.

    ``LOCAL`` — a principal in the host's own machine-SID domain (host-scoped;
    recorded but NO cross-host edge). ``DOMAIN`` — a domain principal/group in a
    different (domain) SID space (the graph-interesting cross-host edge).
    ``WELLKNOWN`` — a non-domain-specific SID (``S-1-5-32-*``, ``S-1-5-<n>``, …);
    also edge-emitting (it links a well-known identity to the host).
    ``UNCLASSIFIABLE`` — a domain-specific SID that, with no machine SID to rule
    out LOCAL and no known-domain/well-known-RID signal to confirm DOMAIN, cannot
    be safely placed: NO edge, NO stub (never leaked as a false DOMAIN edge).
    """

    LOCAL = "local"
    DOMAIN = "domain"
    WELLKNOWN = "wellknown"
    UNCLASSIFIABLE = "unclassifiable"


def _sid_domain_head(sid: str) -> str:
    """Return a domain-specific SID's domain portion (strip the trailing RID)."""
    return sid.rsplit("-", 1)[0]


def _sid_rid(sid: str) -> int | None:
    """Return a SID's trailing RID as an int, or ``None`` if it has no numeric RID."""
    tail = sid.rsplit("-", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return None


def classify_member(
    sid: str, machine_sid: str | None, *, known_domain_sid: str | None = None
) -> MemberClass:
    """Classify an alias member SID as LOCAL / DOMAIN / WELLKNOWN / UNCLASSIFIABLE.

    Two regimes, by whether the host's local machine SID is known:

    * **``machine_sid`` KNOWN (unchanged behavior):** a domain-specific
      ``S-1-5-21-...`` SID whose domain head equals ``machine_sid`` is LOCAL
      (host-scoped, no cross-host edge); any other domain head is DOMAIN; a
      non-domain-specific SID is WELLKNOWN. The host's own built-in admin
      (RID 500, head == ``machine_sid``) is LOCAL by SID, not by name.

    * **``machine_sid`` is ``None`` (``Account\\V`` unreadable):** there is no
      LOCAL ruler, so we MUST NOT default a domain-specific SID to DOMAIN (that
      would leak the host's own local accounts as false DOMAIN edges). Instead
      use positive DOMAIN signals only: the member's domain head equals
      ``known_domain_sid`` (the M3 forest-domain SID — this subsumes the domain's
      own RID 500/501), OR the member bears a well-known DOMAIN group RID
      (:data:`_WELLKNOWN_DOMAIN_RIDS`, e.g. 512 Domain Admins). Any other
      ``S-1-5-21-...`` head is UNCLASSIFIABLE. Non-domain-specific SIDs remain
      WELLKNOWN (well-known identities are domain-independent and safe to emit).

    Inputs:
        sid: the member SID string.
        machine_sid: the host's local account-domain SID (no RID), or ``None``.
        known_domain_sid: the M3 forest-domain SID (the positive DOMAIN signal
            used only when ``machine_sid`` is ``None``); ``None`` if unavailable.

    Returns:
        The :class:`MemberClass`.

    Failure modes:
        Never raises.
    """
    if not is_domain_specific_sid(sid):
        return MemberClass.WELLKNOWN

    head = _sid_domain_head(sid)
    if machine_sid is not None:
        if head == machine_sid:
            return MemberClass.LOCAL
        return MemberClass.DOMAIN

    # No machine SID to rule out LOCAL: confirm DOMAIN only on a positive signal.
    if known_domain_sid is not None and head == known_domain_sid:
        return MemberClass.DOMAIN
    if _sid_rid(sid) in _WELLKNOWN_DOMAIN_RIDS:
        return MemberClass.DOMAIN
    return MemberClass.UNCLASSIFIABLE


# =============================================================================
# Computer-node join (host ComputerName -> DC computer object)
# =============================================================================


@dataclass(frozen=True)
class ComputerIndex:
    """Lookup from a host NetBIOS name / FQDN to a Computer node id (research §2.4).

    Built from the gated ``principal`` table's Computer rows. ``by_name`` keys are
    UPPER-cased: the ``samAccountName`` with and without its trailing ``$`` and the
    first DNS label of ``dNSHostName`` all map to the node id, so a SAM
    ComputerName (``HOST``) joins to the DC computer object (``HOST$`` /
    ``host.dom``). ``ambiguous`` holds names that matched >1 computer (duplicate
    hostnames across OUs) — those are NOT resolved (no guessed edge).
    """

    by_name: Mapping[str, str]
    ambiguous: frozenset[str]

    def resolve(self, computer_name: str | None) -> str | None:
        """Return the Computer node id for ``computer_name``, or ``None``.

        ``None`` when the name is missing, unknown, or ambiguous (duplicate) — the
        caller counts an unresolved host rather than attaching a guessed edge.
        """
        if not computer_name:
            return None
        key = computer_name.strip().upper()
        if not key or key in self.ambiguous:
            return None
        return self.by_name.get(key)


def build_computer_index(con: duckdb.DuckDBPyConnection) -> ComputerIndex:
    """Build a :class:`ComputerIndex` from the gated ``principal`` table.

    Reads every ``principal_type = 'Computer'`` row's ``samaccountname`` /
    ``distinguished_name`` and indexes resolvable name keys to the node id. A name
    that maps to more than one computer becomes ambiguous (unresolvable).

    Inputs:
        con: an open canonical store with the gated ``principal`` table.

    Returns:
        A deterministic :class:`ComputerIndex` (rows read in ``node_id`` order).

    Failure modes:
        ``duckdb.Error`` on a store failure; individual NULL names are skipped.
    """
    by_name: dict[str, str] = {}
    ambiguous: set[str] = set()

    def _register(key: str | None, node_id: str) -> None:
        if not key:
            return
        upper = key.strip().upper()
        if not upper:
            return
        existing = by_name.get(upper)
        if existing is not None and existing != node_id:
            ambiguous.add(upper)
            return
        by_name[upper] = node_id

    rows = con.execute(
        "SELECT node_id, samaccountname FROM principal "
        "WHERE principal_type = 'Computer' ORDER BY node_id"
    ).fetchall()
    for node_id, samaccountname in rows:
        if isinstance(samaccountname, str) and samaccountname:
            _register(samaccountname, node_id)
            if samaccountname.endswith("$"):
                _register(samaccountname[:-1], node_id)

    for key in ambiguous:
        by_name.pop(key, None)
    return ComputerIndex(by_name=by_name, ambiguous=frozenset(ambiguous))


# =============================================================================
# Pure edge builder
# =============================================================================


@dataclass
class AdminEdgeBuild:
    """The outcome of building one local-group lane's edges for a host (pure).

    Named ``AdminEdgeBuild`` for backward compatibility; it is the per-lane build
    result for ANY of the four lanes (``AdminTo`` / ``CanRDP`` / ``ExecuteDCOM`` /
    ``CanPSRemote``) — they share the member->host edge model.
    """

    edges: list[EdgeRow] = field(default_factory=list)
    local_members: int = 0
    domain_members: int = 0
    wellknown_members: int = 0
    unclassifiable_members: int = 0
    minted: int = 0
    self_skipped: int = 0


def build_local_group_edges(
    *,
    member_sids: Sequence[str],
    machine_sid: str | None,
    host_node_id: str,
    resolver: NodeResolver,
    make_provenance: Callable[[str], ProvenanceStruct],
    scoping: tuple[str, str | None, str | None],
    kind: str,
    derivation: str,
    source_object_prefix: str,
) -> AdminEdgeBuild:
    """Build one local-group lane's edges (member -> host computer) (pure).

    The SINGLE edge builder behind all four built-in-alias lanes — ``AdminTo`` and
    the three additional aliases ``CanRDP`` / ``ExecuteDCOM`` / ``CanPSRemote`` —
    which share the member-principal -> host-Computer edge model and differ ONLY in
    the ``kind`` / ``derivation`` strings and the provenance anchor (the alias's
    own ``C`` path). For each member SID (processed in sorted order for
    determinism): LOCAL members are counted and skipped (host-scoped, no cross-host
    edge); DOMAIN / WELLKNOWN members are resolved via the mint-on-miss ``resolver``
    and emitted as ``member_node -> host_node`` edges of ``kind``. A member
    resolving to the host itself is skipped (reflexive). A member requiring a
    freshly-minted stub (an unknown domain SID) is counted on
    :attr:`AdminEdgeBuild.minted`. When the host's ``machine_sid`` is unknown, a
    domain-specific SID that can be neither confirmed DOMAIN (known-domain head /
    well-known RID) nor ruled out LOCAL is UNCLASSIFIABLE: it is counted on
    :attr:`AdminEdgeBuild.unclassifiable_members` and yields NO edge and NO minted
    stub (never a false DOMAIN edge).

    The M3 forest-domain SID (``scoping[1]``, ``domain_id``) is threaded into
    classification as the positive DOMAIN signal for the ``machine_sid is None``
    path.

    Inputs:
        member_sids: the alias member SIDs (authoritative, from the ``C`` array).
        machine_sid: the host's local machine SID (LOCAL/DOMAIN split), or ``None``.
        host_node_id: the resolved Computer node id (the edge target).
        resolver: the shared :class:`NodeResolver` (seeded from ``principal``). The
            SAME resolver is reused across lanes so a minted stub is deduped and
            written once.
        make_provenance: ``source_object_id -> ProvenanceStruct`` for this host's
            SAM artifact, with THIS lane's alias timestamp already bound (§2.7).
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.
        kind: the edge ``kind`` (e.g. ``CanRDP``).
        derivation: the edge ``derivation`` (e.g. ``SAM:CanRDP``).
        source_object_prefix: the provenance anchor prefix — this alias's ``C``
            registry path; the per-member ``source_object_id`` is
            ``f"{source_object_prefix}:{sid}"``.

    Returns:
        An :class:`AdminEdgeBuild` (edges + per-class counts + mint count).

    Failure modes:
        Never raises; resolution always yields a node (mint-on-miss).
    """
    forest_id, domain_id, domain_fqdn = scoping
    build = AdminEdgeBuild()
    seen_edge_ids: set[str] = set()

    for sid in sorted(set(member_sids)):
        cls = classify_member(sid, machine_sid, known_domain_sid=domain_id)
        if cls is MemberClass.LOCAL:
            build.local_members += 1
            continue
        if cls is MemberClass.UNCLASSIFIABLE:
            # Cannot confirm DOMAIN and no machine_sid to rule out LOCAL: count it
            # and retain the raw membership — never emit a guessed edge or stub.
            build.unclassifiable_members += 1
            continue
        if cls is MemberClass.DOMAIN:
            build.domain_members += 1
        else:
            build.wellknown_members += 1

        before = len(resolver.minted)
        source_node_id = resolver.resolve_or_mint(sid)
        if len(resolver.minted) > before:
            build.minted += 1
        if source_node_id == host_node_id:
            build.self_skipped += 1
            continue

        edge_id = stable_id(kind, source_node_id, host_node_id, derivation)
        if edge_id in seen_edge_ids:
            continue
        seen_edge_ids.add(edge_id)
        provenance = make_provenance(f"{source_object_prefix}:{sid}")
        build.edges.append(
            EdgeRow(
                edge_id=edge_id,
                kind=kind,
                source_node_id=source_node_id,
                target_node_id=host_node_id,
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
        )
    build.edges.sort(key=lambda e: e.edge_id)
    return build


def build_admin_to_edges(
    *,
    member_sids: Sequence[str],
    machine_sid: str | None,
    host_node_id: str,
    resolver: NodeResolver,
    make_provenance: Callable[[str], ProvenanceStruct],
    scoping: tuple[str, str | None, str | None],
) -> AdminEdgeBuild:
    """Build ``AdminTo`` edges (member -> host computer) for one host (pure).

    A thin, signature-stable wrapper over :func:`build_local_group_edges` with the
    Administrators lane's ``kind`` / ``derivation`` / provenance anchor. Behavior is
    byte-for-byte identical to the original module-9 builder (Gate 09).

    Inputs/Returns/Failure modes: see :func:`build_local_group_edges`.
    """
    return build_local_group_edges(
        member_sids=member_sids,
        machine_sid=machine_sid,
        host_node_id=host_node_id,
        resolver=resolver,
        make_provenance=make_provenance,
        scoping=scoping,
        kind=KIND_ADMIN_TO,
        derivation=DERIVATION_SAM_ADMIN_TO,
        source_object_prefix=_SOURCE_OBJECT_PREFIX,
    )


# =============================================================================
# Result + orchestration
# =============================================================================


@dataclass
class AliasEdgeResult:
    """Per-lane counts for one ADDITIONAL local-group alias (no secrets).

    Captures each of the three new lanes (``CanRDP`` / ``ExecuteDCOM`` /
    ``CanPSRemote``) independently so coverage can report each alias's state on a
    host. ``found`` distinguishes an absent alias (benign) from a present one;
    ``member_count == 0`` on a ``found`` alias is the present-but-empty state.

    Attributes:
        kind: the edge kind for this lane (e.g. ``CanRDP``).
        found: whether the alias ``C`` value was present on this host.
        member_count: the alias's raw member-SID count (0 when absent/empty).
        edges_emitted: cross-host edges emitted for this lane.
        local_members / domain_members / wellknown_members / unclassifiable_members:
            the per-class member split (mirrors the AdminTo tallies).
        stubs_minted: mint-on-miss stubs created for this lane's unknown SIDs.
        self_skipped: members resolving to the host itself (reflexive, skipped).
        cblob_errors: malformed-field count from this alias's C-blob parse.
    """

    kind: str
    found: bool = False
    member_count: int = 0
    edges_emitted: int = 0
    local_members: int = 0
    domain_members: int = 0
    wellknown_members: int = 0
    unclassifiable_members: int = 0
    stubs_minted: int = 0
    self_skipped: int = 0
    cblob_errors: int = 0


@dataclass
class HostSamResult:
    """Counts from one host-SAM local-group pass (coverage + gaps; no secrets).

    The top-level ``*_members`` / ``edges_emitted`` / ``stubs_minted`` /
    ``self_skipped`` fields remain the ``AdminTo`` (Administrators-alias) tallies,
    unchanged from module 9 (Gate 09). The three additional lanes (``CanRDP`` /
    ``ExecuteDCOM`` / ``CanPSRemote``) report through :attr:`alias_results`, keyed
    by edge kind — so the AdminTo contract and its callers are untouched while the
    new per-alias coverage is fully surfaced.
    """

    computer_name: str | None = None
    host_node_id: str | None = None
    host_resolved: bool = False
    members_total: int = 0
    local_members: int = 0
    domain_members: int = 0
    wellknown_members: int = 0
    unclassifiable_members: int = 0
    edges_emitted: int = 0
    stubs_minted: int = 0
    self_skipped: int = 0
    machine_sid_resolved: bool = True
    member_sids: tuple[str, ...] = ()
    gap_counts: dict[str, int] = field(default_factory=dict)
    alias_results: dict[str, AliasEdgeResult] = field(default_factory=dict)


def _build_resolver(
    con: duckdb.DuckDBPyConnection,
    ingest_run_id: uuid.UUID,
    scoping: tuple[str, str | None, str | None],
) -> NodeResolver:
    """Seed a mint-on-miss :class:`NodeResolver` from the ``principal`` table.

    Mirrors the M5 edge-engine seeding so a minted stub for a given SID gets the
    SAME ``node_id`` M3/M5 would (cross-module id alignment).
    """
    forest_id, domain_id, domain_fqdn = scoping
    sid_to_node: dict[str, str] = {}
    all_nodes: set[str] = set()
    rows = con.execute("SELECT node_id, object_sid FROM principal ORDER BY node_id").fetchall()
    for node_id, object_sid in rows:
        all_nodes.add(node_id)
        if object_sid is not None:
            sid_to_node.setdefault(object_sid, node_id)
    return NodeResolver(
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        sid_to_node=sid_to_node,
        all_nodes=all_nodes,
        ingest_run_id=ingest_run_id,
    )


def _write_stubs(con: duckdb.DuckDBPyConnection, stubs: Mapping[str, PrincipalRow]) -> None:
    """Insert minted stub Principals sorted by ``node_id`` (deterministic)."""
    if not stubs:
        return
    ordered = [stubs[node_id].to_db_values() for node_id in sorted(stubs)]
    placeholders = ",".join("?" * len(ordered[0]))
    sql = f"INSERT INTO principal VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, ordered)


def _write_edges(con: duckdb.DuckDBPyConnection, edges: Sequence[EdgeRow]) -> None:
    """Insert local-group edges (all four lanes) in ``edge_id`` order (deterministic)."""
    if not edges:
        return
    ordered = sorted(edges, key=lambda e: e.edge_id)
    values = [edge.to_db_values() for edge in ordered]
    placeholders = ",".join("?" * len(values[0]))
    sql = f"INSERT INTO edge VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, values)


def _crosscheck_members(read: HostSamRead) -> bool:
    """Return whether the ``Members`` reverse index corroborates the C array.

    The set of domain heads among the C-array members should equal the
    ``Members`` subkey domain-SID set. An empty cross-check (not read) is treated
    as corroborated (the C array is the source of truth; the cross-check is
    optional). Pure.
    """
    if not read.members_crosscheck_domains:
        return True
    member_domains = {
        _sid_domain_head(sid) for sid in read.member_sids if is_domain_specific_sid(sid)
    }
    return member_domains == set(read.members_crosscheck_domains)


def compute_host_admin_edges(
    con: duckdb.DuckDBPyConnection,
    *,
    sam_hive_path: Path | str,
    run: IngestRun,
    scoping: tuple[str, str | None, str | None],
    sam_source_file: str = "SAM",
    system_hive_path: Path | str | None = None,
    computer_name: str | None = None,
) -> HostSamResult:
    """Emit host-SAM local-group edges for one member host into ``con``.

    Pipeline: read the host SAM alias membership for all four built-in aliases
    (:func:`read_host_sam`) -> resolve the host's ComputerName (explicit override,
    else the SYSTEM hive) -> join to a Computer node (:class:`ComputerIndex`) ->
    build + write edges (member -> host) for ``AdminTo`` (Administrators) AND the
    three additional lanes ``CanRDP`` / ``ExecuteDCOM`` / ``CanPSRemote`` (Remote
    Desktop Users / Distributed COM Users / Remote Management Users), each via the
    same mint-on-miss resolver + local/domain split -> write any minted stub
    Principals. The host SAM is its OWN artifact: its ``image_sha256`` and
    provenance come from ``run`` under ``sam_source_file`` (which MUST already be
    registered via ``run.add_artifact`` — provenance is mandatory).

    The top-level result fields carry the ``AdminTo`` tallies unchanged (Gate 09);
    the three additional lanes report through ``result.alias_results`` with
    PER-ALIAS counted gaps (:data:`ALIAS_GAP_TOKENS`).

    Inputs:
        con: an open canonical store with the gated ``principal`` + ``edge`` tables.
        sam_hive_path: the host's ``SAM`` hive (untrusted; validated before read).
        run: the :class:`IngestRun`; ``sam_source_file`` must be registered.
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.
        sam_source_file: the logical artifact name of this host's SAM (provenance).
        system_hive_path: optional host ``SYSTEM`` hive (for ComputerName).
        computer_name: optional explicit NetBIOS name (overrides the SYSTEM read).

    Returns:
        A :class:`HostSamResult` (counts + resolved host + counted gaps).

    Failure modes:
        Raises ``KeyError`` if ``sam_source_file`` is not registered on ``run``
        (provenance is mandatory — fail fast). An unreadable hive / unresolvable
        host / malformed blob degrade to counted gaps on the result + the run
        ledger, never a crash and never a guessed edge.
    """
    # Provenance is mandatory: fail fast if the host SAM artifact is unregistered.
    run.provenance_for(sam_source_file)

    result = HostSamResult()
    read = read_host_sam(sam_hive_path)
    result.member_sids = read.member_sids
    result.members_total = len(read.member_sids)

    if read.read_error:
        # Distinct gaps: a missing/unopenable hive vs a present hive with no
        # Administrators alias data — so an operator can tell them apart.
        reason = (
            GAP_SAM_ALIAS_ABSENT
            if read.read_error_reason == READ_ERROR_ALIAS_ABSENT
            else GAP_SAM_HIVE_UNREADABLE
        )
        _record_gap(run, result, reason)
        return result
    if read.cblob_errors:
        _record_gap(run, result, GAP_CBLOB_PARSE_ERROR, read.cblob_errors)
    if not _crosscheck_members(read):
        _record_gap(run, result, GAP_MEMBERS_CROSSCHECK_MISMATCH)

    # The hive + alias WERE read, but the host's local machine SID was not: the
    # LOCAL/DOMAIN split loses its LOCAL ruler. Never silent — count it, and the
    # builder falls back to the known-domain-SID positive signal (any member it
    # cannot confirm becomes a counted UNCLASSIFIABLE, not a false DOMAIN edge).
    if read.machine_sid is None:
        result.machine_sid_resolved = False
        _record_gap(run, result, GAP_MACHINE_SID_UNRESOLVED)

    # Resolve the host ComputerName -> Computer node (no guess on failure).
    name = computer_name
    if name is None and system_hive_path is not None:
        name, errors = read_computer_name(system_hive_path)
        if errors:
            _log.warning("hostsam: ComputerName unreadable from SYSTEM hive")
    result.computer_name = name

    index = build_computer_index(con)
    host_node_id = index.resolve(name)
    if host_node_id is None:
        _record_gap(run, result, GAP_HOST_UNRESOLVED)
        _log.warning(
            "hostsam: host %r unresolved to a computer node; membership parsed, no edges", name
        )
        return result
    result.host_node_id = host_node_id
    result.host_resolved = True
    run.bump_coverage(COV_HOSTS_IMAGED)

    # ONE resolver shared across all four lanes so a minted stub for a SID that
    # appears in more than one alias is deduped and written exactly once.
    resolver = _build_resolver(con, run.ingest_run_id, scoping)

    def _prov_factory(directory_timestamp: datetime | None) -> Callable[[str], ProvenanceStruct]:
        """Bind this lane's alias timestamp into a per-edge provenance factory."""

        def _make_prov(source_object_id: str) -> ProvenanceStruct:
            return run.provenance_for(
                sam_source_file,
                source_object_id=source_object_id,
                directory_timestamp=directory_timestamp,
            )

        return _make_prov

    all_edges: list[EdgeRow] = []

    # --- AdminTo lane (Administrators, 0x220): legacy top-level fields + tokens.
    admin_build = build_admin_to_edges(
        member_sids=read.member_sids,
        machine_sid=read.machine_sid,
        host_node_id=host_node_id,
        resolver=resolver,
        make_provenance=_prov_factory(read.last_change),
        scoping=scoping,
    )
    all_edges.extend(admin_build.edges)
    result.local_members = admin_build.local_members
    result.domain_members = admin_build.domain_members
    result.wellknown_members = admin_build.wellknown_members
    result.unclassifiable_members = admin_build.unclassifiable_members
    result.edges_emitted = len(admin_build.edges)
    result.stubs_minted = admin_build.minted
    result.self_skipped = admin_build.self_skipped
    if admin_build.local_members:
        run.bump_coverage(COV_LOCAL_MEMBER, admin_build.local_members)
    if admin_build.self_skipped:
        run.bump_coverage(COV_SELF_SKIPPED, admin_build.self_skipped)
    if admin_build.unclassifiable_members:
        _record_gap(run, result, GAP_MEMBER_UNCLASSIFIABLE, admin_build.unclassifiable_members)
    if admin_build.minted:
        _record_gap(run, result, GAP_MEMBER_SID_UNRESOLVED, admin_build.minted)

    # --- The three additional lanes (CanRDP / ExecuteDCOM / CanPSRemote), each
    # driven by the SAME builder + classifier, with PER-ALIAS counted gaps.
    for alias in read.aliases:
        lane = _EXTRA_LANE_BY_RID.get(alias.rid)
        if lane is None:  # pragma: no cover - reader only emits the known three
            continue
        kind, derivation = lane
        _process_extra_alias(
            alias=alias,
            kind=kind,
            derivation=derivation,
            read=read,
            host_node_id=host_node_id,
            resolver=resolver,
            scoping=scoping,
            make_provenance=_prov_factory(alias.last_change),
            run=run,
            result=result,
            all_edges=all_edges,
        )

    # Write minted stubs + every lane's edges ONCE (deterministic ordering).
    _write_stubs(con, resolver.minted)
    _write_edges(con, all_edges)
    return result


def _process_extra_alias(
    *,
    alias: AliasRead,
    kind: str,
    derivation: str,
    read: HostSamRead,
    host_node_id: str,
    resolver: NodeResolver,
    scoping: tuple[str, str | None, str | None],
    make_provenance: Callable[[str], ProvenanceStruct],
    run: IngestRun,
    result: HostSamResult,
    all_edges: list[EdgeRow],
) -> None:
    """Build + record one additional local-group lane (``CanRDP``/DCOM/PSRemote).

    Appends the lane's edges to ``all_edges`` (written once by the caller, sharing
    the caller's ``resolver`` so minted stubs dedupe) and records a per-alias
    :class:`AliasEdgeResult` on ``result.alias_results[kind]``. Every degraded /
    empty / skip branch bumps a PER-ALIAS counted gap (:data:`ALIAS_GAP_TOKENS`):

    * absent alias -> ``hostsam.<lane>.alias_absent`` (coverage; benign)
    * present / 0 members -> ``hostsam.<lane>.alias_present_empty`` (coverage; benign)
    * present / N members -> ``hostsam.<lane>.alias_present`` (coverage)
    * C-blob malformed fields -> ``hostsam.<lane>.cblob_parse_error`` (skip gap)
    * LOCAL members -> ``hostsam.<lane>.local_member_skipped`` (coverage)
    * reflexive members -> ``hostsam.<lane>.self_skipped`` (coverage)
    * minted unknown SIDs -> ``hostsam.<lane>.member_sid_unresolved`` (skip gap)
    * UNCLASSIFIABLE members -> ``hostsam.<lane>.member_unclassifiable`` (skip gap)

    Failure modes:
        Never raises; resolution is mint-on-miss and absence is benign.
    """
    tokens = ALIAS_GAP_TOKENS[kind]
    lane_res = AliasEdgeResult(kind=kind, found=alias.found)
    result.alias_results[kind] = lane_res

    if not alias.found:
        # Absent alias: benign, counted distinctly from present-but-empty.
        run.bump_coverage(tokens.alias_absent)
        return

    if alias.cblob_errors:
        lane_res.cblob_errors = alias.cblob_errors
        _record_gap(run, result, tokens.cblob_parse_error, alias.cblob_errors)

    lane_res.member_count = len(alias.member_sids)
    if not alias.member_sids:
        # Present but empty: a clean parse with zero members (distinct from absent).
        run.bump_coverage(tokens.alias_present_empty)
        return
    run.bump_coverage(tokens.alias_present)

    build = build_local_group_edges(
        member_sids=alias.member_sids,
        machine_sid=read.machine_sid,
        host_node_id=host_node_id,
        resolver=resolver,
        make_provenance=make_provenance,
        scoping=scoping,
        kind=kind,
        derivation=derivation,
        source_object_prefix=_SOURCE_OBJECT_PREFIX_TEMPLATE.format(subkey=alias.subkey),
    )
    all_edges.extend(build.edges)
    lane_res.edges_emitted = len(build.edges)
    lane_res.local_members = build.local_members
    lane_res.domain_members = build.domain_members
    lane_res.wellknown_members = build.wellknown_members
    lane_res.unclassifiable_members = build.unclassifiable_members
    lane_res.stubs_minted = build.minted
    lane_res.self_skipped = build.self_skipped

    if build.local_members:
        run.bump_coverage(tokens.local_member_skipped, build.local_members)
    if build.self_skipped:
        run.bump_coverage(tokens.self_skipped, build.self_skipped)
    if build.unclassifiable_members:
        _record_gap(run, result, tokens.member_unclassifiable, build.unclassifiable_members)
    if build.minted:
        _record_gap(run, result, tokens.member_sid_unresolved, build.minted)


def account_host_coverage(
    con: duckdb.DuckDBPyConnection,
    imaged_host_node_ids: Sequence[str],
    run: IngestRun,
) -> tuple[int, int]:
    """Surface host-SAM coverage: ``(hosts_imaged, total_computers)``.

    Every Computer node WITHOUT a supplied+resolved SAM is a counted
    ``hostsam.host_not_imaged`` gap (research §2.8/5) — a missing artifact is never
    silently assumed to have no local admins.

    Inputs:
        con: an open canonical store with the gated ``principal`` table.
        imaged_host_node_ids: the Computer node ids whose SAM was ingested AND
            resolved this run.
        run: the :class:`IngestRun` to bump the coverage gap on.

    Returns:
        ``(hosts_imaged, total_computers)``.

    Failure modes:
        ``duckdb.Error`` on a store failure.
    """
    imaged = {n for n in imaged_host_node_ids}
    rows = con.execute(
        "SELECT node_id FROM principal WHERE principal_type = 'Computer' ORDER BY node_id"
    ).fetchall()
    total = len(rows)
    not_imaged = sum(1 for (node_id,) in rows if node_id not in imaged)
    if not_imaged:
        run.bump_skip(GAP_HOST_NOT_IMAGED, not_imaged)
    return total - not_imaged, total


def _record_gap(run: IngestRun, result: HostSamResult, reason: str, count: int = 1) -> None:
    """Count a gap on both the run ledger and the local result tally."""
    result.gap_counts[reason] = result.gap_counts.get(reason, 0) + count
    run.bump_skip(reason, count)
