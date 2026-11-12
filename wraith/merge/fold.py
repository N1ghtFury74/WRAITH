"""The opt-in multi-DC merge fold (M-MS4b) — the forensically dangerous core.

This is the Phase-2 same-domain reconciliation engine described by
``docs/schema/multi-source-contract.md`` §3. It is an **explicit operator action**
run over a selected set of sources — it is NEVER wired into ingest (per-source
-separate is the default, §1.2/§3). For each ``node_id``/``edge_id`` observed by
more than one selected source it:

* resolves the **entity** taxonomy (§3.2) — ``deleted_on_source`` (tombstoned on
  one DC, live on another → present LIVE + counted) and
  ``candidate_lingering_object`` (present on a strict subset → surfaced, never
  dropped);
* unions **edges** per source (§3.5) — an edge asserted by A not B is KEPT
  (present-on-A) + counted ``edge_membership_divergence``; it never fabricates an
  edge no source asserted and never silently drops one a source did assert, and it
  NEVER re-derives over the merged object set (that fabricates attack paths — the
  single most important correctness rule in the contract);
* resolves **attributes** down the §3.3 ladder — tier-1 per-attribute newest-wins
  from the decoded ``replPropertyMetaData`` stamps (``dwVersion`` PRIMARY; a
  ``TIED`` result is explicitly NOT resolved), tier-2 object-level ``whenChanged``
  when the stamp is unavailable, tier-3 present-the-safer/higher-privilege reading
  flagged ``unresolved`` + counted ``attribute_divergence``;
* handles **secrets** honestly — divergent per-source secret material is KEPT per
  source (redacted), NEVER picked → ``secret_divergence`` with
  ``value_by_source = {source: {present, differs}}`` and never one byte of
  plaintext in the ledger, the log, or the return value.

**The presented layer is a read-time overlay (coder's §2.3 read — flagged).** The
fold writes the ``divergence`` ledger and, for every resolved attribute, the
*presented value* into that row's ``resolved_value``. It does NOT mutate the typed
canonical columns. The contract's own words are "merge is a **read-time fold, not a
destructive rewrite**" (§2.3), and the frozen canonical columns are strongly typed
while the per-source divergent values live only as raw staged attributes — writing
raw values back into typed columns would require re-normalization and risk a silent
type-coercion error. So the canonical row is left intact (first-writer-wins, as the
ingest loop wrote it), every source's raw copy is preserved untouched in
``staging_object`` + ``source_observation`` (so "not a destructive rewrite" holds),
and the merged/presented value is read by overlaying ``divergence.resolved_value``
onto the canonical row (:func:`presented_attribute`). This differs from a literal
"update the canonical row in place"; see the module hand-off report. A physical
canonical update can be layered on top of the ledger later with no fold change.

Determinism: sources, nodes, edges, and attributes are all processed in sorted
order and every value comparison is of already-decoded fields, so identical inputs
yield an identical ledger (an unresolved/TIED value is deterministically flagged,
never arbitrarily chosen). Idempotent: this run's ledger rows are deleted first
(the ``divergence`` table is intentionally keyless, M-MS4a). Honest degradation:
every skipped tier and every undetermined comparison is a COUNTED gap, never a
silent NULL — the ladder/ledger/no-silent-pick guarantee is identical whether or
not the ``replPropertyMetaData`` decoder populated tier-1.

**Untested-on-real.** The four real divergence shapes (object deleted on one DC,
divergent membership, un-replicated secret, planted lingering object) and the real
``replPropertyMetaData`` / ``msDS-ReplValueMetaData`` byte parity need a real
multi-DC capture with deliberate divergence (GOAD/Samba; contract §7.7). The
synthetic suite proves the plumbing, the ladder, the taxonomy, and the ledger —
not the real metadata bytes.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

import duckdb

from wraith.parsing.repl_metadata import (
    Recency,
    ReplAttributeStamp,
    ReplMetadataParseError,
    compare_recency,
    parse_repl_property_metadata,
)

_log = logging.getLogger(__name__)


@runtime_checkable
class SupportsRunCounters(Protocol):
    """Minimal structural type for the counter sink the fold bumps (an ``IngestRun``).

    Typed so a wrong object is a STATIC error rather than a silently-vanished count
    (reviewer prescription) — the fold never duck-types the counter sink.
    """

    def bump_coverage(self, key: str, count: int = ...) -> None: ...

    def bump_skip(self, key: str, count: int = ...) -> None: ...


# =============================================================================
# Divergence vocabulary (contract §3.2 taxonomy — LOCK) + counted-gap classes.
# =============================================================================


class DivergenceType(StrEnum):
    """The ``divergence.divergence_type`` values this fold writes (§3.2, LOCK).

    Entity-level ``deleted_on_source`` / ``candidate_lingering_object``, the
    edge-level ``edge_membership_divergence``, the attribute-level
    ``attribute_divergence``, and the secret ``secret_divergence`` — the exact
    taxonomy the contract locks. No other value is ever emitted.
    """

    DELETED_ON_SOURCE = "deleted_on_source"
    CANDIDATE_LINGERING_OBJECT = "candidate_lingering_object"
    EDGE_MEMBERSHIP_DIVERGENCE = "edge_membership_divergence"
    ATTRIBUTE_DIVERGENCE = "attribute_divergence"
    SECRET_DIVERGENCE = "secret_divergence"  # noqa: S105 - taxonomy label, not a secret


class ResolvedBy(StrEnum):
    """The ``divergence.resolved_by`` mechanism values (§3.3 ladder, LOCK).

    Exactly the three the contract permits (plus ``None`` in the column for "nothing
    resolved it"). There is deliberately **no** ``authoritative_dc`` — the owner
    removed the operator primary-DC tiebreaker (§3.3, 2026-11-11): WRAITH never lets
    a disagreement be silenced by decree.
    """

    PER_ATTR_META = "per_attr_meta"
    WHEN_CHANGED = "whenChanged"
    SAFER_READING = "safer_reading"


#: ``resolution`` sentinel for a disagreement no tier could resolve (§3.3 tier-3 /
#: a TIED stamp): the value is left un-chosen, flagged, and counted.
RESOLUTION_UNRESOLVED: str = "unresolved"
#: ``resolution`` for an entity presented live despite a tombstone on another DC.
RESOLUTION_PRESENT_LIVE: str = "present_live"
#: ``resolution`` for a candidate lingering object: surfaced, never dropped.
RESOLUTION_SURFACED: str = "surfaced"

# Counted coverage/gap classes (surfaced on the IngestRun, never silent). ------ #
#: Coverage: a node cross-compared across >=2 selected sources (attribute/secret
#: fold ran). Entity classification runs for every observed node separately.
COV_NODES_MERGED: str = "merge.nodes_reconciled"
#: Coverage: an edge observed by >=2 selected sources (a real cross-source edge
#: reconciliation). An edge seen by a single source is a membership divergence, not
#: a reconciliation, and is NOT counted here (it is counted as the divergence).
COV_EDGES_MERGED: str = "merge.edges_reconciled"
#: Gap: an attribute divergence whose tier-1 (per-attribute stamp) was unavailable
#: — no ``attr_metadata_blob``, no ATTID map entry, or no stamp for that attribute;
#: the ladder degraded to tier-2/3. Honest, never a silent tier-1 success.
GAP_TIER1_UNAVAILABLE: str = "merge.tier1_unavailable"
#: Gap: an attribute divergence left UNRESOLVED (tier-3 reached: TIED stamp or no
#: tier could pick). Counted so an un-chosen value is never silently presented.
GAP_ATTR_UNRESOLVED: str = "merge.attribute_unresolved"
#: Gap: a secret divergence (un-replicated secret material). ALWAYS counted; the
#: material is kept per-source + redacted, NEVER picked, NEVER logged.
GAP_SECRET_DIVERGENCE: str = "merge.secret_divergence"  # noqa: S105 - counter key, not a secret
#: Gap: the fold was asked to merge but fewer than two sources were selected — there
#: is nothing to reconcile; counted so the no-op is explicit, never a silent pass.
GAP_NOTHING_TO_MERGE: str = "merge.nothing_to_merge"
#: Gap: a ``staging_object.attributes`` JSON that did NOT parse — that
#: ``(node_id, source_id)`` is EXCLUDED from attribute comparison (a parse failure is
#: NOT "asserts no attributes"), never a silent ``{}`` that would flood the ledger
#: with spurious present-on-A/absent-on-B rows.
GAP_STAGING_ATTRS_UNPARSEABLE: str = "merge.staging_attrs_unparseable"
#: Gap: a per-node ``attr_metadata_blob`` that was present but did NOT decode as a
#: metadata vector — counted DISTINCTLY from the clean "no blob present" case so a
#: minority of corrupt blobs on a 3+-source node is never silently swallowed.
GAP_REPL_BLOB_UNPARSEABLE: str = "merge.repl_blob_unparseable"
#: Gap: a selected source is flagged ``is_global_catalog`` — a GC holds PARTIAL
#: read-only shadows of other domains and must never win/contaminate a same-domain
#: merge (§4.4). Counted as a defensive backstop; see the upstream-scoping precondition.
GAP_GC_SOURCE_IN_SELECTION: str = "merge.gc_source_in_selection"


# =============================================================================
# Per-source observation + secret fingerprint inputs (typed, not loose dicts).
# =============================================================================


@dataclass(frozen=True)
class NodeObservation:
    """One source's observation of one node (from ``source_observation``).

    Attributes:
        source_id: the observing source.
        is_deleted: whether this source saw the object tombstoned.
        when_changed: object-level ``whenChanged`` (``directory_timestamp``);
            replicated + cross-DC comparable (the tier-2 key). May be ``None``.
        when_created: object-level ``whenCreated``; a confidence discriminator for a
            candidate lingering object (older-than-tombstone-lifetime = a real
            candidate vs recent = replication lag). Surfaced for context; the full
            age-vs-tombstone-lifetime logic is a real-data-phase follow-on (we keep
            erring wide: candidate + surfaced). May be ``None``.
        attr_metadata_blob: the raw ``replPropertyMetaData`` bytes captured by
            M-MS4a (the tier-1 input), or ``None`` when absent.
    """

    source_id: str
    is_deleted: bool
    when_changed: datetime | None
    attr_metadata_blob: bytes | None
    when_created: datetime | None = None


@dataclass(frozen=True)
class SecretFingerprint:
    """An image-INDEPENDENT fingerprint of one source's secret material.

    The caller supplies these (the fold never decrypts and never sees plaintext):
    ``digest`` is a hash of the *plaintext secret material only* — it folds in
    neither the image SHA-256 nor the ingest run, so two DCs that replicated the
    SAME credential produce the SAME ``digest`` (no false divergence) and two DCs
    with an un-replicated password produce DIFFERENT digests (a true
    ``secret_divergence``). The fold compares opaque digests; it never stores,
    logs, or returns the digest value in the ledger (only ``present``/``differs``).

    **HARD CALLER PRECONDITION (forensically load-bearing):** ``digest`` MUST be
    computed over the DECRYPTED, normalized plaintext secret material (e.g. the raw
    16-byte NT hash), **NEVER** the on-disk PEK-encrypted form. Each DC encrypts its
    credentials under its own PEK (derived from that DC's SYSTEM boot key), so the
    encrypted blobs ALWAYS differ across DCs even for an identical password —
    fingerprinting the encrypted form would make EVERY secret falsely diverge.
    Decrypt first (Impacket secretsdump path), normalize, then digest.

    Attributes:
        secret_type: the kind of secret (e.g. ``nt_hash``), for per-type matching.
        label: the discriminator (e.g. ``history1``), so history entries match up.
        digest: an opaque hex digest of the DECRYPTED, normalized plaintext material
            (NEVER plaintext, NEVER the PEK-encrypted on-disk form).
    """

    secret_type: str
    label: str
    digest: str


#: A per-``(node_id, source_id)`` secret fingerprint set, injected by the caller.
#: The fold stays pure + DB-free for secrets (dependency-injected, fixture-friendly)
#: and NEVER touches the encrypted secret store or a DEK itself.
SecretFingerprints = Mapping[tuple[str, str], frozenset[SecretFingerprint]]

#: A safer-reading picker: given an attribute name and its per-source raw values,
#: return the more-dangerous value to present, or ``None`` when the attribute has no
#: defined danger ordering (then the fold honestly presents nothing + flags it).
SaferReading = Callable[[str, Mapping[str, object]], object | None]


# =============================================================================
# PURE taxonomy + ladder primitives (each independently unit-testable, DB-free).
# =============================================================================


class EntityVerdict(StrEnum):
    """Verdict of the entity-divergence rule (§3.2)."""

    CONSISTENT = "consistent"
    DELETED_ON_SOURCE = "deleted_on_source"
    CANDIDATE_LINGERING_OBJECT = "candidate_lingering_object"


def classify_entity(
    observations: Sequence[NodeObservation],
    selected_source_count: int,
) -> EntityVerdict:
    """Classify a node's cross-source entity state (§3.2 — pure).

    Rules, in precedence order:

    1. Tombstoned on at least one source AND live on at least one other →
       :attr:`EntityVerdict.DELETED_ON_SOURCE` (present LIVE + counted). A
       deleted-on-one-DC principal is security-relevant.
    2. LIVE on a STRICT subset of the selected sources (present+live on some,
       absent on others) → :attr:`EntityVerdict.CANDIDATE_LINGERING_OBJECT`
       (surfaced, never dropped). "live on B, absent on A" (§3.2) — a tombstone
       present on only a subset is NOT lingering and does not fire this.
    3. Otherwise (present+live on every selected source, or present only as a
       tombstone) → :attr:`EntityVerdict.CONSISTENT` (no row).

    Inputs:
        observations: this node's per-source observations (one per observing
            source; sources that never saw the node are simply absent here).
        selected_source_count: how many sources the operator selected to merge.

    Returns:
        The :class:`EntityVerdict`. Pure; never raises.
    """
    present = {o.source_id for o in observations}
    deleted = {o.source_id for o in observations if o.is_deleted}
    live = present - deleted
    if deleted and live:
        return EntityVerdict.DELETED_ON_SOURCE
    if live and len(present) < selected_source_count:
        return EntityVerdict.CANDIDATE_LINGERING_OBJECT
    return EntityVerdict.CONSISTENT


def classify_edge(
    observing_sources: Sequence[str],
    selected_source_count: int,
) -> bool:
    """Return whether an edge diverges across sources (§3.5 — pure).

    An edge observed by a STRICT subset of the selected sources is an
    ``edge_membership_divergence``: it is KEPT (present-on-the-asserting-sources,
    union) and counted, never fabricated (only edges with ≥1 observation are ever
    considered) and never silently dropped. An edge observed by every selected
    source is consistent.

    Inputs:
        observing_sources: the sources whose ``source_observation`` asserted this
            ``edge_id`` (``obj_kind='edge'``).
        selected_source_count: how many sources the operator selected.

    Returns:
        ``True`` when the edge diverges (strict-subset), else ``False``. Pure.
    """
    return 0 < len(set(observing_sources)) < selected_source_count


@dataclass(frozen=True)
class AttributeResolution:
    """The ladder outcome for one divergent attribute (§3.3)."""

    resolution: str
    resolved_by: ResolvedBy | None
    resolved_value: object | None
    winning_source: str | None
    tier1_available: bool


def decode_node_stamps(
    observations: Sequence[NodeObservation],
) -> tuple[dict[str, dict[int, ReplAttributeStamp]], int]:
    """Decode each source's metadata blob ONCE for a node (pure helper).

    Returns ``({source_id: {attid: ReplAttributeStamp}}, corrupt_blob_count)``. A
    source with no blob is simply absent from the map (the clean "no stamp" case). A
    source whose blob is present but does NOT decode is counted in
    ``corrupt_blob_count`` (DISTINCT from "no blob") and absent from the map — so a
    minority of corrupt blobs on a 3+-source node is never silently swallowed. Pure;
    never raises. Decoding once per node (not per attribute) also avoids re-parsing
    and double-counting the same corrupt blob.
    """
    decoded: dict[str, dict[int, ReplAttributeStamp]] = {}
    corrupt = 0
    for obs in observations:
        if obs.attr_metadata_blob is None:
            continue
        try:
            meta = parse_repl_property_metadata(obs.attr_metadata_blob)
        except ReplMetadataParseError:
            corrupt += 1
            continue
        decoded[obs.source_id] = {stamp.attid: stamp for stamp in meta.stamps}
    return decoded, corrupt


def tier1_per_attribute(stamps_by_source: Mapping[str, object]) -> tuple[str | None, bool]:
    """Tier-1 per-attribute newest-wins over decoded stamps (§3.3.1 — pure).

    Reduces the per-source stamps with :func:`compare_recency` (``dwVersion``
    PRIMARY, skew-immune; then time; then USN). Determinism: sources are folded in
    sorted order, and because the comparator is a total pre-order the fold result
    is order-independent for a clear winner.

    Inputs:
        stamps_by_source: ``{source_id: ReplAttributeStamp}`` for ONE attribute
            (only the sources whose stamp decoded for this attribute's ATTID).

    Returns:
        ``(winning_source_id, tied)``. ``winning_source_id`` is the newest source,
        or ``None`` when tier-1 is unavailable (fewer than two stamps) or the result
        is a true tie. ``tied`` is ``True`` ONLY on a genuine all-equal tie across
        the top candidates — the contract's explicit "NOT resolved" signal (go to
        tier-3, never pick). Pure; never raises.
    """
    items = sorted(stamps_by_source.items())
    if len(items) < 2:
        return None, False
    best_source, best_stamp = items[0]
    tied = False
    for source_id, stamp in items[1:]:
        verdict = compare_recency(best_stamp, stamp)  # type: ignore[arg-type]
        if verdict is Recency.SECOND:
            best_source, best_stamp = source_id, stamp
            tied = False
        elif verdict is Recency.TIED:
            tied = True
    # Re-confirm the winner is STRICTLY newer than every other candidate; if any
    # equal-top rival remains, it is a true tie → not resolved (never pick).
    for source_id, stamp in items:
        if source_id == best_source:
            continue
        if compare_recency(best_stamp, stamp) is Recency.TIED:  # type: ignore[arg-type]
            return None, True
    return best_source, tied


def tier2_when_changed(
    when_changed_by_source: Mapping[str, datetime | None],
) -> str | None:
    """Tier-2 object-level ``whenChanged`` newest-wins (§3.3.2 — pure).

    Returns the single source whose object ``whenChanged`` is STRICTLY the newest
    (a clear single newer object). Returns ``None`` when there is no unique maximum
    (a tie, or fewer than two timestamped sources) — the contract's "used only when
    there is a clear single newer object"; anything else descends to tier-3.

    Inputs:
        when_changed_by_source: ``{source_id: whenChanged|None}``.

    Returns:
        The uniquely-newest ``source_id``, or ``None``. Pure; never raises.
    """
    timed = sorted((ts, sid) for sid, ts in when_changed_by_source.items() if ts is not None)
    if len(timed) < 2:
        return None
    newest_ts, newest_sid = timed[-1]
    runner_ts, _ = timed[-2]
    if newest_ts == runner_ts:
        return None  # tie at the top → not a clear single newer object.
    return newest_sid


def resolve_attribute(
    attribute: str,
    values_by_source: Mapping[str, object],
    when_changed_by_source: Mapping[str, datetime | None],
    *,
    stamps_by_source: Mapping[str, ReplAttributeStamp],
    safer_reading: SaferReading,
) -> AttributeResolution:
    """Descend the §3.3 resolution ladder for one divergent attribute (pure).

    Order (descend until one tier resolves; never pick on a tie):

    1. **Per-attribute newest-wins** (:func:`tier1_per_attribute`) over the decoded
       ``replPropertyMetaData`` stamps for this attribute. A clear winner whose value
       is actually present → present its value, ``resolved_by=per_attr_meta``. A
       ``TIED`` stamp is the contract's explicit "NOT resolved" → straight to tier-3
       (the blunter object-level signal must not override a genuine per-attribute
       tie). A tier-1 winner whose value is ABSENT from staging is NOT accepted (a
       "resolved" row must never carry a null value) → it descends.
    2. **Object-level ``whenChanged``** (:func:`tier2_when_changed`), reached only
       when tier-1 was UNAVAILABLE/not-accepted. A clear single newer object with a
       present value → ``resolved_by=whenChanged``.
    3. **Present-the-safer/higher-privilege reading**, flagged ``unresolved``. When
       ``safer_reading`` knows the attribute's danger ordering it presents the more
       dangerous value (``resolved_by=safer_reading``); when it does not, the fold
       honestly presents NOTHING (``resolved_value=None``, ``resolved_by=None``) so
       it never fabricates a "safer" claim. Either way ``resolution='unresolved'``
       and the divergence is counted.

    Inputs:
        attribute: the attribute ``lDAPDisplayName``.
        values_by_source: ``{source_id: raw staged value}`` (already known to differ).
        when_changed_by_source: ``{source_id: whenChanged|None}`` (the tier-2 key).
        stamps_by_source: ``{source_id: ReplAttributeStamp}`` for THIS attribute
            (already resolved by the caller via its ATTID). Fewer than two makes
            tier-1 unavailable (honest degradation).
        safer_reading: the tier-3 danger-ordering picker.

    Returns:
        An :class:`AttributeResolution`. Pure; never raises.
    """
    tier1_available = len(stamps_by_source) >= 2

    if tier1_available:
        winner, tied = tier1_per_attribute(stamps_by_source)
        # Only accept a tier-1 winner whose value is actually present (a "resolved"
        # row must never carry a null value); otherwise descend.
        if winner is not None and not tied and values_by_source.get(winner) is not None:
            return AttributeResolution(
                resolution=ResolvedBy.PER_ATTR_META.value,
                resolved_by=ResolvedBy.PER_ATTR_META,
                resolved_value=values_by_source[winner],
                winning_source=winner,
                tier1_available=True,
            )
        if tied:
            # A genuine per-attribute tie → do NOT fall to tier-2; go to safer.
            return _tier3(attribute, values_by_source, safer_reading, tier1_available=True)
        # Winner's value absent (or no strict winner) → fall through to tier-2.

    # Tier-2 object-level whenChanged.
    winner = tier2_when_changed(when_changed_by_source)
    if winner is not None and values_by_source.get(winner) is not None:
        return AttributeResolution(
            resolution=ResolvedBy.WHEN_CHANGED.value,
            resolved_by=ResolvedBy.WHEN_CHANGED,
            resolved_value=values_by_source[winner],
            winning_source=winner,
            tier1_available=tier1_available,
        )
    return _tier3(attribute, values_by_source, safer_reading, tier1_available=tier1_available)


def _tier3(
    attribute: str,
    values_by_source: Mapping[str, object],
    safer_reading: SaferReading,
    *,
    tier1_available: bool,
) -> AttributeResolution:
    """Tier-3 safer-reading resolution (always ``unresolved``, flagged + counted)."""
    safer = safer_reading(attribute, values_by_source)
    if safer is not None:
        return AttributeResolution(
            resolution=RESOLUTION_UNRESOLVED,
            resolved_by=ResolvedBy.SAFER_READING,
            resolved_value=safer,
            winning_source=None,
            tier1_available=tier1_available,
        )
    # No defined danger ordering → present nothing; never fabricate a "safer" claim.
    return AttributeResolution(
        resolution=RESOLUTION_UNRESOLVED,
        resolved_by=None,
        resolved_value=None,
        winning_source=None,
        tier1_available=tier1_available,
    )


def _secret_value_differs(
    holders: Mapping[str, frozenset[SecretFingerprint]],
) -> bool:
    """Return whether the secret VALUE diverges among holders (pure, digests only).

    For each ``(secret_type, label)`` seen on any holder, gather the per-holder
    digest (``None`` where that holder lacks that key) and flag divergence if more
    than one distinct digest exists — this catches both a different hash and a
    history/key present on one holder but not another.
    """
    if len(holders) < 2:
        return False
    keys = {(fp.secret_type, fp.label) for fps in holders.values() for fp in fps}
    for key in keys:
        digests: set[str | None] = set()
        for fps in holders.values():
            digests.add(next((fp.digest for fp in fps if (fp.secret_type, fp.label) == key), None))
        if len(digests) > 1:
            return True
    return False


def compare_secrets(
    fingerprints_by_source: Mapping[str, frozenset[SecretFingerprint]],
) -> bool:
    """Return whether a node's secret material diverges across sources (pure).

    Compares opaque, image-independent digests only (never plaintext). A node
    diverges when EITHER:

    * **holder-set divergence** — ≥1 observing source holds secret material and
      ≥1 observing source holds NONE (the un-replicated / missing-on-DC-B headline
      case, §3.2); OR
    * **value divergence** — all observing sources hold material but a
      ``(secret_type, label)`` carries more than one distinct digest.

    Identical replicated material held by every source → ``False`` (no spurious
    divergence — the regression guarantee). A node observed by a single source, or
    with no secret material anywhere, → ``False``.

    **Caller precondition (forensically load-bearing):** each ``digest`` MUST be of
    the DECRYPTED, normalized plaintext material (e.g. the raw NT hash), NEVER the
    per-DC PEK-encrypted on-disk form — see :class:`SecretFingerprint`; otherwise
    every secret would falsely diverge.

    Inputs:
        fingerprints_by_source: ``{source_id: {SecretFingerprint, ...}}`` for ALL
            the sources that observed this node (an empty set = that source holds no
            secret material for the node).

    Returns:
        ``True`` when the secret material diverges, else ``False``. Pure; never
        raises; never logs or returns a digest/plaintext.
    """
    if len(fingerprints_by_source) < 2:
        return False
    holders = {sid: fps for sid, fps in fingerprints_by_source.items() if fps}
    if not holders:
        return False
    if len(holders) < len(fingerprints_by_source):
        return True  # holder-set divergence: some observing source holds none.
    return _secret_value_differs(holders)


# =============================================================================
# Report shapes.
# =============================================================================


@dataclass(frozen=True)
class DcVsDcReport:
    """The "DC-A and DC-B disagreed on X" report (§3.4), driven from the ledger.

    Attributes:
        source_ids: the selected sources this report spans (sorted).
        counts_by_type: ``{divergence_type: count}`` over this run's ledger rows.
        counts_by_resolution: ``{resolution: count}`` over the attribute rows.
        total: the total ledger rows written this run.
    """

    source_ids: tuple[str, ...]
    counts_by_type: dict[str, int]
    counts_by_resolution: dict[str, int]
    total: int


@dataclass
class MergeResult:
    """The outcome of a merge-fold run (counts only — NEVER secrets/plaintext).

    Attributes:
        source_ids: the selected sources that were merged (sorted).
        nodes_reconciled: nodes observed by >1 selected source (an entity fold ran).
        edges_reconciled: edges observed by >1 selected source.
        deleted_on_source: entity rows of that type written.
        candidate_lingering_objects: entity rows of that type written.
        edge_membership_divergences: edge rows written.
        attribute_divergences: attribute rows written.
        secret_divergences: secret rows written.
        attribute_unresolved: attribute rows left unresolved (tier-3).
        tier1_unavailable: attribute divergences whose tier-1 was unavailable.
        staging_attrs_unparseable: ``(node,source)`` staging rows whose attributes
            JSON did not parse (excluded from comparison + counted).
        repl_blob_unparseable: per-node metadata blobs that were present but did not
            decode (counted distinctly from "no blob").
        gc_sources_in_selection: selected sources flagged ``is_global_catalog``
            (a defensive backstop; GC partials must not enter a same-domain merge).
        report: the :class:`DcVsDcReport`.
    """

    source_ids: tuple[str, ...]
    nodes_reconciled: int = 0
    edges_reconciled: int = 0
    deleted_on_source: int = 0
    candidate_lingering_objects: int = 0
    edge_membership_divergences: int = 0
    attribute_divergences: int = 0
    secret_divergences: int = 0
    attribute_unresolved: int = 0
    tier1_unavailable: int = 0
    staging_attrs_unparseable: int = 0
    repl_blob_unparseable: int = 0
    gc_sources_in_selection: int = 0
    report: DcVsDcReport = field(default_factory=lambda: DcVsDcReport((), {}, {}, 0))


# =============================================================================
# Default tier-3 safer-reading registry (small, explicit, documented).
# =============================================================================

#: userAccountControl: the account is DISABLED when set (0x2). The SAFER/more
#: dangerous reading is the ENABLED one (bit CLEAR), so it is handled inversely.
_UAC_ACCOUNTDISABLE: int = 0x0002
#: userAccountControl: NOT_DELEGATED (0x100000) is PROTECTIVE ("account is sensitive
#: and cannot be delegated"). The more-dangerous reading is the bit CLEAR, so it too
#: is handled INVERSELY — a pure NOT_DELEGATED divergence must not tie on score and
#: silently present the safer (protected) copy.
_UAC_NOT_DELEGATED: int = 0x100000
#: userAccountControl bits that make an account MORE dangerous when SET: PASSWD_NOTREQD
#: (0x20), ENCRYPTED_TEXT_PWD_ALLOWED (0x80), DONT_EXPIRE_PASSWORD (0x10000),
#: TRUSTED_FOR_DELEGATION/unconstrained (0x80000), USE_DES_KEY_ONLY (0x200000),
#: DONT_REQ_PREAUTH/AS-REP-roast (0x400000), TRUSTED_TO_AUTH_FOR_DELEGATION/constrained
#: (0x1000000). A non-exhaustive, documented, refine-on-real-data baseline covering
#: the persistence/delegation/roast primitives.
_UAC_DANGEROUS_BITS: int = 0x20 | 0x80 | 0x10000 | 0x80000 | 0x200000 | 0x400000 | 0x1000000
#: Weight for the enabled/protective INVERSE bits so they dominate the set-bit
#: popcount (which maxes at ~7) deterministically.
_UAC_INVERSE_WEIGHT: int = 1 << 40
#: primaryGroupID RID → privilege rank (higher = more dangerous). The classic
#: privileged primary-group RIDs; anything else ranks 0 (e.g. 513 Domain Users).
_PRIMARY_GROUP_DANGER: dict[int, int] = {
    519: 6,  # Enterprise Admins
    512: 5,  # Domain Admins
    518: 4,  # Schema Admins
    516: 3,  # Domain Controllers
    521: 3,  # Read-only Domain Controllers
    520: 2,  # Group Policy Creator Owners
    544: 2,  # Administrators (BUILTIN, if ever a primaryGroupID)
}


def _as_int(value: object) -> int | None:
    """Coerce a staged scalar (int / single-element list / numeric str) to int."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, list) and len(value) == 1:
        return _as_int(value[0])
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _uac_danger_score(value: object) -> int | None:
    """Danger score for a userAccountControl value (higher = more dangerous).

    Enabled (ACCOUNTDISABLE clear) and NOT_DELEGATED-clear are PROTECTIVE-inverse
    bits scored when CLEAR; the delegation/roast/persistence bits are scored when
    SET. A pure NOT_DELEGATED-only divergence therefore does NOT tie on score (the
    bug this fixes).
    """
    raw = _as_int(value)
    if raw is None:
        return None
    score = 0
    if not raw & _UAC_ACCOUNTDISABLE:  # enabled is more dangerous than disabled
        score += _UAC_INVERSE_WEIGHT
    if not raw & _UAC_NOT_DELEGATED:  # delegable (bit CLEAR) is more dangerous
        score += _UAC_INVERSE_WEIGHT
    score += bin(raw & _UAC_DANGEROUS_BITS).count("1")
    return score


def _nonempty_count_score(value: object) -> int | None:
    """Danger score for a multi-valued "presence/count is dangerous" attribute.

    More entries = more dangerous (e.g. more SPNs = more Kerberoastable; a present
    RBCD SD / keyCredentialLink / sIDHistory = an abuse primitive). A list scores by
    length; a present scalar / bytes-tag scores 1; absent/empty scores 0. Never
    ``None`` (presence is always comparable).
    """
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, str):
        return 1 if value else 0
    if isinstance(value, dict):  # a ``{"__bytes_hex__": ...}`` tag or SD struct
        return 1 if value else 0
    return 1


def _primary_group_score(value: object) -> int | None:
    """Danger score for a primaryGroupID RID (privileged primary group = dangerous)."""
    rid = _as_int(value)
    if rid is None:
        return None
    return _PRIMARY_GROUP_DANGER.get(rid, 0)


#: The tier-3 danger-ordering registry (lowercased ``lDAPDisplayName`` → scorer).
#: Covers the account-state + persistence/delegation/roast primitives an attacker
#: reasons about; deliberately conservative + a documented refine-on-real-data point.
_DANGER_SCORERS: dict[str, Callable[[object], int | None]] = {
    "useraccountcontrol": _uac_danger_score,
    "admincount": _as_int,
    "msds-allowedtoactonbehalfofotheridentity": _nonempty_count_score,  # RBCD
    "msds-keycredentiallink": _nonempty_count_score,  # shadow credentials
    "sidhistory": _nonempty_count_score,  # injected privileged SID
    "serviceprincipalname": _nonempty_count_score,  # Kerberoastable surface
    "primarygroupid": _primary_group_score,  # privileged primary group
}


def default_safer_reading(attribute: str, values_by_source: Mapping[str, object]) -> object | None:
    """The default tier-3 danger-ordering picker (small, documented registry).

    Returns the MORE dangerous value for an attribute in :data:`_DANGER_SCORERS`:

    * ``userAccountControl`` — ENABLED and delegation/roast/persistence reading;
      ACCOUNTDISABLE and NOT_DELEGATED are PROTECTIVE and handled INVERSELY (the
      dangerous reading is the bit CLEAR).
    * ``adminCount`` — ``1`` (protected/was-privileged) over ``0``.
    * ``msDS-AllowedToActOnBehalfOfOtherIdentity`` (RBCD), ``msDS-KeyCredentialLink``
      (shadow creds), ``sIDHistory`` (injected SID), ``servicePrincipalName``
      (Kerberoast) — present / more entries is the dangerous reading.
    * ``primaryGroupID`` — the more-privileged primary-group RID.

    Every other attribute has no defined danger ordering and returns ``None`` — the
    fold then honestly presents nothing and flags the divergence ``unresolved``
    rather than claiming a "safer" value it cannot justify.

    Inputs:
        attribute: the attribute ``lDAPDisplayName``.
        values_by_source: ``{source_id: raw staged value}``.

    Returns:
        The more-dangerous value to present, or ``None`` when undefined/uncomparable.
        Pure; deterministic (ties on the danger score fall back to the sorted-first
        source so the presented value is reproducible).
    """
    scorer = _DANGER_SCORERS.get(attribute.lower())
    if scorer is None:
        return None
    best_value: object | None = None
    best_score: int | None = None
    for source_id in sorted(values_by_source):
        value = values_by_source[source_id]
        score = scorer(value)
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score, best_value = score, value
    return best_value


# =============================================================================
# The orchestrator — reads the store, writes the ledger (idempotent, opt-in).
# =============================================================================


def merge_fold(
    con: duckdb.DuckDBPyConnection,
    source_ids: Sequence[str],
    *,
    run_id: UUID,
    attid_by_name: Mapping[str, int] | None = None,
    secret_fingerprints: SecretFingerprints | None = None,
    safer_reading: SaferReading = default_safer_reading,
    run: SupportsRunCounters | None = None,
) -> MergeResult:
    """Run the opt-in merge fold over a selected source set (§3, the forensic core).

    OPT-IN by construction: this is a standalone callable the operator invokes over
    a chosen ``source_ids`` set; it is NEVER called at ingest. It reads the
    per-source raw copies from ``source_observation`` + ``staging_object`` (and
    caller-supplied secret fingerprints), classifies every disagreement per the
    §3.2 taxonomy, resolves attributes down the §3.3 ladder, and writes one
    ``divergence`` ledger row per disagreement. The canonical typed rows are NOT
    mutated (read-time presented overlay via ``resolved_value``; see the module
    docstring). Idempotent: this run's ledger rows are deleted first. Deterministic:
    sources/nodes/edges/attributes are processed in sorted order.

    Inputs:
        con: an open combined multi-source store with ``source_observation``,
            ``staging_object``, and the ``divergence`` ledger (``create_divergence_table``).
        source_ids: the selected sources to merge (2+ to do anything; <2 is a
            counted no-op).
        run_id: the ingest/merge run id stamped on every ledger row (idempotency key).
        attid_by_name: optional ``lDAPDisplayName -> ATTID`` map arming tier-1; its
            absence degrades the ladder honestly to tier-2/3.
        secret_fingerprints: optional per-``(node_id, source_id)`` secret fingerprint
            sets (opaque digests, never plaintext). Absent → no secret comparison is
            performed (no false divergence, honestly reported as ``secret_divergences=0``).
        safer_reading: the tier-3 danger-ordering picker (default
            :func:`default_safer_reading`).
        run: optional :class:`SupportsRunCounters` (an ``IngestRun``) to accumulate
            the coverage/gap counts; ``None`` skips counting but the returned
            :class:`MergeResult` is identical.

    Returns:
        A :class:`MergeResult` (counts + the :class:`DcVsDcReport`; never secrets).

    GC backstop (§4.4): a selected source flagged ``is_global_catalog`` is counted
    (:data:`GAP_GC_SOURCE_IN_SELECTION`) — a GC holds PARTIAL read-only shadows of
    OTHER domains and must never win/contaminate a same-domain merge. In a correctly
    -scoped single-domain merge this never triggers (GC partials are other domains →
    distinct ``node_id``). The UPSTREAM-SCOPING PRECONDITION the caller must honour:
    do not place a GC source in a same-domain merge selection for the shadowed domain.

    Failure modes:
        Raises ``duckdb.Error`` if the required tables are absent. A malformed
        per-node attributes JSON or an unparseable metadata blob degrades to a
        counted gap, never a crash.
    """
    selected = sorted(set(source_ids))
    result = MergeResult(source_ids=tuple(selected))

    # Idempotent: clear THIS run's ledger rows first (the table is keyless, M-MS4a).
    con.execute("DELETE FROM divergence WHERE ingest_run_id = ?", [run_id])

    if len(selected) < 2:
        _bump(run, "skip", GAP_NOTHING_TO_MERGE, 1)
        result.report = _build_report(con, run_id, selected)
        _log.info("merge_fold: <2 sources selected (%d) — nothing to merge", len(selected))
        return result

    # GC partial-replica defensive backstop (§4.4): count any selected GC source.
    result.gc_sources_in_selection = _count_gc_sources(con, selected)

    node_obs = _load_node_observations(con, selected)
    staged, result.staging_attrs_unparseable = _load_staged_attributes(con, selected)
    edge_obs = _load_edge_observations(con, selected)

    rows: list[_LedgerRow] = []
    selected_count = len(selected)

    for node_id in sorted(node_obs):
        observations = node_obs[node_id]
        # Entity classification runs for EVERY observed node: a candidate lingering
        # object is live on a subset of sources (possibly only one), so it must not
        # be gated behind ">1 source" (that gate is only for attribute/secret folds).
        _reconcile_entity(node_id, observations, selected_count, rows, result)
        if len({o.source_id for o in observations}) < 2:
            continue  # observed by a single source — nothing to cross-compare.
        result.nodes_reconciled += 1
        _reconcile_attributes(
            node_id,
            observations,
            staged.get(node_id, {}),
            attid_by_name,
            safer_reading,
            rows,
            result,
        )
        _reconcile_secrets(node_id, observations, secret_fingerprints, rows, result)

    _reconcile_edges(edge_obs, selected_count, rows, result)

    _write_ledger(con, rows, run_id)
    _emit_counts(run, result)
    result.report = _build_report(con, run_id, selected)
    _log.info(
        "merge_fold over %d sources: %d nodes, %d edges reconciled; %d ledger rows "
        "(%d deleted_on_source, %d lingering, %d edge, %d attribute, %d secret)",
        selected_count,
        result.nodes_reconciled,
        result.edges_reconciled,
        len(rows),
        result.deleted_on_source,
        result.candidate_lingering_objects,
        result.edge_membership_divergences,
        result.attribute_divergences,
        result.secret_divergences,
    )
    return result


# --------------------------------------------------------------------------- #
#  Internal row shape + per-taxonomy reconcilers (small, focused).             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _LedgerRow:
    """One pending ``divergence`` row (internal; never carries plaintext)."""

    obj_kind: str
    obj_id: str
    attribute: str | None
    value_by_source: str  # JSON string (sorted keys; secrets redacted)
    divergence_type: str
    resolution: str
    resolved_value: str | None  # JSON string or None
    resolved_by: str | None


def _reconcile_entity(
    node_id: str,
    observations: Sequence[NodeObservation],
    selected_count: int,
    rows: list[_LedgerRow],
    result: MergeResult,
) -> None:
    """Emit the entity-level divergence row (if any) for a node (§3.2)."""
    verdict = classify_entity(observations, selected_count)
    if verdict is EntityVerdict.CONSISTENT:
        return
    value_by_source = {o.source_id: {"is_deleted": o.is_deleted} for o in observations}
    if verdict is EntityVerdict.DELETED_ON_SOURCE:
        live = sorted(o.source_id for o in observations if not o.is_deleted)
        rows.append(
            _LedgerRow(
                obj_kind="node",
                obj_id=node_id,
                attribute=None,
                value_by_source=_json(value_by_source),
                divergence_type=DivergenceType.DELETED_ON_SOURCE.value,
                resolution=RESOLUTION_PRESENT_LIVE,
                resolved_value=_json({"present_live_from": live}),
                resolved_by=None,
            )
        )
        result.deleted_on_source += 1
    else:  # CANDIDATE_LINGERING_OBJECT
        present = sorted(o.source_id for o in observations)
        # whenCreated is surfaced for confidence (older-than-tombstone-lifetime = a
        # real candidate vs recent = replication lag); the full age-vs-lifetime logic
        # is a real-data-phase follow-on — we keep erring wide (candidate + surfaced).
        when_created = {
            o.source_id: (o.when_created.isoformat() if o.when_created else None)
            for o in observations
        }
        rows.append(
            _LedgerRow(
                obj_kind="node",
                obj_id=node_id,
                attribute=None,
                value_by_source=_json(
                    {sid: {"present": True, "when_created": when_created[sid]} for sid in present}
                ),
                divergence_type=DivergenceType.CANDIDATE_LINGERING_OBJECT.value,
                resolution=RESOLUTION_SURFACED,
                resolved_value=_json({"present_on": present}),
                resolved_by=None,
            )
        )
        result.candidate_lingering_objects += 1


def _reconcile_attributes(
    node_id: str,
    observations: Sequence[NodeObservation],
    staged_by_source: Mapping[str, Mapping[str, object]],
    attid_by_name: Mapping[str, int] | None,
    safer_reading: SaferReading,
    rows: list[_LedgerRow],
    result: MergeResult,
) -> None:
    """Emit attribute-divergence rows for a node down the §3.3 ladder.

    ``staged_by_source`` contains only the sources whose ``staging_object.attributes``
    PARSED (unparseable sources are excluded upstream + counted), so a corrupt
    staging row can never masquerade as "asserts no attributes" and flood the ledger
    with spurious present/absent rows.
    """
    if len(staged_by_source) < 2:
        return
    # Decode each source's replPropertyMetaData ONCE for this node; count corrupt
    # blobs distinctly from the clean "no blob" case (never silently swallowed).
    decoded, corrupt = decode_node_stamps(observations)
    result.repl_blob_unparseable += corrupt
    when_changed_by_source = {o.source_id: o.when_changed for o in observations}

    all_attrs = sorted({name for attrs in staged_by_source.values() for name in attrs})
    for attribute in all_attrs:
        values_by_source = {
            sid: attrs[attribute] for sid, attrs in staged_by_source.items() if attribute in attrs
        }
        if not _values_differ(values_by_source, len(staged_by_source)):
            continue
        attid = attid_by_name.get(attribute) if attid_by_name else None
        stamps_by_source: dict[str, ReplAttributeStamp] = (
            {sid: stamps[attid] for sid, stamps in decoded.items() if attid in stamps}
            if attid is not None
            else {}
        )
        resolution = resolve_attribute(
            attribute,
            values_by_source,
            when_changed_by_source,
            stamps_by_source=stamps_by_source,
            safer_reading=safer_reading,
        )
        rows.append(
            _LedgerRow(
                obj_kind="node",
                obj_id=node_id,
                attribute=attribute,
                value_by_source=_json(values_by_source),
                divergence_type=DivergenceType.ATTRIBUTE_DIVERGENCE.value,
                resolution=resolution.resolution,
                resolved_value=(
                    None if resolution.resolved_value is None else _json(resolution.resolved_value)
                ),
                resolved_by=(
                    None if resolution.resolved_by is None else resolution.resolved_by.value
                ),
            )
        )
        result.attribute_divergences += 1
        if not resolution.tier1_available:
            result.tier1_unavailable += 1
        if resolution.resolution == RESOLUTION_UNRESOLVED:
            result.attribute_unresolved += 1


def _reconcile_secrets(
    node_id: str,
    observations: Sequence[NodeObservation],
    secret_fingerprints: SecretFingerprints | None,
    rows: list[_LedgerRow],
    result: MergeResult,
) -> None:
    """Emit a secret-divergence row for a node (redacted, never picked, §3.2).

    ``value_by_source`` names EVERY observing source with ``present`` (holder-set
    divergence — which DC is missing the secret) separated from ``differs`` (value
    divergence among holders), so the un-replicated / missing-on-DC-B shape reads
    legibly. Never a digest, never plaintext — only the redacted flags.
    """
    if secret_fingerprints is None:
        return
    fps_by_source = {
        o.source_id: secret_fingerprints.get((node_id, o.source_id), frozenset())
        for o in observations
    }
    if not compare_secrets(fps_by_source):
        return
    holders = {sid for sid, fps in fps_by_source.items() if fps}
    value_differs = _secret_value_differs({sid: fps_by_source[sid] for sid in holders})
    value_by_source = {
        sid: {"present": sid in holders, "differs": value_differs if sid in holders else False}
        for sid in sorted(fps_by_source)
    }
    rows.append(
        _LedgerRow(
            obj_kind="node",
            obj_id=node_id,
            attribute=None,
            value_by_source=_json(value_by_source),
            divergence_type=DivergenceType.SECRET_DIVERGENCE.value,
            resolution=RESOLUTION_UNRESOLVED,
            resolved_value=None,  # secrets are NEVER picked.
            resolved_by=None,
        )
    )
    result.secret_divergences += 1


def _reconcile_edges(
    edge_obs: Mapping[str, list[str]],
    selected_count: int,
    rows: list[_LedgerRow],
    result: MergeResult,
) -> None:
    """Emit edge-membership-divergence rows via per-source UNION (§3.5).

    The edge-"keep" (union) guarantee is CO-OWNED with the ingest layer: the
    multi-source append copies the frozen ``edge`` table first-writer-wins via
    ``INSERT OR IGNORE`` keyed on the deterministic ``edge_id`` (confirmed in
    ``wraith/export/pipeline.py`` ``_append_source_store`` / ``_FROZEN_CANONICAL_COPY``),
    so the canonical ``edge`` row for an ``edge_id`` asserted by ANY source exists
    exactly once (never last-writer, never duplicated). This fold then unions the
    per-source OBSERVATIONS of that ``edge_id`` and flags the strict-subset ones — it
    adds no edge and drops none.
    """
    for edge_id in sorted(edge_obs):
        observing = edge_obs[edge_id]
        # Every edge with >=1 observation is union-present (kept in canonical); we
        # never fabricate one no source asserted and never drop one a source did.
        # Count edges_reconciled ONLY for edges actually seen by >=2 sources (a real
        # cross-source reconciliation) — an edge on a single source is a divergence,
        # counted as such, not an inflated "reconciliation" (metric honesty).
        if len(set(observing)) >= 2:
            result.edges_reconciled += 1
        if not classify_edge(observing, selected_count):
            continue
        present = sorted(set(observing))
        rows.append(
            _LedgerRow(
                obj_kind="edge",
                obj_id=edge_id,
                attribute=None,
                value_by_source=_json({sid: {"present": True} for sid in present}),
                divergence_type=DivergenceType.EDGE_MEMBERSHIP_DIVERGENCE.value,
                resolution=RESOLUTION_SURFACED,
                resolved_value=_json({"present_on": present}),  # union: kept, never dropped.
                resolved_by=None,
            )
        )
        result.edge_membership_divergences += 1


# --------------------------------------------------------------------------- #
#  Store IO (narrow, parameterized SELECT/INSERT — easy to fixture).           #
# --------------------------------------------------------------------------- #


def _load_node_observations(
    con: duckdb.DuckDBPyConnection, source_ids: Sequence[str]
) -> dict[str, list[NodeObservation]]:
    """Load ``{node_id: [NodeObservation, ...]}`` for the selected sources."""
    placeholders = ", ".join("?" for _ in source_ids)
    rows = con.execute(
        "SELECT obj_id, source_id, is_deleted, directory_timestamp, attr_metadata_blob, "
        "when_created FROM source_observation "
        f"WHERE obj_kind = 'node' AND source_id IN ({placeholders}) "
        "ORDER BY obj_id, source_id",
        list(source_ids),
    ).fetchall()
    out: dict[str, list[NodeObservation]] = {}
    for obj_id, source_id, is_deleted, when_changed, blob, when_created in rows:
        out.setdefault(obj_id, []).append(
            NodeObservation(
                source_id=str(source_id),
                is_deleted=bool(is_deleted),
                when_changed=when_changed,
                attr_metadata_blob=bytes(blob) if blob is not None else None,
                when_created=when_created,
            )
        )
    return out


def _load_staged_attributes(
    con: duckdb.DuckDBPyConnection, source_ids: Sequence[str]
) -> tuple[dict[str, dict[str, dict[str, object]]], int]:
    """Load ``({node_id: {source_id: {attr: value}}}, unparseable_count)``.

    Secrets are already stripped from ``staging_object.attributes`` at normalize
    time, so nothing read here is secret material. A per-row JSON that is present but
    does NOT parse is EXCLUDED from the comparison (that ``(node,source)`` is skipped,
    NOT treated as "asserts no attributes") and counted — a corrupt staging row can
    never flood the ledger with spurious present/absent attribute divergences.
    """
    placeholders = ", ".join("?" for _ in source_ids)
    rows = con.execute(
        "SELECT node_id, source_id, attributes FROM staging_object "
        f"WHERE source_id IN ({placeholders}) "
        "ORDER BY node_id, source_id",
        list(source_ids),
    ).fetchall()
    out: dict[str, dict[str, dict[str, object]]] = {}
    unparseable = 0
    for node_id, source_id, attributes_json in rows:
        attrs = _safe_load_attrs(attributes_json)
        if attrs is None:
            unparseable += 1
            continue  # EXCLUDE (parse failure is not "asserts no attributes").
        out.setdefault(str(node_id), {})[str(source_id)] = attrs
    return out, unparseable


def _count_gc_sources(con: duckdb.DuckDBPyConnection, source_ids: Sequence[str]) -> int:
    """Count selected sources flagged ``is_global_catalog`` (§4.4 defensive backstop).

    Reads the reachable ``source.is_global_catalog`` flag; a missing ``source`` table
    or NULL flag degrades to 0 (no false positive), never a crash.
    """
    placeholders = ", ".join("?" for _ in source_ids)
    try:
        row = con.execute(
            "SELECT COUNT(*) FROM source "
            f"WHERE source_id IN ({placeholders}) AND is_global_catalog = TRUE",
            list(source_ids),
        ).fetchone()
    except duckdb.Error:
        return 0
    return int(row[0]) if row is not None else 0


def _load_edge_observations(
    con: duckdb.DuckDBPyConnection, source_ids: Sequence[str]
) -> dict[str, list[str]]:
    """Load ``{edge_id: [source_id, ...]}`` for the selected sources."""
    placeholders = ", ".join("?" for _ in source_ids)
    rows = con.execute(
        "SELECT obj_id, source_id FROM source_observation "
        f"WHERE obj_kind = 'edge' AND source_id IN ({placeholders}) "
        "ORDER BY obj_id, source_id",
        list(source_ids),
    ).fetchall()
    out: dict[str, list[str]] = {}
    for obj_id, source_id in rows:
        out.setdefault(str(obj_id), []).append(str(source_id))
    return out


def _write_ledger(con: duckdb.DuckDBPyConnection, rows: Sequence[_LedgerRow], run_id: UUID) -> None:
    """Insert the pending ledger rows in a single deterministic pass."""
    for row in rows:
        con.execute(
            "INSERT INTO divergence (obj_kind, obj_id, attribute, value_by_source, "
            "divergence_type, resolution, resolved_value, resolved_by, counted, ingest_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?)",
            [
                row.obj_kind,
                row.obj_id,
                row.attribute,
                row.value_by_source,
                row.divergence_type,
                row.resolution,
                row.resolved_value,
                row.resolved_by,
                run_id,
            ],
        )


def _build_report(
    con: duckdb.DuckDBPyConnection, run_id: UUID, source_ids: Sequence[str]
) -> DcVsDcReport:
    """Build the DC-vs-DC report purely from this run's ledger rows (§3.4)."""
    type_rows = con.execute(
        "SELECT divergence_type, COUNT(*) FROM divergence WHERE ingest_run_id = ? "
        "GROUP BY divergence_type ORDER BY divergence_type",
        [run_id],
    ).fetchall()
    res_rows = con.execute(
        "SELECT resolution, COUNT(*) FROM divergence "
        "WHERE ingest_run_id = ? AND divergence_type = ? "
        "GROUP BY resolution ORDER BY resolution",
        [run_id, DivergenceType.ATTRIBUTE_DIVERGENCE.value],
    ).fetchall()
    counts_by_type = {str(t): int(n) for t, n in type_rows}
    counts_by_resolution = {str(r): int(n) for r, n in res_rows}
    total = sum(counts_by_type.values())
    return DcVsDcReport(
        source_ids=tuple(sorted(source_ids)),
        counts_by_type=counts_by_type,
        counts_by_resolution=counts_by_resolution,
        total=total,
    )


class PresentedState(StrEnum):
    """The three states of a read-time presented attribute (§2.3 overlay)."""

    #: No divergence row for this attribute — use the canonical first-writer value.
    NO_DIVERGENCE = "no_divergence"
    #: A tier resolved a presented value — ``value`` carries the overlay.
    RESOLVED = "resolved"
    #: Diverged but UNRESOLVED (tier-3 / secret): the canonical first-writer value is
    #: still shown, but the consumer MUST badge it contested (no silent benign read).
    CONTESTED_UNRESOLVED = "contested_unresolved"


def presented_attribute(
    con: duckdb.DuckDBPyConnection,
    node_id: str,
    attribute: str,
    run_id: UUID,
) -> tuple[PresentedState, object | None]:
    """Read-time presented value for one attribute (the §2.3 overlay, read-only).

    Overlays this run's ``divergence.resolved_value`` onto the canonical row — the
    "read-time fold" (§2.3); the canonical row is never mutated by the merge fold.
    Returns a THREE-state result so a consumer (dossier/graph) can distinguish a
    resolved overlay from a CONTESTED-but-unresolved attribute (tier-3/secret with a
    null ``resolved_value``) — the latter must be badged, never shown as the benign
    canonical value with no signal.

    Inputs:
        con: the merged store.
        node_id / attribute: the attribute to present.
        run_id: the merge run whose ledger to overlay.

    Returns:
        ``(state, value)``:
          * ``NO_DIVERGENCE`` → ``value`` ``None``; use the canonical column.
          * ``RESOLVED`` → ``value`` is the decoded presented ``resolved_value``.
          * ``CONTESTED_UNRESOLVED`` → ``value`` ``None``; a divergence row exists but
            no tier resolved it (badge it; fall back to canonical for display).
        Pure read; never raises on a missing/odd row.
    """
    row = con.execute(
        "SELECT resolved_value FROM divergence "
        "WHERE ingest_run_id = ? AND obj_kind = 'node' AND obj_id = ? AND attribute = ? "
        "ORDER BY (resolved_value IS NULL), resolved_value LIMIT 1",
        [run_id, node_id, attribute],
    ).fetchone()
    if row is None:
        return PresentedState.NO_DIVERGENCE, None
    if row[0] is None:
        return PresentedState.CONTESTED_UNRESOLVED, None
    try:
        return PresentedState.RESOLVED, json.loads(row[0])
    except (ValueError, TypeError):
        return PresentedState.CONTESTED_UNRESOLVED, None


# --------------------------------------------------------------------------- #
#  Small pure helpers.                                                         #
# --------------------------------------------------------------------------- #


def _values_differ(values_by_source: Mapping[str, object], source_count: int) -> bool:
    """Return whether the per-source values differ (present-vs-absent counts too).

    A value present on only a subset of the sources is a difference (attribute set
    on A, absent on B); among present values, any inequality is a difference.
    """
    if len(values_by_source) < source_count:
        return True  # present on some sources, absent on others.
    seen = [_json(v) for v in values_by_source.values()]
    return len(set(seen)) > 1


def _safe_load_attrs(attributes_json: object) -> dict[str, object] | None:
    """Decode a ``staging_object.attributes`` JSON string (never raises).

    Returns the decoded dict; ``{}`` for a NULL/empty column (legitimately no
    attributes); or ``None`` when the column was PRESENT but did not parse to a JSON
    object — the caller counts that as :data:`GAP_STAGING_ATTRS_UNPARSEABLE` and
    EXCLUDES the row from comparison (a parse failure is not "asserts no attributes").
    """
    if attributes_json is None or attributes_json == "":
        return {}
    if not isinstance(attributes_json, str):
        return None
    try:
        data = json.loads(attributes_json)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _json(value: object) -> str:
    """Deterministic JSON encoding (sorted keys) for ledger values + comparison."""
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _bump(run: SupportsRunCounters | None, kind: str, key: str, count: int) -> None:
    """Bump a coverage/skip counter on the typed counter sink, if provided."""
    if run is None or count <= 0:
        return
    if kind == "coverage":
        run.bump_coverage(key, count)
    else:
        run.bump_skip(key, count)


def _emit_counts(run: SupportsRunCounters | None, result: MergeResult) -> None:
    """Surface the merge coverage/gap counts on the IngestRun (never silent)."""
    _bump(run, "coverage", COV_NODES_MERGED, result.nodes_reconciled)
    _bump(run, "coverage", COV_EDGES_MERGED, result.edges_reconciled)
    _bump(run, "skip", GAP_TIER1_UNAVAILABLE, result.tier1_unavailable)
    _bump(run, "skip", GAP_ATTR_UNRESOLVED, result.attribute_unresolved)
    _bump(run, "skip", GAP_SECRET_DIVERGENCE, result.secret_divergences)
    _bump(run, "skip", GAP_STAGING_ATTRS_UNPARSEABLE, result.staging_attrs_unparseable)
    _bump(run, "skip", GAP_REPL_BLOB_UNPARSEABLE, result.repl_blob_unparseable)
    _bump(run, "skip", GAP_GC_SOURCE_IN_SELECTION, result.gc_sources_in_selection)


__all__ = [
    "COV_EDGES_MERGED",
    "COV_NODES_MERGED",
    "GAP_ATTR_UNRESOLVED",
    "GAP_GC_SOURCE_IN_SELECTION",
    "GAP_NOTHING_TO_MERGE",
    "GAP_REPL_BLOB_UNPARSEABLE",
    "GAP_SECRET_DIVERGENCE",
    "GAP_STAGING_ATTRS_UNPARSEABLE",
    "GAP_TIER1_UNAVAILABLE",
    "RESOLUTION_PRESENT_LIVE",
    "RESOLUTION_SURFACED",
    "RESOLUTION_UNRESOLVED",
    "AttributeResolution",
    "DcVsDcReport",
    "DivergenceType",
    "EntityVerdict",
    "MergeResult",
    "NodeObservation",
    "PresentedState",
    "ResolvedBy",
    "SecretFingerprint",
    "SecretFingerprints",
    "SupportsRunCounters",
    "classify_edge",
    "classify_entity",
    "compare_secrets",
    "decode_node_stamps",
    "default_safer_reading",
    "merge_fold",
    "presented_attribute",
    "resolve_attribute",
    "tier1_per_attribute",
    "tier2_when_changed",
]
