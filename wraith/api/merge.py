"""Multi-source merge / divergence API surface (M-MS5a — backend only).

Exposes the gated M-MS4b merge fold (:mod:`wraith.merge.fold`) to the web API without
changing one line of the forensic merge/fold logic or the ingest pipeline. Three read
helpers + the source validation + report mapping the writable trigger reuses:

* :func:`merge_run_id` — the DETERMINISTIC per-case merge run id (``uuid5`` over the
  case id). A stable, discoverable key so a re-merge REPLACES the prior ledger (the
  fold deletes this run's rows first) and the dossier overlay / ledger read can find
  the current merge with no extra bookkeeping table.
* :func:`validate_sources` — split operator-selected ``source_ids`` into the ones that
  belong to the case (``source`` table) and the FOREIGN/unknown ones (rejected,
  bound params, untrusted input).
* :func:`merge_result_to_report` — map a gated :class:`~wraith.merge.fold.MergeResult`
  into the :class:`~wraith.api.models.MergeReportOut` (counts + DC-vs-DC report),
  surfacing the API-trigger's un-armed-input gaps so the run never over-claims.
* :func:`read_divergence_ledger` — the ``GET /divergence`` read (ledger rows + report;
  secrets stay redacted, never a digest/plaintext).
* :func:`build_merge_overlay` — the node-dossier read-time overlay (presented value +
  three-state badge), returned ONLY when a merge has run for the case (else the
  dossier is byte-UNCHANGED).

Offline, deterministic, read-only except the explicit trigger (which lives in the
writable ingest router). Never surfaces a secret.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from uuid import UUID

import duckdb

from wraith.api.models import (
    DcVsDcReportOut,
    DivergenceLedgerOut,
    DivergenceRowOut,
    MergeOverlayOut,
    MergeReportOut,
    PresentedAttributeOut,
)
from wraith.api.store import StoreReader
from wraith.merge.fold import (
    GAP_NOTHING_TO_MERGE,
    DivergenceType,
    MergeResult,
    PresentedState,
)

#: Fixed namespace for the deterministic per-case merge run id. Derived once from a
#: stable URL seed so a case's merge run id is reproducible across processes and
#: restarts (determinism rule) without hard-coding a hand-written UUID literal.
_MERGE_NAMESPACE: UUID = uuid.uuid5(uuid.NAMESPACE_URL, "https://wraith/merge/run")

#: Counted gap: the API merge trigger did not arm tier-1 of the §3.3 ladder (no
#: ``lDAPDisplayName -> ATTID`` schema map was provided), so attribute resolution ran
#: on tier-2/3 only. Surfaced so the run never silently implies tier-1 succeeded.
GAP_ATTID_MAP_NOT_ARMED: str = "merge.attid_map_not_provided"
#: Counted gap: the API merge trigger did not compute per-source secret fingerprints
#: (the decrypt-and-digest path is a separate integration), so secret divergence was
#: NOT evaluated this run. Surfaced so a store WITH un-replicated secrets never reads
#: as a silent "no secret divergence". (Never a digest/plaintext — just the flag.)
GAP_SECRET_FP_NOT_COMPUTED: str = "merge.secret_fingerprints_not_computed"  # noqa: S105
#: Counted gap: the divergence ledger was read for a case that has no merge run yet —
#: an honest empty ledger, never a silent blank.
GAP_NO_MERGE_RUN: str = "merge.no_merge_run"
#: Counted gap: the read-time presented-value lookup for a KNOWN-divergent attribute
#: FAILED at the DB layer. It degrades to a badged ``contested_unresolved`` (never the
#: benign canonical value) and is counted here so the silent-degrade never masquerades
#: as "no divergence".
GAP_PRESENTED_READ_DEGRADED: str = "merge.presented_read_degraded"


def merge_run_id(case_id: str) -> UUID:
    """Return the deterministic merge run id for ``case_id`` (``uuid5``).

    Inputs:
        case_id: the (already validated) case identifier.

    Returns:
        A stable :class:`UUID` — identical for the same case every time, so a re-merge
        overwrites the prior ledger and the overlay/ledger reads resolve the current
        merge with no side table. Pure; never raises.
    """
    return uuid.uuid5(_MERGE_NAMESPACE, case_id)


def known_source_ids(con: duckdb.DuckDBPyConnection) -> set[str]:
    """Return every ``source_id`` registered in the case store (``source`` table).

    Reads the small ``source`` dimension and returns the set. A missing ``source``
    table (a pre-M-MS1 / never-ingested store) degrades to an empty set (never raises)
    — every requested id then validates as unknown, which the trigger rejects.
    """
    try:
        rows = con.execute("SELECT source_id FROM source").fetchall()
    except duckdb.Error:
        return set()
    return {str(r[0]) for r in rows}


def validate_sources(
    con: duckdb.DuckDBPyConnection, source_ids: Sequence[str]
) -> tuple[list[str], list[str]]:
    """Split operator-selected ``source_ids`` into ``(valid, unknown)`` (untrusted input).

    De-duplicates and sorts. A requested id present in the case's ``source`` table is
    valid; any other id is FOREIGN/unknown and returned separately so the trigger can
    reject the request rather than silently merge a partial/bogus set. The membership
    test is done in Python over the fetched known set (no untrusted value is ever
    interpolated into SQL).

    Inputs:
        con: the open case store.
        source_ids: the requested source ids (untrusted).

    Returns:
        ``(valid_sorted, unknown_sorted)``. Pure over the fetched set; never raises.
    """
    requested = sorted({str(s) for s in source_ids})
    known = known_source_ids(con)
    valid = [s for s in requested if s in known]
    unknown = [s for s in requested if s not in known]
    return valid, unknown


def _report_out(result: MergeResult) -> DcVsDcReportOut:
    """Map the gated :class:`~wraith.merge.fold.DcVsDcReport` into its API shape."""
    rep = result.report
    return DcVsDcReportOut(
        source_ids=list(rep.source_ids),
        counts_by_type=dict(rep.counts_by_type),
        counts_by_resolution=dict(rep.counts_by_resolution),
        total=rep.total,
    )


def merge_result_to_report(
    result: MergeResult, case_id: str, run_id: UUID, *, nothing_to_merge: bool
) -> MergeReportOut:
    """Map a gated :class:`MergeResult` into the :class:`MergeReportOut` (M-MS4b).

    Counts-only (never a secret/digest). Always surfaces the API-trigger's un-armed
    inputs as counted gaps (tier-1 ATTID map + secret fingerprints not computed) so the
    run is honest about what it did NOT evaluate; adds the ``GAP_NOTHING_TO_MERGE`` gap
    on the ``<2``-sources no-op.

    Inputs:
        result: the fold outcome.
        case_id / run_id: echoed back so the UI can address the ledger/overlay.
        nothing_to_merge: whether fewer than two valid sources were selected.

    Returns:
        A fully-populated :class:`MergeReportOut`. Pure; never raises.
    """
    gaps: dict[str, int] = {
        GAP_ATTID_MAP_NOT_ARMED: 1,
        GAP_SECRET_FP_NOT_COMPUTED: 1,
    }
    if nothing_to_merge:
        gaps[GAP_NOTHING_TO_MERGE] = 1
    return MergeReportOut(
        case_id=case_id,
        run_id=str(run_id),
        source_ids=list(result.source_ids),
        nothing_to_merge=nothing_to_merge,
        nodes_reconciled=result.nodes_reconciled,
        edges_reconciled=result.edges_reconciled,
        deleted_on_source=result.deleted_on_source,
        candidate_lingering_objects=result.candidate_lingering_objects,
        edge_membership_divergences=result.edge_membership_divergences,
        attribute_divergences=result.attribute_divergences,
        secret_divergences=result.secret_divergences,
        attribute_unresolved=result.attribute_unresolved,
        tier1_unavailable=result.tier1_unavailable,
        staging_attrs_unparseable=result.staging_attrs_unparseable,
        repl_blob_unparseable=result.repl_blob_unparseable,
        gc_sources_in_selection=result.gc_sources_in_selection,
        report=_report_out(result),
        counted_gaps=gaps,
    )


def _ledger_report(rows: Sequence[DivergenceRowOut], source_ids: Sequence[str]) -> DcVsDcReportOut:
    """Recompute the DC-vs-DC report from ledger rows (same semantics as the fold)."""
    counts_by_type: dict[str, int] = {}
    counts_by_resolution: dict[str, int] = {}
    for r in rows:
        counts_by_type[r.divergence_type] = counts_by_type.get(r.divergence_type, 0) + 1
        if r.divergence_type == DivergenceType.ATTRIBUTE_DIVERGENCE.value and r.resolution:
            counts_by_resolution[r.resolution] = counts_by_resolution.get(r.resolution, 0) + 1
    return DcVsDcReportOut(
        source_ids=sorted(source_ids),
        counts_by_type=dict(sorted(counts_by_type.items())),
        counts_by_resolution=dict(sorted(counts_by_resolution.items())),
        total=sum(counts_by_type.values()),
    )


def read_divergence_ledger(reader: StoreReader, case_id: str) -> DivergenceLedgerOut:
    """Return the divergence ledger for a case's current merge run (``GET /divergence``).

    Reads the rows for :func:`merge_run_id` deterministically. When no merge has run
    (no ``divergence`` table, or no rows for this run) it returns an honest empty ledger
    with ``merged=False`` and a counted :data:`GAP_NO_MERGE_RUN` gap — never a silent
    blank. Secrets never appear: a ``secret_divergence`` row's ``value_by_source`` is
    the redacted ``{present, differs}`` map the fold wrote; this read re-materializes no
    digest/plaintext.

    Inputs:
        reader: the read-only case store accessor.
        case_id: the case whose ledger to read.

    Returns:
        A :class:`DivergenceLedgerOut`. Never raises on content.
    """
    run_id = merge_run_id(case_id)
    merged = reader.divergence_present(run_id)
    rows = [
        DivergenceRowOut(
            obj_kind=r.obj_kind,
            obj_id=r.obj_id,
            attribute=r.attribute,
            divergence_type=r.divergence_type,
            resolution=r.resolution,
            resolved_by=r.resolved_by,
            value_by_source=r.value_by_source,
            resolved_value=r.resolved_value,
        )
        for r in reader.divergence_rows(run_id)
    ]
    source_ids = sorted({s for r in rows for s in r.value_by_source})
    counted_gaps: dict[str, int] = {} if merged else {GAP_NO_MERGE_RUN: 1}
    return DivergenceLedgerOut(
        case_id=case_id,
        run_id=str(run_id),
        merged=merged,
        rows=rows,
        report=_ledger_report(rows, source_ids),
        counted_gaps=counted_gaps,
    )


def build_merge_overlay(reader: StoreReader, node_id: str, case_id: str) -> MergeOverlayOut | None:
    """Build the read-time merge overlay for one node's dossier, or ``None`` (M-MS4b).

    Returns ``None`` when NO merge has run for the case (the gate
    :meth:`StoreReader.divergence_present`) — so the dossier is byte-UNCHANGED on the
    single-source / non-merged path. Otherwise returns a :class:`MergeOverlayOut` for the
    node: each divergent attribute carries its three-state badge from the gated
    :func:`wraith.merge.fold.presented_attribute` (reused, not re-derived); an
    entity-level verdict (``deleted_on_source`` / ``candidate_lingering_object``) and a
    value-free ``secret_divergence`` flag are surfaced too. A contested-but-unresolved
    attribute is flagged ``contested_unresolved`` (NEVER shown as the benign canonical
    value with no signal). Secrets never surface (no digest/plaintext).

    Inputs:
        reader: the read-only (unscoped, folded) case store accessor.
        node_id: the node whose dossier is being assembled.
        case_id: the case (drives :func:`merge_run_id`).

    Returns:
        A populated :class:`MergeOverlayOut`, or ``None`` when no merge has run. Never
        raises on content.
    """
    run_id = merge_run_id(case_id)
    if not reader.divergence_present(run_id):
        return None

    presented: list[PresentedAttributeOut] = []
    entity_divergence: str | None = None
    secret_divergence = False
    contested = 0
    degraded_reads = 0
    for row in reader.divergence_rows(run_id, node_id):
        if row.attribute is not None and row.divergence_type == (
            DivergenceType.ATTRIBUTE_DIVERGENCE.value
        ):
            state, value, degraded = reader.presented_attribute(run_id, node_id, row.attribute)
            if degraded:
                degraded_reads += 1
            if state is PresentedState.CONTESTED_UNRESOLVED:
                contested += 1
            presented.append(
                PresentedAttributeOut(
                    attribute=row.attribute,
                    state=state.value,
                    presented_value=value,
                    value_by_source=row.value_by_source,
                )
            )
        elif row.divergence_type == DivergenceType.SECRET_DIVERGENCE.value:
            secret_divergence = True
        elif row.divergence_type in (
            DivergenceType.DELETED_ON_SOURCE.value,
            DivergenceType.CANDIDATE_LINGERING_OBJECT.value,
        ):
            entity_divergence = row.divergence_type

    counted_gaps: dict[str, int] = {}
    if contested:
        counted_gaps["merge.attribute_contested"] = contested
    if degraded_reads:
        counted_gaps[GAP_PRESENTED_READ_DEGRADED] = degraded_reads
    return MergeOverlayOut(
        merged=True,
        run_id=str(run_id),
        presented_attributes=presented,
        entity_divergence=entity_divergence,
        secret_divergence=secret_divergence,
        counted_gaps=counted_gaps,
    )


__all__ = [
    "GAP_ATTID_MAP_NOT_ARMED",
    "GAP_NO_MERGE_RUN",
    "GAP_PRESENTED_READ_DEGRADED",
    "GAP_SECRET_FP_NOT_COMPUTED",
    "build_merge_overlay",
    "known_source_ids",
    "merge_result_to_report",
    "merge_run_id",
    "read_divergence_ledger",
    "validate_sources",
]
