"""Per-source discovery + scoping surface (multi-source contract §2.3 / §5, M-MS2).

The read-side of the multi-domain (Phase 1) effort: how an operator/UI DISCOVERS the
DC artifact sets in a case and reads any one of them standalone. Three pure functions
over the read-only :class:`~wraith.api.store.StoreReader`:

* :func:`list_sources` — the ``source`` dimension rows + per-source node/edge counts
  (``GET /sources``), so a UI can offer a source picker.
* :func:`source_coverage` — per-source coverage/skip counts, aggregated from the
  provenance ledger by the source's artifact SHA-256s (``GET /sources/{id}/coverage``).
* :func:`resolve_scoped_reader` — turn an optional ``source_id`` request filter into a
  :class:`~wraith.api.store.ScopedStoreReader` (or pass the base reader through when the
  filter is omitted — the unscoped, byte-identical single-source path).

Everything here is read-only, offline, deterministic, and never returns a secret. A
degraded branch (unknown source, a SHA with no ledger row) is always a COUNTED gap,
never a silent empty.
"""

from __future__ import annotations

from wraith.api.models import (
    SourceCoverage,
    SourceCoverageArtifact,
    SourceInfo,
    SourceList,
)
from wraith.api.store import GAP_UNKNOWN_SOURCE, ScopedStoreReader, StoreReader

#: Counted gap: a per-source coverage request named a ``source_id`` that is not in
#: the ``source`` table (an unknown source) — honest empty coverage, never silent.
GAP_COVERAGE_UNKNOWN_SOURCE: str = GAP_UNKNOWN_SOURCE
#: Counted gap: a source's artifact SHA-256 had no matching ``provenance_ledger`` row
#: (coverage for that artifact is unavailable — e.g. the store predates the ledger, or
#: the artifact was not ledgered). One per unmatched SHA.
GAP_COVERAGE_SHA_UNMATCHED: str = "source.coverage_ledger_unmatched"


def list_sources(reader: StoreReader) -> SourceList:
    """Return the per-case source listing + per-source node/edge counts (M-MS2).

    Inputs:
        reader: the read-only store accessor (base reader; this listing is a
            whole-case view, not itself source-scoped).

    Returns:
        A :class:`SourceList` deterministically ordered by ``dc_label`` then
        ``source_id`` (the stable display key — never primarily the random-looking
        ``source_id``). Empty (``count == 0``) on a pre-M-MS1 store with no ``source``
        table — an honest empty listing, not an error.

    Failure modes:
        Never raises on content (a missing ``source`` table degrades to ``[]``).
    """
    rows = reader.source_rows()
    sources = [
        SourceInfo(
            source_id=r.source_id,
            dc_label=r.dc_label,
            domain_id=r.domain_id,
            domain_fqdn=r.domain_fqdn,
            forest_id=r.forest_id,
            declared_domain=r.declared_domain,
            is_global_catalog=r.is_global_catalog,
            node_count=r.node_count,
            edge_count=r.edge_count,
        )
        for r in rows
    ]
    return SourceList(sources=sources, count=len(sources))


def source_coverage(reader: StoreReader, source_id: str) -> SourceCoverage:
    """Return per-source coverage/skip counts for ``source_id`` (contract §5 item 3).

    Joins the source's artifact SHA-256s (``ntds``/``system``) to the latest-run
    ``provenance_ledger`` rows. The per-artifact tallies are summed into
    ``coverage_counts`` / ``skip_counts``. Degraded branches are counted, never
    silent: an unknown ``source_id`` -> :data:`GAP_COVERAGE_UNKNOWN_SOURCE`; a source
    SHA with no ledger row -> :data:`GAP_COVERAGE_SHA_UNMATCHED` (one per unmatched
    SHA).

    Inputs:
        reader: the read-only store accessor.
        source_id: the source whose coverage is requested.

    Returns:
        A :class:`SourceCoverage` (empty + counted gap for an unknown source).

    Failure modes:
        Never raises on content.
    """
    row = reader.source_by_id(source_id)
    if row is None:
        return SourceCoverage(source_id=source_id, counted_gaps={GAP_COVERAGE_UNKNOWN_SOURCE: 1})

    ntds_sha, system_sha = reader.source_artifact_shas(source_id)
    wanted = [s for s in (ntds_sha, system_sha) if s]
    ledger_rows = reader.ledger_coverage_for_shas(wanted)
    matched_shas = {lr.image_sha256 for lr in ledger_rows}

    artifacts: list[SourceCoverageArtifact] = []
    agg_cov: dict[str, int] = {}
    agg_skip: dict[str, int] = {}
    for lr in ledger_rows:
        artifacts.append(
            SourceCoverageArtifact(
                source_file=lr.source_file,
                image_sha256=lr.image_sha256,
                coverage_counts=dict(lr.coverage_counts),
                skip_counts=dict(lr.skip_counts),
            )
        )
        for k, v in lr.coverage_counts.items():
            agg_cov[k] = agg_cov.get(k, 0) + v
        for k, v in lr.skip_counts.items():
            agg_skip[k] = agg_skip.get(k, 0) + v

    counted_gaps: dict[str, int] = {}
    unmatched = sum(1 for s in wanted if s not in matched_shas)
    if unmatched:
        counted_gaps[GAP_COVERAGE_SHA_UNMATCHED] = unmatched

    return SourceCoverage(
        source_id=source_id,
        dc_label=row.dc_label,
        artifacts=artifacts,
        coverage_counts=dict(sorted(agg_cov.items())),
        skip_counts=dict(sorted(agg_skip.items())),
        counted_gaps=counted_gaps,
    )


def resolve_scoped_reader(reader: StoreReader, source_id: str | None) -> StoreReader:
    """Return a per-source view when ``source_id`` is given, else the base reader.

    The single choke point the read endpoints use to honor an optional ``?source_id=``
    filter. When ``source_id`` is omitted the base reader is returned UNCHANGED — the
    unscoped path stays byte-identical + zero-overhead (no ``source_observation`` join).
    When given, a :class:`~wraith.api.store.ScopedStoreReader` over the SAME connection
    is returned; an unknown/empty ``source_id`` still yields a valid (honestly empty)
    scoped reader carrying :data:`~wraith.api.store.GAP_UNKNOWN_SOURCE` in
    ``scope_gaps`` (never an error — ``source_id`` is a filter, not a route key).

    Inputs:
        reader: the base read-only store accessor (already case-resolved).
        source_id: the optional source to scope to.

    Returns:
        The base reader (unscoped) or a :class:`ScopedStoreReader`.

    Failure modes:
        Never raises; an already-scoped reader is scoped again to the requested
        source (the last filter wins) rather than compounding.
    """
    if source_id is None:
        return reader
    return ScopedStoreReader(reader._con, reader.db_path, source_id)  # noqa: SLF001


__all__ = [
    "GAP_COVERAGE_SHA_UNMATCHED",
    "GAP_COVERAGE_UNKNOWN_SOURCE",
    "list_sources",
    "resolve_scoped_reader",
    "source_coverage",
]
