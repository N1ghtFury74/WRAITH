"""Full offline analysis pipeline wiring (M6).

Runs the locked pass order end-to-end so the BloodHound exporter sees the
COMPLETE canonical graph (doc 12 §B.5)::

    ingest (hash + register)
      -> normalize        (M3: entities, staged SDs, ADCS rows)
      -> membership       (M4: MemberOf + primary-group + special-identity + closure)
      -> edges            (M5: ACL + derivations + DCSync + trusts + node flags
                           + ADCS-topology, already wired inside compute_edges)
      -> ADCS-ESC         (M8: inferred ESC composites)       [newly CLI-wired]
      -> host-SAM AdminTo (M9: per member-host SAM -> AdminTo) [newly CLI-wired]
      -> GPO/SYSVOL       (Tier B: GPOLocalGroup + derived_rights)
      -> EXPORT           (M6: canonical graph -> per-type BHCE JSON + zip)

The ADCS-ESC and host-SAM passes were standalone (gates 08/09); M6 invokes them
here. Every pass stamps provenance and surfaces its counted gaps onto the shared
:class:`~wraith.case.ingest_run.IngestRun`, so the export ledger + run ledger
account for every non-exported object (no silent drops at any boundary).
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from wraith.acquisition.hashing import sha256_file
from wraith.analysis import (
    ABSENT_CA_HOST_FACTS,
    AdcsEscResult,
    build_ca_host_facts,
    persist_ca_node_findings,
    run_adcs_esc,
)
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.edges import M5Result, compute_edges
from wraith.edges.cross_domain import (
    KIND_FOREIGN_IDENTITY,
    CrossDomainResult,
    derive_cross_domain_edges,
)
from wraith.edges.derivations import (
    KIND_CROSS_FOREST_TRUST,
    KIND_HAS_SID_HISTORY,
    KIND_HAS_TRUST_KEYS,
    KIND_SAME_FOREST_TRUST,
)
from wraith.edges.membership import resolve_membership
from wraith.edges.models import MembershipResult
from wraith.export.bloodhound import ExportConfig, ExportResult, export_bloodhound
from wraith.gpo import process_sysvol
from wraith.gpo.models import GpoProcessResult
from wraith.hostsam import HostSamResult, compute_host_admin_edges
from wraith.merge.metadata_ingest import populate_attr_metadata
from wraith.model.source import (
    SourceDomainFacts,
    SourceRecord,
    derive_source_id,
    reconcile_case_shape,
    write_source_observations,
    write_source_row,
)
from wraith.model.store import (
    create_canonical_tables,
    create_divergence_table,
    create_edge_tables,
    open_canonical_store,
)
from wraith.normalize.models import NormalizeResult
from wraith.normalize.pipeline import normalize
from wraith.parsing import open_ntds

_log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Multi-source (N-source multi-domain) loop counters (contract §3.5 / §4)     #
# --------------------------------------------------------------------------- #
#: Coverage counter: distinct sources successfully ingested into the combined
#: canonical store (one per uploaded + tagged DC artifact set).
COV_SOURCES_INGESTED: str = "multi_source.sources_ingested"
#: Coverage counter: distinct derived ``domain_id``s present in the combined store.
COV_DOMAINS_INGESTED: str = "multi_source.domains_ingested"
#: HONEST counted state (contract scope-OUT / §1.4): a same-domain second source
#: whose canonical ``node_id``s COLLIDE on the single-PK canonical tables. First
#: -writer-wins at canonical is applied (no overwrite, no crash, no silent loss)
#: and the colliding rows are counted here — the per-DC canonical merge is M-MS4
#: (Phase-2) work. The source's own ``source`` row + per-source staging +
#: ``source_observation`` are still written, so per-source coverage/listing work.
GAP_MULTI_DC_CANONICAL_MERGE_PENDING: str = "multi_dc_canonical_merge_pending_phase2"
#: HONEST counted state: a same-domain second source's ``effective_membership``
#: (the DERIVED closure table, outside the frozen canonical contract) collides
#: first-writer-wins too. Kept DISTINCT from the canonical tally above because it
#: is a derived table, not a frozen-canonical fact — its per-DC merge is likewise
#: M-MS4 work. Counted so the dropped closure rows are never silent.
GAP_MULTI_DC_EFFECTIVE_MEMBERSHIP_PENDING: str = (
    "multi_dc_effective_membership_merge_pending_phase2"
)
#: COUNTED: a source skipped as a duplicate (its deterministic ``source_id`` was
#: already ingested — the identical artifact under the same label), so its append
#: is a no-op. Counted rather than silently skipped (counted-gap-on-every-branch).
GAP_DUPLICATE_SOURCE_SKIPPED: str = "multi_source.duplicate_source_skipped"

#: The frozen canonical tables copied first-writer-wins (``INSERT OR IGNORE``) from
#: each per-source store into the combined store, with their single-column PK (the
#: column whose collision marks a same-domain multi-DC overlap, §scope-OUT).
_FROZEN_CANONICAL_COPY: tuple[tuple[str, str], ...] = (
    ("principal", "node_id"),
    ("container", "node_id"),
    ("gpo", "node_id"),
    ("trust", "node_id"),
    ("adcs", "node_id"),
    ("edge", "edge_id"),
)

#: Edge kinds that the SINGLE cross-domain resolver (:func:`derive_cross_domain_edges`,
#: M-MS3) owns. The per-source M5 pass (``compute_edges``) already emits these as
#: per-source STUBS (partner not in that one source's store); in the multi-source
#: path they are PURGED from the combined store before the resolver runs once, so a
#: cross-domain fact is never represented twice (a per-source stub AND a resolved
#: edge) — the "don't emit both a stub and a resolved edge for one fact" rule.
_CROSS_DOMAIN_EDGE_KINDS: tuple[str, ...] = (
    KIND_SAME_FOREST_TRUST,
    KIND_CROSS_FOREST_TRUST,
    KIND_HAS_TRUST_KEYS,
    KIND_HAS_SID_HISTORY,
    KIND_FOREIGN_IDENTITY,
)


@dataclass(frozen=True)
class SamHostInput:
    """One member-host SAM artifact for the host-SAM ``AdminTo`` pass.

    Attributes:
        sam_path: the host's ``SAM`` hive (untrusted; validated before read).
        source_file: the logical artifact name (provenance; must be unique per
            host, e.g. ``SAM`` or ``SAM:WS01``).
        system_hive_path: optional host ``SYSTEM`` hive for the ComputerName.
        computer_name: optional explicit NetBIOS name (overrides the SYSTEM read).
    """

    sam_path: Path
    source_file: str = "SAM"
    system_hive_path: Path | None = None
    computer_name: str | None = None


@dataclass(frozen=True)
class PipelineInputs:
    """The acquired artifacts feeding one full analysis run.

    Attributes:
        ntds_path: the NTDS ``.dit`` (required).
        forest_id: the scoping forest id (stable across the run).
        system_hive_path: the imaged DC ``SYSTEM`` hive (for ADCS-ESC ESC9/10);
            ``None`` leaves ESC9/10 undecidable (counted, never guessed).
        sam_hosts: member-host SAM artifacts for the host-SAM ``AdminTo`` pass.
        sysvol_root: the acquired SYSVOL directory (for GPO/SYSVOL edges), or None.
        ntds_source_file: logical artifact name for the ``.dit`` (provenance).
    """

    ntds_path: Path
    forest_id: str = "forest-default"
    system_hive_path: Path | None = None
    sam_hosts: tuple[SamHostInput, ...] = ()
    sysvol_root: Path | None = None
    ntds_source_file: str = "ntds.dit"
    #: The Enterprise-CA host's own ``SYSTEM`` + ``SOFTWARE`` hives (catalog kind
    #: ``ca_host_registry``), feeding the ADCS-ESC ESC6/7/11/16 decision. ``None``
    #: leaves those undecidable (the existing LOUD ``ca_host_facts_absent`` path).
    #: The coverage/upload surfacing of this kind is the separate follow-on module;
    #: this is the engine entry point only.
    ca_host_system_path: Path | None = None
    ca_host_software_path: Path | None = None
    ca_host_fqdn: str | None = None
    #: Multi-source tagging (M-MS1, contract §1.2). The operator names this DC
    #: artifact set (``dc_label``) and asserts its ``declared_domain`` (display
    #: only — the derived ``domain_id``/``domain_fqdn`` win for scoping). The two
    #: case-shape axes gate which reconciliation gaps can fire (§1.4). Defaults
    #: keep the single-source path byte-for-byte unchanged.
    dc_label: str = "primary-dc"
    declared_domain: str | None = None
    domain_cardinality: str = "single_domain"
    dc_cardinality: str = "single_dc"


@dataclass(frozen=True)
class PipelineResult:
    """The outcome of a full analysis + export run (counts only; never secrets).

    Attributes:
        domain_id/domain_fqdn: the M3-resolved scoping identity.
        normalize_result: the M3 result.
        membership_result: the M4 result.
        m5_result: the M5 edge-engine result (incl. ADCS topology).
        esc_result: the ADCS-ESC result, or ``None`` if the pass did not run.
        hostsam_results: one :class:`HostSamResult` per member-host SAM.
        gpo_result: the GPO/SYSVOL result, or ``None`` if SYSVOL was not supplied.
        export_result: the BloodHound export ledger.
        coverage_counts/skip_counts: the accumulated run counters snapshot.
    """

    domain_id: str | None
    domain_fqdn: str | None
    normalize_result: NormalizeResult
    membership_result: MembershipResult
    m5_result: M5Result
    esc_result: AdcsEscResult | None
    hostsam_results: tuple[HostSamResult, ...]
    gpo_result: GpoProcessResult | None
    export_result: ExportResult
    coverage_counts: Mapping[str, int] = field(default_factory=dict)
    skip_counts: Mapping[str, int] = field(default_factory=dict)


#: A pass-boundary progress callback: ``(pass_id, phase)`` where ``pass_id`` is a
#: :data:`wraith.case.progress_model.PASS_SPECS` id and ``phase`` is ``"start"``
#: or ``"done"``. Side-effect-only observability; ``None`` disables it and leaves
#: behaviour byte-identical (no change to outputs or determinism).
ProgressCallback = Callable[[str, str], None]


def _notify(cb: ProgressCallback | None, pass_id: str, phase: str) -> None:
    """Invoke an optional progress callback at a pass boundary (no-op if ``None``)."""
    if cb is not None:
        cb(pass_id, phase)


def _register(run: IngestRun, path: Path, source_file: str) -> str:
    """Register an artifact on the run with its SHA-256 (provenance is mandatory).

    Returns the lowercase hex SHA-256 recorded for the artifact, so the caller can
    reuse it (e.g. as the multi-source ``ntds_image_sha256``) without re-hashing.
    """
    digest = sha256_file(path)
    run.add_artifact(
        ArtifactInput(
            source_file=source_file,
            abs_path_or_ref=str(Path(path).resolve()),
            size_bytes=Path(path).stat().st_size,
            image_sha256=digest,
        )
    )
    return digest


def _register_sysvol(run: IngestRun, root: Path) -> str:
    """Register the SYSVOL artifact on the run and return its stable SHA-256.

    SYSVOL is normally a directory tree, so :func:`sha256_file_or_dir` is used for
    a deterministic dir-aware digest and the size is the sum of the member file
    sizes. Registering it here (alongside ntds/system/sam) guarantees the SYSVOL
    artifact lands in the run's artifact manifest for provenance, not only inside
    ``process_sysvol``. The returned digest is reused as ``sysvol_image_sha256``
    so the artifact is hashed exactly once.

    Inputs:
        run: the :class:`IngestRun` accumulating provenance.
        root: the acquired SYSVOL directory (or a single file).

    Returns:
        The lowercase hex SHA-256 recorded for the SYSVOL artifact.

    Failure modes:
        ``OSError`` if the tree cannot be walked; ``pydantic.ValidationError`` on
        a malformed digest (cannot happen — the digest is well-formed by
        construction).
    """
    p = Path(root)
    digest = sha256_file_or_dir(p)
    if p.is_dir():
        size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    else:
        size = p.stat().st_size
    run.add_artifact(
        ArtifactInput(
            source_file="SYSVOL",
            abs_path_or_ref=str(p.resolve()),
            size_bytes=size,
            image_sha256=digest,
        )
    )
    return digest


def _reconcile_sources(
    con: duckdb.DuckDBPyConnection, run: IngestRun, inputs: PipelineInputs
) -> None:
    """Reconcile the case-shape declaration vs the derived facts; COUNT mismatches.

    Reads EVERY ``source`` row for the case (so the same code fires the cross-source
    gaps once M-MS2 ingests N sources into one store; in Phase 1 single-source it
    reads the one row just written) and bumps each returned
    ``(gap_class, count)`` onto the run — derived-wins-for-scoping,
    declaration-wins-for-gating, mismatch-always-counted, never silent (§1.4).

    Failure modes:
        Propagates ``duckdb.Error`` only on a store failure; an absent ``source``
        row simply yields no gaps.
    """
    rows = con.execute(
        "SELECT source_id, dc_label, declared_domain, domain_id, domain_fqdn "
        "FROM source WHERE case_id = ? ORDER BY source_id",
        [run.case_id],
    ).fetchall()
    facts = [
        SourceDomainFacts(
            source_id=str(r[0]),
            dc_label=str(r[1]),
            declared_domain=r[2],
            derived_domain_id=r[3],
            derived_domain_fqdn=r[4],
        )
        for r in rows
    ]
    for gap_class, count in reconcile_case_shape(
        inputs.domain_cardinality, inputs.dc_cardinality, facts
    ):
        run.bump_skip(gap_class, count)


def run_analysis_pipeline(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    inputs: PipelineInputs,
    *,
    output_dir: Path | str,
    export_config: ExportConfig | None = None,
    progress_cb: ProgressCallback | None = None,
) -> PipelineResult:
    """Run the full offline analysis chain and export to BloodHound CE JSON.

    Executes the locked pass order (module docstring) into ``con``, invoking the
    previously-standalone ADCS-ESC and host-SAM passes, then exports the complete
    graph. Each artifact is hashed + registered for provenance before use.

    Inputs:
        con: an open canonical store (created/populated here).
        run: the :class:`IngestRun` accumulating provenance + counted gaps.
        inputs: the acquired artifacts (:class:`PipelineInputs`).
        output_dir: where the per-type BHCE files + zip + ledger are written.
        export_config: the :class:`ExportConfig` (version/methods); defaults applied.
        progress_cb: optional side-effect-only pass-boundary callback (doc 14 §4);
            invoked ``(pass_id, phase)`` at each pass start/done for a live
            loading bar. ``None`` (default) ⇒ behaviour byte-identical.

    Returns:
        A :class:`PipelineResult` with each pass's result + the export ledger.

    Failure modes:
        Propagates parser/store errors (``EseOpenError`` / ``duckdb.Error``).
        A malformed artifact within a pass degrades to that pass's counted gaps
        (surfaced on ``run`` + the export ledger), never a silent wrong answer.
    """
    analysis = _run_source_passes(con, run, inputs, progress_cb)
    identity = analysis.normalize_result.identity

    # M-MS1: record the source dimension row, reconcile the operator's case-shape
    # declaration against the derived domain (counting every mismatch), then
    # register one source_observation per canonical node/edge. Runs AFTER every
    # edge-producing pass so the observation list is complete; BEFORE export so
    # the ledger/manifest already reflect the source. This is the SINGLE-source
    # Phase-1 orchestration; the N-source analyze loop is
    # :func:`run_multi_source_pipeline`.
    _write_source_record(con, run, inputs, analysis)
    _reconcile_sources(con, run, inputs)
    write_source_observations(con, analysis.source_id)

    _notify(progress_cb, "export", "start")
    export_result = export_bloodhound(con, output_dir, export_config)
    _notify(progress_cb, "export", "done")

    _log.info(
        "pipeline complete: %d nodes, %d edges exported to %s",
        export_result.nodes_total,
        export_result.edges_exported,
        output_dir,
    )
    return PipelineResult(
        domain_id=identity.domain_id,
        domain_fqdn=identity.domain_fqdn,
        normalize_result=analysis.normalize_result,
        membership_result=analysis.membership_result,
        m5_result=analysis.m5_result,
        esc_result=analysis.esc_result,
        hostsam_results=analysis.hostsam_results,
        gpo_result=analysis.gpo_result,
        export_result=export_result,
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )


@dataclass(frozen=True)
class _SourceAnalysis:
    """The per-source analysis outcome (register -> normalize -> ... -> GPO).

    The shared core run by BOTH the single-source :func:`run_analysis_pipeline`
    and each iteration of :func:`run_multi_source_pipeline`. It stops BEFORE the
    source-row/observation write + reconcile + export, so the two orchestrators
    compose those steps differently (single-source writes + exports into the one
    store; the N-source loop writes per-source into an isolated store, appends,
    then reconciles + derives cross-domain edges + exports ONCE).
    """

    source_id: str
    ntds_sha256: str
    system_sha256: str | None
    normalize_result: NormalizeResult
    membership_result: MembershipResult
    m5_result: M5Result
    esc_result: AdcsEscResult | None
    hostsam_results: tuple[HostSamResult, ...]
    gpo_result: GpoProcessResult | None


def _run_source_passes(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    inputs: PipelineInputs,
    progress_cb: ProgressCallback | None,
) -> _SourceAnalysis:
    """Run ONE source's analysis passes (register -> normalize -> ... -> GPO).

    Hashes + registers every artifact for provenance, mints the deterministic
    per-source ``source_id``, then runs the locked pass order into ``con``. Does
    NOT write the ``source`` row, reconcile, or export (the caller composes those).
    Every pass stamps provenance + counted gaps onto ``run``.

    Inputs:
        con: the (per-source or single) canonical store this source writes into.
        run: the shared :class:`IngestRun` accumulating provenance + counted gaps.
        inputs: the acquired artifacts for THIS source.
        progress_cb: optional pass-boundary callback (side-effect-only).

    Returns:
        A :class:`_SourceAnalysis` with every pass result + the artifact hashes
        and minted ``source_id`` the source-row writer needs.

    Failure modes:
        Propagates parser/store errors; a malformed artifact within a pass
        degrades to that pass's counted gaps, never a silent wrong answer.
    """
    _notify(progress_cb, "register", "start")
    ntds_sha256 = _register(run, inputs.ntds_path, inputs.ntds_source_file)
    system_sha256: str | None = None
    if inputs.system_hive_path is not None:
        system_sha256 = _register(run, inputs.system_hive_path, "SYSTEM")
    for host in inputs.sam_hosts:
        _register(run, host.sam_path, host.source_file)
    # M-MS1: mint the deterministic per-source id (stable fn of case + label +
    # ntds bytes) BEFORE any pass, so every staged object/link is attributed.
    source_id = derive_source_id(run.case_id, inputs.dc_label, ntds_sha256)
    sysvol_sha256: str | None = None
    if inputs.sysvol_root is not None:
        sysvol_sha256 = _register_sysvol(run, inputs.sysvol_root)
    _notify(progress_cb, "register", "done")

    with open_ntds(inputs.ntds_path, run, source_file=inputs.ntds_source_file) as parsed:
        _notify(progress_cb, "normalize", "start")
        normalize_result = normalize(
            parsed, run, con, forest_id=inputs.forest_id, source_id=source_id
        )
        identity = normalize_result.identity
        scoping = (inputs.forest_id, identity.domain_id, identity.domain_fqdn)
        _notify(progress_cb, "normalize", "done")
        _notify(progress_cb, "membership", "start")
        membership_result = resolve_membership(
            con,
            run,
            parsed.schema,
            forest_id=inputs.forest_id,
            domain_id=identity.domain_id,
            domain_fqdn=identity.domain_fqdn,
        )
        _notify(progress_cb, "membership", "done")
        _notify(progress_cb, "edges", "start")
        m5_result = compute_edges(
            con,
            run,
            parsed.schema,
            forest_id=inputs.forest_id,
            domain_id=identity.domain_id,
            domain_fqdn=identity.domain_fqdn,
        )
        _notify(progress_cb, "edges", "done")

    _notify(progress_cb, "adcs_esc", "start")
    ca_host_facts = ABSENT_CA_HOST_FACTS
    ca_host_hive_errors = 0
    if inputs.ca_host_system_path is not None:
        _register(run, inputs.ca_host_system_path, "CAHOST/SYSTEM")
        if inputs.ca_host_software_path is not None:
            _register(run, inputs.ca_host_software_path, "CAHOST/SOFTWARE")
        ca_host_facts, ca_host_hive_errors = build_ca_host_facts(
            system_hive_path=inputs.ca_host_system_path,
            ingest_run_id=run.ingest_run_id,
            software_hive_path=inputs.ca_host_software_path,
            host_fqdn=inputs.ca_host_fqdn,
        )
    esc_result = run_adcs_esc(
        con,
        run,
        forest_id=inputs.forest_id,
        domain_id=identity.domain_id,
        domain_fqdn=identity.domain_fqdn,
        system_hive_path=inputs.system_hive_path,
        ca_host_facts=ca_host_facts,
        ca_host_hive_errors=ca_host_hive_errors,
    )
    # Persist the ESC11/ESC16/DCOM NODE-LEVEL findings the ESC pass computed but
    # (being node properties, not traversable edges) does not itself write — so the
    # dossier API can surface them per node. Additive table; an empty findings list
    # (the no-CA-host-hive path) writes nothing (not a gap). The ESC forensic logic
    # and the run_adcs_esc wiring above are untouched.
    persist_ca_node_findings(con, esc_result.ca_node_findings, scoping=scoping)
    _notify(progress_cb, "adcs_esc", "done")

    hostsam_results: list[HostSamResult] = []
    if inputs.sam_hosts:
        _notify(progress_cb, "host_sam", "start")
    for host in inputs.sam_hosts:
        hostsam_results.append(
            compute_host_admin_edges(
                con,
                sam_hive_path=host.sam_path,
                run=run,
                scoping=scoping,
                sam_source_file=host.source_file,
                system_hive_path=host.system_hive_path,
                computer_name=host.computer_name,
            )
        )
    if inputs.sam_hosts:
        _notify(progress_cb, "host_sam", "done")

    gpo_result: GpoProcessResult | None = None
    if inputs.sysvol_root is not None and sysvol_sha256 is not None:
        _notify(progress_cb, "gpo_sysvol", "start")
        gpo_result = process_sysvol(
            con,
            run,
            sysvol_root=inputs.sysvol_root,
            sysvol_image_sha256=sysvol_sha256,
            forest_id=inputs.forest_id,
            domain_id=identity.domain_id,
            domain_fqdn=identity.domain_fqdn,
        )
        _notify(progress_cb, "gpo_sysvol", "done")

    return _SourceAnalysis(
        source_id=source_id,
        ntds_sha256=ntds_sha256,
        system_sha256=system_sha256,
        normalize_result=normalize_result,
        membership_result=membership_result,
        m5_result=m5_result,
        esc_result=esc_result,
        hostsam_results=tuple(hostsam_results),
        gpo_result=gpo_result,
    )


def _write_source_record(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    inputs: PipelineInputs,
    analysis: _SourceAnalysis,
) -> None:
    """Write the ``source`` dimension row for one analyzed source (contract §2.2a).

    The derived ``domain_id``/``domain_fqdn`` (authoritative) come from the
    source's normalize identity; ``declared_domain`` is the operator label kept
    for display. Shared by the single-source and N-source orchestrators.
    """
    identity = analysis.normalize_result.identity
    write_source_row(
        con,
        SourceRecord(
            source_id=analysis.source_id,
            case_id=run.case_id,
            dc_label=inputs.dc_label,
            forest_id=inputs.forest_id,
            domain_id=identity.domain_id,
            domain_fqdn=identity.domain_fqdn,
            declared_domain=inputs.declared_domain,
            ntds_image_sha256=analysis.ntds_sha256,
            system_image_sha256=analysis.system_sha256,
            ingest_run_id=run.ingest_run_id,
            ingested_at=datetime.now(UTC),
        ),
    )


@dataclass(frozen=True)
class MultiSourcePipelineResult:
    """The outcome of an N-source multi-domain analyze + export (counts only).

    Attributes:
        source_count: distinct sources ingested into the combined store.
        domain_count: distinct derived ``domain_id``s present in the combined store.
        canonical_collisions: frozen-canonical rows a later (same-domain) source
            could NOT write because its ``node_id``/``edge_id`` already existed
            (first-writer-wins). Non-zero only on a same-domain multi-DC overlap;
            surfaced as :data:`GAP_MULTI_DC_CANONICAL_MERGE_PENDING` (M-MS4 work).
        cross_domain_result: the SINGLE cross-domain derivation outcome (M-MS3).
        export_result: the BloodHound export ledger over the combined store.
        per_source: each source's :class:`PipelineResult`-equivalent identity, in
            deterministic ingest order.
        coverage_counts/skip_counts: the accumulated run counters snapshot.
    """

    source_count: int
    domain_count: int
    canonical_collisions: int
    cross_domain_result: CrossDomainResult
    export_result: ExportResult
    per_source: tuple[tuple[str, str | None, str | None], ...]
    coverage_counts: Mapping[str, int] = field(default_factory=dict)
    skip_counts: Mapping[str, int] = field(default_factory=dict)


def _source_sort_key(inputs: PipelineInputs) -> tuple[str, str]:
    """Deterministic ingest order key: ``(dc_label, ntds_source_file)``.

    ``dc_label`` is enforced per-case-unique at upload (contract §1.3), so it is a
    total order on a case's sources; ``ntds_source_file`` is a stable secondary
    tiebreak. Sorting here makes the combined store identical regardless of upload
    order (the determinism non-negotiable) and makes first-writer-wins
    (``INSERT OR IGNORE``) pick the same winner every run.
    """
    return (inputs.dc_label, inputs.ntds_source_file)


def run_multi_source_pipeline(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    sources: Sequence[PipelineInputs],
    *,
    output_dir: Path | str,
    export_config: ExportConfig | None = None,
    progress_cb: ProgressCallback | None = None,
    scratch_dir: Path | str | None = None,
) -> MultiSourcePipelineResult:
    """Ingest N tagged sources into ONE store, then derive cross-domain edges ONCE.

    The N-source multi-domain analyze loop (multi-source contract §3.5, §4). Each
    source is analyzed in ISOLATION (its own fresh per-source store, the exact
    single-source pass order — so there is zero cross-source bleed and the edge
    engine never re-derives over a merged object set, §3.5), then APPENDED into the
    combined ``con``:

    * **Multi-domain is safe by construction** — distinct domains have forest
      -scoped ``objectGUID`` + domain-scoped well-known SIDs ⇒ disjoint
      ``node_id``s ⇒ a clean append with no canonical PK collision.
    * **Same-domain multi-DC (scope-OUT, M-MS4)** — a second source of the SAME
      domain collides on the single-PK canonical tables. First-writer-wins is
      applied (the already-written canonical row is NOT overwritten), the source's
      own ``source`` row + per-source staging + ``source_observation`` ARE written,
      and the colliding rows are COUNTED as
      :data:`GAP_MULTI_DC_CANONICAL_MERGE_PENDING` — no crash, no silent loss, a
      clear honest boundary (the full per-DC canonical merge awaits Phase 2).
    * **Cross-domain edges derived ONCE** — after every source is appended, the
      per-source M5 trust/sIDHistory stub edges are purged and
      :func:`derive_cross_domain_edges` runs exactly once over the combined store
      (the single resolver), so a cross-domain fact is never both a stub and a
      resolved edge.

    Ingest order is deterministic (:func:`_source_sort_key`), so the combined store
    is identical regardless of upload order.

    Inputs:
        con: an open, writable combined canonical store (tables are created here).
        run: the shared :class:`IngestRun` accumulating provenance + counted gaps.
        sources: the per-source :class:`PipelineInputs` (≥1). All MUST share the
            case-shape axes (same case); sources[0] drives reconciliation gating.
        output_dir: where the combined BHCE export is written.
        export_config: the :class:`ExportConfig`; defaults applied.
        progress_cb: optional pass-boundary callback (fires per source; the live
            bar is wall-clock observability, not part of determinism).
        scratch_dir: where the transient per-source stores are created (a private
            temp dir is made when ``None``). ALWAYS fully removed on return — it is
            owned scratch, so the case workspace is never littered.

    Returns:
        A :class:`MultiSourcePipelineResult` (counts only; never secrets).

    Failure modes:
        Raises ``ValueError`` if ``sources`` is empty. Propagates parser/store
        errors; a malformed artifact degrades to counted gaps, never a crash.
    """
    if not sources:
        raise ValueError("run_multi_source_pipeline requires at least one source")

    create_canonical_tables(con)
    create_edge_tables(con)
    # M-MS4a: provision the divergence ledger on the combined (multi-source) store
    # so the opt-in merge fold (M-MS4b) has somewhere to record disagreements. The
    # single-source path never calls this, so its store is byte-for-byte unchanged.
    create_divergence_table(con)

    # Deterministic ingest order (independent of upload order) + de-dup by the
    # minted source_id so re-listing the identical artifact+label is idempotent.
    ordered = sorted(sources, key=_source_sort_key)

    # The per-source stores are transient scratch, fully owned + cleaned up here
    # (so the case workspace is never littered with per-source DuckDB files).
    scratch_root = (
        Path(scratch_dir)
        if scratch_dir is not None
        else Path(tempfile.mkdtemp(prefix="wraith-ms-"))
    )
    scratch_root.mkdir(parents=True, exist_ok=True)

    collisions = 0
    seen_source_ids: set[str] = set()
    per_source: list[tuple[str, str | None, str | None]] = []
    try:
        for idx, source_inputs in enumerate(ordered):
            src_path = scratch_root / f"src_{idx:04d}.duckdb"
            src_con = open_canonical_store(src_path)
            try:
                analysis = _run_source_passes(src_con, run, source_inputs, progress_cb)
                if analysis.source_id in seen_source_ids:
                    # Idempotent: the identical artifact under the same label was
                    # already ingested — skip the duplicate append (no double rows),
                    # but COUNT the skip (counted-gap-on-every-degraded-branch).
                    run.bump_skip(GAP_DUPLICATE_SOURCE_SKIPPED, 1)
                    continue
                seen_source_ids.add(analysis.source_id)
                identity = analysis.normalize_result.identity
                _write_source_record(src_con, run, source_inputs, analysis)
                write_source_observations(src_con, analysis.source_id)
                # M-MS4a: arm tier-1 of the merge ladder — capture each node's raw
                # replPropertyMetaData bytes into source_observation.attr_metadata_blob
                # (resolve-by-schema; counted gap when absent). Runs in the per-source
                # store BEFORE append so _append_source_store copies the populated blob.
                populate_attr_metadata(src_con, analysis.source_id, run)
                per_source.append((analysis.source_id, identity.domain_id, identity.domain_fqdn))
            finally:
                src_con.close()
            collisions += _append_source_store(con, src_path, run)

        if collisions:
            # Honest counted state for the same-domain multi-DC overlap (M-MS4).
            run.bump_skip(GAP_MULTI_DC_CANONICAL_MERGE_PENDING, collisions)

        # Reconcile the case-shape declaration over ALL ingested source rows now
        # that the combined store holds them (counts multi-domain / same-domain
        # mismatches once; sources share the case-shape axes -> use the first).
        _reconcile_sources(con, run, ordered[0])

        # The SINGLE cross-domain resolver: purge the per-source M5 trust/sIDHistory
        # stub edges, then derive once over the combined (now multi-domain) store.
        _purge_cross_domain_edges(con)
        cross_domain_result = derive_cross_domain_edges(con, run)

        domain_ids = {d for _, d, _ in per_source if d is not None}
        run.bump_coverage(COV_SOURCES_INGESTED, len(per_source))
        run.bump_coverage(COV_DOMAINS_INGESTED, len(domain_ids))

        _notify(progress_cb, "export", "start")
        export_result = export_bloodhound(con, output_dir, export_config)
        _notify(progress_cb, "export", "done")
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)

    _log.info(
        "multi-source pipeline complete: %d sources, %d domains, %d canonical "
        "collisions, %d nodes, %d edges exported to %s",
        len(per_source),
        len(domain_ids),
        collisions,
        export_result.nodes_total,
        export_result.edges_exported,
        output_dir,
    )
    return MultiSourcePipelineResult(
        source_count=len(per_source),
        domain_count=len(domain_ids),
        canonical_collisions=collisions,
        cross_domain_result=cross_domain_result,
        export_result=export_result,
        per_source=tuple(per_source),
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )


def _append_source_store(
    con: duckdb.DuckDBPyConnection,
    src_path: Path,
    run: IngestRun | None = None,
) -> int:
    """Append one per-source store's rows into the combined store (first-writer-wins).

    ATTACHes the per-source store read-only and copies every table in. The frozen
    canonical tables + ``edge`` are copied ``INSERT OR IGNORE`` (so a same-domain
    second source's colliding ``node_id``/``edge_id`` does NOT overwrite the
    already-written row and never crashes); the derived ``effective_membership``
    closure likewise collides first-writer-wins and its dropped rows are COUNTED
    (``GAP_MULTI_DC_EFFECTIVE_MEMBERSHIP_PENDING``) when ``run`` is supplied; the
    per-source ``staging_object`` / ``source_observation`` are keyed by
    ``(..., source_id)`` so both DCs' copies coexist; ``staging_link`` is keyless
    (plain append); the ``source`` row is a plain insert (distinct per source). Row
    order is fixed by an ``ORDER BY`` on each table's key so the combined store is
    byte-deterministic.

    Inputs:
        con: the combined store (its tables already created).
        src_path: the closed per-source store file to ATTACH + copy from.
        run: the :class:`IngestRun` to count the derived-table (effective_membership)
            collisions on; ``None`` (standalone/test callers) skips that counter
            but the returned frozen-canonical count is identical either way.

    Returns:
        The number of FROZEN-canonical rows this source could not write because
        the ``node_id``/``edge_id`` already existed (same-domain multi-DC overlap);
        ``0`` for a genuinely distinct domain. (The derived ``effective_membership``
        collisions are NOT in this tally — they are counted on ``run`` separately.)

    Failure modes:
        Raises ``duckdb.Error`` on an ATTACH/copy failure (e.g. a dc_label clash on
        the ``source`` UNIQUE constraint — an upstream invariant the upload layer
        enforces, surfaced loudly rather than silently dropped).
    """
    alias = "ms_src"
    con.execute(f"ATTACH '{src_path.as_posix()}' AS {alias} (READ_ONLY)")
    try:
        collisions = 0
        for table, pk in _FROZEN_CANONICAL_COPY:
            before = _count(con, table)
            src_n = _count_attached(con, alias, table)
            con.execute(
                f"INSERT OR IGNORE INTO {table} "  # noqa: S608 - internal literals
                f"SELECT * FROM {alias}.{table} ORDER BY {pk}"
            )
            inserted = _count(con, table) - before
            collisions += src_n - inserted
        eff_before = _count(con, "effective_membership")
        eff_src = _count_attached(con, alias, "effective_membership")
        con.execute(
            f"INSERT OR IGNORE INTO effective_membership "  # noqa: S608 - literal
            f"SELECT * FROM {alias}.effective_membership "
            f"ORDER BY member_node_id, group_node_id"
        )
        eff_collisions = eff_src - (_count(con, "effective_membership") - eff_before)
        if run is not None and eff_collisions:
            run.bump_skip(GAP_MULTI_DC_EFFECTIVE_MEMBERSHIP_PENDING, eff_collisions)
        con.execute(
            f"INSERT OR IGNORE INTO staging_object "  # noqa: S608 - literal
            f"SELECT * FROM {alias}.staging_object ORDER BY node_id, source_id"
        )
        con.execute(
            f"INSERT INTO staging_link "  # noqa: S608 - literal
            f"SELECT * FROM {alias}.staging_link "
            f"ORDER BY link_base, source_node_id, target_node_id"
        )
        con.execute(f"INSERT INTO source SELECT * FROM {alias}.source")  # noqa: S608
        con.execute(
            f"INSERT OR IGNORE INTO source_observation "  # noqa: S608 - literal
            f"SELECT * FROM {alias}.source_observation "
            f"ORDER BY obj_kind, obj_id, source_id"
        )
    finally:
        con.execute(f"DETACH {alias}")
    return collisions


def _purge_cross_domain_edges(con: duckdb.DuckDBPyConnection) -> None:
    """Remove the per-source M5 trust/sIDHistory stub edges before the resolver runs.

    The per-source :func:`compute_edges` pass emits trust / sIDHistory edges keyed
    to STUB far-endpoints (the partner domain is absent from that one source's
    store). Over the combined multi-domain store those partners now exist, so
    :func:`derive_cross_domain_edges` re-derives the SAME facts with RESOLVED
    endpoints. Purging the stub versions first (and their ``source_observation``
    rows) guarantees a cross-domain fact is represented exactly once — the "don't
    emit both a stub and a resolved edge for one fact" rule (task §3). Intra-domain
    ACL/membership/DCSync edges are untouched (different kinds).
    """
    placeholders = ",".join("?" * len(_CROSS_DOMAIN_EDGE_KINDS))
    kinds = list(_CROSS_DOMAIN_EDGE_KINDS)
    con.execute(
        f"DELETE FROM source_observation WHERE obj_kind = 'edge' AND obj_id IN "  # noqa: S608
        f"(SELECT edge_id FROM edge WHERE kind IN ({placeholders}))",
        kinds,
    )
    con.execute(
        f"DELETE FROM edge WHERE kind IN ({placeholders})",  # noqa: S608 - bound params
        kinds,
    )


def _count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    """Return ``COUNT(*)`` of a combined-store table (internal literal name)."""
    row = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608 - literal
    return int(row[0]) if row is not None else 0


def _count_attached(con: duckdb.DuckDBPyConnection, alias: str, table: str) -> int:
    """Return ``COUNT(*)`` of an ATTACHed per-source table (internal literals)."""
    row = con.execute(f"SELECT COUNT(*) FROM {alias}.{table}").fetchone()  # noqa: S608
    return int(row[0]) if row is not None else 0


def sha256_file_or_dir(path: Path | str) -> str:
    """Return a stable SHA-256 for a SYSVOL artifact (file hash, or dir digest).

    A SYSVOL artifact is usually a directory tree; ``process_sysvol`` only needs
    a stable per-artifact hash for its provenance. For a directory we hash the
    sorted ``(relpath, size)`` manifest (deterministic, offline, no file reads of
    every byte); for a file we hash its bytes. Never raises on an empty tree.
    """
    p = Path(path)
    if p.is_file():
        return sha256_file(p)
    import hashlib

    digest = hashlib.sha256()
    entries: list[tuple[str, int]] = []
    for child in sorted(p.rglob("*")):
        if child.is_file():
            rel = child.relative_to(p).as_posix()
            entries.append((rel, child.stat().st_size))
    for rel, size in sorted(entries):
        digest.update(f"{rel}\x1f{size}\n".encode())
    return digest.hexdigest()


__all__ = [
    "COV_DOMAINS_INGESTED",
    "COV_SOURCES_INGESTED",
    "GAP_DUPLICATE_SOURCE_SKIPPED",
    "GAP_MULTI_DC_CANONICAL_MERGE_PENDING",
    "GAP_MULTI_DC_EFFECTIVE_MEMBERSHIP_PENDING",
    "MultiSourcePipelineResult",
    "PipelineInputs",
    "PipelineResult",
    "SamHostInput",
    "run_analysis_pipeline",
    "run_multi_source_pipeline",
    "sha256_file_or_dir",
]
