"""The ``IngestRun`` context object — single source of truth for a run.

Both the embedded provenance struct (§2.3) carried on every downstream row and
the provenance-ledger row (§2.4) are produced from this one in-memory object,
so ``ingest_run_id`` / ``image_sha256`` / ``source_file`` can never diverge
(research Item 5). It also accumulates coverage/skip counts so a malformed
input becomes a counted, logged gap rather than a silent omission.
"""

from __future__ import annotations

import platform
import sys
from collections import Counter
from datetime import UTC, datetime
from uuid import UUID, uuid4

from wraith import SCHEMA_VERSION, WRAITH_VERSION
from wraith.case.manifest import (
    ArtifactInput,
    HostEnvironment,
    RunManifest,
    RunOutputs,
    Timings,
)
from wraith.provenance.ledger import LedgerRow
from wraith.provenance.models import ProvenanceStruct


class IngestRun:
    """Mutable accumulator for one ingest run; emits manifest + ledger + prov.

    Lifecycle: construct at the start of an ingest, register each artifact via
    :meth:`add_artifact`, mint provenance via :meth:`provenance_for`, bump
    counters as records are parsed/skipped, then emit the manifest and ledger
    rows at the end. The object itself is the authority for shared identifiers.
    """

    def __init__(
        self,
        case_id: str,
        operator: str,
        *,
        ingest_run_id: UUID | None = None,
        tool_versions: dict[str, str] | None = None,
        parameters: dict[str, object] | None = None,
        started_at: datetime | None = None,
    ) -> None:
        """Start a run context.

        Inputs:
            case_id: owning case.
            operator: responsible operator (from ``case.json``).
            ingest_run_id: override the run id (tests only); else a fresh UUID4.
            tool_versions: ``{tool: version}`` recorded in manifest + ledger.
            parameters: reproducibility inputs (CLI flags, options).
            started_at: run start (wall-clock); defaults to now (UTC).
        """
        self.case_id = case_id
        self.operator = operator
        self.ingest_run_id: UUID = ingest_run_id or uuid4()
        self.tool_versions: dict[str, str] = dict(tool_versions or {})
        self.parameters: dict[str, object] = dict(parameters or {})
        self.started_at: datetime = started_at or datetime.now(UTC)
        self._inputs: list[ArtifactInput] = []
        self._image_hashes: dict[str, str] = {}
        self._acquired_at: dict[str, datetime | None] = {}
        self._coverage: Counter[str] = Counter()
        self._skips: Counter[str] = Counter()

    def add_artifact(self, artifact: ArtifactInput) -> None:
        """Register an acquired artifact (its hash becomes the prov source).

        Inputs:
            artifact: the ``ArtifactInput`` to record.

        Returns:
            None.

        Failure modes:
            Raises ``ValueError`` if a different ``source_file`` with a
            conflicting hash is registered twice (ambiguous provenance).
        """
        existing = self._image_hashes.get(artifact.source_file)
        if existing is not None and existing != artifact.image_sha256:
            raise ValueError(f"conflicting image_sha256 for source_file {artifact.source_file!r}")
        self._inputs.append(artifact)
        self._image_hashes[artifact.source_file] = artifact.image_sha256
        self._acquired_at[artifact.source_file] = artifact.acquired_at

    def provenance_for(
        self,
        source_file: str,
        *,
        source_object_id: str | None = None,
        directory_timestamp: datetime | None = None,
    ) -> ProvenanceStruct:
        """Mint an embedded provenance struct for a record from ``source_file``.

        Inputs:
            source_file: the immediate artifact that produced the record; must
                have been registered via :meth:`add_artifact`.
            source_object_id: the exact record identity (DNT/GUID/sd_id/DN/path).
            directory_timestamp: the source object's ``whenChanged``/``whenCreated``.

        Returns:
            A ``ProvenanceStruct`` carrying this run's id and the artifact hash.

        Failure modes:
            Raises ``KeyError`` if ``source_file`` was never registered (a fact
            must not be produced without its provenance).
        """
        image_sha256 = self._image_hashes.get(source_file)
        if image_sha256 is None:
            raise KeyError(f"no registered artifact for source_file {source_file!r}")
        return ProvenanceStruct(
            source_file=source_file,
            image_sha256=image_sha256,
            source_object_id=source_object_id,
            directory_timestamp=directory_timestamp,
            ingest_run_id=self.ingest_run_id,
        )

    def bump_coverage(self, key: str, count: int = 1) -> None:
        """Increment a coverage counter (e.g. ``objects_parsed``)."""
        self._coverage[key] += count

    def bump_skip(self, key: str, count: int = 1) -> None:
        """Increment a skip counter (e.g. ``malformed_records``) — a gap."""
        self._skips[key] += count

    @property
    def coverage_counts(self) -> dict[str, int]:
        """Current coverage counters as a plain dict."""
        return dict(self._coverage)

    @property
    def skip_counts(self) -> dict[str, int]:
        """Current skip counters as a plain dict (surfaced, never silent)."""
        return dict(self._skips)

    @property
    def inputs(self) -> list[ArtifactInput]:
        """The registered artifacts (copy — the internal list is private)."""
        return list(self._inputs)

    def to_ledger_rows(self, ingested_at: datetime | None = None) -> list[LedgerRow]:
        """Build one ledger row per registered artifact (§2.4).

        Inputs:
            ingested_at: ledger write time; defaults to now (UTC).

        Returns:
            A deterministically ordered list of ``LedgerRow`` (by source_file).

        Failure modes:
            None (validation happens in ``LedgerRow``).
        """
        when = ingested_at or datetime.now(UTC)
        rows = [
            LedgerRow(
                ingest_run_id=self.ingest_run_id,
                source_file=art.source_file,
                image_sha256=art.image_sha256,
                acquired_at=art.acquired_at,
                tool_versions=self.tool_versions,
                parameters=self.parameters,
                db_state=art.db_state,
                coverage_counts=self.coverage_counts,
                skip_counts=self.skip_counts,
                ingested_at=when,
            )
            for art in self._inputs
        ]
        return sorted(rows, key=lambda r: r.source_file)

    def to_manifest(
        self,
        *,
        finished_at: datetime | None = None,
        per_phase: dict[str, float] | None = None,
        outputs: RunOutputs | None = None,
        container_image_id: str | None = None,
    ) -> RunManifest:
        """Build the immutable run manifest from the accumulated state.

        Inputs:
            finished_at: run end (wall-clock); defaults to now (UTC).
            per_phase: optional per-phase durations in seconds.
            outputs: optional produced-output pointers.
            container_image_id: optional container image id for host metadata.

        Returns:
            A fully-populated ``RunManifest``.

        Failure modes:
            Raises ``pydantic.ValidationError`` if accumulated state is invalid.
        """
        end = finished_at or datetime.now(UTC)
        duration = max((end - self.started_at).total_seconds(), 0.0)
        timings = Timings(
            started_at=self.started_at,
            finished_at=end,
            duration_s=duration,
            per_phase=dict(per_phase or {}),
        )
        host = HostEnvironment(
            python_version=sys.version.split()[0],
            platform=platform.platform(),
            container_image_id=container_image_id,
        )
        return RunManifest(
            ingest_run_id=self.ingest_run_id,
            case_id=self.case_id,
            wraith_version=WRAITH_VERSION,
            schema_version=SCHEMA_VERSION,
            tool_versions=self.tool_versions,
            inputs=self.inputs,
            parameters=self.parameters,
            timings=timings,
            coverage_counts=self.coverage_counts,
            skip_counts=self.skip_counts,
            operator=self.operator,
            host_environment=host,
            outputs=outputs or RunOutputs(),
        )
