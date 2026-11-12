"""Run-manifest data shapes and (de)serialization (NFR-06; research Item 2).

One immutable manifest file per ingest run (``manifest/run-<id>.json``) plus a
``latest.json`` pointer, giving an append-only, auditable re-ingest history. The
field set mirrors research Item 2 and binds to the §2.4 ledger. Wall-clock
values live here (and in the ledger) only — never in canonical rows.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from wraith.common.determinism import canonical_json
from wraith.common.validators import validate_sha256_hex


class ArtifactInput(BaseModel):
    """One acquired input artifact as recorded in the manifest.

    Fields:
        source_file: the logical artifact name (e.g. ``ntds.dit``) — matches the
            provenance struct ``source_file``.
        abs_path_or_ref: absolute path inside ``artifacts/`` (copy mode) or the
            referenced source path (reference mode).
        size_bytes: file size in bytes.
        image_sha256: SHA-256 of this immediate artifact (FR-02).
        acquired_at: acquisition timestamp, if known.
        db_state: reserved for Module 2 (clean/dirty); ``None`` in v1.
        mode: ``"copy"`` or ``"reference"``.
        container_source_file: for an extracted member, the container archive's
            ``source_file`` (the hash-boundary record); else ``None``.

    Failure modes:
        Raises ``pydantic.ValidationError`` on a malformed/short ``image_sha256``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_file: str
    abs_path_or_ref: str
    size_bytes: int
    image_sha256: str
    acquired_at: datetime | None = None
    db_state: str | None = None
    mode: str = "copy"
    container_source_file: str | None = None

    @field_validator("image_sha256")
    @classmethod
    def _image_sha256_wellformed(cls, value: str) -> str:
        return validate_sha256_hex(value)


class Timings(BaseModel):
    """Wall-clock timing block (non-deterministic; manifest-only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    started_at: datetime
    finished_at: datetime | None = None
    duration_s: float | None = None
    per_phase: dict[str, float] = Field(default_factory=dict)


class HostEnvironment(BaseModel):
    """Host/environment metadata (non-deterministic; manifest-only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    python_version: str
    platform: str
    container_image_id: str | None = None


class RunOutputs(BaseModel):
    """Pointers to what the run produced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    canonical_db_path: str | None = None
    export_manifest_refs: list[str] = Field(default_factory=list)


class RunManifest(BaseModel):
    """The complete, immutable record of one ingest run (research Item 2).

    Failure modes:
        Raises ``pydantic.ValidationError`` if a required field is missing or an
        input artifact is malformed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ingest_run_id: UUID
    case_id: str
    wraith_version: str
    schema_version: str
    tool_versions: dict[str, str] = Field(default_factory=dict)
    inputs: list[ArtifactInput] = Field(default_factory=list)
    parameters: dict[str, object] = Field(default_factory=dict)
    timings: Timings
    coverage_counts: dict[str, int] = Field(default_factory=dict)
    skip_counts: dict[str, int] = Field(default_factory=dict)
    operator: str
    host_environment: HostEnvironment
    outputs: RunOutputs = Field(default_factory=RunOutputs)


def manifest_filename(ingest_run_id: UUID) -> str:
    """Return the per-run manifest filename ``run-<ingest_run_id>.json``."""
    return f"run-{ingest_run_id}.json"


def write_run_manifest(manifest_dir: Path | str, manifest: RunManifest) -> Path:
    """Write the immutable per-run manifest and update ``latest.json``.

    Inputs:
        manifest_dir: the case ``manifest/`` directory (must exist).
        manifest: the run manifest to persist.

    Returns:
        The path of the written ``run-<id>.json`` file.

    Failure modes:
        Raises ``FileExistsError`` if a manifest for this run id already exists
        (runs are immutable — re-ingest uses a new id); ``OSError`` on write
        failure.
    """
    directory = Path(manifest_dir)
    run_path = directory / manifest_filename(manifest.ingest_run_id)
    if run_path.exists():
        raise FileExistsError(f"run manifest already exists (immutable): {run_path}")
    text = canonical_json(manifest.model_dump(mode="json"))
    run_path.write_text(text, encoding="utf-8", newline="\n")
    (directory / "latest.json").write_text(text, encoding="utf-8", newline="\n")
    return run_path


def load_run_manifest(path: Path | str) -> RunManifest:
    """Load and validate a run manifest from disk.

    Inputs:
        path: the manifest file path.

    Returns:
        A validated ``RunManifest``.

    Failure modes:
        Raises ``FileNotFoundError`` if absent; ``pydantic.ValidationError`` or
        ``json.JSONDecodeError`` if corrupt.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return RunManifest.model_validate(data)
