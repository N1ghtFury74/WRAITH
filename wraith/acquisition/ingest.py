"""Artifact ingest: path-safe copy/reference + integrity + provenance wiring.

Default mode copies the input into the case ``artifacts/`` dir for a
self-contained evidence package; reference-by-path mode avoids copying multi-GB
inputs. The SHA-256 is recorded either way (research Item 2/3). Archives are
hashed as the container BEFORE extraction and each extracted file is hashed
AFTER (the hash-boundary rule). Every registered artifact flows into the
``IngestRun`` so provenance and the ledger derive from one source of truth.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from wraith.acquisition.extract import extract_archive, is_archive
from wraith.acquisition.hashing import sha256_file
from wraith.acquisition.paths import PathSafetyError, ensure_existing_file, resolve_within
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.case.workspace import CaseWorkspace


class IngestMode(StrEnum):
    """How an input artifact is brought into the case."""

    COPY = "copy"
    REFERENCE = "reference"


def ingest_file(
    workspace: CaseWorkspace,
    run: IngestRun,
    source_path: Path | str,
    *,
    mode: IngestMode = IngestMode.COPY,
    logical_name: str | None = None,
    acquired_at: datetime | None = None,
    extract: bool = False,
) -> list[ArtifactInput]:
    """Ingest one artifact (optionally extracting an archive) into the case.

    Inputs:
        workspace: the target case workspace.
        run: the active ingest run (records hashes + provenance source).
        source_path: the input file (validated to exist and be a regular file).
        mode: COPY (into ``artifacts/``) or REFERENCE (record source path).
        logical_name: override the recorded ``source_file`` name; defaults to
            the source basename.
        acquired_at: acquisition timestamp to record, if known.
        extract: if True and the input is a recognized archive, extract it
            safely and register each inner file as its own artifact.

    Returns:
        The list of ``ArtifactInput`` rows registered (the container first when
        extracting, then each inner file).

    Failure modes:
        Raises ``PathSafetyError`` if the source is unsafe or a copy target
        escapes ``artifacts/``; ``FileExistsError`` if a copy target already
        exists (artifacts are write-once); archive errors propagate.
    """
    src = ensure_existing_file(source_path)
    name = logical_name or src.name
    container_sha256 = sha256_file(src)

    if mode is IngestMode.COPY:
        target = resolve_within(workspace.artifacts_dir, name)
        if target.exists():
            raise FileExistsError(f"artifact already ingested: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        recorded_path = target
    else:
        recorded_path = src

    container = ArtifactInput(
        source_file=name,
        abs_path_or_ref=str(recorded_path),
        size_bytes=src.stat().st_size,
        image_sha256=container_sha256,
        acquired_at=acquired_at,
        mode=mode.value,
    )
    run.add_artifact(container)
    run.bump_coverage("artifacts_ingested")
    registered: list[ArtifactInput] = [container]

    if extract and is_archive(recorded_path):
        registered.extend(_ingest_archive_members(workspace, run, recorded_path, name, acquired_at))
    return registered


def _ingest_archive_members(
    workspace: CaseWorkspace,
    run: IngestRun,
    container_path: Path,
    container_name: str,
    acquired_at: datetime | None,
) -> list[ArtifactInput]:
    """Safely extract an archive and register each inner file as an artifact."""
    dest = resolve_within(workspace.artifacts_dir, f"{container_name}.extracted")
    result = extract_archive(container_path, dest)
    members: list[ArtifactInput] = []
    for extracted in result.files:
        # Guard: the extractor already contains members, re-assert containment.
        if not extracted.abs_path.resolve().is_relative_to(dest.resolve()):
            raise PathSafetyError(f"extracted member escaped dest: {extracted.abs_path}")
        inner_name = f"{container_name}!{extracted.inner_path}"
        member = ArtifactInput(
            source_file=inner_name,
            abs_path_or_ref=str(extracted.abs_path),
            size_bytes=extracted.abs_path.stat().st_size,
            image_sha256=extracted.image_sha256,
            acquired_at=acquired_at,
            mode=IngestMode.COPY.value,
            container_source_file=container_name,
        )
        run.add_artifact(member)
        run.bump_coverage("artifacts_extracted")
        members.append(member)
    if result.skipped:
        run.bump_skip("archive_members_skipped", len(result.skipped))
    return members
