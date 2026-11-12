"""Writable case/ingest + coverage router (doc 14 §3) — M7 operate-from-UI backend.

The ONLY writable surface in the M7 API. It lets an operator run the entire
WRAITH workflow from the web UI with zero documentation:

    create case -> upload artifacts -> coverage preview -> analyze (streamed %) ->
    served read-only via the per-case :class:`~wraith.api.registry.CaseReaderRegistry`.

Design (doc 14 §3 / §8a):

* Uploads are untrusted (§5): the client filename is discarded, the stored name is
  derived from the validated ``kind`` (+ slugged ``host_label``), everything is
  confined with ``resolve_within`` under ``artifacts/``, streamed to a temp file
  in bounded chunks with a per-kind size cap enforced WHILE streaming, content-magic
  sniffed, hashed, atomically renamed, and SYSVOL zips are extracted with a
  zip-slip + resource-cap guard. Nothing under ``artifacts/`` is ever executed.
* Analyze runs on a dedicated worker THREAD (not FastAPI ``BackgroundTasks``, §8a
  decision 2) so the async WS progress channel is never blocked; one active run per
  case (a lock; 409 if busy). The worker is wrapped so any exception becomes
  ``state="failed"`` + a typed ``error`` (class + message) — never a crashed server,
  never a stack trace or secret in a response/log.
* Every optional-artifact-absent branch bumps its exact ``gap_class`` (doc 14 §1.2)
  via ``IngestRun.bump_skip`` so coverage loss is counted on the ledger, never silent.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import stat
import threading
import uuid
import zipfile
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from wraith import WRAITH_VERSION
from wraith.acquisition.paths import PathSafetyError, resolve_within, validate_case_id
from wraith.api.merge import (
    merge_result_to_report,
    merge_run_id,
    validate_sources,
)
from wraith.api.models import MergeReportOut, MergeRequest
from wraith.api.registry import CaseReaderRegistry
from wraith.case.case import CaseConfig, load_case_config, write_case_config
from wraith.case.catalog import (
    CATALOG,
    ESE_MAGIC,
    ESE_MAGIC_OFFSET,
    MAGIC_SNIFF,
    MAX_COMPANION_SYSTEM_BYTES,
    MAX_UPLOAD_BYTES,
    REGF_MAGIC,
    SYSVOL_MAX_MEMBERS,
    SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES,
    VALID_KIND_IDS,
    ZIP_MAGICS,
    ArtifactKind,
    SniffKind,
    artifact_kind,
)
from wraith.case.coverage import CoverageReport, compute_coverage, coverage_gap_bumps
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput, RunOutputs, write_run_manifest
from wraith.case.progress_model import PASS_SPECS, active_pass_ids, active_total, percent
from wraith.case.workspace import CaseWorkspace, create_workspace, load_workspace
from wraith.common.determinism import canonical_json
from wraith.export.bloodhound import ExportConfig
from wraith.export.pipeline import (
    PipelineInputs,
    SamHostInput,
    run_analysis_pipeline,
    run_multi_source_pipeline,
)
from wraith.merge.fold import merge_fold
from wraith.model.source import DcCardinality, DomainCardinality
from wraith.model.store import (
    CANONICAL_DB_FILENAME,
    create_divergence_table,
    open_canonical_store,
)

_log = logging.getLogger(__name__)

#: Bounded read granularity for streaming uploads/extraction (1 MiB).
_CHUNK: int = 1024 * 1024
#: Transient upload staging dir name under ``artifacts/`` (never read downstream).
_INCOMING: str = ".incoming"
#: Upload index filename under ``artifacts/`` (kind -> registered uploads).
_UPLOAD_INDEX: str = "_uploads.json"
#: Extracted SYSVOL directory name under ``artifacts/``.
_SYSVOL_DIRNAME: str = "sysvol"
#: WS progress poll interval (seconds). Intermediate timing is wall-clock and NOT
#: part of the determinism guarantee (doc 14 §4); only the final state is.
_POLL_INTERVAL: float = 0.25
#: CaseConfig has no dedicated forest_id field (gated M1 model, extra="forbid"),
#: so the create-time forest_id is persisted under this reserved forest_id_map key
#: and read back at analyze. (Flagged: contract gap — see module handback.)
_FOREST_ID_KEY: str = "_default_forest"
_DEFAULT_FOREST_ID: str = "forest-default"
#: The ``dc_label`` applied to an untagged primary ``ntds_dit`` upload so the
#: single-source path (operator never set a label) still writes a well-formed,
#: per-case-unique ``source`` row (M-MS1). Multi-source operators set their own.
_DEFAULT_DC_LABEL: str = "primary-dc"
#: Max length for the untrusted per-source tag fields (``dc_label`` / ``domain`` /
#: ``source_forest_id``). A DC label / domain FQDN is never this long; the bound
#: just stops an unbounded string from the (untrusted) upload form reaching the
#: index / ``source`` row.
_MAX_TAG_LEN: int = 256


# --------------------------------------------------------------------------- #
#  Typed error for untrusted-upload rejections (doc 14 §5 / §7)               #
# --------------------------------------------------------------------------- #
class _UploadRejected(Exception):
    """An untrusted upload failed a safety check; carries HTTP status + reason.

    ``reason`` is a machine-stable code (the "counted reason" of §7) surfaced in
    the error response; never a stack trace or a secret.
    """

    def __init__(self, status_code: int, reason: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason
        self.message = message


class UploadIndexCorrupt(Exception):
    """An existing upload index could not be read/parsed (integrity gap, not absent).

    Raised by :func:`load_upload_index` so a truncated/corrupt index is never
    silently treated as "no uploads" — the endpoints map it to a typed 500 with a
    counted ``upload_index_corrupt`` reason.
    """


# --------------------------------------------------------------------------- #
#  Request / response shapes (pydantic — no loose dicts)                      #
# --------------------------------------------------------------------------- #
class CreateCaseRequest(BaseModel):
    """Body for ``POST /cases`` (doc 14 §3.1)."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    operator: str
    authorization_ref: str | None = None
    forest_id: str = _DEFAULT_FOREST_ID
    forest_id_map: dict[str, str] = Field(default_factory=dict)
    #: Case-shape axes (multi-source contract §1.1). Defaults keep a case created
    #: without them behaving exactly as a single-source case (zero regression).
    domain_cardinality: DomainCardinality = "single_domain"
    dc_cardinality: DcCardinality = "single_dc"


class CaseCreated(BaseModel):
    """Response for a created case (201; doc 14 §3.1)."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    operator: str
    created_at: datetime
    root_rel: str
    artifacts: list[str] = Field(default_factory=list)


class CaseListItem(BaseModel):
    """One case workspace discovered on disk, for the UI's case picker.

    Lets the operator SELECT a case instead of having to know/type its id
    (doc 14 "operate everything from the UI"): the server enumerates the case
    workspaces under ``cases_root`` so the UI never asks for an id it cannot see.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str
    operator: str | None = None
    created_at: datetime | None = None
    authorization_ref: str | None = None
    analyzed: bool = False  # the canonical store exists (ready to serve a graph)
    uploaded_kinds: list[str] = Field(default_factory=list)
    unreadable: bool = False  # case.json missing/corrupt — surfaced, not hidden


class CaseDeleted(BaseModel):
    """Response for a deleted case workspace (200; ``DELETE /cases/{case_id}``)."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    deleted: bool


class ArtifactRegistered(BaseModel):
    """Response for an accepted artifact upload (201; doc 14 §3.2)."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    source_file: str
    stored_rel_path: str
    size_bytes: int
    image_sha256: str
    replaced: bool


class ArtifactKindOut(BaseModel):
    """One catalog tile for the UI checklist (doc 14 §3.3)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    necessity: str
    multi: bool
    unlocks: list[str]
    uploaded: bool
    source_files: list[str]


class CatalogResponse(BaseModel):
    """The static catalog joined with the upload index (doc 14 §3.3)."""

    model_config = ConfigDict(extra="forbid")

    required: list[ArtifactKindOut]
    optional: list[ArtifactKindOut]


class AnalyzeRequest(BaseModel):
    """Body for ``POST /cases/{case_id}/analyze`` (doc 14 §3.4)."""

    model_config = ConfigDict(extra="forbid")

    export_version: int | None = None
    include: list[str] | None = None  # allow-list of kinds; default = all uploaded


class AnalyzeAccepted(BaseModel):
    """Response for an accepted analyze (202; doc 14 §3.4)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    case_id: str
    ws_url: str
    active_passes: list[str]
    coverage: CoverageReport


class PassStatus(BaseModel):
    """Per-pass progress (doc 14 §3.5)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    weight: int
    state: Literal["pending", "running", "done"]
    pct: int


class AnalyzeResultSummary(BaseModel):
    """Counts-only run result (NEVER secrets; doc 14 §3.5)."""

    model_config = ConfigDict(extra="forbid")

    node_count: int
    edge_count: int
    edge_kind_counts: dict[str, int]
    export_zip_rel: str
    coverage: CoverageReport


class RunStatus(BaseModel):
    """Live/terminal analyze-run status (doc 14 §3.5)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    case_id: str
    state: Literal["pending", "running", "done", "failed"]
    current_pass: str | None
    percent: int
    passes: list[PassStatus]
    coverage_counts: dict[str, int]
    skip_counts: dict[str, int]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    result: AnalyzeResultSummary | None
    #: Case-scoped API path to download the BloodHound CE export zip, set only on a
    #: terminal/done run whose export actually produced a zip (``export_zip_rel`` is
    #: non-empty). ``None`` otherwise — the UI renders a non-clickable "not
    #: available" state rather than a dead link. The served file is still confined +
    #: existence-checked by the download route; this is a convenience pointer, not a
    #: promise the bytes are on disk.
    export_download_url: str | None = None


# --------------------------------------------------------------------------- #
#  Upload index (artifacts/_uploads.json) — lightweight, provenance at analyze #
# --------------------------------------------------------------------------- #
class UploadEntry(BaseModel):
    """One registered upload (the authority is the IngestRun at analyze time)."""

    model_config = ConfigDict(extra="forbid")

    source_file: str
    host_label: str | None
    stored_rel_path: str
    system_stored_rel_path: str | None
    image_sha256: str
    size_bytes: int
    #: CA-host composite companions (module 35b). ``software_stored_rel_path`` is
    #: the stored CA-host ``SOFTWARE`` hive (the DCOM plane) when supplied, and
    #: ``ca_host_fqdn`` the operator-asserted CA host FQDN (for the ``hosts_ca``
    #: cross-check). Both optional so a pre-35b upload index loads unchanged.
    software_stored_rel_path: str | None = None
    ca_host_fqdn: str | None = None
    #: Per-source tags (multi-source contract §1.2, M-MS1). ``dc_label`` is the
    #: operator-supplied, per-case-unique DC name (§1.3); ``declared_domain`` is
    #: the asserted domain (display only — the derived value wins for scoping);
    #: ``source_forest_id`` lets a cross-forest source override the case default.
    #: All optional so a pre-M-MS1 upload index loads unchanged (zero regression).
    dc_label: str | None = None
    declared_domain: str | None = None
    source_forest_id: str | None = None


class UploadIndex(BaseModel):
    """The per-case upload index (kind -> uploads). Multi kinds hold >1 entry."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    entries: dict[str, list[UploadEntry]] = Field(default_factory=dict)

    def present_kinds(self) -> frozenset[str]:
        """Return catalog kinds that have at least one registered upload."""
        return frozenset(k for k, v in self.entries.items() if v and k in VALID_KIND_IDS)


def _index_path(workspace: CaseWorkspace) -> Path:
    """Return the confined path to the upload index under ``artifacts/``."""
    return resolve_within(workspace.artifacts_dir, _UPLOAD_INDEX)


def load_upload_index(workspace: CaseWorkspace) -> UploadIndex:
    """Load the upload index, distinguishing ABSENT (fine) from CORRUPT (honest).

    An ABSENT index is a fresh case with no uploads yet -> an empty
    :class:`UploadIndex`. An EXISTING file that cannot be read/parsed is NOT
    silently treated as empty (that would dishonestly report already-uploaded
    artifacts as missing and 422 the operator in a no-docs UI); it raises
    :class:`UploadIndexCorrupt`, which the endpoints turn into a typed 500 with a
    counted ``upload_index_corrupt`` reason.

    Failure modes:
        Raises :class:`UploadIndexCorrupt` if an existing index file is unreadable
        or fails validation.
    """
    path = _index_path(workspace)
    if not path.is_file():
        return UploadIndex()
    try:
        return UploadIndex.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - any read/parse/validate failure => corrupt
        _log.warning("upload index exists but is unreadable (corrupt): %s", path)
        raise UploadIndexCorrupt(f"upload index at {path} is unreadable") from exc


def _save_upload_index(workspace: CaseWorkspace, index: UploadIndex) -> None:
    """Persist the upload index atomically (temp + ``os.replace``; deterministic LF).

    Written exactly like the artifact placements: canonical JSON to a temp file in
    the same directory, then ``os.replace`` (atomic on Windows + POSIX) so a
    concurrent lock-free :func:`load_upload_index` (``/catalog``, ``/coverage``,
    ``analyze``) or a crash mid-write never observes a truncated file.
    """
    path = _index_path(workspace)
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    data = canonical_json(index.model_dump(mode="json")) + "\n"
    try:
        tmp.write_text(data, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- #
#  Untrusted-upload safety helpers (doc 14 §5) — small + testable             #
# --------------------------------------------------------------------------- #
def slug_host_label(label: str) -> str:
    """Return a filesystem-safe slug for a multi-kind ``host_label`` (doc 14 §5).

    Lowercases, maps any char outside ``[A-Za-z0-9_.-]`` to ``-``, trims leading/
    trailing ``-``/``.``, then enforces ``validate_case_id``-grade rules.

    Failure modes:
        Raises ``PathSafetyError`` if the result is empty or still unsafe.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "-", label.strip().lower()).strip("-.")
    if not cleaned:
        raise PathSafetyError(f"host_label produces an empty slug: {label!r}")
    validate_case_id(cleaned)
    return cleaned


def _clean_source_tag(
    value: str | None, field: str, *, reject_controls: bool = False
) -> str | None:
    """Strip, length-bound, and (optionally) control-char-reject a per-source tag.

    The ``dc_label`` / ``domain`` / ``source_forest_id`` fields arrive on the
    untrusted upload form (M-MS1, §1.2). This trims whitespace, treats blank as
    absent (``None``), enforces :data:`_MAX_TAG_LEN`, and — for ``dc_label`` —
    rejects ASCII control characters so the label is safe as a display key AND the
    ``\\x1f`` seed separator in :func:`wraith.model.source.derive_source_id` stays
    unambiguous.

    Failure modes:
        Raises :class:`_UploadRejected` (422 ``<field>_too_long`` on an over-long
        value; 422 ``<field>_invalid_chars`` on a control character) — the endpoint
        maps either to a typed 422, consistent with the other upload guards.
    """
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > _MAX_TAG_LEN:
        raise _UploadRejected(422, f"{field}_too_long", f"{field} exceeds {_MAX_TAG_LEN} chars")
    if reject_controls and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        raise _UploadRejected(422, f"{field}_invalid_chars", f"{field} has control characters")
    return cleaned


def _magic_ok(sniff: SniffKind, header: bytes) -> bool:
    """Return whether ``header`` matches the per-kind content magic (doc 14 §5)."""
    if sniff == "ese":
        return len(header) >= ESE_MAGIC_OFFSET + 4 and (
            header[ESE_MAGIC_OFFSET : ESE_MAGIC_OFFSET + 4] == ESE_MAGIC
        )
    if sniff == "regf":
        return header[:4] == REGF_MAGIC
    return header[:4] in ZIP_MAGICS  # zip


def _stream_sniff_hash(
    upload: UploadFile, dest: Path, max_bytes: int, sniff: SniffKind
) -> tuple[int, str]:
    """Stream ``upload`` to ``dest`` in bounded chunks: sniff magic, cap, hash.

    The first chunk's prefix is content-sniffed before any further bytes are
    written (fail fast — never write a multi-GB rejected body). Size is enforced
    WHILE streaming; an overflow aborts and the temp file is removed by the caller.

    Returns:
        ``(size_bytes, sha256_hex)`` on success.

    Failure modes:
        Raises :class:`_UploadRejected` (400 ``bad_magic:<kind>`` on a magic
        mismatch / empty body; 413 ``too_large:<kind>`` on cap overflow).
    """
    hasher = hashlib.sha256()
    size = 0
    first = True
    with open(dest, "wb") as handle:
        while True:
            chunk = upload.file.read(_CHUNK)
            if not chunk:
                break
            if first:
                if not _magic_ok(sniff, chunk[:16]):
                    raise _UploadRejected(400, f"bad_magic:{sniff}", "content magic mismatch")
                first = False
            size += len(chunk)
            if size > max_bytes:
                raise _UploadRejected(413, f"too_large:{sniff}", "upload exceeds size cap")
            handle.write(chunk)
            hasher.update(chunk)
    if first:  # empty body never matched a magic
        raise _UploadRejected(400, f"bad_magic:{sniff}", "empty upload")
    return size, hasher.hexdigest()


def _incoming_dir(workspace: CaseWorkspace) -> Path:
    """Return (creating) the confined transient upload staging dir."""
    inc = resolve_within(workspace.artifacts_dir, _INCOMING)
    inc.mkdir(parents=True, exist_ok=True)
    return inc


def _extract_sysvol_zip(zip_path: Path, dest_dir: Path) -> int:
    """Extract a SYSVOL zip into ``dest_dir`` with zip-slip + resource guards (§5).

    Rejects absolute / drive-qualified / backslash / ``..``-escaping member names
    (every target is re-confined via ``resolve_within``) and symlink members, and
    caps the member count + total uncompressed size (anti zip-bomb). Nothing is
    executed — members are copied as data only.

    Returns:
        The number of file members extracted.

    Failure modes:
        Raises :class:`_UploadRejected` (400 ``zip_slip`` / ``zip_bomb`` /
        ``bad_zip``) on any violation; the caller removes a partial tree.
    """
    try:
        with zipfile.ZipFile(zip_path) as archive:
            infos = archive.infolist()
            if len(infos) > SYSVOL_MAX_MEMBERS:
                raise _UploadRejected(400, "zip_bomb", "too many zip members")
            if sum(max(i.file_size, 0) for i in infos) > SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise _UploadRejected(400, "zip_bomb", "zip uncompressed size cap exceeded")
            dest_dir.mkdir(parents=True, exist_ok=True)
            extracted = 0
            for info in infos:
                name = info.filename
                if not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name:
                    raise _UploadRejected(400, "zip_slip", "unsafe zip member name")
                try:
                    target = resolve_within(dest_dir, name)
                except PathSafetyError as exc:
                    raise _UploadRejected(400, "zip_slip", "zip member escapes root") from exc
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise _UploadRejected(400, "zip_slip", "symlink zip member rejected")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out, _CHUNK)
                extracted += 1
            return extracted
    except zipfile.BadZipFile as exc:
        raise _UploadRejected(400, "bad_zip", "not a valid zip archive") from exc


def _canonical_stored_name(kind: ArtifactKind, host_slug: str | None) -> str:
    """Return the confined relative stored name for a kind (client name discarded).

    ntds/system/sysvol use fixed names; multi/host kinds nest under a per-host
    directory. Deterministic from the validated kind (+ slug) only (doc 14 §5.1).
    """
    if kind.id == "ntds_dit":
        return "ntds.dit"
    if kind.id == "system_hive":
        return "SYSTEM"
    if kind.id == "sysvol":
        return _SYSVOL_DIRNAME
    if kind.id == "member_sam":
        if host_slug is None:  # multi kind: endpoint enforces host_label; belt-and-braces
            raise _UploadRejected(422, "host_label_required_for_multi", "member_sam needs host")
        return f"sam_{host_slug}/SAM"
    if kind.id == "ca_host_registry":
        return f"cahost_{host_slug or 'ca'}/SYSTEM"
    if kind.id == "additional_dc":
        if host_slug is None:  # multi kind: endpoint enforces host_label; belt-and-braces
            raise _UploadRejected(422, "host_label_required_for_multi", "additional_dc needs host")
        return f"dc_{host_slug}/ntds.dit"
    raise _UploadRejected(422, f"unknown_kind:{kind.id}", "no stored-name rule for kind")


def _ca_host_software_stored_name(host_slug: str | None) -> str:
    """Return the confined relative stored name for the CA-host SOFTWARE companion.

    Mirrors the ``ca_host_registry`` SYSTEM rule in :func:`_canonical_stored_name`
    (``cahost_<slug>/SYSTEM``) so the two composite hives sit side by side under one
    per-host directory. Deterministic from the validated slug only (doc 14 §5.1).
    """
    return f"cahost_{host_slug or 'ca'}/SOFTWARE"


def _source_file_for(kind: ArtifactKind, host_label: str | None) -> str:
    """Return the provenance ``source_file`` (``:<host>`` substituted for multi)."""
    pattern = kind.canonical_source_file
    if "<host>" in pattern:
        return pattern.replace("<host>", host_label or "host")
    if "<dc>" in pattern:
        return pattern.replace("<dc>", host_label or "dc")
    return pattern


# --------------------------------------------------------------------------- #
#  Analyze run state + worker-thread manager (doc 14 §3.4 / §8a decision 2)    #
# --------------------------------------------------------------------------- #
@dataclass
class _RunState:
    """Mutable, lock-guarded state of one analyze run (thread writes, WS reads)."""

    run_id: str
    case_id: str
    active_ids: tuple[str, ...]
    active_weight_total: int
    coverage: CoverageReport
    state: str = "pending"
    current_pass: str | None = None
    completed_ids: set[str] = field(default_factory=set)
    coverage_counts: dict[str, int] = field(default_factory=dict)
    skip_counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: AnalyzeResultSummary | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **changes: object) -> None:
        """Apply attribute changes under the lock (thread-safe mutation)."""
        with self._lock:
            for key, value in changes.items():
                setattr(self, key, value)

    def mark_completed(self, pass_id: str) -> None:
        """Record a pass as completed (advances the percentage)."""
        with self._lock:
            self.completed_ids.add(pass_id)

    def snapshot(self) -> RunStatus:
        """Build a consistent :class:`RunStatus` snapshot under the lock."""
        with self._lock:
            completed = set(self.completed_ids)
            done_weight = sum(s.weight for s in PASS_SPECS if s.id in completed)
            pct = percent(done_weight, self.active_weight_total)
            passes = [
                PassStatus(
                    id=s.id,
                    label=s.label,
                    weight=s.weight,
                    state=(
                        "done"
                        if s.id in completed
                        else ("running" if s.id == self.current_pass else "pending")
                    ),
                    pct=100 if s.id in completed else 0,
                )
                for s in PASS_SPECS
                if s.id in self.active_ids
            ]
            # Offer the download pointer ONLY when the run finished AND an export zip
            # was actually produced (non-empty rel path). The download route still
            # confines + existence-checks the file, so a non-None URL here is a
            # convenience, never a guarantee the bytes survived on disk.
            export_url: str | None = None
            if self.state == "done" and self.result is not None and self.result.export_zip_rel:
                export_url = f"/api/v1/cases/{self.case_id}/runs/{self.run_id}/export/bhce"
            return RunStatus(
                run_id=self.run_id,
                case_id=self.case_id,
                state=self.state,  # type: ignore[arg-type]
                current_pass=self.current_pass,
                percent=pct,
                passes=passes,
                coverage_counts=dict(self.coverage_counts),
                skip_counts=dict(self.skip_counts),
                error=self.error,
                started_at=self.started_at,
                finished_at=self.finished_at,
                result=self.result,
                export_download_url=export_url,
            )


@dataclass(frozen=True)
class _RunPlan:
    """Immutable inputs the worker thread needs to execute one run."""

    workspace: CaseWorkspace
    run: IngestRun
    inputs: PipelineInputs
    coverage: CoverageReport
    export_config: ExportConfig
    reserved_uploads: tuple[tuple[str, Path, str, int], ...]  # (source_file, path, sha, size)
    #: Extra tagged DC sources (``additional_dc`` uploads) for a multi-domain case.
    #: Empty => the single-source path runs EXACTLY as today (zero regression); one
    #: or more => the N-source multi-domain loop (``run_multi_source_pipeline``).
    additional_inputs: tuple[PipelineInputs, ...] = ()


#: Max length of the scrubbed error message surfaced in ``RunStatus.error``.
_ERROR_MAX_LEN: int = 200
#: A whitespace-delimited token containing a path separator (filesystem path).
_PATHLIKE_RE = re.compile(r"\S*[\\/]\S*")


def _safe_error(exc: BaseException) -> str:
    """Render a client-safe ``RunStatus.error`` (class + scrubbed message).

    Keeps the exception class name (useful + non-sensitive), takes only the first
    line of the message, redacts path-like tokens (parser errors can embed
    filesystem paths), and truncates — so no stack trace, newline, path, or
    secret is echoed to the client.
    """
    cls = type(exc).__name__
    raw = str(exc)
    first_line = raw.splitlines()[0] if raw else ""
    scrubbed = _PATHLIKE_RE.sub("<path>", first_line).strip()
    if len(scrubbed) > _ERROR_MAX_LEN:
        scrubbed = scrubbed[:_ERROR_MAX_LEN].rstrip() + "..."
    return f"{cls}: {scrubbed}" if scrubbed else cls


def _make_progress_cb(state: _RunState) -> Callable[[str, str], None]:
    """Build the pipeline progress callback that drives the live loading bar.

    Translates each pass boundary into a :class:`_RunState` update: ``"start"``
    sets ``current_pass`` (so the WS reports the running pass); ``"done"`` records
    completion so the §4 active-weight percentage advances. Never raises — a
    progress update is a pure in-memory state mutation, so it cannot crash the
    multi-minute run on the worker thread.
    """

    def cb(pass_id: str, phase: str) -> None:
        if phase == "start":
            state.update(current_pass=pass_id)
        else:
            state.mark_completed(pass_id)

    return cb


class MergeCaseNotReadyError(Exception):
    """A merge was requested for a case whose store has not been analyzed yet."""


class MergeUnknownSourceError(Exception):
    """A merge request named ``source_id``(s) that do not belong to the case.

    Carries the offending ids so the route can surface a typed 422 (untrusted input
    rejected, never silently merged over a partial/bogus set).
    """

    def __init__(self, unknown: Sequence[str]) -> None:
        self.unknown = list(unknown)
        super().__init__(f"unknown source_ids: {self.unknown}")


class CaseRunManager:
    """Owns per-case run locks, run state, and the analyze worker threads (§8a-2).

    One active run per case (a non-reentrant lock; the analyze endpoint acquires
    it non-blocking and the worker releases it). A separate per-case IO lock
    serializes upload-index read/modify/write so two uploads cannot corrupt it.
    """

    def __init__(self, registry: CaseReaderRegistry, cases_root: Path) -> None:
        """Store the per-case reader registry + the server cases root."""
        self._registry = registry
        self._cases_root = cases_root
        self._guard = threading.Lock()
        self._run_locks: dict[str, threading.Lock] = {}
        self._io_locks: dict[str, threading.Lock] = {}
        self._runs: dict[str, _RunState] = {}
        self._threads: dict[str, threading.Thread] = {}

    def _run_lock(self, case_id: str) -> threading.Lock:
        with self._guard:
            return self._run_locks.setdefault(case_id, threading.Lock())

    def io_lock(self, case_id: str) -> threading.Lock:
        """Return the per-case IO lock (upload-index serialization)."""
        with self._guard:
            return self._io_locks.setdefault(case_id, threading.Lock())

    def latest_run(self, case_id: str) -> _RunState | None:
        """Return the most recent run state for a case, or ``None``."""
        with self._guard:
            return self._runs.get(case_id)

    def get_run(self, case_id: str, run_id: str) -> _RunState | None:
        """Return the run state iff it matches both ``case_id`` and ``run_id``.

        Only the LATEST run per case is retained (one-run-per-case +
        fresh-DB-per-reanalyze, doc 14 §5.5): querying a superseded prior run_id
        returns ``None`` (the endpoint 404s), which is intended — a case has at
        most one live/terminal run of interest at a time.
        """
        state = self.latest_run(case_id)
        return state if state is not None and state.run_id == run_id else None

    def start_run(self, case_id: str, plan: _RunPlan) -> _RunState:
        """Acquire the case run lock and launch the analyze worker thread.

        Failure modes:
            Raises ``RuntimeError`` ``"busy"`` if a run is already active for the
            case (the caller maps it to 409).
        """
        lock = self._run_lock(case_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("busy")
        # If anything between acquiring the lock and the worker actually starting
        # raises, release the lock here — otherwise the worker's ``finally`` never
        # runs and the case is permanently stuck at 409.
        try:
            run_id = str(plan.run.ingest_run_id)
            present = plan.coverage.present_kinds
            state = _RunState(
                run_id=run_id,
                case_id=case_id,
                active_ids=active_pass_ids(present),
                active_weight_total=active_total(present),
                coverage=plan.coverage,
                skip_counts=dict(plan.run.skip_counts),
            )
            thread = threading.Thread(
                target=self._execute,
                args=(case_id, plan, state, lock),
                name=f"wraith-analyze-{case_id}",
                daemon=True,
            )
            with self._guard:
                self._runs[case_id] = state
                self._threads[case_id] = thread
            thread.start()
        except BaseException:
            lock.release()
            raise
        return state

    def _execute(
        self, case_id: str, plan: _RunPlan, state: _RunState, lock: threading.Lock
    ) -> None:
        """Run the full pipeline on the worker thread; never crash the server.

        Any exception is caught and recorded as ``state="failed"`` with a typed
        ``error`` (class + message) — no stack trace or secret escapes. The run
        lock is always released in ``finally``.
        """
        try:
            self._do_run(case_id, plan, state)
        except Exception as exc:  # noqa: BLE001 - must never crash the server
            # Log the type only (defensive: never log a possibly-sensitive message).
            _log.error("analyze failed for case %s: %s", case_id, type(exc).__name__)
            state.update(
                state="failed",
                error=_safe_error(exc),
                finished_at=datetime.now(UTC),
                current_pass=None,
            )
        finally:
            lock.release()

    def _do_run(self, case_id: str, plan: _RunPlan, state: _RunState) -> None:
        """Execute the locked pass order and bind the case reader on success."""
        workspace = plan.workspace
        run = plan.run
        db_path = Path(workspace.canonical_db)
        first_pass = state.active_ids[0] if state.active_ids else None
        state.update(state="running", started_at=datetime.now(UTC), current_pass=first_pass)

        # Fresh DB per run (doc: the ledger append invariant assumes a fresh DB;
        # re-analyze rebuilds). Unbind the read-only reader first so the file is
        # not held open (Windows), then remove the prior store.
        self._registry.unbind(case_id)
        if db_path.exists():
            db_path.unlink()

        con = open_canonical_store(db_path)
        try:
            # Register reserved-kind artifacts (ca_host/additional_dc) for provenance
            # — the pipeline registers ntds/system/sam/sysvol itself (no double-reg).
            for source_file, path, sha, size in plan.reserved_uploads:
                run.add_artifact(
                    ArtifactInput(
                        source_file=source_file,
                        abs_path_or_ref=str(path.resolve()),
                        size_bytes=size,
                        image_sha256=sha,
                    )
                )
            if plan.additional_inputs:
                # N-source multi-domain loop: ingest the primary + every tagged
                # additional DC into this one store, then derive cross-domain edges
                # once (contract §3.5 / §4). Per-source stores are created under a
                # confined scratch dir inside the case workspace.
                run_multi_source_pipeline(
                    con,
                    run,
                    (plan.inputs, *plan.additional_inputs),
                    output_dir=workspace.exports_dir / "bhce",
                    export_config=plan.export_config,
                    progress_cb=_make_progress_cb(state),
                    scratch_dir=workspace.exports_dir / ".ms_scratch",
                )
            else:
                run_analysis_pipeline(
                    con,
                    run,
                    plan.inputs,
                    output_dir=workspace.exports_dir / "bhce",
                    export_config=plan.export_config,
                    progress_cb=_make_progress_cb(state),
                )
            from wraith.provenance.ledger import write_ledger_rows

            write_ledger_rows(con, run.to_ledger_rows())
            write_run_manifest(
                workspace.manifest_dir,
                run.to_manifest(outputs=RunOutputs(canonical_db_path=str(db_path))),
            )
        finally:
            con.close()

        # Writer closed -> safe to (re)bind the read-only reader (DuckDB 1-writer).
        reader = self._registry.bind(case_id, db_path)
        zip_rel = (workspace.exports_dir / "bhce" / plan.export_config.zip_name).relative_to(
            workspace.root
        )
        result = AnalyzeResultSummary(
            node_count=reader.node_count(),
            edge_count=reader.edge_count(),
            edge_kind_counts=reader.edge_kind_counts(),
            export_zip_rel=zip_rel.as_posix(),
            coverage=plan.coverage,
        )
        for pass_id in state.active_ids:
            state.mark_completed(pass_id)
        state.update(
            state="done",
            current_pass=None,
            finished_at=datetime.now(UTC),
            coverage_counts=dict(run.coverage_counts),
            skip_counts=dict(run.skip_counts),
            result=result,
        )

    async def stream(self, case_id: str) -> AsyncIterator[dict[str, object]]:
        """Yield live progress events for a case's latest run (WS producer, §3.6).

        Emits a ``snapshot``, then a ``progress`` event whenever the percentage /
        current-pass / state changes, and a terminal ``done`` event. Uses the same
        ``{type: snapshot|progress|done}`` family as the ledger-replay producer,
        extended with ``pass``/``pct``/``state`` (additive — a client needs no
        change). Polling cadence is wall-clock (not part of determinism).
        """
        state = self.latest_run(case_id)
        if state is None:
            return
        snap = state.snapshot()
        yield {
            "type": "snapshot",
            "case_id": case_id,
            "run_id": snap.run_id,
            "active_passes": [p.id for p in snap.passes],
            "pct": snap.percent,
            "state": snap.state,
        }
        last: tuple[str, int, str | None] | None = None
        while True:
            snap = state.snapshot()
            key = (snap.state, snap.percent, snap.current_pass)
            if key != last:
                yield {
                    "type": "progress",
                    "case_id": case_id,
                    "pass": snap.current_pass,
                    "pct": snap.percent,
                    "state": snap.state,
                    "coverage_counts": snap.coverage_counts,
                    "skip_counts": snap.skip_counts,
                }
                last = key
            if snap.state in {"done", "failed"}:
                break
            await asyncio.sleep(_POLL_INTERVAL)
        final = state.snapshot()
        yield {
            "type": "done",
            "case_id": case_id,
            "pct": final.percent,
            "state": final.state,
            "coverage_counts": final.coverage_counts,
            "skip_counts": final.skip_counts,
            "error": final.error,
        }

    def try_begin_exclusive(self, case_id: str) -> bool:
        """Non-blocking acquire the case run lock for an exclusive admin op (delete).

        Takes the SAME per-case run lock the analyze worker holds, so an exclusive
        operation (e.g. deleting the case workspace) can never run concurrently with
        an active analyze writer. If an analyze is in progress the worker already
        holds the lock and this returns ``False`` without blocking.

        Returns:
            ``True`` if the lock was acquired (no run in progress — the caller MUST
            pair this with exactly one :meth:`end_exclusive_and_purge`); ``False`` if
            a run is active (the caller maps it to 409).
        """
        return self._run_lock(case_id).acquire(blocking=False)

    def end_exclusive_and_purge(self, case_id: str) -> None:
        """Drop in-memory run/thread state for the case and release its run lock.

        Call exactly once, iff :meth:`try_begin_exclusive` returned ``True``. The
        retained ``_RunState`` / worker-thread handle for the (now-deleted) case are
        purged so a later case reusing the same id starts with clean run state and a
        stale terminal run is never reported for it. The per-case lock object itself
        is left in place (a recreated case reuses it) to avoid a window where two
        distinct lock objects could guard the same id.
        """
        with self._guard:
            self._runs.pop(case_id, None)
            self._threads.pop(case_id, None)
        self._run_lock(case_id).release()

    def run_merge(self, case_id: str, source_ids: Sequence[str]) -> MergeReportOut:
        """Run the opt-in multi-source merge fold for a case (the ONE writing path).

        The only writable merge endpoint: it validates the operator-selected
        ``source_ids`` against the case's ``source`` table (untrusted input — foreign
        ids are rejected), provisions the ``divergence`` ledger, and runs the gated
        :func:`wraith.merge.fold.merge_fold` over the valid set, writing the ledger +
        the presented overlay (``resolved_value``). Idempotent per case: the fold keys
        on the DETERMINISTIC :func:`wraith.api.merge.merge_run_id`, so a re-merge
        REPLACES the prior ledger. Fewer than two valid sources is the honest
        ``nothing_to_merge`` state (surfaced, not an error).

        Write coordination mirrors analyze (DuckDB single-writer): the per-case run
        lock is taken non-blocking (busy -> ``RuntimeError("busy")`` -> 409), the
        read-only reader is UNBOUND so the file is free, the store is opened
        read-write for the fold, then the reader is REBOUND — always, even when source
        validation fails — so the case is never left without a reader.

        The API trigger does NOT arm tier-1 (no ATTID schema map) nor compute secret
        fingerprints (the decrypt-and-digest path is a separate integration); both are
        surfaced as counted gaps on the report (never a silent over-claim). The
        canonical rows are never mutated (read-time fold, §2.3).

        Inputs:
            case_id: the (caller-validated-safe) case id.
            source_ids: the operator-selected sources to reconcile (untrusted).

        Returns:
            A :class:`~wraith.api.models.MergeReportOut` (counts + DC-vs-DC report;
            never a secret/digest).

        Failure modes:
            Raises ``PathSafetyError``/``FileNotFoundError`` (bad/unknown case),
            :class:`MergeCaseNotReadyError` (store not analyzed),
            :class:`MergeUnknownSourceError` (foreign source_ids), or
            ``RuntimeError("busy")`` (a run is active) — each mapped to a typed HTTP
            status by the route.
        """
        workspace = load_workspace(self._cases_root, case_id)
        db_path = Path(workspace.canonical_db)
        if not db_path.is_file():
            raise MergeCaseNotReadyError(case_id)

        lock = self._run_lock(case_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("busy")
        unknown: list[str] = []
        valid: list[str] = []
        result = None
        try:
            self._registry.unbind(case_id)
            # The rebind is in the OUTER finally below so the read-only reader is
            # restored on EVERY exit path — including a raise from open/create/fold on
            # untrusted artifact-derived staged data — and never depends on the
            # cross-module lazy-bind in ``get_reader`` (a mid-fold crash must never
            # leave the case half-bound).
            try:
                con = open_canonical_store(db_path)
                try:
                    create_divergence_table(con)
                    valid, unknown = validate_sources(con, source_ids)
                    if not unknown:
                        result = merge_fold(con, valid, run_id=merge_run_id(case_id))
                finally:
                    con.close()
            finally:
                # Rebind AFTER the writer closes (DuckDB single-writer), ALWAYS.
                self._registry.bind(case_id, db_path)
            if unknown:
                raise MergeUnknownSourceError(unknown)
            assert result is not None  # noqa: S101 - guaranteed when unknown is empty
            return merge_result_to_report(
                result, case_id, merge_run_id(case_id), nothing_to_merge=len(valid) < 2
            )
        finally:
            lock.release()

    def shutdown(self) -> None:
        """Join any in-flight worker threads (best-effort) at app shutdown."""
        with self._guard:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(timeout=5.0)


# --------------------------------------------------------------------------- #
#  Router                                                                      #
# --------------------------------------------------------------------------- #
def _manager(request: Request) -> CaseRunManager:
    """Return the app's :class:`CaseRunManager` (set in the app lifespan)."""
    manager = getattr(request.app.state, "run_manager", None)
    if manager is None:  # pragma: no cover - lifespan always sets it
        raise HTTPException(status_code=503, detail="ingest subsystem not initialized")
    return manager  # type: ignore[no-any-return]


def _registry(request: Request) -> CaseReaderRegistry:
    """Return the app's per-case reader registry (set in the app lifespan)."""
    registry = getattr(request.app.state, "registry", None)
    if registry is None:  # pragma: no cover - lifespan always sets it
        raise HTTPException(status_code=503, detail="store not initialized")
    return registry  # type: ignore[no-any-return]


def _cases_root(request: Request) -> Path:
    """Return the server-configured cases root (never client-supplied)."""
    root = getattr(request.app.state, "cases_root", None)
    if root is None:  # pragma: no cover - lifespan always sets it
        raise HTTPException(status_code=503, detail="cases root not configured")
    return Path(root)


def _load_workspace_or_404(cases_root: Path, case_id: str) -> CaseWorkspace:
    """Load a case workspace, mapping safety/absence to typed HTTP errors."""
    try:
        return load_workspace(cases_root, case_id)
    except PathSafetyError as exc:
        raise HTTPException(status_code=400, detail={"reason": "unsafe_case_id"}) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"reason": "unknown_case"}) from exc


def _kind_tile(kind: ArtifactKind, index: UploadIndex) -> ArtifactKindOut:
    """Join one catalog kind with the upload index into a UI tile (doc 14 §3.3)."""
    entries = index.entries.get(kind.id, [])
    return ArtifactKindOut(
        id=kind.id,
        label=kind.label,
        necessity=kind.necessity,
        multi=kind.multi,
        unlocks=list(kind.unlocks),
        uploaded=bool(entries),
        source_files=[e.source_file for e in entries],
    )


def build_ingest_router() -> APIRouter:
    """Build the writable case/ingest + coverage router (doc 14 §3).

    Returns:
        An :class:`fastapi.APIRouter` to mount under ``/api/v1`` alongside the
        read-only router. All handlers are case-scoped and validate every path.
    """
    router = APIRouter()

    @router.get("/cases", response_model=list[CaseListItem], tags=["ingest"])
    def list_cases(request: Request) -> list[CaseListItem]:
        """List every case workspace on disk so the UI can offer a picker.

        Enumerates ``cases_root`` (each immediate child dir holding a ``case.json``
        is a case) and reports, per case, its operator/created_at (from
        ``case.json``), whether it has been analyzed (canonical store present), and
        which artifact kinds are uploaded. This is what lets an operator SELECT a
        case rather than having to know its id — including cases created from the
        CLI. Read-only; deterministic (sorted by case_id). A case whose
        ``case.json`` is missing/corrupt is returned with ``unreadable=True`` rather
        than being silently dropped (counted-gap honesty at the UI boundary).
        """
        cases_root = _cases_root(request)
        root = Path(cases_root)
        if not root.is_dir():
            return []
        items: list[CaseListItem] = []
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or not (child / "case.json").is_file():
                continue
            case_id = child.name
            analyzed = (child / CANONICAL_DB_FILENAME).is_file()
            try:
                config = load_case_config(child / "case.json")
            except Exception:  # noqa: BLE001 - unreadable case.json => surfaced, not dropped
                _log.warning("case.json unreadable for case %s", case_id)
                items.append(CaseListItem(case_id=case_id, analyzed=analyzed, unreadable=True))
                continue
            try:
                index = load_upload_index(CaseWorkspace(child.resolve()))
                uploaded = sorted(index.entries.keys())
            except UploadIndexCorrupt:
                uploaded = []
            items.append(
                CaseListItem(
                    case_id=case_id,
                    operator=config.operator,
                    created_at=config.created_at,
                    authorization_ref=config.authorization_ref,
                    analyzed=analyzed,
                    uploaded_kinds=uploaded,
                )
            )
        return items

    @router.post("/cases", status_code=201, response_model=CaseCreated, tags=["ingest"])
    def create_case(body: CreateCaseRequest, request: Request) -> CaseCreated:
        """Create a case workspace + ``case.json`` (doc 14 §3.1).

        409 if the case exists; 400 on an unsafe ``case_id``.
        """
        cases_root = _cases_root(request)
        try:
            validate_case_id(body.case_id)
        except PathSafetyError as exc:
            raise HTTPException(status_code=400, detail={"reason": "unsafe_case_id"}) from exc
        try:
            workspace = create_workspace(cases_root, body.case_id)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail={"reason": "case_exists"}) from exc
        forest_map = dict(body.forest_id_map)
        forest_map.setdefault(_FOREST_ID_KEY, body.forest_id)
        created_at = datetime.now(UTC)
        config = CaseConfig(
            case_id=body.case_id,
            operator=body.operator,
            authorization_ref=body.authorization_ref,
            created_at=created_at,
            forest_id_map=forest_map,
            domain_cardinality=body.domain_cardinality,
            dc_cardinality=body.dc_cardinality,
        )
        write_case_config(workspace.case_json, config)
        return CaseCreated(
            case_id=body.case_id,
            operator=body.operator,
            created_at=created_at,
            root_rel=Path(workspace.root).name,
            artifacts=[],
        )

    @router.post("/cases/{case_id}/merge", response_model=MergeReportOut, tags=["merge"])
    def run_merge(case_id: str, body: MergeRequest, request: Request) -> MergeReportOut:
        """Run the opt-in multi-source merge fold for a case (M-MS5a; the ONE writer).

        Validates the operator-selected ``source_ids`` against the case's sources
        (untrusted — foreign ids are rejected with a typed 422), runs the gated fold,
        and returns the DC-vs-DC report (counts per ``divergence_type`` + per
        ``resolution``). Fewer than two valid sources is the honest
        ``nothing_to_merge`` state (200, not an error). Never returns a secret/digest.

        Status codes:
            * 200 — merge ran (or the honest ``<2``-sources no-op);
            * 400 — unsafe ``case_id``;
            * 404 — unknown case;
            * 409 — case not analyzed yet, or a run is already active for the case;
            * 422 — one or more ``source_ids`` do not belong to the case.
        """
        manager = _manager(request)
        try:
            return manager.run_merge(case_id, body.source_ids)
        except PathSafetyError as exc:
            raise HTTPException(status_code=400, detail={"reason": "unsafe_case_id"}) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail={"reason": "unknown_case"}) from exc
        except MergeCaseNotReadyError as exc:
            raise HTTPException(status_code=409, detail={"reason": "case_not_ready"}) from exc
        except MergeUnknownSourceError as exc:
            raise HTTPException(
                status_code=422,
                detail={"reason": "unknown_source_ids", "unknown": exc.unknown},
            ) from exc
        except RuntimeError as exc:  # the per-case run lock is held (analyze/merge active)
            if str(exc) == "busy":
                raise HTTPException(status_code=409, detail={"reason": "case_busy"}) from exc
            raise

    @router.delete("/cases/{case_id}", response_model=CaseDeleted, tags=["ingest"])
    def delete_case(case_id: str, request: Request) -> CaseDeleted:
        """Delete a case workspace and all its evidence (case-scoped, confined).

        The operator confirms in the UI; the server executes safely. Deletion is
        confined to ``cases_root`` (``resolve_within``), refused while a writer is
        active, and never leaks a filesystem path or secret in a failure response.

        Inputs:
            case_id: the case whose workspace is to be removed.

        Returns:
            :class:`CaseDeleted` ``{case_id, deleted: true}`` on success (200).

        Failure modes (all typed; no stack trace / path / secret in the body):
            * unsafe ``case_id`` -> 400 ``{reason: "unsafe_case_id"}``.
            * no such case on disk -> 404 ``{reason: "unknown_case"}``.
            * an analyze is in progress for the case -> 409
              ``{reason: "run_in_progress"}`` (never delete under a running writer).
            * a filesystem error during removal -> 500
              ``{reason: "delete_failed"}`` (the error class is logged, not echoed).
        """
        cases_root = _cases_root(request)
        manager = _manager(request)
        registry = _registry(request)
        # Validate the id before touching the filesystem (400 on an unsafe slug).
        try:
            validate_case_id(case_id)
        except PathSafetyError as exc:
            raise HTTPException(status_code=400, detail={"reason": "unsafe_case_id"}) from exc
        # 404 if the workspace does not exist (also re-maps an unsafe id to 400).
        _load_workspace_or_404(cases_root, case_id)
        # Refuse to delete under an active analyze writer: take the case run lock
        # non-blocking; a worker holding it means a run is in progress -> 409.
        if not manager.try_begin_exclusive(case_id):
            raise HTTPException(status_code=409, detail={"reason": "run_in_progress"})
        try:
            # Drop the read-only reader so no open DuckDB handle blocks removal
            # (Windows holds the file open) before touching the tree.
            registry.unbind(case_id)
            # Confined removal only: re-resolve the target under cases_root so the
            # delete can never escape the cases root even if case_id were crafted.
            target = resolve_within(cases_root, case_id)
            try:
                shutil.rmtree(target)
            except OSError as exc:
                # Log the class only (no path/secret) and return a typed 500.
                _log.error("case delete failed for %s: %s", case_id, type(exc).__name__)
                raise HTTPException(status_code=500, detail={"reason": "delete_failed"}) from exc
        finally:
            manager.end_exclusive_and_purge(case_id)
        return CaseDeleted(case_id=case_id, deleted=True)

    @router.post(
        "/cases/{case_id}/artifacts",
        status_code=201,
        response_model=ArtifactRegistered,
        tags=["ingest"],
    )
    def upload_artifact(
        case_id: str,
        request: Request,
        kind: Annotated[str, Form()],
        file: Annotated[UploadFile, File()],
        host_label: Annotated[str | None, Form()] = None,
        system_file: Annotated[UploadFile | None, File()] = None,
        software_file: Annotated[UploadFile | None, File()] = None,
        ca_host_fqdn: Annotated[str | None, Form()] = None,
        dc_label: Annotated[str | None, Form()] = None,
        domain: Annotated[str | None, Form()] = None,
        source_forest_id: Annotated[str | None, Form()] = None,
    ) -> ArtifactRegistered:
        """Stream + validate + register one artifact upload (doc 14 §3.2 / §5).

        422 unknown kind; 413 over the per-kind size cap; 400 on a failed content
        sniff / unsafe path / zip-slip. The client filename is discarded; the
        stored name is derived from the validated kind (+ slugged host_label).

        Composite CA-host upload (module 35b): a ``ca_host_registry`` upload carries
        the CA host ``SYSTEM`` hive as the primary ``file`` plus an OPTIONAL
        ``software_file`` (the ``SOFTWARE`` hive / DCOM plane) and an optional
        ``ca_host_fqdn`` — both validated as untrusted exactly like the primary hive
        (regf magic, size cap, confined path). This mirrors the ``member_sam`` SAM +
        companion-``SYSTEM`` composite; the ``software_file`` is ignored for every
        other kind.

        Multi-source tags (M-MS1, contract §1.2/§1.3): a source-bearing upload
        (``ntds_dit`` / ``additional_dc``) may carry ``dc_label`` (the per-case
        -unique DC name), ``domain`` (the asserted domain, display only), and
        ``source_forest_id``. A duplicate ``dc_label`` within the case is a HARD
        409 ``dc_label_not_unique`` (never a silent rename). All three are
        optional so an existing single-source upload is unchanged.
        """
        cases_root = _cases_root(request)
        manager = _manager(request)
        workspace = _load_workspace_or_404(cases_root, case_id)
        akind = artifact_kind(kind)
        if akind is None:
            raise HTTPException(status_code=422, detail={"reason": f"unknown_kind:{kind}"})
        if akind.multi and not host_label:
            raise HTTPException(status_code=422, detail={"reason": "host_label_required_for_multi"})
        try:
            # The io_lock spans the whole upload (incl. the stream), not just the
            # index read-modify-write. Narrowing it off the multi-GB stream would
            # reintroduce an index RMW race between the placement + index phases;
            # serializing per-case uploads is correct and acceptable for local,
            # single-operator v1 (correctness first — narrowing deferred).
            with manager.io_lock(case_id):
                return _do_upload(
                    workspace,
                    akind,
                    host_label,
                    file,
                    system_file,
                    dc_label,
                    domain,
                    source_forest_id,
                    software_file=software_file,
                    ca_host_fqdn=ca_host_fqdn,
                )
        except _UploadRejected as exc:
            raise HTTPException(status_code=exc.status_code, detail={"reason": exc.reason}) from exc
        except UploadIndexCorrupt as exc:
            raise HTTPException(status_code=500, detail={"reason": "upload_index_corrupt"}) from exc
        except PathSafetyError as exc:
            raise HTTPException(status_code=400, detail={"reason": "unsafe_path"}) from exc

    @router.get("/cases/{case_id}/catalog", response_model=CatalogResponse, tags=["ingest"])
    def get_catalog(case_id: str, request: Request) -> CatalogResponse:
        """Static catalog joined with the upload index — the UI checklist (§3.3)."""
        workspace = _load_workspace_or_404(_cases_root(request), case_id)
        index = _load_index_or_http(workspace)
        tiles = [_kind_tile(k, index) for k in CATALOG]
        return CatalogResponse(
            required=[t for t in tiles if t.necessity == "required"],
            optional=[t for t in tiles if t.necessity == "optional"],
        )

    @router.get("/cases/{case_id}/coverage", response_model=CoverageReport, tags=["ingest"])
    def get_coverage(case_id: str, request: Request) -> CoverageReport:
        """Coverage preview from the uploaded set (doc 14 §2 / §3.3)."""
        workspace = _load_workspace_or_404(_cases_root(request), case_id)
        index = _load_index_or_http(workspace)
        return compute_coverage(index.present_kinds())

    @router.post(
        "/cases/{case_id}/analyze",
        status_code=202,
        response_model=AnalyzeAccepted,
        tags=["ingest"],
    )
    def analyze(case_id: str, body: AnalyzeRequest, request: Request) -> AnalyzeAccepted:
        """Launch the full analysis on a worker thread (doc 14 §3.4 / §8a-2).

        422 if ``ntds_dit`` is absent (nothing can be produced); 409 if a run is
        already active for the case.
        """
        cases_root = _cases_root(request)
        manager = _manager(request)
        workspace = _load_workspace_or_404(cases_root, case_id)
        config = _load_config_or_500(workspace)
        index = _load_index_or_http(workspace)

        present = index.present_kinds()
        if body.include is not None:
            allow = {k for k in body.include if k in VALID_KIND_IDS}
            present = frozenset(present & allow)
        coverage = compute_coverage(present)
        if not coverage.can_analyze:
            raise HTTPException(
                status_code=422,
                detail={"reason": "ntds_dit_required", "missing": list(coverage.missing_required)},
            )

        forest_id = config.forest_id_map.get(_FOREST_ID_KEY, _DEFAULT_FOREST_ID)
        inputs, additional, reserved = _build_pipeline_inputs(
            workspace, index, present, forest_id, config
        )
        run = IngestRun(
            case_id=case_id,
            operator=config.operator,
            tool_versions={"wraith": WRAITH_VERSION},
            parameters={"present_kinds": sorted(present), "export_version": body.export_version},
        )
        # Counted gap on every absent-capability branch (doc 14 §1.2 / CLAUDE.md).
        for gap_class, count in coverage_gap_bumps(coverage):
            run.bump_skip(gap_class, count)

        export_config = (
            ExportConfig(ingest_version=body.export_version)
            if body.export_version is not None
            else ExportConfig()
        )
        plan = _RunPlan(
            workspace=workspace,
            run=run,
            inputs=inputs,
            coverage=coverage,
            export_config=export_config,
            reserved_uploads=reserved,
            additional_inputs=additional,
        )
        try:
            state = manager.start_run(case_id, plan)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail={"reason": "run_in_progress"}) from exc
        return AnalyzeAccepted(
            run_id=state.run_id,
            case_id=case_id,
            ws_url=f"/api/v1/ws/progress?case_id={case_id}",
            active_passes=list(state.active_ids),
            coverage=coverage,
        )

    @router.get("/cases/{case_id}/runs/{run_id}", response_model=RunStatus, tags=["ingest"])
    def run_status(case_id: str, run_id: str, request: Request) -> RunStatus:
        """Return the live/terminal status of an analyze run (doc 14 §3.5)."""
        manager = _manager(request)
        state = manager.get_run(case_id, run_id)
        if state is None:
            raise HTTPException(status_code=404, detail={"reason": "unknown_run"})
        return state.snapshot()

    @router.get("/cases/{case_id}/runs/{run_id}/export/bhce", tags=["ingest"])
    def download_bhce_export(case_id: str, run_id: str, request: Request) -> FileResponse:
        """Stream a completed run's BloodHound CE export zip for download.

        Read-only, offline (no egress): the operator analyzes offline, then pulls
        the produced ``.zip`` to import into BloodHound CE.

        Inputs:
            case_id: the case the run belongs to (validated + path-confined).
            run_id: the analyze run whose export is requested.
            request: carries the app ``CaseRunManager`` + server cases root.

        Returns:
            A :class:`FileResponse` streaming the zip as ``application/zip`` with the
            zip basename as the download filename.

        Failure modes:
            * 404 ``unknown_run`` — no matching latest run for ``case_id``/``run_id``.
            * 404 ``unknown_case`` / 400 ``unsafe_case_id`` — workspace load (via
              :func:`_load_workspace_or_404`) rejects the id.
            * 404 ``export_absent`` — the run produced no export (empty
              ``export_zip_rel``) OR the zip is not on disk. Never a 500: an absent
              export is an expected, honestly-reported gap, not a server error.
        """
        manager = _manager(request)
        state = manager.get_run(case_id, run_id)
        if state is None:
            raise HTTPException(status_code=404, detail={"reason": "unknown_run"})

        snapshot = state.snapshot()
        zip_rel = snapshot.result.export_zip_rel if snapshot.result is not None else ""
        if not zip_rel:
            # Export never ran (e.g. run not done / export skipped): an honest,
            # expected absence — log it, 404, never 500. No run-scoped skip counter
            # is reachable from this read-only route, so the gap is logged here.
            _log.info("bhce export absent — none produced (case=%s run=%s)", case_id, run_id)
            raise HTTPException(status_code=404, detail={"reason": "export_absent"})

        workspace = _load_workspace_or_404(_cases_root(request), case_id)
        # Confine the case-relative zip path under the case root — a crafted
        # case_id/run_id (or a tampered manifest) must never traverse outside it.
        try:
            zip_path = resolve_within(workspace.root, zip_rel)
        except PathSafetyError as exc:
            _log.warning("bhce export path escapes case root (case=%s run=%s)", case_id, run_id)
            raise HTTPException(status_code=404, detail={"reason": "export_absent"}) from exc

        if not zip_path.is_file():
            _log.info("bhce export path is not on disk (case=%s run=%s)", case_id, run_id)
            raise HTTPException(status_code=404, detail={"reason": "export_absent"})

        return FileResponse(
            path=zip_path,
            media_type="application/zip",
            filename=zip_path.name,
        )

    return router


def _load_config_or_500(workspace: CaseWorkspace) -> CaseConfig:
    """Load ``case.json`` or raise a typed error (never a stack trace)."""
    try:
        return load_case_config(workspace.case_json)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail={"reason": "case_config_missing"}) from exc


def _load_index_or_http(workspace: CaseWorkspace) -> UploadIndex:
    """Load the upload index, mapping a corrupt existing index to a typed 500.

    A truly ABSENT index returns empty (fresh case); a CORRUPT existing index is
    surfaced honestly as a counted ``upload_index_corrupt`` reason rather than
    silently reporting zero uploads.
    """
    try:
        return load_upload_index(workspace)
    except UploadIndexCorrupt as exc:
        raise HTTPException(status_code=500, detail={"reason": "upload_index_corrupt"}) from exc


def _do_upload(
    workspace: CaseWorkspace,
    kind: ArtifactKind,
    host_label: str | None,
    file: UploadFile,
    system_file: UploadFile | None,
    dc_label: str | None = None,
    domain: str | None = None,
    source_forest_id: str | None = None,
    *,
    software_file: UploadFile | None = None,
    ca_host_fqdn: str | None = None,
) -> ArtifactRegistered:
    """Stream, validate, atomically place, and index one upload (doc 14 §3.2/§5).

    Two-phase so no orphan file is ever left outside the index on a rejection
    (§5.4): the artifact AND any companion hive (the ``member_sam`` SYSTEM or the
    ``ca_host_registry`` SOFTWARE) are streamed + validated into ``.incoming/``
    FIRST; only after every upload passes are they ``os.replace``d into their final
    paths; any failure (validation, placement, or the index write) rolls back every
    file this call placed and removes the temps.

    The optional ``software_file`` (CA-host ``SOFTWARE`` hive, module 35b) and
    ``ca_host_fqdn`` apply ONLY to ``ca_host_registry`` (ignored for every other
    kind); the companion is sniffed/capped/confined exactly like the primary hive.
    """
    # Sanitize the untrusted per-source tags FIRST (fail fast — before any stream):
    # trim/blank-to-None, length-bound all three, reject control chars in dc_label.
    dc_label = _clean_source_tag(dc_label, "dc_label", reject_controls=True)
    domain = _clean_source_tag(domain, "domain")
    source_forest_id = _clean_source_tag(source_forest_id, "source_forest_id")
    # The CA-host FQDN is display/correlation text; length-bound + control-reject it
    # like dc_label (it reaches the ``hosts_ca`` cross-check, never a path/exec).
    ca_host_fqdn = _clean_source_tag(ca_host_fqdn, "ca_host_fqdn", reject_controls=True)

    host_slug = slug_host_label(host_label) if host_label else None
    rel_name = _canonical_stored_name(kind, host_slug)
    final_path = resolve_within(workspace.artifacts_dir, rel_name)
    incoming = _incoming_dir(workspace)
    sniff = MAGIC_SNIFF[kind.id]
    max_bytes = MAX_UPLOAD_BYTES[kind.id]

    # The CA-host SOFTWARE companion is a registry hive (regf), capped like the
    # primary CA hive; applies only to ``ca_host_registry``.
    want_software = kind.id == "ca_host_registry" and software_file is not None

    tmp_main = incoming / f"{uuid.uuid4().hex}.part"
    tmp_sys: Path | None = None
    tmp_soft: Path | None = None
    system_rel: str | None = None
    software_rel: str | None = None
    placed_files: list[Path] = []  # final files moved into place by THIS call
    placed_sysvol: Path | None = None  # sysvol dir swapped in by THIS call
    try:
        # Phase 1 — stream + validate EVERYTHING into .incoming/ (no placement yet).
        size, sha = _stream_sniff_hash(file, tmp_main, max_bytes, sniff)
        if kind.id == "member_sam" and system_file is not None:
            tmp_sys = incoming / f"{uuid.uuid4().hex}.part"
            _stream_sniff_hash(system_file, tmp_sys, MAX_COMPANION_SYSTEM_BYTES, "regf")
        if want_software:
            tmp_soft = incoming / f"{uuid.uuid4().hex}.part"
            assert software_file is not None  # noqa: S101 - want_software guarantees it
            _stream_sniff_hash(
                software_file, tmp_soft, MAX_UPLOAD_BYTES["ca_host_registry"], "regf"
            )

        # Phase 2 — all validated: place atomically into the artifacts tree.
        if kind.id == "sysvol":
            size, sha, final_path = _place_sysvol(workspace, tmp_main, final_path)
            placed_sysvol = final_path
        else:
            final_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp_main, final_path)
            placed_files.append(final_path)
        if tmp_sys is not None:
            if host_slug is None:  # member_sam is multi => host_label enforced at endpoint
                raise _UploadRejected(422, "host_label_required_for_multi", "member_sam needs host")
            sys_dest = resolve_within(workspace.artifacts_dir, f"sam_{host_slug}/SYSTEM")
            sys_dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp_sys, sys_dest)
            placed_files.append(sys_dest)
            system_rel = sys_dest.relative_to(workspace.root).as_posix()
        if tmp_soft is not None:
            soft_dest = resolve_within(
                workspace.artifacts_dir, _ca_host_software_stored_name(host_slug)
            )
            soft_dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp_soft, soft_dest)
            placed_files.append(soft_dest)
            software_rel = soft_dest.relative_to(workspace.root).as_posix()

        # Phase 3 — record in the (atomically-written) index last.
        stored_rel = final_path.relative_to(workspace.root).as_posix()
        entry = UploadEntry(
            source_file=_source_file_for(kind, host_label),
            host_label=host_label,
            stored_rel_path=stored_rel,
            system_stored_rel_path=system_rel,
            image_sha256=sha,
            size_bytes=size,
            dc_label=dc_label,
            declared_domain=domain,
            source_forest_id=source_forest_id,
            software_stored_rel_path=software_rel,
            ca_host_fqdn=ca_host_fqdn if kind.id == "ca_host_registry" else None,
        )
        replaced = _index_put(workspace, kind, entry)
    except BaseException:
        # No residue outside the index on any failure: roll back placed files.
        for placed in placed_files:
            placed.unlink(missing_ok=True)
        if placed_sysvol is not None:
            shutil.rmtree(placed_sysvol, ignore_errors=True)
        raise
    finally:
        tmp_main.unlink(missing_ok=True)
        if tmp_sys is not None:
            tmp_sys.unlink(missing_ok=True)
        if tmp_soft is not None:
            tmp_soft.unlink(missing_ok=True)

    return ArtifactRegistered(
        kind=kind.id,
        source_file=entry.source_file,
        stored_rel_path=stored_rel,
        size_bytes=size,
        image_sha256=sha,
        replaced=replaced,
    )


def _place_sysvol(
    workspace: CaseWorkspace, tmp_zip: Path, final_dir: Path
) -> tuple[int, str, Path]:
    """Extract a SYSVOL zip to a fresh confined dir, atomically swap it in (§5).

    Returns ``(uncompressed_total_bytes, zip_sha256, final_dir)``. The zip's own
    sha (already computed while streaming) is preserved by the caller; the size is
    recomputed as the extracted-tree byte total for the index.
    """
    zip_sha = _sha256_file(tmp_zip)
    staging = _incoming_dir(workspace) / f"sysvol_{uuid.uuid4().hex}"
    try:
        _extract_sysvol_zip(tmp_zip, staging)
        if final_dir.exists():
            shutil.rmtree(final_dir)
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    total = sum(f.stat().st_size for f in final_dir.rglob("*") if f.is_file())
    return total, zip_sha, final_dir


def _collect_dc_labels(index: UploadIndex, *, skip_stored_rel_path: str) -> set[str]:
    """Return every ``dc_label`` already registered across the case's sources.

    Excludes the entry at ``skip_stored_rel_path`` (the one being re-uploaded /
    replaced) so re-uploading the SAME source under its own label is not a
    self-collision. The label is how the operator + every per-source view address
    a source, so it must be unique per case (contract §1.3).
    """
    labels: set[str] = set()
    for entries in index.entries.values():
        for e in entries:
            if e.stored_rel_path == skip_stored_rel_path:
                continue
            if e.dc_label:
                labels.add(e.dc_label)
    return labels


def _index_put(workspace: CaseWorkspace, kind: ArtifactKind, entry: UploadEntry) -> bool:
    """Insert/replace ``entry`` in the upload index; return whether it replaced one.

    Non-multi kinds hold exactly one entry (replaced on re-upload). Multi kinds are
    keyed by ``host_label``: a same-host re-upload replaces, a new host appends.

    Enforces ``(case_id, dc_label)`` uniqueness (contract §1.3): a new ``dc_label``
    already used by another source is a HARD ``_UploadRejected`` (409
    ``dc_label_not_unique``), never a silent rename.
    """
    index = load_upload_index(workspace)
    if entry.dc_label and entry.dc_label in _collect_dc_labels(
        index, skip_stored_rel_path=entry.stored_rel_path
    ):
        raise _UploadRejected(409, "dc_label_not_unique", "dc_label already used in this case")
    existing = index.entries.get(kind.id, [])
    replaced = False
    if kind.multi:
        kept = [e for e in existing if e.host_label != entry.host_label]
        replaced = len(kept) != len(existing)
        kept.append(entry)
        index.entries[kind.id] = sorted(kept, key=lambda e: e.source_file)
    else:
        replaced = bool(existing)
        index.entries[kind.id] = [entry]
    _save_upload_index(workspace, index)
    return replaced


def _build_pipeline_inputs(
    workspace: CaseWorkspace,
    index: UploadIndex,
    present: frozenset[str],
    forest_id: str,
    config: CaseConfig,
) -> tuple[PipelineInputs, tuple[PipelineInputs, ...], tuple[tuple[str, Path, str, int], ...]]:
    """Build the primary + additional sources + reserved-upload tuples from the index.

    Returns ``(primary_inputs, additional_inputs, reserved_uploads)``:

    * ``primary_inputs`` — the ``ntds_dit`` source (+ its companion SYSTEM / SAM /
      SYSVOL artifacts), tagged by its ``dc_label`` (default ``primary-dc`` when
      untagged — single-source back-compat), ``declared_domain``, and optional
      ``source_forest_id`` (M-MS1, contract §1.2/§1.4).
    * ``additional_inputs`` — one :class:`PipelineInputs` per ``additional_dc``
      upload (each its OWN tagged DC source: its ``ntds.dit`` only — the
      ``additional_dc`` kind carries no companion hive — with its ``dc_label`` /
      ``declared_domain`` / ``source_forest_id``). EMPTY => the single-source path
      runs exactly as today; non-empty => the N-source multi-domain loop. This is
      what turns ``additional_dc`` from a reserved upload into a real pipeline input.
    * ``reserved_uploads`` — kinds with ``pipeline_field=None`` that still feed no
      pass (today only ``ca_host_registry``), returned so the worker can register
      them for provenance. ``additional_dc`` is deliberately EXCLUDED here: it is
      now consumed as a real source above, not registered as reserved-only.

    Precondition: ``ntds_dit`` is uploaded — the caller has already verified
    ``coverage.can_analyze`` (422 otherwise), so the ``index.entries["ntds_dit"]``
    subscript below is guaranteed non-empty.
    """
    root = Path(workspace.root)

    ntds_entries = index.entries.get("ntds_dit") or []
    if not ntds_entries:  # unreachable: caller already enforced coverage.can_analyze
        raise HTTPException(status_code=422, detail={"reason": "ntds_dit_required"})
    ntds_entry = ntds_entries[0]
    ntds_path = resolve_within(root, ntds_entry.stored_rel_path)
    dc_label = ntds_entry.dc_label or _DEFAULT_DC_LABEL
    source_forest_id = ntds_entry.source_forest_id or forest_id

    system_hive_path: Path | None = None
    if "system_hive" in present and index.entries.get("system_hive"):
        system_hive_path = resolve_within(root, index.entries["system_hive"][0].stored_rel_path)

    sysvol_root: Path | None = None
    if "sysvol" in present and index.entries.get("sysvol"):
        sysvol_root = resolve_within(root, index.entries["sysvol"][0].stored_rel_path)

    sam_hosts: list[SamHostInput] = []
    if "member_sam" in present:
        for e in index.entries.get("member_sam", []):
            companion = (
                resolve_within(root, e.system_stored_rel_path) if e.system_stored_rel_path else None
            )
            sam_hosts.append(
                SamHostInput(
                    sam_path=resolve_within(root, e.stored_rel_path),
                    source_file=e.source_file,
                    system_hive_path=companion,
                )
            )

    # CA-host registry (module 35b): the composite ``ca_host_registry`` upload feeds
    # the already-gated ADCS-ESC CA pass. SYSTEM is required for any CA facts;
    # SOFTWARE (DCOM plane) + FQDN are optional. Threading these makes the pipeline
    # build REAL facts via ``build_ca_host_facts``; leaving them ``None`` (no upload)
    # keeps the engine's ``ABSENT_CA_HOST_FACTS`` path byte-for-byte unchanged.
    ca_host_system_path: Path | None = None
    ca_host_software_path: Path | None = None
    ca_host_fqdn: str | None = None
    if "ca_host_registry" in present and index.entries.get("ca_host_registry"):
        ca_entry = index.entries["ca_host_registry"][0]
        ca_host_system_path = resolve_within(root, ca_entry.stored_rel_path)
        if ca_entry.software_stored_rel_path:
            ca_host_software_path = resolve_within(root, ca_entry.software_stored_rel_path)
        ca_host_fqdn = ca_entry.ca_host_fqdn

    reserved: list[tuple[str, Path, str, int]] = []
    for kind in CATALOG:
        # Reserved-only kinds (``pipeline_field is None``) that still feed no pass are
        # registered here for provenance. ``additional_dc`` is excluded — it is a REAL
        # source (built below); ``ca_host_registry`` is now wired (threaded above and
        # registered by the pipeline itself), so neither lands here anymore.
        if kind.pipeline_field is None and kind.id != "additional_dc" and kind.id in present:
            for e in index.entries.get(kind.id, []):
                reserved.append(
                    (
                        e.source_file,
                        resolve_within(root, e.stored_rel_path),
                        e.image_sha256,
                        e.size_bytes,
                    )
                )

    inputs = PipelineInputs(
        ntds_path=ntds_path,
        forest_id=source_forest_id,
        system_hive_path=system_hive_path,
        sam_hosts=tuple(sam_hosts),
        sysvol_root=sysvol_root,
        ca_host_system_path=ca_host_system_path,
        ca_host_software_path=ca_host_software_path,
        ca_host_fqdn=ca_host_fqdn,
        dc_label=dc_label,
        declared_domain=ntds_entry.declared_domain,
        domain_cardinality=config.domain_cardinality,
        dc_cardinality=config.dc_cardinality,
    )

    # Each ``additional_dc`` upload is its own tagged DC source (multi-domain loop).
    additional: list[PipelineInputs] = []
    if "additional_dc" in present:
        for e in index.entries.get("additional_dc", []):
            # A per-case-unique label: the operator's ``dc_label`` if set, else a
            # deterministic ``dc-<host>`` from the (per-kind-unique) host_label. The
            # ``dc-`` prefix keeps it distinct from the primary default ``primary-dc``.
            if e.dc_label:
                addl_label = e.dc_label
            elif e.host_label:
                addl_label = f"dc-{slug_host_label(e.host_label)}"
            else:  # additional_dc is a multi kind => host_label is enforced at upload
                addl_label = _DEFAULT_DC_LABEL
            additional.append(
                PipelineInputs(
                    ntds_path=resolve_within(root, e.stored_rel_path),
                    forest_id=e.source_forest_id or forest_id,
                    system_hive_path=None,  # additional_dc carries no companion hive
                    sam_hosts=(),
                    sysvol_root=None,
                    ntds_source_file=e.source_file,  # "ntds.dit:<dc>" (per-source prov)
                    dc_label=addl_label,
                    declared_domain=e.declared_domain,
                    domain_cardinality=config.domain_cardinality,
                    dc_cardinality=config.dc_cardinality,
                )
            )

    return inputs, tuple(additional), tuple(reserved)


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 hex of a file (bounded memory)."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


__all__ = [
    "CaseRunManager",
    "build_ingest_router",
    "load_upload_index",
    "slug_host_label",
    "UploadEntry",
    "UploadIndex",
    "UploadIndexCorrupt",
    "CreateCaseRequest",
    "CaseCreated",
    "CaseListItem",
    "CaseDeleted",
    "ArtifactRegistered",
    "CatalogResponse",
    "AnalyzeRequest",
    "AnalyzeAccepted",
    "RunStatus",
]
