"""Acquisition & integrity: path-safety, streaming SHA-256, safe extraction,
artifact ingest.

All inputs are untrusted (NFR-10): paths are validated and contained, archives
are extracted with Zip-Slip/symlink defenses, and every artifact is hashed for
provenance (FR-02).
"""

from __future__ import annotations

from wraith.acquisition.extract import (
    ExtractedFile,
    ExtractionResult,
    extract_archive,
    is_archive,
    safe_extract_tar,
    safe_extract_zip,
)
from wraith.acquisition.hashing import sha256_bytes, sha256_file, sha256_stream
from wraith.acquisition.ingest import IngestMode, ingest_file
from wraith.acquisition.paths import (
    PathSafetyError,
    ensure_existing_file,
    resolve_within,
    validate_case_id,
)

__all__ = [
    "PathSafetyError",
    "validate_case_id",
    "resolve_within",
    "ensure_existing_file",
    "sha256_file",
    "sha256_bytes",
    "sha256_stream",
    "is_archive",
    "extract_archive",
    "safe_extract_tar",
    "safe_extract_zip",
    "ExtractedFile",
    "ExtractionResult",
    "IngestMode",
    "ingest_file",
]
