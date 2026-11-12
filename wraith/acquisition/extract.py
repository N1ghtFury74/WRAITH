"""Safe archive extraction for SYSVOL/container inputs (NFR-10; research Item 4).

Defends against Zip-Slip / path traversal and malicious links:
  * tar: Python 3.12 extraction filters (PEP 706) — ``filter="data"`` blocks
    absolute paths, ``..`` traversal, device/FIFO members, and setuid/setgid
    bits. Only *regular file* members are extracted; sym/hard-link members are
    intentionally excluded from extraction and reported as skipped, so the skip
    count is truthful and nothing is left on disk that was not hashed.
  * zip: each member's resolved target is asserted to be within the destination
    before writing; symlink members are skipped (``zipfile`` does not defend
    against them).

Hash-boundary rule (research Item 3): the archive container hash is recorded by
the caller BEFORE extraction; every file actually written to disk is hashed
AFTER. A member reported as ``skipped`` is never written, so there is no
on-disk file without a provenance hash and no hashed file missing from ``files``.
"""

from __future__ import annotations

import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from wraith.acquisition.hashing import sha256_file
from wraith.acquisition.paths import resolve_within

#: Archive suffixes routed to the tar extractor.
_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


class ExtractedFile(BaseModel):
    """One file written by a safe extraction.

    Fields:
        inner_path: POSIX-style path of the member within the archive.
        abs_path: the resolved absolute path written on disk (within dest).
        image_sha256: SHA-256 of the extracted file (the inner artifact hash).

    Failure modes: none (constructed only for successfully written files).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    inner_path: str
    abs_path: Path
    image_sha256: str


class ExtractionResult(BaseModel):
    """Outcome of a safe extraction, including skipped members (counted gaps).

    Fields:
        files: successfully extracted files (with per-file hashes).
        skipped: ``{inner_path: reason}`` for members intentionally skipped
            (e.g. symlink members) — surfaced as a gap, never silently dropped.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    files: list[ExtractedFile]
    skipped: dict[str, str]


def is_archive(path: Path | str) -> bool:
    """Return ``True`` if ``path`` looks like a supported archive by suffix.

    Inputs:
        path: the candidate path.

    Returns:
        ``True`` for ``.zip`` or a recognized tar suffix, else ``False``.
    """
    name = Path(path).name.lower()
    if name.endswith(".zip"):
        return True
    return any(name.endswith(sfx) for sfx in _TAR_SUFFIXES)


def extract_archive(archive_path: Path | str, dest_dir: Path | str) -> ExtractionResult:
    """Dispatch to the tar or zip safe-extractor based on suffix.

    Inputs:
        archive_path: the container archive (already hashed by the caller).
        dest_dir: destination directory (created if absent).

    Returns:
        An ``ExtractionResult``.

    Failure modes:
        Raises ``PathSafetyError`` on traversal attempts; ``ValueError`` for an
        unrecognized archive type; ``tarfile``/``zipfile`` errors on a corrupt
        archive.
    """
    name = Path(archive_path).name.lower()
    if name.endswith(".zip"):
        return safe_extract_zip(archive_path, dest_dir)
    if any(name.endswith(sfx) for sfx in _TAR_SUFFIXES):
        return safe_extract_tar(archive_path, dest_dir)
    raise ValueError(f"unsupported archive type: {archive_path}")


def safe_extract_tar(archive_path: Path | str, dest_dir: Path | str) -> ExtractionResult:
    """Extract a tar archive using the PEP 706 ``data`` filter.

    Inputs:
        archive_path: the tar container.
        dest_dir: destination directory (created if absent).

    Returns:
        An ``ExtractionResult`` with per-file hashes. Sym/hard-link members are
        NOT extracted and are reported in ``skipped`` (truthful skip count).

    Failure modes:
        Raises ``tarfile.TarError`` on a corrupt/unsafe archive (the ``data``
        filter raises on traversal escapes); ``PathSafetyError`` if a resolved
        member still escapes dest (defense in depth).
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    files: list[ExtractedFile] = []
    skipped: dict[str, str] = {}
    with tarfile.open(archive_path, mode="r:*") as tar:
        members = tar.getmembers()
        # Extract ONLY regular files; links are never written to disk so the
        # skip count is truthful and the data filter only sees file members.
        regular = [m for m in members if m.isfile()]
        tar.extractall(path=dest, members=regular, filter="data")
        for member in members:
            if member.isfile():
                target = resolve_within(dest, member.name)
                files.append(
                    ExtractedFile(
                        inner_path=member.name,
                        abs_path=target,
                        image_sha256=sha256_file(target),
                    )
                )
            elif member.issym() or member.islnk():
                skipped[member.name] = "link member skipped (not extracted)"
    return ExtractionResult(files=_sorted(files), skipped=dict(sorted(skipped.items())))


def safe_extract_zip(archive_path: Path | str, dest_dir: Path | str) -> ExtractionResult:
    """Extract a zip archive with explicit Zip-Slip and symlink defenses.

    Inputs:
        archive_path: the zip container.
        dest_dir: destination directory (created if absent).

    Returns:
        An ``ExtractionResult``; symlink members are skipped and counted.

    Failure modes:
        Raises ``PathSafetyError`` if a member resolves outside dest;
        ``zipfile.BadZipFile`` on a corrupt archive.
    """
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    files: list[ExtractedFile] = []
    skipped: dict[str, str] = {}
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if _zip_is_symlink(info):
                skipped[info.filename] = "symlink member skipped"
                continue
            # Zip-Slip defense: resolved target must stay within dest.
            target = resolve_within(dest, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)  # bounded memory (no full read())
            files.append(
                ExtractedFile(
                    inner_path=info.filename,
                    abs_path=target,
                    image_sha256=sha256_file(target),
                )
            )
    return ExtractionResult(files=_sorted(files), skipped=dict(sorted(skipped.items())))


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    """Return ``True`` if a zip member carries Unix symlink mode bits."""
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _sorted(files: list[ExtractedFile]) -> list[ExtractedFile]:
    """Deterministically order extracted files by their inner path."""
    return sorted(files, key=lambda f: f.inner_path)
