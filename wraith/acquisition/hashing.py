"""Streaming SHA-256 over multi-GB artifacts (FR-02; research Item 3).

Uses stdlib ``hashlib.file_digest`` (Python 3.11+) which reads in bounded-size
chunks, giving constant memory on a multi-GB ``ntds.dit``. SHA-256 is
deterministic, so the digest is stable across runs — it flows into both the
embedded provenance struct (§2.3) and the ledger row (§2.4).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

#: Fixed chunk size for the manual stream fallback (1 MiB).
_CHUNK = 1024 * 1024


def sha256_file(path: Path | str) -> str:
    """Compute the SHA-256 of a file with bounded memory.

    Inputs:
        path: path to an existing regular file.

    Returns:
        The lowercase 64-char hex digest.

    Failure modes:
        Raises ``FileNotFoundError`` if the file is absent; ``OSError`` on read
        errors; ``IsADirectoryError`` if a directory is passed.
    """
    with open(path, "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256")
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute the SHA-256 of an in-memory bytes object.

    Inputs:
        data: the bytes to hash.

    Returns:
        The lowercase 64-char hex digest.

    Failure modes:
        Raises ``TypeError`` for a non-bytes argument.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_stream(path: Path | str, chunk_size: int = _CHUNK) -> str:
    """Compute the SHA-256 via an explicit chunked read loop (fallback path).

    Provided for streams/handles where ``file_digest`` is unsuitable; the
    result is identical to :func:`sha256_file`.

    Inputs:
        path: path to an existing regular file.
        chunk_size: read granularity in bytes (default 1 MiB).

    Returns:
        The lowercase 64-char hex digest.

    Failure modes:
        Raises ``FileNotFoundError``/``OSError`` on read errors; ``ValueError``
        if ``chunk_size`` is not positive.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()
