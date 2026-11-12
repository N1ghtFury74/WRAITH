"""Per-case read-only :class:`StoreReader` registry (doc 14 §3 / §8a decision 1).

Replaces the M7 app's single-lifetime reader with a ``dict[case_id, StoreReader]``
so one app process can serve multiple cases. The query layer stays STRICTLY
read-only: readers are opened via ``StoreReader.open`` (which uses
``open_canonical_store_readonly``). A case's reader is (re)bound only AFTER its
background analyze has CLOSED the write handle (DuckDB is single-writer), so a
reader never races the writer on the same file.

A single optional ``default`` reader is retained for backward compatibility with
``create_app(db_path)`` (the CLI ``serve`` command and the existing M7 gate bind
one case's store as the default); case-scoped endpoints use the keyed readers.
Thread-safe: the ingest worker thread rebinds while the event-loop threads read.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from wraith.api.store import StoreReader

_log = logging.getLogger(__name__)


class CaseReaderRegistry:
    """Thread-safe registry of per-case read-only store readers (+ one default).

    Construct once per app; :meth:`bind` after an analyze completes, :meth:`get`
    from a request handler, :meth:`close_all` at shutdown.
    """

    def __init__(self, default_reader: StoreReader | None = None) -> None:
        """Create the registry, optionally with a lifetime ``default`` reader."""
        self._default = default_reader
        self._readers: dict[str, StoreReader] = {}
        self._lock = threading.Lock()

    @property
    def default(self) -> StoreReader | None:
        """The optional lifetime default reader (``create_app(db_path)`` path)."""
        return self._default

    def get(self, case_id: str) -> StoreReader | None:
        """Return the bound reader for ``case_id``, or ``None`` if none is bound."""
        with self._lock:
            return self._readers.get(case_id)

    def bind(self, case_id: str, db_path: Path | str) -> StoreReader:
        """Open ``db_path`` read-only and register it for ``case_id``.

        Any previously-bound reader for the case is replaced and closed AFTER the
        new one opens, so a concurrent reader is never left dangling.

        Inputs:
            case_id: the case to bind.
            db_path: the case's populated ``canonical.duckdb`` (writer closed).

        Returns:
            The newly opened read-only :class:`StoreReader`.

        Failure modes:
            Raises ``FileNotFoundError`` if the store file does not exist;
            ``duckdb.Error`` on a corrupt file. On failure no binding changes.
        """
        reader = StoreReader.open(db_path)
        with self._lock:
            old = self._readers.get(case_id)
            self._readers[case_id] = reader
        if old is not None:
            _safe_close(old)
        return reader

    def get_or_bind(self, case_id: str, db_path: Path | str) -> StoreReader:
        """Return the bound reader for ``case_id``, else open ``db_path`` and bind it.

        Lazy-binds an already-analyzed case's read-only store on first access (e.g.
        after a server restart, when the in-memory registry is empty but the case's
        ``canonical.duckdb`` is on disk) so analyzed cases survive a restart without
        a re-analyze. Atomic and race-safe: the store is opened OUTSIDE the lock
        (I/O), then under the lock a concurrent bind is detected and the redundant
        freshly-opened reader is discarded (never closing a reader another request
        may be using).

        Inputs:
            case_id: the case to resolve.
            db_path: the case's populated ``canonical.duckdb`` (writer closed).

        Returns:
            The bound read-only :class:`StoreReader`.

        Failure modes:
            Raises ``FileNotFoundError`` if the store file does not exist;
            ``duckdb.Error`` on a corrupt file. On failure no binding changes.
        """
        with self._lock:
            existing = self._readers.get(case_id)
            if existing is not None:
                return existing
        reader = StoreReader.open(db_path)
        redundant: StoreReader | None = None
        with self._lock:
            winner = self._readers.get(case_id)
            if winner is not None:
                redundant = reader  # another thread bound first; discard ours
            else:
                self._readers[case_id] = reader
                winner = reader
        if redundant is not None:
            _safe_close(redundant)
        return winner

    def unbind(self, case_id: str) -> None:
        """Close and remove the reader for ``case_id`` (e.g. before a rebuild)."""
        with self._lock:
            old = self._readers.pop(case_id, None)
        if old is not None:
            _safe_close(old)

    def close_all(self) -> None:
        """Close every reader (case readers + the default). Safe to call once."""
        with self._lock:
            readers = list(self._readers.values())
            self._readers.clear()
            default = self._default
            self._default = None
        for reader in readers:
            _safe_close(reader)
        if default is not None:
            _safe_close(default)


def _safe_close(reader: StoreReader) -> None:
    """Close a reader, swallowing + logging any close error (shutdown path)."""
    try:
        reader.close()
    except Exception:  # pragma: no cover - defensive; a close error must not crash
        _log.warning("error closing store reader", exc_info=True)


__all__ = ["CaseReaderRegistry"]
