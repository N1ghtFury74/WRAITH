"""Swappable ESE (Extensible Storage Engine) reader backend.

WRAITH never hand-rolls an ESE parser (CLAUDE.md: reuse libraries for the hard,
correctness-critical parts). This module is a *thin, swappable adapter* over the
``dissect`` ESE reader so that the single import that differs between
``dissect.esedb`` and its maintained successor ``dissect.database`` is isolated
in exactly one place (see ``_BACKEND_MODULE`` / ``_BACKEND_CLASS`` below). The
rest of WRAITH only ever imports the typed wrappers defined here.

Scope (this pass): a generic, schema-agnostic ESE reader. It can open any ESE
``.edb``/``.dit`` and stream its tables/records with bounded memory. It contains
**no** NTDS semantics — schema resolution, the security-descriptor join, PEK /
secret decryption and canonical mapping all slot *on top* of this adapter in a
later pass. The raw-bytes escape hatch (:meth:`EseRecord.raw`) is the documented
extension point those layers will use for security descriptors and secret blobs.

Design guarantees:

* **Deterministic streaming.** :meth:`EseTable.records` is a lazy generator
  backed by ``dissect``'s primary-index leaf walk (DNT order for NTDS), so
  identical inputs yield records in an identical order with bounded memory.
* **Absent -> ``None``, counted.** ``dissect`` exposes column values through a
  mix of ``.get`` / ``__getitem__`` / attribute access with differing behaviour
  for absent columns. This adapter normalises every access to "absent -> None"
  and never raises on a missing column; it increments a coverage counter instead
  so skipped data is surfaced, never silently wrong (CLAUDE.md error handling).
* **Malformed value -> counted gap.** A value that ``dissect`` cannot parse is
  caught, counted, and degraded to ``None`` rather than crashing a run mid-way.
* **Raw-bytes hatch.** :meth:`EseRecord.raw` returns the stored bytes for a
  column without decoding, for data WRAITH must interpret itself later.
* **Offline.** No network egress; purely local file reads.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

# --- the single swappable backend import -------------------------------------
# These two lines are the ONE place that knows which concrete ``dissect`` ESE
# class is in use. To swap back to ``dissect.esedb`` (its class is named
# ``EseDB``), change only these two imports and the mypy override in pyproject.
from dissect.database import ESE as _BackendEse  # noqa: N811  (upstream class name)
from dissect.database.ese.exception import InvalidDatabase as _BackendInvalidDatabase
from pydantic import BaseModel, ConfigDict

# -----------------------------------------------------------------------------

# Derive the seam identity from the live backend class so it can never silently
# desync from the actual import above. For the locked ``dissect.database`` stack
# these resolve to ``"dissect.database"`` / ``"ESE"`` (``__module__`` is the
# deeper ``dissect.database.ese.ese``; we report the top-level package).
_BACKEND_CLASS: str = _BackendEse.__name__
_BACKEND_MODULE: str = ".".join(_BackendEse.__module__.split(".")[:2])
# -----------------------------------------------------------------------------

_log = logging.getLogger(__name__)

#: Value types an ESE record column can yield once parsed by the backend. Raw
#: (undecoded) access always yields ``bytes | None`` instead (see
#: :meth:`EseRecord.raw`).
EseValue = bool | int | float | str | bytes | list[Any] | None


class EseError(Exception):
    """Base class for all errors raised by the ESE backend adapter."""


class EseOpenError(EseError):
    """Raised when a file cannot be opened/recognised as an ESE database.

    Wraps the underlying ``dissect`` ``InvalidDatabase`` and OS-level errors so
    callers depend only on WRAITH's exception surface, never ``dissect``'s.
    """


class EseTableNotFoundError(EseError):
    """Raised by :meth:`EseHandle.table` when no table of that name exists."""


# -----------------------------------------------------------------------------
# Database (clean/dirty) state
# -----------------------------------------------------------------------------

#: Standard JET ``DBFILEHDR.dbstate`` values. Only the CleanShutdown (3) path is
#: exercisable with a generic clean ``.edb``; the remaining mappings are the
#: documented JET constants but are **UNCONFIRMED** until validated against a
#: real dirty ``ntds.dit`` (see :class:`DatabaseState.mapping_confirmed`).
_DBSTATE_LABELS: dict[int, str] = {
    1: "JustCreated",
    2: "DirtyShutdown",
    3: "CleanShutdown",
    4: "BeingConverted",
    5: "ForceDetach",
}

#: The one ``dbstate`` value a generic clean ``.edb`` lets us positively confirm.
_CLEAN_SHUTDOWN: int = 3
_DIRTY_SHUTDOWN: int = 2


class DatabaseState(BaseModel):
    """Best-effort read of the ESE ``DBFILEHDR`` consistency state.

    Feeds Module 1's reserved ``db_state`` (clean/dirty) provenance field. The
    adapter reports the raw integer verbatim plus a best-effort interpretation;
    it never guesses silently.

    Attributes:
        raw_dbstate: The raw ``DBFILEHDR.dbstate`` integer, reported verbatim.
        label: Human-readable JET state name, or ``"Unknown(<n>)"`` if unmapped.
        is_clean: ``True`` for CleanShutdown (3), ``False`` for DirtyShutdown
            (2), ``None`` for any other/unknown state (we do not guess).
        gen_min_required: ``DBFILEHDR.lGenMinRequired`` (0 on a cleanly detached
            db); non-zero indicates logs are required to reach consistency.
        gen_max_required: ``DBFILEHDR.lGenMaxRequired`` (the log "waypoint").
        mapping_confirmed: ``True`` only when ``raw_dbstate`` is the
            CleanShutdown value validated by WRAITH's generic ``.edb`` fixture.
            ``False`` for every other value: the dirty-state enum mapping is
            **UNCONFIRMED pending a real dirty ``.dit``** and downstream code
            should treat a ``False`` here as lower-confidence.
    """

    model_config = ConfigDict(frozen=True)

    raw_dbstate: int
    label: str
    is_clean: bool | None
    gen_min_required: int
    gen_max_required: int
    mapping_confirmed: bool


def _interpret_dbstate(raw_dbstate: int, gen_min: int, gen_max: int) -> DatabaseState:
    """Map a raw ``dbstate`` integer to a :class:`DatabaseState` (pure)."""
    label = _DBSTATE_LABELS.get(raw_dbstate, f"Unknown({raw_dbstate})")
    if raw_dbstate == _CLEAN_SHUTDOWN:
        is_clean: bool | None = True
    elif raw_dbstate == _DIRTY_SHUTDOWN:
        is_clean = False
    else:
        is_clean = None
    return DatabaseState(
        raw_dbstate=raw_dbstate,
        label=label,
        is_clean=is_clean,
        gen_min_required=gen_min,
        gen_max_required=gen_max,
        mapping_confirmed=(raw_dbstate == _CLEAN_SHUTDOWN),
    )


# -----------------------------------------------------------------------------
# Coverage accounting
# -----------------------------------------------------------------------------


@dataclass
class _CoverageStats:
    """Mutable, handle-scoped coverage/skip counters (internal)."""

    tables_opened: int = 0
    records_yielded: int = 0
    missing_column_requests: int = 0
    value_parse_errors: int = 0
    raw_read_errors: int = 0
    missing_columns: set[str] = field(default_factory=set)


class CoverageReport(BaseModel):
    """Immutable snapshot of an :class:`EseHandle`'s coverage/skip counters.

    Surfaced so a run can report what was skipped rather than silently dropping
    it (CLAUDE.md: "surface coverage/skip counts").

    Attributes:
        tables_opened: Number of ``table()`` lookups that resolved a table.
        records_yielded: Total records streamed across all tables on this handle.
        missing_column_requests: Count of column accesses for a column absent
            from the table schema (each normalised to ``None``, never raised).
        value_parse_errors: Count of values the backend could not parse (each
            degraded to ``None`` and counted, never crashed).
        raw_read_errors: Count of raw-bytes reads that failed (degraded to
            ``None`` and counted).
        missing_column_names: Sorted, de-duplicated names seen in
            ``missing_column_requests`` (for an actionable operator message).
    """

    model_config = ConfigDict(frozen=True)

    tables_opened: int
    records_yielded: int
    missing_column_requests: int
    value_parse_errors: int
    raw_read_errors: int
    missing_column_names: tuple[str, ...]


def _snapshot(stats: _CoverageStats) -> CoverageReport:
    """Produce a deterministic immutable snapshot of ``stats`` (pure)."""
    return CoverageReport(
        tables_opened=stats.tables_opened,
        records_yielded=stats.records_yielded,
        missing_column_requests=stats.missing_column_requests,
        value_parse_errors=stats.value_parse_errors,
        raw_read_errors=stats.raw_read_errors,
        missing_column_names=tuple(sorted(stats.missing_columns)),
    )


# -----------------------------------------------------------------------------
# Record / Table / Handle wrappers
# -----------------------------------------------------------------------------


class EseRecord:
    """A single ESE record, presented as a normalised, dict-like mapping.

    Wraps a backend record and the owning table's column list. It behaves like a
    read-only ``{column: value}`` mapping (``record["col"]``, ``in``, iteration,
    :meth:`as_dict`) while additionally exposing a raw-bytes escape hatch
    (:meth:`raw`) that the backend's parsed-value API does not.

    Normalisation contract (differs from a strict ``Mapping`` by design):
        * A column **absent from the table schema** yields ``None`` and is
          counted (never ``KeyError``) — WRAITH never raises on a missing
          column; it surfaces a skip count instead.
        * A column present but **unset in this record** yields ``None``.
        * A value the backend **cannot parse** yields ``None`` and is counted.
    """

    __slots__ = ("_record", "_columns", "_column_set", "_stats")

    def __init__(
        self,
        record: Any,  # noqa: ANN401 - untyped backend record (dissect ships no stubs)
        columns: tuple[str, ...],
        stats: _CoverageStats,
    ) -> None:
        self._record = record
        self._columns = columns
        self._column_set = frozenset(columns)
        self._stats = stats

    @property
    def columns(self) -> tuple[str, ...]:
        """The owning table's column names, in catalog order."""
        return self._columns

    def value(self, column: str) -> EseValue:
        """Return the parsed value of ``column`` (absent/unset/unparseable -> None).

        Inputs:
            column: the column name to read.

        Returns:
            The backend-parsed value, or ``None`` if the column is absent from
            the schema, unset in this record, or fails to parse.

        Failure modes:
            Never raises. A column missing from the schema is counted in
            ``missing_column_requests``; a parse failure is counted in
            ``value_parse_errors``.
        """
        if column not in self._column_set:
            self._stats.missing_column_requests += 1
            self._stats.missing_columns.add(column)
            return None
        try:
            result: EseValue = self._record.get(column)
        except Exception as exc:  # malformed value -> counted gap, never a crash
            self._stats.value_parse_errors += 1
            _log.debug("value parse error on column %r: %s", column, type(exc).__name__)
            return None
        return result

    def raw(self, column: str) -> bytes | None:
        """Return the undecoded on-disk bytes of ``column``.

        The escape hatch for data WRAITH must interpret itself later (security
        descriptors, secret blobs). The backend returns the undecoded on-disk
        bytes for *any* present and set column (regardless of its declared JET
        type), so no semantic decoding ever happens here.

        Inputs:
            column: the column name to read as raw bytes.

        Returns:
            The undecoded on-disk bytes, or ``None`` if the column is absent
            from the table schema or unset in this record.

        Failure modes:
            Never raises. A column absent from the schema is counted in
            ``missing_column_requests``; a backend read failure is counted in
            ``raw_read_errors`` and degraded to ``None``.
        """
        if column not in self._column_set:
            self._stats.missing_column_requests += 1
            self._stats.missing_columns.add(column)
            return None
        try:
            value: Any = self._record.get(column, raw=True)
        except Exception as exc:
            self._stats.raw_read_errors += 1
            _log.debug("raw read error on column %r: %s", column, type(exc).__name__)
            return None
        if value is None:
            return None
        if isinstance(value, memoryview):
            return value.tobytes()
        # The backend yields ``bytes`` (or a ``memoryview``) for every present,
        # set column when ``raw=True``; normalise to ``bytes``.
        return bytes(value)

    def as_dict(self) -> dict[str, EseValue]:
        """Return every table column as a ``{column: value}`` dict (absent -> None).

        The keys are exactly the owning table's columns, in catalog order, so
        the shape is identical for every record of a table.
        """
        return {name: self.value(name) for name in self._columns}

    def keys(self) -> tuple[str, ...]:
        """Return the owning table's column names (enables ``dict(record)``).

        Together with :meth:`__getitem__` this makes ``dict(record)`` produce
        the same ``{column: value}`` mapping as :meth:`as_dict`.
        """
        return self._columns

    def get(self, column: str, default: EseValue = None) -> EseValue:
        """Dict-style accessor: parsed value, or ``default`` if ``None``."""
        result = self.value(column)
        return default if result is None else result

    def __getitem__(self, column: str) -> EseValue:
        """Mapping access; returns ``None`` for an unknown column (counted)."""
        return self.value(column)

    def __contains__(self, column: object) -> bool:
        """``True`` iff ``column`` is a column of the owning table's schema."""
        return column in self._column_set

    def __iter__(self) -> Iterator[str]:
        """Iterate the owning table's column names, in catalog order."""
        return iter(self._columns)

    def __len__(self) -> int:
        """The number of columns in the owning table's schema."""
        return len(self._columns)


class EseTable:
    """A table in an ESE database: metadata plus a lazy record stream."""

    __slots__ = ("_table", "_columns", "_stats")

    def __init__(
        self,
        table: Any,  # noqa: ANN401 - untyped backend table (dissect ships no stubs)
        stats: _CoverageStats,
    ) -> None:
        self._table = table
        self._columns: tuple[str, ...] = tuple(table.column_names)
        self._stats = stats

    @property
    def name(self) -> str:
        """The table name as stored in the ESE catalog."""
        name: str = self._table.name
        return name

    @property
    def column_names(self) -> tuple[str, ...]:
        """The table's column names, in catalog order."""
        return self._columns

    def records(self) -> Iterator[EseRecord]:
        """Lazily stream every record of this table in primary-index order.

        Backed by the ``dissect`` primary-index leaf walk (DNT order for NTDS),
        so iteration is deterministic and uses bounded memory regardless of
        table size. Each yielded :class:`EseRecord` shares the handle's coverage
        counters.

        Yields:
            One :class:`EseRecord` per stored record.

        Failure modes:
            Propagates only catastrophic backend errors (e.g. a truncated page
            structure). Per-value parse failures are handled lazily inside
            :class:`EseRecord` and counted, not raised.
        """
        for backend_record in self._table.records():
            self._stats.records_yielded += 1
            yield EseRecord(backend_record, self._columns, self._stats)


class EseHandle:
    """An open ESE database. Use as a context manager to guarantee close.

    Obtain via :meth:`EseBackend.open` / :func:`open_ese`. Owns the underlying
    file handle and the backend database object, and accumulates coverage/skip
    counters across all tables read through it.
    """

    __slots__ = ("_db", "_fh", "_source_path", "_stats")

    def __init__(
        self,
        db: Any,  # noqa: ANN401 - untyped backend database (dissect ships no stubs)
        fh: Any,  # noqa: ANN401 - untyped binary file handle owned by the backend
        source_path: Path,
        stats: _CoverageStats,
    ) -> None:
        self._db = db
        self._fh = fh
        self._source_path = source_path
        self._stats = stats

    @property
    def source_path(self) -> Path:
        """The resolved absolute path this handle was opened from (provenance)."""
        return self._source_path

    def tables(self) -> list[str]:
        """Return the names of all tables in the database, in catalog order.

        Returns:
            A list of table-name strings (includes ESE system tables such as
            ``MSysObjects``). Empty if the catalog lists no named tables.

        Failure modes:
            Tables the catalog reports without a name are skipped defensively.
        """
        names: list[str] = []
        for table in self._db.tables():
            table_name = table.name
            if isinstance(table_name, str):
                names.append(table_name)
        return names

    def table(self, name: str) -> EseTable:
        """Resolve a table by name.

        Inputs:
            name: the exact catalog table name (case-sensitive).

        Returns:
            An :class:`EseTable` wrapper. Increments ``tables_opened``.

        Failure modes:
            Raises :class:`EseTableNotFoundError` if no table of that name
            exists (the backend's ``KeyError`` is translated).
        """
        try:
            backend_table = self._db.table(name)
        except KeyError as exc:
            raise EseTableNotFoundError(f"no ESE table named {name!r}") from exc
        self._stats.tables_opened += 1
        return EseTable(backend_table, self._stats)

    def database_state(self) -> DatabaseState:
        """Read the ESE header consistency state (clean/dirty); see Module 1.

        Returns:
            A :class:`DatabaseState` with the raw ``dbstate`` plus a best-effort
            clean/dirty interpretation and the required-log generations. The
            dirty-state mapping is flagged UNCONFIRMED via
            :attr:`DatabaseState.mapping_confirmed`.

        Failure modes:
            Raises :class:`EseError` if the header cannot be read (a header that
            was already validated at open time, so this is near-unreachable).
        """
        try:
            header = self._db.header
            raw_dbstate = int(header.dbstate)
            gen_min = int(header.lGenMinRequired)
            gen_max = int(header.lGenMaxRequired)
        except Exception as exc:  # pragma: no cover - header validated at open
            raise EseError("failed to read ESE database header state") from exc
        return _interpret_dbstate(raw_dbstate, gen_min, gen_max)

    def coverage(self) -> CoverageReport:
        """Return an immutable snapshot of this handle's coverage/skip counters."""
        return _snapshot(self._stats)

    def close(self) -> None:
        """Close the underlying file handle. Idempotent."""
        fh = self._fh
        if fh is not None:
            self._fh = None
            fh.close()

    def __enter__(self) -> EseHandle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def open_ese(path: Path | str) -> EseHandle:
    """Open an ESE database file and return an :class:`EseHandle`.

    The input is treated as untrusted (CLAUDE.md): the path is resolved and
    proven to be an existing regular file before any bytes are read, and only
    local file I/O is performed (no network).

    Inputs:
        path: filesystem path to an ESE ``.edb`` / ``.dit`` file.

    Returns:
        An open :class:`EseHandle`. The caller owns it and must ``close()`` it
        (or use it as a context manager).

    Failure modes:
        Raises :class:`EseOpenError` if the path is not an existing regular
        file, cannot be opened, or is not a valid ESE database. The file handle
        is closed before the error propagates, so no descriptor leaks.
    """
    # Imported lazily to avoid a hard dependency cycle and to keep the backend
    # module import graph flat; `ensure_existing_file` is Module 1 (gated).
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        resolved = ensure_existing_file(path)
    except PathSafetyError as exc:
        raise EseOpenError(str(exc)) from exc

    try:
        fh = resolved.open("rb")
    except OSError as exc:
        raise EseOpenError(f"cannot open ESE file {resolved}: {exc}") from exc

    try:
        db = _BackendEse(fh)
    except _BackendInvalidDatabase as exc:
        fh.close()
        raise EseOpenError(f"not a valid ESE database: {resolved} ({exc})") from exc
    except Exception as exc:  # defensive: any backend parse error at open
        fh.close()
        raise EseOpenError(f"failed to open ESE database {resolved}: {exc}") from exc

    return EseHandle(db, fh, resolved, _CoverageStats())


class EseBackend:
    """The swappable ESE backend entry point.

    A deliberately tiny seam: downstream code depends on ``EseBackend.open`` and
    the typed wrappers, never on the concrete ``dissect`` class. Swapping the
    backend means editing only the isolated import block at the top of this
    module. :attr:`module` / :attr:`class_name` are derived from the live
    backend class (not hand-typed), so they can never silently desync from the
    actual import; they report which backend is live for provenance/diagnostics.
    """

    module: str = _BACKEND_MODULE
    class_name: str = _BACKEND_CLASS

    @staticmethod
    def open(path: Path | str) -> EseHandle:
        """Open ``path`` as an ESE database (see :func:`open_ese`)."""
        return open_ese(path)


def database_state(handle: EseHandle) -> DatabaseState:
    """Module-level convenience: read the clean/dirty state of ``handle``.

    Equivalent to ``handle.database_state()``; provided to match the adapter
    spec's free-function naming.
    """
    return handle.database_state()


def raw(record: EseRecord, column: str) -> bytes | None:
    """Module-level convenience for the raw-bytes escape hatch.

    Equivalent to ``record.raw(column)``; provided to match the adapter spec's
    free-function naming. Returns the stored bytes of ``column`` without
    decoding, or ``None`` (absent/unset/non-byte/failed — counted, never
    raised).
    """
    return record.raw(column)
