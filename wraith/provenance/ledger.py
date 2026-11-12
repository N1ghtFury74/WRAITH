"""The normalized provenance ledger (schema §2.4) — DuckDB physical design.

Write-once, append-only, one row per ``(ingest_run_id, source_file)``. The
table itself is created by ``wraith.model.store`` (the canonical-store
bootstrap); this module owns the row shape, the writer, the reader, and the
in-code referential-integrity validator (DuckDB's FK enforcement is weak, so
the ``ingest_run_id`` link to embedded provenance structs is validated here).

Integrity boundary (honest statement of guarantees): artifact *bytes* are
cryptographically sealed — each row records the SHA-256 (``image_sha256``) of
its source artifact, so any change to the acquired bytes is detectable. The
custody *records* themselves are now also tamper-evident: schema v1.1
(owner-approved 2026-10-26 at M6) adds a deterministic SHA-256 **hash-chain**
over the ledger rows. Each row carries ``entry_hash`` = SHA-256 over this row's
canonical content fields + the previous row's ``entry_hash`` (``prev_entry_hash``,
or a genesis sentinel for the first row), computed on write in a deterministic
row order so identical inputs produce an identical chain.
:func:`verify_ledger_chain` recomputes the chain and reports the exact link at
which any mutation breaks it. Both chain columns are NULLABLE/additive: a row
written without the chain still reads (the verifier treats a null predecessor as
genesis). Append invariant: each write batch's rows must sort strictly after all
existing rows in canonical ``(ingest_run_id, source_file)`` order so the chain
stays a prefix-extendable sequence (trivially true for the fresh-DB-per-run case).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from uuid import UUID

import duckdb
from pydantic import BaseModel, ConfigDict, field_validator

from wraith.common.determinism import canonical_json, sha256_hex
from wraith.common.validators import validate_sha256_hex

#: Ordered ledger columns, used by the writer/reader so SQL and the model never
#: drift apart. Mirrors the §2.4 DDL created in ``wraith.model.store``. The two
#: trailing chain columns (``prev_entry_hash``, ``entry_hash``) are schema v1.1.
LEDGER_COLUMNS: tuple[str, ...] = (
    "ingest_run_id",
    "source_file",
    "image_sha256",
    "acquired_at",
    "tool_versions",
    "parameters",
    "db_state",
    "coverage_counts",
    "skip_counts",
    "ingested_at",
    "prev_entry_hash",
    "entry_hash",
)

#: Genesis sentinel used as the ``prev_entry_hash`` of the first chained row
#: (a SHA-256-shaped all-zero string — unambiguous, deterministic, no network).
GENESIS_PREV_HASH: str = "0" * 64

#: Content columns hashed into ``entry_hash`` (everything except the chain
#: columns themselves; ``prev_entry_hash`` is mixed in separately as the link).
_CONTENT_COLUMNS: tuple[str, ...] = tuple(
    col for col in LEDGER_COLUMNS if col not in {"prev_entry_hash", "entry_hash"}
)

_JSON_COLUMNS = frozenset({"tool_versions", "parameters", "coverage_counts", "skip_counts"})

#: ``TIMESTAMPTZ`` columns. DuckDB's native TIMESTAMPTZ->``datetime`` conversion
#: on ``fetchall()`` requires ``pytz`` (intentionally NOT a WRAITH dependency —
#: offline/minimal-deps). The reader therefore casts these to text engine-side
#: (``::VARCHAR``, rendered without pytz) and parses them back to a tz-aware UTC
#: ``datetime`` in :func:`_params_to_row`. The frozen §2.4 DDL stays TIMESTAMPTZ.
_TIMESTAMPTZ_COLUMNS = frozenset({"acquired_at", "ingested_at"})


def _select_expr() -> str:
    """Build the SELECT list, casting TIMESTAMPTZ columns to text (pytz-free).

    Column order is preserved exactly as ``LEDGER_COLUMNS`` so positional
    mapping in :func:`_params_to_row` is unaffected.
    """
    return ", ".join(
        f"{col}::VARCHAR" if col in _TIMESTAMPTZ_COLUMNS else col for col in LEDGER_COLUMNS
    )


class LedgerRow(BaseModel):
    """One auditable chain-of-custody row (§2.4): one artifact, one run.

    Fields map 1:1 to ``provenance_ledger``. ``db_state`` is reserved for
    Module 2 (clean/dirty) and is ``None`` in v1. The JSON-valued fields are
    modelled as typed mappings here and serialized canonically on write.

    Failure modes:
        Raises ``pydantic.ValidationError`` if ``image_sha256`` is malformed or
        a required field is missing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ingest_run_id: UUID
    source_file: str
    image_sha256: str
    acquired_at: datetime | None = None
    tool_versions: Mapping[str, str] = {}
    parameters: Mapping[str, object] = {}
    db_state: str | None = None
    coverage_counts: Mapping[str, int] = {}
    skip_counts: Mapping[str, int] = {}
    ingested_at: datetime
    prev_entry_hash: str | None = None
    entry_hash: str | None = None

    @field_validator("image_sha256")
    @classmethod
    def _image_sha256_wellformed(cls, value: str) -> str:
        return validate_sha256_hex(value)


class LedgerIntegrityReport(BaseModel):
    """Result of validating that referenced run ids exist in the ledger.

    Fields:
        ok: ``True`` iff every referenced ``ingest_run_id`` has a ledger row.
        known_run_ids: the set of run ids present in the ledger.
        missing_run_ids: referenced run ids with no ledger row (a gap).
    """

    model_config = ConfigDict(frozen=True)

    ok: bool
    known_run_ids: frozenset[UUID]
    missing_run_ids: frozenset[UUID]


class LedgerChainBreak(BaseModel):
    """One broken link in the ledger hash-chain (schema v1.1).

    Fields:
        ingest_run_id: the run id of the row whose link failed.
        source_file: the source-file key of that row (completes the PK).
        reason: a short machine-stable reason
            (``"prev_mismatch"`` — the stored ``prev_entry_hash`` does not equal
            the running chain head; ``"entry_mismatch"`` — the recomputed
            ``entry_hash`` does not equal the stored one; ``"missing_entry_hash"``
            — the row carries no ``entry_hash`` so the chain cannot continue).
    """

    model_config = ConfigDict(frozen=True)

    ingest_run_id: UUID
    source_file: str
    reason: str


class LedgerChainReport(BaseModel):
    """Result of verifying the ledger hash-chain (schema v1.1).

    Fields:
        ok: ``True`` iff the recomputed chain matches every stored row exactly.
        breaks: the links that failed, in canonical row order (empty iff ``ok``).
    """

    model_config = ConfigDict(frozen=True)

    ok: bool
    breaks: tuple[LedgerChainBreak, ...]


def write_ledger_rows(con: duckdb.DuckDBPyConnection, rows: Sequence[LedgerRow]) -> int:
    """Append ledger rows write-once, stamping the deterministic hash-chain.

    Each row is chained in canonical ``(ingest_run_id, source_file)`` order: its
    ``prev_entry_hash`` is the previous row's ``entry_hash`` (the existing ledger
    tail, or :data:`GENESIS_PREV_HASH` for the very first row), and its
    ``entry_hash`` is :func:`_compute_entry_hash` over its content fields +
    ``prev_entry_hash``. Any ``prev_entry_hash`` / ``entry_hash`` supplied on an
    input row is ignored and recomputed, so identical inputs → identical chain.

    Inputs:
        con: an open connection to ``canonical.duckdb`` whose
            ``provenance_ledger`` table already exists (see ``wraith.model``).
        rows: the rows to insert.

    Returns:
        The number of rows inserted.

    Failure modes:
        Raises ``duckdb.ConstraintException`` if a ``(ingest_run_id,
        source_file)`` primary key already exists (re-ingest must use a new
        ``ingest_run_id``); the whole batch is wrapped in a transaction so a
        conflict leaves the ledger unchanged.
    """
    if not rows:
        return 0
    chained = _chain_rows(rows, prev_head=_current_chain_tail(con))
    placeholders = ", ".join("?" for _ in LEDGER_COLUMNS)
    # Columns are module constants (LEDGER_COLUMNS); all values are parameterized.
    column_list = ", ".join(LEDGER_COLUMNS)
    sql = f"INSERT INTO provenance_ledger ({column_list}) VALUES ({placeholders})"  # noqa: S608
    con.execute("BEGIN TRANSACTION")
    try:
        for row in chained:
            con.execute(sql, _row_to_params(row))
    except Exception:
        con.execute("ROLLBACK")
        raise
    con.execute("COMMIT")
    return len(chained)


def verify_ledger_chain(con: duckdb.DuckDBPyConnection) -> LedgerChainReport:
    """Recompute the ledger hash-chain and report any tampering (schema v1.1).

    Reads every ledger row, orders them canonically by
    ``(ingest_run_id, source_file)``, and walks the chain from
    :data:`GENESIS_PREV_HASH`. For each row it checks that the stored
    ``prev_entry_hash`` equals the running chain head and that the recomputed
    ``entry_hash`` equals the stored value; any mismatch is recorded as a
    :class:`LedgerChainBreak` at exactly that link.

    Inputs:
        con: an open ``canonical.duckdb`` connection.

    Returns:
        A :class:`LedgerChainReport`; ``ok`` is ``True`` and ``breaks`` empty for
        an untampered chain.

    Failure modes:
        Raises ``duckdb.Error`` if the ledger table does not exist.
    """
    rows = _canonical_order(read_ledger_rows(con))
    breaks: list[LedgerChainBreak] = []
    head = GENESIS_PREV_HASH
    for row in rows:
        stored_prev = row.prev_entry_hash if row.prev_entry_hash is not None else GENESIS_PREV_HASH
        if stored_prev != head:
            breaks.append(_break(row, "prev_mismatch"))
        if row.entry_hash is None:
            breaks.append(_break(row, "missing_entry_hash"))
            head = GENESIS_PREV_HASH
            continue
        recomputed = _compute_entry_hash(row, stored_prev)
        if recomputed != row.entry_hash:
            breaks.append(_break(row, "entry_mismatch"))
        # Continue from the STORED entry_hash so a single mutated row breaks only
        # its own link (and the next row's prev check), not the whole tail.
        head = row.entry_hash
    return LedgerChainReport(ok=not breaks, breaks=tuple(breaks))


def read_ledger_rows(
    con: duckdb.DuckDBPyConnection, ingest_run_id: UUID | None = None
) -> list[LedgerRow]:
    """Read ledger rows, optionally filtered to one ingest run.

    Inputs:
        con: an open ``canonical.duckdb`` connection.
        ingest_run_id: if given, return only that run's rows; else all rows,
            ordered deterministically by ``(ingest_run_id, source_file)``.

    Returns:
        A list of ``LedgerRow`` (possibly empty).

    Failure modes:
        Raises ``duckdb.Error`` if the table does not exist.
    """
    cols = _select_expr()  # constant identifiers; TIMESTAMPTZ cast to text
    if ingest_run_id is None:
        cur = con.execute(
            f"SELECT {cols} FROM provenance_ledger "  # noqa: S608 (constant identifiers)
            "ORDER BY ingest_run_id, source_file"
        )
    else:
        cur = con.execute(
            f"SELECT {cols} FROM provenance_ledger "  # noqa: S608 (constant identifiers)
            "WHERE ingest_run_id = ? ORDER BY source_file",
            [str(ingest_run_id)],
        )
    return [_params_to_row(record) for record in cur.fetchall()]


def validate_referential_integrity(
    con: duckdb.DuckDBPyConnection, referenced_run_ids: Sequence[UUID]
) -> LedgerIntegrityReport:
    """Check that every referenced ``ingest_run_id`` exists in the ledger.

    Enforces the §2.4 logical join in code because DuckDB FK enforcement is
    weak. Every distinct ``ingest_run_id`` embedded on a downstream row must be
    resolvable to a ledger row; any that is not is surfaced as a gap.

    Inputs:
        con: an open ``canonical.duckdb`` connection.
        referenced_run_ids: run ids observed on embedded provenance structs.

    Returns:
        A ``LedgerIntegrityReport`` with ``ok`` false iff any id is missing.

    Failure modes:
        Raises ``duckdb.Error`` if the ledger table does not exist.
    """
    rows = con.execute("SELECT DISTINCT ingest_run_id FROM provenance_ledger").fetchall()
    known = {UUID(str(row[0])) for row in rows}
    referenced = set(referenced_run_ids)
    missing = referenced - known
    return LedgerIntegrityReport(
        ok=not missing,
        known_run_ids=frozenset(known),
        missing_run_ids=frozenset(missing),
    )


def _row_to_params(row: LedgerRow) -> list[object]:
    """Flatten a ``LedgerRow`` into positional DuckDB bind params.

    JSON-valued columns are serialized with the one canonical JSON form; the
    UUID is bound as text so behavior is identical across DuckDB versions.
    """
    values: dict[str, object] = row.model_dump()
    params: list[object] = []
    for col in LEDGER_COLUMNS:
        value = values[col]
        if col == "ingest_run_id":
            params.append(str(value))
        elif col in _JSON_COLUMNS:
            params.append(canonical_json(value))
        else:
            params.append(value)
    return params


def _params_to_row(record: tuple[object, ...]) -> LedgerRow:
    """Rebuild a ``LedgerRow`` from a fetched DuckDB record (JSON parsed back)."""
    mapping: dict[str, object] = {}
    for col, value in zip(LEDGER_COLUMNS, record, strict=True):
        if col in _JSON_COLUMNS and isinstance(value, str):
            mapping[col] = json.loads(value)
        elif col in _TIMESTAMPTZ_COLUMNS and isinstance(value, str):
            # Parse the engine-rendered offset form and normalize to UTC so the
            # read-back is host-independent (same instant, microsecond-exact).
            mapping[col] = datetime.fromisoformat(value).astimezone(UTC)
        else:
            mapping[col] = value
    return LedgerRow.model_validate(mapping)


# --------------------------- hash-chain (schema v1.1) ----------------------


def _utc_iso(value: datetime | None) -> str | None:
    """Render a timestamp as a UTC-normalized ISO-8601 string (chain-stable).

    The ledger stores TIMESTAMPTZ and reads it back UTC-normalized
    (:func:`_params_to_row`). Hashing a UTC-normalized rendering at both write
    and verify time makes ``entry_hash`` invariant across the DB round-trip
    regardless of the input/session timezone. A naive datetime is treated as UTC
    (the store's timestamp policy), so the chain stays deterministic.
    """
    if value is None:
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def _compute_entry_hash(row: LedgerRow, prev_entry_hash: str) -> str:
    """Compute a row's deterministic ``entry_hash`` (SHA-256 over content + link).

    The hash covers every content column (``_CONTENT_COLUMNS``) in a canonical,
    round-trip-stable form plus ``prev_entry_hash``; the ``entry_hash`` /
    ``prev_entry_hash`` columns themselves are excluded (``prev`` is mixed in as
    the link). Timestamps are UTC-normalized (:func:`_utc_iso`), the UUID is its
    canonical string, and the JSON-valued mappings go through the one canonical
    JSON form — so identical content yields an identical hash on every host.
    """
    payload: dict[str, object | None] = {
        "ingest_run_id": str(row.ingest_run_id),
        "source_file": row.source_file,
        "image_sha256": row.image_sha256,
        "acquired_at": _utc_iso(row.acquired_at),
        "tool_versions": dict(row.tool_versions),
        "parameters": dict(row.parameters),
        "db_state": row.db_state,
        "coverage_counts": dict(row.coverage_counts),
        "skip_counts": dict(row.skip_counts),
        "ingested_at": _utc_iso(row.ingested_at),
        "prev_entry_hash": prev_entry_hash,
    }
    return sha256_hex(canonical_json(payload).encode("utf-8"))


def _canonical_order(rows: Sequence[LedgerRow]) -> list[LedgerRow]:
    """Order rows by ``(str(ingest_run_id), source_file)`` — the chain order.

    String-keyed on the UUID so write-time and verify-time ordering agree
    independently of DuckDB's internal UUID collation.
    """
    return sorted(rows, key=lambda r: (str(r.ingest_run_id), r.source_file))


def _chain_rows(rows: Sequence[LedgerRow], prev_head: str) -> list[LedgerRow]:
    """Return rows in chain order with ``prev_entry_hash`` / ``entry_hash`` set.

    Any chain fields already present on the inputs are overwritten so the chain
    is a pure function of the content + the existing ledger tail (``prev_head``).
    """
    head = prev_head
    chained: list[LedgerRow] = []
    for row in _canonical_order(rows):
        entry_hash = _compute_entry_hash(row, head)
        chained.append(row.model_copy(update={"prev_entry_hash": head, "entry_hash": entry_hash}))
        head = entry_hash
    return chained


def _current_chain_tail(con: duckdb.DuckDBPyConnection) -> str:
    """Return the ``entry_hash`` of the last existing row, else the genesis value.

    Lets a later write batch extend the chain of rows already in the ledger
    (append invariant: new rows sort strictly after existing ones in canonical
    order). A tail row with a NULL ``entry_hash`` (legacy/unchained) degrades to
    genesis rather than raising.
    """
    existing = _canonical_order(read_ledger_rows(con))
    if not existing:
        return GENESIS_PREV_HASH
    tail = existing[-1].entry_hash
    return tail if tail is not None else GENESIS_PREV_HASH


def _break(row: LedgerRow, reason: str) -> LedgerChainBreak:
    """Build a :class:`LedgerChainBreak` for ``row`` with the given reason."""
    return LedgerChainBreak(
        ingest_run_id=row.ingest_run_id,
        source_file=row.source_file,
        reason=reason,
    )
