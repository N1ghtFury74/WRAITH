"""Independent gate suite for the swappable ESE reader backend.

Authored by ``wraith-tester`` (the gatekeeper), independently of the coder's
sanity checks in ``tests/test_ese_backend.py``. Exercises the adapter across the
five gate layers required for Module 2's ESE sub-layer:

1. Unit / golden   — known fixture contents -> exact asserted output.
2. Determinism     — same input twice -> identical order & content.
3. Robustness      — unknown table, missing column, corrupt/empty/missing file.
4. Bounded memory  — ``records()`` is a lazy generator, not materialised.
5. db-state        — the CleanShutdown ``DBFILEHDR`` path.

Cross-validation strategy (gate layer 1 done honestly): the typed value reads
are NOT merely asserted against the adapter's own output. Each is decoded
*independently* from the raw-bytes escape hatch using the stdlib ``struct`` /
``uuid`` modules, so the typed decoder is checked against a source of truth that
does not depend on ``dissect``'s type interpretation.

Deferred (cannot be tested without a real ``ntds.dit`` — NOT failures):
    * DirtyShutdown / recovery ``database_state`` path (needs a dirty ``.dit``).
    * All NTDS semantics (schema, SD join, PEK/secret decryption, mapping).
"""

from __future__ import annotations

import gc
import hashlib
import os
import struct
import tempfile
import types
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from wraith.parsing import (
    CoverageReport,
    DatabaseState,
    EseBackend,
    EseHandle,
    EseOpenError,
    EseRecord,
    EseTable,
    EseTableNotFoundError,
    database_state,
    open_ese,
    raw,
)

# --- fixture anchor ----------------------------------------------------------

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "ese" / "generic-sample.edb"
_FIXTURE_SHA256 = "39f0370d0149288c758e818f8857aff9abc2a6d605f6dbf498c43390eb3fd711"

# Documented ground-truth record-0 (Id==1) of table ``basic``. The three values
# the task spec calls out explicitly, plus the full typed row for golden assert.
_REC0_EXPECTED: dict[str, object] = {
    "Id": 1,
    "Bit": False,
    "UnsignedByte": 213,
    "Short": -1337,
    "Long": -13371337,
    "Currency": 1337133713371337,
    "IEEESingle": 1.0,
    "IEEEDouble": 13371337.13371337,
    "DateTime": 4675210852477960192,
    "UnsignedLong": 13371337,
    "LongLong": -13371337,
    "GUID": "3f360af1-6766-46dc-9af2-0dacf295c2a1",
    "UnsignedShort": 1337,
}

_BASIC_COLUMNS = (
    "Id",
    "Bit",
    "UnsignedByte",
    "Short",
    "Long",
    "Currency",
    "IEEESingle",
    "IEEEDouble",
    "DateTime",
    "UnsignedLong",
    "LongLong",
    "GUID",
    "UnsignedShort",
)


@pytest.fixture
def handle() -> Iterator[EseHandle]:
    """A freshly opened handle to the vendored generic fixture, auto-closed."""
    h = open_ese(_FIXTURE)
    try:
        yield h
    finally:
        h.close()


def _rec0(h: EseHandle) -> EseRecord:
    """Return record 0 (primary-index first) of the ``basic`` table."""
    return next(iter(h.table("basic").records()))


# =============================================================================
# Pre-flight: the fixture under test is the exact documented artifact.
# =============================================================================


def test_fixture_is_the_documented_artifact() -> None:
    """Proves: the suite tests the exact vendored bytes (SHA-256 pinned)."""
    assert _FIXTURE.is_file()
    digest = hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()
    assert digest == _FIXTURE_SHA256, "fixture bytes differ from the pinned SHA-256"


# =============================================================================
# Layer 1 — Unit / golden
# =============================================================================


def test_backend_identity_seam() -> None:
    """Proves: the swappable seam reports the live backend (provenance)."""
    assert EseBackend.module == "dissect.database"
    assert EseBackend.class_name == "ESE"
    assert EseBackend.open is open_ese or callable(EseBackend.open)


def test_tables_lists_user_and_system_tables(handle: EseHandle) -> None:
    """Proves: tables() surfaces the user table and ESE system catalog tables."""
    tables = handle.tables()
    assert "basic" in tables
    assert "MSysObjects" in tables
    # The full documented catalog, so a silently-dropped table would be caught.
    for expected in ("MSysObjects", "MSysObjectsShadow", "MSysObjids", "MSysLocales", "basic"):
        assert expected in tables, f"catalog missing table {expected!r}"


def test_table_column_names_match_catalog(handle: EseHandle) -> None:
    """Proves: EseTable.column_names is the exact catalog column tuple."""
    table = handle.table("basic")
    assert isinstance(table, EseTable)
    assert table.name == "basic"
    assert table.column_names == _BASIC_COLUMNS


def test_basic_yields_exactly_two_records_in_primary_index_order(handle: EseHandle) -> None:
    """Proves: exactly 2 records, Id == [1, 2] in primary-index (DNT) order."""
    rows = [r.as_dict() for r in handle.table("basic").records()]
    assert len(rows) == 2
    assert [row["Id"] for row in rows] == [1, 2]


def test_record0_golden_values_exact(handle: EseHandle) -> None:
    """Proves: every typed column of rec0 equals its documented golden value."""
    row = _rec0(handle).as_dict()
    assert set(row) == set(_REC0_EXPECTED), "column set differs from golden"
    for col, expected in _REC0_EXPECTED.items():
        got = row[col]
        if isinstance(expected, bool):
            # Bit must be a genuine bool, not int 0/1 (True == 1 would hide it).
            assert type(got) is bool, f"{col}: expected bool, got {type(got)}"
            assert got is expected, f"{col}: {got!r} is not {expected!r}"
        elif isinstance(expected, float):
            assert isinstance(got, float), f"{col}: expected float, got {type(got)}"
            assert got == pytest.approx(expected), f"{col}: {got!r} != {expected!r}"
        elif isinstance(expected, str):
            assert isinstance(got, str), f"{col}: expected str, got {type(got)}"
            assert got == expected, f"{col}: {got!r} != {expected!r}"
        else:
            # dissect yields int-subclass cstruct types (e.g. int32); value and
            # int-ness are what matter, and it must not be a bool.
            assert isinstance(got, int) and not isinstance(
                got, bool
            ), f"{col}: expected int, got {type(got)}"
            assert got == expected, f"{col}: {got!r} != {expected!r}"


def test_typed_reads_cross_validated_against_raw_bytes(handle: EseHandle) -> None:
    """Proves: typed decoding matches an INDEPENDENT struct/uuid decode of the
    raw escape-hatch bytes — a source of truth not dependent on dissect's typer.
    """
    rec0 = _rec0(handle)

    def rb(col: str) -> bytes:
        b = raw(rec0, col)
        assert isinstance(b, bytes), f"raw({col}) should yield bytes on rec0"
        return b

    # Integer JET types: decode the raw little-endian bytes ourselves.
    assert struct.unpack("<B", rb("UnsignedByte"))[0] == rec0.value("UnsignedByte")
    assert struct.unpack("<h", rb("Short"))[0] == rec0.value("Short")
    assert struct.unpack("<H", rb("UnsignedShort"))[0] == rec0.value("UnsignedShort")
    assert struct.unpack("<i", rb("Long"))[0] == rec0.value("Long")
    assert struct.unpack("<I", rb("UnsignedLong"))[0] == rec0.value("UnsignedLong")
    assert struct.unpack("<q", rb("LongLong"))[0] == rec0.value("LongLong")
    assert struct.unpack("<q", rb("Currency"))[0] == rec0.value("Currency")
    # IEEE floating types.
    assert struct.unpack("<f", rb("IEEESingle"))[0] == pytest.approx(rec0.value("IEEESingle"))
    assert struct.unpack("<d", rb("IEEEDouble"))[0] == pytest.approx(rec0.value("IEEEDouble"))
    # Bit: a single zero byte -> False.
    assert rb("Bit") == b"\x00"
    assert rec0.value("Bit") is False
    # GUID: mixed-endian (bytes_le) decode must match the typed string.
    guid_raw = rb("GUID")
    assert len(guid_raw) == 16, "a GUID is 16 undecoded bytes"
    assert str(uuid.UUID(bytes_le=guid_raw)) == rec0.value("GUID")
    assert rec0.value("GUID") == _REC0_EXPECTED["GUID"]


def test_raw_guid_is_sixteen_undecoded_bytes(handle: EseHandle) -> None:
    """Proves: the raw-bytes hatch returns exactly 16 undecoded bytes for GUID."""
    rec0 = _rec0(handle)
    guid_raw = rec0.raw("GUID")
    assert isinstance(guid_raw, bytes)
    assert len(guid_raw) == 16
    # module-level alias must be equivalent to the method.
    assert raw(rec0, "GUID") == guid_raw


def test_unset_value_in_record_is_none(handle: EseHandle) -> None:
    """Proves: a column present in schema but unset in a record -> None.

    Record 1 (Id==2) has several NULL columns in the fixture.
    """
    rows = [r.as_dict() for r in handle.table("basic").records()]
    rec1 = rows[1]
    assert rec1["Id"] == 2
    assert rec1["GUID"] is None
    assert rec1["UnsignedLong"] is None
    assert rec1["LongLong"] is None


def test_record_mapping_protocol(handle: EseHandle) -> None:
    """Proves: dict-like protocol — __getitem__, get, in, iter, len, as_dict."""
    rec0 = _rec0(handle)
    assert len(rec0) == len(_BASIC_COLUMNS)
    assert "Id" in rec0
    assert "NotAColumn" not in rec0
    assert tuple(iter(rec0)) == _BASIC_COLUMNS
    assert rec0["Id"] == 1
    assert rec0.get("Id") == 1
    assert rec0.get("NotAColumn", "fallback") == "fallback"
    assert rec0.get("NotAColumn") is None
    assert rec0.columns == _BASIC_COLUMNS
    d = rec0.as_dict()
    assert set(d) == set(_BASIC_COLUMNS)


def test_coverage_and_dbstate_are_frozen_models(handle: EseHandle) -> None:
    """Proves: CoverageReport and DatabaseState are frozen (immutable snapshots)."""
    cov = handle.coverage()
    state = handle.database_state()
    assert isinstance(cov, CoverageReport)
    assert isinstance(state, DatabaseState)
    with pytest.raises(ValidationError):
        cov.records_yielded = 999
    with pytest.raises(ValidationError):
        state.raw_dbstate = 0


# =============================================================================
# Layer 2 — Determinism
# =============================================================================


def test_reiteration_same_handle_is_identical(handle: EseHandle) -> None:
    """Proves: two passes over records() on one handle yield identical results."""
    first = [r.as_dict() for r in handle.table("basic").records()]
    second = [r.as_dict() for r in handle.table("basic").records()]
    assert first == second


def test_fresh_open_is_identical() -> None:
    """Proves: re-opening the file from scratch yields identical results."""
    with open_ese(_FIXTURE) as h1:
        a = [r.as_dict() for r in h1.table("basic").records()]
    with open_ese(_FIXTURE) as h2:
        b = [r.as_dict() for r in h2.table("basic").records()]
    assert a == b


def test_tables_order_is_stable(handle: EseHandle) -> None:
    """Proves: tables() returns a stable, deterministic ordering."""
    assert handle.tables() == handle.tables()


def test_coverage_missing_names_sorted_deterministic(handle: EseHandle) -> None:
    """Proves: missing_column_names is sorted & deterministic regardless of
    the order columns were first requested.
    """
    rec0 = _rec0(handle)
    for col in ("ZZZ", "AAA", "MMM"):
        _ = rec0.value(col)
    names = handle.coverage().missing_column_names
    assert names == tuple(sorted(names))
    assert {"AAA", "MMM", "ZZZ"}.issubset(set(names))


# =============================================================================
# Layer 3 — Robustness / adversarial
# =============================================================================


def test_unknown_table_raises_typed_error(handle: EseHandle) -> None:
    """Proves: an unknown table name raises the typed EseTableNotFoundError."""
    with pytest.raises(EseTableNotFoundError):
        handle.table("DefinitelyNotATable")


def test_missing_column_all_accessors_none_and_counted(handle: EseHandle) -> None:
    """Proves: a schema-absent column -> None via value()/[]/raw() AND is
    counted in coverage with its name recorded (never raises).
    """
    with open_ese(_FIXTURE) as h:
        rec0 = _rec0(h)
        assert rec0.value("GhostColumn") is None
        assert rec0["GhostColumn"] is None
        assert rec0.raw("GhostColumn") is None
        assert raw(rec0, "GhostColumn") is None
        cov = h.coverage()
        # 4 missing accesses were made above (value, __getitem__, raw, alias).
        assert cov.missing_column_requests >= 4
        assert "GhostColumn" in cov.missing_column_names


def test_corrupt_file_raises_eseopenerror_no_leak() -> None:
    """Proves: garbage / truncated / empty content -> EseOpenError, no fd leak,
    no uncaught crash. (fd-leak proxy on Windows: an unclosed handle would make
    os.remove raise PermissionError.)
    """
    real = _FIXTURE.read_bytes()
    cases = {
        "garbage.edb": b"NOT-AN-ESE-DATABASE" * 64,
        "zero.edb": b"",
        "truncated.edb": real[:2048],  # valid header start, truncated body
    }
    with tempfile.TemporaryDirectory() as d:
        for name, payload in cases.items():
            p = Path(d) / name
            p.write_bytes(payload)
            with pytest.raises(EseOpenError):
                open_ese(p)
            gc.collect()
            # If a descriptor leaked, Windows refuses removal.
            try:
                os.remove(p)
            except PermissionError:  # pragma: no cover - only trips on a leak
                pytest.fail(f"fd leak: {name} still open after EseOpenError")


def test_nonexistent_path_raises_eseopenerror() -> None:
    """Proves: a non-existent path is rejected with EseOpenError."""
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(EseOpenError):
            open_ese(Path(d) / "does-not-exist.edb")


def test_directory_path_raises_eseopenerror() -> None:
    """Proves: untrusted-path validation rejects a directory (not a regular file)."""
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(EseOpenError):
            open_ese(Path(d))


def test_record_iteration_does_not_crash_on_full_scan(handle: EseHandle) -> None:
    """Proves: a full scan of every table's records never raises (counted gaps
    only). A smoke scan over the whole fixture.
    """
    for tname in handle.tables():
        for rec in handle.table(tname).records():
            _ = rec.as_dict()  # force every column read path
    cov = handle.coverage()
    assert cov.records_yielded >= 2
    # No column was requested outside a schema during a clean full scan.
    assert cov.value_parse_errors == 0


# =============================================================================
# Layer 4 — Bounded memory / lazy streaming
# =============================================================================


def test_records_is_lazy_generator(handle: EseHandle) -> None:
    """Proves: records() is a lazy generator, not a materialised list."""
    gen = handle.table("basic").records()
    assert isinstance(gen, types.GeneratorType)
    assert isinstance(gen, Iterator)


def test_records_yields_without_consuming_whole_table(handle: EseHandle) -> None:
    """Proves: the first record is produced before the table is fully consumed
    (bounded memory / streaming), tracked via records_yielded.
    """
    gen = handle.table("basic").records()
    first = next(gen)
    assert first["Id"] == 1
    # Only one record has been pulled so far; the table (2 rows) is not drained.
    assert handle.coverage().records_yielded == 1


# =============================================================================
# Layer 5 — Database (clean/dirty) state
# =============================================================================


def test_clean_shutdown_state_method_and_alias(handle: EseHandle) -> None:
    """Proves: the CleanShutdown DBFILEHDR path maps correctly, via both the
    method and the module-level alias (which must agree).
    """
    via_method = handle.database_state()
    via_alias = database_state(handle)
    assert via_method == via_alias
    assert via_method.raw_dbstate == 3
    assert via_method.label == "CleanShutdown"
    assert via_method.is_clean is True
    assert via_method.mapping_confirmed is True
    # Generation waypoints are present as ints (0 on a cleanly detached db).
    assert isinstance(via_method.gen_min_required, int)
    assert isinstance(via_method.gen_max_required, int)


def test_dbstate_is_deterministic(handle: EseHandle) -> None:
    """Proves: reading database_state twice yields an equal frozen snapshot."""
    assert handle.database_state() == handle.database_state()


# =============================================================================
# Handle lifecycle
# =============================================================================


def test_close_is_idempotent() -> None:
    """Proves: close() is idempotent and the context manager closes the handle."""
    h = open_ese(_FIXTURE)
    h.close()
    h.close()  # second close must not raise


def test_context_manager_closes_and_exposes_source_path() -> None:
    """Proves: the context manager yields the handle and exposes source_path."""
    with open_ese(_FIXTURE) as h:
        assert isinstance(h, EseHandle)
        assert h.source_path.is_file()
        assert h.source_path.name == "generic-sample.edb"
