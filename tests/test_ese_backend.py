"""Minimal sanity checks for the ESE reader backend adapter.

These are NOT the full gate (wraith-tester owns that). They only confirm the
adapter wires up against the vendored generic ``.edb`` fixture: open, list
tables, stream records, read a typed value, read raw bytes, normalise a missing
column to ``None`` (counted), and read the clean-shutdown database state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wraith.parsing import (
    EseBackend,
    EseTableNotFoundError,
    database_state,
    open_ese,
    raw,
)

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "ese" / "generic-sample.edb"


def test_backend_identity() -> None:
    assert EseBackend.module == "dissect.database"
    assert EseBackend.class_name == "ESE"


def test_open_lists_tables() -> None:
    with open_ese(_FIXTURE) as handle:
        tables = handle.tables()
        assert "basic" in tables
        assert "MSysObjects" in tables


def test_stream_records_deterministic_and_typed() -> None:
    with open_ese(_FIXTURE) as handle:
        table = handle.table("basic")
        assert "Id" in table.column_names
        rows = [r.as_dict() for r in table.records()]
        assert len(rows) == 2
        # Primary-index order is deterministic: Id ascending.
        assert [row["Id"] for row in rows] == [1, 2]
        # Second pass yields the identical order/content.
        again = [r.as_dict() for r in handle.table("basic").records()]
        assert again == rows


def test_raw_hatch_returns_bytes() -> None:
    with open_ese(_FIXTURE) as handle:
        record = next(iter(handle.table("basic").records()))
        guid_raw = raw(record, "GUID")
        assert isinstance(guid_raw, bytes)
        assert len(guid_raw) == 16  # a GUID is 16 raw bytes, undecoded


def test_missing_column_is_none_and_counted() -> None:
    with open_ese(_FIXTURE) as handle:
        record = next(iter(handle.table("basic").records()))
        assert record.value("NoSuchColumn") is None
        assert record["NoSuchColumn"] is None
        assert raw(record, "NoSuchColumn") is None
        cov = handle.coverage()
        assert cov.missing_column_requests >= 1
        assert "NoSuchColumn" in cov.missing_column_names


def test_missing_table_raises_typed_error() -> None:
    with open_ese(_FIXTURE) as handle:
        with pytest.raises(EseTableNotFoundError):
            handle.table("DefinitelyNotATable")


def test_clean_shutdown_database_state() -> None:
    with open_ese(_FIXTURE) as handle:
        state = database_state(handle)
        assert state.raw_dbstate == 3
        assert state.label == "CleanShutdown"
        assert state.is_clean is True
        assert state.mapping_confirmed is True
