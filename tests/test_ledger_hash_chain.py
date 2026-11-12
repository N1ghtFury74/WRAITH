"""Schema v1.1 — provenance-ledger hash-chain (§2.4) unit tests.

Proves the tamper-evidence guarantee: a clean chain verifies; mutating a row's
content breaks verification at EXACTLY that link (and nowhere else); the chain is
deterministic (identical inputs -> identical ``entry_hash`` sequence across a
fresh DB); and the genesis sentinel anchors the first row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from wraith.model.store import open_canonical_store
from wraith.provenance.ledger import (
    GENESIS_PREV_HASH,
    LedgerRow,
    read_ledger_rows,
    verify_ledger_chain,
    write_ledger_rows,
)

_FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_IMG = "a" * 64
_IMG2 = "b" * 64


def _rows(run_id) -> list[LedgerRow]:  # noqa: ANN001
    return [
        LedgerRow(
            ingest_run_id=run_id,
            source_file="ntds.dit",
            image_sha256=_IMG,
            acquired_at=_FIXED,
            tool_versions={"wraith": "0.1.0"},
            parameters={"mode": "copy"},
            coverage_counts={"n": 1},
            skip_counts={"s": 0},
            ingested_at=_FIXED,
        ),
        LedgerRow(
            ingest_run_id=run_id,
            source_file="SYSTEM",
            image_sha256=_IMG2,
            ingested_at=_FIXED,
        ),
    ]


def test_clean_chain_verifies(tmp_path) -> None:  # noqa: ANN001
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        write_ledger_rows(con, _rows(uuid4()))
        report = verify_ledger_chain(con)
        assert report.ok is True
        assert report.breaks == ()
    finally:
        con.close()


def test_first_row_anchors_to_genesis(tmp_path) -> None:  # noqa: ANN001
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        write_ledger_rows(con, _rows(uuid4()))
        rows = sorted(read_ledger_rows(con), key=lambda r: r.source_file)
        # Canonical order is (ingest_run_id, source_file): "SYSTEM" < "ntds.dit".
        system = next(r for r in rows if r.source_file == "SYSTEM")
        ntds = next(r for r in rows if r.source_file == "ntds.dit")
        assert system.prev_entry_hash == GENESIS_PREV_HASH
        assert ntds.prev_entry_hash == system.entry_hash
        assert system.entry_hash is not None and ntds.entry_hash is not None
    finally:
        con.close()


def test_mutated_row_breaks_exactly_that_link(tmp_path) -> None:  # noqa: ANN001
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        write_ledger_rows(con, _rows(uuid4()))
        # Tamper with one row's content WITHOUT touching its stored entry_hash.
        con.execute(
            "UPDATE provenance_ledger SET image_sha256=? WHERE source_file='SYSTEM'",
            ["c" * 64],
        )
        report = verify_ledger_chain(con)
        assert report.ok is False
        offenders = {(b.source_file, b.reason) for b in report.breaks}
        assert ("SYSTEM", "entry_mismatch") in offenders
        # The untampered row must NOT be reported (break localized to the link).
        assert all(b.source_file != "ntds.dit" for b in report.breaks)
    finally:
        con.close()


def test_chain_is_deterministic(tmp_path) -> None:  # noqa: ANN001
    run_id = uuid4()
    hashes = []
    for name in ("a.duckdb", "b.duckdb"):
        con = open_canonical_store(tmp_path / name)
        try:
            write_ledger_rows(con, _rows(run_id))
            rows = sorted(read_ledger_rows(con), key=lambda r: r.source_file)
            hashes.append([r.entry_hash for r in rows])
        finally:
            con.close()
    assert hashes[0] == hashes[1]
