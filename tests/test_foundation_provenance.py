"""Foundation gate — provenance ledger (§2.4) + IngestRun single-source-of-truth.

Layer-3 forensic invariants: the embedded provenance struct, the manifest
artifact row, and the ledger row for one artifact must carry an IDENTICAL
image_sha256 and ingest_run_id; the ledger is append-only with a PK conflict on
re-insert; referential integrity flags a referenced run with no ledger row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import duckdb
import pytest
from pydantic import ValidationError

from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.model.store import open_canonical_store
from wraith.provenance.ledger import (
    LedgerRow,
    read_ledger_rows,
    validate_referential_integrity,
    write_ledger_rows,
)
from wraith.provenance.models import ProvenanceStruct, ScopingBlock

_IMG = "a" * 64
_IMG2 = "b" * 64
_FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _run_with_artifact() -> IngestRun:
    run = IngestRun("case1", "operator", ingest_run_id=uuid4(), started_at=_FIXED)
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref="/cases/case1/artifacts/ntds.dit",
            size_bytes=1024,
            image_sha256=_IMG,
        )
    )
    return run


# --------------------------- shared models ---------------------------------


def test_scoping_block_requires_forest_id() -> None:
    assert ScopingBlock(forest_id="F1").forest_id == "F1"
    with pytest.raises(ValidationError):
        ScopingBlock(forest_id="   ")


def test_provenance_struct_validates_image_sha256() -> None:
    good = ProvenanceStruct(source_file="ntds.dit", image_sha256=_IMG, ingest_run_id=uuid4())
    assert good.image_sha256 == _IMG
    with pytest.raises(ValidationError):
        ProvenanceStruct(source_file="ntds.dit", image_sha256="A" * 64, ingest_run_id=uuid4())


def test_provenance_struct_is_frozen() -> None:
    p = ProvenanceStruct(source_file="ntds.dit", image_sha256=_IMG, ingest_run_id=uuid4())
    with pytest.raises(ValidationError):
        p.source_file = "tampered"  # type: ignore[misc]


# --------------------------- single source of truth ------------------------


def test_provenance_for_unregistered_raises_keyerror() -> None:
    run = _run_with_artifact()
    with pytest.raises(KeyError):
        run.provenance_for("SYSTEM")  # never registered


def test_single_source_of_truth_image_sha256_identical() -> None:
    run = _run_with_artifact()
    prov = run.provenance_for("ntds.dit", source_object_id="DNT-123")
    rows = run.to_ledger_rows(ingested_at=_FIXED)
    manifest = run.to_manifest(finished_at=_FIXED)
    art = manifest.inputs[0]

    assert prov.image_sha256 == art.image_sha256 == rows[0].image_sha256 == _IMG
    assert prov.ingest_run_id == run.ingest_run_id == rows[0].ingest_run_id
    assert art.source_file == rows[0].source_file == prov.source_file == "ntds.dit"


def test_add_artifact_conflicting_hash_rejected() -> None:
    run = _run_with_artifact()
    with pytest.raises(ValueError):
        run.add_artifact(
            ArtifactInput(
                source_file="ntds.dit",  # same logical name
                abs_path_or_ref="/x",
                size_bytes=1,
                image_sha256=_IMG2,  # conflicting hash => ambiguous provenance
            )
        )


# --------------------------- ledger: append-only + PK ----------------------


def test_ledger_pk_conflict_on_duplicate(tmp_path) -> None:  # noqa: ANN001
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        run_id = uuid4()
        row = LedgerRow(
            ingest_run_id=run_id,
            source_file="ntds.dit",
            image_sha256=_IMG,
            ingested_at=_FIXED,
        )
        assert write_ledger_rows(con, [row]) == 1
        # same (ingest_run_id, source_file) => PK conflict, append-only
        with pytest.raises(duckdb.ConstraintException):
            write_ledger_rows(con, [row])
    finally:
        con.close()


def test_ledger_referential_integrity_flags_missing(tmp_path) -> None:  # noqa: ANN001
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        present = uuid4()
        absent = uuid4()
        write_ledger_rows(
            con,
            [
                LedgerRow(
                    ingest_run_id=present,
                    source_file="f",
                    image_sha256=_IMG,
                    ingested_at=_FIXED,
                )
            ],
        )
        report = validate_referential_integrity(con, [present, absent])
        assert report.ok is False
        assert absent in report.missing_run_ids
        assert present in report.known_run_ids
        # all-present => ok
        ok_report = validate_referential_integrity(con, [present])
        assert ok_report.ok is True
        assert ok_report.missing_run_ids == frozenset()
    finally:
        con.close()


def test_ledger_write_read_roundtrip(tmp_path) -> None:  # noqa: ANN001
    """The auditable ledger must be readable back (chain-of-custody view).

    NOTE (gate finding): this exercises read_ledger_rows across the TIMESTAMPTZ
    columns. If it errors, the ledger is write-only on the shipped deps.
    """
    con = open_canonical_store(tmp_path / "canonical.duckdb")
    try:
        run_id = uuid4()
        row = LedgerRow(
            ingest_run_id=run_id,
            source_file="ntds.dit",
            image_sha256=_IMG,
            acquired_at=_FIXED,
            tool_versions={"wraith": "0.1.0"},
            parameters={"mode": "copy", "extract": False},
            coverage_counts={"artifacts_ingested": 1},
            skip_counts={"archive_members_skipped": 0},
            ingested_at=_FIXED,
        )
        write_ledger_rows(con, [row])
        back = read_ledger_rows(con, run_id)
        assert len(back) == 1
        got = back[0]
        assert got.image_sha256 == _IMG
        assert got.source_file == "ntds.dit"
        assert dict(got.tool_versions) == {"wraith": "0.1.0"}
        assert dict(got.parameters) == {"mode": "copy", "extract": False}
        assert dict(got.coverage_counts) == {"artifacts_ingested": 1}
    finally:
        con.close()
