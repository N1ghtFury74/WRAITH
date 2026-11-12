"""Foundation gate — case workspace, case.json, run-manifest immutability.

Workspace containment (NFR-10), manifest write-once immutability + round-trip,
and case config round-trip.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from wraith.acquisition.paths import PathSafetyError
from wraith.case.case import CaseConfig, load_case_config, write_case_config
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput, load_run_manifest, write_run_manifest
from wraith.case.workspace import create_workspace, load_workspace

_IMG = "a" * 64
_FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

_SUBDIRS = ("manifest", "artifacts", "secrets", "exports", "dossiers", "logs", "provenance")


# --------------------------- workspace -------------------------------------


def test_create_workspace_builds_tree(tmp_path) -> None:  # noqa: ANN001
    ws = create_workspace(tmp_path / "cases", "case1")
    assert ws.root.is_dir()
    for sub in _SUBDIRS:
        assert (ws.root / sub).is_dir()
    # every workspace path stays within the case root
    for p in (
        ws.case_json,
        ws.manifest_dir,
        ws.artifacts_dir,
        ws.canonical_db,
        ws.secrets_dir,
        ws.keyring_json,
        ws.secret_store_db,
        ws.exports_dir,
        ws.dossiers_dir,
        ws.logs_dir,
        ws.provenance_dir,
    ):
        assert p.resolve().is_relative_to(ws.root.resolve())


def test_create_workspace_rejects_unsafe_case_id(tmp_path) -> None:  # noqa: ANN001
    with pytest.raises(PathSafetyError):
        create_workspace(tmp_path / "cases", "../evil")


def test_create_workspace_refuses_existing(tmp_path) -> None:  # noqa: ANN001
    create_workspace(tmp_path / "cases", "case1")
    with pytest.raises(FileExistsError):
        create_workspace(tmp_path / "cases", "case1")


def test_load_workspace_missing_raises(tmp_path) -> None:  # noqa: ANN001
    with pytest.raises(FileNotFoundError):
        load_workspace(tmp_path / "cases", "ghost")


# --------------------------- case.json -------------------------------------


def test_case_config_round_trip(tmp_path) -> None:  # noqa: ANN001
    ws = create_workspace(tmp_path / "cases", "case1")
    cfg = CaseConfig(
        case_id="case1",
        operator="alice",
        authorization_ref="ENG-2026-01",
        created_at=_FIXED,
        forest_id_map={"corp.local": "F1"},
    )
    write_case_config(ws.case_json, cfg)
    loaded = load_case_config(ws.case_json)
    assert loaded == cfg
    # written with LF newlines, UTF-8
    assert b"\r\n" not in ws.case_json.read_bytes()


# --------------------------- manifest immutability -------------------------


def _manifest():  # noqa: ANN202
    run = IngestRun("case1", "alice", ingest_run_id=uuid4(), started_at=_FIXED)
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref="/x/ntds.dit",
            size_bytes=10,
            image_sha256=_IMG,
        )
    )
    return run.to_manifest(finished_at=_FIXED)


def test_manifest_write_once_and_latest(tmp_path) -> None:  # noqa: ANN001
    ws = create_workspace(tmp_path / "cases", "case1")
    manifest = _manifest()
    run_path = write_run_manifest(ws.manifest_dir, manifest)
    assert run_path.exists()
    assert ws.latest_manifest.exists()
    assert ws.latest_manifest.read_text(encoding="utf-8") == run_path.read_text(encoding="utf-8")


def test_manifest_refuses_overwrite(tmp_path) -> None:  # noqa: ANN001
    ws = create_workspace(tmp_path / "cases", "case1")
    manifest = _manifest()
    write_run_manifest(ws.manifest_dir, manifest)
    with pytest.raises(FileExistsError):
        write_run_manifest(ws.manifest_dir, manifest)  # same run id => immutable


def test_manifest_round_trip(tmp_path) -> None:  # noqa: ANN001
    ws = create_workspace(tmp_path / "cases", "case1")
    manifest = _manifest()
    run_path = write_run_manifest(ws.manifest_dir, manifest)
    loaded = load_run_manifest(run_path)
    assert loaded == manifest
