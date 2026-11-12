"""Foundation gate — Layer 3: determinism, offline guarantee, full ingest flow.

Determinism: with a fixed ingest_run_id + fixed timestamps the deterministic
surface (ledger rows, serialized manifest) is byte-identical across two
independent runs. Offline: a full ingest + secret flow completes with every
socket connect patched to fail, proving no network egress on those paths.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import SecretBytes

from wraith.acquisition.ingest import IngestMode, ingest_file
from wraith.case.case import CaseConfig, write_case_config
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput, write_run_manifest
from wraith.case.workspace import create_workspace
from wraith.common.determinism import canonical_json
from wraith.model.store import open_canonical_store
from wraith.provenance.ledger import write_ledger_rows
from wraith.secrets.kdf import KdfAlgorithm
from wraith.secrets.keyring import create_keyring, unwrap_dek, write_keyring
from wraith.secrets.records import SecretType
from wraith.secrets.store import SecretStore

_IMG = "a" * 64
_RUN_ID = UUID("11111111-1111-1111-1111-111111111111")
_STARTED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_FINISHED = datetime(2026, 1, 2, 3, 5, 0, tzinfo=UTC)
_INGESTED = datetime(2026, 1, 2, 3, 5, 1, tzinfo=UTC)


def _fixed_run() -> IngestRun:
    run = IngestRun(
        "case1",
        "alice",
        ingest_run_id=_RUN_ID,
        tool_versions={"wraith": "0.1.0", "python": "3.12.0"},
        parameters={"mode": "copy", "extract": False},
        started_at=_STARTED,
    )
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref="/cases/case1/artifacts/ntds.dit",
            size_bytes=4096,
            image_sha256=_IMG,
        )
    )
    run.bump_coverage("artifacts_ingested")
    return run


def test_determinism_ledger_rows_byte_identical() -> None:
    a = _fixed_run().to_ledger_rows(ingested_at=_INGESTED)
    b = _fixed_run().to_ledger_rows(ingested_at=_INGESTED)
    assert [canonical_json(r.model_dump(mode="json")) for r in a] == [
        canonical_json(r.model_dump(mode="json")) for r in b
    ]


def test_determinism_manifest_bytes_identical() -> None:
    m1 = _fixed_run().to_manifest(finished_at=_FINISHED)
    m2 = _fixed_run().to_manifest(finished_at=_FINISHED)
    # host_environment is deterministic on one host; all varying fields fixed.
    assert canonical_json(m1.model_dump(mode="json")) == canonical_json(m2.model_dump(mode="json"))


def test_determinism_real_double_ingest_ledger(tmp_path) -> None:  # noqa: ANN001
    """Ingesting the identical source into two workspaces yields identical
    deterministic ledger rows (reference mode keeps the recorded path stable)."""
    source = tmp_path / "ntds.dit"
    source.write_bytes(b"NTDS-FIXED-CONTENT" * 100)

    def ingest_once() -> list[str]:
        ws_root = tmp_path / f"cases-{uuid_seed[0]}"
        uuid_seed[0] += 1
        ws = create_workspace(ws_root, "case1")
        run = IngestRun("case1", "alice", ingest_run_id=_RUN_ID, started_at=_STARTED)
        ingest_file(ws, run, source, mode=IngestMode.REFERENCE, logical_name="ntds.dit")
        rows = run.to_ledger_rows(ingested_at=_INGESTED)
        return [canonical_json(r.model_dump(mode="json")) for r in rows]

    uuid_seed = [0]
    assert ingest_once() == ingest_once()


def test_offline_no_network_egress_full_flow(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """A full ingest + secret put/reveal must complete with all socket connects
    patched to raise — proving no network egress on these paths (offline guarantee)."""

    def _no_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("network egress attempted in an offline path")

    monkeypatch.setattr(socket.socket, "connect", _no_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _no_connect)

    ws = create_workspace(tmp_path / "cases", "case1")
    write_case_config(
        ws.case_json,
        CaseConfig(case_id="case1", operator="alice", created_at=_STARTED),
    )
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"hive-bytes")

    run = IngestRun("case1", "alice", ingest_run_id=_RUN_ID, started_at=_STARTED)
    ingest_file(ws, run, source, mode=IngestMode.COPY, logical_name="SYSTEM")
    manifest = run.to_manifest(finished_at=_FINISHED)
    write_run_manifest(ws.manifest_dir, manifest)
    con = open_canonical_store(ws.canonical_db)
    try:
        assert write_ledger_rows(con, run.to_ledger_rows(ingested_at=_INGESTED)) == 1
    finally:
        con.close()

    keyring, _dek = create_keyring("case1", b"pw", algorithm=KdfAlgorithm.SCRYPT)
    write_keyring(ws.keyring_json, keyring)
    dek = unwrap_dek(keyring, b"pw")
    store = SecretStore.open(ws.secret_store_db, "case1")
    try:
        sid = store.put_secret(
            dek,
            ingest_run_id=_RUN_ID,
            secret_type=SecretType.NT_HASH,
            node_id="n1",
            plaintext=SecretBytes(b"hash"),
        )
        assert store.reveal(sid, dek).get_secret_value() == b"hash"
    finally:
        store.close()


def test_ingest_archive_registers_members_and_counts_skips(tmp_path) -> None:  # noqa: ANN001
    """extract=True: the container + each inner file are registered artifacts,
    a skipped link member is counted, and inner provenance hashes are correct."""
    import stat
    import zipfile

    ws = create_workspace(tmp_path / "cases", "case1")
    archive = tmp_path / "sysvol.zip"
    inner = b"GptTmpl-contents"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("GptTmpl.inf", inner)
        link = zipfile.ZipInfo("symlink")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, "/etc/passwd")

    run = IngestRun("case1", "alice", ingest_run_id=_RUN_ID, started_at=_STARTED)
    registered = ingest_file(
        ws, run, archive, mode=IngestMode.COPY, logical_name="sysvol.zip", extract=True
    )
    # container first, then the one inner regular file (symlink skipped)
    names = [a.source_file for a in registered]
    assert names[0] == "sysvol.zip"
    assert any(n.endswith("!GptTmpl.inf") for n in names)
    assert len(registered) == 2  # container + 1 inner; symlink not registered
    assert run.skip_counts.get("archive_members_skipped") == 1
    # inner member hash is the sha256 of the inner bytes
    import hashlib as _h

    inner_art = next(a for a in registered if a.source_file.endswith("!GptTmpl.inf"))
    assert inner_art.image_sha256 == _h.sha256(inner).hexdigest()
    assert inner_art.container_source_file == "sysvol.zip"


def test_copy_mode_write_once(tmp_path) -> None:  # noqa: ANN001
    """COPY ingest is write-once: re-ingesting the same logical name is refused."""
    ws = create_workspace(tmp_path / "cases", "case1")
    source = tmp_path / "ntds.dit"
    source.write_bytes(b"content")
    run = IngestRun("case1", "alice", ingest_run_id=_RUN_ID, started_at=_STARTED)
    ingest_file(ws, run, source, mode=IngestMode.COPY, logical_name="ntds.dit")
    with pytest.raises(FileExistsError):
        ingest_file(ws, run, source, mode=IngestMode.COPY, logical_name="ntds.dit")
