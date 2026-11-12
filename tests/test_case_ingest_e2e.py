"""Module 14 — analyze orchestration + end-to-end layer.

Two tiers:

* **Orchestration (fast, deterministic)** — the ``CaseRunManager`` worker-thread
  executor, WS live producer, per-case reader registry, run-status progression,
  one-run-per-case lock (409), and the fail-safe (a corrupt ntds -> ``failed``
  with a typed error, server still serving) are exercised with a FAKE
  ``run_analysis_pipeline`` (drives the §4 progress callback + leaves a usable
  empty store) so the orchestration is tested without the multi-minute pipeline.

* **Real end-to-end (skipif evidence)** — one true run: upload the real c137
  ntds/SYSTEM/SAM/SYSVOL through the HTTP router, analyze with the REAL pipeline,
  stream to ``done`` at 100%, and confirm the store is bound + served read-only.
"""

from __future__ import annotations

import hashlib
import io
import threading
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from wraith.api import ingest as ingest_mod
from wraith.api.app import create_app
from wraith.case.catalog import ESE_MAGIC, ESE_MAGIC_OFFSET, REGF_MAGIC
from wraith.case.manifest import ArtifactInput
from wraith.model.store import create_canonical_tables, create_edge_tables

ESE_BYTES = b"\x00" * ESE_MAGIC_OFFSET + ESE_MAGIC + b"\x00" * 64
REGF_BYTES = REGF_MAGIC + b"\x00" * 64

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

# §1.2 counted-gap classes expected on an ntds-only run (no optional artifacts).
_NTDS_ONLY_GAPS = {
    "secrets_unavailable_no_system_hive",
    "esc_dc_config_undecidable_no_system_hive",
    "adcs_dc_config_degraded_no_system_hive",
    "gpo_edges_unavailable_no_sysvol",
    "host_adminto_unavailable_no_member_sam",
    "ca_host_edges_unavailable_no_ca_hive",
    "adcs_degraded_no_ca_hive",
    "multi_domain_unavailable_single_dc",
}

# ---- fake pipelines (orchestration only) ----------------------------------- #
_PIPELINE_ORDER_HEAD = ("register", "normalize", "membership", "edges", "adcs_esc")


def _active_order(inputs) -> list[str]:
    order = list(_PIPELINE_ORDER_HEAD)
    if inputs.sam_hosts:
        order.append("host_sam")
    if inputs.sysvol_root is not None:
        order.append("gpo_sysvol")
    order.append("export")
    return order


def _prepare_empty_store(con) -> None:
    """Create the node/edge tables the real normalize/edge passes would create, so
    the post-run read-only reader can query an (empty) store."""
    create_canonical_tables(con)
    create_edge_tables(con)


def _fake_pipeline(con, run, inputs, *, output_dir, export_config=None, progress_cb=None):
    """A byte-cheap stand-in: register ntds, drive every active pass boundary."""
    _prepare_empty_store(con)
    run.add_artifact(
        ArtifactInput(
            source_file=inputs.ntds_source_file,
            abs_path_or_ref=str(inputs.ntds_path),
            size_bytes=inputs.ntds_path.stat().st_size,
            image_sha256="0" * 64,
        )
    )
    for pid in _active_order(inputs):
        if progress_cb is not None:
            progress_cb(pid, "start")
            progress_cb(pid, "done")
    return None


class _BlockingPipeline:
    """A fake that blocks at the first pass until released (concurrency/live test)."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()

    def __call__(self, con, run, inputs, *, output_dir, export_config=None, progress_cb=None):
        _prepare_empty_store(con)
        run.add_artifact(
            ArtifactInput(
                source_file=inputs.ntds_source_file,
                abs_path_or_ref=str(inputs.ntds_path),
                size_bytes=inputs.ntds_path.stat().st_size,
                image_sha256="0" * 64,
            )
        )
        if progress_cb is not None:
            progress_cb("register", "start")
        self.entered.set()
        self.release.wait(timeout=15)
        for pid in _active_order(inputs):
            if progress_cb is not None:
                progress_cb(pid, "start")
                progress_cb(pid, "done")


# ---- client / helpers ------------------------------------------------------ #
@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(cases_root=tmp_path)) as c:
        c.cases_root = tmp_path  # type: ignore[attr-defined]
        yield c


def _mk_case(client: TestClient, case_id: str = "run1") -> str:
    assert (
        client.post("/api/v1/cases", json={"case_id": case_id, "operator": "t"}).status_code == 201
    )
    return case_id


def _upload_bytes(client: TestClient, case: str, kind: str, content: bytes, **kw) -> None:
    data = {"kind": kind}
    if kw.get("host_label"):
        data["host_label"] = kw["host_label"]
    r = client.post(
        f"/api/v1/cases/{case}/artifacts",
        data=data,
        files=[("file", ("x.bin", content, "application/octet-stream"))],
    )
    assert r.status_code == 201, r.text


def _poll_until(client: TestClient, case: str, run_id: str, states: set[str], timeout: float):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/api/v1/cases/{case}/runs/{run_id}").json()
        if last["state"] in states:
            return last
        time.sleep(0.1)
    raise AssertionError(f"run did not reach {states}; last={last}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
#  orchestration (fake pipeline)                                               #
# --------------------------------------------------------------------------- #


def test_analyze_happy_path_done_at_100(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)

    acc = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert acc.status_code == 202, acc.text
    body = acc.json()
    run_id = body["run_id"]
    # ntds-only -> host_sam + gpo_sysvol NOT active
    assert body["active_passes"] == [
        "register",
        "normalize",
        "membership",
        "edges",
        "adcs_esc",
        "export",
    ]
    assert body["ws_url"].endswith(f"case_id={case}")
    assert body["coverage"]["can_analyze"] is True

    final = _poll_until(client, case, run_id, {"done", "failed"}, timeout=20)
    assert final["state"] == "done", final
    assert final["percent"] == 100
    assert final["current_pass"] is None
    assert all(p["state"] == "done" for p in final["passes"])
    # the result is counts-only + carries coverage; NEVER secrets
    assert final["result"] is not None
    assert "node_count" in final["result"] and "edge_count" in final["result"]
    assert final["result"]["coverage"]["can_analyze"] is True
    # §1.2 counted gaps are present on the run (seeded from coverage_gap_bumps)
    assert _NTDS_ONLY_GAPS.issubset(set(final["skip_counts"]))
    # no secret/plaintext anywhere in the status payload
    blob = client.get(f"/api/v1/cases/{case}/runs/{run_id}").text.lower()
    assert "plaintext" not in blob and "password" not in blob


def test_reader_bound_read_only_sha_unchanged(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    registry = client.app.state.registry  # type: ignore[attr-defined]
    reader = registry.get(case)
    assert reader is not None, "case reader must be bound after a successful run"
    db_file = client.cases_root / case / "canonical.duckdb"  # type: ignore[attr-defined]
    before = _sha256(db_file)
    # repeated reads via the read-only reader must not mutate the store
    for _ in range(3):
        reader.node_count()
        reader.edge_kind_counts()
    assert _sha256(db_file) == before


def test_ws_case_scoped_terminal_shape(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    events: list[dict] = []
    with client.websocket_connect(f"/api/v1/ws/progress?case_id={case}") as ws:
        try:
            while True:
                events.append(ws.receive_json())
        except WebSocketDisconnect:
            pass
    types = [e["type"] for e in events]
    assert types[0] == "snapshot"
    assert types[-1] == "done"
    # the case-scoped events carry the additive pass/pct/state fields
    assert events[0]["case_id"] == case
    assert events[0]["pct"] == 100 and events[0]["state"] == "done"
    assert any("pass" in e and "pct" in e and "state" in e for e in events)
    assert events[-1]["pct"] == 100 and events[-1]["state"] == "done"


def test_one_run_per_case_lock_409(client: TestClient, monkeypatch) -> None:
    blocking = _BlockingPipeline()
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", blocking)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)

    first = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert first.status_code == 202
    run_id = first.json()["run_id"]
    assert blocking.entered.wait(timeout=5), "worker did not start"

    # a second concurrent analyze on the SAME case is refused
    second = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert second.status_code == 409
    assert second.json()["detail"]["reason"] == "run_in_progress"

    # while blocked, the run is live: state running, first pass current
    live = client.get(f"/api/v1/cases/{case}/runs/{run_id}").json()
    assert live["state"] == "running"
    assert live["current_pass"] == "register"

    blocking.release.set()
    final = _poll_until(client, case, run_id, {"done", "failed"}, timeout=20)
    assert final["state"] == "done"
    assert final["percent"] == 100
    # the lock is released -> a fresh analyze is accepted again
    again = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert again.status_code == 202


def test_corrupt_ntds_fails_cleanly_server_survives(client: TestClient) -> None:
    """A valid-magic but unparseable ntds -> state=failed with a typed error (no
    stack trace / secret), and the server keeps serving (real pipeline)."""
    case = _mk_case(client)
    # passes the ESE magic sniff but is not a real database -> parser raises
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES + b"\xde\xad\xbe\xef" * 64)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    final = _poll_until(client, case, run_id, {"failed", "done"}, timeout=60)
    assert final["state"] == "failed", final
    assert final["error"] is not None
    # typed error = "ClassName: message"; never a traceback or secret
    assert "Traceback" not in final["error"]
    assert "\n" not in final["error"]
    assert ":" in final["error"]
    # §1.2 gaps still counted even on a failed run (seeded pre-thread)
    assert _NTDS_ONLY_GAPS.issubset(set(final["skip_counts"]))
    # the server is NOT crashed: another request still works
    assert client.get(f"/api/v1/cases/{case}/coverage").status_code == 200
    assert (
        client.post("/api/v1/cases", json={"case_id": "after", "operator": "t"}).status_code == 201
    )


# --------------------------------------------------------------------------- #
#  BloodHound CE export download (GET /cases/{c}/runs/{r}/export/bhce)          #
# --------------------------------------------------------------------------- #


def _fake_pipeline_with_zip(con, run, inputs, *, output_dir, export_config=None, progress_cb=None):
    """As ``_fake_pipeline`` but also writes a real export zip into ``output_dir``."""
    _fake_pipeline(
        con,
        run,
        inputs,
        output_dir=output_dir,
        export_config=export_config,
        progress_cb=progress_cb,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_name = export_config.zip_name if export_config is not None else "bloodhound.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("data/meta.json", '{"ok": true}')
    (output_dir / zip_name).write_bytes(buf.getvalue())


def test_export_download_streams_zip(client: TestClient, monkeypatch) -> None:
    """A completed run whose export produced a zip streams it as application/zip."""
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline_with_zip)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    final = _poll_until(client, case, run_id, {"done"}, timeout=20)

    # snapshot offers the convenience download pointer on a done run with an export
    assert final["export_download_url"] == f"/api/v1/cases/{case}/runs/{run_id}/export/bhce"

    resp = client.get(final["export_download_url"])
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "bloodhound.zip" in resp.headers["content-disposition"]
    # the streamed bytes are a valid, intact zip
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert zf.namelist() == ["data/meta.json"]


def test_export_download_404_absent_when_file_missing(client: TestClient, monkeypatch) -> None:
    """A done run whose export zip is NOT on disk -> 404 export_absent, never 500."""
    # _fake_pipeline drives every pass but writes no zip, so export_zip_rel is set
    # (the run builds it) yet the file is absent -> the honest absent branch.
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    resp = client.get(f"/api/v1/cases/{case}/runs/{run_id}/export/bhce")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "export_absent"


def test_export_download_404_unknown_run(client: TestClient) -> None:
    """An unknown run id on the download route 404s with ``unknown_run``."""
    case = _mk_case(client)
    resp = client.get(f"/api/v1/cases/{case}/runs/does-not-exist/export/bhce")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "unknown_run"


@pytest.mark.parametrize(
    "evil_rel",
    [
        "../outside_secret.txt",  # escape the case root, land in cases_root
        "../../../../../../../../etc/hosts",  # deep relative traversal
        "..\\..\\outside_secret.txt",  # backslash traversal (Windows-style)
    ],
)
def test_export_download_path_confinement(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, evil_rel: str
) -> None:
    """A TAMPERED ``export_zip_rel`` that traverses out of the case root must NOT
    stream an out-of-tree file: it degrades to 404 ``export_absent``, never 500,
    never leaks the target's bytes (artifacts/manifests are untrusted)."""
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline_with_zip)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    # plant a readable secret OUTSIDE the case root (but inside cases_root, the
    # most favourable case for an attacker) so a confinement bug would leak it.
    secret = b"TOP-SECRET-OUT-OF-TREE-BYTES"
    (client.cases_root / "outside_secret.txt").write_bytes(secret)  # type: ignore[attr-defined]

    # tamper the in-memory run result so the download route reads a traversing
    # export_zip_rel (models a manifest/state poisoned by untrusted input).
    state = client.app.state.run_manager.get_run(case, run_id)  # type: ignore[attr-defined]
    assert state is not None and state.result is not None
    state.update(result=state.result.model_copy(update={"export_zip_rel": evil_rel}))

    resp = client.get(f"/api/v1/cases/{case}/runs/{run_id}/export/bhce")
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["reason"] == "export_absent"
    assert secret not in resp.content


def test_export_download_404_absolute_path(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ABSOLUTE ``export_zip_rel`` (outside the case root) -> 404 export_absent."""
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline_with_zip)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    secret = b"ABSOLUTE-PATH-SECRET"
    outside = client.cases_root / "abs_secret.txt"  # type: ignore[attr-defined]
    outside.write_bytes(secret)

    state = client.app.state.run_manager.get_run(case, run_id)  # type: ignore[attr-defined]
    state.update(result=state.result.model_copy(update={"export_zip_rel": str(outside)}))

    resp = client.get(f"/api/v1/cases/{case}/runs/{run_id}/export/bhce")
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["reason"] == "export_absent"
    assert secret not in resp.content


def test_export_download_url_null_while_running(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``export_download_url`` is null while the run is still running (not done), so
    the UI never offers a download before the export pass has produced its rel path."""
    blocking = _BlockingPipeline()
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", blocking)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    assert blocking.entered.wait(timeout=5)

    running = client.get(f"/api/v1/cases/{case}/runs/{run_id}").json()
    assert running["state"] == "running"
    assert running["export_download_url"] is None  # not offered mid-run
    blocking.release.set()
    _poll_until(client, case, run_id, {"done"}, timeout=20)


def test_export_url_is_pointer_not_disk_promise(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documented contract: ``export_download_url`` is set on a done run whose
    ``export_zip_rel`` is non-empty (a CONVENIENCE pointer), but it is NOT a promise
    the bytes are on disk — the download route still existence-checks and 404s. The
    _fake_pipeline reports done with a rel path yet writes no zip."""
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    final = _poll_until(client, case, run_id, {"done"}, timeout=20)

    # pointer is offered (rel path non-empty on a done run) ...
    assert final["export_download_url"] == f"/api/v1/cases/{case}/runs/{run_id}/export/bhce"
    # ... but it is not a promise: the route confirms absence honestly, never 500.
    resp = client.get(final["export_download_url"])
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "export_absent"


def test_export_download_deterministic_repeat(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same inputs -> same route behaviour: repeated GETs return byte-identical zips."""
    monkeypatch.setattr(ingest_mod, "run_analysis_pipeline", _fake_pipeline_with_zip)
    case = _mk_case(client)
    _upload_bytes(client, case, "ntds_dit", ESE_BYTES)
    run_id = client.post(f"/api/v1/cases/{case}/analyze", json={}).json()["run_id"]
    _poll_until(client, case, run_id, {"done"}, timeout=20)

    url = f"/api/v1/cases/{case}/runs/{run_id}/export/bhce"
    first = client.get(url)
    second = client.get(url)
    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert first.headers["content-type"] == second.headers["content-type"] == "application/zip"


# --------------------------------------------------------------------------- #
#  real end-to-end (skipif evidence)                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_real_evidence_full_run_served_read_only(client: TestClient) -> None:
    case = _mk_case(client, "c137")

    # upload the real artifacts through the HTTP router (streamed + magic-sniffed)
    with open(_NTDS, "rb") as fh:
        r = client.post(
            f"/api/v1/cases/{case}/artifacts",
            data={"kind": "ntds_dit"},
            files=[("file", ("ntds.dit", fh, "application/octet-stream"))],
        )
    assert r.status_code == 201, r.text
    assert len(r.json()["image_sha256"]) == 64

    if _SYSTEM.is_file():
        with open(_SYSTEM, "rb") as fh:
            assert (
                client.post(
                    f"/api/v1/cases/{case}/artifacts",
                    data={"kind": "system_hive"},
                    files=[("file", ("SYSTEM", fh, "application/octet-stream"))],
                ).status_code
                == 201
            )
    if _SAM.is_file():
        files = [("file", ("SAM", open(_SAM, "rb"), "application/octet-stream"))]
        if _SYSTEM.is_file():
            files.append(
                ("system_file", ("SYSTEM", open(_SYSTEM, "rb"), "application/octet-stream"))
            )
        assert (
            client.post(
                f"/api/v1/cases/{case}/artifacts",
                data={"kind": "member_sam", "host_label": "citadel"},
                files=files,
            ).status_code
            == 201
        )
    if _SYSVOL.is_dir():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(_SYSVOL.rglob("*")):
                if f.is_file():
                    z.write(f, f.relative_to(_SYSVOL).as_posix())
        buf.seek(0)
        assert (
            client.post(
                f"/api/v1/cases/{case}/artifacts",
                data={"kind": "sysvol"},
                files=[("file", ("sysvol.zip", buf, "application/zip"))],
            ).status_code
            == 201
        )

    cov = client.get(f"/api/v1/cases/{case}/coverage").json()
    assert cov["can_analyze"] is True

    acc = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert acc.status_code == 202, acc.text
    run_id = acc.json()["run_id"]

    final = _poll_until(client, case, run_id, {"done", "failed"}, timeout=420)
    assert final["state"] == "done", final
    assert final["percent"] == 100
    assert final["result"]["node_count"] > 0
    assert final["result"]["edge_count"] > 0
    assert "MemberOf" in final["result"]["edge_kind_counts"]

    # bound + served read-only; DB SHA unchanged across reads
    registry = client.app.state.registry  # type: ignore[attr-defined]
    reader = registry.get(case)
    assert reader is not None
    db_file = client.cases_root / case / "canonical.duckdb"  # type: ignore[attr-defined]
    before = _sha256(db_file)
    assert reader.node_count() == final["result"]["node_count"]
    assert _sha256(db_file) == before
