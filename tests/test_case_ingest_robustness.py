"""Module 14 — robustness / untrusted-upload layer (the security surface).

Drives the writable ingest router through FastAPI's ``TestClient`` with a temp
``cases_root`` (no real evidence needed). Hammers the untrusted-upload rules of
doc 14 §5 / §7: kind + host_label validation, per-kind magic sniff, size cap
enforced while streaming, SYSVOL zip-slip / symlink / zip-bomb / bad-zip guards
(asserting nothing is extracted outside ``artifacts/sysvol/``), the re-upload /
multi-append index semantics, the analyze no-ntds refusal, and the WS no-case
ledger-replay shape (unchanged). Concurrency, failure-state, and the live run are
covered in ``test_case_ingest_e2e.py``.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from wraith.api import ingest as ingest_mod
from wraith.api.app import create_app
from wraith.case.catalog import ESE_MAGIC, ESE_MAGIC_OFFSET, REGF_MAGIC

# --- valid-magic byte fixtures (sniff guards, not real parseable artifacts) ---
ESE_BYTES = b"\x00" * ESE_MAGIC_OFFSET + ESE_MAGIC + b"\x00" * 64
REGF_BYTES = REGF_MAGIC + b"\x00" * 64


def _good_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("domain/Policies/GPT.INI", b"[General]\nVersion=1\n")
        z.writestr("domain/Policies/MACHINE/Registry.pol", b"PReg\x01\x00\x00\x00")
    return buf.getvalue()


def _zip_with_member(name: str, *, external_attr: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo(filename=name)
        if external_attr:
            info.external_attr = external_attr
        z.writestr(info, b"malicious")
        z.writestr("safe/ok.txt", b"ok")
    return buf.getvalue()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(cases_root=tmp_path)) as c:
        c.cases_root = tmp_path  # type: ignore[attr-defined]
        yield c


def _mk_case(client: TestClient, case_id: str = "case1") -> str:
    r = client.post("/api/v1/cases", json={"case_id": case_id, "operator": "tester"})
    assert r.status_code == 201, r.text
    return case_id


def _upload(
    client: TestClient,
    case_id: str,
    kind: str,
    content: bytes,
    *,
    host_label: str | None = None,
    system_content: bytes | None = None,
    software_content: bytes | None = None,
    ca_host_fqdn: str | None = None,
) -> httpx.Response:
    data: dict[str, str] = {"kind": kind}
    if host_label is not None:
        data["host_label"] = host_label
    if ca_host_fqdn is not None:
        data["ca_host_fqdn"] = ca_host_fqdn
    files: list = [("file", ("clientname.bin", content, "application/octet-stream"))]
    if system_content is not None:
        files.append(("system_file", ("SYSTEM", system_content, "application/octet-stream")))
    if software_content is not None:
        files.append(("software_file", ("SOFTWARE", software_content, "application/octet-stream")))
    response: httpx.Response = client.post(
        f"/api/v1/cases/{case_id}/artifacts", data=data, files=files
    )
    return response


# --------------------------------------------------------------------------- #
#  case creation guards                                                        #
# --------------------------------------------------------------------------- #


def test_create_case_then_conflict_and_unsafe_id(client: TestClient) -> None:
    assert client.post("/api/v1/cases", json={"case_id": "c", "operator": "t"}).status_code == 201
    # duplicate -> 409
    assert client.post("/api/v1/cases", json={"case_id": "c", "operator": "t"}).status_code == 409
    # unsafe id -> 400
    bad = client.post("/api/v1/cases", json={"case_id": "../evil", "operator": "t"})
    assert bad.status_code == 400
    assert bad.json()["detail"]["reason"] == "unsafe_case_id"


def test_upload_to_unknown_case_404(client: TestClient) -> None:
    r = _upload(client, "nope", "ntds_dit", ESE_BYTES)
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
#  upload kind / host_label / magic / size                                     #
# --------------------------------------------------------------------------- #


def test_upload_unknown_kind_422(client: TestClient) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "bogus_kind", ESE_BYTES)
    assert r.status_code == 422
    assert r.json()["detail"]["reason"].startswith("unknown_kind")


def test_upload_multi_without_host_label_422(client: TestClient) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "member_sam", REGF_BYTES)  # multi, no host_label
    assert r.status_code == 422
    assert r.json()["detail"]["reason"] == "host_label_required_for_multi"


def test_upload_wrong_magic_400(client: TestClient) -> None:
    case = _mk_case(client)
    # ntds kind but regf bytes -> bad_magic
    r = _upload(client, case, "ntds_dit", REGF_BYTES)
    assert r.status_code == 400
    assert r.json()["detail"]["reason"].startswith("bad_magic")
    # system_hive kind but ese bytes -> bad_magic
    r2 = _upload(client, case, "system_hive", ESE_BYTES)
    assert r2.status_code == 400


def test_upload_empty_body_400(client: TestClient) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "ntds_dit", b"")
    assert r.status_code == 400
    assert r.json()["detail"]["reason"].startswith("bad_magic")


def test_upload_oversize_while_streaming_413(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _mk_case(client)
    # shrink the system_hive cap to a few bytes; a valid-magic body over it -> 413
    monkeypatch.setitem(ingest_mod.MAX_UPLOAD_BYTES, "system_hive", 8)
    r = _upload(client, case, "system_hive", REGF_BYTES)  # 68 bytes > 8
    assert r.status_code == 413
    assert r.json()["detail"]["reason"].startswith("too_large")
    # nothing left behind in artifacts root except the (empty) index / incoming
    art = client.cases_root / case / "artifacts"  # type: ignore[attr-defined]
    assert not (art / "SYSTEM").exists()


# --------------------------------------------------------------------------- #
#  accept + index semantics (replace / multi-append)                           #
# --------------------------------------------------------------------------- #


def test_upload_accept_and_reupload_replaced(client: TestClient) -> None:
    case = _mk_case(client)
    r1 = _upload(client, case, "ntds_dit", ESE_BYTES)
    assert r1.status_code == 201
    body1 = r1.json()
    assert body1["kind"] == "ntds_dit"
    assert body1["source_file"] == "ntds.dit"
    assert body1["replaced"] is False
    assert len(body1["image_sha256"]) == 64
    assert body1["stored_rel_path"].endswith("artifacts/ntds.dit")
    # re-upload of a non-multi kind replaces
    r2 = _upload(client, case, "ntds_dit", ESE_BYTES + b"\x01")
    assert r2.status_code == 201
    assert r2.json()["replaced"] is True
    # client filename never used as stored name
    assert "clientname" not in r2.json()["stored_rel_path"]


def test_member_sam_multi_appends_per_host(client: TestClient) -> None:
    case = _mk_case(client)
    a = _upload(
        client, case, "member_sam", REGF_BYTES, host_label="WS01", system_content=REGF_BYTES
    )
    b = _upload(client, case, "member_sam", REGF_BYTES, host_label="WS02")
    assert a.status_code == 201 and b.status_code == 201
    assert a.json()["replaced"] is False and b.json()["replaced"] is False
    assert a.json()["source_file"] == "SAM:WS01"
    # catalog reflects two member_sam source files
    cat = client.get(f"/api/v1/cases/{case}/catalog").json()
    sam = next(t for t in cat["optional"] if t["id"] == "member_sam")
    assert sam["uploaded"] is True
    assert set(sam["source_files"]) == {"SAM:WS01", "SAM:WS02"}
    # same host re-upload replaces (still 2 hosts total)
    c = _upload(client, case, "member_sam", REGF_BYTES, host_label="WS01")
    assert c.json()["replaced"] is True
    cat2 = client.get(f"/api/v1/cases/{case}/catalog").json()
    sam2 = next(t for t in cat2["optional"] if t["id"] == "member_sam")
    assert set(sam2["source_files"]) == {"SAM:WS01", "SAM:WS02"}


def test_catalog_and_coverage_reflect_uploads(client: TestClient) -> None:
    case = _mk_case(client)
    _upload(client, case, "ntds_dit", ESE_BYTES)
    _upload(client, case, "ca_host_registry", REGF_BYTES, host_label=None)
    cat = client.get(f"/api/v1/cases/{case}/catalog").json()
    req_ids = {t["id"] for t in cat["required"]}
    assert req_ids == {"ntds_dit"}
    ca = next(t for t in cat["optional"] if t["id"] == "ca_host_registry")
    assert ca["uploaded"] is True
    cov = client.get(f"/api/v1/cases/{case}/coverage").json()
    assert cov["can_analyze"] is True
    ca_cov = next(c for c in cov["capabilities"] if c["capability_id"] == "ca_host_edges")
    # module 35b wired: supplying the CA hive makes the capability AVAILABLE (the
    # pass now runs with real CA-host facts), no reserved reason survives.
    assert ca_cov["status"] == "available"
    assert ca_cov["reasons"] == []


def test_ca_host_composite_upload_stores_software_and_fqdn(client: TestClient) -> None:
    """Module 35b: a ``ca_host_registry`` upload accepts the SYSTEM primary + an
    optional SOFTWARE companion + an FQDN, confines both hives under
    ``cahost_ca/``, and records them on the upload index for the pipeline to
    thread into ``PipelineInputs`` (facts built from REAL hives)."""
    from wraith.api import ingest as ingest_mod
    from wraith.case.case import load_case_config
    from wraith.case.workspace import load_workspace

    cases_root = client.cases_root  # type: ignore[attr-defined]
    case = _mk_case(client)
    _upload(client, case, "ntds_dit", ESE_BYTES)
    r = _upload(
        client,
        case,
        "ca_host_registry",
        REGF_BYTES,
        software_content=REGF_BYTES,
        ca_host_fqdn="CA01.corp.local",
    )
    assert r.status_code == 201, r.text

    # both hives are confined side-by-side under the per-host dir, SYSTEM primary
    art = cases_root / case / "artifacts"
    assert (art / "cahost_ca" / "SYSTEM").is_file()
    assert (art / "cahost_ca" / "SOFTWARE").is_file()

    # the index records the companion + fqdn
    workspace = load_workspace(cases_root, case)
    index = ingest_mod.load_upload_index(workspace)
    entry = index.entries["ca_host_registry"][0]
    assert entry.software_stored_rel_path is not None
    assert entry.software_stored_rel_path.endswith("cahost_ca/SOFTWARE")
    assert entry.ca_host_fqdn == "CA01.corp.local"

    # _build_pipeline_inputs threads all three into PipelineInputs (real facts)
    config = load_case_config(workspace.case_json)
    present = index.present_kinds()
    inputs, _additional, reserved = ingest_mod._build_pipeline_inputs(
        workspace, index, present, ingest_mod._DEFAULT_FOREST_ID, config
    )
    assert inputs.ca_host_system_path is not None
    assert inputs.ca_host_system_path.name == "SYSTEM"
    assert inputs.ca_host_software_path is not None
    assert inputs.ca_host_software_path.name == "SOFTWARE"
    assert inputs.ca_host_fqdn == "CA01.corp.local"
    # ca_host is no longer reserved-only, so it is NOT in the reserved registration
    # list (the pipeline registers CAHOST/SYSTEM + CAHOST/SOFTWARE itself).
    assert all("CAHOST" not in src for src, *_ in reserved)


def test_ca_host_absent_leaves_pipeline_inputs_none(client: TestClient) -> None:
    """Absent path unchanged: with NO CA hive uploaded, the three ``ca_host_*``
    fields are ``None`` -> the pipeline uses ``ABSENT_CA_HOST_FACTS`` byte-for-byte
    as before (counted gap on the degraded branch, no crash, no silent drop)."""
    from wraith.api import ingest as ingest_mod
    from wraith.case.case import load_case_config
    from wraith.case.workspace import load_workspace

    cases_root = client.cases_root  # type: ignore[attr-defined]
    case = _mk_case(client)
    _upload(client, case, "ntds_dit", ESE_BYTES)

    workspace = load_workspace(cases_root, case)
    index = ingest_mod.load_upload_index(workspace)
    config = load_case_config(workspace.case_json)
    inputs, _additional, _reserved = ingest_mod._build_pipeline_inputs(
        workspace, index, index.present_kinds(), ingest_mod._DEFAULT_FOREST_ID, config
    )
    assert inputs.ca_host_system_path is None
    assert inputs.ca_host_software_path is None
    assert inputs.ca_host_fqdn is None


# --------------------------------------------------------------------------- #
#  SYSVOL zip extraction guards (§5 / §7)                                       #
# --------------------------------------------------------------------------- #


def _sysvol_dir(client: TestClient, case: str) -> Path:
    return client.cases_root / case / "artifacts" / "sysvol"  # type: ignore[attr-defined]


def test_sysvol_good_zip_extracts_confined(client: TestClient) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "sysvol", _good_zip())
    assert r.status_code == 201, r.text
    svol = _sysvol_dir(client, case)
    assert (svol / "domain" / "Policies" / "GPT.INI").is_file()
    # nothing escaped the sysvol subtree
    case_root = client.cases_root / case  # type: ignore[attr-defined]
    assert not (case_root / "GPT.INI").exists()


@pytest.mark.parametrize(
    "member",
    ["../evil.txt", "/abs/evil.txt", "a/../../evil.txt"],
)
def test_sysvol_zip_slip_rejected(client: TestClient, member: str) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "sysvol", _zip_with_member(member))
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "zip_slip"
    # NOTHING extracted outside artifacts/sysvol (the dir must not exist)
    assert not _sysvol_dir(client, case).exists()
    cases_root = client.cases_root  # type: ignore[attr-defined]
    stray = [p for p in cases_root.rglob("evil.txt")]
    assert stray == []


def test_sysvol_symlink_member_rejected(client: TestClient) -> None:
    case = _mk_case(client)
    # S_IFLNK (0o120000) in the high word of external_attr marks a symlink member
    attr = (0o120777) << 16
    r = _upload(client, case, "sysvol", _zip_with_member("link", external_attr=attr))
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "zip_slip"
    assert not _sysvol_dir(client, case).exists()


def test_sysvol_zip_bomb_member_count_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _mk_case(client)
    monkeypatch.setattr(ingest_mod, "SYSVOL_MAX_MEMBERS", 2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(5):
            z.writestr(f"f{i}.txt", b"x")
    r = _upload(client, case, "sysvol", buf.getvalue())
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "zip_bomb"
    assert not _sysvol_dir(client, case).exists()


def test_sysvol_bad_zip_rejected(client: TestClient) -> None:
    case = _mk_case(client)
    # passes the ZIP magic sniff (PK\x03\x04) but is not a valid archive
    r = _upload(client, case, "sysvol", b"PK\x03\x04" + b"garbage" * 4)
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "bad_zip"
    assert not _sysvol_dir(client, case).exists()


def test_sysvol_wrong_magic_rejected_before_extract(client: TestClient) -> None:
    case = _mk_case(client)
    r = _upload(client, case, "sysvol", REGF_BYTES)  # not a zip
    assert r.status_code == 400
    assert r.json()["detail"]["reason"].startswith("bad_magic")


# --------------------------------------------------------------------------- #
#  analyze refusal + WS no-case shape                                           #
# --------------------------------------------------------------------------- #


def test_analyze_without_ntds_refused_422(client: TestClient) -> None:
    case = _mk_case(client)
    _upload(client, case, "system_hive", REGF_BYTES)  # optional only, no ntds
    r = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert r.status_code == 422
    assert r.json()["detail"]["reason"] == "ntds_dit_required"


def test_run_status_unknown_run_404(client: TestClient) -> None:
    case = _mk_case(client)
    r = client.get(f"/api/v1/cases/{case}/runs/does-not-exist")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
#  regression: silent/race failures the reviewer flagged (keep them locked)     #
# --------------------------------------------------------------------------- #


def test_corrupt_upload_index_is_honest_not_silently_empty(client: TestClient) -> None:
    """A CORRUPT (not absent) upload index must surface as a typed 500
    ``upload_index_corrupt`` on every reader endpoint — never a silently-empty
    200 report and never a bogus 422 'ntds required' (which would dishonestly
    claim already-uploaded artifacts are missing)."""
    case = _mk_case(client)
    assert _upload(client, case, "ntds_dit", ESE_BYTES).status_code == 201
    idx = client.cases_root / case / "artifacts" / "_uploads.json"  # type: ignore[attr-defined]
    assert idx.is_file()
    idx.write_text("{ this is : not valid json", encoding="utf-8")  # hand-corrupt on disk

    for path in (
        f"/api/v1/cases/{case}/coverage",
        f"/api/v1/cases/{case}/catalog",
    ):
        r = client.get(path)
        assert r.status_code == 500, (path, r.status_code, r.text)
        assert r.json()["detail"]["reason"] == "upload_index_corrupt"
    a = client.post(f"/api/v1/cases/{case}/analyze", json={})
    assert a.status_code == 500
    assert a.json()["detail"]["reason"] == "upload_index_corrupt"


def test_absent_upload_index_is_empty_report_not_corrupt(client: TestClient) -> None:
    """corrupt != absent: a fresh case with NO index yet is the normal empty
    report (can_analyze=False), not a 500."""
    case = _mk_case(client, "fresh")
    cov = client.get(f"/api/v1/cases/{case}/coverage")
    assert cov.status_code == 200
    assert cov.json()["can_analyze"] is False
    cat = client.get(f"/api/v1/cases/{case}/catalog")
    assert cat.status_code == 200
    tiles = cat.json()["required"] + cat.json()["optional"]
    assert all(t["uploaded"] is False for t in tiles)


def test_no_orphan_when_companion_system_fails(client: TestClient) -> None:
    """A member_sam whose companion SYSTEM fails validation leaves NOTHING behind:
    the main SAM is not placed on disk and no index entry is recorded (the 3-phase
    _do_upload validates the companion before placing the SAM)."""
    case = _mk_case(client)
    # valid regf SAM, but a companion system_file with WRONG magic (ESE, not regf)
    r = _upload(
        client,
        case,
        "member_sam",
        REGF_BYTES,
        host_label="WS09",
        system_content=ESE_BYTES,
    )
    assert 400 <= r.status_code < 500, r.text
    assert r.json()["detail"]["reason"].startswith("bad_magic")
    # the main SAM must NOT be orphaned on disk
    sam_file = client.cases_root / case / "artifacts" / "sam_ws09" / "SAM"  # type: ignore[attr-defined]
    assert not sam_file.exists()
    assert not sam_file.parent.exists()
    # and no index entry: the host never appears as uploaded
    cat = client.get(f"/api/v1/cases/{case}/catalog").json()
    sam = next(t for t in cat["optional"] if t["id"] == "member_sam")
    assert sam["uploaded"] is False
    assert sam["source_files"] == []


def test_ws_no_case_id_replays_unchanged_shape(client: TestClient) -> None:
    # No default reader bound (multi-case app) -> the pre-existing empty-run
    # ledger-replay terminal: snapshot then done, with the artifacts field and
    # WITHOUT the case-scoped pass/pct/state fields.
    events: list[dict] = []
    with client.websocket_connect("/api/v1/ws/progress") as ws:
        try:
            while True:
                events.append(ws.receive_json())
        except WebSocketDisconnect:
            pass
    assert [e["type"] for e in events] == ["snapshot", "done"]
    assert events[0] == {"type": "snapshot", "artifacts": 0}
    assert events[-1] == {"type": "done", "artifacts": 0}
    for e in events:
        assert "pct" not in e and "pass" not in e and "state" not in e
