"""M7 API — real-DC integration gate against the committed c137.local store.

Builds the canonical store once (full analysis pipeline on
``eviedence_test/NTDS/ntds.dit`` + SYSTEM/SAM/SYSVOL) with the provenance ledger
populated, then drives the read-only API via FastAPI's TestClient and asserts the
LOCKED real-DC facts: the 3 DCSync holders, the Administrator -> Domain Admins
path, a known dossier, deterministic slices, the summary counts, and the
WebSocket progress replay. Skipped cleanly when the evidence is absent (CI-safe).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from wraith.api.app import create_app
from wraith.common.determinism import canonical_json

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

# Locked c137.local oracle (re-derived 2026-10-27; matches the M6 gate numbers).
_EXPECT_DOMAIN_FQDN = "c137.local"
_EXPECT_NODES = 390
_EXPECT_EDGES = 30303
_EXPECT_DCSYNC = 3
# Tier-0 CLASSIFICATION count (DE gates G1/G2/H1): 7 RID-suffix principals
# {-512,-519,-544,-516,-518,-502,-500} + the Domain root object + the 2 effective
# Tier-0 members not otherwise counted (ricksanchez in Domain Admins, CITADEL-DC01$
# in Domain Controllers) = 10. The GPCO group (-520) is NOT Tier-0 (G2); the old
# value 8 counted -520 and omitted the Domain object + possession-members.
_EXPECT_TIER0 = 10
_DCSYNC_HOLDER_SAMS = {"Domain Admins", "Enterprise Admins", "Administrators"}

pytestmark = pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")


@pytest.fixture(scope="module")
def db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the c137 canonical store once (with ledger) for the whole module."""
    from wraith.case.ingest_run import IngestRun
    from wraith.export.pipeline import PipelineInputs, SamHostInput, run_analysis_pipeline
    from wraith.model.store import open_canonical_store
    from wraith.provenance.ledger import write_ledger_rows

    work = tmp_path_factory.mktemp("c137")
    store = work / "canonical.duckdb"
    con = open_canonical_store(store)  # creates provenance_ledger
    run = IngestRun("C137", "tester", ingest_run_id=UUID(int=0x6A7E))
    inputs = PipelineInputs(
        ntds_path=_NTDS,
        forest_id="forest-c137",
        system_hive_path=_SYSTEM if _SYSTEM.is_file() else None,
        sam_hosts=(
            (SamHostInput(sam_path=_SAM, system_hive_path=_SYSTEM),) if _SAM.is_file() else ()
        ),
        sysvol_root=_SYSVOL if _SYSVOL.is_dir() else None,
    )
    try:
        run_analysis_pipeline(con, run, inputs, output_dir=work / "bh")
        write_ledger_rows(con, run.to_ledger_rows())
    finally:
        con.close()
    return store


@pytest.fixture(scope="module")
def client(db_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(db_path)) as c:
        yield c


def test_summary_counts(client: TestClient) -> None:
    s = client.get("/api/v1/summary").json()
    assert s["domain_fqdn"] == _EXPECT_DOMAIN_FQDN
    assert s["node_count"] == _EXPECT_NODES
    assert s["edge_count"] == _EXPECT_EDGES
    assert s["dcsync_holder_count"] == _EXPECT_DCSYNC
    assert s["tier0_node_count"] == _EXPECT_TIER0
    assert s["node_kind_counts"]["User"] >= 1


def test_dcsync_holder_set(client: TestClient) -> None:
    """The 3 DCSync holders are exactly Domain/Enterprise Admins + Administrators."""
    nodes = client.get("/api/v1/risk/nodes", params={"limit": 5000}).json()
    holders = {
        nr["label"] for nr in nodes if any(f["code"] == "DCSYNC_HOLDER" for f in nr["factors"])
    }
    assert holders == _DCSYNC_HOLDER_SAMS
    # and the summary agrees
    rs = client.get("/api/v1/risk/summary").json()
    assert rs["dcsync_holders"] == _EXPECT_DCSYNC


def _administrator_node_id(client: TestClient) -> str:
    hits = client.get("/api/v1/search", params={"q": "Administrator"}).json()["hits"]
    admin = next(h for h in hits if h["label"] == "Administrator" and h["kind"] == "User")
    return str(admin["node_id"])


def test_administrator_path_to_domain_admins(client: TestClient) -> None:
    admin = _administrator_node_id(client)
    res = client.post("/api/v1/paths", json={"source_node_ids": [admin], "target": "tier0"}).json()
    assert res["paths_found"] >= 1
    labels = {p["target_label"] for p in res["paths"]}
    assert "Domain Admins" in labels
    da_path = next(p for p in res["paths"] if p["target_label"] == "Domain Admins")
    assert da_path["length"] == 1
    assert da_path["edges"][0]["kind"] == "MemberOf"


def test_administrator_dossier(client: TestClient) -> None:
    admin = _administrator_node_id(client)
    d = client.get(f"/api/v1/nodes/{admin}").json()
    assert d["object_sid"].endswith("-500")
    assert d["kind"] == "User"
    assert d["uac"]["enabled"] is True
    assert d["provenance"]["source_file"] == "ntds.dit"
    assert len(d["provenance"]["image_sha256"]) == 64
    # effective membership includes Domain Admins
    assert any(g["label"] == "Domain Admins" for g in d["group_memberships"])
    # risk present and transparent
    assert d["risk"] is not None
    assert d["risk"]["score"] == sum(f["weight"] for f in d["risk"]["factors"])
    # secrets are references only — never plaintext
    for ref in d["secret_refs"]:
        assert "plaintext" not in ref and "value" not in ref


def test_unknown_node_404(client: TestClient) -> None:
    assert client.get("/api/v1/nodes/does-not-exist").status_code == 404


def test_slice_deterministic(client: TestClient) -> None:
    body = {"limit": 2000, "layout": "server"}
    a = client.post("/api/v1/graph/slice", json=body).json()
    b = client.post("/api/v1/graph/slice", json=body).json()
    assert canonical_json(a) == canonical_json(b)
    assert a["returned"] == _EXPECT_NODES
    assert a["truncated"] is False
    assert a["layout"] == "server"
    # every node carries a server-computed position
    assert all(n["x"] is not None and n["y"] is not None for n in a["nodes"])


def test_tier0_slice(client: TestClient) -> None:
    g = client.post(
        "/api/v1/graph/slice", json={"tier0_only": True, "limit": 50, "layout": "none"}
    ).json()
    assert g["returned"] == _EXPECT_TIER0
    assert all(n["highvalue"] for n in g["nodes"])


def test_neighbors_expand(client: TestClient) -> None:
    admin = _administrator_node_id(client)
    g = client.get(f"/api/v1/nodes/{admin}/neighbors", params={"depth": 1}).json()
    ids = {n["node_id"] for n in g["nodes"]}
    assert admin in ids
    assert g["returned"] >= 2  # Administrator + at least one group


def test_ws_progress_replays_ledger(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    events = []
    with client.websocket_connect("/api/v1/ws/progress") as ws:
        try:
            while True:
                events.append(ws.receive_json())
        except WebSocketDisconnect:
            pass
    types = [e["type"] for e in events]
    assert types[0] == "snapshot"
    assert types[-1] == "done"
    assert any(t == "progress" for t in types)  # ledger populated -> real progress


def test_nodes_browse_list(client: TestClient) -> None:
    """Browse-by-type: kind filter is bounded; risk sort is monotone; bad param -> 422."""
    page = client.get(
        "/api/v1/nodes", params={"kind": "User", "limit": 5, "sort": "name"}
    ).json()
    assert page["limit"] == 5
    assert page["returned"] <= 5
    assert page["total_matched"] >= page["returned"]
    assert all(e["kind"] == "User" for e in page["entries"])
    # risk sort, descending: scores are non-increasing and Tier-0 surfaces
    top = client.get(
        "/api/v1/nodes", params={"sort": "risk", "order": "desc", "limit": 10}
    ).json()
    scores = [e["risk_score"] for e in top["entries"] if e["risk_score"] is not None]
    assert scores == sorted(scores, reverse=True)
    assert any(e["highvalue"] for e in top["entries"])
    # bounded always: over-cap limit is a typed 422, never an unbounded dump
    assert client.get("/api/v1/nodes", params={"limit": 999}).status_code == 422


def test_behavior_reserved_501(client: TestClient) -> None:
    assert client.get("/api/v1/behavior").status_code == 501
    admin = _administrator_node_id(client)
    assert client.get(f"/api/v1/behavior/nodes/{admin}").status_code == 501
