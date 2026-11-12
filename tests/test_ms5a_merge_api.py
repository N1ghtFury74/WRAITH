"""M-MS5a — the multi-source merge / divergence API (backend only).

SYNTHETIC only. Proves the API surface the UI needs:

* the opt-in merge TRIGGER runs the gated fold + returns the DC-vs-DC report;
* ``<2`` sources is the honest ``nothing_to_merge`` state (not an error);
* a FOREIGN ``source_id`` is rejected (untrusted input, 422);
* the divergence ledger read returns rows with NO secret digest/plaintext;
* a MERGED node's dossier shows the presented value + the correct three-state badge;
* a non-merged dossier is BYTE-UNCHANGED (zero regression) + the ``merge`` key absent.

These do NOT prove the real multi-DC divergence byte shapes (contract §7.7); they prove
the API plumbing, redaction, three-state badge, and the zero-regression guarantee.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import duckdb
import pytest
from fastapi.testclient import TestClient

from wraith.api.app import create_app
from wraith.api.merge import (
    GAP_NO_MERGE_RUN,
    build_merge_overlay,
    merge_run_id,
    read_divergence_ledger,
)
from wraith.api.store import StoreReader
from wraith.case.workspace import create_workspace
from wraith.merge.fold import GAP_NOTHING_TO_MERGE, SecretFingerprint, merge_fold
from wraith.model.store import (
    create_canonical_tables,
    create_divergence_table,
    create_edge_tables,
)

_SRC_A = "11111111-1111-5111-8111-111111111111"
_SRC_B = "22222222-2222-5222-8222-222222222222"
_CASE = "ms5a-case"


# --------------------------------------------------------------------------- #
#  Synthetic store builders                                                   #
# --------------------------------------------------------------------------- #
def _add_source(con: duckdb.DuckDBPyConnection, source_id: str, label: str) -> None:
    con.execute(
        "INSERT INTO source (source_id, case_id, dc_label, forest_id, domain_id, "
        "domain_fqdn, ntds_image_sha256, ingest_run_id, ingested_at) "
        "VALUES (?, ?, ?, 'f1', 'dom', 'corp.local', 'ab', ?, ?)",
        [source_id, _CASE, label, UUID(int=1), datetime.now(UTC)],
    )


def _add_node_obs(con: duckdb.DuckDBPyConnection, obj_id: str, source_id: str) -> None:
    con.execute(
        "INSERT INTO source_observation (obj_kind, obj_id, source_id, is_deleted) "
        "VALUES ('node', ?, ?, FALSE)",
        [obj_id, source_id],
    )


def _add_staging(
    con: duckdb.DuckDBPyConnection, node_id: str, source_id: str, **attrs: object
) -> None:
    con.execute(
        "INSERT INTO staging_object (node_id, attributes, forest_id, source_id) "
        "VALUES (?, ?, 'f1', ?)",
        [node_id, json.dumps(attrs), source_id],
    )


def _add_principal(con: duckdb.DuckDBPyConnection, node_id: str) -> None:
    con.execute(
        "INSERT INTO principal (node_id, principal_type, samaccountname, forest_id, "
        "domain_id, domain_fqdn) VALUES (?, 'User', ?, 'f1', 'dom', 'corp.local')",
        [node_id, node_id],
    )


def _build_divergent_store(path: Path) -> None:
    """Build a two-source store where node ``u1`` diverges on two attributes.

    ``userAccountControl`` (512 vs 514) has a tier-3 danger ordering -> presented
    (``resolved`` badge). ``description`` ("alpha" vs "beta") has no danger ordering and
    no tier can resolve it -> ``contested_unresolved`` badge.
    """
    con = duckdb.connect(str(path))
    try:
        create_canonical_tables(con)
        create_edge_tables(con)
        create_divergence_table(con)
        _add_source(con, _SRC_A, "DC-A")
        _add_source(con, _SRC_B, "DC-B")
        _add_principal(con, "u1")
        for sid, uac, desc in ((_SRC_A, 512, "alpha"), (_SRC_B, 514, "beta")):
            _add_node_obs(con, "u1", sid)
            _add_staging(con, "u1", sid, userAccountControl=uac, description=desc)
    finally:
        con.close()


def _case_client(tmp_path: Path, builder: object = _build_divergent_store) -> TestClient:
    """Create a case workspace with a built canonical store + an app TestClient."""
    ws = create_workspace(tmp_path, _CASE)
    builder(Path(ws.canonical_db))  # type: ignore[operator]
    return TestClient(create_app(cases_root=tmp_path))


# --------------------------------------------------------------------------- #
#  merge_run_id determinism                                                   #
# --------------------------------------------------------------------------- #
def test_merge_run_id_is_deterministic() -> None:
    assert merge_run_id(_CASE) == merge_run_id(_CASE)
    assert merge_run_id("a") != merge_run_id("b")


# --------------------------------------------------------------------------- #
#  Trigger: runs the fold + returns the report                                #
# --------------------------------------------------------------------------- #
def test_merge_trigger_runs_fold_and_returns_report(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nothing_to_merge"] is False
        assert body["source_ids"] == sorted([_SRC_A, _SRC_B])
        # both attributes diverge -> 2 attribute_divergence rows
        assert body["attribute_divergences"] == 2
        assert body["report"]["counts_by_type"]["attribute_divergence"] == 2
        assert body["nodes_reconciled"] == 1
        # the un-armed inputs are surfaced as counted gaps (never a silent over-claim)
        assert "merge.secret_fingerprints_not_computed" in body["counted_gaps"]
        assert "merge.attid_map_not_provided" in body["counted_gaps"]


def test_merge_trigger_is_idempotent(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        a = client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        b = client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        assert a.json()["attribute_divergences"] == b.json()["attribute_divergences"] == 2
        # a re-merge replaces the prior ledger (not doubled)
        led = client.get("/api/v1/divergence", params={"case_id": _CASE}).json()
        assert sum(led["report"]["counts_by_type"].values()) == 2


# --------------------------------------------------------------------------- #
#  Trigger: <2 sources = honest nothing-to-merge; foreign source rejected      #
# --------------------------------------------------------------------------- #
def test_merge_fewer_than_two_sources_is_nothing_to_merge(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nothing_to_merge"] is True
        assert body["counted_gaps"][GAP_NOTHING_TO_MERGE] == 1
        assert body["attribute_divergences"] == 0


def test_merge_foreign_source_id_rejected(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.post(
            f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, "deadbeef-foreign"]}
        )
        assert r.status_code == 422, r.text
        detail = r.json()["detail"]
        assert detail["reason"] == "unknown_source_ids"
        assert "deadbeef-foreign" in detail["unknown"]


def test_merge_rejects_real_source_id_from_another_case(tmp_path: Path) -> None:
    """A REAL source_id that belongs to a DIFFERENT case is rejected (cross-case isolation).

    Hardens the foreign-id gate with a genuine other-case source (not a bogus string):
    caseB's ``_SRC_C`` is a valid source in its own store but foreign to caseA, so
    merging caseA with it must 422 — never silently merge across case boundaries.
    """
    src_c = "33333333-3333-5333-8333-333333333333"
    case_b = "ms5a-case-b"

    def _build_case_b(path: Path) -> None:
        con = duckdb.connect(str(path))
        try:
            create_canonical_tables(con)
            create_edge_tables(con)
            create_divergence_table(con)
            con.execute(
                "INSERT INTO source (source_id, case_id, dc_label, forest_id, "
                "ntds_image_sha256, ingest_run_id, ingested_at) "
                "VALUES (?, ?, 'DC-C', 'f2', 'cd', ?, ?)",
                [src_c, case_b, UUID(int=2), datetime.now(UTC)],
            )
        finally:
            con.close()

    with _case_client(tmp_path) as client:
        # caseA already exists (from _case_client); build caseB alongside it.
        ws_b = create_workspace(tmp_path, case_b)
        _build_case_b(Path(ws_b.canonical_db))
        r = client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, src_c]})
        assert r.status_code == 422, r.text
        detail = r.json()["detail"]
        assert detail["reason"] == "unknown_source_ids"
        assert src_c in detail["unknown"]
        # caseA's reader survives the rejected merge (rebound) — a follow-up read works.
        assert client.get("/api/v1/nodes/u1", params={"case_id": _CASE}).status_code == 200


def test_merge_unknown_case_404(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.post("/api/v1/cases/no-such-case/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        assert r.status_code == 404


# --------------------------------------------------------------------------- #
#  Divergence ledger read                                                     #
# --------------------------------------------------------------------------- #
def test_divergence_ledger_before_merge_is_honest_empty(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.get("/api/v1/divergence", params={"case_id": _CASE})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["merged"] is False
        assert body["rows"] == []
        assert body["counted_gaps"][GAP_NO_MERGE_RUN] == 1


def test_divergence_ledger_after_merge_returns_rows(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        body = client.get("/api/v1/divergence", params={"case_id": _CASE}).json()
        assert body["merged"] is True
        attrs = {row["attribute"] for row in body["rows"]}
        assert {"userAccountControl", "description"} <= attrs


def test_divergence_requires_case_id(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        r = client.get("/api/v1/divergence")
        assert r.status_code == 400
        assert r.json()["detail"]["reason"] == "case_id_required"


# --------------------------------------------------------------------------- #
#  Secret redaction in the ledger read (no digest / plaintext EVER)           #
# --------------------------------------------------------------------------- #
def test_ledger_read_never_surfaces_secret_digest() -> None:
    """A secret_divergence row reads back as {present,differs} only — no digest."""
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    create_divergence_table(con)
    _add_source(con, _SRC_A, "DC-A")
    _add_source(con, _SRC_B, "DC-B")
    for sid in (_SRC_A, _SRC_B):
        _add_node_obs(con, "u1", sid)
        _add_staging(con, "u1", sid)  # no attr divergence; isolate the secret row
    run_id = merge_run_id(_CASE)
    secret = "cafebabecafebabecafebabecafebabe"  # the plaintext-derived digest (must NOT leak)
    fingerprints = {
        ("u1", _SRC_A): frozenset({SecretFingerprint("nt_hash", "current", secret)}),
        ("u1", _SRC_B): frozenset({SecretFingerprint("nt_hash", "current", "0" * 32)}),
    }
    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=run_id, secret_fingerprints=fingerprints)
    assert result.secret_divergences == 1

    reader = StoreReader(con, Path(":memory:"))
    ledger = read_divergence_ledger(reader, _CASE)
    secret_rows = [r for r in ledger.rows if r.divergence_type == "secret_divergence"]
    assert len(secret_rows) == 1
    blob = json.dumps(ledger.model_dump(), default=str)
    assert secret not in blob
    assert "0" * 32 not in blob
    # value_by_source carries only the redacted present/differs flags
    for src_map in secret_rows[0].value_by_source.values():
        assert set(src_map) == {"present", "differs"}
    con.close()


# --------------------------------------------------------------------------- #
#  Dossier overlay: presented value + three-state badge                       #
# --------------------------------------------------------------------------- #
def test_merged_dossier_shows_presented_value_and_badges(tmp_path: Path) -> None:
    with _case_client(tmp_path) as client:
        client.post(f"/api/v1/cases/{_CASE}/merge", json={"source_ids": [_SRC_A, _SRC_B]})
        d = client.get("/api/v1/nodes/u1", params={"case_id": _CASE}).json()
        assert "merge" in d
        overlay = d["merge"]
        assert overlay["merged"] is True
        by_attr = {p["attribute"]: p for p in overlay["presented_attributes"]}
        # userAccountControl: tier-3 danger ordering presents the more-dangerous value
        assert by_attr["userAccountControl"]["state"] == "resolved"
        assert by_attr["userAccountControl"]["presented_value"] is not None
        # description: no danger ordering, no tier resolves -> contested, flagged
        assert by_attr["description"]["state"] == "contested_unresolved"
        assert by_attr["description"]["presented_value"] is None
        assert d["merge"]["counted_gaps"]["merge.attribute_contested"] == 1


def test_merged_dossier_secret_divergence_flag_only(tmp_path: Path) -> None:
    """The overlay direct builder flags secret divergence WITHOUT a digest."""
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    create_divergence_table(con)
    _add_source(con, _SRC_A, "DC-A")
    _add_source(con, _SRC_B, "DC-B")
    _add_principal(con, "u1")
    for sid in (_SRC_A, _SRC_B):
        _add_node_obs(con, "u1", sid)
        _add_staging(con, "u1", sid)
    fingerprints = {
        ("u1", _SRC_A): frozenset({SecretFingerprint("nt_hash", "current", "a" * 32)}),
        ("u1", _SRC_B): frozenset(),  # missing on DC-B -> holder-set divergence
    }
    merge_fold(con, [_SRC_A, _SRC_B], run_id=merge_run_id(_CASE), secret_fingerprints=fingerprints)
    reader = StoreReader(con, Path(":memory:"))
    overlay = build_merge_overlay(reader, "u1", _CASE)
    assert overlay is not None
    assert overlay.secret_divergence is True
    assert json.dumps(overlay.model_dump(), default=str).find("a" * 32) == -1
    con.close()


# --------------------------------------------------------------------------- #
#  Zero regression: non-merged dossier is byte-UNCHANGED                       #
# --------------------------------------------------------------------------- #
def test_non_merged_dossier_is_byte_unchanged(tmp_path: Path) -> None:
    from wraith.api.dossier import build_dossier

    ws = create_workspace(tmp_path, _CASE)
    _build_divergent_store(Path(ws.canonical_db))
    reader = StoreReader.open(Path(ws.canonical_db))
    try:
        # The raw dossier (no overlay machinery at all) is the pre-M-MS5a baseline.
        baseline = build_dossier(reader, "u1")
        assert baseline is not None
        baseline_json = baseline.model_dump(mode="json")
        assert "merge" not in baseline_json  # the serializer drops a None merge key
    finally:
        reader.close()

    with TestClient(create_app(cases_root=tmp_path)) as client:
        # Served WITH case_id but NO merge has run: byte-identical to the baseline,
        # and no ``merge`` key — the overlay path added nothing (zero regression).
        with_case = client.get("/api/v1/nodes/u1", params={"case_id": _CASE})
        assert with_case.status_code == 200, with_case.text
        assert "merge" not in with_case.json()
        assert with_case.json() == baseline_json


def test_overlay_none_when_no_merge(tmp_path: Path) -> None:
    path = tmp_path / "canonical.duckdb"
    _build_divergent_store(path)
    reader = StoreReader.open(path)
    try:
        assert build_merge_overlay(reader, "u1", _CASE) is None
    finally:
        reader.close()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
