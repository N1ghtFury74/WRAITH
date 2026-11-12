"""N-source multi-domain ingest loop (coder-side tests).

Covers :func:`wraith.export.pipeline.run_multi_source_pipeline` and its append /
first-writer-wins / single-cross-domain-resolver mechanics (multi-source contract
§3.5 / §4):

* **Store-level append (synthetic, no real ``.dit``)** — two DISTINCT-domain
  per-source stores append into ONE combined store with disjoint ids + ZERO
  canonical collisions; a same-node-id (same-domain) second source collides on the
  frozen single-PK tables (first-writer-wins, COUNTED) while its own ``source`` +
  per-source staging + ``source_observation`` still land; append order does not
  change the combined store (determinism).
* **Single cross-domain resolver** — a per-source M5 trust STUB edge is purged and
  the one :func:`derive_cross_domain_edges` pass emits the RESOLVED edge instead
  (never both a stub AND a resolved edge for one fact).
* **Real multi-DC smoke (skipif evidence)** — the committed real ``ntds.dit``
  ingested TWICE as two DCs of the SAME domain: the store is NOT corrupted,
  canonical stays consistent (first-writer-wins), BOTH ``source`` rows + per-source
  staging + ``source_observation`` exist, and the honest
  ``multi_dc_canonical_merge_pending_phase2`` marker is counted (NOT a crash /
  silent overwrite). Plus a single-source-equivalence regression.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.edges.cross_domain import derive_cross_domain_edges
from wraith.edges.derivations import KIND_SAME_FOREST_TRUST
from wraith.export.pipeline import (
    GAP_MULTI_DC_CANONICAL_MERGE_PENDING,
    PipelineInputs,
    _append_source_store,
    _purge_cross_domain_edges,
    run_analysis_pipeline,
    run_multi_source_pipeline,
)
from wraith.model.store import (
    create_canonical_tables,
    create_edge_tables,
    open_canonical_store,
)

FOREST = "f1"
DOM_A = "S-1-5-21-1-1-1"
DOM_B = "S-1-5-21-2-2-2"
RUN_ID = "00000000-0000-0000-0000-000000000000"
IMG = "a" * 64

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_evidence = _NTDS.is_file()


def _prov(oid: str | None = None) -> dict[str, object]:
    return {
        "source_file": "ntds.dit",
        "image_sha256": IMG,
        "source_object_id": oid,
        "directory_timestamp": None,
        "ingest_run_id": RUN_ID,
    }


def _combined() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _build_src_store(
    path: Path,
    *,
    source_id: str,
    dc_label: str,
    domain_id: str,
    fqdn: str,
    domain_node: str,
    trust_target: str | None = None,
    stub_edge_target: str | None = None,
    effective_pair: tuple[str, str] | None = None,
) -> None:
    """Write a minimal per-source store FILE mimicking the per-source pipeline output.

    One Domain container + source row + node observations, optionally a trust
    object (``trust_target`` SID), an M5-style per-source trust STUB edge
    (``stub_edge_target`` node id) to exercise the purge + single-resolver path, and
    an ``effective_membership`` closure pair (``effective_pair`` = member,group) to
    exercise the derived-table collision counter.
    """
    con = open_canonical_store(path)
    try:
        create_canonical_tables(con)
        create_edge_tables(con)
        con.execute(
            "INSERT INTO source (source_id,case_id,dc_label,forest_id,domain_id,domain_fqdn,"
            "declared_domain,ntds_image_sha256,system_image_sha256,is_global_catalog,"
            "ingest_run_id,ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,now())",
            [
                source_id,
                "c1",
                dc_label,
                FOREST,
                domain_id,
                fqdn,
                fqdn,
                "ab" * 32,
                None,
                False,
                RUN_ID,
            ],
        )
        con.execute(
            "INSERT INTO container (node_id,object_guid,object_sid,distinguished_name,"
            "container_type,forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
            [
                domain_node,
                domain_node,
                domain_id,
                f"DC={fqdn}",
                "Domain",
                FOREST,
                domain_id,
                fqdn,
                _prov(),
            ],
        )
        con.execute(
            "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
            "VALUES ('node',?,?,FALSE)",
            [domain_node, source_id],
        )
        if trust_target is not None:
            con.execute(
                "INSERT INTO trust (node_id,source_domain_id,target_domain_id,direction,trust_type,"
                "trust_attributes,transitive,sid_filtering,trust_key_ref,"
                "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    "t1",
                    domain_id,
                    trust_target,
                    "inbound",
                    2,
                    0x20,
                    True,
                    False,
                    None,
                    FOREST,
                    domain_id,
                    fqdn,
                    _prov("t1"),
                ],
            )
            con.execute(
                "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
                "VALUES ('node','t1',?,FALSE)",
                [source_id],
            )
        if stub_edge_target is not None:
            # An M5-style per-source trust stub edge (partner not in THIS source).
            con.execute(
                "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,is_inherited,"
                "derivation,confidence,forest_id,domain_id,domain_fqdn,provenance) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    "stub-e1",
                    KIND_SAME_FOREST_TRUST,
                    domain_node,
                    stub_edge_target,
                    False,
                    "DERIV:same_forest_trust",
                    "confirmed",
                    FOREST,
                    domain_id,
                    fqdn,
                    _prov("t1"),
                ],
            )
            con.execute(
                "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
                "VALUES ('edge','stub-e1',?,FALSE)",
                [source_id],
            )
        if effective_pair is not None:
            con.execute(
                "INSERT INTO effective_membership "
                "(member_node_id,group_node_id,forest_id,domain_id) VALUES (?,?,?,?)",
                [effective_pair[0], effective_pair[1], FOREST, domain_id],
            )
    finally:
        con.close()


def _ids(con: duckdb.DuckDBPyConnection, table: str, col: str) -> set[str]:
    return {str(r[0]) for r in con.execute(f"SELECT {col} FROM {table}").fetchall()}


# --------------------------------------------------------------------------- #
#  Layer A — store-level append: distinct domains, zero collisions             #
# --------------------------------------------------------------------------- #
def test_distinct_domains_append_disjoint_zero_collisions(tmp_path: Path) -> None:
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    _build_src_store(
        a,
        source_id="src-A",
        dc_label="DC-A",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
    )
    _build_src_store(
        b,
        source_id="src-B",
        dc_label="DC-B",
        domain_id=DOM_B,
        fqdn="b.local",
        domain_node="dnode_b",
    )

    con = _combined()
    assert _append_source_store(con, a) == 0
    assert _append_source_store(con, b) == 0

    assert _ids(con, "container", "node_id") == {"dnode_a", "dnode_b"}
    assert _ids(con, "source", "source_id") == {"src-A", "src-B"}
    # Per-source observations stay distinct (no bleed).
    assert (
        con.execute("SELECT COUNT(*) FROM source_observation WHERE source_id='src-A'").fetchone()[0]
        == 1
    )


def test_append_order_is_deterministic(tmp_path: Path) -> None:
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    _build_src_store(
        a,
        source_id="src-A",
        dc_label="DC-A",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
    )
    _build_src_store(
        b,
        source_id="src-B",
        dc_label="DC-B",
        domain_id=DOM_B,
        fqdn="b.local",
        domain_node="dnode_b",
    )

    c1 = _combined()
    _append_source_store(c1, a)
    _append_source_store(c1, b)
    c2 = _combined()
    _append_source_store(c2, b)
    _append_source_store(c2, a)

    assert _ids(c1, "container", "node_id") == _ids(c2, "container", "node_id")
    assert _ids(c1, "source", "source_id") == _ids(c2, "source", "source_id")


# --------------------------------------------------------------------------- #
#  Layer B — same-domain collision: first-writer-wins + counted, no crash      #
# --------------------------------------------------------------------------- #
def test_same_domain_second_source_collides_counted_no_overwrite(tmp_path: Path) -> None:
    # Two DCs of the SAME domain => identical canonical node_ids, distinct sources.
    a1 = tmp_path / "a1.duckdb"
    a2 = tmp_path / "a2.duckdb"
    _build_src_store(
        a1,
        source_id="src-A1",
        dc_label="DC-A1",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
    )
    _build_src_store(
        a2,
        source_id="src-A2",
        dc_label="DC-A2",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
    )

    con = _combined()
    assert _append_source_store(con, a1) == 0
    collisions = _append_source_store(con, a2)
    assert collisions == 1  # the one Domain container node_id collided

    # Canonical NOT overwritten / not duplicated (first-writer-wins).
    assert con.execute("SELECT COUNT(*) FROM container").fetchone()[0] == 1
    # BOTH source rows + BOTH per-source observations exist (per-source views work).
    assert _ids(con, "source", "source_id") == {"src-A1", "src-A2"}
    obs = con.execute(
        "SELECT source_id FROM source_observation WHERE obj_id='dnode_a' ORDER BY source_id"
    ).fetchall()
    assert [str(r[0]) for r in obs] == ["src-A1", "src-A2"]


def test_effective_membership_collision_is_counted(tmp_path: Path) -> None:
    # Two same-domain DCs sharing an effective_membership closure pair: the derived
    # table collides first-writer-wins and the dropped row is COUNTED on the run
    # (distinct from the frozen-canonical tally), never silent.
    a1 = tmp_path / "a1.duckdb"
    a2 = tmp_path / "a2.duckdb"
    pair = ("m-node", "g-node")
    _build_src_store(
        a1,
        source_id="src-A1",
        dc_label="DC-A1",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
        effective_pair=pair,
    )
    _build_src_store(
        a2,
        source_id="src-A2",
        dc_label="DC-A2",
        domain_id=DOM_A,
        fqdn="a.local",
        domain_node="dnode_a",
        effective_pair=pair,
    )

    con = _combined()
    run = IngestRun(case_id="c1", operator="t", ingest_run_id=UUID(RUN_ID))
    _append_source_store(con, a1, run)
    _append_source_store(con, a2, run)

    # The closure pair is kept once (first-writer-wins); the dropped second copy is
    # counted on the dedicated derived-table marker.
    assert con.execute("SELECT COUNT(*) FROM effective_membership").fetchone()[0] == 1
    assert run.skip_counts.get("multi_dc_effective_membership_merge_pending_phase2") == 1


# --------------------------------------------------------------------------- #
#  Layer C — single cross-domain resolver (purge stub, derive resolved once)   #
# --------------------------------------------------------------------------- #
def test_purge_then_single_resolver_no_stub_and_resolved(tmp_path: Path) -> None:
    # A (child) has a within-forest trust to B (parent) + an M5 stub trust edge to a
    # non-ingested-in-A stub target. After append of BOTH domains, the stub is purged
    # and the one resolver emits the RESOLVED dnode_a -> dnode_b edge.
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    _build_src_store(
        a,
        source_id="src-A",
        dc_label="DC-A",
        domain_id=DOM_A,
        fqdn="child.corp.local",
        domain_node="dnode_a",
        trust_target=DOM_B,
        stub_edge_target="stub_b",
    )
    _build_src_store(
        b,
        source_id="src-B",
        dc_label="DC-B",
        domain_id=DOM_B,
        fqdn="corp.local",
        domain_node="dnode_b",
    )

    con = _combined()
    _append_source_store(con, a)
    _append_source_store(con, b)
    # The per-source M5 stub edge is present pre-purge.
    assert "stub-e1" in _ids(con, "edge", "edge_id")

    _purge_cross_domain_edges(con)
    assert "stub-e1" not in _ids(con, "edge", "edge_id")

    run = IngestRun(case_id="c1", operator="t", ingest_run_id=UUID(RUN_ID))
    res = derive_cross_domain_edges(con, run)
    assert res.trust_edges == 1
    edges = [
        (str(k), str(s), str(t))
        for k, s, t in con.execute(
            "SELECT kind,source_node_id,target_node_id FROM edge ORDER BY kind"
        ).fetchall()
    ]
    # Exactly one trust edge: the RESOLVED one (no lingering stub to stub_b).
    assert (KIND_SAME_FOREST_TRUST, "dnode_a", "dnode_b") in edges
    assert all(t != "stub_b" for _, _, t in edges)


# --------------------------------------------------------------------------- #
#  Layer D — REAL multi-DC smoke (same domain twice): no corruption + marker   #
# --------------------------------------------------------------------------- #
def _real_inputs(dc_label: str, source_file: str) -> PipelineInputs:
    return PipelineInputs(
        ntds_path=_NTDS,
        forest_id="forest-c137",
        system_hive_path=_SYSTEM if _SYSTEM.is_file() else None,
        ntds_source_file=source_file,
        dc_label=dc_label,
        domain_cardinality="single_domain",
        dc_cardinality="multi_dc",
    )


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_real_multi_dc_same_domain_twice(tmp_path: Path) -> None:
    con = duckdb.connect(":memory:")
    run = IngestRun("c1", "tester", ingest_run_id=uuid4())
    try:
        result = run_multi_source_pipeline(
            con,
            run,
            [_real_inputs("DC-1", "ntds.dit"), _real_inputs("DC-2", "ntds.dit:dc2")],
            output_dir=tmp_path / "bh",
            scratch_dir=tmp_path / "scratch",
        )
        # Two sources, ONE domain, and the same-domain collision is counted.
        assert result.source_count == 2
        assert result.domain_count == 1
        assert result.canonical_collisions > 0
        assert (
            run.skip_counts.get(GAP_MULTI_DC_CANONICAL_MERGE_PENDING) == result.canonical_collisions
        )

        # Store NOT corrupted: both source rows + per-source staging/observation.
        assert con.execute("SELECT COUNT(*) FROM source").fetchone()[0] == 2
        src_ids = [str(r[0]) for r in con.execute("SELECT source_id FROM source").fetchall()]
        for sid in src_ids:
            assert (
                con.execute(
                    "SELECT COUNT(*) FROM staging_object WHERE source_id=?", [sid]
                ).fetchone()[0]
                > 0
            )
            assert (
                con.execute(
                    "SELECT COUNT(*) FROM source_observation WHERE source_id=?", [sid]
                ).fetchone()[0]
                > 0
            )
        # Canonical stays consistent: principals present and single-PK intact
        # (no duplicate node_id rows survived the collision).
        total = con.execute("SELECT COUNT(*) FROM principal").fetchone()[0]
        distinct = con.execute("SELECT COUNT(DISTINCT node_id) FROM principal").fetchone()[0]
        assert total == distinct > 0
    finally:
        con.close()


@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_real_single_source_loop_matches_single_pipeline(tmp_path: Path) -> None:
    # run_multi_source_pipeline with ONE source => same canonical node set as the
    # single-source run_analysis_pipeline (regression: the loop does not lose nodes).
    con_single = duckdb.connect(":memory:")
    con_multi = duckdb.connect(":memory:")
    try:
        run_analysis_pipeline(
            con_single,
            IngestRun("c1", "t", ingest_run_id=uuid4()),
            _real_inputs("DC-1", "ntds.dit"),
            output_dir=tmp_path / "s",
        )
        run_multi_source_pipeline(
            con_multi,
            IngestRun("c1", "t", ingest_run_id=uuid4()),
            [_real_inputs("DC-1", "ntds.dit")],
            output_dir=tmp_path / "m",
            scratch_dir=tmp_path / "scratch",
        )
        for table in ("principal", "container", "gpo", "adcs"):
            n_single = con_single.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            n_multi = con_multi.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert n_single == n_multi, table

        # Non-cross-domain edge kinds (MemberOf/ACL/etc.) are byte-for-byte unchanged
        # by the loop (only the cross-domain-kind edges are purged + re-derived).
        def _kinds(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
            return {
                str(k): int(c)
                for k, c in con.execute("SELECT kind, COUNT(*) FROM edge GROUP BY kind").fetchall()
            }

        cross = {
            "SameForestTrust",
            "CrossForestTrust",
            "HasTrustKeys",
            "HasSIDHistory",
            "ForeignIdentity",
        }
        ks, km = _kinds(con_single), _kinds(con_multi)
        for kind in set(ks) - cross:
            assert ks[kind] == km.get(kind), kind
    finally:
        con_single.close()
        con_multi.close()
