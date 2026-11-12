"""Tester GATE (independent) — ADCS/ESC end-to-end WIRING + coverage-honesty slice.

This is the behavioural gate for the ESC *surfacing + wiring* delta (doc 16 §F,
assertions 3/4/5). It is deliberately the proof the standalone composition gate
(``tests/test_adcs_esc_gate.py``) never covered: that the ESC edges a crafted
fixture produces actually travel the FULL ``run_analysis_pipeline`` and land in
every downstream surface the operator uses —

  (a) the canonical ``edge`` table,
  (b) a kind-filtered graph slice (``build_slice``),
  (c) a node dossier (``build_dossier``),
  (d) the ``edge_kind_counts`` summary, and
  (e) the BloodHound export ledger (``export_bloodhound``) — honestly accounted,

with the ``adcs_esc`` progress pass firing on the pipeline ledger.

Because the pipeline front half (ESE parse + M3 normalize) cannot synthesise an
ADCS-bearing ``.dit`` offline (c137 has none), the ONLY stubbed seam is
``open_ntds`` + ``normalize`` — exactly the artifact-parse step that is already
gated by M2/M3. Everything downstream of it is the REAL code: the REAL
``resolve_membership`` → REAL ``compute_edges`` (topology + ACL base edges) → REAL
``run_adcs_esc`` (ESC composition) → REAL ``export_bloodhound``. The synthetic
ADCS fixture is reused from the coder's sanity builders (fixture reuse is allowed;
the assertions here are independent).

🧪 synthetic-only: this certifies the wiring + surfacing + coverage-honesty. The
GOAD + ``certipy find -vulnerable`` parity gate (flips 🧪 → ✅) is DEFERRED to the
CA-host-adapter spike (doc 16 §F "Later").
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

# Reuse the coder's SYNTHETIC ADCS fixture builders (real impacket SDs + real CA
# certs). Imported by basename (pytest prepend mode puts tests/ on sys.path).
import test_adcs_esc_sanity as fx

from wraith.analysis.adcs_esc import (
    KIND_ESC1,
    KIND_ESC9,
    KIND_ESC10A,
    KIND_ESC10B,
    DcConfigFlags,
    compute_adcs_esc,
    run_adcs_esc,
)
from wraith.api.dossier import build_dossier
from wraith.api.graph import build_slice
from wraith.api.queries import (
    PATHS_TO_ADCS_ESC,
    SET_ADCS_TOPOLOGY,
    SET_ENROLLMENT_RIGHTS,
    UnknownQueryError,
    UnsupportedQueryError,
    list_queries,
    run_query,
)
from wraith.api.store import StoreReader
from wraith.case.ingest_run import IngestRun
from wraith.export import pipeline as pipeline_mod
from wraith.export.pipeline import PipelineInputs, PipelineResult, run_analysis_pipeline
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import DomainIdentity, NormalizeResult

# The ESC1 edge the fixture is engineered to emit (Domain Users -> Domain object).
_ESC1_SRC = "n-grp513"
_ESC1_TGT = "n-domain"


# --- the synthetic ESC1-bearing store (rows only; M5/ESC run for real) --------


def _seed_esc1_rows(con: duckdb.DuckDBPyConnection) -> None:
    """Insert the raw canonical rows for a known ESC1 (no M5/ESC here — the pipeline
    runs those for real). Mirrors ``test_esc1_full_offline``'s fixture: a trusted
    Enterprise CA + NTAuth + an ENROLLEE_SUPPLIES_SUBJECT client-auth template
    enrollable by Domain Users (-513)."""
    create_canonical_tables(con)
    create_edge_tables(con)
    fx._vulnerable_ca_forest(con)
    fx._add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1Tpl",
        pki_flags=fx._enrollable_template(
            certificate_name_flag="1",  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag="0",  # no manager approval
            ra_signature="0",
            certificate_application_policy=[fx._EKU_CLIENT_AUTH],
        ),
        raw_sd=fx._enroll_sd(fx._SID_DOMAIN_USERS),
    )


def _install_fake_front_half(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub ONLY ``open_ntds`` + ``normalize`` (the ESE/M3 seam) so the pipeline
    seeds the synthetic ESC store, then runs the REAL membership/edge/ESC/export
    chain. Scoping is forced to match the fixture's forest/domain."""

    class _FakeParsed:
        schema = fx._empty_schema()

        def __enter__(self) -> _FakeParsed:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    def _fake_open_ntds(path: object, run: object, *, source_file: str) -> _FakeParsed:
        return _FakeParsed()

    def _fake_normalize(
        parsed: object,
        run: object,
        con: duckdb.DuckDBPyConnection,
        *,
        forest_id: str,
        source_id: str | None = None,
    ) -> NormalizeResult:
        _seed_esc1_rows(con)
        identity = DomainIdentity(
            domain_id=fx._DOMAIN_SID,
            domain_fqdn="corp.local",
            forest_id=forest_id,
            domain_dnt=None,
        )
        return NormalizeResult(
            identity=identity,
            entity_counts={},
            principal_type_counts={},
            staging_counts={},
            wellknown_stub_count=0,
            coverage_counts={},
            skip_counts={},
        )

    monkeypatch.setattr(pipeline_mod, "open_ntds", _fake_open_ntds)
    monkeypatch.setattr(pipeline_mod, "normalize", _fake_normalize)


def _run_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out_name: str = "out"
) -> tuple[duckdb.DuckDBPyConnection, PipelineResult, list[tuple[str, str]], Path]:
    """Drive the REAL ``run_analysis_pipeline`` on the synthetic ESC fixture with no
    SYSTEM hive. Returns ``(con, pipeline_result, progress_events, output_dir)``."""
    _install_fake_front_half(monkeypatch)
    ntds = tmp_path / "ntds.dit"
    ntds.write_bytes(b"\x00" * 64)  # only hashed/stat'd; open_ntds is stubbed
    out_dir = tmp_path / out_name
    con = duckdb.connect(":memory:")
    run = IngestRun("case-esc", "tester", ingest_run_id=fx._RUN)
    events: list[tuple[str, str]] = []
    result = run_analysis_pipeline(
        con,
        run,
        PipelineInputs(ntds_path=ntds, forest_id=fx._FOREST, system_hive_path=None),
        output_dir=out_dir,
        progress_cb=lambda pid, phase: events.append((pid, phase)),
    )
    return con, result, events, out_dir


# =============================================================================
# PROOF #1 — full end-to-end pipeline: ESC edge reaches every surface
# =============================================================================


def test_e2e_esc_edge_reaches_store_slice_dossier_counts_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    con, result, events, out_dir = _run_pipeline(tmp_path, monkeypatch)
    try:
        # (0) the adcs_esc progress pass fired, and the ESC composition ran for real.
        assert ("adcs_esc", "start") in events
        assert ("adcs_esc", "done") in events
        assert result.esc_result is not None
        assert result.esc_result.esc1 == 1

        # (a) canonical edge table carries the literal ESC1 edge.
        rows = con.execute(
            "SELECT source_node_id, target_node_id, confidence FROM edge WHERE kind = ?",
            [KIND_ESC1],
        ).fetchall()
        assert (_ESC1_SRC, _ESC1_TGT, "inferred") in {(r[0], r[1], r[2]) for r in rows}

        reader = StoreReader(con, Path(":memory:"))

        # (b) kind-filtered graph slice surfaces the ESC1 edge.
        sl = build_slice(
            reader,
            seed_node_ids=[_ESC1_SRC, _ESC1_TGT],
            edge_kinds=[KIND_ESC1],
            depth=0,
            expand_base_endpoints=False,
        )
        assert any(
            e.kind == KIND_ESC1 and e.source == _ESC1_SRC and e.target == _ESC1_TGT
            for e in sl.edges
        )

        # (c) node dossier lists the ESC1 edge as outbound on the holder.
        dossier = build_dossier(reader, _ESC1_SRC)
        assert dossier is not None
        assert KIND_ESC1 in {e.kind for e in dossier.outbound_edges}
        assert dossier.outbound_edge_counts.get(KIND_ESC1) == 1

        # (d) edge_kind_counts summary includes the ESC1 kind.
        assert reader.edge_kind_counts().get(KIND_ESC1) == 1

        # (e) BloodHound export ledger accounts the ESC1 kind — fully, no silent drop.
        #     ADCSESC1 is a BHCE-COMPOSED kind: WRAITH exports the base enrollment/ACL
        #     facts and marks the composite dropped=composed_by_bhce (BHCE recomposes
        #     it post-ingest). The honest proof is that it is COUNTED + ACCOUNTED, not
        #     that a literal ADCSESC1 edge appears in the JSON.
        disp = {d.kind: d for d in result.export_result.dispositions}
        assert KIND_ESC1 in disp, "ESC1 kind never reached the exporter"
        d1 = disp[KIND_ESC1]
        assert d1.count == 1
        assert d1.exported + sum(d1.dropped.values()) == d1.count  # no silent drop
        assert "composed_by_bhce" in d1.dropped
        assert KIND_ESC1 not in result.export_result.unmapped_kinds

        # export actually wrote the ingest bundle to disk.
        assert (out_dir / "bloodhound.zip").is_file()
        assert list(out_dir.glob("*.json"))
    finally:
        con.close()


# =============================================================================
# PROOF #4 — determinism: byte-identical export AND byte-identical query result
# =============================================================================


def test_e2e_determinism_export_bytes_and_query_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    con_a, res_a, _ev_a, out_a = _run_pipeline(tmp_path, monkeypatch, out_name="a")
    con_b, res_b, _ev_b, out_b = _run_pipeline(tmp_path, monkeypatch, out_name="b")
    try:
        # per-type JSON bytes identical across the two independent pipeline runs.
        files_a = sorted(p.name for p in out_a.glob("*.json"))
        files_b = sorted(p.name for p in out_b.glob("*.json"))
        assert files_a == files_b and files_a
        for name in files_a:
            assert (out_a / name).read_bytes() == (out_b / name).read_bytes(), name

        # same ESC composition count both runs (idempotent INSERT OR IGNORE).
        assert res_a.esc_result is not None and res_b.esc_result is not None
        assert res_a.esc_result.esc1 == res_b.esc_result.esc1 == 1

        # query results byte-identical across the two stores.
        reader_a = StoreReader(con_a, Path(":memory:"))
        reader_b = StoreReader(con_b, Path(":memory:"))
        for qid in (SET_ADCS_TOPOLOGY, SET_ENROLLMENT_RIGHTS, PATHS_TO_ADCS_ESC):
            a = run_query(reader_a, qid, max_hops=8, max_paths=25).model_dump()
            b = run_query(reader_b, qid, max_hops=8, max_paths=25).model_dump()
            assert a == b, qid
    finally:
        con_a.close()
        con_b.close()


# =============================================================================
# PROOF #2 — the three ADCS queries surface correctly on the synthetic store
# =============================================================================


def test_three_adcs_queries_resolve_run_and_badge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    con, _result, _events, _out = _run_pipeline(tmp_path, monkeypatch)
    try:
        reader = StoreReader(con, Path(":memory:"))

        # catalog listing: supported + synthetic-only badge + live non-zero count.
        by_id = {q.id: q for q in list_queries(reader)}
        for qid in (SET_ADCS_TOPOLOGY, SET_ENROLLMENT_RIGHTS, PATHS_TO_ADCS_ESC):
            spec = by_id[qid]
            assert spec.supported is True, qid
            assert spec.data_confidence == "synthetic-only", qid
            assert spec.source_count is not None and spec.source_count >= 1, qid

        # run outputs: non-empty, bounded, badge rides the run result, no gaps.
        topo = run_query(reader, SET_ADCS_TOPOLOGY, max_hops=8, max_paths=25)
        assert topo.kind == "set" and topo.slice is not None and topo.slice.returned >= 1
        assert topo.data_confidence == "synthetic-only" and topo.counted_gaps == {}

        enroll = run_query(reader, SET_ENROLLMENT_RIGHTS, max_hops=8, max_paths=25)
        assert enroll.kind == "set" and enroll.slice is not None and enroll.slice.returned >= 1
        assert enroll.data_confidence == "synthetic-only" and enroll.counted_gaps == {}

        esc = run_query(reader, PATHS_TO_ADCS_ESC, max_hops=8, max_paths=25)
        assert esc.kind == "path" and esc.paths is not None
        assert set(esc.paths.target_node_ids) == {_ESC1_TGT}
        assert esc.paths.paths_found >= 1
        assert esc.data_confidence == "synthetic-only" and esc.counted_gaps == {}
    finally:
        con.close()


def test_adcs_queries_count_named_gaps_on_empty_store() -> None:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    fx._add_domain(con)  # a domain object, but zero ADCS surface
    try:
        reader = StoreReader(con, Path(":memory:"))
        topo = run_query(reader, SET_ADCS_TOPOLOGY, max_hops=8, max_paths=25)
        assert topo.counted_gaps == {"no_adcs_topology": 1}
        assert topo.slice is not None and topo.slice.returned == 0
        assert topo.data_confidence == "synthetic-only"

        enroll = run_query(reader, SET_ENROLLMENT_RIGHTS, max_hops=8, max_paths=25)
        assert enroll.counted_gaps == {"no_enrollment_rights": 1}

        esc = run_query(reader, PATHS_TO_ADCS_ESC, max_hops=8, max_paths=25)
        assert esc.counted_gaps == {"empty_target_set": 1}
        assert esc.paths is not None and esc.paths.paths_found == 0
    finally:
        con.close()


def test_unknown_404_and_unsupported_422_hold() -> None:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    try:
        reader = StoreReader(con, Path(":memory:"))
        with pytest.raises(UnknownQueryError):
            run_query(reader, "no-such-query", max_hops=8, max_paths=25)
        # azure-paths is a frozen supported=False catalog entry -> 422 surface.
        with pytest.raises(UnsupportedQueryError):
            run_query(reader, "azure-paths", max_hops=8, max_paths=25)
    finally:
        con.close()


# =============================================================================
# PROOF #3 — the two coverage planes are DISTINCT (the honesty requirement)
# =============================================================================


def test_no_system_hive_plane_both_counters_equal_and_no_edge() -> None:
    """No SYSTEM hive supplied to the ESC pass ⇒ ESC9 undecidable: ``dc_config_absent``
    and ``dc_config_no_hive`` BOTH > 0 and EQUAL, and NO ESC9 edge / 'safe' verdict."""
    con = fx._esc9_store()
    try:
        run = IngestRun("c", "op", ingest_run_id=fx._RUN)
        result = run_adcs_esc(
            con,
            run,
            forest_id=fx._FOREST,
            domain_id=fx._DOMAIN_SID,
            domain_fqdn="corp.local",
            system_hive_path=None,
        )
        assert result.esc9 == 0
        assert result.dc_config_absent > 0
        assert result.dc_config_no_hive > 0
        assert result.dc_config_no_hive == result.dc_config_absent
        # hive_read=False NEVER yields an emitted ESC9/10 edge.
        kinds = {r[0] for r in con.execute("SELECT DISTINCT kind FROM edge").fetchall()}
        assert KIND_ESC9 not in kinds
        assert KIND_ESC10A not in kinds and KIND_ESC10B not in kinds
    finally:
        con.close()


def test_hive_present_value_unset_plane_is_distinct() -> None:
    """A SYSTEM hive WAS read but the cert-binding values are unset ⇒ still
    undecidable: ``dc_config_absent`` > 0 while ``dc_config_no_hive`` == 0 — the
    operator can tell 'no hive supplied' from 'hive read, value unset'."""
    con = fx._victim_store()  # ESC10 victim-write surface (UPN / dNSHostName writes)
    buf = fx._Buffer()
    try:
        result = compute_adcs_esc(
            con,
            buf,
            domain_node_id="n-domain",
            scoping=fx._SCOPING,
            dc_config=DcConfigFlags(hive_read=True),  # read, both values None
        )
        assert result.esc10a == 0 and result.esc10b == 0
        assert result.dc_config_absent > 0
        assert result.dc_config_no_hive == 0
        # no ESC10 edge emitted on an undecidable (value-unset) plane.
        emitted_kinds = {e.kind for e in buf.edges}  # type: ignore[attr-defined]
        assert KIND_ESC10A not in emitted_kinds
        assert KIND_ESC10B not in emitted_kinds
    finally:
        con.close()
