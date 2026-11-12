"""Module 14 — unit / golden layer (pure, no evidence needed).

Covers the three pure cores of the case/ingest + coverage API:

* :mod:`wraith.case.coverage` — ``compute_coverage`` across artifact sets incl.
  the §2a reserved-artifact honesty rule + determinism + ``coverage_gap_bumps``.
* :mod:`wraith.case.progress_model` — active-pass selection + the §4 percent model.
* :mod:`wraith.case.catalog` — table integrity invariants.

Every expected value is hand-derived from the locked contract
``docs/research/14-case-ingest-coverage-api-decisions.md`` §1-§2a/§4.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wraith.api.app import create_app
from wraith.case.catalog import (
    CAPABILITIES,
    CATALOG,
    NO_NTDS_GAP_CLASS,
    REQUIRED_KIND_IDS,
    RESERVED_KIND_IDS,
    absence_effect,
)
from wraith.case.coverage import (
    CoverageReason,
    CoverageReport,
    compute_coverage,
    coverage_gap_bumps,
)
from wraith.case.progress_model import (
    PASS_SPECS,
    active_pass_ids,
    active_total,
    percent,
)
from wraith.common.determinism import canonical_json

# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #


def _status(report: CoverageReport, cap_id: str) -> str:
    return next(c.status for c in report.capabilities if c.capability_id == cap_id)


def _reasons(report: CoverageReport, cap_id: str) -> tuple[CoverageReason, ...]:
    return next(c.reasons for c in report.capabilities if c.capability_id == cap_id)


def _gap_classes(report: CoverageReport, cap_id: str) -> set[str]:
    return {r.gap_class for r in _reasons(report, cap_id)}


# --------------------------------------------------------------------------- #
#  catalog integrity                                                           #
# --------------------------------------------------------------------------- #


def test_required_and_reserved_kind_ids() -> None:
    assert REQUIRED_KIND_IDS == ("ntds_dit",)
    # module 35b wired ``ca_host_registry`` -> ``ca_host_system_path``; only
    # ``additional_dc`` remains reserved (multi-DC merge not built).
    assert RESERVED_KIND_IDS == frozenset({"additional_dc"})
    # reserved <=> no wired pipeline field
    for kind in CATALOG:
        assert (kind.pipeline_field is None) == (kind.id in RESERVED_KIND_IDS)
    # the CA-host kind now names its real pipeline input
    ca = next(k for k in CATALOG if k.id == "ca_host_registry")
    assert ca.pipeline_field == "ca_host_system_path"


def test_effect_index_covers_every_capability_relationship() -> None:
    """Every (artifact -> capability) dependency except ntds_dit declares a counted
    CapabilityEffect, so a degraded/unavailable status is never silent (§1.2)."""
    for cap in CAPABILITIES:
        for art_id in (*cap.requires_all, *cap.degrades_without):
            if art_id == "ntds_dit":
                # documented exception: ntds absent is a hard 422, synthesized reason
                assert absence_effect(art_id, cap.id) is None
                continue
            eff = absence_effect(art_id, cap.id)
            assert eff is not None, f"missing effect for {art_id} -> {cap.id}"
            assert eff.capability_id == cap.id
            assert eff.gap_class  # non-empty counted-gap key


def test_capabilities_cover_catalog_order() -> None:
    # coverage report preserves CAPABILITIES declared order
    rep = compute_coverage(["ntds_dit"])
    assert [c.capability_id for c in rep.capabilities] == [c.id for c in CAPABILITIES]


# --------------------------------------------------------------------------- #
#  coverage — artifact sets                                                    #
# --------------------------------------------------------------------------- #


def test_empty_set_cannot_analyze() -> None:
    rep = compute_coverage([])
    assert rep.can_analyze is False
    assert rep.missing_required == ("ntds_dit",)
    assert rep.present_kinds == ()
    # every capability unavailable; each cites the synthesized ntds reason (ntds is
    # in every requires_all). Multi-requirement caps may carry additional reasons.
    for cap in rep.capabilities:
        assert cap.status == "unavailable"
        assert NO_NTDS_GAP_CLASS in {r.gap_class for r in cap.reasons}
    # the synthesized ntds reason is NEVER a counted run gap
    assert NO_NTDS_GAP_CLASS not in {gc for gc, _ in coverage_gap_bumps(rep)}


def test_ntds_only() -> None:
    rep = compute_coverage(["ntds_dit"])
    assert rep.can_analyze is True
    assert rep.missing_required == ()
    assert _status(rep, "core_directory_graph") == "available"
    # base facts degrade without system_hive AND ca_host_registry
    assert _status(rep, "adcs_base_facts") == "degraded"
    assert _gap_classes(rep, "adcs_base_facts") == {
        "adcs_dc_config_degraded_no_system_hive",
        "adcs_degraded_no_ca_hive",
    }
    assert _status(rep, "secret_recovery") == "unavailable"
    assert _gap_classes(rep, "secret_recovery") == {"secrets_unavailable_no_system_hive"}
    assert _status(rep, "adcs_esc_dc_config") == "unavailable"
    assert _status(rep, "gpo_driven_edges") == "unavailable"
    assert _status(rep, "host_adminto") == "unavailable"
    # reserved caps use the GENERIC catalog reason (not uploaded)
    assert _gap_classes(rep, "ca_host_edges") == {"ca_host_edges_unavailable_no_ca_hive"}
    assert _gap_classes(rep, "multi_domain_forest") == {"multi_domain_unavailable_single_dc"}


def test_ntds_plus_system_hive() -> None:
    rep = compute_coverage(["ntds_dit", "system_hive"])
    assert _status(rep, "secret_recovery") == "available"
    assert _status(rep, "adcs_esc_dc_config") == "available"
    # base facts still degraded — only because ca_host_registry is absent now
    assert _status(rep, "adcs_base_facts") == "degraded"
    assert _gap_classes(rep, "adcs_base_facts") == {"adcs_degraded_no_ca_hive"}


def test_ntds_plus_sysvol() -> None:
    rep = compute_coverage(["ntds_dit", "sysvol"])
    assert _status(rep, "gpo_driven_edges") == "available"
    assert _status(rep, "host_adminto") == "unavailable"


def test_ntds_plus_member_sam() -> None:
    rep = compute_coverage(["ntds_dit", "member_sam"])
    assert _status(rep, "host_adminto") == "available"
    assert _status(rep, "gpo_driven_edges") == "unavailable"


def test_full_real_set() -> None:
    rep = compute_coverage(["ntds_dit", "system_hive", "sysvol", "member_sam"])
    # every NON-reserved capability is available
    available = {
        "core_directory_graph",
        "secret_recovery",
        "adcs_esc_dc_config",
        "gpo_driven_edges",
        "host_adminto",
    }
    for cap in rep.capabilities:
        if cap.capability_id in available:
            assert cap.status == "available", cap.capability_id
            assert cap.reasons == ()
    # adcs_base_facts still degraded (ca_host_registry not in this set -> absent)
    assert _status(rep, "adcs_base_facts") == "degraded"
    assert _gap_classes(rep, "adcs_base_facts") == {"adcs_degraded_no_ca_hive"}
    # ca_host / multi-domain caps remain unavailable (not uploaded here)
    assert _status(rep, "ca_host_edges") == "unavailable"
    assert _status(rep, "multi_domain_forest") == "unavailable"


# --------------------------------------------------------------------------- #
#  coverage — §2a reserved-artifact honesty                                    #
# --------------------------------------------------------------------------- #


def test_ca_host_uploaded_unlocks_ca_host_edges() -> None:
    """Module 35b wired reality: supplying ``ca_host_registry`` makes ``_CA_HOST``
    AVAILABLE (ManageCA/ManageCertificates + full-ESC resolution), replacing the old
    ``reserved_pass_not_wired`` coverage. The reserved-honesty wording is gone — the
    pass now runs with real CA-host facts."""
    rep = compute_coverage(["ntds_dit", "ca_host_registry"])
    assert "ca_host_registry" in rep.present_kinds
    # the capability is now produced — no reserved reason survives
    assert _status(rep, "ca_host_edges") == "available"
    assert _reasons(rep, "ca_host_edges") == ()
    # adcs_base_facts is no longer degraded BY the CA hive (system_hive still absent,
    # but the ca-hive degrade reason is gone)
    assert "adcs_degraded_no_ca_hive" not in _gap_classes(rep, "adcs_base_facts")
    assert "reserved_pass_not_wired:ca_host_registry" not in _gap_classes(rep, "adcs_base_facts")
    # with BOTH optional hives present, adcs_base_facts is fully available
    rep2 = compute_coverage(["ntds_dit", "system_hive", "ca_host_registry"])
    assert _status(rep2, "adcs_base_facts") == "available"
    assert _reasons(rep2, "adcs_base_facts") == ()


def test_ca_host_absent_keeps_generic_counted_gap() -> None:
    """The absent path is unchanged: with NO CA hive, ``_CA_HOST`` is unavailable via
    the GENERIC catalog gap (``ca_host_edges_unavailable_no_ca_hive``) — never the
    reserved wording — and ``adcs_base_facts`` carries ``adcs_degraded_no_ca_hive``.
    This is byte-for-byte the pre-35b ntds-only coverage."""
    rep = compute_coverage(["ntds_dit"])
    assert _status(rep, "ca_host_edges") == "unavailable"
    assert _gap_classes(rep, "ca_host_edges") == {"ca_host_edges_unavailable_no_ca_hive"}
    assert "adcs_degraded_no_ca_hive" in _gap_classes(rep, "adcs_base_facts")


def test_reserved_additional_dc_uploaded_stays_unavailable_with_wired_reason() -> None:
    rep = compute_coverage(["ntds_dit", "additional_dc"])
    assert "additional_dc" in rep.present_kinds
    assert _status(rep, "multi_domain_forest") == "unavailable"
    assert _gap_classes(rep, "multi_domain_forest") == {"reserved_pass_not_wired:additional_dc"}


def test_coverage_gap_bumps_includes_reserved_present_excludes_ntds() -> None:
    # ``additional_dc`` is the remaining reserved kind (ca_host_registry is wired now);
    # an uploaded reserved kind still contributes its ``reserved_pass_not_wired`` bump.
    rep = compute_coverage(["ntds_dit", "additional_dc"])
    classes = {gc for gc, _ in coverage_gap_bumps(rep)}
    assert "reserved_pass_not_wired:additional_dc" in classes
    assert NO_NTDS_GAP_CLASS not in classes
    # every bump has count 1
    assert all(n == 1 for _, n in coverage_gap_bumps(rep))


# --------------------------------------------------------------------------- #
#  coverage — determinism / unknown kinds                                      #
# --------------------------------------------------------------------------- #


def test_determinism_reordered_and_duplicated_inputs() -> None:
    a = compute_coverage(["ntds_dit", "system_hive", "sysvol"])
    b = compute_coverage(["sysvol", "sysvol", "system_hive", "ntds_dit"])
    assert canonical_json(a.model_dump(mode="json")) == canonical_json(b.model_dump(mode="json"))
    assert a.present_kinds == ("ntds_dit", "system_hive", "sysvol")  # sorted, deduped


def test_unknown_kinds_ignored() -> None:
    rep = compute_coverage(["ntds_dit", "not_a_real_kind"])
    assert "not_a_real_kind" not in rep.present_kinds
    assert rep.can_analyze is True


# --------------------------------------------------------------------------- #
#  progress model (§4)                                                         #
# --------------------------------------------------------------------------- #


def test_all_active_sums_to_100() -> None:
    full = ["ntds_dit", "system_hive", "sysvol", "member_sam"]
    assert active_total(full) == 100
    assert active_pass_ids(full) == tuple(p.id for p in PASS_SPECS)


def test_host_sam_and_gpo_inactive_without_their_artifact() -> None:
    ids = active_pass_ids(["ntds_dit"])
    assert "host_sam" not in ids
    assert "gpo_sysvol" not in ids
    assert active_total(["ntds_dit"]) == 83  # 100 - 7 (host_sam) - 10 (gpo_sysvol)
    # gating is per-artifact
    assert "gpo_sysvol" in active_pass_ids(["ntds_dit", "sysvol"])
    assert "host_sam" in active_pass_ids(["ntds_dit", "member_sam"])
    assert "gpo_sysvol" not in active_pass_ids(["ntds_dit", "member_sam"])


@pytest.mark.parametrize(
    "present",
    [
        ["ntds_dit"],
        ["ntds_dit", "sysvol"],
        ["ntds_dit", "member_sam"],
        ["ntds_dit", "system_hive", "sysvol", "member_sam"],
    ],
)
def test_percent_monotonic_non_decreasing_and_terminal_100(present: list[str]) -> None:
    specs = [p for p in PASS_SPECS if p.id in active_pass_ids(present)]
    total = active_total(present)
    completed = 0.0
    last = -1
    for spec in specs:
        pct_start = percent(completed, total)
        completed += spec.weight
        pct_done = percent(completed, total)
        assert pct_start >= last
        assert pct_done >= pct_start
        last = pct_done
    assert percent(completed, total) == 100


def test_percent_zero_total_and_clamp() -> None:
    assert percent(5, 0) == 0  # defensive zero denominator
    assert percent(200, 100) == 100  # overshoot clamped
    assert percent(0, 100) == 0


# --------------------------------------------------------------------------- #
#  delete-case endpoint smoke (TestClient; no evidence needed)                 #
# --------------------------------------------------------------------------- #


@pytest.fixture
def delete_client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(cases_root=tmp_path)) as c:
        yield c


def test_delete_case_then_404_on_refetch(delete_client: TestClient) -> None:
    assert (
        delete_client.post("/api/v1/cases", json={"case_id": "delme", "operator": "t"}).status_code
        == 201
    )
    # the case is listed before deletion
    assert any(item["case_id"] == "delme" for item in delete_client.get("/api/v1/cases").json())

    deleted = delete_client.delete("/api/v1/cases/delme")
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"case_id": "delme", "deleted": True}

    # re-fetch / re-delete now 404s; the case is gone from the listing
    assert delete_client.get("/api/v1/cases/delme/coverage").status_code == 404
    assert delete_client.delete("/api/v1/cases/delme").status_code == 404
    assert not any(item["case_id"] == "delme" for item in delete_client.get("/api/v1/cases").json())


def test_delete_unknown_case_404(delete_client: TestClient) -> None:
    r = delete_client.delete("/api/v1/cases/never-created")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "unknown_case"


def test_delete_unsafe_case_id_400(delete_client: TestClient) -> None:
    # a leading dot is rejected by validate_case_id before any filesystem touch
    r = delete_client.delete("/api/v1/cases/.hidden")
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "unsafe_case_id"
