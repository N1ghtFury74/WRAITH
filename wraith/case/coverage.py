"""Coverage computation over the frozen catalog (doc 14 §2).

A pure, deterministic function of the *present artifact-kind set* and the frozen
:mod:`wraith.case.catalog`. No I/O, no network, no wall-clock. The same function
backs the pre-run **preview** (``GET /coverage``) and the post-run **actual**
coverage (recomputed from the run's registered artifacts), so an operator sees
the same truth before and after a run.

Honesty rule (CLAUDE.md): a capability is never silently "unavailable" — every
degraded/unavailable status carries one :class:`CoverageReason` per missing
artifact, naming the exact counted ``gap_class`` the analyze step bumps on the
run ledger.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from wraith.case.catalog import (
    CAPABILITIES,
    NO_NTDS_GAP_CLASS,
    REQUIRED_KIND_IDS,
    RESERVED_KIND_IDS,
    VALID_KIND_IDS,
    Capability,
    absence_effect,
    artifact_kind,
)

Status = Literal["available", "degraded", "unavailable"]


class CoverageReason(BaseModel):
    """Why a capability is degraded/unavailable (one per missing artifact)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    missing_artifact_id: str
    effect: Literal["degraded", "unavailable"]
    gap_class: str
    note: str


class CapabilityCoverage(BaseModel):
    """The resolved status of one capability given the present artifact set."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_id: str
    label: str
    tier: str
    status: Status
    reasons: tuple[CoverageReason, ...]  # empty iff status == "available"


class CoverageReport(BaseModel):
    """The full coverage verdict for an artifact set (doc 14 §2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    present_kinds: tuple[str, ...]  # sorted, deduped, catalog-known only
    missing_required: tuple[str, ...]  # [] unless ntds_dit absent
    can_analyze: bool  # == ntds_dit present
    capabilities: tuple[CapabilityCoverage, ...]  # one per CAPABILITIES, declared order


def _reason_for(missing_id: str, capability_id: str, present_raw: frozenset[str]) -> CoverageReason:
    """Build a :class:`CoverageReason` for ``missing_id`` unsatisfied on a capability.

    Three cases, in order:

    * ``missing_id`` is a *reserved* kind that WAS actually uploaded (in
      ``present_raw``): the artifact is on disk (provenance) but its consuming
      pass is not wired, so the reason uses ``reserved_pass_not_wired:<id>`` and a
      note that says so — NOT the generic "provide the CA host registry" (doc 14
      §2a: never ask the operator for what they already gave). The declared effect
      (degraded/unavailable) is preserved so status is unchanged.
    * the catalog declares a :class:`~wraith.case.catalog.CapabilityEffect` for
      ``missing_id`` on this capability: use it verbatim.
    * otherwise (the hard-required ``ntds_dit``, which has no declared effect):
      synthesize an ``unavailable`` reason with
      :data:`~wraith.case.catalog.NO_NTDS_GAP_CLASS`, so a capability is never
      shown unavailable without a stated reason.
    """
    effect = absence_effect(missing_id, capability_id)
    if missing_id in RESERVED_KIND_IDS and missing_id in present_raw:
        kind = artifact_kind(missing_id)
        label = kind.label if kind is not None else missing_id
        return CoverageReason(
            missing_artifact_id=missing_id,
            effect=effect.effect if effect is not None else "unavailable",
            gap_class=f"reserved_pass_not_wired:{missing_id}",
            note=f"{label} stored for provenance; the consuming pass is not yet wired.",
        )
    if effect is not None:
        return CoverageReason(
            missing_artifact_id=missing_id,
            effect=effect.effect,
            gap_class=effect.gap_class,
            note=effect.note,
        )
    return CoverageReason(
        missing_artifact_id=missing_id,
        effect="unavailable",
        gap_class=NO_NTDS_GAP_CLASS,
        note="NTDS database absent — no capability can be produced.",
    )


def _resolve(
    capability: Capability, effective: frozenset[str], present_raw: frozenset[str]
) -> CapabilityCoverage:
    """Resolve one capability's status + reasons (doc 14 §2 step 3, §2a amendment).

    Satisfaction is computed against ``effective`` (the present set with RESERVED
    kinds removed), so a capability needing a reserved artifact stays
    unavailable/degraded EXACTLY as if the artifact were absent — the pass is not
    wired. ``present_raw`` is consulted only to word a reserved-but-uploaded
    artifact's reason honestly (see :func:`_reason_for`).

    Precedence: an unsatisfied ``requires_all`` artifact makes the capability
    ``unavailable`` (any effect is ``unavailable``, or no declared effect — i.e.
    ``ntds_dit``) or ``degraded`` (all unsatisfied-required effects are
    ``degraded``); otherwise an unsatisfied ``degrades_without`` artifact makes it
    ``degraded``; otherwise ``available``. Reasons are emitted in catalog
    (declared-id) order for determinism.
    """
    absent_required = [a for a in capability.requires_all if a not in effective]
    if absent_required:
        reasons = tuple(_reason_for(a, capability.id, present_raw) for a in absent_required)
        status: Status = (
            "unavailable" if any(r.effect == "unavailable" for r in reasons) else "degraded"
        )
        return CapabilityCoverage(
            capability_id=capability.id,
            label=capability.label,
            tier=capability.tier,
            status=status,
            reasons=reasons,
        )

    absent_degrade = [a for a in capability.degrades_without if a not in effective]
    if absent_degrade:
        reasons = tuple(_reason_for(a, capability.id, present_raw) for a in absent_degrade)
        return CapabilityCoverage(
            capability_id=capability.id,
            label=capability.label,
            tier=capability.tier,
            status="degraded",
            reasons=reasons,
        )

    return CapabilityCoverage(
        capability_id=capability.id,
        label=capability.label,
        tier=capability.tier,
        status="available",
        reasons=(),
    )


def compute_coverage(present_kinds: Iterable[str]) -> CoverageReport:
    """Compute the coverage report for a set of present artifact kinds (doc 14 §2).

    Inputs:
        present_kinds: artifact-kind ids the operator has uploaded. Unknown ids
            are ignored (the upload endpoint already rejects them); duplicates are
            collapsed; order is irrelevant.

    Returns:
        A :class:`CoverageReport`. ``present_kinds`` is sorted + deduped (the RAW
        uploaded set — reserved kinds still show as present/``uploaded``);
        ``missing_required`` lists any required id (only ``ntds_dit``) still
        absent; ``can_analyze`` is ``True`` iff no required id is missing;
        ``capabilities`` has one :class:`CapabilityCoverage` per
        :data:`~wraith.case.catalog.CAPABILITIES`, in declared order. Capability
        satisfaction is computed against the present set with
        :data:`~wraith.case.catalog.RESERVED_KIND_IDS` removed (doc 14 §2a): an
        uploaded reserved artifact never makes its capability ``available``
        because no pass consumes it yet.

    Failure modes:
        None. Pure and deterministic: identical input sets -> identical report
        (iterates ``CAPABILITIES``/catalog in declared order; sorts present kinds).
    """
    present = frozenset(k for k in present_kinds if k in VALID_KIND_IDS)
    effective = present - RESERVED_KIND_IDS
    missing_required = tuple(k for k in REQUIRED_KIND_IDS if k not in present)
    return CoverageReport(
        present_kinds=tuple(sorted(present)),
        missing_required=missing_required,
        can_analyze=not missing_required,
        capabilities=tuple(_resolve(c, effective, present) for c in CAPABILITIES),
    )


def coverage_gap_bumps(report: CoverageReport) -> tuple[tuple[str, int], ...]:
    """Return the ``(gap_class, 1)`` bumps to count for an actual-run coverage.

    Every degraded/unavailable capability reason is a counted gap the analyze
    step records via ``IngestRun.bump_skip`` (CLAUDE.md: counted gap on every
    absent/degraded branch). Deterministic order (capability declared order, then
    reason order). The synthesized ``ntds_dit``-absent reason is excluded: ntds
    absent is a hard 422 and analyze never runs, so it is never bumped.

    Inputs:
        report: a :class:`CoverageReport` (typically the committed run preview).

    Returns:
        A tuple of ``(gap_class, count)`` pairs, one per real coverage reason.

    Failure modes:
        None.
    """
    bumps: list[tuple[str, int]] = []
    for cap in report.capabilities:
        for reason in cap.reasons:
            if reason.gap_class == NO_NTDS_GAP_CLASS:
                continue
            bumps.append((reason.gap_class, 1))
    return tuple(bumps)


__all__ = [
    "Status",
    "CoverageReason",
    "CapabilityCoverage",
    "CoverageReport",
    "compute_coverage",
    "coverage_gap_bumps",
]
