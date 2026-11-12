"""Loading-% model for an analyze run (doc 14 §4).

The pipeline pass order is fixed (``wraith.export.pipeline`` module docstring).
This module holds the frozen weight table and the pure functions that turn a
*present-artifact set* + a *set of completed passes* into a 0-100 percentage:

    percent = floor(100 * completed_active_weight / total_active_weight)

where a pass is "active" only if its gating artifact is present. Weights are
nominal **perceived** progress, NOT time estimates — an operator must not read
the bar as an ETA (doc 14 §4). The FINAL state (100%, done) is deterministic;
intermediate timing is wall-clock and explicitly outside the determinism
guarantee.

Everything here is pure and deterministic; the mutable run state + thread that
drives real pass boundaries lives in :mod:`wraith.api.ingest`.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

#: How a pass becomes "active": always, only with SYSVOL, or only with >=1
#: member SAM (doc 14 §4 "active when" column).
ActiveRule = Literal["always", "sysvol", "member_sam"]


class PassSpec(BaseModel):
    """One pipeline pass's nominal weight + activation rule (doc 14 §4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    label: str
    weight: int
    active_rule: ActiveRule


#: Frozen weight table, in the pipeline's fixed execution order (doc 14 §4).
PASS_SPECS: Final[tuple[PassSpec, ...]] = (
    PassSpec(id="register", label="Hash + register artifacts", weight=5, active_rule="always"),
    PassSpec(id="normalize", label="Normalize entities (M3)", weight=20, active_rule="always"),
    PassSpec(id="membership", label="Resolve membership (M4)", weight=10, active_rule="always"),
    PassSpec(
        id="edges",
        label="Edge engine incl. ADCS topology (M5)",
        weight=30,
        active_rule="always",
    ),
    PassSpec(id="adcs_esc", label="ADCS ESC composites (M8)", weight=8, active_rule="always"),
    PassSpec(id="host_sam", label="Host-SAM AdminTo (M9)", weight=7, active_rule="member_sam"),
    PassSpec(id="gpo_sysvol", label="GPO/SYSVOL edges (Tier B)", weight=10, active_rule="sysvol"),
    PassSpec(id="export", label="BloodHound CE export (M6)", weight=10, active_rule="always"),
)

_SPEC_BY_ID: Final[dict[str, PassSpec]] = {p.id: p for p in PASS_SPECS}


def is_active(spec: PassSpec, present_kinds: Iterable[str]) -> bool:
    """Return whether ``spec`` runs for the given present-artifact set (doc 14 §4).

    ``always`` passes are active unconditionally; ``sysvol`` is active iff
    ``sysvol`` is present; ``member_sam`` iff at least one ``member_sam`` is
    present. Never raises.
    """
    present = set(present_kinds)
    if spec.active_rule == "always":
        return True
    if spec.active_rule == "sysvol":
        return "sysvol" in present
    return "member_sam" in present  # member_sam


def active_specs(present_kinds: Iterable[str]) -> tuple[PassSpec, ...]:
    """Return the active passes (in pipeline order) for a present-artifact set."""
    present = set(present_kinds)
    return tuple(p for p in PASS_SPECS if is_active(p, present))


def active_pass_ids(present_kinds: Iterable[str]) -> tuple[str, ...]:
    """Return the active pass ids (in pipeline order) — echoed in AnalyzeAccepted."""
    return tuple(p.id for p in active_specs(present_kinds))


def active_total(present_kinds: Iterable[str]) -> int:
    """Return ``Sigma weight`` over the active passes (``>= 0``; doc 14 §4).

    Always ``>= 1`` in practice (the ``always`` passes alone sum to 83), so the
    percent denominator is never zero; callers still guard (see :func:`percent`).
    """
    return sum(p.weight for p in active_specs(present_kinds))


def percent(completed_active_weight: float, total_active_weight: float) -> int:
    """Return ``floor(100 * completed / total)`` clamped to ``0..100`` (doc 14 §4).

    Inputs:
        completed_active_weight: summed weight of completed active passes (may be
            fractional for the host_sam intra-pass per-host split).
        total_active_weight: :func:`active_total` for the run.

    Returns:
        An integer 0-100. A zero/negative total yields 0 (defensive; the real
        total is always positive). Clamped so a fractional overshoot can never
        exceed 100.

    Failure modes:
        None.
    """
    if total_active_weight <= 0:
        return 0
    raw = math.floor(100.0 * completed_active_weight / total_active_weight)
    return max(0, min(100, raw))


def pass_spec(pass_id: str) -> PassSpec | None:
    """Return the :class:`PassSpec` for ``pass_id``, or ``None`` if unknown."""
    return _SPEC_BY_ID.get(pass_id)


__all__ = [
    "ActiveRule",
    "PassSpec",
    "PASS_SPECS",
    "is_active",
    "active_specs",
    "active_pass_ids",
    "active_total",
    "percent",
    "pass_spec",
]
