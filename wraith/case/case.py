"""Case-level configuration (``case.json``) read/write.

Holds the identity and authorization context of a case — what every run in the
case inherits. Separate from the per-run manifest (which records one ingest).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from wraith import SCHEMA_VERSION, WRAITH_VERSION
from wraith.acquisition.paths import validate_case_id
from wraith.common.determinism import canonical_json
from wraith.model.source import DcCardinality, DomainCardinality


class CaseConfig(BaseModel):
    """Case-level metadata persisted as ``case.json``.

    Fields:
        case_id: the validated case slug (also the directory name).
        operator: the responsible operator (attribution; redaction scope does
            not apply — this is not a secret).
        authorization_ref: engagement / authorization reference, if any.
        created_at: case creation timestamp (wall-clock; not a canonical row).
        forest_id_map: operator-assigned ``{domain_hint: forest_id}`` mapping;
            the scoping block's ``forest_id`` source for multi-forest support.
        domain_cardinality: the case-shape domain axis (multi-source contract
            §1.1) — ``single_domain`` (default) or ``multi_domain``; drives whether
            cross-domain edge wiring (M-MS3) runs. ``forest_scope`` is DERIVED from
            the distinct ``forest_id`` set, not a third axis (owner decision §8.3).
        dc_cardinality: the case-shape DC axis — ``single_dc`` (default) or
            ``multi_dc``; drives whether the Phase-2 merge/divergence engine
            (M-MS4) is *available*. ``multi_dc`` is ACCEPTED in Phase 1 for ingest
            + per-source views but merge stays disabled (owner decision §8.4);
            never a silent degradation.
        wraith_version / schema_version: tool + contract versions at creation.

    Back-compat: both case-shape axes default so an existing ``case.json`` written
    before M-MS1 loads unchanged as a ``single_domain`` / ``single_dc`` case (zero
    regression on the single-source path).

    Failure modes:
        Raises ``pydantic.ValidationError`` for an unsafe ``case_id`` or an
        out-of-vocabulary case-shape value.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    operator: str
    authorization_ref: str | None = None
    created_at: datetime
    forest_id_map: dict[str, str] = Field(default_factory=dict)
    domain_cardinality: DomainCardinality = "single_domain"
    dc_cardinality: DcCardinality = "single_dc"
    wraith_version: str = WRAITH_VERSION
    schema_version: str = SCHEMA_VERSION


def write_case_config(path: Path | str, config: CaseConfig) -> None:
    """Persist ``case.json`` in canonical JSON (LF).

    Inputs:
        path: destination (``CaseWorkspace.case_json``).
        config: the case configuration.

    Returns:
        None.

    Failure modes:
        Raises ``PathSafetyError`` if ``config.case_id`` is unsafe; ``OSError``
        on write failure.
    """
    validate_case_id(config.case_id)
    text = canonical_json(config.model_dump(mode="json"))
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def load_case_config(path: Path | str) -> CaseConfig:
    """Load and validate ``case.json``.

    Inputs:
        path: the ``case.json`` path.

    Returns:
        A validated ``CaseConfig``.

    Failure modes:
        Raises ``FileNotFoundError`` if absent; ``pydantic.ValidationError`` or
        ``json.JSONDecodeError`` if corrupt.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return CaseConfig.model_validate(data)
