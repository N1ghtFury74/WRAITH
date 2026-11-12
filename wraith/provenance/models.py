"""Shared provenance pydantic models (schema §2.2 scoping, §2.3 provenance).

These are the data shapes every later module embeds on each entity/edge/finding
row. They are frozen (immutable) value objects: once attached at creation a
provenance fact cannot be mutated, matching the "provenance at the point of
creation" non-negotiable.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from wraith.common.validators import validate_sha256_hex


class ScopingBlock(BaseModel):
    """Multi-forest scoping block carried on every entity and edge (§2.2).

    Built now, exercised later: v1 ingests a single forest, but every row is
    already scoped so a second forest ingests with no key collisions.

    Fields:
        forest_id: stable forest identifier (required).
        domain_id: domain SID (or GUID); may be unknown at ingest time.
        domain_fqdn: e.g. ``corp.contoso.com``; may be unknown at ingest time.

    Failure modes:
        Raises ``pydantic.ValidationError`` if ``forest_id`` is missing/blank.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    forest_id: str
    domain_id: str | None = None
    domain_fqdn: str | None = None

    @field_validator("forest_id")
    @classmethod
    def _forest_id_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("forest_id must be a non-empty identifier")
        return value


class ProvenanceStruct(BaseModel):
    """Embedded chain-of-custody struct on every entity/edge/finding (§2.3).

    Fields:
        source_file: the immediate artifact that produced the record
            (e.g. ``ntds.dit``, ``SYSVOL/.../GptTmpl.inf``, ``SYSTEM``).
        image_sha256: SHA-256 of that immediate ``source_file`` (FR-02);
            lowercase 64-hex.
        source_object_id: the exact record identity (DNT / objectGUID / sd_id /
            DN / GPO path). ``None`` only when the fact is artifact-level.
        directory_timestamp: ``whenChanged``/``whenCreated`` of the source
            object, when known.
        ingest_run_id: the run-manifest id (NFR-06) — the logical join key back
            to the provenance ledger (§2.4).

    Failure modes:
        Raises ``pydantic.ValidationError`` if ``image_sha256`` is not a
        lowercase 64-hex string or ``source_file`` is blank.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_file: str
    image_sha256: str
    source_object_id: str | None = None
    directory_timestamp: datetime | None = None
    ingest_run_id: UUID

    @field_validator("source_file")
    @classmethod
    def _source_file_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source_file must be a non-empty label")
        return value

    @field_validator("image_sha256")
    @classmethod
    def _image_sha256_wellformed(cls, value: str) -> str:
        return validate_sha256_hex(value)
