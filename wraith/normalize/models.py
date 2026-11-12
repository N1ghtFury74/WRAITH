"""Canonical row dataclasses + nested-value encoders for Module 3.

Each row class mirrors its DuckDB table's column order exactly (see
``wraith/model/store.py``) and exposes :meth:`to_db_values` producing the
positional tuple the writer passes to ``executemany``. Nested columns are
already native Python (``list``/``dict``) on the dataclass; only the embedded
provenance struct and timestamps are normalized at write time (naive UTC).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from wraith.common.determinism import canonical_json
from wraith.model.store import DEFAULT_SOURCE_ID
from wraith.normalize.decoders import to_naive_utc
from wraith.provenance.models import ProvenanceStruct

#: A nested STRUCT value as a plain dict, or a LIST(STRUCT) as a list of dicts.
StructValue = Mapping[str, object]


def _prov_to_struct(provenance: ProvenanceStruct) -> dict[str, object]:
    """Encode a :class:`ProvenanceStruct` as the DuckDB provenance STRUCT dict."""
    return {
        "source_file": provenance.source_file,
        "image_sha256": provenance.image_sha256,
        "source_object_id": provenance.source_object_id,
        "directory_timestamp": to_naive_utc(provenance.directory_timestamp),
        "ingest_run_id": provenance.ingest_run_id,
    }


def _json_safe(value: object) -> object:
    """Recursively convert an NTDS attribute value to a JSON-safe structure.

    Bytes become ``{"__bytes_hex__": hex}`` (round-trippable — M5 reconstructs
    the raw delegation/RBCD/keyCredentialLink blobs), datetimes become
    ``{"__datetime__": iso}`` (round-trippable), and lists/dicts recurse. Any
    OTHER type falls back to ``{"__repr__": str(v)}`` — surfaced, never silently
    dropped, but a lossy (non-round-trippable) representation; in practice NTDS
    values are only bytes/int/str/datetime/lists, so the fallback is a safety net.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"__bytes_hex__": bytes(value).hex()}
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return {"__repr__": str(value)}


def encode_raw_attributes(attributes: Mapping[str, object]) -> str:
    """Encode a raw NTDS attribute map to a deterministic JSON string.

    Round-trippable for the value types NTDS actually stores (bytes/datetime/
    int/str/bool/lists); an exotic type is preserved lossily as a tagged repr
    (never dropped). NOTE the caller (:func:`build_staging_object`) strips
    denylisted secret attributes BEFORE calling this.

    Inputs:
        attributes: the object's attributes keyed by ``lDAPDisplayName``.

    Returns:
        A canonical JSON string (sorted keys) with bytes/datetimes tagged.

    Failure modes:
        Never raises for NTDS value shapes; an exotic value degrades to its repr.
    """
    return canonical_json({name: _json_safe(value) for name, value in attributes.items()})


@dataclass(frozen=True)
class PrincipalRow:
    """A §3.1 Principal canonical row (User/Computer/Group)."""

    node_id: str
    object_sid: str | None
    object_guid: str | None
    principal_type: str
    samaccountname: str | None
    upn: str | None
    distinguished_name: str | None
    display_name: str | None
    description: str | None
    uac_flags: int | None
    enabled: bool | None
    admincount: int | None
    spns: list[str]
    sid_history: list[str]
    primary_group_id: int | None
    pwd_last_set: datetime | None
    last_logon_timestamp: datetime | None
    when_created: datetime | None
    when_changed: datetime | None
    secret_refs: list[StructValue]
    behavior_summary_ref: str | None
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``principal`` table."""
        return (
            self.node_id,
            self.object_sid,
            self.object_guid,
            self.principal_type,
            self.samaccountname,
            self.upn,
            self.distinguished_name,
            self.display_name,
            self.description,
            self.uac_flags,
            self.enabled,
            self.admincount,
            list(self.spns),
            list(self.sid_history),
            self.primary_group_id,
            to_naive_utc(self.pwd_last_set),
            to_naive_utc(self.last_logon_timestamp),
            to_naive_utc(self.when_created),
            to_naive_utc(self.when_changed),
            list(self.secret_refs),
            self.behavior_summary_ref,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
        )


@dataclass(frozen=True)
class ContainerRow:
    """A §3.2 OU/Container/Domain canonical row."""

    node_id: str
    object_guid: str | None
    object_sid: str | None
    distinguished_name: str | None
    container_type: str
    parent_node_id: str | None
    gplinks: list[StructValue]
    functional_level: int | None
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``container`` table."""
        return (
            self.node_id,
            self.object_guid,
            self.object_sid,
            self.distinguished_name,
            self.container_type,
            self.parent_node_id,
            list(self.gplinks),
            self.functional_level,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
        )


@dataclass(frozen=True)
class GpoRow:
    """A §3.3 GPO canonical row (``derived_rights`` empty in M3)."""

    node_id: str
    object_guid: str | None
    display_name: str | None
    gpc_file_sys_path: str | None
    derived_rights: list[StructValue]
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``gpo`` table."""
        return (
            self.node_id,
            self.object_guid,
            self.display_name,
            self.gpc_file_sys_path,
            list(self.derived_rights),
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
        )


@dataclass(frozen=True)
class TrustRow:
    """A §3.4 Trust canonical row."""

    node_id: str
    source_domain_id: str | None
    target_domain_id: str | None
    direction: str | None
    trust_type: str | None
    trust_attributes: int | None
    transitive: bool | None
    sid_filtering: bool | None
    trust_key_ref: str | None
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``trust`` table."""
        return (
            self.node_id,
            self.source_domain_id,
            self.target_domain_id,
            self.direction,
            self.trust_type,
            self.trust_attributes,
            self.transitive,
            self.sid_filtering,
            self.trust_key_ref,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
        )


@dataclass(frozen=True)
class AdcsRow:
    """A §3.5 CertTemplate/EnterpriseCA/... canonical row (raw base facts)."""

    node_id: str
    object_guid: str | None
    name: str | None
    adcs_type: str
    pki_flags: StructValue | None
    enrollment_rights: list[StructValue]
    published_templates: list[str]
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``adcs`` table."""
        return (
            self.node_id,
            self.object_guid,
            self.name,
            self.adcs_type,
            dict(self.pki_flags) if self.pki_flags is not None else None,
            list(self.enrollment_rights),
            list(self.published_templates),
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
        )


@dataclass(frozen=True)
class StagingObjectRow:
    """One ``staging_object`` row — raw attrs + SD for M4/M5 (outside §3)."""

    node_id: str
    dnt: int
    object_guid: str | None
    object_sid: str | None
    object_class: list[str]
    raw_sd: bytes | None
    attributes_json: str
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct
    #: Multi-source attribution (contract §2.2b, schema v1.2). LAST field so the
    #: positional insert matches the ``source_id``-last ``staging_object`` DDL.
    source_id: str = DEFAULT_SOURCE_ID

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for ``staging_object``."""
        return (
            self.node_id,
            self.dnt,
            self.object_guid,
            self.object_sid,
            list(self.object_class),
            self.raw_sd,
            self.attributes_json,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
            self.source_id,
        )


@dataclass(frozen=True)
class StagingLinkRow:
    """One ``staging_link`` row — raw link with resolved node ids (outside §3)."""

    link_base: int | None
    source_node_id: str | None
    target_node_id: str | None
    link_dnt: int | None
    backlink_dnt: int | None
    link_deactivetime: int | None
    link_deltime: int | None
    link_usnchanged: int | None
    link_ncdnt: int | None
    link_data: bytes | None
    link_metadata: bytes | None
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct
    #: Multi-source attribution (contract §2.2b, schema v1.2). LAST field so the
    #: positional insert matches the ``source_id``-last ``staging_link`` DDL.
    source_id: str = DEFAULT_SOURCE_ID

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for ``staging_link``."""
        return (
            self.link_base,
            self.source_node_id,
            self.target_node_id,
            self.link_dnt,
            self.backlink_dnt,
            self.link_deactivetime,
            self.link_deltime,
            self.link_usnchanged,
            self.link_ncdnt,
            self.link_data,
            self.link_metadata,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _prov_to_struct(self.provenance),
            self.source_id,
        )


@dataclass(frozen=True)
class DomainIdentity:
    """The resolved scoping identity for the ingested domain (research item 5)."""

    domain_id: str | None
    domain_fqdn: str | None
    forest_id: str
    domain_dnt: int | None


@dataclass(frozen=True)
class NormalizeResult:
    """The outcome of a normalize run (counts only — never secret values).

    Attributes:
        identity: the resolved :class:`DomainIdentity`.
        entity_counts: rows written per canonical table.
        principal_type_counts: Principal rows per ``principal_type``.
        staging_counts: rows written per staging table.
        wellknown_stub_count: synthetic well-known/referenced-SID stub Principals.
        coverage_counts: the run's coverage counters snapshot.
        skip_counts: the run's skip/gap counters snapshot.
    """

    identity: DomainIdentity
    entity_counts: Mapping[str, int]
    principal_type_counts: Mapping[str, int]
    staging_counts: Mapping[str, int]
    wellknown_stub_count: int
    coverage_counts: Mapping[str, int]
    skip_counts: Mapping[str, int]


def sort_rows_by_node_id(
    rows: Sequence[tuple[str, tuple[object, ...]]],
) -> list[tuple[object, ...]]:
    """Return insert tuples sorted by ``node_id`` for deterministic writes."""
    return [values for _node_id, values in sorted(rows, key=lambda pair: pair[0])]
