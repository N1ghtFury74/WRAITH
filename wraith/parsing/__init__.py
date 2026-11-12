"""Parsing layer: offline readers for DC forensic artifacts.

Two layers ship here:

* ``ese_backend`` — the swappable, schema-agnostic ESE reader adapter over
  ``dissect`` (gated PASS). Opens any ``.edb``/``.dit`` and streams tables.
* NTDS structural layer (sub-layer 2a) — ``ntds_values`` (pure structural
  decoders: SID/GUID/timestamp), ``schema`` (the ``ATT<type><id>`` column
  resolver + extended-rights map), and ``ntds`` (``ParsedObject`` /
  ``LinkRow`` exposure with raw SD bytes + provenance).

* NTDS secret decryption (sub-layer 2b) — ``ntds_secrets``: boot-key + PEK +
  ``NTDSHashes`` via Impacket (crypto delegated, routed through the dissect
  impacket shim), mapping each recovered secret to a ``SecretType`` + owning
  ``node_id`` and storing it encrypted via Module 1's ``SecretStore``.

Still out of scope (later passes): SD → ACE parsing and canonical entity/edge/
membership normalisation (Module 3). This layer *exposes* structure and
*recovers* secrets into the encrypted store; downstream *interprets* it.
"""

from __future__ import annotations

from wraith.parsing.ese_backend import (
    CoverageReport,
    DatabaseState,
    EseBackend,
    EseError,
    EseHandle,
    EseOpenError,
    EseRecord,
    EseTable,
    EseTableNotFoundError,
    EseValue,
    database_state,
    open_ese,
    raw,
)
from wraith.parsing.ntds import (
    LinkRow,
    ParsedNtds,
    ParsedObject,
    open_ntds,
    parse_ntds,
)
from wraith.parsing.ntds_secrets import (
    IdentityIndex,
    ImpacketReadPath,
    ImpacketUnavailableError,
    MappedSecret,
    SecretExtractionError,
    SecretExtractionResult,
    StoredSecretRef,
    compute_node_id,
    extract_secrets,
    map_secret_line,
)
from wraith.parsing.ntds_values import (
    as_list,
    as_scalar,
    decode_guid,
    decode_ntds_sid,
    decode_ntds_timestamp,
)
from wraith.parsing.repl_metadata import (
    AttidResolution,
    DsaResolution,
    Recency,
    ReplAttributeStamp,
    ReplMetadata,
    ReplMetadataParseError,
    compare_recency,
    parse_repl_property_metadata,
    resolve_attid,
    resolve_dsa,
)
from wraith.parsing.schema import (
    AttributeDef,
    ClassDef,
    ExtendedRight,
    NtdsSchema,
    build_schema,
)

__all__ = [
    "AttidResolution",
    "AttributeDef",
    "ClassDef",
    "CoverageReport",
    "DatabaseState",
    "DsaResolution",
    "EseBackend",
    "EseError",
    "EseHandle",
    "EseOpenError",
    "EseRecord",
    "EseTable",
    "EseTableNotFoundError",
    "EseValue",
    "ExtendedRight",
    "IdentityIndex",
    "ImpacketReadPath",
    "ImpacketUnavailableError",
    "LinkRow",
    "MappedSecret",
    "NtdsSchema",
    "ParsedNtds",
    "ParsedObject",
    "Recency",
    "ReplAttributeStamp",
    "ReplMetadata",
    "ReplMetadataParseError",
    "SecretExtractionError",
    "SecretExtractionResult",
    "StoredSecretRef",
    "as_list",
    "as_scalar",
    "build_schema",
    "compare_recency",
    "compute_node_id",
    "database_state",
    "decode_guid",
    "decode_ntds_sid",
    "decode_ntds_timestamp",
    "extract_secrets",
    "map_secret_line",
    "open_ese",
    "open_ntds",
    "parse_ntds",
    "parse_repl_property_metadata",
    "raw",
    "resolve_attid",
    "resolve_dsa",
]
