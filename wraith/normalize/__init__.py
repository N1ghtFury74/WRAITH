"""Module 3 — the Object Normalizer.

Turns 2a ``ParsedObject``s into canonical, SID-keyed entities written to the
DuckDB canonical store (frozen schema §3), plus the two additive staging tables
(``staging_object`` / ``staging_link``) that are the sanctioned M3 -> M4/M5
hand-off. It reuses 2b's ``compute_node_id`` for ``node_id`` and attaches 2b's
``node_id -> secret_refs`` by reference only.

Scope (per ``docs/research/04-module3-normalizer-decisions.md``): classification,
attribute decode (incl. a distinct FILETIME decoder), scoping/DN reconstruction,
entity builders, and the deterministic two-pass write. It does NOT resolve group
membership (M4), derive SD/ACE/UAC/DCSync edges (M5), parse SYSVOL GPOs (M5), or
do any ESC/ADCS composition (M5/BloodHound).
"""

from __future__ import annotations

from wraith.normalize.builders import SECRET_ATTRIBUTE_DENYLIST, strip_secret_attributes
from wraith.normalize.classify import ClassifiedKind, EntityKind, classify
from wraith.normalize.decoders import (
    GpLinkEntry,
    decode_filetime,
    decode_trust_direction,
    decode_trust_sid_filtering,
    decode_trust_transitive,
    decode_trust_type,
    decode_uac_enabled,
    parse_gplink,
    to_naive_utc,
)
from wraith.normalize.identity import (
    WELL_KNOWN_SIDS,
    WELLKNOWN_IMAGE_SHA256,
    WELLKNOWN_SOURCE_FILE,
    DirectoryIndex,
    IndexEntry,
    is_domain_specific_sid,
    node_id_for_sid,
    resolve_forest_id,
    wellknown_source_object_id,
)
from wraith.normalize.models import DomainIdentity, NormalizeResult
from wraith.normalize.pipeline import normalize

__all__ = [
    "SECRET_ATTRIBUTE_DENYLIST",
    "WELLKNOWN_IMAGE_SHA256",
    "WELLKNOWN_SOURCE_FILE",
    "WELL_KNOWN_SIDS",
    "ClassifiedKind",
    "DirectoryIndex",
    "DomainIdentity",
    "EntityKind",
    "GpLinkEntry",
    "IndexEntry",
    "NormalizeResult",
    "classify",
    "strip_secret_attributes",
    "decode_filetime",
    "decode_trust_direction",
    "decode_trust_sid_filtering",
    "decode_trust_transitive",
    "decode_trust_type",
    "decode_uac_enabled",
    "is_domain_specific_sid",
    "node_id_for_sid",
    "normalize",
    "parse_gplink",
    "resolve_forest_id",
    "to_naive_utc",
    "wellknown_source_object_id",
]
