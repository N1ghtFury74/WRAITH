"""WRAITH multi-DC merge (M-MS4) — opt-in reconciliation + divergence ledger.

Phase-2 same-domain multi-DC reconciliation (``docs/schema/multi-source-contract.md``
§3). This package is the forensically dangerous core: it never fabricates and never
silently drops, union-per-source for edges (never re-derive over a merged set), keeps
secrets per-source (never picks), and records every disagreement in the ``divergence``
ledger.

Landed so far (M-MS4a — decoder-ingest wiring + ledger scaffolding):

* :mod:`wraith.merge.metadata_ingest` — captures each node's raw
  ``replPropertyMetaData`` bytes into ``source_observation.attr_metadata_blob`` so
  the gated decoder (:mod:`wraith.parsing.repl_metadata`) is no longer dormant and
  tier-1 of the §3.3 ladder has a real input.
* The ``divergence`` ledger table (``wraith.model.store.create_divergence_table``).

Landed in M-MS4b (the merge fold, :mod:`wraith.merge.fold`): the opt-in
``GROUP BY obj_id`` reconciliation, the entity/edge/attribute divergence taxonomy
(§3.2), the resolution ladder (§3.3), secret-divergence handling (redacted, never
picked), and the "DC-A vs DC-B" report. Merge is a standalone operator action,
never wired into ingest.
"""

from __future__ import annotations

from wraith.merge.fold import (
    COV_EDGES_MERGED,
    COV_NODES_MERGED,
    GAP_ATTR_UNRESOLVED,
    GAP_GC_SOURCE_IN_SELECTION,
    GAP_NOTHING_TO_MERGE,
    GAP_REPL_BLOB_UNPARSEABLE,
    GAP_SECRET_DIVERGENCE,
    GAP_STAGING_ATTRS_UNPARSEABLE,
    GAP_TIER1_UNAVAILABLE,
    AttributeResolution,
    DcVsDcReport,
    DivergenceType,
    EntityVerdict,
    MergeResult,
    NodeObservation,
    PresentedState,
    ResolvedBy,
    SecretFingerprint,
    SupportsRunCounters,
    classify_edge,
    classify_entity,
    compare_secrets,
    decode_node_stamps,
    default_safer_reading,
    merge_fold,
    presented_attribute,
    resolve_attribute,
    tier1_per_attribute,
    tier2_when_changed,
)
from wraith.merge.metadata_ingest import (
    COV_REPL_METADATA_CAPTURED,
    GAP_REPL_METADATA_ABSENT,
    GAP_REPL_METADATA_UNPARSEABLE,
    MetadataIngestResult,
    extract_repl_metadata_blob,
    populate_attr_metadata,
)

__all__ = [
    "COV_EDGES_MERGED",
    "COV_NODES_MERGED",
    "COV_REPL_METADATA_CAPTURED",
    "GAP_ATTR_UNRESOLVED",
    "GAP_GC_SOURCE_IN_SELECTION",
    "GAP_NOTHING_TO_MERGE",
    "GAP_REPL_BLOB_UNPARSEABLE",
    "GAP_REPL_METADATA_ABSENT",
    "GAP_REPL_METADATA_UNPARSEABLE",
    "GAP_SECRET_DIVERGENCE",
    "GAP_STAGING_ATTRS_UNPARSEABLE",
    "GAP_TIER1_UNAVAILABLE",
    "AttributeResolution",
    "DcVsDcReport",
    "DivergenceType",
    "EntityVerdict",
    "MergeResult",
    "MetadataIngestResult",
    "NodeObservation",
    "PresentedState",
    "ResolvedBy",
    "SecretFingerprint",
    "SupportsRunCounters",
    "classify_edge",
    "classify_entity",
    "compare_secrets",
    "decode_node_stamps",
    "default_safer_reading",
    "extract_repl_metadata_blob",
    "merge_fold",
    "populate_attr_metadata",
    "presented_attribute",
    "resolve_attribute",
    "tier1_per_attribute",
    "tier2_when_changed",
]
