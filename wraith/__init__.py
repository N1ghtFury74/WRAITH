"""WRAITH — offline, dead-disk Active Directory relationship mapper.

Module 1 (Foundation / Case Framework) provides the case workspace, artifact
ingest + integrity, provenance ledger + run manifest, the encrypted secret
store, and the untrusted-input/path-safety primitives that every later module
builds on. No ESE/NTDS parsing, normalization, edges, or UI live here.
"""

from __future__ import annotations

#: WRAITH release version. Recorded into run manifests and ``case.json`` so
#: every produced artifact is attributable to a tool version.
WRAITH_VERSION: str = "0.1.0"

#: Canonical schema version (``docs/schema/01-canonical-schema-v1.md`` + the
#: additive multi-source contract ``docs/schema/multi-source-contract.md``).
#:
#: History (all strictly ADDITIVE — no frozen column removed/retyped, so the
#: stamp reconciles honestly with every shipped store):
#:   * ``v1``   — frozen canonical node/edge contract (M3/M4/M5).
#:   * ``v1.1`` — additive columns shipped at M6 (owner-approved 2026-10-26):
#:                ledger hash-chain (``prev_entry_hash``/``entry_hash``),
#:                ``gpo.derived_rights.image_sha256``, ``edge.access_mask`` BIGINT.
#:                The prior stamp lagged at ``"v1"`` despite these landing; this
#:                bump reconciles the lag (M-MS1 doc-pass fix).
#:   * ``v1.2`` — additive multi-source tables (M-MS1): ``source``,
#:                ``source_observation``; ``source_id`` on the (outside-the-freeze)
#:                staging tables. The frozen §3/§4 tables are untouched. The opt-in
#:                ``divergence`` merge ledger (M-MS4) also shipped under this stamp.
#:   * ``v1.4`` — additive ``ca_node_finding`` table (CA-host adapter surfacing):
#:                the ESC11/ESC16/DCOM NODE-LEVEL findings the ADCS-ESC pass computes,
#:                persisted so the dossier API can surface them per node. Additive
#:                only; the frozen §3/§4 tables remain untouched (a store built
#:                without a CA-host hive never provisions a row).
SCHEMA_VERSION: str = "v1.4"

__all__ = ["WRAITH_VERSION", "SCHEMA_VERSION"]
