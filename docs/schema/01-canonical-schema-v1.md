# 01 — Canonical Entity/Edge Schema (WRAITH v1)

**Status:** 🔖 **v1.1 — additive revision, PM-ratified 2026-10-26 (owner-approved)** · **Date:** 2026-10-26
**Freeze history:** ❄️ **FROZEN v1.0** (2026-10-25) — the frozen contract below is unchanged in shape; v1.1 only *adds* three nullable/additive fields and one unsigned-clean retype (see the §8 changelog). No existing field changes shape; no data migration (fresh DB per run).
**Authority:** This is THE contract between parsing and analysis (spec §5.3, M-A exit criterion). Every downstream module speaks it. A change after freeze requires owner + PM re-sign-off and a version bump.
**Decision provenance:** Phase 0 report `docs/research/01-phase0-decisions.md` (2026-10-24) + owner rulings (2026-10-24/25):
- Provenance → **embedded struct on every row + a normalized provenance ledger table**.
- Principal → **one discriminated table**.
- Edge → **explicit `confidence` field**.
- Export → **native SharpHound JSON** (BloodHound is a *reference/export adapter only*, not a dependency; the canonical graph below is the product).

---

## 1. Locked design principles

1. **SID-keyed, surrogate-stable.** Every node carries a deterministic surrogate `node_id`; natural keys (`object_sid`, `object_guid`) are stored but edges reference only `node_id`. Handles SID-less objects (containers, some FSPs) and multi-forest collisions.
2. **Multi-forest from day one.** Every entity and edge carries a `forest_id` + `domain_id` scoping block. A second forest ingests into the same tables with no key collisions; cross-forest trust edges are first-class. (Built now, exercised later — we do NOT ingest multiple forests in v1.)
3. **Provenance on everything.** Every entity, edge, and finding carries an embedded provenance struct; a separate `provenance_ledger` table holds the full chain-of-custody view.
4. **Baselining-ready, not baselining.** A single nullable `behavior_summary_ref` column is the only hook v1 adds for M3. All event data lives in a *separate* future store — the frozen tables below never hold event rows. (Spec §8.2 "decide early; hard to retrofit.")
5. **Secrets by reference only.** Recovered secrets are never stored in these tables — only encrypted-store references. (NFR-05.)
6. **Deterministic.** All surrogate keys are hashes of stable inputs → identical inputs produce identical rows/ids.
7. **BloodHound is downstream.** This canonical model is the product. The SharpHound-JSON export is one swappable adapter built *from* this model; nothing here depends on BloodHound.

---

## 2. Shared building blocks

### 2.1 `node_id` (surrogate primary key for all nodes)
Deterministic hash of `forest_id || object_guid`, falling back to `forest_id || object_sid` only when GUID is absent. All edges reference `node_id`, never a raw SID.

### 2.2 Scoping block (on every entity and edge)
| Field | Type | Notes |
|---|---|---|
| `forest_id` | text | stable forest identifier |
| `domain_id` | text | domain SID (or GUID) |
| `domain_fqdn` | text | e.g. `corp.contoso.com` |

### 2.3 Provenance — embedded struct (on every entity, edge, finding)
| Field | Type | Source |
|---|---|---|
| `source_file` | text | e.g. `ntds.dit`, `SYSVOL/.../GptTmpl.inf`, `SYSTEM` |
| `image_sha256` | text(64) | SHA-256 of the acquired artifact (FR-02) |
| `source_object_id` | text | DNT / objectGUID / sd_id / DN / GPO path — the exact record |
| `directory_timestamp` | timestamp | `whenChanged` (and/or `whenCreated`) of the source object |
| `ingest_run_id` | uuid | run-manifest id (NFR-06) |

### 2.4 Provenance ledger (normalized chain-of-custody table)
One row per (artifact, ingest run): `ingest_run_id`, `source_file`, `image_sha256`, `acquired_at`, `tool_versions`, `parameters`, `db_state` (clean/dirty), `coverage_counts`, `skip_counts`. The embedded struct above is the fast query-local copy; this table is the auditable record.

**v1.1 (additive, nullable) — hash-chain for tamper-evidence:**
| Field | Type | Notes |
|---|---|---|
| `prev_entry_hash` | text(64), nullable | the previous ledger row's `entry_hash` in deterministic `(ingest_run_id, source_file)` order, or a genesis sentinel (`"0"*64`) for the first row |
| `entry_hash` | text(64), nullable | deterministic SHA-256 over this row's canonical content fields + `prev_entry_hash`, computed on write |

Both columns are nullable/additive: a row written without the chain still reads (the verifier treats a null predecessor as genesis). `verify_ledger_chain(con)` recomputes the chain and reports the exact link at which any mutation breaks it. Identical inputs → identical chain (determinism).

---

## 3. Entities

### 3.1 Principal — **one discriminated table** (User / Computer / Group)
| Field | Type | Notes |
|---|---|---|
| `node_id` | text (PK) | surrogate |
| `object_sid` | text | primary natural key; nullable for SID-less |
| `object_guid` | text | fallback key |
| `principal_type` | enum | `User` / `Computer` / `Group` |
| `samaccountname`, `upn`, `distinguished_name` | text | |
| `display_name`, `description` | text | |
| `uac_flags` | int | raw `userAccountControl` |
| `enabled` | bool | derived from UAC |
| `admincount` | int | AdminSDHolder marker |
| `spns` | text[] | `servicePrincipalName` |
| `sid_history` | text[] | |
| `primary_group_id` | int | for membership resolution |
| `pwd_last_set`, `last_logon_timestamp`, `when_created`, `when_changed` | timestamp | |
| `secret_refs` | struct/FK | **references only** → encrypted secret store (NFR-05) |
| `behavior_summary_ref` | text, nullable | **M3 hook** — null in v1 |
| *scoping block* + *provenance struct* | | on every row |

### 3.2 OU / Container / Domain — one discriminated table
| Field | Type | Notes |
|---|---|---|
| `node_id` (PK), `object_guid`, `distinguished_name` | | `object_sid` present for Domain |
| `container_type` | enum | `OU` / `Container` / `Domain` |
| `parent_node_id` | text | tree edges |
| `gplinks` | struct[] | `{gpo_node_id, enforced, link_order}` from `gPLink` |
| `functional_level` | int | Domain only |
| *scoping* + *provenance* | | |

### 3.3 GPO
| Field | Type | Notes |
|---|---|---|
| `node_id` (PK), `object_guid`, `display_name`, `gpc_file_sys_path` | | |
| `derived_rights` | struct[] | `{right, target_scope, source_file, image_sha256}` parsed from SYSVOL. **v1.1 (additive, nullable):** `image_sha256` = SHA-256 of the source SYSVOL artifact, so each derived-rights fact is self-describing |
| *scoping* + *provenance* | | |

### 3.4 Trust
| Field | Type | Notes |
|---|---|---|
| `node_id` (PK) | | |
| `source_domain_id`, `target_domain_id` | text | |
| `direction` | enum | inbound / outbound / bidirectional |
| `trust_type` | enum | parent-child / tree-root / external / forest / realm |
| `trust_attributes` | int | raw bitmask |
| `transitive`, `sid_filtering` | bool | |
| `trust_key_ref` | FK | encrypted store |
| *scoping* + *provenance* | | |

### 3.5 CertTemplate / EnterpriseCA (ADCS base facts — spec §7.3 T3)
| Field | Type | Notes |
|---|---|---|
| `node_id` (PK), `object_guid`, `name` | | |
| `adcs_type` | enum | `CertTemplate` / `EnterpriseCA` / `RootCA` / `AIACA` / `NTAuthStore` / `IssuancePolicy` |
| `pki_flags` | struct | enrollment flags, name flags, EKUs, schema version (raw, so BloodHound composes ESC1–13) |
| `enrollment_rights` | struct[] | `{principal_node_id, right}` from the object's DACL |
| `published_templates` | text[] | EnterpriseCA only |
| *scoping* + *provenance* | | |

---

## 4. Edge — the core contract

| Field | Type | Notes |
|---|---|---|
| `edge_id` | text (PK) | deterministic hash of (kind, source, target, derivation) — dedup + reproducibility |
| `kind` | enum | `MemberOf`, `GenericAll`, `DCSync`, `CanRDP`, … (full set = spec §7.3 T1–T3) |
| `source_node_id` | text | attacker-direction source |
| `target_node_id` | text | |
| `is_inherited` | bool | from the ACE (inherited vs explicit) |
| `derivation` | text | rule id that produced it (`ACE:GenericAll`, `SYNTH:DCSync`, `UAC:Unconstrained`, `GPO:AdminTo`, …) |
| `access_mask` | bigint, nullable | raw mask for ACL-derived edges (audit trail). **v1.1 retype:** was `int` (signed 32-bit two's-complement); now **BIGINT storing the 32-bit mask as a CLEAN UNSIGNED value** (`0..4294967295`). No signed-recovery dance on read. Backward-compatible: still nullable, value identity preserved (just non-negative) |
| `object_type_guid` | text, nullable | the rights-GUID that triggered it (Appendix B) |
| `confidence` | enum | **`confirmed` / `inferred`** (GPO-pushed subset is `inferred`; ACL-derived is `confirmed`). Feeds Operator/Investigator views + future M2 inferred→confirmed upgrade. |
| *scoping block* | | `forest_id`, `domain_id` |
| *provenance struct* | | `sd_table` row / attribute / GPO file + image hash |

---

## 5. Future-proofing (built now, implemented later — NOT in v1)

- **Baselining (M3):** entity tables hold no event rows. The `behavior_summary_ref` column + a separate time-partitioned `events_raw` store (Parquet/DuckDB, keyed by `node_id`) lets M3 join millions of events to thousands of objects **without touching this frozen schema**.
- **Multi-forest:** `forest_id`/`domain_id` on every node+edge + the `node_id` surrogate means a second forest ingests with no key collisions.
- **Host-context (M2):** confirmed per-host local-admin/RDP edges upgrade `confidence` from `inferred` → `confirmed` on existing edge rows — no schema change.

---

## 6. Physical homes & adapters

- **Canonical / analytics store:** **DuckDB** (Parquet-ready). SQLite dropped.
- **Graph / traversal store:** **Neo4j** (feeds the BloodHound CE UI; our own pathing runs in `networkx` in-process).
- **Export adapter (swappable, outside this schema):** **native SharpHound JSON**, pinned to the version the bundled BloodHound CE image accepts. Specified separately in a forthcoming `docs/schema/02-bloodhound-export-contract.md` after the version/layout spike. **This schema never depends on it.**

---

## 7. Open items that do NOT affect this frozen contract

These are *adapter/implementation* spikes resolved during module builds against real fixtures; they map into/out of this schema and do not change it:
1. Exact `sd_table` / sd_id column names exposed by current `dissect.esedb`/`dissect.database` (parser adapter detail).
2. Exact SharpHound JSON `version` integer + ADCS filename set accepted by the bundled BloodHound CE image (export adapter detail).
3. Whether a sample `.dit` ships in `ntdsdotsqlite/tests` or must be lab-generated (fixture detail).

---

## 8. Change control
Frozen. Any field addition/removal/retype after sign-off requires: (a) a documented reason, (b) owner + external-PM approval, (c) a schema version bump (`v1.1`, …), (d) a note of which modules must be re-gated.

### 8.1 Changelog

#### v1.1 — 2026-10-26 (owner-approved at M6; PM-ratified; implemented + gates green)
Three **additive / backward-compatible** changes. No existing field changes shape; no data migration (fresh DB per run). Reason: owner-approved 2026-10-26 at M6 to make custody records tamper-evident, make `access_mask` unsigned-clean, and make derived-rights facts self-describing.

1. **Ledger hash-chain (§2.4).** Added nullable `prev_entry_hash` + `entry_hash` to `provenance_ledger`; a deterministic SHA-256 chain computed on write, verified by `verify_ledger_chain(con)`. *Additive/nullable* — a row without the chain still reads (genesis). **Affected module:** `provenance/ledger` (+ `model/store` ledger DDL).
2. **`access_mask` INTEGER → BIGINT, unsigned-clean (§4).** The `edge.access_mask` column is now BIGINT storing the 32-bit mask as a clean unsigned value (`0..4294967295`) instead of a signed two's-complement reinterpretation. Write path masks with `& 0xFFFFFFFF`; the signed-recovery dance is removed from the read path. *Backward-compatible* — still nullable, value identity preserved (just non-negative). **Affected module:** `edges` (+ `model/store` edge DDL).
3. **`derived_rights` + `image_sha256` (§3.3).** The GPO `derived_rights` struct `{right, target_scope, source_file}` gains nullable `image_sha256` (the source SYSVOL artifact's hash → self-describing fact). *Additive/nullable*. **Affected module:** `gpo` (+ `model/store` GPO DDL).

**Re-gate note:** provenance/ledger (new chain unit test), edges (edge gate access_mask now non-negative — a tester-owned signed-form assertion needs reconciliation, see below), gpo (derived_rights struct now carries `image_sha256`).

#### v1.0 — 2026-10-25 (frozen)
Initial frozen canonical entity/edge contract (§1–§7). Decision provenance: `docs/research/01-phase0-decisions.md` + owner rulings 2026-10-24/25.
