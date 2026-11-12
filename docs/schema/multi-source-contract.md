# WRAITH — Multi-Source Ingestion: LOCKED Design Contract

**Status:** DESIGN-OF-RECORD, awaiting owner sign-off. No production code, no changes to the
frozen canonical node/edge contract. This document is the contract that governs the Phase-1
(multi-domain) build and reserves the seat for Phase-2 (multi-DC-same-domain) with no
re-architecture.

**Grounded in:** `docs/research/25-multi-dc-multi-domain.md` (plan-first reference),
`docs/modules/10-bloodhound-export.md` (trust-direction / FSP / ADCS conventions),
`wraith/model/store.py` (frozen tables + `_SCOPING_BLOCK` / `_PROVENANCE_STRUCT`),
`wraith/normalize/identity.py` (`node_id_for_sid`, `is_domain_specific_sid`).

**Owner's locked decisions honored verbatim:**
1. Build **multi-domain first (Phase 1)**; design with the full two-phase picture so Phase 1
   needs no re-architecting for Phase 2 (multi-DC-same-domain).
2. **Per-source-first, merge-optional.** Every uploaded source is viewable standalone (its
   objects, edges, coverage, gaps). Merge is an **explicit operator action**, never automatic.
3. A **per-attribute metadata decoder is being attempted in a parallel spike**; the contract
   must accommodate per-attribute recency IF it lands, and **degrade honestly** to object-level
   `whenChanged` + union + counted divergence otherwise.

---

## 0. Scope, vocabulary, and the one-line thesis

- **Source** = one ingested DC artifact set: `{ntds.dit + SYSTEM hive (+ optional SAM, + optional
  SYSVOL)}`, tagged by an operator-supplied **DC label** and **domain**. WRAITH cannot
  self-identify which DC a `ntds.dit` came from (the DSA/NTDS-Settings object is not reliably
  recoverable dead-disk), so the operator names it. One source = one row in the new `source`
  dimension (§2).
- **Per-source view** = the objects/edges/coverage attributable to exactly one `source_id`,
  readable on its own with no merge applied.
- **Merge** = an operator-initiated overlay that produces one canonical *presented* row per
  `node_id`/`edge_id` across selected sources, **retaining every source's raw copy** and emitting
  a counted `divergence` ledger. Merge never reconstructs "the single logical directory state at a
  point in time" — that is impossible from divergent dead-disk captures and is explicitly a
  non-goal (research 25 §1 assumption).
- **Thesis:** *The per-source graph is the product by default; merge is a read-time overlay the
  operator opts into. Union-with-provenance is the substrate; nothing is ever silently chosen or
  silently dropped.*

**Non-goals reaffirmed (no drift):** no live collection, no password cracking, no Azure/Entra,
on-prem AD only. Multi-source changes none of these; it only changes how many offline artifacts a
case holds and how they are scoped, viewed, and optionally reconciled.

---

## 1. Case-shape model (LOCK)

### 1.1 How a case declares its shape
A case is declared at creation with two orthogonal axes:

| Axis | Values | Drives |
|---|---|---|
| **Domain cardinality** | `single_domain` \| `multi_domain` | whether cross-domain edge wiring (trust/FSP/sIDHistory) runs |
| **DC cardinality (per domain)** | `single_dc` \| `multi_dc` | whether the merge/divergence engine is *available* (Phase 2) |

- `forest_scope` is a derived descriptor, not a third axis: multiple domains sharing a
  `forest_id` = same-forest; distinct `forest_id`s = cross-forest. The operator supplies
  `forest_id` per source (today's `PipelineInputs.forest_id`); the case's forest set is the
  distinct union.
- **Phase 1 ships `single_domain` and `multi_domain`, each with `single_dc` only.** `multi_dc`
  is declarable but gated "Phase 2 — not yet enabled" until M-MS4 lands. A case declared
  `multi_dc` in Phase 1 is accepted for *ingest and per-source views* but the merge toggle is
  disabled with an honest "multi-DC merge ships in Phase 2" note — no silent degradation.

### 1.2 How each source is tagged
Each uploaded source carries, operator-supplied at the upload row:
- `dc_label` — free text, human-meaningful (e.g. `DC01-CORP`, `DC-ROOT`). **Required.**
- `domain` — the domain the operator asserts this DC belongs to (FQDN preferred, e.g.
  `corp.example.com`). **Required.**
- `forest_id` — defaults per existing pipeline; operator may set for cross-forest cases.
- Derived at ingest (never operator-trusted): `domain_id` = the reconstructed `domainDNS`
  objectSID / domain NC, `domain_fqdn` = reconstructed from the directory. The operator's
  asserted `domain` string is the *label*; the derived `domain_id`/`domain_fqdn` from the actual
  `ntds.dit` is **authoritative** and is cross-checked against the label (§1.4).

### 1.3 Label-uniqueness validation (LOCK)
- `(case_id, dc_label)` MUST be unique. Two sources with the same label is a hard validation
  error at upload (not a silent rename) — the label is how the operator and every per-source view
  address a source.
- `(case_id, source_id)` is the machine key (UUID, minted at ingest); `dc_label` is the display
  key. Internals join on `source_id`, never on the mutable label.
- For `multi_dc`: two sources MAY share the same derived `domain_id` (that is the whole point —
  two DCs of one domain). For `multi_domain` + `single_dc`: two sources SHOULD NOT share a
  `domain_id`; if they do, it is surfaced as a **counted** "unexpected duplicate domain" warning
  (the operator may have mis-declared a multi-DC case as multi-domain — see §1.4), not auto-merged.

### 1.4 What happens if the operator mis-declares (LOCK — honesty, never silent correction)
The operator's declaration is a *hint for UI/engine gating*, not ground truth. WRAITH reconciles
it against what the `ntds.dit` actually is and surfaces any mismatch as a counted honesty card —
**it never silently overrides the declaration and never silently trusts it**:

- **Declared `single_domain`, ingested sources have ≥2 distinct derived `domain_id`s** →
  counted `case_shape_mismatch: multiple_domains_detected`; UI prompts the operator to re-declare
  as multi-domain (cross-domain edges stay off until they do — no guessing).
- **Declared `multi_domain` + `single_dc`, two sources share a derived `domain_id`** → counted
  `case_shape_mismatch: same_domain_two_dcs`; UI surfaces "these two sources are the same domain —
  this is a multi-DC case; enable Phase-2 merge or keep them as separate per-source views." Default
  stays per-source-separate (never auto-merge).
- **Declared `domain` label disagrees with derived `domain_fqdn`** (e.g. label `prod.local` but
  the dit is `corp.local`) → counted `source_label_domain_mismatch`; the **derived** value is used
  for all scoping/joins, the label is kept for display with a divergence badge. Rationale: a
  mislabeled artifact must never cause a cross-domain edge to be wired against the wrong domain.

**Forensic validation:** this is the correct discipline. The declaration gates *which analyses
run*; the `ntds.dit` itself gates *what is true*. An operator who fat-fingers a domain label must
not be able to make WRAITH fabricate or misroute a cross-domain trust/FSP edge. Derived-wins for
scoping, declaration-wins for workflow gating, mismatch-always-counted.

---

## 2. Per-source-first data/view model (LOCK — additive-only)

### 2.1 The frozen contract is untouched
The frozen canonical tables — `principal`, `container`, `gpo`, `trust`, `adcs`, `edge`
(`store.py`) — keep their `node_id`/`edge_id` **single-column PRIMARY KEY**, their inline
`_SCOPING_BLOCK` (`forest_id NOT NULL, domain_id, domain_fqdn`), and their embedded
`_PROVENANCE_STRUCT`. **No column is removed or retyped.** Everything below is additive: new side
tables + a widened *staging* key (staging is explicitly outside the frozen contract, `store.py:188`).

### 2.2 New additive objects (confirming + refining research 25 §7)

**(a) `source` dimension table — one row per ingested DC artifact set.**
```
source(
  source_id          UUID PRIMARY KEY,
  case_id            VARCHAR NOT NULL,
  dc_label           VARCHAR NOT NULL,          -- operator-supplied, unique per case
  forest_id          VARCHAR NOT NULL,
  domain_id          VARCHAR,                   -- DERIVED from the dit (authoritative)
  domain_fqdn        VARCHAR,                   -- DERIVED
  declared_domain    VARCHAR,                   -- operator label (display only)
  ntds_image_sha256  VARCHAR NOT NULL,
  system_image_sha256 VARCHAR,
  is_global_catalog  BOOLEAN,                   -- flagged when partial-replica shadows seen (§4.4)
  dsa_guid           VARCHAR,                   -- NULLABLE; only if ever recoverable
  invocation_id      VARCHAR,                   -- NULLABLE; for future per-attribute origin match
  ingest_run_id      UUID NOT NULL,
  ingested_at        TIMESTAMPTZ NOT NULL,
  UNIQUE(case_id, dc_label)
)
```

**(b) Composite staging key `(node_id, source_id)`.** `staging_object` and `staging_link`
(`store.py:193`, `:210`) gain a `source_id` column and widen their PK to `(node_id, source_id)` /
`(link_base, source_node_id, target_node_id, source_id)`. This is the one place two DCs' divergent
raw copies of the same object physically coexist. Legal because staging is outside the frozen
contract.

**(c) `source_observation` side table — the per-source provenance list.**
```
source_observation(
  obj_kind     VARCHAR NOT NULL,     -- 'node' | 'edge'
  obj_id       VARCHAR NOT NULL,     -- node_id or edge_id
  source_id    UUID NOT NULL,
  directory_timestamp TIMESTAMP,     -- object-level whenChanged (cross-DC comparable)
  when_created TIMESTAMP,
  usn_local    BIGINT,               -- stored, NEVER used as a cross-DC winner key
  is_deleted   BOOLEAN,              -- tombstone seen on this source
  attr_metadata_blob BLOB,           -- NULLABLE; raw replPropertyMetaData, filled IFF decoder lands
  PRIMARY KEY (obj_kind, obj_id, source_id)
)
```
This is the "which source asserted this node/edge, and when" list the single embedded
`ProvenanceStruct` cannot hold. It makes a per-source standalone view a simple
`WHERE source_id = ?` filter, and makes merge a `GROUP BY obj_id` fold.

**(d) `divergence` ledger table — the honest merge report.**
```
divergence(
  obj_kind     VARCHAR NOT NULL,     -- 'node' | 'edge' | 'attribute'
  obj_id       VARCHAR NOT NULL,
  attribute    VARCHAR,              -- NULL for whole-entity/whole-edge divergences
  value_by_source JSON NOT NULL,     -- {source_id: value} (secrets redacted -> {present:true,differs:true})
  divergence_type VARCHAR NOT NULL,  -- see §3.2 taxonomy
  resolution   VARCHAR,              -- which policy tier resolved it (§3.3), or 'unresolved'
  resolved_value JSON,               -- the presented value, if any
  resolved_by  VARCHAR,              -- 'per_attr_meta'|'whenChanged'|'safer_reading'|null  (no 'authoritative_dc' — owner decision 2026-11-11)
  counted      BOOLEAN NOT NULL DEFAULT TRUE,
  ingest_run_id UUID NOT NULL
)
```

### 2.3 How the SAME schema serves BOTH views with no Phase-2 re-architecture

- **Per-source standalone (default, Phase 1 and 2):** read canonical rows joined to
  `source_observation WHERE source_id = ?`. In Phase 1 (`single_dc` per domain) every `node_id`
  has exactly one observation, so the frozen canonical row *is* the per-source row — zero overhead,
  nothing special. The per-source API is `source_id`-scoped selects.
- **Opt-in merge (Phase 2, and trivially correct in Phase 1 where there is nothing to merge):** the
  canonical row holds the *presented* value (§3.3 policy); `source_observation` holds every
  source's copy; `divergence` holds every disagreement. Merge is a read-time fold, not a
  destructive rewrite.
- **Why Phase 1 needs no re-architecture for Phase 2:** Phase 1 writes `source` rows,
  `source_observation` rows, and `source_id` on staging *already* — even though each `node_id` has
  one observation. Phase 2 only has to (i) allow >1 observation per `node_id`, (ii) run the merge
  fold + divergence ledger. No column added in Phase 2 that Phase 1 didn't already create. The
  frozen canonical tables are identical in both phases. **This is the load-bearing guarantee of the
  two-phase design.**

**Forensic validation:** the additive model is correct. Keeping staging per-source means a
multi-DC capture never loses a DC's raw bytes (un-replicated secret, tombstone, divergent
membership all survive). Keeping canonical single-PK means downstream (M5 edges, export, dossiers)
is unchanged for the common single-source case. The `source_observation` timestamp column stores
`whenChanged` (replicated, cross-DC comparable per research 25 §4) and **stores but never uses**
`usn_local` (local counter, NOT cross-DC comparable) — exactly the right discipline.

---

## 3. Merge semantics (opt-in) (LOCK)

Merge runs ONLY when the operator toggles it on over a selected set of sources. It never runs at
ingest.

### 3.1 The substrate: union-with-provenance
Every source's raw copy is retained in staging + `source_observation`. Merge produces one
*presented* canonical row per `node_id`/`edge_id`; it chooses a presented value per attribute but
**drops nothing and fabricates nothing**.

### 3.2 Divergence taxonomy — precise definitions (LOCK)

| Level | Divergence is… | Example | Handling |
|---|---|---|---|
| **Entity** | same `node_id` present on A, tombstoned/absent on B | deleted on DC-A, live on DC-B | present as **live (from B)** + counted `deleted_on_source` / `candidate_lingering_object` |
| **Edge** | same `edge_id` asserted by A, not by B | `MemberOf` on A, absent on B | **keep the edge** (present-on-A) + counted `edge_membership_divergence`. Never fabricate (no edge in neither source), never drop (no silent loss) |
| **Attribute** | same `node_id`, scalar attr differs across sources | `userAccountControl` enabled on A, disabled on B; divergent `description`, `pwdLastSet`; **secret hash differs** | present per §3.3 policy + counted `attribute_divergence`; **secrets: keep BOTH per-source, never pick** |

Entity-level special cases (research 25 §2b), all counted, never merged away:
- **`deleted_on_source`** — tombstone (`isDeleted=TRUE`, `CN=Deleted Objects`) on one DC, live on
  another. A deleted-on-one-DC principal is security-relevant; present live + flag.
- **`candidate_lingering_object`** — live on B, absent on authoritative A past tombstone lifetime.
  A genuine IR signal; surfaced, never dropped.
- **`secret_divergence`** — un-replicated password: different NT hash / `supplementalCredentials`
  per DC. Both were real at capture, both PtH/crack-relevant; keep both (encrypted-at-rest,
  redacted), surface "secret differs across DCs," never choose.

### 3.3 The resolution ladder (LOCK — ordered, honest degradation)
For a presented attribute value, descend until one tier resolves; record `resolved_by` and, if
nothing resolves, leave it divergent + flagged:

1. **Per-attribute newest-wins** — pick the value with the highest originating version (`dwVersion`,
   skew-immune PRIMARY comparator) then time from decoded `replPropertyMetaData`. The decoder spike
   returned **FEASIBLE (research 26)**, so `attr_metadata_blob` will be populated once the decoder
   module ships; `resolved_by='per_attr_meta'`.
2. **Object-level `whenChanged` newest-wins** — when one source's object is unambiguously newer and
   the decoder is absent/metadata missing. Blunt (object-level, cannot say *which* attribute changed),
   so used only when there is a clear single newer object. `resolved_by='whenChanged'`.
3. **Present-the-safer/higher-privilege reading, flagged** — when nothing above resolves, present
   the more dangerous interpretation (e.g. account *enabled*, privilege *present*) so a hunter is
   never lulled by the benign copy, mark it `unresolved` + `resolved_by='safer_reading'`, and count
   the divergence. **Never claim certainty.**

> **OWNER DECISION 2026-11-11 — no operator-authoritative-DC tiebreaker.** The former tier-3
> "operator nominates a primary DC whose value wins" is **removed**. On a true tie the metadata
> cannot break, WRAITH ALWAYS leaves the value un-chosen (present the safer reading, flagged, count
> the divergence) — it never lets the operator silence a disagreement by decree. There is no
> `authoritative_dc` resolution and no primary-DC nomination anywhere in the UI or schema.

Every tier-3 (and every un-dropped tier-1..2) disagreement writes a `divergence` row. The decoder's
presence or absence changes only *tier 1's availability*; the ladder, the ledger, and the
no-silent-pick guarantee are identical either way — this is the "degrade honestly" requirement
satisfied structurally.

### 3.4 The "DC-A and DC-B disagreed on X" report
Driven entirely from the `divergence` ledger: "DC-A and DC-B disagreed on N attributes, M
memberships, K secrets; P objects deleted-on-one-DC; Q candidate lingering objects." Every line
drills into `value_by_source`. Same honesty polarity as the existing GPO "inferred/superset" and
AD CS coverage cards. Never a silent reconciliation.

### 3.5 Edge merge rule (LOCK — the real danger)
**Re-derive edges PER SOURCE, tag each with `source_id`, then UNION. NEVER re-derive over the
merged object set.** Combining DC-A's membership with DC-B's ACL over a merged superset can
fabricate a path no single DC ever held (member-of only on A + ACL only on B → "User → DA" real on
neither capture). Dedup identical edges by the deterministic `edge_id`; the merged edge carries a
multi-source provenance list via `source_observation`. Contradictory edges stay as counted
divergence (§3.2). Cross-source edges (FSP/trust/sIDHistory) derive only when **both endpoints'
sources were ingested**, else a counted stub (§4). **Net rule: never union an edge into existence
that no source asserted; never silently drop an edge a source did assert.**

**Forensic validation:** this is the single most important correctness rule in the whole contract.
Inventing an attack path is strictly worse than missing one — a fabricated User→DA edge sends an
operator or IR team down a path that does not exist on any real DC. Per-source derive + union is
the only sound strategy.

---

## 4. Phase-1 multi-domain specifics (forensic core)

### 4.1 Cross-domain identity
- **Dedup key stays `objectGUID`, forest-scoped** (`node_id = stable_id(forest_id, objectGUID)`,
  with SID fallback). objectGUID is forest-wide-unique and immutable within a forest → distinct
  domains ⇒ distinct GUIDs ⇒ distinct `node_id` ⇒ **no collisions.** Cross-forest migration mints a
  NEW objectGUID, so cross-forest objectGUID uniqueness holds only *within* a `forest_id` — which is
  exactly how WRAITH already scopes it.
- **`sIDHistory` is the cross-domain/forest identity bridge.** A migrated principal carries the old
  domain SID in `sIDHistory`; WRAITH emits a `HasSIDHistory` edge linking the new identity to the
  old-domain principal (or a stub if the old domain was not ingested). This is the primary
  cross-domain link after objectGUID changes on migration. `objectSID` is the *link* key here, never
  the dedup key (SIDs change on migration).
- Well-known/BUILTIN SIDs stay **domain-scoped** (`node_id_for_sid`, `identity.py:138`) so two
  domains' `BUILTIN\Administrators` do not collide; `S-1-5-21-*` domain SIDs are forest-scoped
  (globally unique). This existing split is correct for multi-domain and needs no change.

### 4.2 FSP resolution (LOCK)
- Each domain's `CN=ForeignSecurityPrincipals` holds stub objects whose **RDN is a foreign SID**,
  materialized when a trusted-domain principal is ACL'd or made a local member.
- **Resolve the FSP's foreign SID to the real principal node in its owning domain IF that domain was
  also ingested in the case; else emit a COUNTED cross-domain stub** `fsp_owning_domain_not_ingested`.
  Never guess a concrete principal.
- **`principal_type` default = `Group` is UNEXERCISED and Phase 1 finally tests it on real data.**
  FSPs can wrap users, groups, OR computers; the `classify.py` default must be validated against a
  real cross-domain capture and corrected if the real distribution differs. Flagged as a
  must-confirm (§7).

### 4.3 Trust objects → trust edges + attack-direction convention (LOCK)
- `trustedDomain` objects → the frozen `trust` table (`store.py:137`): `direction`, `trust_type`,
  `trust_attributes` bits (0x1 NON_TRANSITIVE, 0x8 FOREST_TRANSITIVE, 0x20 WITHIN_FOREST, 0x4
  QUARANTINED/SID-filtering, 0x40 TREAT_AS_EXTERNAL, 0x10 CROSS_ORGANIZATION), `transitive`,
  `sid_filtering`.
- **WRAITH's attack-direction convention (from `docs/modules/10`):** the edge engine (M5) emits
  trust edges in the **ATTACK direction (trusted → trusting)** — access flows opposite to the trust
  arrow: if domain A (trusting) trusts domain B (trusted), B's principals can reach A's resources, so
  the attack edge runs B→A. The BloodHound export does **not** flip a literal edge; it drops the
  attack-direction edge as `trust_postprocess` (counted) and rebuilds each domain's `Trusts[]` from
  the `trust` table, mapping `direction` via `_trust_direction` (`inbound→1, outbound→2,
  bidirectional→3`) so BHCE post-composes the direction-correct structural + abuse edges. **This
  round-trip is UNEXERCISED on the dev DC (0 trusts) and Phase 1 finally validates it on real data.**
- **Parent-child vs tree-root `trust_type` is now FQDN-inferable.** Both are intra-forest
  (`WITHIN_FOREST` set) and indistinguishable from a single attribute; with both domains' `ntds.dit`
  present, WRAITH compares reconstructed FQDNs — contiguous DNS namespace (child.parent.tld under
  parent.tld) = parent-child; a new tree root = tree-root. **This is a real multi-domain capability a
  single-DC case cannot have**, and Phase 1 is where it is first exercised.

### 4.4 Global Catalog partial-replica tagging (LOCK)
- A GC holds a **partial, read-only replica** of every *other* domain in the forest. A supplied GC
  `ntds.dit` shows cross-domain objects as **partial-attribute shadows**. Tag such a source
  `is_global_catalog=TRUE` and its shadow observations `partial_gc_replica`. **A partial GC replica
  NEVER wins over a full-domain copy** in merge, and is counted. Needs a GC fixture to validate (§7).

### 4.5 Single-DC-UNEXERCISED conventions Phase 1 validates on real data
Phase 1 is the first time these logged blind spots meet real multi-domain data (research 25 §9,
`memory/multi-dc-multi-domain-planning.md`):
1. **Trust direction + BHCE round-trip** (attack-direction `trusted→trusting` → export `Trusts[]` →
   BHCE structural/abuse arrow). *Riskiest unknown.*
2. **FSP `principal_type=Group` default** across a real trust.
3. **`trust_type` parent-child vs tree-root** — now FQDN-inferable with both domains present.
4. **Host-SAM well-known domain-RID set** `{498,502,512,513,516,518,519,520,521}` resolving across a
   trust (domain-RID → principal in the correct domain).
5. **The 8 ADCS edge directions + the IssuedSignedBy CA→CA arrow** — exercised only synthetically so
   far; a cross-domain PKI capture would test them. (ADCS topology-edge export is still
   `adcs_pending_spike`; multi-domain does not lift that gate — noted, not claimed.)

**Forensic validation:** this is how multi-domain AD attack paths actually work. The three real
cross-domain bridges an operator reasons about are (a) **trusts** (SID-history-free lateral/forest
traversal, abuse via the trust account / TGT delegation / SID filtering gaps), (b) **sIDHistory**
(an identity carrying a privileged old-domain SID across the boundary — a classic cross-domain
escalation), and (c) **FSP memberships/ACLs** (a foreign principal holding local rights, the
"domain-local membership blind spot"). The contract wires exactly these three and leaves ESC
composition / trust abuse-edge composition to BHCE where intended, which is correct.

---

## 5. UI contract (LOCK)

Same honesty polarity as the existing GPO "inferred/superset" and AD CS coverage cards.

1. **Case-shape picker at case creation** — the two axes (§1.1). Drives whether cross-domain wiring
   and (Phase 2) the merge engine are available. `multi_dc` selectable but marked "Phase 2."
2. **Per-source upload rows** — one row per source = `{ntds.dit + SYSTEM (+ SAM/SYSVOL)}` tagged
   with `dc_label` + `domain`; add-row for multi-DC/multi-domain. Label-uniqueness validated inline
   (§1.3); declaration-vs-derived mismatch surfaced (§1.4).
3. **Per-source coverage cards** — reuse the coverage-card component; required/missing files + object
   /edge counts **per source**, each addressable standalone. This is the default view.
4. **Opt-in merge view toggle** — OFF by default. Per-source-separate is the landing view; the
   operator flips "Merge sources" to see the folded canonical graph + the divergence report. Disabled
   with an honest note in Phase 1 `multi_dc` cases.
5. **Divergence card** (Phase 2) — "DC-A and DC-B disagreed on N attrs / M memberships / K secrets; P
   deleted-on-one-DC; Q candidate lingering," each drilling into the `divergence` ledger.
6. **Cross-domain honesty card** (Phase 1) — FSPs resolved vs `fsp_owning_domain_not_ingested`, trust
   edges found + inferred `trust_type`, sIDHistory bridges, GC partial-replica warnings — all counted.

---

## 6. Phase-1 module breakdown (ordered, each independently buildable + testable)

Each module follows the WRAITH rhythm (research → lock → build one → test three layers → gate →
next). The `replPropertyMetaData` decoder runs as a **parallel Phase-0 spike**; M-MS4 consumes it
IFF it lands, else degrades per §3.3.

### M-MS1 — Case-shape + multi-source ingest/tagging
- **Inputs:** case-shape declaration (two axes); N upload rows each `{ntds.dit, SYSTEM, (SAM),
  (SYSVOL), dc_label, domain, forest_id}`.
- **Outputs:** `source` dimension rows; `source_id` stamped on every staged object/edge/provenance;
  per-source provenance registration (hash each artifact before use).
- **Must get right:** label-uniqueness; declared-vs-derived domain reconciliation (§1.4) with every
  mismatch counted; `source_id` threaded through the whole ingest so nothing is un-attributed.
- **Needs a real capture to validate:** nothing critical — synthetic multi-source fixtures suffice
  for the plumbing; real data only sharpens the mismatch heuristics.

### M-MS2 — Per-source scoping + standalone per-source views
- **Inputs:** a multi-source store from M-MS1.
- **Outputs:** per-source API/query surface (`source_id`-scoped selects over canonical +
  `source_observation`); per-source coverage counts; per-source graph/dossier.
- **Must get right:** a per-source view shows *exactly* that source's objects/edges/gaps with zero
  cross-source bleed, and in Phase 1 (one observation per node) adds zero overhead to the single-
  source path.
- **Needs a real capture to validate:** nothing critical; a real multi-domain capture confirms the
  counts read sensibly per DC.

### M-MS3 — Cross-domain edges (trust / FSP / sIDHistory)
- **Inputs:** ≥2 domains ingested (same-forest and/or cross-forest), their trust objects, FSP
  containers, and sIDHistory attributes.
- **Outputs:** trust edges (attack-direction convention) + export `Trusts[]`; FSP resolution to
  owning-domain principals or counted stubs; `HasSIDHistory` cross-domain edges; inferred
  `trust_type` (parent-child vs tree-root by FQDN).
- **Must get right:** derive cross-source edges only when both endpoints' sources are ingested, else
  a counted stub — never a guessed principal; attack-direction correctness; FSP `principal_type`
  not blindly `Group`.
- **Needs a real capture to validate (critical):** trust-direction BHCE round-trip; FSP cross-domain
  resolution + `principal_type` distribution; `trust_type` FQDN inference; host-SAM domain-RID
  resolution across a trust. **This is the module that most needs GOAD / a real multi-domain forest.**

### M-MS4 — Opt-in merge + divergence ledger (Phase 2 bulk, scaffolded in Phase 1)
- **Inputs:** multiple sources sharing a `domain_id` (multi-DC); optional decoded
  `replPropertyMetaData` from the Phase-0 spike.
- **Outputs:** the merge fold (one presented row per `node_id`/`edge_id`); the `divergence` ledger;
  the "DC-A vs DC-B" report; the resolution ladder (§3.3).
- **Must get right:** per-source edge union, NEVER re-derive over the merged set; every disagreement
  counted, nothing fabricated or dropped; secrets kept per-source, redacted; honest degradation when
  the decoder is absent.
- **Needs a real capture to validate (critical):** a **real multi-DC capture with deliberate
  divergence** — object deleted on one DC, divergent membership, un-replicated password, planted
  lingering object — plus the real `replPropertyMetaData` / `msDS-ReplValueMetaData` byte shapes.
  Synthetic fixtures prove the plumbing but not the real metadata shapes. *(Phase 1 ships only the
  scaffolding — `source`/`source_observation`/`divergence` tables and the per-source edge-tagging —
  so M-MS4's merge logic drops in with no schema change in Phase 2.)*

### M-MS5 — UI (case-shape picker + per-source rows/coverage + merge toggle + honesty cards)
- **Inputs:** M-MS1..M-MS3 (and M-MS4 when Phase 2 lands).
- **Outputs:** §5 UI contract.
- **Must get right:** per-source-separate is the default landing; merge is an explicit opt-in toggle;
  mismatch/divergence/cross-domain cards carry the same honesty polarity as the GPO/AD CS cards; no
  silent reconciliation anywhere in the UI.
- **Needs a real capture to validate:** real multi-domain data to confirm the cross-domain + coverage
  cards read correctly to an operator.

**Suggested build order:** M-MS1 → M-MS2 → M-MS3 → (Phase 2: M-MS4) → M-MS5, with M-MS5's Phase-1
surfaces (picker, per-source rows/coverage, cross-domain card) buildable right after M-MS3 and the
merge/divergence surfaces added with M-MS4.

---

## 7. What must be confirmed on a real multi-domain / forest capture

Not signable on synthetic data (research 25 §9); needs GOAD (multi-domain/forest + trusts), Samba AD
DC (controllable divergence), BadBlood (bulk), and a GC fixture:

1. **Trust-direction BHCE round-trip** — attack-direction `trusted→trusting` → export `Trusts[]` →
   the arrow BHCE actually draws + abuse semantics survive. *Highest-risk unknown.*
2. **FSP cross-domain resolution + `principal_type`** — the `=Group` default vs the real User/
   Group/Computer distribution; owning-domain resolution vs counted stub.
3. **`trust_type` parent-child vs tree-root** FQDN inference on a real contiguous-namespace forest.
4. **Host-SAM well-known domain-RID set** resolving to the correct domain's principals across a trust.
5. **sIDHistory cross-domain bridge** — a real migrated identity carrying a privileged old-domain SID.
6. **GC partial-replica contamination** — shadows hard-tagged, never winning over a full-domain copy.
7. **(Phase 2 / M-MS4)** The four divergence scenarios + lingering/tombstone detection + the real
   `replPropertyMetaData` / `msDS-ReplValueMetaData` byte shapes.
8. **ADCS 8 edge directions + IssuedSignedBy** on a cross-domain PKI (still `adcs_pending_spike` for
   export — multi-domain does not lift that gate).

---

## 8. Owner decisions — RESOLVED 2026-11-11 (all four locked)

1. **Authoritative-DC tiebreaker — REMOVED.** WRAITH ALWAYS leaves a true tie un-chosen (safer
   reading, flagged, counted); no operator primary-DC nomination exists. See §3.3 (ladder is now
   tiers 1–3, no `authoritative_dc`). This was research 25 Open Decision 6.
2. **Phase-0 decoder — BUILD IT.** The spike returned FEASIBLE (research 26): `replPropertyMetaData`
   is a pure offline struct-parse via `dissect.esedb`. Tier-1 per-attribute newest-wins is on; the
   `whenChanged`-only ceiling does not apply. Residual: byte-parity test vs a real blob before M-MS4
   trusts it.
3. **Cross-forest surfacing — DERIVED** from distinct `forest_id`s (picker stays two axes:
   domain-cardinality × DC-cardinality). Not an explicit third toggle.
4. **Phase-1 `multi_dc` ingest — ALLOWED** for per-source views with the merge toggle disabled +
   an honest "multi-DC merge ships in Phase 2" note (§1.2). Not hard-blocked.

**Build order confirmed: start M-MS1 now, one module at a time, each gated.**

---

## Sources
`docs/research/25-multi-dc-multi-domain.md` (and its cited [MS-ADTS]/[MS-ADA3]/[MS-DRSR]/[MS-DTYP],
BloodHound edge docs, SharpHoundCommon Apache-2.0 study-only, DSInternals MIT study-only);
`docs/modules/10-bloodhound-export.md` (trust-direction convention, FSP default, ADCS lane status);
`wraith/model/store.py` (frozen tables, `_SCOPING_BLOCK`, `_PROVENANCE_STRUCT`, staging outside the
contract); `wraith/normalize/identity.py` (`node_id_for_sid`, `is_domain_specific_sid`).
