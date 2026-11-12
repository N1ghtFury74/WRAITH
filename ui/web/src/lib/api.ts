/**
 * Thin typed WRAITH API client — the ONE module wrapping fetch + the progress
 * WebSocket. Every type here mirrors a pydantic model in `wraith/api/*.py`
 * (models.py, ingest.py) and `wraith/case/*.py` (catalog.py, coverage.py,
 * progress_model.py). All requests are same-origin (`/api/v1/...`) so the offline
 * guarantee holds: no scheme, no host, nothing a CDN could serve.
 */

export const API_PREFIX = "/api/v1";

// --------------------------------------------------------------------------- //
//  Catalog constants mirrored from wraith/case/catalog.py (client pre-screen). //
//  The server re-enforces every one of these while streaming — this mirror is  //
//  a convenience so the UI can route/pre-screen without a round-trip.          //
// --------------------------------------------------------------------------- //
export type ArtifactKindId =
  | "ntds_dit"
  | "system_hive"
  | "sysvol"
  | "member_sam"
  | "ca_host_registry"
  | "additional_dc";

/** Human labels (catalog.py ArtifactKind.label). */
export const KIND_LABELS: Record<ArtifactKindId, string> = {
  ntds_dit: "NTDS database (ntds.dit)",
  system_hive: "DC SYSTEM registry hive",
  sysvol: "SYSVOL tree (GPO files)",
  member_sam: "Member-host SAM (+opt SYSTEM)",
  ca_host_registry: "Enterprise-CA host SYSTEM/SOFTWARE",
  additional_dc: "Additional DC ntds.dit (other domain)",
};

/** Reserved kinds: stored for provenance, no wired pass — never auto-routed. */
export const RESERVED_KIND_IDS: readonly ArtifactKindId[] = ["additional_dc"];

const GIB = 1024 * 1024 * 1024;
const MIB = 1024 * 1024;

/** Per-kind upload cap in bytes (catalog.py MAX_UPLOAD_BYTES). */
export const MAX_UPLOAD_BYTES: Record<ArtifactKindId, number> = {
  ntds_dit: 10 * GIB,
  system_hive: 256 * MIB,
  sysvol: 2 * GIB,
  member_sam: 256 * MIB,
  ca_host_registry: 256 * MIB,
  additional_dc: 10 * GIB,
};

/** Companion host SYSTEM hive cap (catalog.py MAX_COMPANION_SYSTEM_BYTES). */
export const MAX_COMPANION_SYSTEM_BYTES = 256 * MIB;

/** SYSVOL extraction bounds (catalog.py) — pre-screened client-side before zipping. */
export const SYSVOL_MAX_MEMBERS = 100_000;
export const SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * GIB;

// --------------------------------------------------------------------------- //
//  Provenance + node shapes (wraith/api/models.py)                            //
// --------------------------------------------------------------------------- //
export interface ProvenanceOut {
  source_file: string | null;
  image_sha256: string | null;
  source_object_id: string | null;
  directory_timestamp: string | null;
  ingest_run_id: string | null;
}

export interface CaseListEntry {
  id: string;
  domain_id: string | null;
  domain_fqdn: string | null;
  node_count: number;
  edge_count: number;
}

/** One workspace enumerated from disk by `GET /api/v1/cases` (authoritative). */
export interface CaseListItem {
  case_id: string;
  operator: string | null;
  created_at: string | null;
  authorization_ref: string | null;
  /** Canonical store exists => the graph/dossiers are viewable. */
  analyzed: boolean;
  uploaded_kinds: string[];
  /** The workspace could not be read (surfaced, never silently dropped). */
  unreadable: boolean;
}

export interface CaseSummary {
  domain_id: string | null;
  domain_fqdn: string | null;
  functional_level: number | null;
  node_count: number;
  edge_count: number;
  node_kind_counts: Record<string, number>;
  edge_kind_counts: Record<string, number>;
  tier0_node_count: number;
  dcsync_holder_count: number;
}

// --------------------------------------------------------------------------- //
//  Graph slice + search + node dossier (wraith/api/models.py)                 //
// --------------------------------------------------------------------------- //
export interface NodeRef {
  node_id: string;
  kind: string;
  label: string;
  /** Tier (0 when Tier-0) — present on dossier edge parties + memberships. */
  tier?: number | null;
  /** True when this party is a Tier-0 / high-value object. */
  is_tier0?: boolean;
}

export interface GraphNode {
  node_id: string;
  kind: string;
  label: string;
  object_sid: string | null;
  tier: number | null;
  highvalue: boolean;
  x: number | null;
  y: number | null;
}

export interface GraphEdge {
  edge_id: string;
  kind: string;
  source: string;
  target: string;
  confidence: string | null;
  is_inherited: boolean | null;
}

export interface GraphSlice {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_matched: number;
  returned: number;
  truncated: boolean;
  /** "server" when the backend precomputed x/y; "none" when the client lays out. */
  layout: string;
  seed_node_ids: string[];
  depth: number;
  /** Named counts for any degraded branch (e.g. no-Tier-0 fallback). */
  counted_gaps?: Record<string, number>;
}

// --------------------------------------------------------------------------- //
//  Attack paths + prebuilt analysis catalog (wraith/api/models.py, queries.py) //
// --------------------------------------------------------------------------- //
export interface PathEdge {
  source: string;
  target: string;
  kind: string;
  edge_id: string | null;
}

export interface AttackPath {
  nodes: NodeRef[];
  edges: PathEdge[];
  length: number;
  target_node_id: string;
  target_label: string;
}

export interface PathResult {
  source_node_ids: string[];
  target_node_ids: string[];
  paths: AttackPath[];
  paths_found: number;
  truncated: boolean;
  max_hops: number;
  unreachable_targets: string[];
  over_budget_targets: string[];
}

export interface PathRequest {
  source_node_ids?: string[] | null;
  source_sid?: string | null;
  target?: string | null;
  target_node_ids?: string[] | null;
  direction?: "outbound" | "inbound";
  max_hops?: number;
  max_paths?: number;
}

export interface PrebuiltQuery {
  id: string;
  label: string;
  description: string;
  kind: "path" | "set";
  direction: "to-target" | "source-to-target" | "set";
  supported: boolean;
  reason: string | null;
  data_confidence: "real" | "synthetic-only" | "none";
  source_count: number | null;
  /** Hunter category (e.g. "Privileged Access", "Dangerous ACLs", "ADCS"). */
  category: string;
}

export interface PrebuiltQueryResult {
  query_id: string;
  kind: "path" | "set";
  paths: PathResult | null;
  slice: GraphSlice | null;
  counted_gaps: Record<string, number>;
}

/** One connecting chain from the connect-the-dots endpoint (two never-mixed lanes). */
export interface ConnectorPath {
  /** "control" = real principal→object capability; "scope" = GPO→…→principal application. */
  lane: "control" | "scope";
  nodes: NodeRef[];
  edges: PathEdge[];
  length: number;
  /** Weakest-hop confidence ("confirmed" | "inferred" | "unknown"). */
  confidence: string;
  source_node_id: string;
  target_node_id: string;
  /** RSoP caveat (set on every scope chain; null on control chains). */
  caveat: string | null;
}

/** The connect-the-dots result: two ranked lanes + the honest gap/caveat ledger. */
export interface ConnectorResult {
  paths: ConnectorPath[];
  control_count: number;
  scope_count: number;
  retained_node_ids: string[];
  /** Intermediate directory objects ADDED to connect (not filter matches). */
  via_node_ids: string[];
  truncated: boolean;
  max_hops: number;
  caveats: string[];
  counted_gaps: Record<string, number>;
  /** Set only when no chain was found: the explicit "no connection" message. */
  note: string | null;
}

export interface ConnectorRequest {
  node_ids: string[];
  max_hops?: number;
  max_paths?: number;
  max_pairs?: number;
}

export interface SliceRequest {
  seed_node_ids?: string[] | null;
  search?: string | null;
  node_kinds?: string[] | null;
  edge_kinds?: string[] | null;
  tier0_only?: boolean;
  depth?: number;
  limit?: number;
  layout?: string;
}

export interface SearchResult {
  query: string;
  hits: NodeRef[];
  count: number;
  truncated: boolean;
}

export interface UacFlagsOut {
  raw: number | null;
  enabled: boolean | null;
  account_disabled: boolean;
  password_not_required: boolean;
  dont_expire_password: boolean;
  trusted_for_delegation: boolean;
  trusted_to_auth_for_delegation: boolean;
  not_delegated: boolean;
  dont_require_preauth: boolean;
  server_trust_account: boolean;
  workstation_trust_account: boolean;
  partial_secrets_account: boolean;
  /** ENCRYPTED_TEXT_PWD_ALLOWED (0x80) — password stored reversibly. */
  reversible_password?: boolean;
}

export interface RiskFactor {
  code: string;
  label: string;
  detail: string;
  weight: number;
}

export interface NodeRisk {
  node_id: string;
  kind: string;
  label: string;
  object_sid: string | null;
  score: number;
  tier: number | null;
  factors: RiskFactor[];
  /** Shortest attacker-path hop count to Tier-0 (null if unreachable/unknown). */
  tier0_hops?: number | null;
}

export interface RiskSummary {
  scored_nodes: number;
  tier0_nodes: number;
  dcsync_holders: number;
  tier0_reachable: number;
  unconstrained_delegation: number;
  kerberoastable: number;
  asrep_roastable: number;
  has_sid_history: number;
  top: NodeRisk[];
}

/** A redacted secret reference — NEVER a plaintext value or hash (NFR-05). */
export interface SecretRefOut {
  secret_id: string | null;
  secret_type: string | null;
  label: string | null;
  decrypted: boolean | null;
  decryptable_offline: boolean | null;
}

/** A member of a group (effective-membership closure; Group dossiers only). */
export interface GroupMemberRef {
  node_id: string;
  kind: string;
  label: string;
  object_sid: string | null;
  tier: number | null;
  risk_score: number | null;
  is_tier0: boolean;
  /** True when the member comes in via nesting/primary-group (not a direct MemberOf). */
  is_nested?: boolean;
}

/** One rights-glossary entry (grants/why/action) — static, not case-scoped. */
export interface GlossaryEntry {
  grants: string;
  why: string;
  action: string;
}

/** The static rights/attributes glossary (GET /glossary) — fetched once, cached. */
export interface Glossary {
  edges: Record<string, GlossaryEntry>;
  flags: Record<string, GlossaryEntry>;
}

/**
 * One CA-host NODE-LEVEL finding surfaced on a dossier — mirrors
 * wraith/api/models.py CaNodeFindingOut. ESC11/ESC16 appear on the EnterpriseCA
 * node; the DCOM activation summary on the CA host Computer node. Each finding is
 * self-describing (title + caption state what it means AND that it needed the CA
 * host hive) and carries its own hive provenance. `value` is the NON-SECRET decided
 * value only (`"true"` for ESC11/ESC16; the `EnableDCOM=Y/N` summary for DCOM) —
 * never a security-descriptor byte.
 */
export interface CaNodeFindingOut {
  /** `esc11_no_encrypt_enforcement` / `esc16_sid_ext_disabled` / `dcom_restrictions`. */
  prop: string;
  title: string;
  caption: string;
  value: string;
  provenance: ProvenanceOut;
}

/** One inbound/outbound ACE/edge row in a dossier (with the resolved other party). */
export interface DossierEdge {
  edge_id: string;
  kind: string;
  direction: string;
  other: NodeRef;
  confidence: string | null;
  is_inherited: boolean | null;
  access_mask: number | null;
  object_type_guid: string | null;
  /** Resolved attribute/control-right name for the scoped GUID (null = whole-object). */
  attribute_name: string | null;
}

/** Full per-entity dossier — mirrors wraith/api/models.py NodeDossier exactly. */
export interface NodeDossier {
  node_id: string;
  kind: string;
  label: string;
  object_sid: string | null;
  object_guid: string | null;
  samaccountname: string | null;
  upn: string | null;
  distinguished_name: string | null;
  display_name: string | null;
  description: string | null;
  domain_id: string | null;
  domain_fqdn: string | null;
  admincount: number | null;
  primary_group_id: number | null;
  spns: string[];
  sid_history: string[];
  pwd_last_set: string | null;
  last_logon_timestamp: string | null;
  when_created: string | null;
  when_changed: string | null;
  uac: UacFlagsOut | null;
  node_flags: Record<string, boolean>;
  inbound_edges: DossierEdge[];
  outbound_edges: DossierEdge[];
  inbound_edge_counts: Record<string, number>;
  outbound_edge_counts: Record<string, number>;
  group_memberships: NodeRef[];
  /** CA-host node-level findings (ESC11/ESC16 on an EnterpriseCA; DCOM summary on a
   *  CA host Computer). Dropped by the API when empty, so a non-CA node omits it. */
  ca_node_findings?: CaNodeFindingOut[];
  /** Members of this group (Group nodes only; [] otherwise). */
  group_members?: GroupMemberRef[];
  /** Pre-composed plain-language briefing sentences (rendered at the top). */
  exec_summary?: string[];
  secret_refs: SecretRefOut[];
  behavior_summary_ref: string | null;
  risk: NodeRisk | null;
  provenance: ProvenanceOut;
  /** Read-time multi-source merge overlay — present ONLY on a folded (unscoped)
   *  dossier of a case whose opt-in merge has run. Omitted otherwise. */
  merge?: MergeOverlay | null;
}

// --------------------------------------------------------------------------- //
//  Multi-source / multi-domain shapes (wraith/api/models.py — M-MS)           //
// --------------------------------------------------------------------------- //
/** One ingested DC artifact set (source) in a case (SourceInfo, §2.2a). */
export interface SourceInfo {
  source_id: string;
  dc_label: string;
  /** DERIVED (authoritative) domain facts from the actual ntds.dit. */
  domain_id: string | null;
  domain_fqdn: string | null;
  forest_id: string;
  /** Operator-declared domain label (display only). */
  declared_domain: string | null;
  /** Flagged when partial-replica shadows were seen (a GC source). */
  is_global_catalog: boolean | null;
  node_count: number;
  edge_count: number;
}

/** The per-case source listing (GET /sources). */
export interface SourceList {
  sources: SourceInfo[];
  count: number;
}

/** One artifact's coverage/skip tally within a source's coverage. */
export interface SourceCoverageArtifact {
  source_file: string | null;
  image_sha256: string | null;
  coverage_counts: Record<string, number>;
  skip_counts: Record<string, number>;
}

/** Per-source coverage/skip counts (GET /sources/{id}/coverage). */
export interface SourceCoverage {
  source_id: string;
  dc_label: string | null;
  artifacts: SourceCoverageArtifact[];
  coverage_counts: Record<string, number>;
  skip_counts: Record<string, number>;
  counted_gaps: Record<string, number>;
}

/** Three-state badge for a merged node's divergent attribute (§3.3). */
export type PresentedState = "no_divergence" | "resolved" | "contested_unresolved";

/** One divergent attribute's read-time presented value + three-state badge. */
export interface PresentedAttribute {
  attribute: string;
  state: PresentedState;
  /** The resolved presented value (null for `contested_unresolved`). */
  presented_value?: unknown;
  /** Per-source raw staged values (never a secret). */
  value_by_source: Record<string, unknown>;
}

/** The read-time merge overlay attached to a MERGED node's dossier. */
export interface MergeOverlay {
  merged: boolean;
  run_id: string;
  presented_attributes: PresentedAttribute[];
  /** `deleted_on_source` / `candidate_lingering_object` when one fired. */
  entity_divergence: string | null;
  /** True when un-replicated/divergent secret material exists (value-free). */
  secret_divergence: boolean;
  counted_gaps: Record<string, number>;
}

/** The "DC-A vs DC-B disagreed on X" report (§3.4), ledger-driven. */
export interface DcVsDcReport {
  source_ids: string[];
  counts_by_type: Record<string, number>;
  counts_by_resolution: Record<string, number>;
  total: number;
}

/** Result of an opt-in merge-fold run (POST /cases/{id}/merge). */
export interface MergeReport {
  case_id: string;
  run_id: string;
  source_ids: string[];
  /** The honest <2-sources state (surfaced, not an error). */
  nothing_to_merge: boolean;
  nodes_reconciled: number;
  edges_reconciled: number;
  deleted_on_source: number;
  candidate_lingering_objects: number;
  edge_membership_divergences: number;
  attribute_divergences: number;
  secret_divergences: number;
  attribute_unresolved: number;
  tier1_unavailable: number;
  staging_attrs_unparseable: number;
  repl_blob_unparseable: number;
  gc_sources_in_selection: number;
  report: DcVsDcReport;
  counted_gaps: Record<string, number>;
}

/** One divergence ledger row (the DC-vs-DC drill-down). */
export interface DivergenceRow {
  obj_kind: string;
  obj_id: string;
  attribute: string | null;
  divergence_type: string;
  resolution: string | null;
  resolved_by: string | null;
  /** Per-source map; a secret row is `{source: {present, differs}}` only. */
  value_by_source: Record<string, unknown>;
  resolved_value?: unknown;
}

/** The divergence ledger read for a case/merge run (GET /divergence). */
export interface DivergenceLedger {
  case_id: string;
  run_id: string;
  /** False (+ counted `merge.no_merge_run`) when no merge has run yet. */
  merged: boolean;
  rows: DivergenceRow[];
  report: DcVsDcReport;
  counted_gaps: Record<string, number>;
}

/** One row in the browse-by-type node list (GET /nodes). */
export interface NodeListEntry {
  node_id: string;
  kind: string;
  label: string;
  object_sid: string | null;
  tier: number | null;
  risk_score: number | null;
  highvalue: boolean;
}

/** A bounded page of the browse-by-type node list (GET /nodes). */
export interface NodeListPage {
  entries: NodeListEntry[];
  total_matched: number;
  returned: number;
  offset: number;
  limit: number;
  truncated: boolean;
}

export type NodeSort = "name" | "kind" | "risk" | "tier";
export type SortOrder = "asc" | "desc";

export interface NodesPageParams {
  kind?: string;
  q?: string;
  sort?: NodeSort;
  order?: SortOrder;
  limit?: number;
  offset?: number;
}

// --------------------------------------------------------------------------- //
//  Case / ingest shapes (wraith/api/ingest.py)                                //
// --------------------------------------------------------------------------- //
/** Case-shape axes (multi-source contract §1.1). */
export type DomainCardinality = "single_domain" | "multi_domain";
export type DcCardinality = "single_dc" | "multi_dc";

export interface CreateCaseRequest {
  case_id: string;
  operator: string;
  authorization_ref?: string | null;
  forest_id?: string;
  forest_id_map?: Record<string, string>;
  /** Whether cross-domain edge wiring runs (trust/FSP/sIDHistory). */
  domain_cardinality?: DomainCardinality;
  /** Whether the merge/divergence engine is available for the case. */
  dc_cardinality?: DcCardinality;
}

export interface CaseCreated {
  case_id: string;
  operator: string;
  created_at: string;
  root_rel: string;
  artifacts: string[];
}

export interface ArtifactKindOut {
  id: string;
  label: string;
  necessity: "required" | "optional";
  multi: boolean;
  unlocks: string[];
  uploaded: boolean;
  source_files: string[];
}

export interface CatalogResponse {
  required: ArtifactKindOut[];
  optional: ArtifactKindOut[];
}

export interface ArtifactRegistered {
  kind: string;
  source_file: string;
  stored_rel_path: string;
  size_bytes: number;
  image_sha256: string;
  replaced: boolean;
}

// --------------------------------------------------------------------------- //
//  Coverage shapes (wraith/case/coverage.py)                                  //
// --------------------------------------------------------------------------- //
export type CoverageStatus = "available" | "degraded" | "unavailable";

export interface CoverageReason {
  missing_artifact_id: string;
  effect: "degraded" | "unavailable";
  gap_class: string;
  note: string;
}

export interface CapabilityCoverage {
  capability_id: string;
  label: string;
  tier: string;
  status: CoverageStatus;
  reasons: CoverageReason[];
}

export interface CoverageReport {
  present_kinds: string[];
  missing_required: string[];
  can_analyze: boolean;
  capabilities: CapabilityCoverage[];
}

// --------------------------------------------------------------------------- //
//  Analyze + run status (wraith/api/ingest.py, progress_model.py)             //
// --------------------------------------------------------------------------- //
export interface AnalyzeRequest {
  export_version?: number | null;
  include?: string[] | null;
}

export interface AnalyzeAccepted {
  run_id: string;
  case_id: string;
  ws_url: string;
  active_passes: string[];
  coverage: CoverageReport;
}

export type PassState = "pending" | "running" | "done";
export type RunState = "pending" | "running" | "done" | "failed";

export interface PassStatus {
  id: string;
  label: string;
  weight: number;
  state: PassState;
  pct: number;
}

export interface AnalyzeResultSummary {
  node_count: number;
  edge_count: number;
  edge_kind_counts: Record<string, number>;
  export_zip_rel: string;
  coverage: CoverageReport;
}

export interface RunStatus {
  run_id: string;
  case_id: string;
  state: RunState;
  current_pass: string | null;
  percent: number;
  passes: PassStatus[];
  coverage_counts: Record<string, number>;
  skip_counts: Record<string, number>;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  result: AnalyzeResultSummary | null;
  /** Case-scoped API path to download the BloodHound CE export zip, or `null`
   *  when the run is not done / produced no export. */
  export_download_url: string | null;
}

// --------------------------------------------------------------------------- //
//  WebSocket progress events (wraith/api/ingest.py CaseRunManager.stream)      //
// --------------------------------------------------------------------------- //
export interface ProgressEvent {
  type: "snapshot" | "progress" | "done";
  case_id?: string;
  run_id?: string;
  active_passes?: string[];
  pass?: string | null;
  pct?: number;
  state?: RunState;
  coverage_counts?: Record<string, number>;
  skip_counts?: Record<string, number>;
  error?: string | null;
}

// --------------------------------------------------------------------------- //
//  Typed error — carries the backend's machine-stable `reason` code            //
// --------------------------------------------------------------------------- //
/**
 * A failed API call. `reason` is the backend's typed code
 * (`bad_magic:<kind>` / `too_large:<kind>` / `zip_slip` / `unknown_case` /
 * `run_in_progress` / `ntds_dit_required` / ...) when the response carried a
 * `{detail: {reason}}` body; otherwise a generic HTTP code. `fields` holds any
 * extra detail keys (e.g. `missing` for `ntds_dit_required`).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;
  readonly fields: Record<string, unknown>;

  constructor(status: number, reason: string, message: string, fields: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
    this.fields = fields;
  }
}

type DetailBody = {
  detail?: unknown;
};

function extractReason(status: number, body: DetailBody | null): ApiError {
  const detail = body?.detail;
  if (detail && typeof detail === "object" && "reason" in detail) {
    const d = detail as Record<string, unknown>;
    const reason = String(d.reason);
    const { reason: _ignored, ...rest } = d;
    void _ignored;
    return new ApiError(status, reason, reason, rest);
  }
  if (typeof detail === "string") {
    return new ApiError(status, `http_${status}`, detail);
  }
  return new ApiError(status, `http_${status}`, `request failed (${status})`);
}

async function parseError(res: Response): Promise<ApiError> {
  let body: DetailBody | null = null;
  try {
    body = (await res.json()) as DetailBody;
  } catch {
    body = null;
  }
  return extractReason(res.status, body);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_PREFIX}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// --------------------------------------------------------------------------- //
//  Public API surface                                                         //
// --------------------------------------------------------------------------- //
export const api = {
  /** List every case workspace on disk (sorted by case_id) — the authoritative
   * selector source. Includes CLI-created cases and their analyzed state. */
  listCases(): Promise<CaseListItem[]> {
    return request<CaseListItem[]>("/cases");
  },

  /** Create a case workspace. 409 `case_exists`, 400 `unsafe_case_id`. */
  createCase(body: CreateCaseRequest): Promise<CaseCreated> {
    return postJson<CaseCreated>("/cases", body);
  },

  /** Delete a case + its artifacts/results (IRREVERSIBLE). 409 `run_in_progress`,
   * 404 `unknown_case`, 400 `unsafe_case_id`. */
  deleteCase(caseId: string): Promise<{ case_id: string; deleted: boolean }> {
    return request<{ case_id: string; deleted: boolean }>(
      `/cases/${encodeURIComponent(caseId)}`,
      { method: "DELETE" },
    );
  },

  /** Catalog tiles (required/optional) joined with the upload index. */
  catalog(caseId: string): Promise<CatalogResponse> {
    return request<CatalogResponse>(`/cases/${encodeURIComponent(caseId)}/catalog`);
  },

  /** Live coverage preview from the uploaded set. */
  coverage(caseId: string): Promise<CoverageReport> {
    return request<CoverageReport>(`/cases/${encodeURIComponent(caseId)}/coverage`);
  },

  /** Launch analysis (202). 422 `ntds_dit_required`, 409 `run_in_progress`. */
  analyze(caseId: string, body: AnalyzeRequest = {}): Promise<AnalyzeAccepted> {
    return postJson<AnalyzeAccepted>(`/cases/${encodeURIComponent(caseId)}/analyze`, body);
  },

  /** Poll a run's live/terminal status (fallback if the WS drops). */
  runStatus(caseId: string, runId: string): Promise<RunStatus> {
    return request<RunStatus>(
      `/cases/${encodeURIComponent(caseId)}/runs/${encodeURIComponent(runId)}`,
    );
  },

  /** Read-only case summary (available once analyzed). `case_id` scopes it;
   * an optional `sourceId` narrows the counts to one ingested source (M-MS2). */
  summary(caseId: string, sourceId?: string): Promise<CaseSummary> {
    const p = new URLSearchParams({ case_id: caseId });
    if (sourceId) p.set("source_id", sourceId);
    return request<CaseSummary>(`/summary?${p.toString()}`);
  },

  /** List the DC artifact sets (sources) in the case + per-source counts (M-MS2). */
  sources(caseId: string): Promise<SourceList> {
    return request<SourceList>(`/sources?case_id=${encodeURIComponent(caseId)}`);
  },

  /** Per-source coverage/skip counts for one source (M-MS2). */
  sourceCoverage(caseId: string, sourceId: string): Promise<SourceCoverage> {
    return request<SourceCoverage>(
      `/sources/${encodeURIComponent(sourceId)}/coverage?case_id=${encodeURIComponent(caseId)}`,
    );
  },

  /** Run the opt-in merge-fold over the operator-selected sources (M-MS4b).
   * 422 `unknown_source_ids`, 409 `run_in_progress`. */
  mergeSources(caseId: string, sourceIds: string[]): Promise<MergeReport> {
    return postJson<MergeReport>(`/cases/${encodeURIComponent(caseId)}/merge`, {
      source_ids: sourceIds,
    });
  },

  /** The divergence ledger for a case's current merge run (M-MS4b). */
  divergence(caseId: string): Promise<DivergenceLedger> {
    return request<DivergenceLedger>(`/divergence?case_id=${encodeURIComponent(caseId)}`);
  },

  /** Bounded, deterministic server-side graph slice for the canvas. */
  slice(caseId: string, body: SliceRequest): Promise<GraphSlice> {
    return postJson<GraphSlice>(`/graph/slice?case_id=${encodeURIComponent(caseId)}`, body);
  },

  /** Typeahead search over SID / name / sAMAccountName / UPN / DN. */
  search(caseId: string, q: string, limit = 25): Promise<SearchResult> {
    return request<SearchResult>(
      `/search?case_id=${encodeURIComponent(caseId)}&q=${encodeURIComponent(q)}&limit=${limit}`,
    );
  },

  /** Full per-entity dossier (identity, edges, memberships, risk, redacted secrets).
   * An optional `sourceId` scopes it to one source (per-source, no merge overlay). */
  node(caseId: string, nodeId: string, sourceId?: string): Promise<NodeDossier> {
    const p = new URLSearchParams({ case_id: caseId });
    if (sourceId) p.set("source_id", sourceId);
    return request<NodeDossier>(`/nodes/${encodeURIComponent(nodeId)}?${p.toString()}`);
  },

  /** Browse-by-type bounded node list (GET /nodes). `sourceId` scopes to one source. */
  nodesPage(caseId: string, params: NodesPageParams = {}, sourceId?: string): Promise<NodeListPage> {
    const p = new URLSearchParams({ case_id: caseId });
    if (params.kind) p.set("kind", params.kind);
    if (params.q) p.set("q", params.q);
    if (params.sort) p.set("sort", params.sort);
    if (params.order) p.set("order", params.order);
    if (params.limit !== undefined) p.set("limit", String(params.limit));
    if (params.offset !== undefined) p.set("offset", String(params.offset));
    if (sourceId) p.set("source_id", sourceId);
    return request<NodeListPage>(`/nodes?${p.toString()}`);
  },

  /** The static rights/attributes glossary (not case-scoped; fetch once + cache). */
  glossary(): Promise<Glossary> {
    return request<Glossary>("/glossary");
  },

  /** Aggregate risk/landing stats + the top-scored nodes. */
  riskSummary(caseId: string, top = 10): Promise<RiskSummary> {
    return request<RiskSummary>(`/risk/summary?case_id=${encodeURIComponent(caseId)}&top=${top}`);
  },

  /** Ranked per-node risk scores (bounded, min-score filtered). */
  riskNodes(caseId: string, opts: { limit?: number; min_score?: number } = {}): Promise<NodeRisk[]> {
    const p = new URLSearchParams({ case_id: caseId });
    if (opts.limit !== undefined) p.set("limit", String(opts.limit));
    if (opts.min_score !== undefined) p.set("min_score", String(opts.min_score));
    return request<NodeRisk[]>(`/risk/nodes?${p.toString()}`);
  },

  /** The edge-rich Tier-0 neighborhood — the initial canvas load (design §7.1). */
  graphDefault(caseId: string): Promise<GraphSlice> {
    return request<GraphSlice>(`/graph/default?case_id=${encodeURIComponent(caseId)}`);
  },

  /** Lazy neighbourhood expand around one node (existing endpoint). */
  neighbors(
    caseId: string,
    nodeId: string,
    opts: { depth?: number; limit?: number; edgeKinds?: string[] } = {},
  ): Promise<GraphSlice> {
    const p = new URLSearchParams({ case_id: caseId });
    if (opts.depth !== undefined) p.set("depth", String(opts.depth));
    if (opts.limit !== undefined) p.set("limit", String(opts.limit));
    for (const k of opts.edgeKinds ?? []) p.append("edge_kinds", k);
    return request<GraphSlice>(`/nodes/${encodeURIComponent(nodeId)}/neighbors?${p.toString()}`);
  },

  /** The frozen prebuilt attack-query catalog with live source counts. */
  listQueries(caseId: string): Promise<PrebuiltQuery[]> {
    return request<PrebuiltQuery[]>(`/analysis/queries?case_id=${encodeURIComponent(caseId)}`);
  },

  /** Run one catalog query (bounded). 404 unknown_query, 422 query_not_supported. */
  runQuery(
    caseId: string,
    queryId: string,
    body: { max_hops?: number; max_paths?: number } = {},
  ): Promise<PrebuiltQueryResult> {
    return postJson<PrebuiltQueryResult>(
      `/analysis/queries/${encodeURIComponent(queryId)}/run?case_id=${encodeURIComponent(caseId)}`,
      body,
    );
  },

  /** Attacker pathfinding. outbound = source(s)->Tier-0/target; inbound = who-can-reach. */
  paths(caseId: string, body: PathRequest): Promise<PathResult> {
    return postJson<PathResult>(`/paths?case_id=${encodeURIComponent(caseId)}`, body);
  },

  /** Connect-the-dots: minimal labelled connecting chains for a retained node set
   * (two lanes — control ranked above scope; scope carries the RSoP caveat). */
  connector(caseId: string, body: ConnectorRequest): Promise<ConnectorResult> {
    return postJson<ConnectorResult>(
      `/graph/connector?case_id=${encodeURIComponent(caseId)}`,
      body,
    );
  },

  /**
   * Upload one artifact (multipart). The client filename is discarded by the
   * backend; `kind` + optional `host_label` drive the stored path. `onProgress`
   * reports 0..1 upload fraction. Rejects with {@link ApiError} carrying the
   * typed reason (`bad_magic:<kind>`, `too_large:<kind>`, `zip_slip`, ...).
   */
  uploadArtifact(
    caseId: string,
    opts: {
      kind: string;
      file: File;
      hostLabel?: string;
      systemFile?: File | null;
      /** Optional CA-host SOFTWARE companion hive (ca_host_registry only — the DCOM
       *  plane). Rides the same composite upload as the primary SYSTEM hive. */
      softwareFile?: File | null;
      /** Operator-asserted CA host FQDN (ca_host_registry only; display/correlation). */
      caHostFqdn?: string;
      /** Per-source tag for an ntds.dit/additional_dc source (multi-source §1.2). */
      dcLabel?: string;
      /** Operator-declared domain for this source (display label). */
      domain?: string;
      /** Cross-forest override for this source's forest_id. */
      sourceForestId?: string;
      onProgress?: (fraction: number) => void;
      signal?: AbortSignal;
    },
  ): Promise<ArtifactRegistered> {
    const form = new FormData();
    form.append("kind", opts.kind);
    form.append("file", opts.file, opts.file.name);
    if (opts.hostLabel) form.append("host_label", opts.hostLabel);
    if (opts.systemFile) form.append("system_file", opts.systemFile, opts.systemFile.name);
    if (opts.softwareFile) form.append("software_file", opts.softwareFile, opts.softwareFile.name);
    if (opts.caHostFqdn) form.append("ca_host_fqdn", opts.caHostFqdn);
    if (opts.dcLabel) form.append("dc_label", opts.dcLabel);
    if (opts.domain) form.append("domain", opts.domain);
    if (opts.sourceForestId) form.append("source_forest_id", opts.sourceForestId);

    // XHR (not fetch) because only XHR exposes upload-progress events, which the
    // per-file progress bar needs. Still same-origin, still no external host.
    return new Promise<ArtifactRegistered>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${API_PREFIX}/cases/${encodeURIComponent(caseId)}/artifacts`);
      xhr.responseType = "json";

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && opts.onProgress) {
          opts.onProgress(e.loaded / e.total);
        }
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          opts.onProgress?.(1);
          resolve(xhr.response as ArtifactRegistered);
        } else {
          const body = (xhr.response ?? null) as DetailBody | null;
          reject(extractReason(xhr.status, body));
        }
      };
      xhr.onerror = () =>
        reject(new ApiError(0, "network_error", "upload failed (connection error)"));
      xhr.onabort = () => reject(new ApiError(0, "aborted", "upload aborted"));
      if (opts.signal) {
        opts.signal.addEventListener("abort", () => xhr.abort(), { once: true });
      }
      xhr.send(form);
    });
  },
};

/** Build the same-origin WS URL for a case's progress stream. */
export function progressWsUrl(caseId: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${API_PREFIX}/ws/progress?case_id=${encodeURIComponent(caseId)}`;
}
