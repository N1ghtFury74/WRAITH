"""Pydantic response shapes for the WRAITH M7 API (versioned ``/api/v1``).

Every entity/edge/finding response carries its provenance block (the WRAITH
non-negotiable). Secrets appear ONLY as redacted references
(:class:`SecretRefOut` — never plaintext). All models are plain data shapes; the
feature modules (``graph``/``paths``/``risk``/``dossier``) build them from the
read-only :class:`~wraith.api.store.StoreReader` rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)

from wraith.api.tiering import MAX_PATH_HOPS, MAX_PATH_RESULTS


class ProvenanceOut(BaseModel):
    """Embedded §2.3 provenance block attached to every fact."""

    model_config = ConfigDict(extra="forbid")

    source_file: str | None = None
    image_sha256: str | None = None
    source_object_id: str | None = None
    directory_timestamp: datetime | None = None
    ingest_run_id: str | None = None


class NodeRef(BaseModel):
    """A minimal node reference (id + kind + display label).

    ``tier``/``is_tier0`` are resolved from the shared Tier-0 classification set
    (``tier0_sets().classified_ids``) when the reference is built in a context that
    knows it (e.g. a dossier edge endpoint), so the UI can badge a controller /
    target that is Tier-0. They default to ``None``/``False`` for references built
    where tiering is not resolved (paths, search), which is honest — not a claim of
    "not Tier-0".
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    tier: int | None = None
    is_tier0: bool = False


class GroupMemberRef(BaseModel):
    """One effective member of a Group dossier (design doc 21 §3.2).

    Populated ONLY for a ``kind == "Group"`` dossier from the M4
    ``effective_membership`` closure (``effective_members_of`` — the SAME source the
    hunt catalog uses, so the dossier and the hunts agree). ``tier``/``is_tier0``
    come from the shared Tier-0 classification set; ``risk_score`` from the shared
    scored map (``None`` for kinds the risk model does not score). ``is_nested`` is
    ``False`` for a direct member (the source of an inbound ``MemberOf`` edge) and
    ``True`` for a member folded in via nested-group / primary-group membership.
    ``is_nested`` is the SINGLE source of truth for the direct/nested split
    (research 11 §2.2): the frontend MUST consume this flag, never recompute it
    from ``inbound_edges``. ``confidence`` is the strongest available derivation on
    the member->group path (``"confirmed"`` when a stored-``member`` /
    primary-group path exists, ``"inferred"`` when the node is an effective member
    ONLY via a special-identity hop — Everyone / Authenticated Users / Domain
    Users — so a weaker, logon-time-only claim is distinguishable). No secret field
    is ever carried.
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    object_sid: str | None = None
    tier: int | None = None
    risk_score: int | None = None
    is_tier0: bool = False
    is_nested: bool = False
    #: The strongest-available member->group derivation confidence
    #: (``"confirmed"`` | ``"inferred"``). ``None`` only if the membership source
    #: carried no confidence (should not happen for a closure member).
    confidence: str | None = None


class GraphNode(BaseModel):
    """A node in a graph slice; ``x``/``y`` set only when layout is server-side."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    object_sid: str | None = None
    tier: int | None = None
    highvalue: bool = False
    x: float | None = None
    y: float | None = None


class GraphEdge(BaseModel):
    """An attacker-direction edge (``source -> target``) in a graph slice."""

    model_config = ConfigDict(extra="forbid")

    edge_id: str
    kind: str
    source: str
    target: str
    confidence: str | None = None
    is_inherited: bool | None = None


class GraphSlice(BaseModel):
    """A bounded, deterministic slice of the graph for the canvas.

    ``total_matched`` is the full node count of the slice's conceptual match set:
    the canonical candidate matches (before the ``limit`` cap) PLUS any ``Base``
    endpoints materialized into the returned slice (those are added beyond the cap to
    keep kept edges from dangling, so they are counted here too — never inflating
    ``returned`` past ``total_matched``). ``returned`` is the rendered node count;
    ``truncated`` is ``True`` exactly when ``returned < total_matched`` (a canonical
    match was dropped by the cap — the honest "214 / 390 shown" rule).
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_matched: int
    returned: int
    truncated: bool
    layout: str
    seed_node_ids: list[str] = []
    depth: int = 0
    #: Named counts of any degraded branch that produced this slice (e.g. the
    #: ``GET /graph/default`` no-Tier-0 fallback that seeded top-risk nodes). Empty
    #: for an ordinary slice — the "counted gap on every degraded branch" rule.
    counted_gaps: dict[str, int] = {}


class PathEdge(BaseModel):
    """One hop of an attack path (with the edge kind that enabled it)."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    kind: str
    edge_id: str | None = None


class AttackPath(BaseModel):
    """An ordered attacker path from a source principal to a Tier-0 target."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[NodeRef]
    edges: list[PathEdge]
    length: int
    target_node_id: str
    target_label: str


class PathResult(BaseModel):
    """The result of a pathfinding query (ranked shortest-first, capped)."""

    model_config = ConfigDict(extra="forbid")

    source_node_ids: list[str]
    target_node_ids: list[str]
    paths: list[AttackPath]
    paths_found: int
    truncated: bool
    max_hops: int
    unreachable_targets: list[str] = []
    #: Targets that ARE reachable but whose path exceeds ``max_hops`` (non-simple
    #: query) or were cut by the enumeration cap — honestly distinct from
    #: ``unreachable_targets`` (genuinely no path) so an operator is never told a
    #: reachable Tier-0 is unreachable.
    over_budget_targets: list[str] = []


class RiskFactor(BaseModel):
    """One transparent, itemized contribution to a node's risk score."""

    model_config = ConfigDict(extra="forbid")

    code: str
    label: str
    detail: str
    weight: int


class NodeRisk(BaseModel):
    """A node's transparent risk score = sum of its itemized factor weights."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    object_sid: str | None = None
    score: int
    tier: int | None = None
    #: Shortest attacker-path hop count from this node to ANY Tier-0 target (the
    #: structured promotion of the ``TIER0_REACHABLE`` factor's hop count, design
    #: doc 21 add #3). ``None`` when the node is itself Tier-0 or cannot reach a
    #: Tier-0 target — so "reaches Tier-0 in K hops" needs no string-parsing.
    tier0_hops: int | None = None
    factors: list[RiskFactor]


class RiskSummary(BaseModel):
    """Aggregate risk/landing stats for the dashboard."""

    model_config = ConfigDict(extra="forbid")

    scored_nodes: int
    tier0_nodes: int
    dcsync_holders: int
    tier0_reachable: int
    unconstrained_delegation: int
    kerberoastable: int
    asrep_roastable: int
    has_sid_history: int
    top: list[NodeRisk]
    #: Counted gaps for a degraded per-source scope (M-MS2); empty when unscoped.
    counted_gaps: dict[str, int] = {}


class SecretRefOut(BaseModel):
    """A redacted secret reference (NEVER plaintext — NFR-05)."""

    model_config = ConfigDict(extra="forbid")

    secret_id: str | None = None
    secret_type: str | None = None
    label: str | None = None
    decrypted: bool | None = None
    decryptable_offline: bool | None = None


class UacFlagsOut(BaseModel):
    """Decoded userAccountControl flags for the dossier."""

    model_config = ConfigDict(extra="forbid")

    raw: int | None = None
    enabled: bool | None = None
    account_disabled: bool = False
    password_not_required: bool = False
    dont_expire_password: bool = False
    trusted_for_delegation: bool = False
    trusted_to_auth_for_delegation: bool = False
    not_delegated: bool = False
    dont_require_preauth: bool = False
    server_trust_account: bool = False
    workstation_trust_account: bool = False
    partial_secrets_account: bool = False
    #: ENCRYPTED_TEXT_PWD_ALLOWED (``0x80``) — password stored with reversible
    #: encryption (recoverable to plaintext from the directory). Surfaced so the
    #: glossary's reversible-password flag can render on the entity (doc 21 add #).
    reversible_password: bool = False


class DossierEdge(BaseModel):
    """An inbound/outbound edge entry in a node dossier (with the other party)."""

    model_config = ConfigDict(extra="forbid")

    edge_id: str
    kind: str
    direction: str
    other: NodeRef
    confidence: str | None = None
    is_inherited: bool | None = None
    access_mask: int | None = None
    object_type_guid: str | None = None
    #: The readable attribute/right name resolved from ``object_type_guid`` via the
    #: public MS ``adschema`` GUID map (e.g. ``"servicePrincipalName"``,
    #: ``"User-Force-Change-Password"``). ``None`` for a whole-object edge (no GUID)
    #: or an unmapped scoped GUID. The raw ``object_type_guid`` stays in the payload
    #: (forensic transparency); this only adds the human-readable name.
    attribute_name: str | None = None


class PresentedAttributeOut(BaseModel):
    """One divergent attribute's read-time presented value + three-state badge (M-MS4b).

    The dossier overlay for a MERGED node (multi-source contract §2.3 / §3.3). ``state``
    is the :class:`~wraith.merge.fold.PresentedState` the gated fold reports:

    * ``no_divergence`` — never emitted here (an attribute with no divergence row has no
      overlay entry); listed in the literal for completeness/forward-compat.
    * ``resolved`` — a tier resolved the presented value (``presented_value`` carries it).
    * ``contested_unresolved`` — diverged but no tier resolved it: the UI MUST badge it
      contested and NOT present it as the benign canonical value (``presented_value`` is
      ``None``; fall back to the canonical column for display, but flagged).

    ``value_by_source`` is the per-source raw staged values (never a secret — attribute
    divergence rows never carry secret material; secret divergence is a separate,
    value-free flag).
    """

    model_config = ConfigDict(extra="forbid")

    attribute: str
    state: Literal["no_divergence", "resolved", "contested_unresolved"]
    presented_value: Any | None = None
    value_by_source: dict[str, Any] = {}


class MergeOverlayOut(BaseModel):
    """The read-time merge overlay attached to a MERGED node's dossier (M-MS4b, §2.3).

    Present ONLY when an opt-in merge has run for the case (else the dossier is
    byte-UNCHANGED and this field is omitted entirely). ``presented_attributes`` lists
    the node's divergent attributes with their three-state badge; ``entity_divergence``
    carries an entity-level verdict (``deleted_on_source`` / ``candidate_lingering_object``)
    when one fired; ``secret_divergence`` flags un-replicated/divergent secret material
    WITHOUT ever surfacing a digest or plaintext (redacted per contract §3.2).
    """

    model_config = ConfigDict(extra="forbid")

    merged: bool = True
    run_id: str
    presented_attributes: list[PresentedAttributeOut] = []
    entity_divergence: str | None = None
    secret_divergence: bool = False
    counted_gaps: dict[str, int] = {}


class DcVsDcReportOut(BaseModel):
    """The "DC-A and DC-B disagreed on X" report (contract §3.4), ledger-driven."""

    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] = []
    counts_by_type: dict[str, int] = {}
    counts_by_resolution: dict[str, int] = {}
    total: int = 0


class MergeReportOut(BaseModel):
    """Result of an opt-in merge-fold run (``POST /cases/{id}/merge``, M-MS4b).

    Mirrors :class:`~wraith.merge.fold.MergeResult` (counts only — NEVER a secret or a
    digest) plus the :class:`DcVsDcReportOut`. ``nothing_to_merge`` is the honest
    ``<2``-sources state (surfaced, not an error). ``counted_gaps`` surfaces every
    degraded branch, including the API-trigger's un-armed inputs (tier-1 ATTID map /
    secret fingerprints not computed) so the run never silently over-claims.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str
    run_id: str
    source_ids: list[str]
    nothing_to_merge: bool = False
    nodes_reconciled: int = 0
    edges_reconciled: int = 0
    deleted_on_source: int = 0
    candidate_lingering_objects: int = 0
    edge_membership_divergences: int = 0
    attribute_divergences: int = 0
    secret_divergences: int = 0
    attribute_unresolved: int = 0
    tier1_unavailable: int = 0
    staging_attrs_unparseable: int = 0
    repl_blob_unparseable: int = 0
    gc_sources_in_selection: int = 0
    report: DcVsDcReportOut
    counted_gaps: dict[str, int] = {}


class DivergenceRowOut(BaseModel):
    """One ``divergence`` ledger row (the DC-vs-DC drill-down, M-MS4a/§2.2d).

    ``value_by_source`` is the per-source JSON map. For a ``secret_divergence`` row it
    is ``{source: {present, differs}}`` ONLY — never a digest or plaintext (redacted at
    write time by the fold; this read never re-materializes a secret). ``resolved_value``
    is the presented overlay value for a resolved attribute, else ``None``.
    """

    model_config = ConfigDict(extra="forbid")

    obj_kind: str
    obj_id: str
    attribute: str | None = None
    divergence_type: str
    resolution: str | None = None
    resolved_by: str | None = None
    value_by_source: dict[str, Any] = {}
    resolved_value: Any | None = None


class DivergenceLedgerOut(BaseModel):
    """The divergence ledger read for a case/merge run (``GET /divergence``, M-MS4b).

    ``merged`` is ``False`` (with a counted ``merge.no_merge_run`` gap) when no merge
    has run for the case — an honest empty ledger, never a silent blank. Secrets never
    appear (see :class:`DivergenceRowOut`).
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str
    run_id: str
    merged: bool
    rows: list[DivergenceRowOut] = []
    report: DcVsDcReportOut
    counted_gaps: dict[str, int] = {}


class MergeRequest(BaseModel):
    """Request body for the opt-in merge trigger (``POST /cases/{id}/merge``).

    ``source_ids`` is the operator-selected set of sources to reconcile. Untrusted: the
    trigger validates every id belongs to the case before any fold runs.
    """

    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] = Field(default_factory=list)


class CaNodeFindingOut(BaseModel):
    """One CA-host NODE-LEVEL finding surfaced on a dossier (ESC11/ESC16/DCOM).

    The read-time projection of a persisted
    :class:`~wraith.analysis.adcs_esc.CaNodeFinding`. ESC11/ESC16 appear on the
    EnterpriseCA node; the DCOM summary on the CA host Computer node. Each finding
    is self-describing — ``title`` + ``caption`` state what it means and that it
    needed the CA host hive — and carries its own hive :class:`ProvenanceOut` so the
    forensic chain is intact. NO secret material is ever carried: ``value`` is the
    non-secret decided value (``"true"`` for ESC11/ESC16; the ``EnableDCOM=Y/N``
    summary for DCOM — never a raw security descriptor).
    """

    model_config = ConfigDict(extra="forbid")

    #: The property name: ``esc11_no_encrypt_enforcement`` /
    #: ``esc16_sid_ext_disabled`` / ``dcom_restrictions``.
    prop: str
    #: Short human title for the finding (static, authored per ``prop``).
    title: str
    #: Honest caption: what it means AND that it was decided from the CA host hive.
    caption: str
    #: The NON-SECRET decided value as stored (``"true"`` for ESC11/ESC16; the
    #: ``EnableDCOM=Y/N`` summary for DCOM). Never a security-descriptor byte.
    value: str
    provenance: ProvenanceOut


class NodeDossier(BaseModel):
    """Full per-entity detail: identity, flags, edges, memberships, secrets, risk."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    object_sid: str | None = None
    object_guid: str | None = None
    samaccountname: str | None = None
    upn: str | None = None
    distinguished_name: str | None = None
    display_name: str | None = None
    description: str | None = None
    domain_id: str | None = None
    domain_fqdn: str | None = None
    admincount: int | None = None
    primary_group_id: int | None = None
    spns: list[str] = []
    sid_history: list[str] = []
    pwd_last_set: datetime | None = None
    last_logon_timestamp: datetime | None = None
    when_created: datetime | None = None
    when_changed: datetime | None = None
    uac: UacFlagsOut | None = None
    node_flags: dict[str, bool] = {}
    inbound_edges: list[DossierEdge]
    outbound_edges: list[DossierEdge]
    inbound_edge_counts: dict[str, int] = {}
    outbound_edge_counts: dict[str, int] = {}
    group_memberships: list[NodeRef] = []
    #: The effective members of this node (doc 21 §3). Populated ONLY when
    #: ``kind == "Group"`` (``[]`` for every other kind); sorted Tier-0 first, then
    #: ``risk_score`` descending, then ``label``. Complementary to
    #: ``group_memberships`` (the groups this node is a member OF).
    group_members: list[GroupMemberRef] = []
    #: The deterministic, composed executive-summary sentences (doc 21 §2), in fixed
    #: order [identity/role][posture][exposure][flags]. A sentence is dropped when
    #: its governing data is absent — no filler. Pure template composition over this
    #: dossier's own fields + the static glossary; no runtime free-text.
    exec_summary: list[str] = []
    secret_refs: list[SecretRefOut] = []
    #: CA-host NODE-LEVEL findings (ESC11/ESC16 on an EnterpriseCA node; the DCOM
    #: summary on a CA host Computer node). Populated ONLY for a node that has a
    #: persisted ``ca_node_finding`` row; ``[]`` for every other node. The
    #: serializer below DROPS the key entirely when empty, so a non-CA dossier is
    #: byte-UNCHANGED from the pre-surfacing output (zero regression).
    ca_node_findings: list[CaNodeFindingOut] = []
    behavior_summary_ref: str | None = None
    risk: NodeRisk | None = None
    provenance: ProvenanceOut
    #: Named counts of any degraded branch encountered while assembling THIS
    #: dossier (research 11 Fix B). Today the only key is
    #: ``dossier.unresolved_edge_endpoint`` — an inbound/outbound edge endpoint id
    #: that resolved to no node even after the ``Base`` projection (a genuinely
    #: dangling id). Empty for an ordinary dossier — the "counted gap on every
    #: degraded branch" rule. Never a bare hash shown as a label.
    counted_gaps: dict[str, int] = {}
    #: The read-time multi-source merge overlay (M-MS4b, contract §2.3). Present ONLY
    #: when an opt-in merge has run for the case AND this is the folded (unscoped) view;
    #: ``None`` on the single-source / non-merged / per-source path. The conditional
    #: serializer below OMITS the key entirely when ``None`` so the non-merged dossier is
    #: BYTE-UNCHANGED from the pre-M-MS5a output (zero regression, proven in tests).
    merge: MergeOverlayOut | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Serialize normally, but DROP optional keys that do not apply to this node.

        Keeps a dossier byte-identical to its pre-feature serialization when the
        feature is absent:

        * ``merge`` is dropped when no merge overlay applies (pre-M-MS5a parity).
        * ``ca_node_findings`` is dropped when empty, so a non-CA node is
          byte-UNCHANGED from the pre-CA-host-surfacing output (zero regression). A
          node that DOES carry ESC11/ESC16/DCOM findings keeps the populated list.
        """
        data: dict[str, Any] = handler(self)
        if self.merge is None:
            data.pop("merge", None)
        if not self.ca_node_findings:
            data.pop("ca_node_findings", None)
        return data


class NodeListEntry(BaseModel):
    """One row of the bounded browse-by-type node list (M7 phase-2 #3).

    ``tier``/``highvalue`` come from the Tier-0 classification set — the SAME source
    as ``/graph/slice`` (``tier0_sets().classified_ids``). ``risk_score`` is the
    transparent score from the shared risk map (``_compute_scored``); it is ``None``
    for non-principal kinds (OU/Container/GPO/ADCS), which the risk model does not
    score. No secret fields are ever exposed here.
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    label: str
    object_sid: str | None = None
    tier: int | None = None
    risk_score: int | None = None
    highvalue: bool = False


class NodeListPage(BaseModel):
    """A bounded page of the browse-by-type node list (``GET /nodes``).

    ``total_matched`` is the full count under the ``kind``/``q`` filter BEFORE
    paging; ``returned`` is this page's size; ``truncated`` is ``True`` when more
    rows exist beyond ``offset + returned`` (the honest "X of Y shown" rule).
    """

    model_config = ConfigDict(extra="forbid")

    entries: list[NodeListEntry]
    total_matched: int
    returned: int
    offset: int
    limit: int
    truncated: bool
    #: Counted gaps for a degraded per-source scope (e.g. an unknown/empty
    #: ``source_id`` -> honest empty page + ``source.unknown_or_empty``). Empty on the
    #: unscoped page — the "counted gap on every degraded branch" rule (M-MS2).
    counted_gaps: dict[str, int] = {}


class SearchResult(BaseModel):
    """A capped, deterministic search result set."""

    model_config = ConfigDict(extra="forbid")

    query: str
    hits: list[NodeRef]
    count: int
    truncated: bool


class SliceRequest(BaseModel):
    """Request body for ``POST /api/v1/graph/slice`` (server-side slicing).

    A reserved ``time_window`` placeholder is accepted (and ignored) now so an
    event-windowed graph view is purely additive when baselining lands.
    """

    model_config = ConfigDict(extra="forbid")

    seed_node_ids: list[str] | None = None
    search: str | None = None
    node_kinds: list[str] | None = None
    edge_kinds: list[str] | None = None
    tier0_only: bool = False
    depth: int = 1
    limit: int = 1000
    layout: str = "auto"
    time_window: dict[str, str] | None = None  # reserved for baselining; ignored in v1


class PathRequest(BaseModel):
    """Request body for ``POST /api/v1/paths`` (networkx attacker pathfinding)."""

    model_config = ConfigDict(extra="forbid")

    source_node_ids: list[str] | None = None
    source_sid: str | None = None
    target: str | None = "tier0"
    target_node_ids: list[str] | None = None
    #: Bounded so a crafted request cannot force unbounded enumeration (hang/OOM).
    max_hops: int = Field(default=8, ge=1, le=MAX_PATH_HOPS)
    max_paths: int = Field(default=25, ge=1, le=MAX_PATH_RESULTS)
    all_simple: bool = False
    #: Traversal direction (design §8/§13, additive). ``"outbound"`` (default) keeps
    #: the existing byte-identical behavior: ``find_paths`` from ``source_node_ids``
    #: to ``target``. ``"inbound"`` routes to ``find_paths_to`` — the request's
    #: ``target``/``target_node_ids`` is the SINK and ``source_node_ids`` (if given)
    #: is the source filter (``None`` = every source that can reach the sink).
    direction: Literal["outbound", "inbound"] = "outbound"


class PrebuiltQuery(BaseModel):
    """One frozen attack-query catalog entry (design §3.1 / §3.2).

    Pure metadata plus a ``source_count`` that the ``GET /analysis/queries``
    endpoint fills live from the SAME risk predicates the Risk dashboard uses (one
    source of truth). Out-of-scope entries (§3.2) carry ``supported=False`` + an
    honest ``reason`` and are listed, never hidden.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    description: str
    #: Hunter grouping for the Analysis panel (doc 20 §5). One of the eight fixed
    #: categories: ``"Privileged Access"``, ``"Dangerous ACLs"``, ``"Shadow Admins"``,
    #: ``"Credential Exposure"``, ``"Delegation"``, ``"Stale/Risk"``, ``"Topology"``,
    #: ``"ADCS"``. A plain ``str`` (not an enum) so adding a category later is purely
    #: additive for the UI, which groups by this value.
    category: str
    kind: Literal["path", "set"]
    #: ``"to-target"`` (global reverse BFS to a sink), ``"source-to-target"``
    #: (a source set to Tier-0), or ``"set"`` (a node collection, no traversal).
    direction: Literal["to-target", "source-to-target", "set"]
    supported: bool
    reason: str | None = None
    #: ``"real"`` (backed by real c137 data), ``"synthetic-only"`` (Tier C/D edges
    #: tested only on synthetic fixtures), or ``"none"`` (not wired in v1).
    data_confidence: Literal["real", "synthetic-only", "none"] = "real"
    #: Live source-set size (``None`` for unsupported queries we cannot resolve).
    source_count: int | None = None


class PrebuiltQueryRunRequest(BaseModel):
    """Optional body for ``POST /analysis/queries/{id}/run`` (design §8).

    Both fields are bounded by the SAME ``Field`` ceilings as :class:`PathRequest`
    so a crafted request cannot force unbounded work. (No ``all_simple``: §3.1 routes
    every ``path`` query through the single bounded ``find_paths_to`` reverse BFS,
    which has no simple-path enumeration — the field would be an accepted no-op.)
    """

    model_config = ConfigDict(extra="forbid")

    max_hops: int = Field(default=8, ge=1, le=MAX_PATH_HOPS)
    max_paths: int = Field(default=25, ge=1, le=MAX_PATH_RESULTS)


class PrebuiltQueryResult(BaseModel):
    """The result of running one catalog query (design §6).

    Exactly one of ``paths`` (a ``kind == "path"`` query) or ``slice`` (a
    ``kind == "set"`` query) is populated; the other is ``None``. ``counted_gaps``
    surfaces every degraded/absent branch (empty source set, Domain Users group
    absent / empty effective membership, empty target set) as a named count — never
    a silent empty result.
    """

    model_config = ConfigDict(extra="forbid")

    query_id: str
    kind: Literal["path", "set"]
    paths: PathResult | None = None
    slice: GraphSlice | None = None
    counted_gaps: dict[str, int] = {}
    #: The source query's confidence badge, carried onto the RUN output so a UI that
    #: runs a query (not just lists the catalog) can keep showing the honesty badge.
    #: ``"synthetic-only"`` for the AD CS queries (Tier C/D, untested on real data).
    data_confidence: Literal["real", "synthetic-only", "none"] = "real"


class ConnectorRequest(BaseModel):
    """Request body for ``POST /api/v1/graph/connector`` (connect-the-dots).

    Given the node ids retained in the current canvas slice that share NO direct
    edge (the ``noEdges`` state, e.g. a User+GPO filter), compute the minimal
    labelled connecting chains through hidden intermediate objects. All three
    bounds (and ``node_ids`` length) are ``Field``-capped so a crafted request cannot
    force unbounded work.
    """

    model_config = ConfigDict(extra="forbid")

    #: The retained slice node ids to connect (deduplicated + validated server-side).
    #: Length-bounded so a crafted body cannot force unbounded membership work.
    node_ids: list[str] = Field(..., max_length=2000)
    #: Maximum connecting-chain length (hop count); clamped by the engine too.
    max_hops: int = Field(default=6, ge=1, le=MAX_PATH_HOPS)
    #: Maximum connecting chains returned (control lane first, then scope).
    max_paths: int = Field(default=12, ge=1, le=MAX_PATH_RESULTS)
    #: Representative-node cap: at most this many retained nodes seed the pairwise
    #: search, so the work is bounded even for a large filtered set (counted gap
    #: ``representatives_capped`` when it bites).
    max_pairs: int = Field(default=12, ge=2, le=50)


class ConnectorPath(BaseModel):
    """One minimal connecting chain between two retained nodes (connect-the-dots).

    Two lanes are never conflated (doc 09 §0): a ``"control"`` chain is a real
    attacker capability (``principal -> object``); a ``"scope"`` chain is a GPO
    application path (``GPO -> container -> principal``) that is only *potential*
    offline and therefore carries an RSoP ``caveat``. ``confidence`` is the weakest
    hop's confidence (an inferred hop taints the whole chain, doc 09 §3.2).
    """

    model_config = ConfigDict(extra="forbid")

    lane: Literal["control", "scope"]
    nodes: list[NodeRef]
    edges: list[PathEdge]
    length: int
    #: The weakest hop's confidence (``"confirmed"`` | ``"inferred"`` | ``"unknown"``).
    confidence: str
    source_node_id: str
    target_node_id: str
    #: Set on every ``scope`` lane chain (the mandatory RSoP caveat); ``None`` on
    #: ``control`` chains.
    caveat: str | None = None


class ConnectorResult(BaseModel):
    """The connect-the-dots result: two ranked lanes + the honest gap ledger.

    Chains are ordered control-lane-first (real capability), then scope-lane
    (potential application). ``via_node_ids`` are the intermediate directory objects
    ADDED to connect the retained set — NOT filter matches — surfaced so the canvas
    can state "+N intermediate nodes shown to connect" (honesty rule). An empty
    ``paths`` with ``note`` set means no attack-relevant and no scope chain exists
    (stated explicitly, never a silent blank canvas).
    """

    model_config = ConfigDict(extra="forbid")

    paths: list[ConnectorPath]
    control_count: int
    scope_count: int
    retained_node_ids: list[str]
    via_node_ids: list[str]
    truncated: bool
    max_hops: int
    #: Feature-level caveats shown once (DENY-ACE over-statement; RSoP for scope).
    caveats: list[str] = []
    #: Named counts of every degraded/suppressed branch (``rsop_not_resolvable``,
    #: ``structural_only_suppressed``, ``representatives_capped``,
    #: ``hop_confidence_unknown``, ``no_connection``) — never a silent wrong answer.
    counted_gaps: dict[str, int] = {}
    #: Set only when ``paths`` is empty: the explicit "no connection found" message.
    note: str | None = None


class CaseSummary(BaseModel):
    """Landing-dashboard counts + the case/domain context."""

    model_config = ConfigDict(extra="forbid")

    domain_id: str | None = None
    domain_fqdn: str | None = None
    functional_level: int | None = None
    node_count: int
    edge_count: int
    node_kind_counts: dict[str, int]
    edge_kind_counts: dict[str, int]
    tier0_node_count: int
    dcsync_holder_count: int
    #: Counted gaps for a degraded per-source scope (M-MS2); empty when unscoped.
    counted_gaps: dict[str, int] = {}


class SourceInfo(BaseModel):
    """One ingested DC artifact set in a case (multi-source contract §2.2a, M-MS2).

    The row an operator/UI reads to DISCOVER + address a source. ``source_id`` is the
    machine key (used by the ``?source_id=`` per-source read filter); ``dc_label`` is
    the human display key. ``domain_id``/``domain_fqdn`` are the DERIVED (authoritative)
    domain facts; ``declared_domain`` is the operator label (display only).
    ``node_count``/``edge_count`` are the objects this source observed.
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str
    dc_label: str
    domain_id: str | None = None
    domain_fqdn: str | None = None
    forest_id: str
    declared_domain: str | None = None
    is_global_catalog: bool | None = None
    node_count: int
    edge_count: int


class SourceList(BaseModel):
    """The per-case source listing (``GET /sources``), deterministically ordered."""

    model_config = ConfigDict(extra="forbid")

    sources: list[SourceInfo]
    count: int


class SourceCoverageArtifact(BaseModel):
    """One artifact's coverage/skip tally within a source's coverage (M-MS2)."""

    model_config = ConfigDict(extra="forbid")

    source_file: str | None = None
    image_sha256: str | None = None
    coverage_counts: dict[str, int] = {}
    skip_counts: dict[str, int] = {}


class SourceCoverage(BaseModel):
    """Per-source coverage/skip counts (contract §5 item 3, M-MS2).

    Aggregated from the provenance ledger rows whose ``image_sha256`` matches one of
    the source's artifact SHA-256s (``ntds``/``system``). ``counted_gaps`` surfaces any
    degraded branch — an unknown source, or a source SHA with no matching ledger row —
    so a thin/absent coverage is never a silent empty.
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str
    dc_label: str | None = None
    artifacts: list[SourceCoverageArtifact] = []
    coverage_counts: dict[str, int] = {}
    skip_counts: dict[str, int] = {}
    counted_gaps: dict[str, int] = {}


class CaseListEntry(BaseModel):
    """One entry in the top-bar case list (the single store-backed case in v1)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    domain_id: str | None = None
    domain_fqdn: str | None = None
    node_count: int
    edge_count: int


class GlossaryEntryOut(BaseModel):
    """One plain-language, forensically-true glossary entry (doc 21 §4).

    Three columns authored by the domain-expert: ``grants`` (what the right/flag
    actually confers), ``why`` (why a hunter cares / the abuse), and ``action`` (the
    one-liner caption used verbatim per-entry). No overclaiming — where a right does
    NOT grant something, the text says so.
    """

    model_config = ConfigDict(extra="forbid")

    grants: str
    why: str
    action: str


class GlossaryOut(BaseModel):
    """The static rights/attributes glossary (``GET /api/v1/glossary``, doc 21 §4).

    Read-only, NOT case-scoped (pure static reference the frontend fetches once to
    annotate dossier entries by kind). ``edges`` keys are WRAITH edge kinds;
    ``flags`` keys are node-flag / UAC-flag / attribute-signal codes.
    ``counted_gaps`` reports any edge kind the engine can emit that lacks a glossary
    entry (the "counted gap on every degraded branch" rule) — normally empty.
    """

    model_config = ConfigDict(extra="forbid")

    edges: dict[str, GlossaryEntryOut]
    flags: dict[str, GlossaryEntryOut]
    counted_gaps: dict[str, int] = {}
