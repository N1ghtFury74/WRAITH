"""The Edge Engine orchestrator — the full Module 5 edge pass (5A + 5B).

Writes the attacker-direction §4 ``edge`` graph from Module 3's staged data:

* **Slice 5A (SD/ACE core):** streams ``staging_object``, parses each object's
  security descriptor (:mod:`wraith.edges.acl`), and emits whole-object + scoped
  object-control edges (the DACL), the ``Owns`` edge (SD owner), and the
  synthesized ``DCSync`` edge (``GetChanges`` + ``GetChangesAll`` on the domain).
* **Slice 5B (non-SD derivations):** constrained delegation, RBCD, ReadGMSAPassword
  (the attribute values are SDs, reusing the same parse seam), HasSIDHistory,
  trust edges (attack direction), and the ADCS base facts
  (:mod:`wraith.edges.derivations`). Node flags (unconstrained / kerberoastable /
  AS-REP) are computed for M6/M7 but stored nowhere (:mod:`wraith.edges.node_flags`).

Both slices share ONE :class:`~wraith.edges.acl.NodeResolver` (mint-on-miss, so a
SID referenced by an ACE and by a trust/sid-history resolves to the same node and
a stub is minted once), ONE edge buffer (dedup by ``edge_id`` + OR-merge of ACL
masks), and ONE deterministic write (stubs sorted by ``node_id``; edges sorted by
``edge_id``). Every malformed SD/ACE/attribute is a counted gap, never a crash.

``compute_edges`` is the combined Module-5 entry point. ``compute_acl_edges`` runs
only slice 5A (used by the 5A checkpoint + unit tests); the two are alternatives,
not chained, on one store.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.edges.acl import (
    NOISE_TRUSTEE_SIDS,
    NodeResolver,
    build_ace_edges,
    build_dcsync_edge,
    build_owner_edge,
    merge_mask,
    parse_sd,
)
from wraith.edges.adcs_topology import AdcsTopologyResult, compute_adcs_topology
from wraith.edges.derivations import (
    ATTR_ALLOWED_TO_ACT,
    ATTR_ALLOWED_TO_DELEGATE_TO,
    ATTR_GROUP_MSA_MEMBERSHIP,
    KIND_HAS_TRUST_KEYS,
    SpnIndex,
    TrustInput,
    build_adcs_enrollment_edges,
    build_coerce_to_tgt_edge,
    build_constrained_delegation_edges,
    build_contains_edge,
    build_gmsa_read_edges,
    build_gplink_edges,
    build_published_to_edges,
    build_rbcd_edges,
    build_sid_history_edges,
    build_spn_index,
    build_trust_edges,
    parent_dn,
)
from wraith.edges.guid_map import (
    GUID_CERTIFICATE_AUTOENROLLMENT,
    GUID_CERTIFICATE_ENROLLMENT,
    KIND_GET_CHANGES,
    KIND_GET_CHANGES_ALL,
    PkiFlagGuids,
    resolve_laps_guids,
    resolve_pki_flag_guids,
)
from wraith.edges.models import EdgeRow
from wraith.edges.node_flags import compute_node_flags, is_coercible_unconstrained
from wraith.model.store import create_edge_tables
from wraith.normalize.models import PrincipalRow
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

# --- coverage + skip counter keys (surfaced on the IngestRun, never silent) ---
_COV_ACE_EDGES = "edges.ace_edges"
_COV_OWNER_EDGES = "edges.owner_edges"
_COV_DCSYNC = "edges.dcsync_synth"
_COV_STUBS = "edges.stubs_minted"
_COV_OBJECTS_NO_SD = "edges.objects_without_sd"
_COV_DELEGATION = "edges.delegation"
_COV_RBCD = "edges.rbcd"
_COV_GMSA = "edges.gmsa_read"
_COV_SIDHISTORY = "edges.sidhistory"
_COV_TRUST = "edges.trust"
_COV_TRUST_KEYS = "edges.trust_keys"
_COV_ADCS = "edges.adcs"
_COV_PUBLISHED = "edges.published_to"
_COV_CONTAINS = "edges.contains"
_COV_GPLINK = "edges.gplink"
_COV_COERCE_TGT = "edges.coerce_to_tgt"
# ADCS topology (Phase 1) coverage keys.
_COV_ADCS_ENTERPRISE_CA_FOR = "edges.enterprise_ca_for"
_COV_ADCS_ROOT_CA_FOR = "edges.root_ca_for"
_COV_ADCS_NTAUTH_STORE_FOR = "edges.ntauth_store_for"
_COV_ADCS_HOSTS_CA_SERVICE = "edges.hosts_ca_service"
_COV_ADCS_TRUSTED_FOR_NTAUTH = "edges.trusted_for_ntauth"
_COV_ADCS_ISSUED_SIGNED_BY = "edges.issued_signed_by"
_COV_ADCS_EXTENDED_BY_POLICY = "edges.extended_by_policy"
_COV_ADCS_OID_GROUP_LINK = "edges.oid_group_link"
_COV_FLAG_UNCONSTRAINED = "nodeflags.unconstrained_delegation"
_COV_FLAG_KERBEROASTABLE = "nodeflags.kerberoastable"
_COV_FLAG_ASREP = "nodeflags.asrep_roastable"
_SKIP_SD_PARSE = "edges.sd_parse_error"
_SKIP_ACE_DECODE = "edges.ace_decode_error"
_SKIP_UNMAPPED_GUID = "edges.unmapped_objecttype"
_SKIP_DENY = "edges.deny_ace_skipped"
_SKIP_INHERIT_ONLY = "edges.inherit_only_skipped"
_SKIP_NOISE_TRUSTEE = "edges.noise_trustee_skipped"
_SKIP_OWNER_NOISE = "edges.owner_noise_skipped"
_SKIP_LAPS_UNRESOLVABLE = "edges.laps_guid_unresolvable"
_SKIP_DCSYNC_NO_DOMAIN = "edges.dcsync_domain_unresolved"
_SKIP_DELEGATION_UNRESOLVED = "edges.delegation_target_unresolved"
_SKIP_RBCD_SD_PARSE = "edges.rbcd_sd_parse_error"
_SKIP_GMSA_SD_PARSE = "edges.gmsa_sd_parse_error"
_SKIP_ADCS_SD_PARSE = "edges.adcs_sd_parse_error"
_SKIP_PKI_FLAG_UNRESOLVABLE = "edges.pki_flag_guid_unresolvable"
_SKIP_TRUST_PARTNER_UNRESOLVED = "edges.trust_partner_unresolved"
_SKIP_PUBLISHED_UNRESOLVED = "edges.published_template_unresolved"
_SKIP_CONTAINS_UNRESOLVED = "edges.contains_parent_unresolved"
# ADCS topology (Phase 1) counted gaps (never silent).
_SKIP_ADCS_HOSTSCA_UNRESOLVED = "adcs.hostscaservice_unresolved"
_SKIP_ADCS_CHAIN_AMBIGUOUS = "adcs.ca_cert_chain_ambiguous"
_SKIP_ADCS_NTAUTH_UNMATCHED = "adcs.ntauth_cert_unmatched"
_SKIP_ADCS_OIDLINK_UNRESOLVED = "adcs.oidgrouplink_sid_unresolved"
_SKIP_ADCS_CERT_PARSE = "adcs.cert_parse_error"

_COVERAGE_KEYS: frozenset[str] = frozenset(
    {
        _COV_ACE_EDGES,
        _COV_OWNER_EDGES,
        _COV_DCSYNC,
        _COV_STUBS,
        _COV_OBJECTS_NO_SD,
        _COV_DELEGATION,
        _COV_RBCD,
        _COV_GMSA,
        _COV_SIDHISTORY,
        _COV_TRUST,
        _COV_TRUST_KEYS,
        _COV_ADCS,
        _COV_PUBLISHED,
        _COV_CONTAINS,
        _COV_GPLINK,
        _COV_COERCE_TGT,
        _COV_ADCS_ENTERPRISE_CA_FOR,
        _COV_ADCS_ROOT_CA_FOR,
        _COV_ADCS_NTAUTH_STORE_FOR,
        _COV_ADCS_HOSTS_CA_SERVICE,
        _COV_ADCS_TRUSTED_FOR_NTAUTH,
        _COV_ADCS_ISSUED_SIGNED_BY,
        _COV_ADCS_EXTENDED_BY_POLICY,
        _COV_ADCS_OID_GROUP_LINK,
        _COV_FLAG_UNCONSTRAINED,
        _COV_FLAG_KERBEROASTABLE,
        _COV_FLAG_ASREP,
    }
)


# =============================================================================
# Shared harness: the edge buffer + the deterministic writers
# =============================================================================


@dataclass
class _EdgeBuffer:
    """Dedup buffer keyed by ``edge_id`` (the determinism harness for both slices)."""

    by_id: dict[str, EdgeRow] = field(default_factory=dict)

    def add_acl(self, edge: EdgeRow) -> None:
        """Add an ACL edge; on ``edge_id`` collision keep first + OR the masks."""
        existing = self.by_id.get(edge.edge_id)
        self.by_id[edge.edge_id] = edge if existing is None else merge_mask(existing, edge)

    def add(self, edge: EdgeRow) -> None:
        """Add a non-ACL (NULL-mask) edge; first writer wins on collision."""
        self.by_id.setdefault(edge.edge_id, edge)

    def ordered(self) -> list[EdgeRow]:
        """Return the buffered edges sorted by ``edge_id`` (byte-reproducible)."""
        return sorted(self.by_id.values(), key=lambda e: e.edge_id)


def _load_resolver(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> NodeResolver:
    """Build the mint-on-miss resolver seeded from the ``principal`` table."""
    sid_to_node: dict[str, str] = {}
    all_nodes: set[str] = set()
    rows = con.execute("SELECT node_id, object_sid FROM principal ORDER BY node_id").fetchall()
    for node_id, object_sid in rows:
        all_nodes.add(node_id)
        if object_sid is not None:
            sid_to_node.setdefault(object_sid, node_id)
    return NodeResolver(
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        sid_to_node=sid_to_node,
        all_nodes=all_nodes,
        ingest_run_id=run.ingest_run_id,
    )


def _resolve_domain_node(con: duckdb.DuckDBPyConnection, domain_id: str | None) -> str | None:
    """Return the Domain object's node id (DCSync + trust local endpoint), or ``None``."""
    if domain_id is not None:
        row = con.execute(
            "SELECT node_id FROM container WHERE container_type = 'Domain' "
            "AND object_sid = ? ORDER BY node_id LIMIT 1",
            [domain_id],
        ).fetchone()
        if row is not None:
            return str(row[0])
    row = con.execute(
        "SELECT node_id FROM container WHERE container_type = 'Domain' ORDER BY node_id LIMIT 1"
    ).fetchone()
    return str(row[0]) if row is not None else None


def _write_stubs(con: duckdb.DuckDBPyConnection, stubs: Mapping[str, PrincipalRow]) -> None:
    """Insert minted stub Principals sorted by ``node_id`` (deterministic)."""
    if not stubs:
        return
    ordered = [stubs[node_id].to_db_values() for node_id in sorted(stubs)]
    placeholders = ",".join("?" * len(ordered[0]))
    sql = f"INSERT INTO principal VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, ordered)


def _write_edges(con: duckdb.DuckDBPyConnection, edges: Sequence[EdgeRow]) -> None:
    """Insert edges in ``edge_id`` order (deterministic)."""
    if not edges:
        return
    placeholders = ",".join("?" * len(edges[0].to_db_values()))
    sql = f"INSERT INTO edge VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, [e.to_db_values() for e in edges])


def _bump(run: IngestRun, key: str, count: int) -> None:
    """Bump a coverage/skip counter only when non-zero (keeps the snapshot clean)."""
    if count <= 0:
        return
    if key in _COVERAGE_KEYS:
        run.bump_coverage(key, count)
    else:
        run.bump_skip(key, count)


# =============================================================================
# Slice 5A core (shared by compute_acl_edges and compute_edges)
# =============================================================================


@dataclass(frozen=True)
class _AclCounts:
    """Per-pass 5A counters (no I/O; the caller bumps the run + writes)."""

    ace_edges: int
    owner_edges: int
    dcsync_edges: int
    sd_parse_errors: int
    ace_decode_errors: int
    deny: int
    inherit_only: int
    noise: int
    owner_noise: int
    unmapped: int
    objects_no_sd: int


#: Rows pulled per ``fetchmany`` batch while streaming ``staging_object`` — bounds
#: the resident set so we never hold all SD BLOBs + all attribute JSON at once
#: (M-2). The edge BUFFER is still fully resident until the final sort — a v1
#: scale known-gap documented in docs/modules/05-edge-engine.md (full in-DB sort
#: is the large-forest increment).
_FETCH_BATCH: int = 2000

#: The staging columns streamed by each pass. The combined pass also pulls the
#: attributes JSON (for the 5B delegation/RBCD/gMSA derivations) so there is ONE
#: pass over ``staging_object`` for the whole SD + attribute surface.
_SD_COLUMNS: str = "node_id, object_sid, raw_sd, provenance"
_SD_ATTR_COLUMNS: str = "node_id, object_sid, raw_sd, attributes, provenance"

#: An attribute handler invoked once per streamed object with a readable SD or
#: attributes: ``(node_id, attributes_json, object_provenance) -> None``.
_AttrHandler = Callable[[str, str, ProvenanceStruct], None]


def _compute_acl_into(
    con: duckdb.DuckDBPyConnection,
    resolver: NodeResolver,
    buffer: _EdgeBuffer,
    laps_guids: frozenset[str],
    domain_node_id: str | None,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
    handled_elsewhere: frozenset[str] = frozenset(),
    attr_handler: _AttrHandler | None = None,
) -> _AclCounts:
    """Run the slice-5A SD/ACE pass into the shared buffer (no write).

    Streams ``staging_object`` once via ``fetchmany`` (never materializing all SDs
    at once). When ``attr_handler`` is given (the combined pass), the SAME streamed
    row's attributes JSON is handed to it so the 5B delegation/RBCD/gMSA builders
    share this single pass. ``is_domain_target`` enables the all-extended-rights ->
    replication expansion on the Domain head (DE ISSUE-2); ``handled_elsewhere``
    keeps the ``unmapped_objecttype`` counter honest on the ADCS surface (M-1).
    """
    ace_count = owner_count = 0
    sd_parse_errors = ace_decode_errors = deny = inherit_only = 0
    noise = owner_noise = unmapped = objects_no_sd = 0

    columns = _SD_ATTR_COLUMNS if attr_handler is not None else _SD_COLUMNS
    cursor = con.execute(f"SELECT {columns} FROM staging_object ORDER BY node_id")  # noqa: S608
    while True:
        rows = cursor.fetchmany(_FETCH_BATCH)
        if not rows:
            break
        for row in rows:
            if attr_handler is not None:
                node_id, object_sid, raw_sd, attributes_json, provenance = row
            else:
                node_id, object_sid, raw_sd, provenance = row
                attributes_json = None
            obj_prov: ProvenanceStruct | None = None

            if not raw_sd:
                objects_no_sd += 1
            else:
                parsed = parse_sd(bytes(raw_sd))
                if parsed is None:
                    sd_parse_errors += 1
                else:
                    deny += parsed.deny_skipped
                    inherit_only += parsed.inherit_only_skipped
                    ace_decode_errors += parsed.ace_errors
                    obj_prov = ProvenanceStruct.model_validate(provenance)
                    if parsed.owner_sid is not None:
                        owner_edge = build_owner_edge(
                            parsed.owner_sid,
                            node_id,
                            object_sid,
                            resolver,
                            obj_prov,
                            forest_id,
                            domain_id,
                            domain_fqdn,
                        )
                        if owner_edge is None:
                            owner_noise += 1
                        else:
                            buffer.add_acl(owner_edge)
                            owner_count += 1
                    ace_edges, gaps = build_ace_edges(
                        parsed.aces,
                        node_id,
                        object_sid,
                        laps_guids,
                        resolver,
                        obj_prov,
                        forest_id,
                        domain_id,
                        domain_fqdn,
                        is_domain_target=(node_id == domain_node_id),
                        handled_elsewhere=handled_elsewhere,
                    )
                    noise += gaps.noise_trustee_skipped
                    unmapped += gaps.unmapped_objecttype
                    for edge in ace_edges:
                        buffer.add_acl(edge)
                        ace_count += 1

            if attr_handler is not None and attributes_json:
                if obj_prov is None:
                    obj_prov = ProvenanceStruct.model_validate(provenance)
                attr_handler(node_id, attributes_json, obj_prov)

    dcsync = 0
    if domain_node_id is not None:
        for edge in _synthesize_dcsync(buffer, domain_node_id, forest_id, domain_id, domain_fqdn):
            buffer.add(edge)
            dcsync += 1

    return _AclCounts(
        ace_edges=ace_count,
        owner_edges=owner_count,
        dcsync_edges=dcsync,
        sd_parse_errors=sd_parse_errors,
        ace_decode_errors=ace_decode_errors,
        deny=deny,
        inherit_only=inherit_only,
        noise=noise,
        owner_noise=owner_noise,
        unmapped=unmapped,
        objects_no_sd=objects_no_sd,
    )


def _synthesize_dcsync(
    buffer: _EdgeBuffer,
    domain_node_id: str,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> list[EdgeRow]:
    """Synthesize ``DCSync`` from ``GetChanges`` + ``GetChangesAll`` on the domain."""
    get_changes: set[str] = set()
    get_changes_all: dict[str, ProvenanceStruct] = {}
    for edge in buffer.by_id.values():
        if edge.target_node_id != domain_node_id:
            continue
        if edge.kind == KIND_GET_CHANGES:
            get_changes.add(edge.source_node_id)
        elif edge.kind == KIND_GET_CHANGES_ALL:
            get_changes_all[edge.source_node_id] = edge.provenance
    return [
        build_dcsync_edge(
            src, domain_node_id, get_changes_all[src], forest_id, domain_id, domain_fqdn
        )
        for src in sorted(get_changes & set(get_changes_all))
    ]


@dataclass(frozen=True)
class AclEdgeResult:
    """The outcome of the slice-5A-only ACL edge pass (counts only — never secrets)."""

    ace_edges: int
    owner_edges: int
    dcsync_edges: int
    stubs_minted: int
    edges_total: int
    laps_guids: frozenset[str]
    laps_unresolvable: int
    domain_node_id: str | None
    coverage_counts: Mapping[str, int]
    skip_counts: Mapping[str, int]


def _bump_acl(run: IngestRun, counts: _AclCounts, stubs: int) -> None:
    """Surface the 5A counters on the run."""
    _bump(run, _COV_ACE_EDGES, counts.ace_edges)
    _bump(run, _COV_OWNER_EDGES, counts.owner_edges)
    _bump(run, _COV_DCSYNC, counts.dcsync_edges)
    _bump(run, _COV_STUBS, stubs)
    _bump(run, _COV_OBJECTS_NO_SD, counts.objects_no_sd)
    _bump(run, _SKIP_SD_PARSE, counts.sd_parse_errors)
    _bump(run, _SKIP_ACE_DECODE, counts.ace_decode_errors)
    _bump(run, _SKIP_UNMAPPED_GUID, counts.unmapped)
    _bump(run, _SKIP_DENY, counts.deny)
    _bump(run, _SKIP_INHERIT_ONLY, counts.inherit_only)
    _bump(run, _SKIP_NOISE_TRUSTEE, counts.noise)
    _bump(run, _SKIP_OWNER_NOISE, counts.owner_noise)


def compute_acl_edges(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    schema: NtdsSchema,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> AclEdgeResult:
    """Compute and write ONLY the slice-5A ACL / Owner / DCSync §4 edges.

    Reads Module 3's ``staging_object`` + ``principal`` + ``container`` tables and
    writes the ACL-derived edges (deduped by ``edge_id``, sorted) plus minted stub
    Principals. Use :func:`compute_edges` for the full Module-5 pass (5A + 5B).

    Inputs:
        con: an open canonical-store connection holding the gated M3 (+ M4) tables.
        run: the :class:`IngestRun` providing counters + the ``ingest_run_id``.
        schema: the gated 2a :class:`NtdsSchema` (for LAPS ``schemaIDGUID``s).
        forest_id/domain_id/domain_fqdn: the scoping block (M3's identity).

    Returns:
        An :class:`AclEdgeResult`.

    Failure modes:
        ``duckdb.Error`` on a store failure / ``edge`` PK clash from re-running on
        a populated store. Malformed per-SD/per-ACE data degrades to counted gaps.
    """
    create_edge_tables(con)
    resolver = _load_resolver(
        con, run, forest_id=forest_id, domain_id=domain_id, domain_fqdn=domain_fqdn
    )
    laps_guids, laps_unresolvable = resolve_laps_guids(schema)
    _bump(run, _SKIP_LAPS_UNRESOLVABLE, laps_unresolvable)
    pki_flag_guids, _pki_unresolvable = resolve_pki_flag_guids(schema)
    handled = _handled_elsewhere_guids(pki_flag_guids)
    domain_node_id = _resolve_domain_node(con, domain_id)

    buffer = _EdgeBuffer()
    counts = _compute_acl_into(
        con,
        resolver,
        buffer,
        laps_guids,
        domain_node_id,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        handled_elsewhere=handled,
    )
    if domain_node_id is None:
        _bump(run, _SKIP_DCSYNC_NO_DOMAIN, 1)

    ordered = buffer.ordered()
    _write_stubs(con, resolver.minted)
    _write_edges(con, ordered)
    _bump_acl(run, counts, len(resolver.minted))

    return AclEdgeResult(
        ace_edges=counts.ace_edges,
        owner_edges=counts.owner_edges,
        dcsync_edges=counts.dcsync_edges,
        stubs_minted=len(resolver.minted),
        edges_total=len(ordered),
        laps_guids=laps_guids,
        laps_unresolvable=laps_unresolvable,
        domain_node_id=domain_node_id,
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )


# =============================================================================
# Slice 5B derivations
# =============================================================================


@dataclass(frozen=True)
class _DerivationCounts:
    """Per-pass 5B counters."""

    delegation: int
    rbcd: int
    gmsa: int
    sidhistory: int
    trust: int
    trust_keys: int
    adcs: int
    published_to: int
    contains: int
    gplink: int
    coerce_to_tgt: int  # noqa: S105 - counter name, not a secret
    delegation_unresolved: int
    rbcd_sd_errors: int
    gmsa_sd_errors: int
    adcs_sd_errors: int
    trust_partner_unresolved: int
    published_unresolved: int
    contains_parent_unresolved: int
    adcs_topology: AdcsTopologyResult


@dataclass(frozen=True)
class NodeFlagCounts:
    """Node-flag tallies (facts, not edges; stored nowhere — M6/M7 consume)."""

    unconstrained_delegation: int
    kerberoastable: int
    asrep_roastable: int


def _attr_bytes(value: object) -> bytes | None:
    """Decode a staging-JSON attribute value to raw bytes (the ``__bytes_hex__`` tag)."""
    if isinstance(value, dict) and "__bytes_hex__" in value:
        raw = value["__bytes_hex__"]
        return bytes.fromhex(raw) if isinstance(raw, str) else None
    if isinstance(value, list):
        for item in value:
            decoded = _attr_bytes(item)
            if decoded is not None:
                return decoded
    return None


def _attr_str_list(value: object) -> list[str]:
    """Decode a staging-JSON attribute value to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _ci_lookup(attrs: Mapping[str, object], name: str) -> object:
    """Case-insensitive attribute lookup in a staging attributes dict."""
    target = name.lower()
    for key, value in attrs.items():
        if key.lower() == target:
            return value
    return None


def _handled_elsewhere_guids(pki_flag_guids: PkiFlagGuids) -> frozenset[str]:
    """The scoped GUIDs the 5B ADCS pass maps (so 5A must not flag them unmapped)."""
    guids = {GUID_CERTIFICATE_ENROLLMENT, GUID_CERTIFICATE_AUTOENROLLMENT}
    if pki_flag_guids.enrollment_flag is not None:
        guids.add(pki_flag_guids.enrollment_flag)
    if pki_flag_guids.name_flag is not None:
        guids.add(pki_flag_guids.name_flag)
    return frozenset(guids)


def _build_spn_index(con: duckdb.DuckDBPyConnection) -> SpnIndex:
    """Build the SPN->node index (for constrained-delegation target resolution)."""
    spn_rows = con.execute(
        "SELECT node_id, spns FROM principal WHERE spns IS NOT NULL ORDER BY node_id"
    ).fetchall()
    return build_spn_index([(n, list(s)) for n, s in spn_rows if s])


@dataclass
class _DerivAttrState:
    """Accumulator for the staged-attribute 5B builders (delegation / RBCD / gMSA).

    Its :meth:`handle` is the ``attr_handler`` driven by the single streamed pass
    over ``staging_object`` in :func:`_compute_acl_into` (M-2: one pass, not a
    second full-table read), so these edges share that pass. Mutable counters are
    folded into the final :class:`_DerivationCounts`.
    """

    resolver: NodeResolver
    buffer: _EdgeBuffer
    spn_index: SpnIndex
    scoping: tuple[str, str | None, str | None]
    delegation: int = 0
    rbcd: int = 0
    gmsa: int = 0
    delegation_unresolved: int = 0
    rbcd_sd_errors: int = 0
    gmsa_sd_errors: int = 0

    def handle(self, node_id: str, attributes_json: str, obj_prov: ProvenanceStruct) -> None:
        """Process one object's staged attributes for delegation / RBCD / gMSA."""
        attrs = json.loads(attributes_json) if attributes_json else {}
        if not isinstance(attrs, dict):
            return
        deleg = _attr_str_list(_ci_lookup(attrs, ATTR_ALLOWED_TO_DELEGATE_TO))
        rbcd_b = _attr_bytes(_ci_lookup(attrs, ATTR_ALLOWED_TO_ACT))
        gmsa_b = _attr_bytes(_ci_lookup(attrs, ATTR_GROUP_MSA_MEMBERSHIP))
        if deleg:
            result = build_constrained_delegation_edges(
                node_id, deleg, self.spn_index, obj_prov, self.scoping
            )
            for edge in result.edges:
                self.buffer.add(edge)
                self.delegation += 1
            self.delegation_unresolved += result.skipped
        if rbcd_b is not None:
            edges, failed = build_rbcd_edges(node_id, rbcd_b, self.resolver, obj_prov, self.scoping)
            for edge in edges:
                self.buffer.add(edge)
                self.rbcd += 1
            self.rbcd_sd_errors += int(failed)
        if gmsa_b is not None:
            edges, failed = build_gmsa_read_edges(
                node_id, gmsa_b, self.resolver, obj_prov, self.scoping
            )
            for edge in edges:
                self.buffer.add(edge)
                self.gmsa += 1
            self.gmsa_sd_errors += int(failed)


def _compute_derivations_into(
    con: duckdb.DuckDBPyConnection,
    resolver: NodeResolver,
    buffer: _EdgeBuffer,
    domain_node_id: str | None,
    state: _DerivAttrState,
    pki_flag_guids: PkiFlagGuids,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> _DerivationCounts:
    """Run the table-driven slice-5B builders (SID-history / trust / ADCS).

    The staged-attribute builders (delegation / RBCD / gMSA) already ran via
    ``state`` during the single streamed SD pass; their counts are merged here.
    """
    scoping = (forest_id, domain_id, domain_fqdn)

    # SID history.
    sidhistory = 0
    sh_rows = con.execute(
        "SELECT node_id, sid_history, provenance FROM principal "
        "WHERE sid_history IS NOT NULL AND length(sid_history) > 0 ORDER BY node_id"
    ).fetchall()
    for node_id, sid_history, provenance in sh_rows:
        obj_prov = ProvenanceStruct.model_validate(provenance)
        for edge in build_sid_history_edges(
            node_id, list(sid_history), resolver, obj_prov, scoping
        ):
            buffer.add(edge)
            sidhistory += 1

    # Trust edges.
    trust = trust_keys = trust_partner_unresolved = 0
    if domain_node_id is not None:
        trust_rows = con.execute(
            "SELECT target_domain_id, direction, trust_attributes, trust_key_ref, provenance "
            "FROM trust ORDER BY node_id"
        ).fetchall()
        for target_sid, direction, attrs_bits, trust_key_ref, provenance in trust_rows:
            ti = TrustInput(
                local_domain_node_id=domain_node_id,
                other_domain_sid=target_sid,
                direction=direction,
                trust_attributes=attrs_bits,
                has_trust_key=trust_key_ref is not None,
                provenance=ProvenanceStruct.model_validate(provenance),
            )
            edges, unresolved = build_trust_edges(ti, resolver, scoping)
            trust_partner_unresolved += unresolved
            for edge in edges:
                buffer.add(edge)
                if edge.kind == KIND_HAS_TRUST_KEYS:
                    trust_keys += 1
                else:
                    trust += 1

    adcs, published_to, adcs_sd_errors, published_unresolved = _compute_adcs_into(
        con, resolver, buffer, pki_flag_guids, scoping
    )

    adcs_topology = compute_adcs_topology(
        con,
        buffer,
        domain_node_id,
        state.spn_index.host_to_node,
        _build_group_dn_index(con),
        scoping,
    )

    contains, gplink, coerce_tgt, contains_unresolved = _compute_structural_into(
        con, buffer, domain_node_id, scoping
    )

    return _DerivationCounts(
        delegation=state.delegation,
        rbcd=state.rbcd,
        gmsa=state.gmsa,
        sidhistory=sidhistory,
        trust=trust,
        trust_keys=trust_keys,
        adcs=adcs,
        published_to=published_to,
        contains=contains,
        gplink=gplink,
        coerce_to_tgt=coerce_tgt,
        delegation_unresolved=state.delegation_unresolved,
        rbcd_sd_errors=state.rbcd_sd_errors,
        gmsa_sd_errors=state.gmsa_sd_errors,
        adcs_sd_errors=adcs_sd_errors,
        trust_partner_unresolved=trust_partner_unresolved,
        published_unresolved=published_unresolved,
        contains_parent_unresolved=contains_unresolved,
        adcs_topology=adcs_topology,
    )


def _build_group_dn_index(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """Build the lowercased group-DN -> node index (for OIDGroupLink resolution).

    ``msDS-OIDToGroupLink`` holds a group's distinguished name, so the IssuancePolicy
    -> Group edge resolves against the ``principal`` table's reconstructed DNs. The
    first node in ``node_id`` order wins on a DN collision (deterministic).
    """
    rows = con.execute(
        "SELECT node_id, distinguished_name FROM principal "
        "WHERE principal_type = 'Group' AND distinguished_name IS NOT NULL ORDER BY node_id"
    ).fetchall()
    index: dict[str, str] = {}
    for node_id, dn in rows:
        if dn:
            index.setdefault(dn.lower(), node_id)
    return index


def _compute_adcs_into(
    con: duckdb.DuckDBPyConnection,
    resolver: NodeResolver,
    buffer: _EdgeBuffer,
    pki_flag_guids: PkiFlagGuids,
    scoping: tuple[str, str | None, str | None],
) -> tuple[int, int, int, int]:
    """Build the ADCS-scoped + PublishedTo edges; return the four 5B ADCS counts."""
    adcs_rows = con.execute(
        "SELECT a.node_id, a.name, a.adcs_type, a.published_templates, "
        "s.raw_sd, s.provenance "
        "FROM adcs a LEFT JOIN staging_object s ON s.node_id = a.node_id ORDER BY a.node_id"
    ).fetchall()

    template_name_to_node: dict[str, str] = {}
    for node_id, name, adcs_type, _pub, _sd, _prov in adcs_rows:
        if adcs_type == "CertTemplate" and name:
            template_name_to_node.setdefault(name.lower(), node_id)

    adcs = published_to = sd_errors = published_unresolved = 0
    for node_id, _name, _adcs_type, published, raw_sd, provenance in adcs_rows:
        if provenance is None:
            continue
        obj_prov = ProvenanceStruct.model_validate(provenance)
        sd_bytes = bytes(raw_sd) if raw_sd else None
        edges, failed = build_adcs_enrollment_edges(
            node_id, sd_bytes, pki_flag_guids, NOISE_TRUSTEE_SIDS, resolver, obj_prov, scoping
        )
        sd_errors += int(failed)
        for edge in edges:
            buffer.add(edge)
            adcs += 1
        if published:
            pub_edges, unresolved = build_published_to_edges(
                node_id, list(published), template_name_to_node, obj_prov, scoping
            )
            published_unresolved += unresolved
            for edge in pub_edges:
                buffer.add(edge)
                published_to += 1
    return adcs, published_to, sd_errors, published_unresolved


def _compute_structural_into(
    con: duckdb.DuckDBPyConnection,
    buffer: _EdgeBuffer,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
) -> tuple[int, int, int, int]:
    """Build the structural/derived edges (Contains, GPLink, CoerceToTGT).

    Pure-ntds, M3-sourced (no DN-tree re-walk, no gPLink re-parse):

    * **Contains** (container -> child) — from ``container.parent_node_id`` for the
      container tree, and from a parent-DN lookup (reusing M3's reconstructed
      ``distinguished_name`` strings) for principals, since M3 persists
      ``parent_node_id`` only on the ``container`` table.
    * **GPLink** (GPO -> linked container) — from the M3-resolved ``gplinks`` STRUCT
      list on each container (disabled links were already dropped + counted in M3).
    * **CoerceToTGT** (non-DC unconstrained-delegation principal -> domain) — from
      the principal's ``userAccountControl`` (DC-self suppressed).

    Returns:
        ``(contains, gplink, coerce_to_tgt, contains_parent_unresolved)``.
    """
    contains = gplink = coerce_tgt = contains_unresolved = 0

    container_rows = con.execute(
        "SELECT node_id, parent_node_id, gplinks, distinguished_name, provenance "
        "FROM container ORDER BY node_id"
    ).fetchall()
    container_nodes: set[str] = {row[0] for row in container_rows}
    dn_to_node: dict[str, str] = {}
    for node_id, _parent, _gplinks, dn, _prov in container_rows:
        if dn:
            dn_to_node.setdefault(dn.lower(), node_id)

    # Contains (container tree) + GPLink from the container rows.
    for node_id, parent_node_id, gplinks, _dn, prov in container_rows:
        obj_prov = ProvenanceStruct.model_validate(prov)
        if parent_node_id is not None and parent_node_id in container_nodes:
            edge = build_contains_edge(parent_node_id, node_id, obj_prov, scoping)
            if edge is not None:
                buffer.add(edge)
                contains += 1
        elif parent_node_id is not None:
            # A persisted parent that is not a known container is a dangling parent
            # (M3 counts truly-absent parents as orphans; this guards the rare case).
            contains_unresolved += 1
        if gplinks:
            for edge in build_gplink_edges(node_id, list(gplinks), obj_prov, scoping):
                buffer.add(edge)
                gplink += 1

    # Contains for principals (parent resolved via DN) + CoerceToTGT.
    principal_rows = con.execute(
        "SELECT node_id, distinguished_name, uac_flags, provenance FROM principal ORDER BY node_id"
    ).fetchall()
    for node_id, dn, uac_flags, prov in principal_rows:
        principal_prov: ProvenanceStruct | None = None
        # A principal with no reconstructed DN (or a single-RDN root with no
        # parent) yields no Contains edge and is NOT counted here: that absence
        # is already accounted for by M3's not_modeled/orphan counters at DN
        # reconstruction time, so re-counting it here would double-count.
        if dn:
            pdn = parent_dn(dn)
            if pdn is not None:
                parent_node = dn_to_node.get(pdn.lower())
                if parent_node is not None:
                    principal_prov = ProvenanceStruct.model_validate(prov)
                    edge = build_contains_edge(parent_node, node_id, principal_prov, scoping)
                    if edge is not None:
                        buffer.add(edge)
                        contains += 1
                else:
                    contains_unresolved += 1
        if domain_node_id is not None and is_coercible_unconstrained(uac_flags):
            if principal_prov is None:
                principal_prov = ProvenanceStruct.model_validate(prov)
            coerce_edge = build_coerce_to_tgt_edge(node_id, domain_node_id, principal_prov, scoping)
            if coerce_edge is not None:
                buffer.add(coerce_edge)
                coerce_tgt += 1

    return contains, gplink, coerce_tgt, contains_unresolved


def _compute_node_flags(con: duckdb.DuckDBPyConnection, run: IngestRun) -> NodeFlagCounts:
    """Compute node-flag tallies over the ``principal`` table (stored nowhere)."""
    unconstrained = kerberoastable = asrep = 0
    rows = con.execute(
        "SELECT principal_type, uac_flags, enabled, spns, samaccountname FROM principal"
    ).fetchall()
    for principal_type, uac_flags, enabled, spns, samaccountname in rows:
        flags = compute_node_flags(
            principal_type, uac_flags, enabled, list(spns) if spns else [], samaccountname
        )
        unconstrained += int(flags.unconstrained_delegation)
        kerberoastable += int(flags.kerberoastable)
        asrep += int(flags.asrep_roastable)
    _bump(run, _COV_FLAG_UNCONSTRAINED, unconstrained)
    _bump(run, _COV_FLAG_KERBEROASTABLE, kerberoastable)
    _bump(run, _COV_FLAG_ASREP, asrep)
    return NodeFlagCounts(unconstrained, kerberoastable, asrep)


def _bump_derivations(run: IngestRun, c: _DerivationCounts) -> None:
    """Surface the 5B counters on the run."""
    _bump(run, _COV_DELEGATION, c.delegation)
    _bump(run, _COV_RBCD, c.rbcd)
    _bump(run, _COV_GMSA, c.gmsa)
    _bump(run, _COV_SIDHISTORY, c.sidhistory)
    _bump(run, _COV_TRUST, c.trust)
    _bump(run, _COV_TRUST_KEYS, c.trust_keys)
    _bump(run, _COV_ADCS, c.adcs)
    _bump(run, _COV_PUBLISHED, c.published_to)
    _bump(run, _COV_CONTAINS, c.contains)
    _bump(run, _COV_GPLINK, c.gplink)
    _bump(run, _COV_COERCE_TGT, c.coerce_to_tgt)
    _bump(run, _SKIP_DELEGATION_UNRESOLVED, c.delegation_unresolved)
    _bump(run, _SKIP_RBCD_SD_PARSE, c.rbcd_sd_errors)
    _bump(run, _SKIP_GMSA_SD_PARSE, c.gmsa_sd_errors)
    _bump(run, _SKIP_ADCS_SD_PARSE, c.adcs_sd_errors)
    _bump(run, _SKIP_TRUST_PARTNER_UNRESOLVED, c.trust_partner_unresolved)
    _bump(run, _SKIP_PUBLISHED_UNRESOLVED, c.published_unresolved)
    _bump(run, _SKIP_CONTAINS_UNRESOLVED, c.contains_parent_unresolved)
    _bump_adcs_topology(run, c.adcs_topology)


def _bump_adcs_topology(run: IngestRun, a: AdcsTopologyResult) -> None:
    """Surface the ADCS-topology coverage + counted-gap counters on the run."""
    _bump(run, _COV_ADCS_ENTERPRISE_CA_FOR, a.enterprise_ca_for)
    _bump(run, _COV_ADCS_ROOT_CA_FOR, a.root_ca_for)
    _bump(run, _COV_ADCS_NTAUTH_STORE_FOR, a.ntauth_store_for)
    _bump(run, _COV_ADCS_HOSTS_CA_SERVICE, a.hosts_ca_service)
    _bump(run, _COV_ADCS_TRUSTED_FOR_NTAUTH, a.trusted_for_ntauth)
    _bump(run, _COV_ADCS_ISSUED_SIGNED_BY, a.issued_signed_by)
    _bump(run, _COV_ADCS_EXTENDED_BY_POLICY, a.extended_by_policy)
    _bump(run, _COV_ADCS_OID_GROUP_LINK, a.oid_group_link)
    _bump(run, _SKIP_ADCS_HOSTSCA_UNRESOLVED, a.hostscaservice_unresolved)
    _bump(run, _SKIP_ADCS_CHAIN_AMBIGUOUS, a.ca_cert_chain_ambiguous)
    _bump(run, _SKIP_ADCS_NTAUTH_UNMATCHED, a.ntauth_cert_unmatched)
    _bump(run, _SKIP_ADCS_OIDLINK_UNRESOLVED, a.oidgrouplink_sid_unresolved)
    _bump(run, _SKIP_ADCS_CERT_PARSE, a.cert_parse_error)


# =============================================================================
# Combined Module-5 orchestrator
# =============================================================================


@dataclass(frozen=True)
class M5Result:
    """The outcome of the full Module-5 edge pass (counts only — never secrets).

    Attributes:
        acl: the slice-5A counts (ace/owner/dcsync + LAPS + domain node).
        derivations: the slice-5B counts (delegation/rbcd/gmsa/sidhistory/trust/adcs).
        node_flags: node-flag tallies (facts, stored nowhere; M6/M7 consume).
        stubs_minted: total stub Principals materialized (5A + 5B share the resolver).
        edges_total: distinct edge rows written this pass (deduped by ``edge_id``).
        coverage_counts/skip_counts: the run's counter snapshots.
    """

    acl: AclEdgeResult
    derivations: _DerivationCounts
    node_flags: NodeFlagCounts
    stubs_minted: int
    edges_total: int
    coverage_counts: Mapping[str, int]
    skip_counts: Mapping[str, int]


def compute_edges(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    schema: NtdsSchema,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> M5Result:
    """Compute and write the FULL Module-5 edge graph (slices 5A + 5B).

    Runs the SD/ACE core (5A) and the non-SD derivations (5B) over the shared
    resolver + buffer, then writes minted stub Principals (sorted by ``node_id``)
    and all edges (sorted by ``edge_id``) in a single deterministic pass. Node
    flags are computed for M6/M7 but stored nowhere. All counted gaps are surfaced
    on ``run``.

    Inputs:
        con: an open canonical-store connection holding the gated M3 (+ M4) tables.
        run: the :class:`IngestRun` providing counters + the ``ingest_run_id``.
        schema: the gated 2a :class:`NtdsSchema` (LAPS + PKI-flag ``schemaIDGUID``s).
        forest_id/domain_id/domain_fqdn: the scoping block (M3's identity, MUST
            equal the one M3/M4 used).

    Returns:
        An :class:`M5Result`.

    Failure modes:
        ``duckdb.Error`` on a store failure / ``edge`` PK clash from re-running on
        a populated store. Malformed per-SD/per-ACE/per-attribute data degrades to
        counted gaps; never a dangling edge.
    """
    create_edge_tables(con)
    resolver = _load_resolver(
        con, run, forest_id=forest_id, domain_id=domain_id, domain_fqdn=domain_fqdn
    )
    laps_guids, laps_unresolvable = resolve_laps_guids(schema)
    _bump(run, _SKIP_LAPS_UNRESOLVABLE, laps_unresolvable)
    pki_flag_guids, pki_unresolvable = resolve_pki_flag_guids(schema)
    _bump(run, _SKIP_PKI_FLAG_UNRESOLVABLE, pki_unresolvable)
    handled = _handled_elsewhere_guids(pki_flag_guids)
    domain_node_id = _resolve_domain_node(con, domain_id)

    buffer = _EdgeBuffer()
    scoping = (forest_id, domain_id, domain_fqdn)
    # The 5B staged-attribute builders (delegation / RBCD / gMSA) ride the SINGLE
    # streamed SD pass via this state's handler (M-2: one pass over staging_object).
    attr_state = _DerivAttrState(resolver, buffer, _build_spn_index(con), scoping)

    acl_counts = _compute_acl_into(
        con,
        resolver,
        buffer,
        laps_guids,
        domain_node_id,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        handled_elsewhere=handled,
        attr_handler=attr_state.handle,
    )
    if domain_node_id is None:
        _bump(run, _SKIP_DCSYNC_NO_DOMAIN, 1)

    deriv_counts = _compute_derivations_into(
        con,
        resolver,
        buffer,
        domain_node_id,
        attr_state,
        pki_flag_guids,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
    )

    ordered = buffer.ordered()
    _write_stubs(con, resolver.minted)
    _write_edges(con, ordered)

    _bump_acl(run, acl_counts, len(resolver.minted))
    _bump_derivations(run, deriv_counts)
    node_flags = _compute_node_flags(con, run)

    acl_result = AclEdgeResult(
        ace_edges=acl_counts.ace_edges,
        owner_edges=acl_counts.owner_edges,
        dcsync_edges=acl_counts.dcsync_edges,
        stubs_minted=len(resolver.minted),
        edges_total=len(ordered),
        laps_guids=laps_guids,
        laps_unresolvable=laps_unresolvable,
        domain_node_id=domain_node_id,
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )
    return M5Result(
        acl=acl_result,
        derivations=deriv_counts,
        node_flags=node_flags,
        stubs_minted=len(resolver.minted),
        edges_total=len(ordered),
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )
