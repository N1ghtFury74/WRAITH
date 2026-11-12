"""Module 4 — the Membership Resolver (the first writer of §4 ``edge`` rows).

Resolves Active Directory group membership into the canonical graph as direct
``MemberOf`` edges and materializes their transitive closure:

* **Stored links** — Module 3's ``staging_link`` rows filtered to the ``member``
  linked attribute (``link_base == schema(member).linkID >> 1``), live only (both
  ``link_deltime`` and ``link_deactivetime`` zero/NULL). The member/group
  endpoints are **swapped** relative to ``staging_link`` (M3 stores
  ``source=group, target=member``; a ``MemberOf`` edge runs ``member -> group``),
  giving ``derivation="LINK:member"``, ``confidence="confirmed"``.
* **Primary group** — each User/Computer's implicit ``primaryGroupID`` membership
  (not present in ``link_table``), ``derivation="SYNTH:primarygroup"``,
  ``confidence="confirmed"``.
* **Special identities** — a minimal synthetic set
  (Domain Users/Computers -> Authenticated Users -> Everyone),
  ``derivation="SYNTH:specialidentity"``, ``confidence="inferred"``.
* **effective_membership** — the reflexive-free transitive closure of the direct
  edges, computed by an in-process cycle-guarded BFS (AD membership cycles are
  legal), materialized for O(1) "effective members of G" lookups by M5.

Scope: ``MemberOf`` only. ACL/UAC/DCSync/trust/GPO/ADCS edges are Module 5.
No secrets are touched. Every function is pure except the thin orchestrator,
which reads the M3 tables and writes the two tables deterministically.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.common.determinism import sha256_hex, stable_id
from wraith.edges.models import EdgeRow, EffectiveMembershipRow, MembershipResult
from wraith.model.store import create_edge_tables
from wraith.normalize.identity import node_id_for_sid
from wraith.parsing.ntds_values import as_scalar
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

# --- §4 edge literals for MemberOf -------------------------------------------
KIND_MEMBEROF: str = "MemberOf"
DERIVATION_LINK: str = "LINK:member"
DERIVATION_PRIMARY_GROUP: str = "SYNTH:primarygroup"
DERIVATION_SPECIAL_IDENTITY: str = "SYNTH:specialidentity"
CONFIDENCE_CONFIRMED: str = "confirmed"
CONFIDENCE_INFERRED: str = "inferred"

# --- well-known SIDs for the synthetic special-identity set ------------------
SID_AUTHENTICATED_USERS: str = "S-1-5-11"
SID_EVERYONE: str = "S-1-1-0"
RID_DOMAIN_USERS: int = 513
RID_DOMAIN_COMPUTERS: int = 515

#: Provenance markers for synthetic special-identity edges (no backing object).
SPECIALIDENTITY_SOURCE_FILE: str = "synthetic:specialidentity"
#: Deterministic, NON-real image hash sentinel (mirrors the normalizer's stub
#: sentinel policy): a valid 64-hex value that claims no acquired artifact.
_SYNTHETIC_IMAGE_SHA256: str = sha256_hex(b"wraith:synthetic:specialidentity")

# --- counter keys (surfaced on the IngestRun, never silent) ------------------
_COV_EDGES_DIRECT = "membership.edges_direct"
_COV_EDGES_PRIMARY = "membership.edges_primarygroup"
_COV_EDGES_SYNTH = "membership.edges_synthetic"
_COV_EFFECTIVE = "membership.effective_pairs"
_SKIP_LINK_UNRESOLVED = "membership.link_unresolved_endpoint"
_SKIP_LINK_TOMBSTONED = "membership.link_tombstoned"
_SKIP_PRIMARY_UNRESOLVED = "membership.primarygroup_unresolved"
_SKIP_SPECIAL_UNRESOLVED = "membership.specialidentity_unresolved"
_SKIP_MEMBER_BASE_UNRESOLVED = "membership.member_link_base_unresolved"


@dataclass(frozen=True)
class Scoping:
    """The scoping block carried onto every edge produced by this run."""

    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None


@dataclass(frozen=True)
class LinkInput:
    """A ``staging_link`` row as M4 reads it (M3 stores source=group/target=member)."""

    link_base: int | None
    source_node_id: str | None
    target_node_id: str | None
    link_deltime: int | None
    link_deactivetime: int | None
    provenance: ProvenanceStruct


@dataclass(frozen=True)
class AccountInput:
    """A ``principal`` row as M4 reads it for primary-group synthesis."""

    node_id: str
    primary_group_id: int | None
    principal_type: str
    provenance: ProvenanceStruct


@dataclass(frozen=True)
class PrincipalIndex:
    """SID/node lookup maps built once from the ``principal`` table.

    Attributes:
        sid_to_node: ``object_sid`` -> ``node_id`` for every principal with a SID.
        group_nodes: the ``node_id`` set of principals typed ``Group``.
        all_nodes: every principal ``node_id`` (used to confirm a resolved
            endpoint actually exists as a node, never a dangling edge).
    """

    sid_to_node: Mapping[str, str]
    group_nodes: frozenset[str]
    all_nodes: frozenset[str]


@dataclass(frozen=True)
class _LinkGaps:
    """Counted gaps from the stored-link pass."""

    tombstoned: int
    unresolved_endpoint: int
    non_member: int


def resolve_member_link_base(schema: NtdsSchema) -> int | None:
    """Resolve the ``member`` attribute's ``link_base`` from the in-DIT schema.

    Linked attributes are forward/back-link pairs: the forward link carries an
    even ``linkID`` and its ``link_base`` is ``linkID >> 1`` (the value joined in
    ``link_table.link_base``). ``member`` is the forward link (``linkID == 2`` on
    a standard schema, so ``link_base == 1``). Reading it from the schema (rather
    than hard-coding) is portable across schema versions and avoids trusting a
    dev-observed constant.

    Inputs:
        schema: the gated 2a :class:`NtdsSchema` (its raw ``attributeSchema``
            records carry the ``linkID`` column).

    Returns:
        ``member``'s ``link_base`` (``linkID >> 1``), or ``None`` if the schema
        did not surface a ``member`` record with an integer ``linkID`` (a
        surfaced gap — the caller then produces no stored-link edges).

    Failure modes:
        Never raises; a missing/unreadable value degrades to ``None``.
    """
    ldap_col = schema.column_for("lDAPDisplayName")
    link_id_col = schema.column_for("linkID")
    if ldap_col is None or link_id_col is None:
        return None
    for record in schema.raw_attribute_records:
        if as_scalar(record.get(ldap_col)) != "member":
            continue
        link_id = as_scalar(record.get(link_id_col))
        if isinstance(link_id, bool) or not isinstance(link_id, int):
            return None
        return link_id >> 1
    return None


def is_live_link(link_deltime: int | None, link_deactivetime: int | None) -> bool:
    """Return whether a link row is live (not tombstoned / not deactivated).

    A ``member`` link counts as live only when BOTH ``link_deltime`` and
    ``link_deactivetime`` are the "unset" sentinel — ``0`` or ``NULL`` (dissect
    surfaces ``NULL`` on the dev DIT; ``0`` is accepted too so a different
    surfacing cannot silently admit a tombstoned link). A non-zero value marks a
    deleted/deactivated membership retained for replication/recycle-bin and MUST
    be excluded (counting it would over-report membership).

    Inputs:
        link_deltime: the link's deletion time sentinel, or ``None``.
        link_deactivetime: the link's deactivation time sentinel, or ``None``.

    Returns:
        ``True`` if both are zero/``None`` (live), else ``False``.

    Failure modes:
        Never raises.
    """
    return link_deltime in (None, 0) and link_deactivetime in (None, 0)


def _make_memberof_edge(
    member_node_id: str,
    group_node_id: str,
    derivation: str,
    confidence: str,
    provenance: ProvenanceStruct,
    scoping: Scoping,
) -> EdgeRow:
    """Build one ``MemberOf`` §4 edge (member -> group) with a deterministic id."""
    edge_id = stable_id(KIND_MEMBEROF, member_node_id, group_node_id, derivation)
    return EdgeRow(
        edge_id=edge_id,
        kind=KIND_MEMBEROF,
        source_node_id=member_node_id,
        target_node_id=group_node_id,
        is_inherited=False,
        derivation=derivation,
        access_mask=None,
        object_type_guid=None,
        confidence=confidence,
        forest_id=scoping.forest_id,
        domain_id=scoping.domain_id,
        domain_fqdn=scoping.domain_fqdn,
        provenance=provenance,
    )


def build_link_memberof_edges(
    links: Iterable[LinkInput],
    member_link_base: int,
    scoping: Scoping,
) -> tuple[list[EdgeRow], _LinkGaps]:
    """Build direct ``MemberOf`` edges from stored ``member`` links (with the swap).

    Filters ``links`` to the ``member`` linked attribute, drops tombstoned/
    deactivated rows, and SWAPS the endpoints: M3 stores ``source=group,
    target=member`` so the ``MemberOf`` edge is ``source=member (link.target),
    target=group (link.source)``. A link whose required endpoint is unresolved
    (``None``) is skipped and counted — never a dangling edge.

    Inputs:
        links: the ``staging_link`` rows (all linked attributes).
        member_link_base: the ``member`` ``link_base`` from
            :func:`resolve_member_link_base`.
        scoping: the scoping block to stamp on each edge.

    Returns:
        ``(edges, gaps)`` — the ``LINK:member`` edges and the counted gaps
        (tombstoned, unresolved-endpoint, non-member-link).

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    tombstoned = unresolved = non_member = 0
    for link in links:
        if link.link_base != member_link_base:
            non_member += 1
            continue
        if not is_live_link(link.link_deltime, link.link_deactivetime):
            tombstoned += 1
            continue
        member_node_id = link.target_node_id  # SWAP: M3 target == the member
        group_node_id = link.source_node_id  # SWAP: M3 source == the group
        if member_node_id is None or group_node_id is None:
            unresolved += 1
            continue
        edges.append(
            _make_memberof_edge(
                member_node_id,
                group_node_id,
                DERIVATION_LINK,
                CONFIDENCE_CONFIRMED,
                link.provenance,
                scoping,
            )
        )
    return edges, _LinkGaps(tombstoned, unresolved, non_member)


def resolve_primary_group_node(
    primary_group_id: int,
    domain_id: str | None,
    forest_id: str,
    index: PrincipalIndex,
) -> str | None:
    """Resolve an account's primary group to an existing Group ``node_id``.

    ``group_sid = <domain_sid>-<primary_group_id>``; resolve via
    ``principal.object_sid`` first, else via the shared
    :func:`~wraith.normalize.identity.node_id_for_sid`. The result is returned
    only if it names a principal typed ``Group``; otherwise ``None`` (the caller
    skips + counts — a primaryGroupID resolving to no/non-Group node).

    Inputs:
        primary_group_id: the account's ``primaryGroupID`` RID.
        domain_id: the domain SID (needed to build the group SID).
        forest_id: the scoping forest id (for the fallback resolver).
        index: the :class:`PrincipalIndex`.

    Returns:
        The group ``node_id``, or ``None`` if unresolvable to a Group node.

    Failure modes:
        Never raises.
    """
    if domain_id is None:
        return None
    group_sid = f"{domain_id}-{primary_group_id}"
    node = index.sid_to_node.get(group_sid)
    if node is None:
        node = node_id_for_sid(forest_id, domain_id, group_sid)
    return node if node in index.group_nodes else None


def build_primary_group_edges(
    accounts: Iterable[AccountInput],
    scoping: Scoping,
    index: PrincipalIndex,
) -> tuple[list[EdgeRow], int]:
    """Build implicit ``SYNTH:primarygroup`` ``MemberOf`` edges for User/Computer.

    Each User/Computer with a ``primaryGroupID`` is an implicit member of that
    group (invisible to the link scan). Groups and stub principals (no
    ``primaryGroupID``) are skipped silently — not a gap. The edge provenance is
    the member object's own provenance.

    Inputs:
        accounts: the principal rows (all types).
        scoping: the scoping block to stamp on each edge.
        index: the :class:`PrincipalIndex`.

    Returns:
        ``(edges, unresolved)`` — the ``SYNTH:primarygroup`` edges and the count
        of accounts whose primaryGroupID resolved to no/non-Group node.

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    unresolved = 0
    for account in accounts:
        if account.principal_type not in ("User", "Computer"):
            continue
        if account.primary_group_id is None:
            continue  # no primaryGroupID (groups/stubs) -> silent skip, not a gap
        group_node_id = resolve_primary_group_node(
            account.primary_group_id, scoping.domain_id, scoping.forest_id, index
        )
        if group_node_id is None:
            unresolved += 1
            continue
        edges.append(
            _make_memberof_edge(
                account.node_id,
                group_node_id,
                DERIVATION_PRIMARY_GROUP,
                CONFIDENCE_CONFIRMED,
                account.provenance,
                scoping,
            )
        )
    return edges, unresolved


def _resolve_existing_node(
    sid: str, domain_id: str | None, forest_id: str, index: PrincipalIndex
) -> str | None:
    """Resolve a SID to an existing principal ``node_id`` (real row or stub)."""
    node = index.sid_to_node.get(sid)
    if node is None:
        node = node_id_for_sid(forest_id, domain_id, sid)
    return node if node in index.all_nodes else None


def build_special_identity_edges(
    scoping: Scoping,
    index: PrincipalIndex,
    provenance: ProvenanceStruct,
) -> tuple[list[EdgeRow], int]:
    """Build the minimal synthetic special-identity ``MemberOf`` set.

    Emits (per domain), as ``SYNTH:specialidentity`` / ``confidence="inferred"``
    (a logon-time truth, not a stored fact):

    * Domain Users (``...-513``)      -> Authenticated Users (``S-1-5-11``)
    * Domain Computers (``...-515``)  -> Authenticated Users (``S-1-5-11``)
    * Authenticated Users             -> Everyone (``S-1-1-0``)

    An edge is emitted only when BOTH endpoints resolve to existing principal
    nodes (the S-1-5-11 / S-1-1-0 stubs are materialized by M3); a missing
    endpoint is skipped + counted.

    Inputs:
        scoping: the scoping block (``domain_id`` builds the 513/515 SIDs).
        index: the :class:`PrincipalIndex`.
        provenance: the synthetic provenance to stamp (no backing object).

    Returns:
        ``(edges, unresolved)`` — the synthetic edges and the count of pairs
        skipped because an endpoint did not resolve.

    Failure modes:
        Never raises.
    """
    edges: list[EdgeRow] = []
    unresolved = 0
    domain_id = scoping.domain_id
    pairs: list[tuple[str, str]] = []
    if domain_id is not None:
        pairs.append((f"{domain_id}-{RID_DOMAIN_USERS}", SID_AUTHENTICATED_USERS))
        pairs.append((f"{domain_id}-{RID_DOMAIN_COMPUTERS}", SID_AUTHENTICATED_USERS))
    pairs.append((SID_AUTHENTICATED_USERS, SID_EVERYONE))

    for member_sid, group_sid in pairs:
        member_node_id = _resolve_existing_node(member_sid, domain_id, scoping.forest_id, index)
        group_node_id = _resolve_existing_node(group_sid, domain_id, scoping.forest_id, index)
        if member_node_id is None or group_node_id is None:
            unresolved += 1
            continue
        edges.append(
            _make_memberof_edge(
                member_node_id,
                group_node_id,
                DERIVATION_SPECIAL_IDENTITY,
                CONFIDENCE_INFERRED,
                provenance,
                scoping,
            )
        )
    return edges, unresolved


def _transitive_members(group_node_id: str, group_to_members: Mapping[str, set[str]]) -> set[str]:
    """Return all transitive members of ``group_node_id`` (cycle-guarded BFS).

    Traverses the direct ``group -> members`` adjacency downward, expanding
    nested groups. A per-traversal ``visited`` set terminates on membership
    cycles (which AD permits). The returned set never intentionally contains
    ``group_node_id``; a cycle back to it is filtered reflexive-free by the
    caller.

    Failure modes:
        Never raises.
    """
    visited: set[str] = set()
    stack: list[str] = sorted(group_to_members.get(group_node_id, set()))
    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        for nested in group_to_members.get(node, set()):
            if nested not in visited:
                stack.append(nested)
    return visited


def compute_effective_membership(
    edges: Iterable[EdgeRow], scoping: Scoping
) -> list[EffectiveMembershipRow]:
    """Materialize the reflexive-free transitive closure of direct ``MemberOf``.

    Builds the ``group -> direct members`` adjacency from the direct edges
    (``target`` is the group, ``source`` is the member) and runs a cycle-guarded
    BFS per group. Output is de-duplicated and sorted by
    ``(group_node_id, member_node_id)`` so the materialized table is
    byte-reproducible. A member equal to its group (only reachable via a cycle)
    is dropped (reflexive-free).

    Inputs:
        edges: the direct ``MemberOf`` edges (links + primary group + special).
        scoping: the scoping block to stamp on each closure row.

    Returns:
        The sorted :class:`EffectiveMembershipRow` list.

    Failure modes:
        Never raises; cycles terminate via the per-traversal visited set.
    """
    group_to_members: dict[str, set[str]] = {}
    for edge in edges:
        group_to_members.setdefault(edge.target_node_id, set()).add(edge.source_node_id)

    rows: list[EffectiveMembershipRow] = []
    for group_node_id in sorted(group_to_members):
        for member_node_id in sorted(_transitive_members(group_node_id, group_to_members)):
            if member_node_id == group_node_id:
                continue  # reflexive-free (drop a cycle that returns to the group)
            rows.append(
                EffectiveMembershipRow(
                    member_node_id=member_node_id,
                    group_node_id=group_node_id,
                    forest_id=scoping.forest_id,
                    domain_id=scoping.domain_id,
                )
            )
    rows.sort(key=lambda row: (row.group_node_id, row.member_node_id))
    return rows


def _provenance_from_struct(value: object) -> ProvenanceStruct:
    """Rebuild a :class:`ProvenanceStruct` from a DuckDB provenance STRUCT dict.

    The stored struct's keys match the model's fields exactly, so pydantic's
    ``model_validate`` reconstructs (and re-validates) it directly.
    """
    return ProvenanceStruct.model_validate(value)


def _load_principals(con: duckdb.DuckDBPyConnection) -> tuple[PrincipalIndex, list[AccountInput]]:
    """Read the ``principal`` table into the lookup index + account list.

    Deterministic (``ORDER BY node_id``). Reconstructs each account's provenance
    so primary-group edges carry the member object's own provenance.
    """
    sid_to_node: dict[str, str] = {}
    group_nodes: set[str] = set()
    all_nodes: set[str] = set()
    accounts: list[AccountInput] = []
    rows = con.execute(
        "SELECT node_id, object_sid, principal_type, primary_group_id, provenance "
        "FROM principal ORDER BY node_id"
    ).fetchall()
    for node_id, object_sid, principal_type, primary_group_id, provenance in rows:
        all_nodes.add(node_id)
        if object_sid is not None:
            sid_to_node.setdefault(object_sid, node_id)
        if principal_type == "Group":
            group_nodes.add(node_id)
        accounts.append(
            AccountInput(
                node_id=node_id,
                primary_group_id=primary_group_id,
                principal_type=principal_type,
                provenance=_provenance_from_struct(provenance),
            )
        )
    index = PrincipalIndex(
        sid_to_node=sid_to_node,
        group_nodes=frozenset(group_nodes),
        all_nodes=frozenset(all_nodes),
    )
    return index, accounts


def _load_links(con: duckdb.DuckDBPyConnection) -> list[LinkInput]:
    """Read ``staging_link`` into :class:`LinkInput` rows (deterministic order)."""
    rows = con.execute(
        "SELECT link_base, source_node_id, target_node_id, link_deltime, "
        "link_deactivetime, provenance FROM staging_link "
        "ORDER BY link_base, source_node_id, target_node_id"
    ).fetchall()
    links: list[LinkInput] = []
    for link_base, source_node_id, target_node_id, deltime, deactivetime, provenance in rows:
        links.append(
            LinkInput(
                link_base=link_base,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                link_deltime=deltime,
                link_deactivetime=deactivetime,
                provenance=_provenance_from_struct(provenance),
            )
        )
    return links


def _write_edges(con: duckdb.DuckDBPyConnection, edges: Sequence[EdgeRow]) -> None:
    """Bulk-insert edges in ``edge_id`` order (deterministic)."""
    if not edges:
        return
    placeholders = ",".join("?" * len(edges[0].to_db_values()))
    sql = f"INSERT INTO edge VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, [edge.to_db_values() for edge in edges])


def _write_effective(
    con: duckdb.DuckDBPyConnection, rows: Sequence[EffectiveMembershipRow]
) -> None:
    """Bulk-insert effective-membership rows in sorted order (deterministic)."""
    if not rows:
        return
    placeholders = ",".join("?" * len(rows[0].to_db_values()))
    sql = f"INSERT INTO effective_membership VALUES ({placeholders})"  # noqa: S608 - literal
    con.executemany(sql, [row.to_db_values() for row in rows])


def resolve_membership(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    schema: NtdsSchema,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> MembershipResult:
    """Resolve group membership into ``edge`` + ``effective_membership`` tables.

    Reads Module 3's ``staging_link`` and ``principal`` tables, produces the
    direct ``MemberOf`` edges (stored links + primary group + special
    identities), de-duplicates them by ``edge_id``, writes them sorted, then
    materializes and writes the transitive closure. All counted gaps are surfaced
    on ``run`` and echoed in the result.

    Inputs:
        con: an open canonical-store connection holding the gated M3 tables.
        run: the :class:`IngestRun` providing counters + the ``ingest_run_id``.
        schema: the gated 2a :class:`NtdsSchema` (to resolve ``member``'s
            ``link_base``).
        forest_id: the scoping forest id — MUST equal the one M3 used.
        domain_id: the domain SID (M3's resolved :class:`DomainIdentity`).
        domain_fqdn: the domain FQDN (M3's resolved identity).

    Returns:
        A :class:`MembershipResult` with per-derivation edge counts, the
        effective-pair count, the resolved ``member`` ``link_base``, and the
        run's coverage/skip snapshots.

    Failure modes:
        ``duckdb.Error`` propagates on a store failure (e.g. the M3 tables
        absent, or a PK clash from re-running on a populated store). Malformed
        per-row data was already degraded to counted gaps by M3; M4 adds its own
        counted gaps and never writes a dangling/half-null edge.
    """
    create_edge_tables(con)
    scoping = Scoping(forest_id=forest_id, domain_id=domain_id, domain_fqdn=domain_fqdn)

    index, accounts = _load_principals(con)

    member_link_base = resolve_member_link_base(schema)
    link_edges: list[EdgeRow] = []
    if member_link_base is None:
        run.bump_skip(_SKIP_MEMBER_BASE_UNRESOLVED)
        _log.warning("membership: could not resolve 'member' link_base from schema")
    else:
        links = _load_links(con)
        link_edges, link_gaps = build_link_memberof_edges(links, member_link_base, scoping)
        if link_gaps.tombstoned:
            run.bump_skip(_SKIP_LINK_TOMBSTONED, link_gaps.tombstoned)
        if link_gaps.unresolved_endpoint:
            run.bump_skip(_SKIP_LINK_UNRESOLVED, link_gaps.unresolved_endpoint)

    primary_edges, primary_unresolved = build_primary_group_edges(accounts, scoping, index)
    if primary_unresolved:
        run.bump_skip(_SKIP_PRIMARY_UNRESOLVED, primary_unresolved)

    # Synthetic provenance is built directly (NOT via run.provenance_for): the
    # special-identity source is not a registered artifact, so it carries the
    # non-real image-hash sentinel and never claims an acquired artifact's hash.
    synthetic_provenance = ProvenanceStruct(
        source_file=SPECIALIDENTITY_SOURCE_FILE,
        image_sha256=_SYNTHETIC_IMAGE_SHA256,
        source_object_id="synthetic:specialidentity",
        directory_timestamp=None,
        ingest_run_id=run.ingest_run_id,
    )
    special_edges, special_unresolved = build_special_identity_edges(
        scoping, index, synthetic_provenance
    )
    if special_unresolved:
        run.bump_skip(_SKIP_SPECIAL_UNRESOLVED, special_unresolved)

    # De-dup by edge_id (a (member,group) that is both a stored-link and a
    # primary-group member yields two rows — distinct derivation, distinct id).
    by_id: dict[str, EdgeRow] = {}
    for edge in (*link_edges, *primary_edges, *special_edges):
        by_id.setdefault(edge.edge_id, edge)
    ordered_edges = sorted(by_id.values(), key=lambda edge: edge.edge_id)

    effective = compute_effective_membership(ordered_edges, scoping)

    _write_edges(con, ordered_edges)
    _write_effective(con, effective)

    edges_direct = sum(1 for e in ordered_edges if e.derivation == DERIVATION_LINK)
    edges_primary = sum(1 for e in ordered_edges if e.derivation == DERIVATION_PRIMARY_GROUP)
    edges_synth = sum(1 for e in ordered_edges if e.derivation == DERIVATION_SPECIAL_IDENTITY)
    run.bump_coverage(_COV_EDGES_DIRECT, edges_direct)
    run.bump_coverage(_COV_EDGES_PRIMARY, edges_primary)
    run.bump_coverage(_COV_EDGES_SYNTH, edges_synth)
    run.bump_coverage(_COV_EFFECTIVE, len(effective))

    return MembershipResult(
        member_link_base=member_link_base,
        edges_direct=edges_direct,
        edges_primarygroup=edges_primary,
        edges_synthetic=edges_synth,
        edges_total=len(ordered_edges),
        effective_pairs=len(effective),
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )
