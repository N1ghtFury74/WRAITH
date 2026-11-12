"""The Tier-B orchestrator: SYSVOL -> §4 GPO edges + §3.3 ``derived_rights``.

Given a canonical store already holding the gated M3 entities and M5 edges, and
an acquired SYSVOL tree, this pass:

1. Reuses M5 ``Contains`` + ``GPLink`` to resolve each GPO's affected computers
   (:mod:`wraith.gpo.scope`) — it does NOT recompute containment.
2. Parses each GPO's SYSVOL files (:mod:`wraith.gpo.inf_parser`,
   :mod:`wraith.gpo.preg_parser`, :mod:`wraith.gpo.gpp_parser`).
3. Emits ``AdminTo`` / ``CanRDP`` / ``ExecuteDCOM`` / ``CanPSRemote`` from
   restricted-groups + GPP (flat principal -> computer), and WRAITH-native
   ``WRAITH:<Priv>`` edges for high-value privileges held by NON-baseline
   principals. Everything is ``confidence="inferred"``.
4. Writes all ``[Privilege Rights]`` into the GPO node's ``derived_rights[]``.
5. Surfaces ``Registry.pol`` attack signals and routes any GPP ``cpassword`` to
   the encrypted secret store by reference as a redacted finding (never an edge).

OFFLINE-RSoP LIMITATION (documented, not silently resolved): WMI filters,
security filtering, block-inheritance, link precedence and enforcement CANNOT be
evaluated dead-disk. WRAITH emits the SharpHound-parity UNION of non-disabled
links — hence every edge is ``inferred``, possibly over-stating membership.
Disabled links (gPLink option bit ``0x1``) were already dropped and counted by
M3, so the ``GPLink`` edges reused here are the non-disabled set by construction.

Determinism: folders walked in sorted GUID order; edges deduped by ``edge_id``
and written sorted; ``derived_rights`` sorted per node. Identical SYSVOL + store
-> identical edges, facts, and gap counts.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import duckdb
from pydantic import SecretBytes

from wraith.case.ingest_run import IngestRun
from wraith.edges.acl import NodeResolver
from wraith.edges.models import EdgeRow
from wraith.gpo.constants import (
    HIGH_VALUE_PRIVILEGES,
    KIND_ADMIN_TO,
    LOCAL_GROUP_RID_TO_KIND,
    LOCAL_GROUP_SID_TO_KIND,
    is_baseline_privileged_sid,
)
from wraith.gpo.edges import build_local_group_edges, build_privilege_edges
from wraith.gpo.gpp_parser import decrypt_gpp_cpassword_text, parse_gpp_document
from wraith.gpo.inf_parser import parse_gpttmpl
from wraith.gpo.models import (
    GpoProcessResult,
    GppCpassword,
    GppGroup,
    GppPasswordFinding,
    GptTmplData,
    RegistrySignal,
)
from wraith.gpo.preg_parser import parse_registry_pol
from wraith.gpo.signals import signals_from_preg, signals_from_registry_values
from wraith.gpo.sysvol import PolicyFiles, discover_policy_folders, normalize_folder_guid
from wraith.model.store import create_edge_tables
from wraith.normalize.models import PrincipalRow
from wraith.provenance.models import ProvenanceStruct
from wraith.secrets.records import SecretType
from wraith.secrets.store import SecretStore

_log = logging.getLogger(__name__)

# --- coverage + skip counter keys (surfaced on the IngestRun, never silent) ---
_COV_FOLDERS = "gpo.folders_matched"
_COV_ADMIN_TO = "gpo.admin_to_edges"
_COV_LOCAL_GROUP = "gpo.local_group_edges"
_COV_PRIVILEGE = "gpo.privilege_edges"
_COV_DERIVED_RIGHTS = "gpo.derived_rights"
_COV_SIGNALS = "gpo.registry_signals"
_COV_STUBS = "gpo.stubs_minted"
_SKIP_MEMBER_NAME = "gpo.member_name_unresolved"
_SKIP_SCOPE_COMPUTER = "gpo.scope_computer_unresolved"
_SKIP_SYSVOL_MISSING = "gpo.sysvol_missing"
_SKIP_ORPHAN_FOLDER = "gpo.orphan_folder"
_SKIP_PREG_PARSE = "gpo.preg_parse_error"
_SKIP_INF_PARSE = "gpo.inf_parse_error"
_SKIP_GPP_PARSE = "gpo.gpp_parse_error"
_SKIP_GPP_SUPERSEDED = "gpo.gpp_superseded_by_restricted_groups"
_SKIP_GPP_CPASSWORD = "gpo.gpp_cpassword_finding"  # noqa: S105 - counter name, not a secret
_SKIP_FILE_READ = "gpo.file_read_error"
_SKIP_FILE_TOO_LARGE = "gpo.file_oversize"

#: Hard cap on a single SYSVOL file read (untrusted input). Real policy files are
#: a few KiB; anything past this is rejected as a counted gap, never loaded.
_MAX_SYSVOL_FILE_BYTES: int = 8 * 1024 * 1024

_COVERAGE_KEYS: frozenset[str] = frozenset(
    {
        _COV_FOLDERS,
        _COV_ADMIN_TO,
        _COV_LOCAL_GROUP,
        _COV_PRIVILEGE,
        _COV_DERIVED_RIGHTS,
        _COV_SIGNALS,
        _COV_STUBS,
    }
)


# =============================================================================
# Small helpers
# =============================================================================


def _is_sid(token: str) -> bool:
    """Return whether ``token`` looks like a canonical SID (``S-1-...``)."""
    return token.startswith("S-1-")


def local_group_kind(token: str) -> str | None:
    """Return the edge kind for a local-group token, or ``None`` if not tracked.

    Matches the full well-known alias SID first (``S-1-5-32-544`` -> AdminTo),
    then falls back to the trailing RID of an ``S-1-5-32-<RID>`` SID. Bare group
    name tokens are not resolved to a kind here (no reliable offline name->RID
    map) and yield ``None``.
    """
    kind = LOCAL_GROUP_SID_TO_KIND.get(token)
    if kind is not None:
        return kind
    if token.startswith("S-1-5-32-"):
        tail = token.rsplit("-", 1)[-1]
        if tail.isdigit():
            return LOCAL_GROUP_RID_TO_KIND.get(int(tail))
    return None


def _sysvol_relpath(sysvol_root: Path, path: Path) -> str:
    """Return a stable ``SYSVOL/...`` relative label for a file's provenance."""
    try:
        rel = path.relative_to(sysvol_root).as_posix()
    except ValueError:
        rel = path.name
    return f"SYSVOL/{rel}"


def _file_mtime(path: Path) -> datetime | None:
    """Return a file's image-filesystem mtime as tz-aware UTC (deterministic)."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None


# =============================================================================
# Topology load (reuse of M5 edges + M3 entities)
# =============================================================================


class _Topology:
    """The M3/M5 facts the pass reads (computers, Contains tree, GPO links)."""

    def __init__(
        self,
        computer_nodes: frozenset[str],
        contains_adjacency: dict[str, set[str]],
        gpo_to_containers: dict[str, list[str]],
        folder_guid_to_node: dict[str, str],
    ) -> None:
        self.computer_nodes = computer_nodes
        self.contains_adjacency = contains_adjacency
        self.gpo_to_containers = gpo_to_containers
        self.folder_guid_to_node = folder_guid_to_node


def _load_topology(con: duckdb.DuckDBPyConnection) -> _Topology:
    """Load computer nodes, the Contains tree, GPO->containers, and the GUID join."""
    from wraith.gpo.scope import build_contains_adjacency

    computer_rows: Sequence[Any] = con.execute(
        "SELECT node_id FROM principal WHERE principal_type = 'Computer'"
    ).fetchall()
    computer_nodes = frozenset(str(r[0]) for r in computer_rows)

    contains_rows: Sequence[Any] = con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = 'Contains'"
    ).fetchall()
    adjacency = build_contains_adjacency((str(r[0]), str(r[1])) for r in contains_rows)

    gplink_rows: Sequence[Any] = con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = 'GPLink' "
        "ORDER BY source_node_id, target_node_id"
    ).fetchall()
    gpo_to_containers: dict[str, list[str]] = {}
    for gpo_node, container_node in gplink_rows:
        gpo_to_containers.setdefault(str(gpo_node), []).append(str(container_node))

    gpo_rows: Sequence[Any] = con.execute(
        "SELECT node_id, gpc_file_sys_path FROM gpo ORDER BY node_id"
    ).fetchall()
    folder_guid_to_node: dict[str, str] = {}
    for node_id, gpc_path in gpo_rows:
        token = _folder_guid_from_path(gpc_path)
        if token is not None:
            folder_guid_to_node.setdefault(token, str(node_id))
    return _Topology(computer_nodes, adjacency, gpo_to_containers, folder_guid_to_node)


def _folder_guid_from_path(gpc_file_sys_path: str | None) -> str | None:
    """Extract the trailing ``{GUID}`` of a ``gPCFileSysPath`` and normalize it.

    ``\\\\dom\\SysVol\\dom\\Policies\\{6AC1786C-...}`` -> ``6ac1786c-...``.
    Returns ``None`` if no GUID-like trailing component is present.
    """
    if not gpc_file_sys_path:
        return None
    tail = gpc_file_sys_path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
    token = normalize_folder_guid(tail)
    return token or None


def _find_policies_dir(sysvol_root: Path) -> Path | None:
    """Locate the ``Policies`` directory under a SYSVOL root (case-insensitive).

    Accepts either a SYSVOL root containing ``<domain>/Policies`` or a path that
    already IS a ``Policies`` directory.
    """
    if sysvol_root.name.lower() == "policies" and sysvol_root.is_dir():
        return sysvol_root
    if not sysvol_root.is_dir():
        return None
    # SYSVOL/<domain>/Policies
    try:
        for domain_dir in sysvol_root.iterdir():
            if not domain_dir.is_dir():
                continue
            for child in domain_dir.iterdir():
                if child.is_dir() and child.name.lower() == "policies":
                    return child
    except OSError:
        return None
    return None


# =============================================================================
# Per-GPO processing state
# =============================================================================


class _PassState:
    """Mutable accumulators for one SYSVOL pass (counts, edges, facts)."""

    def __init__(
        self,
        resolver: NodeResolver,
        scoping: tuple[str, str | None, str | None],
        image_sha256: str,
        ingest_run_id: UUID,
    ) -> None:
        self.resolver = resolver
        self.scoping = scoping
        self.image_sha256 = image_sha256
        self.ingest_run_id = ingest_run_id
        self.edges: dict[str, EdgeRow] = {}
        self.derived_rights: dict[str, list[dict[str, str | None]]] = {}
        self.signals: list[RegistrySignal] = []
        self.findings: list[GppPasswordFinding] = []
        self.counts: Counter[str] = Counter()

    def add_edge(self, edge: EdgeRow) -> None:
        """Buffer one edge, deduped by ``edge_id`` (first writer wins)."""
        self.edges.setdefault(edge.edge_id, edge)

    def provenance(
        self, source_file: str, source_object_id: str, timestamp: datetime | None
    ) -> ProvenanceStruct:
        """Mint SYSVOL provenance for one fact (image hash = the SYSVOL artifact)."""
        return ProvenanceStruct(
            source_file=source_file,
            image_sha256=self.image_sha256,
            source_object_id=source_object_id,
            directory_timestamp=timestamp,
            ingest_run_id=self.ingest_run_id,
        )


# =============================================================================
# Section processors (small, focused)
# =============================================================================


def _resolve_affected(gpo_node: str, topology: _Topology) -> list[str]:
    """Return the sorted affected-computer node ids for a GPO (reused M5 scope)."""
    from wraith.gpo.scope import affected_computers

    containers = topology.gpo_to_containers.get(gpo_node, [])
    return sorted(
        affected_computers(containers, topology.contains_adjacency, topology.computer_nodes)
    )


def _process_privilege_rights(
    state: _PassState,
    gpttmpl: GptTmplData,
    gpo_node: str,
    folder_guid: str,
    source_file: str,
    timestamp: datetime | None,
    affected: list[str],
) -> None:
    """Record ALL privilege rights as derived_rights; emit high-value delta edges."""
    rights = state.derived_rights.setdefault(gpo_node, [])
    for priv in gpttmpl.privilege_rights:
        for holder in priv.holders:
            rights.append(
                {
                    "right": priv.name,
                    "target_scope": holder,
                    "source_file": source_file,
                    # schema v1.1: stamp the source SYSVOL artifact hash so each
                    # derived-rights fact is self-describing (provenance at birth).
                    "image_sha256": state.image_sha256,
                }
            )
            state.counts[_COV_DERIVED_RIGHTS] += 1
            if priv.name not in HIGH_VALUE_PRIVILEGES:
                continue
            if not _is_sid(holder):
                state.counts[_SKIP_MEMBER_NAME] += 1
                continue
            if is_baseline_privileged_sid(holder):
                continue  # already admin-equivalent -> true-negative, no edge
            if not affected:
                state.counts[_SKIP_SCOPE_COMPUTER] += 1
                continue
            holder_node = state.resolver.resolve_or_mint(holder)
            prov = state.provenance(
                source_file,
                f"{{{folder_guid}}}#[Privilege Rights]/{priv.name}",
                timestamp,
            )
            for edge in build_privilege_edges(
                holder_node, priv.name, affected, prov, state.scoping
            ):
                state.add_edge(edge)
                state.counts[_COV_PRIVILEGE] += 1


def _emit_local_group(
    state: _PassState,
    member_token: str,
    kind: str,
    gpo_node: str,
    folder_guid: str,
    section: str,
    source_file: str,
    timestamp: datetime | None,
    affected: list[str],
) -> None:
    """Resolve one member token and emit its local-group edges to all computers."""
    if not _is_sid(member_token):
        state.counts[_SKIP_MEMBER_NAME] += 1
        return
    if not affected:
        state.counts[_SKIP_SCOPE_COMPUTER] += 1
        return
    member_node = state.resolver.resolve_or_mint(member_token)
    prov = state.provenance(
        source_file,
        f"{{{folder_guid}}}#[{section}]/{kind}:{member_token}",
        timestamp,
    )
    for edge in build_local_group_edges(member_node, kind, affected, prov, state.scoping):
        state.add_edge(edge)
        state.counts[_COV_LOCAL_GROUP] += 1
        if kind == KIND_ADMIN_TO:
            state.counts[_COV_ADMIN_TO] += 1


def _process_group_membership(
    state: _PassState,
    gpttmpl: GptTmplData,
    gpo_node: str,
    folder_guid: str,
    source_file: str,
    timestamp: datetime | None,
    affected: list[str],
) -> set[str]:
    """Emit local-group edges from ``[Group Membership]``; return handled kinds.

    The returned kind set lets GPP honor Restricted-Groups-wins precedence.
    """
    handled: set[str] = set()
    for membership in gpttmpl.group_memberships:
        if membership.relation == "Members":
            kind = local_group_kind(membership.group_token)
            if kind is None:
                continue
            handled.add(kind)
            for member in membership.values:
                _emit_local_group(
                    state,
                    member,
                    kind,
                    gpo_node,
                    folder_guid,
                    "Group Membership",
                    source_file,
                    timestamp,
                    affected,
                )
        else:  # Memberof: group_token is made a member of each value (a local group)
            for value in membership.values:
                kind = local_group_kind(value)
                if kind is None:
                    continue
                handled.add(kind)
                _emit_local_group(
                    state,
                    membership.group_token,
                    kind,
                    gpo_node,
                    folder_guid,
                    "Group Membership",
                    source_file,
                    timestamp,
                    affected,
                )
    return handled


def _process_gpp_groups(
    state: _PassState,
    groups: Sequence[GppGroup],
    restricted_kinds: set[str],
    gpo_node: str,
    folder_guid: str,
    source_file: str,
    timestamp: datetime | None,
    affected: list[str],
) -> None:
    """Emit local-group edges from GPP ADD members (Restricted-Groups-wins)."""
    for group in groups:
        kind = None
        if group.group_sid:
            kind = local_group_kind(group.group_sid)
        if kind is None:
            continue
        if kind in restricted_kinds:
            state.counts[_SKIP_GPP_SUPERSEDED] += 1
            continue
        for member in group.members:
            if member.action != "ADD" or not member.sid:
                continue
            _emit_local_group(
                state,
                member.sid,
                kind,
                gpo_node,
                folder_guid,
                "GPP Groups.xml",
                source_file,
                timestamp,
                affected,
            )


def _process_cpassword(
    state: _PassState,
    cpasswords: Sequence[GppCpassword],
    gpo_node: str,
    source_file: str,
    timestamp: datetime | None,
    secret_store: SecretStore | None,
    dek: bytes | None,
    folder_guid: str,
) -> None:
    """Route each parsed GPP ``cpassword`` -> secret store by reference + finding.

    Operates on the cpasswords already extracted by :func:`parse_gpp_document`
    (the XML is parsed exactly once upstream). Never emits a graph edge and never
    logs the plaintext. If a secret store + DEK are wired, the decrypted value is
    stored and the finding carries the ``secret_id``; otherwise the finding
    records that a cpassword was present. Every finding carries full provenance
    (source file, SYSVOL image hash, source file timestamp).
    """
    for entry in cpasswords:
        state.counts[_SKIP_GPP_CPASSWORD] += 1
        secret_ref: str | None = None
        if secret_store is not None and dek is not None:
            plaintext = decrypt_gpp_cpassword_text(entry.cpassword)
            if plaintext is not None:
                secret_ref = secret_store.put_secret(
                    dek,
                    ingest_run_id=state.ingest_run_id,
                    secret_type=SecretType.CLEARTEXT,
                    node_id=gpo_node,
                    plaintext=SecretBytes(plaintext.encode("utf-8")),
                    label=f"gpp_cpassword:{folder_guid}",
                    image_sha256=state.image_sha256,
                )
        state.findings.append(
            GppPasswordFinding(
                source_file=source_file,
                user_name=entry.user_name,
                secret_ref=secret_ref,
                image_sha256=state.image_sha256,
                directory_timestamp=timestamp,
            )
        )


# =============================================================================
# Public entry point
# =============================================================================


def process_sysvol(
    con: duckdb.DuckDBPyConnection,
    run: IngestRun,
    *,
    sysvol_root: Path | str,
    sysvol_image_sha256: str,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
    secret_store: SecretStore | None = None,
    dek: bytes | None = None,
) -> GpoProcessResult:
    """Process an acquired SYSVOL into §4 GPO edges + §3.3 ``derived_rights``.

    Inputs:
        con: an open canonical store holding the gated M3 entities + M5 edges
            (the ``edge`` table with ``Contains`` / ``GPLink`` already present).
        run: the :class:`IngestRun` providing counters + the ``ingest_run_id``.
        sysvol_root: the acquired SYSVOL directory (its ``<domain>/Policies`` is
            located case-insensitively), or a ``Policies`` directory directly.
        sysvol_image_sha256: SHA-256 of the SYSVOL artifact (its own provenance,
            distinct from the ntds.dit image hash).
        forest_id/domain_id/domain_fqdn: the scoping block (MUST match M3/M5).
        secret_store/dek: optional encrypted-store wiring for GPP ``cpassword``;
            when omitted, a cpassword is still surfaced as a finding (no store).

    Returns:
        A :class:`GpoProcessResult` (counts + signals + findings; never secrets).

    Failure modes:
        ``duckdb.Error`` on a store failure / ``edge`` PK clash from re-running on
        a store that already holds these GPO edges. Malformed SYSVOL files
        degrade to counted gaps; never a crash mid-run.
    """
    create_edge_tables(con)
    root = Path(sysvol_root)
    scoping = (forest_id, domain_id, domain_fqdn)
    resolver = _load_resolver(con, run.ingest_run_id, forest_id, domain_id, domain_fqdn)
    topology = _load_topology(con)
    state = _PassState(resolver, scoping, sysvol_image_sha256, run.ingest_run_id)

    policies_dir = _find_policies_dir(root)
    folders: list[PolicyFiles] = (
        discover_policy_folders(policies_dir) if policies_dir is not None else []
    )

    seen_folder_guids: set[str] = set()
    for policy in folders:
        gpo_node = topology.folder_guid_to_node.get(policy.folder_guid)
        if gpo_node is None:
            state.counts[_SKIP_ORPHAN_FOLDER] += 1
            continue
        seen_folder_guids.add(policy.folder_guid)
        state.counts[_COV_FOLDERS] += 1
        affected = _resolve_affected(gpo_node, topology)
        _process_one_gpo(state, policy, gpo_node, root, affected, secret_store, dek)

    # GPO nodes whose SYSVOL folder is absent on disk (object in ntds, no files).
    for folder_guid, _node in topology.folder_guid_to_node.items():
        if folder_guid not in seen_folder_guids:
            state.counts[_SKIP_SYSVOL_MISSING] += 1

    _write_results(con, state)
    return _finalize(run, state)


def _process_one_gpo(
    state: _PassState,
    policy: PolicyFiles,
    gpo_node: str,
    sysvol_root: Path,
    affected: list[str],
    secret_store: SecretStore | None,
    dek: bytes | None,
) -> None:
    """Parse one GPO folder's files and emit its edges / facts / signals."""
    restricted_kinds: set[str] = set()

    if policy.gpttmpl is not None:
        raw = _read_bytes(policy.gpttmpl, state)
        if raw is not None:  # None was already counted as a read/oversize gap
            source_file = _sysvol_relpath(sysvol_root, policy.gpttmpl)
            timestamp = _file_mtime(policy.gpttmpl)
            gpttmpl = parse_gpttmpl(raw)
            if not gpttmpl.parse_ok:
                state.counts[_SKIP_INF_PARSE] += 1
            else:
                _process_privilege_rights(
                    state, gpttmpl, gpo_node, policy.folder_guid, source_file, timestamp, affected
                )
                restricted_kinds = _process_group_membership(
                    state, gpttmpl, gpo_node, policy.folder_guid, source_file, timestamp, affected
                )
                state.signals.extend(
                    signals_from_registry_values(
                        gpttmpl.registry_values, source_file, state.image_sha256, timestamp
                    )
                )

    if policy.registry_pol is not None:
        raw = _read_bytes(policy.registry_pol, state)
        if raw is not None:
            source_file = _sysvol_relpath(sysvol_root, policy.registry_pol)
            timestamp = _file_mtime(policy.registry_pol)
            result = parse_registry_pol(raw)
            if not result.ok:
                state.counts[_SKIP_PREG_PARSE] += 1
            state.signals.extend(
                signals_from_preg(result.records, source_file, state.image_sha256, timestamp)
            )

    if policy.groups_xml is not None:
        raw = _read_bytes(policy.groups_xml, state)
        if raw is not None:
            source_file = _sysvol_relpath(sysvol_root, policy.groups_xml)
            timestamp = _file_mtime(policy.groups_xml)
            document = parse_gpp_document(raw)
            if not document.parse_ok:
                # A corrupt/truncated Groups.xml is a counted gap (not silent), and
                # counted exactly once because the file was parsed exactly once.
                state.counts[_SKIP_GPP_PARSE] += 1
            else:
                _process_gpp_groups(
                    state,
                    document.groups,
                    restricted_kinds,
                    gpo_node,
                    policy.folder_guid,
                    source_file,
                    timestamp,
                    affected,
                )
                _process_cpassword(
                    state,
                    document.cpasswords,
                    gpo_node,
                    source_file,
                    timestamp,
                    secret_store,
                    dek,
                    policy.folder_guid,
                )


def _read_bytes(path: Path, state: _PassState) -> bytes | None:
    """Read a SYSVOL file's bytes with a size cap, counting any failure.

    Inputs:
        path: the SYSVOL file to read.
        state: the pass state whose counters record a read gap.

    Returns:
        The file bytes, or ``None`` when the file could not be obtained — either
        an OSError (``gpo.file_read_error``) or a size over ``_MAX_SYSVOL_FILE_BYTES``
        (``gpo.file_oversize``). A genuinely empty file returns ``b""`` (NOT a gap),
        so an unreadable file is never mistaken for a legitimately empty one.

    Failure modes:
        Never raises — every read failure becomes a counted gap and ``None``.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        _log.debug("gpo: unreadable SYSVOL file %s: %s", path.name, type(exc).__name__)
        state.counts[_SKIP_FILE_READ] += 1
        return None
    if size > _MAX_SYSVOL_FILE_BYTES:
        _log.debug("gpo: oversize SYSVOL file %s (%d bytes) skipped", path.name, size)
        state.counts[_SKIP_FILE_TOO_LARGE] += 1
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        _log.debug("gpo: unreadable SYSVOL file %s: %s", path.name, type(exc).__name__)
        state.counts[_SKIP_FILE_READ] += 1
        return None


# =============================================================================
# Resolver + writers + finalize
# =============================================================================


def _load_resolver(
    con: duckdb.DuckDBPyConnection,
    ingest_run_id: UUID,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
) -> NodeResolver:
    """Build the mint-on-miss resolver seeded from the ``principal`` table.

    Mirrors the M5 loader so a SID referenced by a GPO resolves to the same node
    as everywhere else, and a stub is minted at most once per SID.
    """
    sid_to_node: dict[str, str] = {}
    all_nodes: set[str] = set()
    rows: Sequence[Any] = con.execute(
        "SELECT node_id, object_sid FROM principal ORDER BY node_id"
    ).fetchall()
    for node_id, object_sid in rows:
        all_nodes.add(str(node_id))
        if object_sid is not None:
            sid_to_node.setdefault(str(object_sid), str(node_id))
    return NodeResolver(
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        sid_to_node=sid_to_node,
        all_nodes=all_nodes,
        ingest_run_id=ingest_run_id,
    )


def _write_results(con: duckdb.DuckDBPyConnection, state: _PassState) -> None:
    """Write minted stubs, edges (sorted), and the ``derived_rights`` updates."""
    _write_stubs(con, state.resolver.minted)
    edges = sorted(state.edges.values(), key=lambda e: e.edge_id)
    if edges:
        placeholders = ",".join("?" * len(edges[0].to_db_values()))
        sql = f"INSERT INTO edge VALUES ({placeholders})"  # noqa: S608 - fixed literal
        con.executemany(sql, [e.to_db_values() for e in edges])
    _write_derived_rights(con, state.derived_rights)


def _write_stubs(con: duckdb.DuckDBPyConnection, stubs: dict[str, PrincipalRow]) -> None:
    """Insert minted stub Principals sorted by ``node_id`` (deterministic)."""
    if not stubs:
        return
    ordered = [stubs[node_id].to_db_values() for node_id in sorted(stubs)]
    placeholders = ",".join("?" * len(ordered[0]))
    sql = f"INSERT INTO principal VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, ordered)


def _write_derived_rights(
    con: duckdb.DuckDBPyConnection, derived: dict[str, list[dict[str, str | None]]]
) -> None:
    """Fill each GPO node's ``derived_rights[]`` (sorted; append-merge with M3's)."""
    for node_id in sorted(derived):
        entries = sorted(
            derived[node_id],
            key=lambda e: (e["right"] or "", e["target_scope"] or ""),
        )
        con.execute(
            "UPDATE gpo SET derived_rights = ? WHERE node_id = ?",
            [entries, node_id],
        )


def _finalize(run: IngestRun, state: _PassState) -> GpoProcessResult:
    """Surface counters on the run and build the result object."""
    # Fold the two derived counters (stubs + signals) into the counts snapshot.
    state.counts[_COV_STUBS] = len(state.resolver.minted)
    state.counts[_COV_SIGNALS] = len(state.signals)
    for key, count in state.counts.items():
        if count <= 0:
            continue
        if key in _COVERAGE_KEYS:
            run.bump_coverage(key, count)
        else:
            run.bump_skip(key, count)
    return GpoProcessResult(
        edges_written=len(state.edges),
        admin_to_edges=state.counts[_COV_ADMIN_TO],
        privilege_edges=state.counts[_COV_PRIVILEGE],
        derived_rights_written=state.counts[_COV_DERIVED_RIGHTS],
        stubs_minted=len(state.resolver.minted),
        signals=list(state.signals),
        findings=list(state.findings),
        gpos_matched=state.counts[_COV_FOLDERS],
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )
