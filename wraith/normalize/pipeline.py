"""The Module 3 normalize pipeline: ``ParsedNtds`` -> canonical DuckDB rows.

Two deterministic passes over the 2a objects (DNT order):

* **Pass A (index):** mint each object's ``node_id`` (via 2b's
  :func:`~wraith.parsing.ntds_secrets.compute_node_id`), build the
  :class:`~wraith.normalize.identity.DirectoryIndex` for DN/parent
  reconstruction, locate the ``domainDNS`` identity, and collect the GPC
  cn-GUID -> node map.
* **Pass B (emit):** classify each object, build its canonical row + its raw
  ``staging_object`` row, resolve ``gPLink`` edges, and buffer everything. Raw
  ``link_table`` rows become ``staging_link`` rows. Referenced/well-known SIDs
  with no backing object are materialized as stub Principals via
  :func:`~wraith.normalize.identity.node_id_for_sid`.

Every table buffer is sorted (nodes by ``node_id``; links by
``(link_base, source, target)``) before a single bulk ``executemany`` insert, so
identical inputs produce identical rows. All counted gaps are surfaced on the
``IngestRun`` and echoed in the returned :class:`NormalizeResult`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import fields

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.model.store import DEFAULT_SOURCE_ID, create_canonical_tables
from wraith.normalize.builders import (
    BuildContext,
    build_adcs,
    build_container,
    build_gpo,
    build_principal,
    build_staging_object,
    build_stub_principal,
    build_trust,
    resolve_gplinks,
)
from wraith.normalize.classify import (
    SKIP_NOT_MODELED,
    ClassifiedKind,
    EntityKind,
    classify,
)
from wraith.normalize.decoders import parse_gplink
from wraith.normalize.identity import (
    WELL_KNOWN_SIDS,
    WELLKNOWN_IMAGE_SHA256,
    WELLKNOWN_SOURCE_FILE,
    DirectoryIndex,
    IndexEntry,
    node_id_for_sid,
    resolve_forest_id,
    wellknown_source_object_id,
)
from wraith.normalize.models import (
    AdcsRow,
    ContainerRow,
    DomainIdentity,
    GpoRow,
    NormalizeResult,
    PrincipalRow,
    StagingLinkRow,
    StagingObjectRow,
    TrustRow,
    sort_rows_by_node_id,
)
from wraith.parsing.ntds import ParsedNtds, ParsedObject
from wraith.parsing.ntds_secrets import StoredSecretRef, compute_node_id
from wraith.parsing.ntds_values import as_list, as_scalar, decode_ntds_sid
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

# --- counter keys (surfaced on the IngestRun) --------------------------------
_COV_PRINCIPALS = "normalizer.principals"
_COV_CONTAINERS = "normalizer.containers"
_COV_GPOS = "normalizer.gpos"
_COV_TRUSTS = "normalizer.trusts"
_COV_ADCS = "normalizer.adcs"
_COV_STAGING_OBJECTS = "normalizer.staging_objects"
_COV_STAGING_LINKS = "normalizer.staging_links"
_COV_WELLKNOWN_STUBS = "normalizer.wellknown_stubs"
_SKIP_UNCLASSIFIED = "normalizer.unclassified"
_SKIP_NOT_MODELED = "normalizer.not_modeled"
#: Back-compat aggregate of the two split deleted counters below (sum).
_SKIP_DELETED = "normalizer.deleted_skipped"
#: isDeleted=TRUE but NOT isRecycled — attributes intact, recoverable later.
_SKIP_DELETED_RECOVERABLE = "normalizer.deleted_recoverable"
#: isRecycled / tombstone — most attributes stripped, not recoverable.
_SKIP_DELETED_RECYCLED = "normalizer.deleted_recycled"
_SKIP_NO_IDENTITY = "normalizer.no_identity"
_SKIP_ORPHAN_PARENT = "normalizer.orphan_parent"
_SKIP_GPLINK_DISABLED = "normalizer.gplink_disabled"
_SKIP_GPLINK_UNRESOLVED = "normalizer.gplink_unresolved"
_SKIP_MISSING_SAM = "normalizer.missing_samaccountname"
#: A staging_link whose source/target DNT resolves to no indexed node.
_SKIP_LINK_UNRESOLVED = "normalizer.link_unresolved_endpoint"


def _normalize_guid_token(value: str | None) -> str | None:
    """Lowercase + strip braces from a GPC cn GUID token (or ``None``)."""
    if not value:
        return None
    return value.strip().lstrip("{").rstrip("}").lower()


def _class_names(obj: ParsedObject, governs_to_ldap: Mapping[int, str]) -> list[str]:
    """Decode an object's ``objectClass`` (governsID ints) to class names.

    The resolver yields the chain most-derived first; unmappable ids are dropped
    (they cannot name a class). Returns ``[]`` if ``objectClass`` is absent.
    """
    names: list[str] = []
    for value in as_list(obj.attribute("objectClass", scalar=False)):
        if isinstance(value, int):
            name = governs_to_ldap.get(value)
            if name is not None:
                names.append(name)
    return names


def _deletion_state(obj: ParsedObject) -> str | None:
    """Classify an object's deletion state (DE ISSUE-1).

    Returns:
        ``None`` if live; ``"recycled"`` if ``isRecycled=TRUE`` (tombstone — most
        attributes stripped, not recoverable); ``"recoverable"`` if
        ``isDeleted=TRUE`` but not recycled (AD Recycle Bin — attributes intact).

    Failure modes:
        Never raises.
    """
    if not bool(as_scalar(obj.attribute("isDeleted", scalar=False))):
        return None
    if bool(as_scalar(obj.attribute("isRecycled", scalar=False))):
        return "recycled"
    return "recoverable"


def normalize(
    parsed: ParsedNtds,
    run: IngestRun,
    con: duckdb.DuckDBPyConnection,
    *,
    forest_id: str,
    node_secret_refs: Mapping[str, tuple[StoredSecretRef, ...]] | None = None,
    source_id: str = DEFAULT_SOURCE_ID,
) -> NormalizeResult:
    """Normalize a parsed NTDS into the canonical + staging DuckDB tables.

    Inputs:
        parsed: the gated 2a :class:`ParsedNtds` (same ``.dit``). Object/link rows
            carry their own 2a provenance; stub-node provenance is synthetic.
        run: the :class:`IngestRun` providing counters + the ``ingest_run_id``.
        con: an open canonical-store DuckDB connection (tables are created here).
        forest_id: the scoping forest id — MUST equal the ``forest_id`` passed to
            2b's ``extract_secrets`` so the ``node_secret_refs`` keys line up.
        node_secret_refs: 2b's ``node_id -> (StoredSecretRef, ...)`` map; empty if
            secrets were not extracted (secret_refs then empty).
        source_id: the multi-source ``source_id`` (contract §2.2b, schema v1.2)
            stamped on every staged object/link so each is attributed to its DC
            artifact. Defaults to the single-source sentinel
            (:data:`~wraith.model.store.DEFAULT_SOURCE_ID`) for legacy callers;
            the multi-source ingest path supplies a deterministic per-source UUID.

    Returns:
        A :class:`NormalizeResult` with per-table + per-type counts and the
        resolved :class:`DomainIdentity`.

    Memory:
        NOT streaming end-to-end — the whole DNT-ordered object list is
        materialized once (two logical passes read it), and every per-table row
        buffer is held in memory until a single sorted bulk insert. Bounded by
        one domain's object/link/SD footprint (fine at v1 single-domain scale);
        revisit for multi-forest/very-large forests (see ``01-phase0`` ceiling).

    Failure modes:
        Malformed per-object values degrade to counted gaps, never a crash.
        ``duckdb.Error`` propagates on a store failure (e.g. a DDL/row-shape
        mismatch — the writer binds exactly one param per row-dataclass field).
    """
    refs = dict(node_secret_refs or {})
    governs_to_ldap = {
        c.governs_id: c.ldap_display_name for c in parsed.schema.classes_by_ldap.values()
    }
    create_canonical_tables(con)

    # Materialize the DNT-ordered object stream once: both passes read this list
    # (deterministic; avoids a second ESE read and double-counting 2a coverage).
    objects = list(parsed.objects())

    index, gpc_cn_to_node, domain_dnt, real_sids = _pass_a_index(
        objects, forest_id, governs_to_ldap
    )

    domain_entry = index.by_dnt.get(domain_dnt) if domain_dnt is not None else None
    domain_id = domain_entry.object_sid if domain_entry is not None else None
    domain_fqdn = index.domain_fqdn_for(domain_dnt) if domain_dnt is not None else None
    identity = DomainIdentity(
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        forest_id=forest_id,
        domain_dnt=domain_dnt,
    )

    ctx = BuildContext(
        source_id=source_id,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        index=index,
        node_secret_refs=refs,
        gpc_cn_to_node=gpc_cn_to_node,
    )

    buffers = _EmitBuffers()
    referenced_sids: set[str] = set()

    # Pass B: emit entity rows + staging_object rows.
    for obj in objects:
        node_id = compute_node_id(forest_id, obj.object_guid, obj.object_sid)
        if node_id is None:
            run.bump_skip(_SKIP_NO_IDENTITY)
            continue
        class_names = _class_names(obj, governs_to_ldap)

        # Every identified object contributes a raw staging_object (SD home for M5).
        buffers.staging_objects.setdefault(
            node_id, build_staging_object(obj, node_id, class_names, ctx).to_db_values()
        )

        _collect_referenced_sids(obj, domain_id, referenced_sids)

        deletion = _deletion_state(obj)
        if deletion is not None:
            # DE ISSUE-1: split the opaque skip; keep the aggregate for continuity.
            # Recoverable deleted objects are NOT emitted as graph entities in v1
            # (documented IR-completeness gap) but their raw object is retained in
            # staging_object (written above) for later recovery.
            run.bump_skip(_SKIP_DELETED)
            if deletion == "recycled":
                run.bump_skip(_SKIP_DELETED_RECYCLED)
            else:
                run.bump_skip(_SKIP_DELETED_RECOVERABLE)
            continue

        most_derived = class_names[0] if class_names else None
        dn = index.reconstruct_dn(obj.dnt)
        kind = classify(class_names, most_derived, _sam_type(obj), dn)
        _emit_object(obj, node_id, kind, ctx, buffers, run)

    # Materialize stub Principals for referenced + well-known SIDs with no object.
    _materialize_stubs(referenced_sids, real_sids, ctx, run, buffers)

    # staging_link rows (resolved via the index).
    _emit_links(parsed, index, ctx, buffers, run)

    counts = _write_all(con, buffers)

    # Surface coverage counters on the run.
    run.bump_coverage(_COV_PRINCIPALS, counts["principal"])
    run.bump_coverage(_COV_CONTAINERS, counts["container"])
    run.bump_coverage(_COV_GPOS, counts["gpo"])
    run.bump_coverage(_COV_TRUSTS, counts["trust"])
    run.bump_coverage(_COV_ADCS, counts["adcs"])
    run.bump_coverage(_COV_STAGING_OBJECTS, counts["staging_object"])
    run.bump_coverage(_COV_STAGING_LINKS, counts["staging_link"])
    run.bump_coverage(_COV_WELLKNOWN_STUBS, buffers.stub_count)

    principal_type_counts = dict(sorted(buffers.principal_type_counts.items()))
    return NormalizeResult(
        identity=identity,
        entity_counts={
            "principal": counts["principal"],
            "container": counts["container"],
            "gpo": counts["gpo"],
            "trust": counts["trust"],
            "adcs": counts["adcs"],
        },
        principal_type_counts=principal_type_counts,
        staging_counts={
            "staging_object": counts["staging_object"],
            "staging_link": counts["staging_link"],
        },
        wellknown_stub_count=buffers.stub_count,
        coverage_counts=run.coverage_counts,
        skip_counts=run.skip_counts,
    )


class _EmitBuffers:
    """Per-table insert buffers (node tables deduped by ``node_id``)."""

    def __init__(self) -> None:
        self.principals: dict[str, tuple[object, ...]] = {}
        self.containers: dict[str, tuple[object, ...]] = {}
        self.gpos: dict[str, tuple[object, ...]] = {}
        self.trusts: dict[str, tuple[object, ...]] = {}
        self.adcs: dict[str, tuple[object, ...]] = {}
        self.staging_objects: dict[str, tuple[object, ...]] = {}
        self.staging_links: list[tuple[object, ...]] = []
        self.principal_type_counts: dict[str, int] = {}
        self.stub_count: int = 0


def _pass_a_index(
    objects: list[ParsedObject],
    forest_id: str,
    governs_to_ldap: Mapping[int, str],
) -> tuple[DirectoryIndex, dict[str, str], int | None, set[str]]:
    """Pass A: build the directory index, GPC cn map, domain dnt, real-SID set."""
    index = DirectoryIndex()
    gpc_cn_to_node: dict[str, str] = {}
    domain_dnt: int | None = None
    real_sids: set[str] = set()
    for obj in objects:
        node_id = compute_node_id(forest_id, obj.object_guid, obj.object_sid)
        class_names = frozenset(_class_names(obj, governs_to_ldap))
        rdn = _name(obj)
        index.add(
            IndexEntry(
                dnt=obj.dnt,
                parent_dnt=obj.parent_dnt,
                rdn=rdn,
                class_names=class_names,
                node_id=node_id,
                object_sid=obj.object_sid,
                object_guid=obj.object_guid,
            )
        )
        if obj.object_sid is not None and node_id is not None:
            real_sids.add(obj.object_sid)
        if "groupPolicyContainer" in class_names and node_id is not None:
            token = _normalize_guid_token(rdn)
            if token is not None:
                gpc_cn_to_node.setdefault(token, node_id)
        if "domainDNS" in class_names and obj.object_sid is not None and domain_dnt is None:
            domain_dnt = obj.dnt
    return index, gpc_cn_to_node, domain_dnt, real_sids


def _emit_object(
    obj: ParsedObject,
    node_id: str,
    kind: ClassifiedKind,
    ctx: BuildContext,
    buffers: _EmitBuffers,
    run: IngestRun,
) -> None:
    """Dispatch one classified object to its table buffer + bump counters."""
    if not ctx.index.parent_resolved(obj.dnt):
        run.bump_skip(_SKIP_ORPHAN_PARENT)

    if kind.entity is EntityKind.PRINCIPAL:
        principal = build_principal(obj, node_id, kind, ctx)
        if not kind.is_fsp and obj.sam_account_name is None and principal.principal_type != "Group":
            run.bump_skip(_SKIP_MISSING_SAM)
        if node_id not in buffers.principals:
            buffers.principals[node_id] = principal.to_db_values()
            buffers.principal_type_counts[principal.principal_type] = (
                buffers.principal_type_counts.get(principal.principal_type, 0) + 1
            )
    elif kind.entity is EntityKind.CONTAINER:
        resolution = resolve_gplinks(parse_gplink(_gplink_str(obj)), ctx.gpc_cn_to_node)
        if resolution.disabled:
            run.bump_skip(_SKIP_GPLINK_DISABLED, resolution.disabled)
        if resolution.unresolved:
            run.bump_skip(_SKIP_GPLINK_UNRESOLVED, resolution.unresolved)
        container = build_container(obj, node_id, kind, resolution.gplinks, ctx)
        buffers.containers.setdefault(node_id, container.to_db_values())
    elif kind.entity is EntityKind.GPO:
        buffers.gpos.setdefault(node_id, build_gpo(obj, node_id, ctx).to_db_values())
    elif kind.entity is EntityKind.TRUST:
        buffers.trusts.setdefault(node_id, build_trust(obj, node_id, ctx).to_db_values())
    elif kind.entity is EntityKind.ADCS:
        buffers.adcs.setdefault(node_id, build_adcs(obj, node_id, kind, ctx).to_db_values())
    else:  # SKIP (deletion is handled before classify; only these two reach here)
        if kind.skip_reason == SKIP_NOT_MODELED:
            run.bump_skip(_SKIP_NOT_MODELED)
        else:
            run.bump_skip(_SKIP_UNCLASSIFIED)


def _materialize_stubs(
    referenced_sids: set[str],
    real_sids: set[str],
    ctx: BuildContext,
    run: IngestRun,
    buffers: _EmitBuffers,
) -> None:
    """Mint stub Principals for referenced + well-known SIDs lacking an object.

    Stub provenance is SYNTHETIC (DE ISSUE-3): ``source_file`` is the synthetic
    ``WELLKNOWN_SOURCE_FILE`` and ``image_sha256`` is a deterministic non-real
    sentinel, so a well-known/FSP stub never claims the real artifact's hash.
    """
    candidate_sids = (referenced_sids | set(WELL_KNOWN_SIDS)) - real_sids
    for sid in sorted(candidate_sids):
        node_id = node_id_for_sid(ctx.forest_id, ctx.domain_id, sid)
        if node_id in buffers.principals:
            continue
        provenance = ProvenanceStruct(
            source_file=WELLKNOWN_SOURCE_FILE,
            image_sha256=WELLKNOWN_IMAGE_SHA256,
            source_object_id=wellknown_source_object_id(sid),
            directory_timestamp=None,
            ingest_run_id=run.ingest_run_id,
        )
        row = build_stub_principal(sid, node_id, provenance, ctx)
        buffers.principals[node_id] = row.to_db_values()
        buffers.principal_type_counts[row.principal_type] = (
            buffers.principal_type_counts.get(row.principal_type, 0) + 1
        )
        buffers.stub_count += 1


def _emit_links(
    parsed: ParsedNtds,
    index: DirectoryIndex,
    ctx: BuildContext,
    buffers: _EmitBuffers,
    run: IngestRun,
) -> None:
    """Build ``staging_link`` rows (raw link rows with resolved node ids)."""
    for link in parsed.links():
        source_entry = index.by_dnt.get(link.link_dnt) if link.link_dnt is not None else None
        target_entry = (
            index.by_dnt.get(link.backlink_dnt) if link.backlink_dnt is not None else None
        )
        # Surface a dangling endpoint (a present DNT that indexes to no node) as a
        # counted gap for M4 (reviewer M3) — the row is still emitted with a NULL.
        if (link.link_dnt is not None and source_entry is None) or (
            link.backlink_dnt is not None and target_entry is None
        ):
            run.bump_skip(_SKIP_LINK_UNRESOLVED)
        row = StagingLinkRow(
            link_base=link.link_base,
            source_node_id=source_entry.node_id if source_entry is not None else None,
            target_node_id=target_entry.node_id if target_entry is not None else None,
            link_dnt=link.link_dnt,
            backlink_dnt=link.backlink_dnt,
            link_deactivetime=link.link_deactivetime,
            link_deltime=link.link_deltime,
            link_usnchanged=link.link_usnchanged,
            link_ncdnt=link.link_ncdnt,
            link_data=link.link_data,
            link_metadata=link.link_metadata,
            forest_id=ctx.forest_id,
            domain_id=ctx.domain_id,
            domain_fqdn=ctx.domain_fqdn,
            provenance=link.provenance,
            source_id=ctx.source_id,
        )
        buffers.staging_links.append(row.to_db_values())


def _write_all(con: duckdb.DuckDBPyConnection, buffers: _EmitBuffers) -> dict[str, int]:
    """Bulk-insert every buffer in deterministic order; return per-table counts.

    Each table's bound-parameter count is derived from its row dataclass's field
    count (``len(fields(Row))`` == one param per column) rather than a hardcoded
    integer, so a writer/DDL/dataclass drift fails loudly at insert time
    (reviewer M5) instead of silently mis-binding.
    """
    counts: dict[str, int] = {}
    counts["principal"] = _write_node_table(
        con, "principal", len(fields(PrincipalRow)), buffers.principals
    )
    counts["container"] = _write_node_table(
        con, "container", len(fields(ContainerRow)), buffers.containers
    )
    counts["gpo"] = _write_node_table(con, "gpo", len(fields(GpoRow)), buffers.gpos)
    counts["trust"] = _write_node_table(con, "trust", len(fields(TrustRow)), buffers.trusts)
    counts["adcs"] = _write_node_table(con, "adcs", len(fields(AdcsRow)), buffers.adcs)
    counts["staging_object"] = _write_node_table(
        con, "staging_object", len(fields(StagingObjectRow)), buffers.staging_objects
    )
    counts["staging_link"] = _write_link_table(con, buffers.staging_links)
    return counts


def _write_node_table(
    con: duckdb.DuckDBPyConnection,
    table: str,
    column_count: int,
    rows_by_node: dict[str, tuple[object, ...]],
) -> int:
    """Insert a node table's buffer sorted by ``node_id`` (deterministic)."""
    if not rows_by_node:
        return 0
    ordered = sort_rows_by_node_id(list(rows_by_node.items()))
    placeholders = ",".join("?" * column_count)
    # `table` is an internal literal (never external input); values are bound params.
    con.executemany(f"INSERT INTO {table} VALUES ({placeholders})", ordered)  # noqa: S608
    return len(ordered)


def _write_link_table(con: duckdb.DuckDBPyConnection, rows: list[tuple[object, ...]]) -> int:
    """Insert ``staging_link`` rows sorted by (link_base, source, target)."""
    if not rows:
        return 0

    def key(values: tuple[object, ...]) -> tuple[int, str, str]:
        base = values[0]
        source = values[1]
        target = values[2]
        return (
            base if isinstance(base, int) else -1,
            source if isinstance(source, str) else "",
            target if isinstance(target, str) else "",
        )

    ordered = sorted(rows, key=key)
    placeholders = ",".join("?" * len(fields(StagingLinkRow)))
    sql = f"INSERT INTO staging_link VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, ordered)
    return len(ordered)


def _collect_referenced_sids(
    obj: ParsedObject, domain_id: str | None, referenced: set[str]
) -> None:
    """Collect primaryGroup + sIDHistory SID references for stub materialization."""
    primary_group = as_scalar(obj.attribute("primaryGroupID", scalar=False))
    if isinstance(primary_group, int) and domain_id:
        referenced.add(f"{domain_id}-{primary_group}")
    for value in as_list(obj.attribute("sIDHistory", scalar=False)):
        if isinstance(value, (bytes, bytearray, memoryview)):
            decoded = decode_ntds_sid(bytes(value))
            if decoded is not None:
                referenced.add(decoded)


def _name(obj: ParsedObject) -> str | None:
    """Return the object's RDN value (``name``), or ``None``."""
    value = as_scalar(obj.attribute("name", scalar=False))
    return value if isinstance(value, str) and value else None


def _gplink_str(obj: ParsedObject) -> str | None:
    """Return the raw ``gPLink`` string, or ``None``."""
    value = as_scalar(obj.attribute("gPLink", scalar=False))
    return value if isinstance(value, str) and value else None


def _sam_type(obj: ParsedObject) -> int | None:
    """Return the object's ``sAMAccountType`` int, or ``None``."""
    value = as_scalar(obj.attribute("sAMAccountType", scalar=False))
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


__all__ = [
    "DomainIdentity",
    "NormalizeResult",
    "normalize",
    "resolve_forest_id",
]
