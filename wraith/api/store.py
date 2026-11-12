"""Read-only data-access layer over the canonical DuckDB store (M7).

Every query opens its own DuckDB *cursor* (``con.cursor()``) off one shared
read-only connection so the FastAPI threadpool can serve concurrent requests
without sharing a single cursor across threads. The store is opened READ-ONLY
(:func:`wraith.model.store.open_canonical_store_readonly`): the API never writes.

All reads are ordered deterministically (by ``node_id`` / ``edge_id`` / a total
key) so identical stores produce identical API responses (determinism rule).
Nothing here returns secret plaintext — only encrypted-store *references*.

The helper SQL unions the node id-space into one ``(node_id, kind, label,
object_sid, domain_fqdn)`` shape that the graph/search/risk layers consume as
plain typed rows. Two unions exist:

* :data:`CANONICAL_NODE_UNION_SQL` — the four attack-modeled entity tables
  (``principal`` / ``container`` / ``gpo`` / ``adcs``). These are the first-class
  graph citizens: the summary ``node_count``/kind-counts, the browse-by-type list
  and the default graph slice count/list from THIS union only.
* :data:`NODE_UNION_SQL` — the canonical union PLUS a trailing ``Base`` projection
  (research 11 Fix A) over every remaining ``staging_object`` row (not-modeled /
  infra / leaf directory objects that are nevertheless ACL/Owns edge targets). This
  is a SUPERSET of the edge id-space, so an edge endpoint never resolves to a bare
  node-id hash. It is used ONLY for on-demand resolution — ``nodes_by_ids`` (connector
  / explicit expansion / dossier-by-id) and the ``node_generic_detail`` dossier
  fallback — never for bulk enumeration or counting.

``Base`` objects are **endpoint-only + on-demand** (owner decision 2026-10-29): they
do NOT inflate the node count and do NOT bulk-populate the default canvas; a ``Base``
node renders in a slice only when it is the endpoint of an edge already included in
that slice (graph-layer materialization). This mirrors BloodHound's ``Base`` type
(structural / low attack-value) while keeping graph↔dossier consistency.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import duckdb

from wraith.api.tiering import (
    GPO_CREATOR_OWNER_SID_SUFFIX,
    TIER0_GROUP_SUFFIXES,
    TIER0_SID_SUFFIXES,
    TIER0_TARGET_SUFFIXES,
)
from wraith.merge.fold import PresentedState, presented_attribute
from wraith.model.store import open_canonical_store_readonly

#: SQL predicate selecting the ``staging_object`` rows that are NOT one of the
#: four attack-modeled entity tables — i.e. the ``Base`` id-space (research 11
#: Fix A). ``node_id`` is a NOT-NULL primary key in every table, so ``NOT IN`` is
#: null-safe. Reused by :data:`NODE_UNION_SQL` and ``node_generic_detail`` so a
#: node is a ``Base`` object in EXACTLY the same set of cases in both.
_BASE_OBJECT_EXCLUSION_SQL: str = """
node_id NOT IN (SELECT node_id FROM principal
                UNION ALL SELECT node_id FROM container
                UNION ALL SELECT node_id FROM gpo
                UNION ALL SELECT node_id FROM adcs)
"""

#: The RDN label expression for a ``Base`` / ``staging_object`` projection: the
#: ``name`` RDN attribute, then ``cn``, then the node_id as a last resort. Raw
#: NTDS attributes are serialized round-trippably, so a single-valued ``name``
#: may be stored EITHER as a JSON scalar (``"RID Set"``) OR a one-element JSON
#: array (``["ms-DFSR-RdcEnabled"]``); the ``[0]`` path unwraps the array form
#: first (it yields NULL for a scalar, falling through to the scalar path) so the
#: label is always the bare name, never a bracketed array literal. The id fallback
#: keeps the row resolvable (never NULL) but is rare — most directory objects
#: carry a ``name``. ``object_class`` is stored most-derived-first (``classify``
#: docstring), so ``object_class[1]`` (DuckDB 1-indexed) is the most-derived
#: class, surfaced on the Base dossier as its honest objectClass.
_BASE_LABEL_SQL: str = (
    "COALESCE(json_extract_string(attributes, '$.name[0]'), "
    "json_extract_string(attributes, '$.name'), "
    "json_extract_string(attributes, '$.cn[0]'), "
    "json_extract_string(attributes, '$.cn'), node_id)"
)

#: UNION of ONLY the four attack-modeled entity tables (``principal`` /
#: ``container`` / ``gpo`` / ``adcs``) into one minimal shape. This is the
#: *canonical* node id-space — the first-class graph citizens. ``kind`` is the
#: discriminator (``User``/``Computer``/``Group``/``Domain``/``OU``/``Container``/
#: ``GPO``/the ADCS types); ``label`` is the best human-readable name. Deterministic
#: order is applied by callers (``ORDER BY node_id``).
#:
#: The default node enumeration, the summary ``node_count``/kind-counts, the
#: browse-by-type list and the graph slice candidate pool all count/list from THIS
#: union only — ``Base``-projected objects (deleted/tombstone ``DEL:`` leaves, DNS
#: ``_ldap._tcp`` records, raw ACL endpoints) are deliberately excluded here so they
#: never inflate the node count or overprint the default canvas (owner decision
#: 2026-10-29). ``Base`` objects are endpoint-only + on-demand: they materialize in a
#: slice only as the endpoint of an already-included edge (see the graph layer) and
#: resolve on demand for dossiers / ``nodes_by_ids`` via :data:`NODE_UNION_SQL`.
CANONICAL_NODE_UNION_SQL: str = """
SELECT node_id, principal_type AS kind,
       COALESCE(samaccountname, display_name, distinguished_name, node_id) AS label,
       object_sid, domain_id, domain_fqdn
FROM principal
UNION ALL
SELECT node_id, container_type AS kind,
       COALESCE(distinguished_name, node_id) AS label,
       object_sid, domain_id, domain_fqdn
FROM container
UNION ALL
SELECT node_id, 'GPO' AS kind,
       COALESCE(display_name, node_id) AS label,
       NULL AS object_sid, domain_id, domain_fqdn
FROM gpo
UNION ALL
SELECT node_id, adcs_type AS kind,
       COALESCE(name, node_id) AS label,
       NULL AS object_sid, domain_id, domain_fqdn
FROM adcs
"""

#: The FULL node id-space: the canonical union PLUS a trailing ``Base`` projection
#: over every remaining ``staging_object`` row (Fix A). This is a SUPERSET of the
#: edge id-space, so any ACL/Owns edge endpoint resolves to a real node rather than a
#: bare node-id hash. It is used ONLY for on-demand resolution (``nodes_by_ids`` /
#: the ``node_generic_detail`` dossier fallback / graph endpoint materialization) —
#: never for bulk enumeration or counting (that is :data:`CANONICAL_NODE_UNION_SQL`).
NODE_UNION_SQL: str = f"""
{CANONICAL_NODE_UNION_SQL}
UNION ALL
SELECT node_id, 'Base' AS kind,
       {_BASE_LABEL_SQL} AS label,
       object_sid, domain_id, domain_fqdn
FROM staging_object
WHERE {_BASE_OBJECT_EXCLUSION_SQL}
"""


#: Hard cap on one browse-by-type page (``GET /nodes``). Every response is bounded
#: so a crafted request cannot force an unbounded result (NFR / "bounded always").
NODES_PAGE_MAX: int = 200

#: The counted-gap key incremented once per edge endpoint that resolves to no node
#: even after the ``Base`` projection (research 11 Fix B). Defined here (the lowest
#: common module) so both the dossier edge-resolution path and the graph slice
#: endpoint-materialization path count the SAME gap under one key — a truly dangling
#: id, which after Fix A should be rare/impossible, is always surfaced (counted),
#: never silently dropped and never shown as a bare node-id hash.
GAP_UNRESOLVED_EDGE_ENDPOINT: str = "dossier.unresolved_edge_endpoint"

#: Subquery yielding the node ids ONE source observed (``source_observation``,
#: ``obj_kind='node'``) — the per-source node id-space (multi-source contract §2.3,
#: M-MS2). Spliced into the read methods ONLY when a reader is source-scoped; the
#: base (unscoped) reader never references it, so the single-source path is
#: byte-identical and pays zero join overhead.
_SOURCE_NODE_IDS_SQL: str = (
    "SELECT obj_id FROM source_observation WHERE obj_kind = 'node' AND source_id = ?"
)
#: Subquery yielding the edge ids ONE source observed (``obj_kind='edge'``).
_SOURCE_EDGE_IDS_SQL: str = (
    "SELECT obj_id FROM source_observation WHERE obj_kind = 'edge' AND source_id = ?"
)

#: Counted gap (never a silent empty): a ``source_id`` addressed by a scoped read
#: matched ZERO observations (an unknown or empty source). The per-source view is
#: still returned — honestly empty — with this gap counted, per the project rule
#: "counted gap on every degraded branch".
GAP_UNKNOWN_SOURCE: str = "source.unknown_or_empty"

#: Counted gap (never a silent surface): on a ``source_id``-scoped drill-in, an edge
#: endpoint that would be MATERIALIZED belongs to a FOREIGN source (not in this
#: scope's node id-space). Pre-M-MS3 this was impossible (per-source id-spaces were
#: disjoint and no cross-source edge existed); M-MS3's cross-domain edges make a
#: scoped view's drill-in able to reach a foreign-source node, so it is dropped +
#: counted here rather than surfaced as a result row in a scoped view (contract §6).
GAP_FOREIGN_SOURCE_ENDPOINT: str = "graph.foreign_source_endpoint_scoped_out"


@dataclass(frozen=True)
class NodeRow:
    """A minimal node projection used across the graph/search/risk layers."""

    node_id: str
    kind: str
    label: str
    object_sid: str | None
    domain_id: str | None
    domain_fqdn: str | None


@dataclass(frozen=True)
class EdgeRow:
    """A minimal edge projection (attacker-direction ``source -> target``)."""

    edge_id: str
    kind: str
    source_node_id: str
    target_node_id: str
    confidence: str | None
    is_inherited: bool | None
    access_mask: int | None
    object_type_guid: str | None
    #: The edge's ``derivation`` tag (e.g. ``GPO:AdminTo`` / ``SAM:AdminTo`` /
    #: ``ACE:GenericAll``), carried so a consumer can tell a fact's ORIGIN apart —
    #: e.g. the honest ``set-admin-on-dc`` badge distinguishing GPO-derived (real
    #: SYSVOL) from host-SAM AdminTo (synthetic). Only populated by ``all_edges``;
    #: ``None`` on the narrower per-node projections that do not select it.
    derivation: str | None = None


@dataclass(frozen=True)
class Tier0Sets:
    """The resolved Tier-0 node-id sets the risk/path layers reason over.

    Keeps the two Tier-0 notions apart (gate G1/G3):

    * ``classified_ids`` — every node that IS Tier-0 (owning it is domain
      compromise): RID-suffix principals + the Domain root object + any effective
      member of a Tier-0 group. Drives the ``TIER0`` factor / high-value marking.
    * ``target_ids`` — the traversal destinations for pathfinding/reachability:
      the Tier-0 groups (-512/-519/-544/-516) + the Domain root object.
    * ``group_target_ids`` — the subset of targets that are *groups*; used for the
      H2 "no structural hop into a Tier-0 group" rule.
    * ``domain_object_ids`` — the Domain root object(s) (control of which is
      self-grant-DCSync; G1).
    * ``member_ids`` — effective members of a Tier-0 group (Tier-0 by possession;
      H1). ``gpo_creator_ids`` — GPCO group + its members (small factor; G2).
    """

    classified_ids: frozenset[str]
    target_ids: tuple[str, ...]
    group_target_ids: frozenset[str]
    domain_object_ids: frozenset[str]
    member_ids: frozenset[str]
    gpo_creator_ids: frozenset[str]
    #: The full Tier-0 classification GROUP ids (suffixes -512/-519/-544/-516/-518).
    #: This is the H2-protected set for the attack graph: a ``Contains``/``GPLink``
    #: INTO any of these groups is a false control hop and is dropped EVERYWHERE,
    #: independent of a query's target (H2 is a construction invariant). It is a
    #: superset of ``group_target_ids`` by Schema Admins (-518), which is
    #: classification-only (never a traversal target). Defaults empty so existing
    #: ``Tier0Sets`` constructors (tests) keep working.
    classification_group_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ProvenanceRow:
    """The embedded §2.3 provenance struct as returned from DuckDB."""

    source_file: str | None
    image_sha256: str | None
    source_object_id: str | None
    directory_timestamp: datetime | None
    ingest_run_id: str | None


@dataclass(frozen=True)
class CaNodeFindingRow:
    """One persisted ``ca_node_finding`` row (ESC11/ESC16/DCOM) for a dossier.

    The read projection of a CA-host node-level finding (schema v1.4). ``value`` is
    the NON-SECRET decided value (``"true"`` for ESC11/ESC16; the ``EnableDCOM=Y/N``
    summary for DCOM — never a security-descriptor byte). ``provenance`` is the
    CA-host HIVE anchor (with the registry value path as ``source_object_id``).
    """

    node_id: str
    prop: str
    value: str
    provenance: ProvenanceRow


@dataclass(frozen=True)
class NodesPageResult:
    """One bounded page of the browse-by-type node list (``GET /nodes``).

    ``rows`` is the deterministic page (at most ``limit`` rows); ``total_matched``
    is the full count under the same ``kind``/``q`` filter BEFORE paging;
    ``truncated`` is ``True`` when more rows exist beyond this page.
    """

    rows: list[NodeRow]
    total_matched: int
    truncated: bool


@dataclass(frozen=True)
class SourceRow:
    """One ``source`` dimension row + its per-source node/edge observation counts.

    The row an operator/UI reads to DISCOVER the DC artifact sets in a case
    (multi-source contract §2.2a / §5 item 3, M-MS2). ``node_count`` / ``edge_count``
    are ``COUNT(*)`` over ``source_observation`` for this ``source_id`` (one row per
    canonical node / edge the source asserted). Secrets never appear here.
    """

    source_id: str
    case_id: str
    dc_label: str
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    declared_domain: str | None
    is_global_catalog: bool | None
    node_count: int
    edge_count: int


@dataclass(frozen=True)
class LedgerCoverageRow:
    """One per-artifact coverage/skip tally from the provenance ledger (per source)."""

    source_file: str | None
    image_sha256: str | None
    coverage_counts: Mapping[str, int]
    skip_counts: Mapping[str, int]


@dataclass(frozen=True)
class DivergenceLedgerRow:
    """One ``divergence`` ledger row (multi-source contract §2.2d, M-MS4a).

    The read-side projection of a merge-fold disagreement. ``value_by_source`` /
    ``resolved_value`` are decoded from their JSON columns. For a ``secret_divergence``
    row ``value_by_source`` is ``{source: {present, differs}}`` ONLY — the fold never
    writes a digest/plaintext, so this read can never surface one.
    """

    obj_kind: str
    obj_id: str
    attribute: str | None
    divergence_type: str
    resolution: str | None
    resolved_by: str | None
    value_by_source: dict[str, Any]
    resolved_value: Any | None


def _escape_like(term: str) -> str:
    """Escape SQL ``LIKE`` wildcards so user ``%``/``_`` match literally.

    Backslash is the escape character (paired with ``ESCAPE '\\'`` in the query);
    it is escaped first so an existing backslash cannot swallow a following wildcard
    escape. Never raises.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _prov(value: object) -> ProvenanceRow:
    """Coerce a DuckDB provenance STRUCT cell into a :class:`ProvenanceRow`."""
    d = value if isinstance(value, dict) else {}
    run = d.get("ingest_run_id")
    return ProvenanceRow(
        source_file=d.get("source_file"),
        image_sha256=d.get("image_sha256"),
        source_object_id=d.get("source_object_id"),
        directory_timestamp=d.get("directory_timestamp"),
        ingest_run_id=str(run) if run is not None else None,
    )


def _json_counts(value: object) -> dict[str, int]:
    """Coerce a DuckDB JSON counts cell (str | dict | None) into ``{str: int}``.

    Ledger ``coverage_counts`` / ``skip_counts`` are JSON columns; DuckDB may return
    them as a JSON string or a native mapping. Non-int / malformed values are skipped
    (never raises) so a degraded ledger row still yields an honest partial map.
    """
    raw: object = value
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            out[str(k)] = v
    return dict(sorted(out.items()))


def _json_value(value: object) -> object:
    """Decode a DuckDB JSON cell (str | native | None) into a Python value.

    ``divergence.value_by_source`` / ``resolved_value`` are JSON columns DuckDB may
    return as a JSON string or a native structure. A ``None`` cell stays ``None``; a
    malformed string degrades to ``None`` (never raises) so a degraded ledger row
    still reads honestly rather than crashing the dossier/ledger endpoint.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


def _order_rows_by_score(
    rows: Sequence[NodeRow],
    *,
    sort: str,
    order: str,
    risk_by_id: Mapping[str, int],
    tier0_ids: frozenset[str],
) -> list[NodeRow]:
    """Order rows by risk score / tier in Python; absent values sort LAST.

    Inputs:
        rows: the candidate rows (any pre-order; this imposes a total order).
        sort: ``"risk"`` (key on ``risk_by_id``) or ``"tier"`` (key on Tier-0
            membership via ``tier0_ids``).
        order: ``"asc"`` or ``"desc"`` — applied to the score/tier value only.
        risk_by_id: node_id -> score; a node absent from the map (e.g. an
            OU/GPO/ADCS object the risk model does not score) sorts after every
            scored node, under BOTH orders.
        tier0_ids: the Tier-0 classification set; Tier-0 nodes sort ahead of
            non-Tier-0 nodes (the only non-``None`` tier value is 0).

    Returns:
        A new, totally-ordered list. Ties always break on ``node_id`` ascending so
        the result is deterministic regardless of ``order`` (never a silent
        nondeterministic tie).
    """
    desc = order == "desc"

    def key(row: NodeRow) -> tuple[int, int, str]:
        if sort == "tier":
            missing = 0 if row.node_id in tier0_ids else 1
            value = 0
        else:  # "risk"
            score = risk_by_id.get(row.node_id)
            missing = 0 if score is not None else 1
            value = score if score is not None else 0
        return (missing, -value if desc else value, row.node_id)

    return sorted(rows, key=key)


class StoreReader:
    """Thread-safe read-only accessor over one canonical store.

    Construct once per app (:meth:`open`); every method runs on a fresh cursor so
    concurrent requests do not share cursor state. The underlying file is opened
    read-only, so no method can mutate the store.
    """

    def __init__(self, con: duckdb.DuckDBPyConnection, db_path: Path) -> None:
        self._con = con
        self.db_path = db_path
        #: Counted gaps attached to the scope itself (e.g. an unknown/empty
        #: ``source_id``). Always empty on the base (unscoped) reader; populated by
        #: :class:`ScopedStoreReader`. Endpoints merge this into their response's
        #: ``counted_gaps`` so a degraded per-source scope is never a silent empty.
        self.scope_gaps: dict[str, int] = {}

    @classmethod
    def open(cls, db_path: Path | str) -> StoreReader:
        """Open the canonical store READ-ONLY.

        Inputs:
            db_path: path to an existing populated ``canonical.duckdb``.

        Returns:
            A :class:`StoreReader`.

        Failure modes:
            Raises ``FileNotFoundError`` if the store does not exist;
            ``duckdb.Error`` on a corrupt file.
        """
        path = Path(db_path)
        con = open_canonical_store_readonly(path)
        return cls(con, path)

    def close(self) -> None:
        """Close the underlying read-only connection."""
        self._con.close()

    def _rows(self, sql: str, params: Sequence[object] | None = None) -> list[tuple[Any, ...]]:
        """Run one query on a private cursor and return all rows (read-only)."""
        cur = self._con.cursor()
        try:
            return cur.execute(sql, list(params) if params is not None else []).fetchall()
        finally:
            cur.close()

    # --- per-source scoping hooks (M-MS2) -------------------------------------
    # The SINGLE scope hook every read method consults. The base reader returns
    # ``None`` -> every read builds its EXACT pre-M-MS2 SQL (byte-identical) and
    # adds no join (zero overhead on the single-source path). :class:`ScopedStoreReader`
    # overrides ONLY this one method; the predicate helpers below turn it into the
    # right ``source_observation`` / ``staging_object`` ``WHERE`` fragment per table.
    def _source_filter_id(self) -> str | None:
        """Return the ``source_id`` this reader is scoped to, or ``None`` (unscoped)."""
        return None

    def _node_pred(self, column: str) -> tuple[str, list[object]]:
        """Build ``(predicate, params)`` restricting ``column`` to the scope's nodes.

        Unscoped -> ``("", [])`` so the caller's SQL is unchanged; scoped ->
        ``("<column> IN (<source_observation node ids>)", [source_id])``. Joins to
        ``source_observation`` per the contract §2.3 (``WHERE source_id = ?`` over
        ``obj_id``). Never orders by ``source_id`` (determinism).
        """
        sid = self._source_filter_id()
        if sid is None:
            return "", []
        return f"{column} IN ({_SOURCE_NODE_IDS_SQL})", [sid]

    def _edge_pred(self, column: str) -> tuple[str, list[object]]:
        """Build ``(predicate, params)`` restricting ``column`` to the scope's edges."""
        sid = self._source_filter_id()
        if sid is None:
            return "", []
        return f"{column} IN ({_SOURCE_EDGE_IDS_SQL})", [sid]

    def _staging_pred(self) -> tuple[str, list[object]]:
        """Build ``(predicate, params)`` restricting ``staging_object`` to the source.

        ``Base``-projected leaves are NOT in ``source_observation`` (M-MS1 registers
        only canonical nodes + edges), so a direct ``Base`` dossier entry is bound to
        its source via ``staging_object.source_id`` instead — the one place a leaf's
        source attribution lives. Unscoped -> ``("", [])``.
        """
        sid = self._source_filter_id()
        if sid is None:
            return "", []
        return "source_id = ?", [sid]

    # --- identity / summary ---------------------------------------------------
    def domain_identity(self) -> tuple[str | None, str | None, int | None]:
        """Return ``(domain_id, domain_fqdn, functional_level)`` for the real domain.

        Picks the ``container_type='Domain'`` row that carries an ``object_sid``
        (the two DNS application partitions are SID-less Domain rows and are
        skipped). Returns ``(None, None, None)`` if no domain row exists.
        """
        rows = self._rows(
            "SELECT domain_id, domain_fqdn, functional_level FROM container "
            "WHERE container_type='Domain' AND object_sid IS NOT NULL "
            "ORDER BY node_id LIMIT 1"
        )
        if not rows:
            return (None, None, None)
        return (rows[0][0], rows[0][1], rows[0][2])

    def node_kind_counts(self) -> dict[str, int]:
        """Return a deterministic ``kind -> count`` map over the canonical nodes.

        Counts ONLY the four attack-modeled entity tables
        (:data:`CANONICAL_NODE_UNION_SQL`); ``Base``-projected ``staging_object``
        leaves are endpoint-only + on-demand and are deliberately excluded so the
        summary breakdown matches :meth:`node_count` (owner decision 2026-10-29).
        """
        pred, p = self._node_pred("node_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(
            f"SELECT kind, count(*) FROM ({CANONICAL_NODE_UNION_SQL}) t{where} "
            f"GROUP BY kind ORDER BY kind",
            p,
        )
        return {str(r[0]): int(r[1]) for r in rows}

    def edge_kind_counts(self) -> dict[str, int]:
        """Return a deterministic ``kind -> count`` map over the edge table."""
        pred, p = self._edge_pred("edge_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(f"SELECT kind, count(*) FROM edge{where} GROUP BY kind ORDER BY kind", p)
        return {str(r[0]): int(r[1]) for r in rows}

    def node_count(self) -> int:
        """Total count of canonical nodes (the summary headline count).

        Counts ONLY the four attack-modeled entity tables
        (:data:`CANONICAL_NODE_UNION_SQL`). ``Base``-projected ``staging_object``
        leaves are endpoint-only + on-demand and MUST NOT inflate this count (owner
        decision 2026-10-29): they render in a slice only as an edge endpoint and
        resolve on demand for dossiers, never via bulk enumeration.
        """
        pred, p = self._node_pred("node_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(f"SELECT count(*) FROM ({CANONICAL_NODE_UNION_SQL}) t{where}", p)
        return int(rows[0][0])

    def edge_count(self) -> int:
        """Total edge count."""
        pred, p = self._edge_pred("edge_id")
        where = f" WHERE {pred}" if pred else ""
        return int(self._rows(f"SELECT count(*) FROM edge{where}", p)[0][0])

    # --- node projections -----------------------------------------------------
    def canonical_nodes(self) -> list[NodeRow]:
        """Return the canonical nodes (minimal projection) ordered by ``node_id``.

        The first-class graph citizens only — the four attack-modeled entity tables
        (:data:`CANONICAL_NODE_UNION_SQL`), WITHOUT the ``Base`` projection. This is
        the candidate pool for the default graph slice and the browse-by-type list;
        ``Base`` objects enter a slice only as the endpoint of an already-included
        edge (graph-layer materialization), never in bulk (owner decision
        2026-10-29). Deterministically ordered; never raises on content.

        When the reader is source-scoped (M-MS2) the pool is restricted to the
        canonical nodes THAT source observed (``source_observation`` join); the
        unscoped reader is byte-identical to the pre-M-MS2 query.
        """
        pred, p = self._node_pred("node_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id, kind, label, object_sid, domain_id, domain_fqdn "
            f"FROM ({CANONICAL_NODE_UNION_SQL}) t{where} ORDER BY node_id",
            p,
        )
        return [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def all_nodes(self) -> list[NodeRow]:
        """Return every node in the FULL id-space (incl. ``Base``) by ``node_id``.

        This is the superset projection (:data:`NODE_UNION_SQL`): the canonical
        entities PLUS every ``Base``-projected ``staging_object`` leaf. Used where a
        complete id -> (kind, label) resolution is required for arbitrary edge
        endpoints (e.g. the connector's intermediate-label map), so a chain through a
        ``Base`` object is never mislabeled. For bulk ENUMERATION / COUNTING use
        :meth:`canonical_nodes` / :meth:`node_count` instead — those exclude ``Base``.
        """
        rows = self._rows(
            f"SELECT node_id, kind, label, object_sid, domain_id, domain_fqdn "
            f"FROM ({NODE_UNION_SQL}) t ORDER BY node_id"
        )
        return [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def nodes_by_ids(self, node_ids: Sequence[str]) -> list[NodeRow]:
        """Return the minimal projections for ``node_ids`` ordered by ``node_id``.

        Pure RESOLVER — intentionally NOT source-scoped even on a
        :class:`ScopedStoreReader` (M-MS2). It only resolves ids that are already
        within the source's scope by construction (endpoints of already-scoped edges,
        explicit seeds), and ``node_id`` is globally unique with one canonical row, so
        resolving against the full id-space yields identical labels with zero cross-
        source bleed — and crucially keeps a scoped view's ``Base`` edge endpoints
        (absent from ``source_observation``) resolvable, preserving single-source
        parity. Scoping the CANDIDATE POOL (``canonical_nodes``) + the EDGE id-space
        (``all_edges``) is what makes a per-source view exact; this method only labels.
        """
        if not node_ids:
            return []
        placeholders = ",".join("?" for _ in node_ids)
        rows = self._rows(
            f"SELECT node_id, kind, label, object_sid, domain_id, domain_fqdn "
            f"FROM ({NODE_UNION_SQL}) t WHERE node_id IN ({placeholders}) ORDER BY node_id",
            list(node_ids),
        )
        return [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def in_scope_node_ids(self, node_ids: Sequence[str]) -> set[str]:
        """Return the subset of ``node_ids`` that is WITHIN this reader's scope.

        The base (unscoped) reader returns ALL of ``node_ids`` unchanged — a true
        no-op with zero overhead, so the single-source path is byte-identical.
        A :class:`ScopedStoreReader` returns only the ids this source actually
        observed: the per-source canonical nodes (``source_observation``,
        ``obj_kind='node'``) UNION this source's ``Base`` leaves
        (``staging_object.source_id``). It is the scope gate for graph
        materialization: on a cross-source drill-in, a FOREIGN-source endpoint
        (absent from both) is excluded here so a scoped view never surfaces it as a
        result row (contract §6, M-MS3). ``nodes_by_ids`` stays an unscoped pure
        LABELLER; this method is the scope DECISION it must be filtered through.

        Inputs:
            node_ids: candidate ids (e.g. edge endpoints to materialize).

        Returns:
            The in-scope subset (all of them on the unscoped reader).

        Failure modes:
            Never raises on content.
        """
        ids = list(node_ids)
        if not ids:
            return set()
        sid = self._source_filter_id()
        if sid is None:
            return set(ids)
        placeholders = ",".join("?" for _ in ids)
        rows = self._rows(
            f"SELECT obj_id FROM source_observation "
            f"WHERE obj_kind = 'node' AND source_id = ? AND obj_id IN ({placeholders}) "
            f"UNION "
            f"SELECT node_id FROM staging_object "
            f"WHERE source_id = ? AND node_id IN ({placeholders})",
            [sid, *ids, sid, *ids],
        )
        return {str(r[0]) for r in rows}

    def all_edges(self) -> list[EdgeRow]:
        """Return every edge (minimal projection) in a total deterministic order.

        When the reader is source-scoped (M-MS2) only the edges THAT source observed
        are returned (``source_observation`` join on ``edge_id``); the unscoped reader
        is byte-identical to the pre-M-MS2 query. This is the edge id-space that makes
        a per-source graph slice / risk pass / hunt exact.
        """
        pred, p = self._edge_pred("edge_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(
            f"SELECT edge_id, kind, source_node_id, target_node_id, confidence, "
            f"is_inherited, access_mask, object_type_guid, derivation FROM edge{where} "
            f"ORDER BY source_node_id, target_node_id, kind, edge_id",
            p,
        )
        return [EdgeRow(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]) for r in rows]

    def search(self, query: str, limit: int) -> list[NodeRow]:
        """Case-insensitive search over name / SID / sAMAccountName / UPN / DN.

        Matches a substring against the principal natural keys and the union
        label; results are ordered by ``node_id`` for determinism and capped at
        ``limit``. Never raises on an empty/odd query — returns an empty list.
        """
        q = (query or "").strip()
        if not q:
            return []
        like = f"%{_escape_like(q.lower())}%"
        pred, sp = self._node_pred("node_id")
        scope_sql = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"""
            SELECT node_id, kind, label, object_sid, domain_id, domain_fqdn FROM (
              SELECT node_id, principal_type AS kind,
                     COALESCE(samaccountname, display_name, distinguished_name, node_id) AS label,
                     object_sid, domain_id, domain_fqdn,
                     lower(COALESCE(samaccountname,'')||' '||COALESCE(upn,'')||' '||
                           COALESCE(object_sid,'')||' '||COALESCE(display_name,'')||' '||
                           COALESCE(distinguished_name,'')||' '||node_id) AS hay
              FROM principal
              UNION ALL
              SELECT node_id, container_type AS kind,
                     COALESCE(distinguished_name, node_id) AS label,
                     object_sid, domain_id, domain_fqdn,
                     lower(COALESCE(distinguished_name,'')||' '||COALESCE(object_sid,'')||' '||
                           node_id) AS hay
              FROM container
              UNION ALL
              SELECT node_id, 'GPO' AS kind, COALESCE(display_name, node_id) AS label,
                     NULL, domain_id, domain_fqdn,
                     lower(COALESCE(display_name,'')||' '||node_id) AS hay
              FROM gpo
              UNION ALL
              SELECT node_id, adcs_type AS kind, COALESCE(name, node_id) AS label,
                     NULL, domain_id, domain_fqdn,
                     lower(COALESCE(name,'')||' '||node_id) AS hay
              FROM adcs
            ) t
            WHERE hay LIKE ? ESCAPE '\\'{scope_sql}
            ORDER BY node_id
            LIMIT ?
            """,
            [like, *sp, limit],
        )
        return [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def _nodes_filter(self, kind: str | None, q: str | None) -> tuple[list[str], list[object]]:
        """Build the shared ``WHERE`` clauses + params for the node-browse filter.

        ``kind`` becomes an exact ``kind = ?``; a non-blank ``q`` becomes a
        case-insensitive substring over ``label`` and ``object_sid`` (``LIKE`` with
        wildcards escaped, paired with ``ESCAPE '\\'``). Never raises.
        """
        where: list[str] = []
        params: list[object] = []
        if kind:
            where.append("kind = ?")
            params.append(kind)
        term = (q or "").strip()
        if term:
            like = f"%{_escape_like(term.lower())}%"
            where.append(
                "(lower(label) LIKE ? ESCAPE '\\' "
                "OR lower(COALESCE(object_sid,'')) LIKE ? ESCAPE '\\')"
            )
            params.extend([like, like])
        return where, params

    def nodes_page(
        self,
        *,
        kind: str | None = None,
        q: str | None = None,
        sort: str = "name",
        order: str = "asc",
        limit: int = 50,
        offset: int = 0,
        risk_by_id: Mapping[str, int] | None = None,
        tier0_ids: frozenset[str] = frozenset(),
    ) -> NodesPageResult:
        """Return one bounded, deterministic page of the browse-by-type node list.

        Lists ONLY the canonical nodes (:data:`CANONICAL_NODE_UNION_SQL`);
        ``Base``-projected ``staging_object`` leaves are endpoint-only + on-demand and
        are never bulk-listed here (owner decision 2026-10-29), so a ``kind="Base"``
        filter yields an empty page by design.

        Inputs:
            kind: keep only this node ``kind`` (e.g. ``User``/``Group``/``GPO``);
                all kinds if ``None``.
            q: optional case-insensitive substring over label / object_sid
                (wildcards escaped). Blank/``None`` disables the filter.
            sort: ``"name"``/``"kind"`` are ordered in SQL; ``"risk"``/``"tier"`` are
                ordered in Python via :func:`_order_rows_by_score` over
                ``risk_by_id``/``tier0_ids``. Any other value falls back to
                ``"name"`` (never raises on an odd sort).
            order: ``"asc"`` (default) or ``"desc"``; anything else is ``"asc"``.
            limit: page size, clamped to ``[1, NODES_PAGE_MAX]``.
            offset: rows to skip, clamped to ``>= 0``.
            risk_by_id: node_id -> risk score (the shared scored map); used ONLY to
                order ``sort="risk"``. Nodes absent from it sort last.
            tier0_ids: the Tier-0 classification set; used ONLY to order
                ``sort="tier"``.

        Returns:
            A :class:`NodesPageResult` (page rows, ``total_matched``, ``truncated``).

        Failure modes:
            Never raises on content. ``sort``/``order`` are mapped through a fixed
            whitelist before interpolation, so no caller value reaches SQL (no
            injection). An out-of-range ``offset`` simply yields an empty page.
        """
        limit = max(1, min(int(limit), NODES_PAGE_MAX))
        offset = max(0, int(offset))
        where, params = self._nodes_filter(kind, q)
        # Append the per-source scope predicate (M-MS2) LAST so its ``?`` param
        # follows the kind/q filter params positionally; unscoped -> no-op (the SQL
        # and params are byte-identical to the pre-M-MS2 page).
        scope_pred, scope_params = self._node_pred("node_id")
        if scope_pred:
            where = [*where, scope_pred]
            params = [*params, *scope_params]
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        projection = "SELECT node_id, kind, label, object_sid, domain_id, domain_fqdn"

        if sort in ("risk", "tier"):
            # The sort key is not a SQL column: fetch all matched rows (minimal
            # projection, bounded by the kind filter), order in Python, then page.
            raw = self._rows(
                f"{projection} FROM ({CANONICAL_NODE_UNION_SQL}) t{where_sql} ORDER BY node_id",
                params,
            )
            all_rows = [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in raw]
            ordered = _order_rows_by_score(
                all_rows,
                sort=sort,
                order=order,
                risk_by_id=risk_by_id or {},
                tier0_ids=tier0_ids,
            )
            total = len(ordered)
            page = ordered[offset : offset + limit]
            return NodesPageResult(rows=page, total_matched=total, truncated=offset + limit < total)

        # name / kind -> SQL ordering + paging. Fetch limit+1 to detect a next page
        # without a second count; the deterministic tie-break is always node_id asc.
        col = "kind" if sort == "kind" else "lower(label)"
        dir_sql = "DESC" if order == "desc" else "ASC"
        raw = self._rows(
            f"{projection} FROM ({CANONICAL_NODE_UNION_SQL}) t{where_sql} "
            f"ORDER BY {col} {dir_sql}, node_id ASC LIMIT ? OFFSET ?",
            [*params, limit + 1, offset],
        )
        rows = [NodeRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in raw]
        truncated = len(rows) > limit
        rows = rows[:limit]
        count = self._rows(
            f"SELECT count(*) FROM ({CANONICAL_NODE_UNION_SQL}) t{where_sql}", params
        )
        return NodesPageResult(rows=rows, total_matched=int(count[0][0]), truncated=truncated)

    # --- dossier reads --------------------------------------------------------
    def principal_detail(self, node_id: str) -> dict[str, object] | None:
        """Return the full ``principal`` row as a dict, or ``None`` if not a principal.

        On a :class:`ScopedStoreReader` (M-MS2) a principal NOT observed by the scope's
        source returns ``None`` (the dossier entry 404s) — a per-source dossier shows
        only that source's objects. Unscoped: byte-identical to the pre-M-MS2 query.
        """
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"""
            SELECT node_id, object_sid, object_guid, principal_type, samaccountname, upn,
                   distinguished_name, display_name, description, uac_flags, enabled,
                   admincount, spns, sid_history, primary_group_id, pwd_last_set,
                   last_logon_timestamp, when_created, when_changed, secret_refs,
                   behavior_summary_ref, forest_id, domain_id, domain_fqdn, provenance
            FROM principal WHERE node_id = ?{tail}
            """,
            [node_id, *p],
        )
        if not rows:
            return None
        r = rows[0]
        return {
            "node_id": r[0],
            "object_sid": r[1],
            "object_guid": r[2],
            "principal_type": r[3],
            "samaccountname": r[4],
            "upn": r[5],
            "distinguished_name": r[6],
            "display_name": r[7],
            "description": r[8],
            "uac_flags": r[9],
            "enabled": r[10],
            "admincount": r[11],
            "spns": list(r[12] or []),
            "sid_history": list(r[13] or []),
            "primary_group_id": r[14],
            "pwd_last_set": r[15],
            "last_logon_timestamp": r[16],
            "when_created": r[17],
            "when_changed": r[18],
            "secret_refs": list(r[19] or []),
            "behavior_summary_ref": r[20],
            "forest_id": r[21],
            "domain_id": r[22],
            "domain_fqdn": r[23],
            "provenance": _prov(r[24]),
        }

    def node_generic_detail(self, node_id: str) -> dict[str, object] | None:
        """Return the minimal projection + provenance for a non-principal node.

        Checks ``container`` / ``gpo`` / ``adcs`` in turn, then falls back to a
        ``Base`` projection over ``staging_object`` (research 11 Fix A) for a
        not-modeled / infra / leaf directory object that is nonetheless an
        ACL/Owns edge target. The ``Base`` branch returns ``kind="Base"`` (so the
        UI treats it as structural / low attack-value), the RDN ``name`` as the
        label, and the most-derived ``object_class`` under ``object_class`` so the
        dossier can honestly state what the object actually is.

        Returns ``None`` only if the node id is unknown in EVERY table (including
        ``staging_object``) — a genuinely dangling id, handled by the caller as a
        counted gap rather than a silent empty answer.
        """
        pred, pp = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        for table, label_expr, kind_expr in (
            ("container", "COALESCE(distinguished_name, node_id)", "container_type"),
            ("gpo", "COALESCE(display_name, node_id)", "'GPO'"),
            ("adcs", "COALESCE(name, node_id)", "adcs_type"),
        ):
            rows = self._rows(
                f"SELECT node_id, {kind_expr} AS kind, {label_expr} AS label, object_guid, "
                f"domain_id, domain_fqdn, provenance FROM {table} WHERE node_id = ?{tail}",
                [node_id, *pp],
            )
            if rows:
                r = rows[0]
                return {
                    "node_id": r[0],
                    "kind": r[1],
                    "label": r[2],
                    "object_guid": r[3],
                    "domain_id": r[4],
                    "domain_fqdn": r[5],
                    "provenance": _prov(r[6]),
                }

        # ``Base`` leaves are absent from ``source_observation`` (M-MS1 registers only
        # canonical nodes/edges), so a scoped ``Base`` dossier entry is bound to its
        # source via ``staging_object.source_id`` (M-MS2). Unscoped: byte-identical.
        spred, sp = self._staging_pred()
        stail = f" AND {spred}" if spred else ""
        base = self._rows(
            f"SELECT node_id, 'Base' AS kind, {_BASE_LABEL_SQL} AS label, object_guid, "
            f"domain_id, domain_fqdn, provenance, object_class[1] AS object_class "
            f"FROM staging_object WHERE node_id = ? AND {_BASE_OBJECT_EXCLUSION_SQL}{stail}",
            [node_id, *sp],
        )
        if base:
            r = base[0]
            return {
                "node_id": r[0],
                "kind": r[1],
                "label": r[2],
                "object_guid": r[3],
                "domain_id": r[4],
                "domain_fqdn": r[5],
                "provenance": _prov(r[6]),
                "object_class": r[7],
            }
        return None

    def inbound_edges(self, node_id: str) -> list[EdgeRow]:
        """Return edges whose ``target_node_id == node_id`` (who can control it).

        Source-scoped (M-MS2): restricted to edges the scope's source observed;
        unscoped: byte-identical to the pre-M-MS2 query.
        """
        pred, p = self._edge_pred("edge_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT edge_id, kind, source_node_id, target_node_id, confidence, is_inherited, "
            f"access_mask, object_type_guid FROM edge WHERE target_node_id = ?{tail} "
            f"ORDER BY kind, source_node_id, edge_id",
            [node_id, *p],
        )
        return [EdgeRow(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]) for r in rows]

    def outbound_edges(self, node_id: str) -> list[EdgeRow]:
        """Return edges whose ``source_node_id == node_id`` (what it can control).

        Source-scoped (M-MS2): restricted to edges the scope's source observed;
        unscoped: byte-identical to the pre-M-MS2 query.
        """
        pred, p = self._edge_pred("edge_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT edge_id, kind, source_node_id, target_node_id, confidence, is_inherited, "
            f"access_mask, object_type_guid FROM edge WHERE source_node_id = ?{tail} "
            f"ORDER BY kind, target_node_id, edge_id",
            [node_id, *p],
        )
        return [EdgeRow(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]) for r in rows]

    def ca_node_findings(self, node_id: str) -> list[CaNodeFindingRow]:
        """Return the CA-host node-level findings (ESC11/ESC16/DCOM) for ``node_id``.

        Reads the additive ``ca_node_finding`` table (schema v1.4): ESC11/ESC16 for
        an EnterpriseCA node, the DCOM summary for a CA host Computer node. Ordered
        deterministically by ``prop``. A node with no finding simply yields ``[]``
        (NOT a gap). A store that never provisioned the table (built without a
        CA-host hive, or a pre-v1.4 store) degrades to ``[]`` via the ``duckdb.Error``
        guard — never raising, keeping every non-CA dossier unaffected.

        Not source-scoped: ``node_id`` is globally unique with one canonical finding
        set, and this is only called for a node the dossier already resolved as
        in-scope (same rationale as :meth:`nodes_by_ids`). No secret is ever
        returned — ``value`` is the ``Y/N`` DCOM summary / ``"true"`` flag only.

        Inputs:
            node_id: the EnterpriseCA / CA host Computer node id to read findings for.

        Returns:
            The typed finding rows (``[]`` when none / table absent).

        Failure modes:
            Never raises on content; a missing table degrades to ``[]``.
        """
        try:
            rows = self._rows(
                "SELECT node_id, prop, value, provenance FROM ca_node_finding "
                "WHERE node_id = ? ORDER BY prop",
                [node_id],
            )
        except duckdb.Error:
            return []
        return [
            CaNodeFindingRow(
                node_id=str(r[0]),
                prop=str(r[1]),
                value=str(r[2]),
                provenance=_prov(r[3]),
            )
            for r in rows
        ]

    def effective_groups_of(self, node_id: str) -> list[str]:
        """Return the group node ids a node is an effective member of (closure).

        Source-scoped (M-MS2): the groups are restricted to those the scope's source
        observed (a group can only be shown in a per-source view if that source
        asserted it); unscoped: byte-identical. ``effective_membership`` itself is not
        source-partitioned (M4 closure, single-PK), so the scope is applied on the
        resolved ``group_node_id`` against ``source_observation`` — a no-op in the
        single-source case (every group has exactly one observation).
        """
        pred, p = self._node_pred("group_node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT group_node_id FROM effective_membership WHERE member_node_id = ?{tail} "
            f"ORDER BY group_node_id",
            [node_id, *p],
        )
        return [str(r[0]) for r in rows]

    def tier0_node_ids(self, rid_suffixes: Sequence[str] = TIER0_SID_SUFFIXES) -> list[str]:
        """Return node ids whose ``object_sid`` ends in a Tier-0 RID suffix.

        Covers principals (groups like Domain Admins -512) and the domain row.
        Deterministically ordered. ``rid_suffixes`` are e.g. ``("-512","-519",...)``.
        """
        if not rid_suffixes:
            return []
        conds = " OR ".join("object_sid LIKE ?" for _ in rid_suffixes)
        params: list[object] = [f"%{s}" for s in rid_suffixes]
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id FROM ("
            f"  SELECT node_id, object_sid FROM principal"
            f"  UNION ALL SELECT node_id, object_sid FROM container"
            f") t WHERE object_sid IS NOT NULL AND ({conds}){tail} ORDER BY node_id",
            [*params, *p],
        )
        return [str(r[0]) for r in rows]

    def group_node_ids_by_samaccountname(self, name: str) -> list[str]:
        """Return group principal node ids whose ``sAMAccountName`` equals ``name``.

        Case-insensitive exact match, restricted to ``principal_type='Group'``.
        Backs the DnsAdmins resolver (doc 20 §7/§8): DnsAdmins has no fixed RID (it
        is created on DNS-role install), so it is resolved by NAME rather than by a
        SID suffix. The name-match carries a small collision/locale risk, so the
        caller counts an absent group as a gap. Deterministically ordered.

        Inputs:
            name: the ``sAMAccountName`` to match (e.g. ``"DnsAdmins"``).

        Returns:
            The matching group node ids (``[]`` if none / blank name).

        Failure modes:
            Never raises on content.
        """
        term = (name or "").strip()
        if not term:
            return []
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id FROM principal "
            f"WHERE principal_type='Group' AND lower(samaccountname) = lower(?){tail} "
            f"ORDER BY node_id",
            [term, *p],
        )
        return [str(r[0]) for r in rows]

    def domain_object_node_ids(self) -> list[str]:
        """Return the Domain root object node id(s) — ``container_type='Domain'``.

        The Domain root object carries the bare domain SID (no RID suffix) yet is
        Tier-0: WriteDacl/GenericAll/Owns on it self-grants DCSync (gate G1). The
        SID-less ``Domain`` rows (the two DNS application partitions) are excluded.
        Deterministically ordered. Never raises.
        """
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id FROM container WHERE container_type='Domain' "
            f"AND object_sid IS NOT NULL{tail} ORDER BY node_id",
            p,
        )
        return [str(r[0]) for r in rows]

    def effective_members_of(self, group_node_ids: Sequence[str]) -> list[str]:
        """Return the effective member node ids of ANY of ``group_node_ids``.

        Reads the M4 ``effective_membership`` closure (never re-expanded here).
        Deterministically ordered, de-duplicated. Empty input -> empty list.
        Never raises on content.
        """
        ids = sorted(set(group_node_ids))
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        # Source-scoped (M-MS2): only members the scope's source observed (no-op in
        # the single-source case). ``effective_membership`` is not source-partitioned,
        # so the scope is applied on the resolved ``member_node_id``.
        pred, p = self._node_pred("member_node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT DISTINCT member_node_id FROM effective_membership "
            f"WHERE group_node_id IN ({placeholders}){tail} ORDER BY member_node_id",
            [*ids, *p],
        )
        return [str(r[0]) for r in rows]

    def tier0_sets(self) -> Tier0Sets:
        """Resolve the Tier-0 classification/target/member sets (gates G1/G2/G3/H1/H2).

        Returns a :class:`Tier0Sets`:

        * ``group_target_ids`` = RID-suffix groups in :data:`TIER0_TARGET_SUFFIXES`
          (all of which are groups); ``target_ids`` = those + the Domain object.
        * ``classified_ids`` = RID-suffix principals in :data:`TIER0_SID_SUFFIXES`
          + the Domain object + effective members of a Tier-0 group.
        * ``member_ids`` = effective members of a Tier-0 group (H1).
        * ``gpo_creator_ids`` = the -520 group + its effective members (G2).
        * ``classification_group_ids`` = RID-suffix groups in
          :data:`TIER0_GROUP_SUFFIXES` (= ``group_target_ids`` + Schema Admins -518)
          — the H2-protected group set for the attack graph (H2 construction
          invariant, independent of a query's target; -518 is H2-protected yet never
          a traversal target, G3).

        Pure projection over the store; never returns secrets; never raises.
        """
        suffix_classified = self.tier0_node_ids(TIER0_SID_SUFFIXES)
        group_targets = self.tier0_node_ids(TIER0_TARGET_SUFFIXES)
        classification_groups = self.tier0_node_ids(TIER0_GROUP_SUFFIXES)
        domain_objects = self.domain_object_node_ids()
        member_ids = self.effective_members_of(suffix_classified)
        gpco_groups = self.tier0_node_ids((GPO_CREATOR_OWNER_SID_SUFFIX,))
        gpco_ids = sorted(set(gpco_groups) | set(self.effective_members_of(gpco_groups)))

        classified = set(suffix_classified) | set(domain_objects) | set(member_ids)
        targets = sorted(set(group_targets) | set(domain_objects))
        return Tier0Sets(
            classified_ids=frozenset(classified),
            target_ids=tuple(targets),
            group_target_ids=frozenset(group_targets),
            domain_object_ids=frozenset(domain_objects),
            member_ids=frozenset(member_ids),
            gpo_creator_ids=frozenset(gpco_ids),
            classification_group_ids=frozenset(classification_groups),
        )

    def domain_risk_inputs(self) -> list[dict[str, object]]:
        """Return the Domain root object(s) in the risk-input dict shape.

        The Domain object is a ``container`` (not a ``principal``) yet is the #1
        high-value Tier-0 target, so the risk model scores it too (gate G1). All
        principal-only fields (uac/spns/...) are absent, so only Tier-0 /
        inbound-control factors can fire. Deterministically ordered. Never raises.
        """
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id, object_sid, "
            f"COALESCE(distinguished_name, node_id) AS label, domain_fqdn "
            f"FROM container WHERE container_type='Domain' AND object_sid IS NOT NULL{tail} "
            f"ORDER BY node_id",
            p,
        )
        return [
            {
                "node_id": r[0],
                "principal_type": "Domain",
                "object_sid": r[1],
                "samaccountname": None,
                "uac_flags": None,
                "enabled": None,
                "spns": [],
                "sid_history": [],
                "admincount": None,
                "label": r[2],
                "domain_fqdn": r[3],
            }
            for r in rows
        ]

    def node_id_by_sid(self, object_sid: str) -> str | None:
        """Return the node id for an exact (case-insensitive) ``object_sid``."""
        pred, p = self._node_pred("node_id")
        tail = f" AND {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id FROM ("
            f"  SELECT node_id, object_sid FROM principal"
            f"  UNION ALL SELECT node_id, object_sid FROM container"
            f") t WHERE upper(object_sid) = upper(?){tail} ORDER BY node_id LIMIT 1",
            [object_sid, *p],
        )
        return str(rows[0][0]) if rows else None

    def principal_risk_inputs(self) -> list[dict[str, object]]:
        """Return the per-principal fields the risk model needs, ordered by node_id.

        One dict per ``principal`` row with ``node_id``/``principal_type``/
        ``object_sid``/``samaccountname``/``uac_flags``/``enabled``/``spns``/
        ``sid_history``/``admincount``/``label``/``domain_fqdn``. Pure projection;
        never returns secrets.
        """
        pred, p = self._node_pred("node_id")
        where = f" WHERE {pred}" if pred else ""
        rows = self._rows(
            f"SELECT node_id, principal_type, object_sid, samaccountname, uac_flags, enabled, "
            f"spns, sid_history, admincount, "
            f"COALESCE(samaccountname, display_name, distinguished_name, node_id) AS label, "
            f"domain_fqdn FROM principal{where} ORDER BY node_id",
            p,
        )
        return [
            {
                "node_id": r[0],
                "principal_type": r[1],
                "object_sid": r[2],
                "samaccountname": r[3],
                "uac_flags": r[4],
                "enabled": r[5],
                "spns": list(r[6] or []),
                "sid_history": list(r[7] or []),
                "admincount": r[8],
                "label": r[9],
                "domain_fqdn": r[10],
            }
            for r in rows
        ]

    def latest_run_counts(self) -> list[dict[str, object]]:
        """Return per-artifact ledger rows (coverage/skip counts) for the latest run.

        Reads ``provenance_ledger`` ordered by ``(ingested_at, source_file)`` for
        the most recent ``ingest_run_id``. Used by the WebSocket progress channel
        to replay the run's counted coverage/skip gaps. Returns an empty list if
        the ledger is empty OR absent (a store populated without the ledger DDL) —
        degrading to a counted gap rather than crashing the progress channel.
        """
        try:
            latest = self._rows(
                "SELECT ingest_run_id FROM provenance_ledger "
                "ORDER BY ingested_at DESC, source_file DESC LIMIT 1"
            )
            if not latest:
                return []
            run_id = latest[0][0]
            rows = self._rows(
                "SELECT source_file, coverage_counts, skip_counts, image_sha256 "
                "FROM provenance_ledger WHERE ingest_run_id = ? ORDER BY source_file",
                [run_id],
            )
        except duckdb.Error:
            return []
        return [
            {
                "source_file": r[0],
                "coverage_counts": r[1],
                "skip_counts": r[2],
                "image_sha256": r[3],
            }
            for r in rows
        ]

    # --- per-source discovery + coverage (M-MS2) ------------------------------
    def source_rows(self) -> list[SourceRow]:
        """Return the ``source`` dimension rows + per-source node/edge counts.

        The listing an operator/UI reads to DISCOVER the DC artifact sets in a case
        (contract §5 item 3). ``node_count``/``edge_count`` are ``COUNT(*)`` over
        ``source_observation`` for each ``source_id``. Ordered by ``dc_label`` then
        ``source_id`` (the stable display key — NEVER primarily by the random-looking
        ``source_id``, determinism rule). Returns ``[]`` if the ``source`` table is
        absent (a pre-M-MS1 store) rather than raising.

        Failure modes:
            Never raises on content; a missing ``source``/``source_observation`` table
            degrades to ``[]`` (the caller surfaces an empty listing honestly).
        """
        try:
            rows = self._rows(
                "SELECT s.source_id, s.case_id, s.dc_label, s.forest_id, s.domain_id, "
                "s.domain_fqdn, s.declared_domain, s.is_global_catalog, "
                "(SELECT count(*) FROM source_observation o "
                " WHERE o.source_id = s.source_id AND o.obj_kind = 'node'), "
                "(SELECT count(*) FROM source_observation o "
                " WHERE o.source_id = s.source_id AND o.obj_kind = 'edge') "
                "FROM source s ORDER BY s.dc_label, s.source_id"
            )
        except duckdb.Error:
            return []
        return [
            SourceRow(
                source_id=str(r[0]),
                case_id=str(r[1]),
                dc_label=str(r[2]),
                forest_id=str(r[3]),
                domain_id=r[4],
                domain_fqdn=r[5],
                declared_domain=r[6],
                is_global_catalog=r[7],
                node_count=int(r[8]),
                edge_count=int(r[9]),
            )
            for r in rows
        ]

    def source_by_id(self, source_id: str) -> SourceRow | None:
        """Return one :class:`SourceRow` by ``source_id`` (``None`` if unknown)."""
        for row in self.source_rows():
            if row.source_id == source_id:
                return row
        return None

    def source_artifact_shas(self, source_id: str) -> tuple[str | None, str | None]:
        """Return ``(ntds_image_sha256, system_image_sha256)`` for ``source_id``.

        The source's artifact fingerprints, used to join the ``provenance_ledger``
        for per-source coverage (M-MS2). Returns ``(None, None)`` if the source is
        unknown or the ``source`` table is absent (never raises).
        """
        try:
            rows = self._rows(
                "SELECT ntds_image_sha256, system_image_sha256 FROM source " "WHERE source_id = ?",
                [source_id],
            )
        except duckdb.Error:
            return (None, None)
        if not rows:
            return (None, None)
        return (rows[0][0], rows[0][1])

    def source_observation_count(self, source_id: str) -> int:
        """Return the total ``source_observation`` row count for ``source_id`` (0 if none)."""
        try:
            rows = self._rows(
                "SELECT count(*) FROM source_observation WHERE source_id = ?", [source_id]
            )
        except duckdb.Error:
            return 0
        return int(rows[0][0]) if rows else 0

    def ledger_coverage_for_shas(self, shas: Sequence[str]) -> list[LedgerCoverageRow]:
        """Return the latest run's per-artifact coverage/skip rows for ``shas``.

        Per-source coverage (contract §5 item 3): a source maps to its artifact
        image SHA-256s (``ntds_image_sha256`` / ``system_image_sha256``); the
        ``provenance_ledger`` keys coverage/skip counts by ``image_sha256``, so the
        source's coverage is the ledger rows whose ``image_sha256`` is one of the
        source's shas, for the most recent ``ingest_run_id``. ``coverage_counts`` /
        ``skip_counts`` JSON is parsed to a dict. Deterministically ordered by
        ``source_file``. Returns ``[]`` if the ledger is absent/empty or ``shas`` is
        empty (the caller counts the gap), never raising.
        """
        wanted = [s for s in shas if s]
        if not wanted:
            return []
        try:
            latest = self._rows(
                "SELECT ingest_run_id FROM provenance_ledger "
                "ORDER BY ingested_at DESC, source_file DESC LIMIT 1"
            )
            if not latest:
                return []
            placeholders = ",".join("?" for _ in wanted)
            rows = self._rows(
                f"SELECT source_file, image_sha256, coverage_counts, skip_counts "
                f"FROM provenance_ledger WHERE ingest_run_id = ? "
                f"AND image_sha256 IN ({placeholders}) ORDER BY source_file",
                [latest[0][0], *wanted],
            )
        except duckdb.Error:
            return []
        return [
            LedgerCoverageRow(
                source_file=r[0],
                image_sha256=r[1],
                coverage_counts=_json_counts(r[2]),
                skip_counts=_json_counts(r[3]),
            )
            for r in rows
        ]

    # --- divergence ledger reads (M-MS4b overlay, read-only) ------------------
    def divergence_present(self, run_id: UUID) -> bool:
        """Return whether any ``divergence`` row exists for ``run_id`` (M-MS4b).

        The single gate the dossier overlay consults: ``True`` only when an opt-in
        merge actually wrote a ledger for this run. A store that was never merged (no
        ``divergence`` table at all, the single-source path) degrades to ``False`` —
        so the overlay is skipped and the dossier stays byte-identical. Never raises.
        """
        try:
            rows = self._rows("SELECT 1 FROM divergence WHERE ingest_run_id = ? LIMIT 1", [run_id])
        except duckdb.Error:
            return False
        return bool(rows)

    def divergence_rows(
        self, run_id: UUID, node_id: str | None = None
    ) -> list[DivergenceLedgerRow]:
        """Return this run's ``divergence`` rows (optionally for one ``node_id``).

        Deterministically ordered by ``(obj_kind, obj_id, attribute)``. ``value_by_source``
        / ``resolved_value`` are JSON-decoded. Secrets never appear — a
        ``secret_divergence`` row's ``value_by_source`` is the redacted
        ``{present, differs}`` map the fold wrote. A missing ``divergence`` table (the
        never-merged store) degrades to ``[]`` (never raises).

        Inputs:
            run_id: the merge run whose ledger to read.
            node_id: when given, restrict to that object's rows (``obj_id``).

        Returns:
            The typed ledger rows (``[]`` when absent/empty).
        """
        sql = (
            "SELECT obj_kind, obj_id, attribute, divergence_type, resolution, "
            "resolved_by, value_by_source, resolved_value FROM divergence "
            "WHERE ingest_run_id = ?"
        )
        params: list[object] = [run_id]
        if node_id is not None:
            sql += " AND obj_id = ?"
            params.append(node_id)
        sql += " ORDER BY obj_kind, obj_id, attribute"
        try:
            rows = self._rows(sql, params)
        except duckdb.Error:
            return []
        out: list[DivergenceLedgerRow] = []
        for r in rows:
            vbs = _json_value(r[6])
            out.append(
                DivergenceLedgerRow(
                    obj_kind=str(r[0]),
                    obj_id=str(r[1]),
                    attribute=r[2],
                    divergence_type=str(r[3]),
                    resolution=r[4],
                    resolved_by=r[5],
                    value_by_source=vbs if isinstance(vbs, dict) else {},
                    resolved_value=_json_value(r[7]),
                )
            )
        return out

    def presented_attribute(
        self, run_id: UUID, node_id: str, attribute: str
    ) -> tuple[PresentedState, Any | None, bool]:
        """Reuse the gated read-time overlay (:func:`wraith.merge.fold.presented_attribute`).

        Thin wrapper that runs the gated fold function on a private cursor (thread-safe)
        so the dossier overlay reuses the exact three-state semantics rather than
        re-deriving them.

        Returns ``(state, value, degraded)``. ``degraded`` is ``True`` only when the
        read itself FAILED (``duckdb.Error``): the caller asks this ONLY for a row
        already known to diverge, so a failed read must NOT read back as the benign
        ``NO_DIVERGENCE`` (that would silently contradict a known divergence). Instead it
        degrades to ``CONTESTED_UNRESOLVED`` (badged, never benign) and flags
        ``degraded`` so the caller COUNTS the gap (``merge.presented_read_degraded``) —
        the "counted gap on every degraded branch" rule. Never raises.
        """
        cur = self._con.cursor()
        try:
            state, value = presented_attribute(cur, node_id, attribute, run_id)
            return state, value, False
        except duckdb.Error:
            return PresentedState.CONTESTED_UNRESOLVED, None, True
        finally:
            cur.close()


class ScopedStoreReader(StoreReader):
    """A per-source VIEW over one canonical store (multi-source contract §2.3, M-MS2).

    Restricts every read to the objects ONE source observed by overriding the single
    scope hook (:meth:`_source_filter_id`) the base read methods consult. The node
    id-space becomes ``source_observation(obj_kind='node', source_id=X)`` and the edge
    id-space ``...obj_kind='edge'...``; a direct ``Base`` dossier entry is bound via
    ``staging_object.source_id`` (``Base`` leaves are not in ``source_observation``).
    Pure RESOLVERS (:meth:`nodes_by_ids` / :meth:`all_nodes`) stay unscoped so an
    already-scoped edge's endpoint still resolves to a label — preserving single-source
    parity (where every node has exactly one observation, a scoped view == the full
    view) and avoiding cross-source bleed (the endpoint is the source's by construction).

    The base reader (unscoped) is byte-identical + zero-overhead: its hook returns
    ``None`` so no ``source_observation`` join is ever added on the single-source path.

    Counted gap (never a silent empty): a ``source_id`` with ZERO observations (unknown
    or empty source) still returns an honest empty view with
    :data:`GAP_UNKNOWN_SOURCE` counted in :attr:`scope_gaps`, which every per-source
    endpoint folds into its response ``counted_gaps``.
    """

    def __init__(self, con: duckdb.DuckDBPyConnection, db_path: Path, source_id: str) -> None:
        super().__init__(con, db_path)
        self._source_id = source_id
        if self.source_observation_count(source_id) == 0:
            self.scope_gaps = {GAP_UNKNOWN_SOURCE: 1}

    @property
    def source_id(self) -> str:
        """The ``source_id`` this reader is scoped to."""
        return self._source_id

    def _source_filter_id(self) -> str | None:
        return self._source_id
