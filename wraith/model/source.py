"""Multi-source ingest primitives (M-MS1) — ``source`` + ``source_observation``.

The additive, per-source-first substrate of the multi-domain (Phase 1) effort
(``docs/schema/multi-source-contract.md`` §1/§2). Everything here is pure or a
single-table writer so it is independently testable and drops into both the
single-source path (one ``source`` row, one ``source_observation`` per node) and
the future N-source path (M-MS2+) with no schema change.

What this module owns:

* :func:`derive_source_id` — the DETERMINISTIC per-source UUIDv5 (stable function
  of ``case_id`` + ``dc_label`` + ``ntds_image_sha256``), so identical inputs
  produce an identical ``source_id`` and nothing downstream drifts run-to-run.
* :func:`reconcile_case_shape` — the PURE declared-vs-derived reconciliation that
  returns the COUNTED mismatch gaps (§1.4); derived-wins-for-scoping,
  declaration-wins-for-workflow-gating, mismatch-always-counted, never silent.
* :func:`write_source_row` / :func:`write_source_observations` — the two single
  -table writers that record a source and register one observation per canonical
  node/edge, attributing every fact to its ``source_id``.

It owns NO merge logic (M-MS4), NO per-source view/query surface (M-MS2), and NO
cross-domain edge derivation (M-MS3). Those consume this substrate later.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid5

import duckdb

# --------------------------------------------------------------------------- #
#  Case-shape vocabulary (contract §1.1) — the two orthogonal axes             #
# --------------------------------------------------------------------------- #
#: Whether cross-domain edge wiring (trust/FSP/sIDHistory, M-MS3) is in scope.
DomainCardinality = Literal["single_domain", "multi_domain"]
#: Whether the merge/divergence engine (M-MS4, Phase 2) is *available*.
DcCardinality = Literal["single_dc", "multi_dc"]

#: Deterministic namespace for :func:`derive_source_id` (a fixed UUIDv5 of the
#: literal ``"wraith.multi-source.v1"`` under the DNS namespace — frozen forever;
#: changing it would re-mint every ``source_id``).
SOURCE_ID_NAMESPACE: UUID = UUID("9f2c7e3a-5d41-5b8e-9c2a-7f1d3e6b4a05")

#: Field separator for the :func:`derive_source_id` seed (a byte that cannot
#: appear in a case_id/dc_label/hex-sha, so the seed is unambiguous).
_SEED_SEP: str = "\x1f"

# --------------------------------------------------------------------------- #
#  Counted mismatch gap classes (contract §1.4) — honesty, never silent        #
# --------------------------------------------------------------------------- #
#: Declared ``single_domain`` but the ingested sources carry >=2 distinct derived
#: ``domain_id``s — the case is really multi-domain (cross-domain edges stay off
#: until the operator re-declares; no guessing).
GAP_MULTIPLE_DOMAINS: str = "case_shape_mismatch:multiple_domains_detected"
#: Declared ``multi_domain`` + ``single_dc`` but two sources share a derived
#: ``domain_id`` — these are two DCs of ONE domain (a multi-DC case). Default
#: stays per-source-separate; never auto-merged.
GAP_SAME_DOMAIN_TWO_DCS: str = "case_shape_mismatch:same_domain_two_dcs"
#: An operator ``declared_domain`` label disagrees with the derived
#: ``domain_fqdn`` — the DERIVED value is used for all scoping/joins, the label is
#: kept for display. A mislabeled artifact must never misroute a cross-domain edge.
GAP_LABEL_DOMAIN_MISMATCH: str = "source_label_domain_mismatch"


def derive_source_id(case_id: str, dc_label: str, ntds_image_sha256: str) -> str:
    """Return the DETERMINISTIC per-source UUIDv5 for a source (contract §1.3).

    ``source_id`` is the machine key (the mutable ``dc_label`` is only the display
    key). Deriving it as ``uuid5(NAMESPACE, case_id|dc_label|ntds_sha)`` makes it a
    stable function of the case, the operator label, and the actual artifact bytes:
    identical inputs => identical ``source_id`` => the canonical store is
    byte-deterministic (the determinism non-negotiable) and a re-ingest of the same
    artifact under the same label is idempotent. Because ``(case_id, dc_label)`` is
    enforced unique per case (§1.3), two live sources can never collide.

    Inputs:
        case_id: the owning case slug.
        dc_label: the operator-supplied, per-case-unique DC label.
        ntds_image_sha256: the lowercase SHA-256 of this source's ``ntds.dit``.

    Returns:
        The ``source_id`` as a lowercase canonical UUID string.

    Failure modes:
        Raises ``ValueError`` if any component is empty (a source_id must be
        fully attributable — never minted from a blank key).
    """
    if not case_id or not dc_label or not ntds_image_sha256:
        raise ValueError("derive_source_id requires non-empty case_id, dc_label, ntds_image_sha256")
    seed = _SEED_SEP.join((case_id, dc_label, ntds_image_sha256.lower()))
    return str(uuid5(SOURCE_ID_NAMESPACE, seed))


@dataclass(frozen=True)
class SourceDomainFacts:
    """The declared + derived domain facts of ONE source, for reconciliation.

    Attributes:
        source_id: the minted machine key.
        dc_label: the operator-supplied display label.
        declared_domain: the operator-asserted domain (display only); may be blank.
        derived_domain_id: the ``domainDNS`` objectSID reconstructed from the dit
            (authoritative for scoping); ``None`` when the dit yielded no domain.
        derived_domain_fqdn: the reconstructed domain FQDN; ``None`` when unknown.
    """

    source_id: str
    dc_label: str
    declared_domain: str | None
    derived_domain_id: str | None
    derived_domain_fqdn: str | None


def _domain_label_matches(declared: str | None, derived_fqdn: str | None) -> bool:
    """Return whether a declared domain label is consistent with a derived FQDN.

    Lenient by design (the label is a human hint, not ground truth): a match is
    ``True`` when either side is unknown/blank, when they are equal (case-
    insensitive), or when the declared label is the derived FQDN's leading DNS
    label (operator typed the short NetBIOS-ish name, e.g. ``corp`` for
    ``corp.example.com``) or vice-versa (operator typed the FQDN, derived is
    short). Only a genuinely different namespace counts as a mismatch. The
    heuristic is intentionally conservative to avoid false honesty flags and is a
    documented refine-on-real-data point (contract §7).
    """
    if not declared or not derived_fqdn:
        return True
    d = declared.strip().lower().rstrip(".")
    f = derived_fqdn.strip().lower().rstrip(".")
    if not d or not f:
        return True
    if d == f:
        return True
    if f.split(".", 1)[0] == d or d.split(".", 1)[0] == f:
        return True
    return False


def reconcile_case_shape(
    domain_cardinality: str,
    dc_cardinality: str,
    sources: Sequence[SourceDomainFacts],
) -> list[tuple[str, int]]:
    """Reconcile the operator's case-shape declaration against the derived facts.

    PURE function over the FULL set of a case's sources (so it is DB-free and
    directly unit-testable). It never mutates state and never "corrects" the
    declaration — it only returns the COUNTED mismatch gaps the caller bumps onto
    the :class:`~wraith.case.ingest_run.IngestRun` (§1.4). Derived-wins for
    scoping (the caller always writes the derived ``domain_id``); declaration-wins
    for workflow gating (which analyses run); mismatch-always-counted.

    Returned gaps (each ``(gap_class, count)``, deterministic order):
        * :data:`GAP_LABEL_DOMAIN_MISMATCH` — one per source whose declared label
          disagrees with its derived FQDN.
        * :data:`GAP_MULTIPLE_DOMAINS` — when declared ``single_domain`` but the
          sources carry >=2 distinct derived ``domain_id``s; count = the number of
          domains beyond the first (i.e. ``distinct_domains - 1``).
        * :data:`GAP_SAME_DOMAIN_TWO_DCS` — when declared ``multi_domain`` +
          ``single_dc`` but a derived ``domain_id`` is shared by >1 source; count =
          the number of redundant same-domain sources (``sum(k-1)`` over shared ids).

    Inputs:
        domain_cardinality: the case's declared :data:`DomainCardinality`.
        dc_cardinality: the case's declared :data:`DcCardinality`.
        sources: every source in the case (including the one being ingested).

    Returns:
        The list of ``(gap_class, count)`` to count; empty when consistent.

    Failure modes:
        None — unknown cardinality strings are treated as their non-triggering
        case (the axis simply does not fire its gap); the caller validates the
        declaration shape at the API boundary.
    """
    gaps: list[tuple[str, int]] = []

    # (1) Per-source label-vs-derived FQDN mismatch — order-stable by source_id.
    label_mismatches = sum(
        1
        for s in sorted(sources, key=lambda x: x.source_id)
        if not _domain_label_matches(s.declared_domain, s.derived_domain_fqdn)
    )
    if label_mismatches:
        gaps.append((GAP_LABEL_DOMAIN_MISMATCH, label_mismatches))

    derived_ids = [s.derived_domain_id for s in sources if s.derived_domain_id]
    distinct_ids = sorted(set(derived_ids))

    # (2) Declared single_domain but multiple distinct domains observed.
    if domain_cardinality == "single_domain" and len(distinct_ids) >= 2:
        gaps.append((GAP_MULTIPLE_DOMAINS, len(distinct_ids) - 1))

    # (3) Declared multi_domain + single_dc but a domain is shared by >1 source.
    if domain_cardinality == "multi_domain" and dc_cardinality == "single_dc":
        redundant = 0
        for did in distinct_ids:
            k = sum(1 for x in derived_ids if x == did)
            if k > 1:
                redundant += k - 1
        if redundant:
            gaps.append((GAP_SAME_DOMAIN_TWO_DCS, redundant))

    return gaps


@dataclass(frozen=True)
class SourceRecord:
    """One ``source`` dimension row (contract §2.2a).

    ``domain_id``/``domain_fqdn`` are the DERIVED (authoritative) values;
    ``declared_domain`` is the operator label (display only). ``ingested_at`` is
    wall-clock and NOT part of the determinism guarantee (like the ledger's).
    """

    source_id: str
    case_id: str
    dc_label: str
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    declared_domain: str | None
    ntds_image_sha256: str
    system_image_sha256: str | None
    ingest_run_id: UUID
    ingested_at: datetime
    is_global_catalog: bool | None = None
    dsa_guid: str | None = None
    invocation_id: str | None = None


def write_source_row(con: duckdb.DuckDBPyConnection, record: SourceRecord) -> None:
    """Insert one ``source`` dimension row (contract §2.2a).

    Inputs:
        con: an open canonical store with the ``source`` table created.
        record: the :class:`SourceRecord` to persist.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.ConstraintException`` if ``(case_id, dc_label)`` is already
        present (label-uniqueness, §1.3) or ``source_id`` already exists — the
        caller surfaces either as a hard validation error, never a silent rename.
    """
    con.execute(
        "INSERT INTO source ("
        "source_id, case_id, dc_label, forest_id, domain_id, domain_fqdn, "
        "declared_domain, ntds_image_sha256, system_image_sha256, is_global_catalog, "
        "dsa_guid, invocation_id, ingest_run_id, ingested_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            record.source_id,
            record.case_id,
            record.dc_label,
            record.forest_id,
            record.domain_id,
            record.domain_fqdn,
            record.declared_domain,
            record.ntds_image_sha256,
            record.system_image_sha256,
            record.is_global_catalog,
            record.dsa_guid,
            record.invocation_id,
            record.ingest_run_id,
            record.ingested_at,
        ],
    )


#: The canonical NODE tables whose rows each register one ``source_observation``.
#: ``principal`` carries ``when_created``; the others expose only the provenance
#: struct's ``directory_timestamp`` (set by the normalizer to whenChanged/
#: whenCreated). Each table contributes ``obj_kind='node'``.
_NODE_TABLES: tuple[str, ...] = ("principal", "container", "gpo", "trust", "adcs")


def write_source_observations(con: duckdb.DuckDBPyConnection, source_id: str) -> int:
    """Register one ``source_observation`` per canonical node and edge (§2.2c).

    After a source's passes have populated the canonical tables, this records
    "``source_id`` asserted this node/edge, and when" so a per-source standalone
    view (M-MS2) is a ``WHERE source_id = ?`` filter and merge (M-MS4) a ``GROUP BY
    obj_id`` fold. In Phase 1 (one source per node) exactly one observation exists
    per node/edge, so this is pure additive bookkeeping over the single-source path.

    Recorded per row:
        * ``directory_timestamp`` = the row's ``provenance.directory_timestamp``
          (object-level ``whenChanged`` — cross-DC comparable).
        * ``when_created`` = ``principal.when_created`` where present, else NULL.
        * ``usn_local`` = NULL (STORED-but-never-a-winner-key; no per-object USN is
          surfaced at the canonical layer in Phase 1).
        * ``is_deleted`` = FALSE (recoverable/tombstoned objects are not emitted as
          canonical entities in v1 — a documented normalizer gap, not this writer's).
        * ``attr_metadata_blob`` = NULL (filled IFF the decoder lands, M-MS4).

    Idempotent per source: existing observations for ``source_id`` are deleted
    first so a re-run of this writer does not raise on the PK.

    Inputs:
        con: an open canonical store (canonical tables + ``source_observation``).
        source_id: the source these observations are attributed to.

    Returns:
        The number of ``source_observation`` rows written.

    Failure modes:
        Raises ``duckdb.Error`` if the canonical/observation tables are absent.
    """
    con.execute("DELETE FROM source_observation WHERE source_id = ?", [source_id])

    written = 0
    for table in _NODE_TABLES:
        when_created = "when_created" if table == "principal" else "CAST(NULL AS TIMESTAMP)"
        # ``table`` / ``when_created`` are internal literals (never external input);
        # the source_id is a bound parameter.
        con.execute(
            f"INSERT INTO source_observation "  # noqa: S608 - fixed internal literals
            f"(obj_kind, obj_id, source_id, directory_timestamp, when_created, "
            f"usn_local, is_deleted, attr_metadata_blob) "
            f"SELECT 'node', node_id, ?, provenance.directory_timestamp, {when_created}, "
            f"NULL, FALSE, NULL FROM {table}",
            [source_id],
        )
        written += _rowcount(con, table)

    con.execute(
        "INSERT INTO source_observation "
        "(obj_kind, obj_id, source_id, directory_timestamp, when_created, "
        "usn_local, is_deleted, attr_metadata_blob) "
        "SELECT 'edge', edge_id, ?, provenance.directory_timestamp, "
        "CAST(NULL AS TIMESTAMP), NULL, FALSE, NULL FROM edge",
        [source_id],
    )
    written += _rowcount(con, "edge")
    return written


def _rowcount(con: duckdb.DuckDBPyConnection, table: str) -> int:
    """Return ``COUNT(*)`` of an internal-literal table name (0 if absent)."""
    # ``table`` is an internal literal from a fixed tuple (never external input).
    query = f"SELECT COUNT(*) FROM {table}"  # noqa: S608 - internal literal
    try:
        row = con.execute(query).fetchone()
    except duckdb.Error:
        return 0
    return int(row[0]) if row is not None else 0


__all__ = [
    "DcCardinality",
    "DomainCardinality",
    "GAP_LABEL_DOMAIN_MISMATCH",
    "GAP_MULTIPLE_DOMAINS",
    "GAP_SAME_DOMAIN_TWO_DCS",
    "SOURCE_ID_NAMESPACE",
    "SourceDomainFacts",
    "SourceRecord",
    "derive_source_id",
    "reconcile_case_shape",
    "write_source_observations",
    "write_source_row",
]
