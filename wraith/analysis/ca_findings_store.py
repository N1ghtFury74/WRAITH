"""Persist the ADCS-ESC CA-host NODE-LEVEL findings into the canonical store.

The ADCS-ESC composition pass (:mod:`wraith.analysis.adcs_esc`) computes the
ESC11 / ESC16 / DCOM findings (:class:`~wraith.analysis.adcs_esc.CaNodeFinding`)
but — being node PROPERTIES, not traversable edges — it does NOT write them to
the store, so the dossier API cannot show them. This module is the thin,
deterministic WRITER the pipeline calls to close that gap: it provisions the
additive ``ca_node_finding`` table (schema v1.4) and appends each finding,
carrying the CA-host HIVE provenance each finding already holds. It touches
neither the ESC forensic logic nor the ingest wiring (both gated); it only
persists an already-computed result.

Design rules (CLAUDE.md): additive-only schema; determinism (rows sorted by
``(node_id, prop)``, keyed by a stable id -> idempotent re-runs); provenance on
every row; and NO secret material persisted (ESC11/ESC16 store ``"true"``; DCOM
stores only the ``EnableDCOM=Y/N`` summary, never a raw security descriptor).
"""

from __future__ import annotations

from collections.abc import Sequence

import duckdb

from wraith.analysis.adcs_esc import CaNodeFinding
from wraith.common.determinism import stable_id
from wraith.model.store import create_ca_node_finding_table
from wraith.normalize.decoders import to_naive_utc


def _value_text(value: bool | str) -> str:
    """Return the NON-SECRET stored text for a finding value.

    A boolean (ESC11/ESC16 — always ``True`` when a finding exists) becomes the
    lowercase ``"true"`` / ``"false"`` literal; a string (the ``EnableDCOM=Y/N``
    DCOM summary) is stored verbatim. Never a secret / security-descriptor byte.

    Inputs:
        value: the :attr:`CaNodeFinding.value` (``bool`` for ESC11/ESC16, ``str``
            for the redacted DCOM summary).

    Returns:
        The VARCHAR text to store.

    Failure modes:
        Never raises; pure.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _provenance_value(finding: CaNodeFinding) -> dict[str, object]:
    """Encode the finding's CA-host hive provenance as the DuckDB STRUCT dict.

    Re-stamps the finding's registry value path as ``source_object_id`` on the
    hive-provenance anchor (mirroring :func:`wraith.edges.models._provenance_struct_value`),
    so each persisted finding is a fact WITH full provenance: ``{source_file,
    image_sha256, source_object_id, directory_timestamp, ingest_run_id}``. The
    ``directory_timestamp`` is normalized to naive-UTC for byte-determinism, exactly
    as every other canonical row.

    Inputs:
        finding: the :class:`CaNodeFinding` whose hive provenance to encode.

    Returns:
        The provenance STRUCT dict for the ``ca_node_finding.provenance`` column.

    Failure modes:
        Never raises; pure.
    """
    p = finding.provenance
    return {
        "source_file": p.source_file,
        "image_sha256": p.image_sha256,
        "source_object_id": finding.source_object_id,
        "directory_timestamp": to_naive_utc(p.directory_timestamp),
        "ingest_run_id": p.ingest_run_id,
    }


def persist_ca_node_findings(
    con: duckdb.DuckDBPyConnection,
    findings: Sequence[CaNodeFinding],
    *,
    scoping: tuple[str, str | None, str | None],
) -> int:
    """Persist the ESC11/ESC16/DCOM node findings into ``ca_node_finding``.

    Provisions the additive table (always, so a reader never hits a missing table)
    and appends each finding. ESC11/ESC16 rows attach to the EnterpriseCA node; the
    DCOM summary row to the CA host Computer node — the ``node_id`` each finding
    already carries. Deterministic: findings are sorted by ``(node_id, prop)`` and
    keyed by ``stable_id(node_id, prop)``, so identical input yields identical rows
    and a re-run is a no-op (``INSERT OR IGNORE``).

    Inputs:
        con: an open canonical store connection.
        findings: the ADCS-ESC pass's ``ca_node_findings`` (``CaNodeFinding`` list).
            An EMPTY list is the ordinary no-CA-host-hive state — NOT a gap.
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block the rest of the
            run used (so the findings share a consistent per-source scope).

    Returns:
        The number of finding rows newly inserted (``0`` when ``findings`` is empty
        or every row already existed).

    Failure modes:
        Raises ``duckdb.Error`` on a store failure (same contract as the edge
        writer). No secret material is ever written — DCOM is a ``Y/N`` summary.
    """
    create_ca_node_finding_table(con)
    if not findings:
        return 0
    forest_id, domain_id, domain_fqdn = scoping
    rows: list[tuple[object, ...]] = [
        (
            stable_id(f.node_id, f.prop),
            f.node_id,
            f.prop,
            _value_text(f.value),
            forest_id,
            domain_id,
            domain_fqdn,
            _provenance_value(f),
        )
        for f in sorted(findings, key=lambda x: (x.node_id, x.prop))
    ]
    before = con.execute("SELECT count(*) FROM ca_node_finding").fetchone()
    con.executemany("INSERT OR IGNORE INTO ca_node_finding VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    after = con.execute("SELECT count(*) FROM ca_node_finding").fetchone()
    return int(after[0]) - int(before[0]) if before and after else 0
