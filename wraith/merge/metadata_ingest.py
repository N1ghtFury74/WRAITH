"""Decoder-ingest wiring (M-MS4a) — fill ``source_observation.attr_metadata_blob``.

The ``replPropertyMetaData`` decoder (:mod:`wraith.parsing.repl_metadata`) is built
and gated, but it is DORMANT until something feeds it the raw per-object metadata
bytes. This module is that feed: after a source's canonical passes and its
``source_observation`` rows exist, it copies each node's raw ``replPropertyMetaData``
column bytes out of that source's ``staging_object.attributes`` and writes them into
the matching ``source_observation`` row's ``attr_metadata_blob``. The opt-in merge
fold (M-MS4b) then decodes those bytes for the **tier-1** per-attribute newest-wins
rung of the §3.3 resolution ladder.

Resolve-by-schema (not by raw column id). The normalizer already keys every staged
attribute by its schema ``lDAPDisplayName``, so the metadata is found under the
display name ``replPropertyMetaData`` — the correct, schema-driven lookup
(``docs/research/26-replmetadata-decode-spike.md``). The raw datatable column name
``ATTk589827`` is a **sanity fallback only** for the rare store whose attribute was
never schema-resolved; it is never the primary key and never hard-coded as the
answer. A node whose staged attributes carry neither is a COUNTED gap
(:data:`GAP_REPL_METADATA_ABSENT`), never a silent NULL — tier-1 then simply does
not apply for that node and the merge degrades honestly to tier-2/3 (§3.5, item 5).

Scope boundary. Only NODE observations are fed: ``replPropertyMetaData`` is a
per-object stamp vector. The per-value (membership) recency lives in a SEPARATE
``msDS-ReplValueMetaData`` / ``link_metadata`` parse that is out of scope here and
for M-MS4; edge observations therefore keep ``attr_metadata_blob = NULL`` and edge
divergence (M-MS4b) uses per-source union + object-level ``whenChanged``, never a
tier-1 value stamp. The raw bytes are captured verbatim; a blob that does not decode
is still stored (it IS the column value) but COUNTED
(:data:`GAP_REPL_METADATA_UNPARSEABLE`) so the honesty signal is not lost.

Pure/single-table by design: :func:`extract_repl_metadata_blob` is a pure decode of
one staged-attributes JSON string (unit-testable with no DB), and
:func:`populate_attr_metadata` is one scoped ``UPDATE`` per source. Determinism: node
observations are processed in ``ORDER BY obj_id`` and the extraction is a pure
function of the stored bytes, so identical inputs yield identical ``attr_metadata_blob``
values and identical counts.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import duckdb

from wraith.case.ingest_run import IngestRun
from wraith.parsing.repl_metadata import ReplMetadataParseError, parse_repl_property_metadata

_log = logging.getLogger(__name__)

#: Schema ``lDAPDisplayName`` of the per-object replication-metadata attribute —
#: the PRIMARY, resolve-by-schema lookup key into a staged attributes map.
REPL_METADATA_LDAP_NAME: str = "replPropertyMetaData"

#: Raw datatable column name (attributeID OID ``1.2.840.113556.1.4.3`` -> internal
#: id ``589827``). A SANITY FALLBACK ONLY (research 26): used solely when a store's
#: attribute was never schema-resolved to :data:`REPL_METADATA_LDAP_NAME`.
REPL_METADATA_FALLBACK_COLUMN: str = "ATTk589827"

#: The ``_json_safe`` tag the normalizer uses to encode raw bytes in staging JSON.
_BYTES_HEX_TAG: str = "__bytes_hex__"

#: Coverage: node observations whose raw ``replPropertyMetaData`` bytes were captured.
COV_REPL_METADATA_CAPTURED: str = "repl_metadata.captured"

#: Skip/gap: a node observation whose staged attributes carried no
#: ``replPropertyMetaData`` (nor the ``ATTk589827`` fallback) — tier-1 cannot apply
#: for this node; merge degrades honestly to tier-2/3 (§3.3/§3.5). Never a silent NULL.
GAP_REPL_METADATA_ABSENT: str = "repl_metadata_absent"

#: Skip/gap: raw bytes were present and captured but did NOT decode as a valid
#: ``PROPERTY_META_DATA_EXT_VECTOR``. The bytes are stored verbatim (they are the
#: real column value) but the honesty signal is counted so M-MS4b's tier-1 miss is
#: not silent. Expected zero on a well-formed dit; non-zero flags a parity concern.
GAP_REPL_METADATA_UNPARSEABLE: str = "repl_metadata_unparseable"


@dataclass(frozen=True)
class MetadataIngestResult:
    """Counts of one source's ``replPropertyMetaData`` capture pass (never secrets).

    Attributes:
        source_id: the source whose node observations were fed.
        nodes_considered: node observations examined (``obj_kind='node'``).
        captured: observations whose raw metadata bytes were written to
            ``attr_metadata_blob``.
        absent: observations with no ``replPropertyMetaData`` in their staged
            attributes (counted :data:`GAP_REPL_METADATA_ABSENT`); left NULL.
        unparseable: captured blobs that did not decode as a metadata vector
            (counted :data:`GAP_REPL_METADATA_UNPARSEABLE`); bytes still stored.
    """

    source_id: str
    nodes_considered: int
    captured: int
    absent: int
    unparseable: int


def _bytes_from_tagged(value: object) -> bytes | None:
    """Return raw bytes from a ``_json_safe``-encoded value, or ``None`` (pure).

    Accepts the normalizer's ``{"__bytes_hex__": hex}`` tag, and — because a
    multi-valued attribute is encoded as a list — a single-element list wrapping
    one such tag. Any other shape (absent, str, multi-element, bad hex) yields
    ``None`` so a malformed encoding degrades to a counted absence, never a crash.
    """
    if isinstance(value, list):
        if len(value) != 1:
            return None
        value = value[0]
    if not isinstance(value, dict):
        return None
    hex_str = value.get(_BYTES_HEX_TAG)
    if not isinstance(hex_str, str):
        return None
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def extract_repl_metadata_blob(attributes_json: str | None) -> bytes | None:
    """Extract the raw ``replPropertyMetaData`` bytes from a staged attributes JSON.

    Pure and deterministic. Resolves BY SCHEMA display name
    (:data:`REPL_METADATA_LDAP_NAME`) first, then the :data:`REPL_METADATA_FALLBACK_COLUMN`
    raw column name as a sanity fallback only. Returns the raw column bytes exactly
    as the normalizer stored them (the decoder's expected input), or ``None`` when
    neither key is present or the value is not a byte-encoded tag.

    Inputs:
        attributes_json: the ``staging_object.attributes`` JSON string for one
            node (as stored by :func:`wraith.normalize.models.encode_raw_attributes`),
            or ``None``.

    Returns:
        The raw ``replPropertyMetaData`` bytes, or ``None`` if absent/unencodable.

    Failure modes:
        Never raises. Invalid JSON, a missing key, or a non-byte value all return
        ``None`` (the caller counts that as an absence).
    """
    if not attributes_json:
        return None
    try:
        attributes = json.loads(attributes_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(attributes, dict):
        return None
    for key in (REPL_METADATA_LDAP_NAME, REPL_METADATA_FALLBACK_COLUMN):
        if key in attributes:
            blob = _bytes_from_tagged(attributes[key])
            if blob is not None:
                return blob
    return None


def populate_attr_metadata(
    con: duckdb.DuckDBPyConnection,
    source_id: str,
    run: IngestRun | None = None,
) -> MetadataIngestResult:
    """Feed one source's raw ``replPropertyMetaData`` into ``source_observation``.

    For every ``obj_kind='node'`` observation of ``source_id``, read the matching
    ``staging_object.attributes`` (same ``source_id``), extract the raw
    ``replPropertyMetaData`` bytes (resolve-by-schema, :func:`extract_repl_metadata_blob`),
    and ``UPDATE`` the observation's ``attr_metadata_blob`` with them. This arms
    tier-1 of the merge ladder (M-MS4b) without touching the gated parser/normalizer
    — it only mines what staging already preserved. Idempotent and deterministic
    (processes nodes ``ORDER BY obj_id``; a re-run writes identical bytes).

    Honest degradation (every branch counted, never silent):
        * a node with no ``replPropertyMetaData`` in staging ->
          :data:`GAP_REPL_METADATA_ABSENT`, blob left NULL (tier-1 skipped for it);
        * captured bytes that do not decode -> :data:`GAP_REPL_METADATA_UNPARSEABLE`,
          bytes still stored verbatim;
        * captured + decodable -> :data:`COV_REPL_METADATA_CAPTURED`.

    Only node observations are fed — ``replPropertyMetaData`` is a per-object vector;
    linked-value (membership) recency is a separate out-of-scope parse, so edge
    observations keep ``attr_metadata_blob = NULL`` by design.

    Inputs:
        con: an open store holding this source's ``staging_object`` +
            ``source_observation`` rows (the per-source store in the N-source loop).
        source_id: the source whose node observations are fed.
        run: optional :class:`IngestRun` to accumulate the coverage/gap counters;
            ``None`` (standalone/unit callers) skips counting but the returned
            :class:`MetadataIngestResult` tallies are identical either way.

    Returns:
        A :class:`MetadataIngestResult` (counts only; never secrets).

    Failure modes:
        Raises ``duckdb.Error`` if ``source_observation``/``staging_object`` are
        absent. A malformed per-node attributes JSON degrades to a counted absence,
        never a crash.
    """
    rows = con.execute(
        "SELECT o.obj_id, s.attributes "
        "FROM source_observation o "
        "LEFT JOIN staging_object s "
        "  ON s.node_id = o.obj_id AND s.source_id = o.source_id "
        "WHERE o.obj_kind = 'node' AND o.source_id = ? "
        "ORDER BY o.obj_id",
        [source_id],
    ).fetchall()

    captured = 0
    absent = 0
    unparseable = 0
    for obj_id, attributes_json in rows:
        blob = extract_repl_metadata_blob(attributes_json)
        if blob is None:
            absent += 1
            continue
        con.execute(
            "UPDATE source_observation SET attr_metadata_blob = ? "
            "WHERE obj_kind = 'node' AND obj_id = ? AND source_id = ?",
            [blob, obj_id, source_id],
        )
        captured += 1
        # Validate parseability for an honesty signal ONLY — the raw bytes are
        # kept either way (they are the real column value; M-MS4b may inspect them).
        try:
            parse_repl_property_metadata(blob)
        except ReplMetadataParseError:
            unparseable += 1

    if run is not None:
        if captured:
            run.bump_coverage(COV_REPL_METADATA_CAPTURED, captured)
        if absent:
            run.bump_skip(GAP_REPL_METADATA_ABSENT, absent)
        if unparseable:
            run.bump_skip(GAP_REPL_METADATA_UNPARSEABLE, unparseable)

    _log.info(
        "replPropertyMetaData capture for source %s: %d captured, %d absent, "
        "%d unparseable (of %d node observations)",
        source_id,
        captured,
        absent,
        unparseable,
        len(rows),
    )
    return MetadataIngestResult(
        source_id=source_id,
        nodes_considered=len(rows),
        captured=captured,
        absent=absent,
        unparseable=unparseable,
    )


__all__ = [
    "COV_REPL_METADATA_CAPTURED",
    "GAP_REPL_METADATA_ABSENT",
    "GAP_REPL_METADATA_UNPARSEABLE",
    "REPL_METADATA_FALLBACK_COLUMN",
    "REPL_METADATA_LDAP_NAME",
    "MetadataIngestResult",
    "extract_repl_metadata_blob",
    "populate_attr_metadata",
]
