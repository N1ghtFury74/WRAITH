"""M-MS4a — decoder-ingest wiring + divergence-ledger scaffolding (coder-side).

SYNTHETIC only (the real ``replPropertyMetaData`` byte parity needs a real
capture; contract §7.7). These prove the PLUMBING + honest degradation:

* ``divergence`` ledger — created by :func:`create_divergence_table` (and NOT by
  :func:`create_canonical_tables`, so the single-source path is unchanged); has the
  §2.2d columns and a ``resolved_by`` that is a plain VARCHAR (the WRITER, M-MS4b,
  never emits ``'authoritative_dc'`` — owner decision §3.3).
* ``extract_repl_metadata_blob`` — pure resolve-by-schema extraction with the
  ``ATTk589827`` sanity fallback and safe degradation on malformed input.
* ``populate_attr_metadata`` — fills ``source_observation.attr_metadata_blob`` for
  node observations only, counts the absent/unparseable gaps, is deterministic, and
  arms tier-1 of the merge ladder without touching the gated parser/normalizer.
"""

from __future__ import annotations

import json
import struct
import uuid
from datetime import UTC, datetime

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.merge.metadata_ingest import (
    COV_REPL_METADATA_CAPTURED,
    GAP_REPL_METADATA_ABSENT,
    GAP_REPL_METADATA_UNPARSEABLE,
    extract_repl_metadata_blob,
    populate_attr_metadata,
)
from wraith.model.store import (
    create_canonical_tables,
    create_divergence_table,
    create_edge_tables,
)
from wraith.parsing.repl_metadata import parse_repl_property_metadata

# --------------------------------------------------------------------------- #
#  Synthetic replPropertyMetaData blob builder (the documented on-disk layout) #
# --------------------------------------------------------------------------- #
_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


def _make_blob(entries: list[tuple[int, int, int, int]]) -> bytes:
    """Build a valid PROPERTY_META_DATA_EXT_VECTOR from (attid, version, dstime, usn)."""
    out = struct.pack("<III", 1, 0, len(entries))
    dsa = uuid.UUID("11111111-2222-3333-4444-555555555555")
    for attid, version, dstime, usn in entries:
        out += struct.pack("<IIq", attid, version, dstime)
        out += dsa.bytes_le
        out += struct.pack("<q", usn)
    return out


_VALID_BLOB = _make_blob([(1, 5, 1_000_000, 42), (589825, 3, 2_000_000, 99)])


def _attrs_json(**attrs: object) -> str:
    return json.dumps(attrs)


def _hex_tag(blob: bytes) -> dict[str, str]:
    return {"__bytes_hex__": blob.hex()}


# --------------------------------------------------------------------------- #
#  Store helpers                                                               #
# --------------------------------------------------------------------------- #
def _store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


_PROV = (
    "struct_pack(source_file := 'ntds.dit', image_sha256 := 'ab', "
    "source_object_id := NULL, directory_timestamp := NULL, ingest_run_id := NULL)"
)


def _add_staging_node(
    con: duckdb.DuckDBPyConnection, node_id: str, source_id: str, attributes_json: str
) -> None:
    con.execute(
        f"INSERT INTO staging_object (node_id, attributes, forest_id, provenance, source_id) "
        f"VALUES (?, ?, 'f1', {_PROV}, ?)",
        [node_id, attributes_json, source_id],
    )


def _add_node_obs(con: duckdb.DuckDBPyConnection, obj_id: str, source_id: str) -> None:
    con.execute(
        "INSERT INTO source_observation (obj_kind, obj_id, source_id, is_deleted) "
        "VALUES ('node', ?, ?, FALSE)",
        [obj_id, source_id],
    )


def _add_edge_obs(con: duckdb.DuckDBPyConnection, obj_id: str, source_id: str) -> None:
    con.execute(
        "INSERT INTO source_observation (obj_kind, obj_id, source_id, is_deleted) "
        "VALUES ('edge', ?, ?, FALSE)",
        [obj_id, source_id],
    )


def _blob_of(con: duckdb.DuckDBPyConnection, obj_id: str, source_id: str) -> bytes | None:
    row = con.execute(
        "SELECT attr_metadata_blob FROM source_observation "
        "WHERE obj_kind = 'node' AND obj_id = ? AND source_id = ?",
        [obj_id, source_id],
    ).fetchone()
    return None if row is None else row[0]


def _run() -> IngestRun:
    return IngestRun("case-x", "op", ingest_run_id=uuid.uuid4())


# --------------------------------------------------------------------------- #
#  extract_repl_metadata_blob — pure resolve-by-schema                         #
# --------------------------------------------------------------------------- #
def test_extract_by_schema_display_name() -> None:
    js = _attrs_json(replPropertyMetaData=_hex_tag(_VALID_BLOB), sAMAccountName="alice")
    assert extract_repl_metadata_blob(js) == _VALID_BLOB


def test_extract_fallback_column_only() -> None:
    js = _attrs_json(ATTk589827=_hex_tag(_VALID_BLOB))
    assert extract_repl_metadata_blob(js) == _VALID_BLOB


def test_extract_prefers_schema_name_over_fallback() -> None:
    other = _make_blob([(7, 1, 1, 1)])
    js = _attrs_json(replPropertyMetaData=_hex_tag(_VALID_BLOB), ATTk589827=_hex_tag(other))
    assert extract_repl_metadata_blob(js) == _VALID_BLOB


def test_extract_single_element_list_wrapper() -> None:
    js = _attrs_json(replPropertyMetaData=[_hex_tag(_VALID_BLOB)])
    assert extract_repl_metadata_blob(js) == _VALID_BLOB


@pytest.mark.parametrize(
    "js",
    [
        None,
        "",
        "not-json",
        json.dumps({"sAMAccountName": "alice"}),  # key absent
        json.dumps({"replPropertyMetaData": "plainstring"}),  # not a tag
        json.dumps({"replPropertyMetaData": {"__bytes_hex__": "zz"}}),  # bad hex
        json.dumps({"replPropertyMetaData": {"__bytes_hex__": 123}}),  # non-str tag value
        json.dumps({"replPropertyMetaData": [_hex_tag(_VALID_BLOB), _hex_tag(_VALID_BLOB)]}),
        json.dumps(["list", "not", "dict"]),
    ],
)
def test_extract_degrades_to_none(js: str | None) -> None:
    assert extract_repl_metadata_blob(js) is None


# --------------------------------------------------------------------------- #
#  populate_attr_metadata — the wiring                                         #
# --------------------------------------------------------------------------- #
def test_populate_captures_node_leaves_edge_and_counts_absent() -> None:
    con = _store()
    sid = "s-aaaa"
    # node A has metadata; node B does not; one edge observation (never fed).
    _add_node_obs(con, "nodeA", sid)
    _add_node_obs(con, "nodeB", sid)
    _add_edge_obs(con, "edge1", sid)
    _add_staging_node(con, "nodeA", sid, _attrs_json(replPropertyMetaData=_hex_tag(_VALID_BLOB)))
    _add_staging_node(con, "nodeB", sid, _attrs_json(sAMAccountName="bob"))

    run = _run()
    result = populate_attr_metadata(con, sid, run)

    assert (result.nodes_considered, result.captured, result.absent, result.unparseable) == (
        2,
        1,
        1,
        0,
    )
    assert _blob_of(con, "nodeA", sid) == _VALID_BLOB
    assert _blob_of(con, "nodeB", sid) is None
    # the edge observation is never fed
    edge_blob = con.execute(
        "SELECT attr_metadata_blob FROM source_observation WHERE obj_kind='edge' AND obj_id='edge1'"
    ).fetchone()
    assert edge_blob is not None and edge_blob[0] is None
    # counters
    assert run.coverage_counts.get(COV_REPL_METADATA_CAPTURED) == 1
    assert run.skip_counts.get(GAP_REPL_METADATA_ABSENT) == 1
    assert GAP_REPL_METADATA_UNPARSEABLE not in run.skip_counts
    # the captured bytes really decode (tier-1 feed is valid)
    assert parse_repl_property_metadata(_blob_of(con, "nodeA", sid)).num_props == 2


def test_populate_counts_unparseable_but_still_stores() -> None:
    con = _store()
    sid = "s-bbbb"
    garbage = b"\x01\x00\x00\x00"  # valid bytes, invalid vector (length-mismatch)
    _add_node_obs(con, "nodeG", sid)
    _add_staging_node(con, "nodeG", sid, _attrs_json(replPropertyMetaData=_hex_tag(garbage)))

    run = _run()
    result = populate_attr_metadata(con, sid, run)

    assert (result.captured, result.unparseable, result.absent) == (1, 1, 0)
    assert _blob_of(con, "nodeG", sid) == garbage  # stored verbatim, not dropped
    assert run.skip_counts.get(GAP_REPL_METADATA_UNPARSEABLE) == 1


def test_populate_absent_when_no_staging_row() -> None:
    con = _store()
    sid = "s-cccc"
    _add_node_obs(con, "orphan", sid)  # observation with no staging_object
    result = populate_attr_metadata(con, sid, _run())
    assert (result.nodes_considered, result.captured, result.absent) == (1, 0, 1)
    assert _blob_of(con, "orphan", sid) is None


def test_populate_is_source_scoped() -> None:
    con = _store()
    other = _make_blob([(3, 9, 5, 5)])
    _add_node_obs(con, "n1", "sA")
    _add_node_obs(con, "n1", "sB")  # same node_id, different source
    _add_staging_node(con, "n1", "sA", _attrs_json(replPropertyMetaData=_hex_tag(_VALID_BLOB)))
    _add_staging_node(con, "n1", "sB", _attrs_json(replPropertyMetaData=_hex_tag(other)))

    populate_attr_metadata(con, "sA", _run())
    # only sA's observation is touched; sB stays NULL until its own pass runs
    assert _blob_of(con, "n1", "sA") == _VALID_BLOB
    assert _blob_of(con, "n1", "sB") is None

    populate_attr_metadata(con, "sB", _run())
    assert _blob_of(con, "n1", "sA") == _VALID_BLOB
    assert _blob_of(con, "n1", "sB") == other


def test_populate_is_deterministic_and_idempotent() -> None:
    def build() -> tuple[bytes | None, tuple[int, int, int, int]]:
        con = _store()
        sid = "s-det"
        _add_node_obs(con, "n", sid)
        _add_staging_node(con, "n", sid, _attrs_json(replPropertyMetaData=_hex_tag(_VALID_BLOB)))
        r1 = populate_attr_metadata(con, sid, _run())
        r2 = populate_attr_metadata(con, sid, _run())  # re-run: identical
        assert (r1.captured, r1.absent) == (r2.captured, r2.absent)
        return _blob_of(con, "n", sid), (
            r2.nodes_considered,
            r2.captured,
            r2.absent,
            r2.unparseable,
        )

    assert build() == build()


# --------------------------------------------------------------------------- #
#  divergence ledger scaffolding                                               #
# --------------------------------------------------------------------------- #
def test_divergence_table_not_created_by_canonical_bootstrap() -> None:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    present = {
        r[0] for r in con.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }
    assert "divergence" not in present  # single-source path unchanged
    create_divergence_table(con)
    present2 = {
        r[0] for r in con.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }
    assert "divergence" in present2


def test_divergence_table_has_contract_columns_and_no_authoritative_dc() -> None:
    con = duckdb.connect(":memory:")
    create_divergence_table(con)
    cols = {
        r[0]: r[1]
        for r in con.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name = 'divergence'"
        ).fetchall()
    }
    assert set(cols) == {
        "obj_kind",
        "obj_id",
        "attribute",
        "value_by_source",
        "divergence_type",
        "resolution",
        "resolved_value",
        "resolved_by",
        "counted",
        "ingest_run_id",
    }
    assert cols["value_by_source"] == "JSON"
    # resolved_by is a free VARCHAR (no enum constraint); the writer (M-MS4b) is
    # what must never emit 'authoritative_dc'. A smoke insert of each allowed value
    # succeeds and 'authoritative_dc' is simply never written by WRAITH.
    run_id = str(uuid.uuid4())
    for rb in ("per_attr_meta", "whenChanged", "safer_reading", None):
        con.execute(
            "INSERT INTO divergence (obj_kind, obj_id, value_by_source, divergence_type, "
            "resolved_by, ingest_run_id) VALUES ('node', 'n', '{}', 'attribute_divergence', ?, ?)",
            [rb, run_id],
        )
    n = con.execute("SELECT COUNT(*) FROM divergence").fetchone()[0]
    assert n == 4


def test_divergence_create_is_idempotent() -> None:
    con = duckdb.connect(":memory:")
    create_divergence_table(con)
    create_divergence_table(con)  # no raise
    assert con.execute("SELECT COUNT(*) FROM divergence").fetchone()[0] == 0
