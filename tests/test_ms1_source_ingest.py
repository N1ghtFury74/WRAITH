"""M-MS1 — case-shape + multi-source ingest/tagging (coder-side unit/golden).

Three layers, all synthetic (the plumbing + reconciliation need no real ``.dit``;
contract §6 M-MS1 "needs a real capture to validate: nothing critical"):

* **Schema** — the additive ``source`` / ``source_observation`` tables, the
  widened ``staging_object`` PK ``(node_id, source_id)`` (two DCs' copies coexist),
  the ``source_id`` column on ``staging_link`` (keyless by design), and that the
  frozen single-column PKs are untouched.
* **Pure reconciliation** — :func:`reconcile_case_shape` fires each counted
  mismatch gap exactly in its declared branch and stays silent when consistent;
  :func:`derive_source_id` is deterministic + guards empty keys.
* **Writers + 2-source fixture** — ``source`` label-uniqueness is a hard error;
  ``source_observation`` registers one row per canonical node/edge; a 2-source
  multi-domain store keeps both sources' observations distinct with zero bleed,
  and single-source is byte-identical apart from the stamped sentinel.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import duckdb
import pytest

from wraith.model.source import (
    GAP_LABEL_DOMAIN_MISMATCH,
    GAP_MULTIPLE_DOMAINS,
    GAP_SAME_DOMAIN_TWO_DCS,
    SourceDomainFacts,
    SourceRecord,
    derive_source_id,
    reconcile_case_shape,
    write_source_observations,
    write_source_row,
)
from wraith.model.store import (
    DEFAULT_SOURCE_ID,
    create_canonical_tables,
    create_edge_tables,
)

# --------------------------------------------------------------------------- #
#  Minimal synthetic canonical store (no real .dit needed)                     #
# --------------------------------------------------------------------------- #
_PROV = (
    "struct_pack("
    "source_file := 'ntds.dit', image_sha256 := 'ab', source_object_id := NULL, "
    "directory_timestamp := TIMESTAMP '2020-01-02 03:04:05', ingest_run_id := NULL)"
)


def _store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _add_principal(con: duckdb.DuckDBPyConnection, node_id: str, domain_id: str) -> None:
    con.execute(
        f"INSERT INTO principal (node_id, principal_type, forest_id, domain_id, "
        f"when_created, provenance) VALUES (?, 'User', 'f1', ?, "
        f"TIMESTAMP '2021-05-05 00:00:00', {_PROV})",
        [node_id, domain_id],
    )


def _add_edge(con: duckdb.DuckDBPyConnection, edge_id: str, src: str, tgt: str) -> None:
    con.execute(
        f"INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, "
        f"provenance) VALUES (?, 'MemberOf', ?, ?, 'f1', {_PROV})",
        [edge_id, src, tgt],
    )


def _source(
    con: duckdb.DuckDBPyConnection,
    *,
    source_id: str,
    case_id: str,
    dc_label: str,
    domain_id: str | None,
    domain_fqdn: str | None = None,
    declared: str | None = None,
) -> None:
    write_source_row(
        con,
        SourceRecord(
            source_id=source_id,
            case_id=case_id,
            dc_label=dc_label,
            forest_id="f1",
            domain_id=domain_id,
            domain_fqdn=domain_fqdn,
            declared_domain=declared,
            ntds_image_sha256="ab" * 32,
            system_image_sha256=None,
            ingest_run_id=uuid4(),
            ingested_at=datetime.now(UTC),
        ),
    )


# --------------------------------------------------------------------------- #
#  Schema layer                                                                #
# --------------------------------------------------------------------------- #
def test_additive_tables_created() -> None:
    con = _store()
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    assert {"source", "source_observation"} <= tables
    # M-MS4's divergence ledger is explicitly NOT created by M-MS1.
    assert "divergence" not in tables


def test_frozen_node_pk_is_single_column() -> None:
    con = _store()
    # principal keeps its single-column node_id PRIMARY KEY (frozen contract §2.1).
    con.execute(
        f"INSERT INTO principal (node_id, principal_type, forest_id, provenance) "
        f"VALUES ('n1', 'User', 'f1', {_PROV})"
    )
    with pytest.raises(duckdb.ConstraintException):
        con.execute(
            f"INSERT INTO principal (node_id, principal_type, forest_id, provenance) "
            f"VALUES ('n1', 'User', 'f1', {_PROV})"
        )


def test_staging_object_pk_widened_to_node_and_source() -> None:
    con = _store()
    base = ["n1", 1, None, None, ["top"], None, "{}", "f1", None, None, None]
    # Same node_id under TWO different source_ids coexist (Phase-2 substrate).
    con.execute("INSERT INTO staging_object VALUES " + _ph(12), [*base, "src-A"])
    con.execute("INSERT INTO staging_object VALUES " + _ph(12), [*base, "src-B"])
    assert con.execute("SELECT COUNT(*) FROM staging_object").fetchone()[0] == 2
    # Same (node_id, source_id) violates the widened PK.
    with pytest.raises(duckdb.ConstraintException):
        con.execute("INSERT INTO staging_object VALUES " + _ph(12), [*base, "src-A"])


def test_staging_link_has_source_id_and_tolerates_null_endpoints() -> None:
    con = _store()
    # A dangling link (NULL endpoints) + a duplicate triple both insert: staging_link
    # is keyless by design (endpoints are legitimately nullable/non-unique). 15 base
    # columns (11 link + forest_id/domain_id/domain_fqdn + provenance) + source_id.
    row = [1, None, None, None, None, None, None, None, None, None, None, "f1", None, None, None]
    con.execute("INSERT INTO staging_link VALUES " + _ph(16), [*row, "src-A"])
    con.execute("INSERT INTO staging_link VALUES " + _ph(16), [*row, "src-A"])
    assert con.execute("SELECT COUNT(*) FROM staging_link").fetchone()[0] == 2
    # source_id is NOT NULL (the attribution guarantee still holds).
    with pytest.raises((duckdb.ConstraintException, duckdb.InvalidInputException)):
        con.execute("INSERT INTO staging_link VALUES " + _ph(16), [*row, None])


def _ph(n: int) -> str:
    return "(" + ",".join("?" * n) + ")"


# --------------------------------------------------------------------------- #
#  derive_source_id — deterministic                                            #
# --------------------------------------------------------------------------- #
def test_derive_source_id_is_deterministic_and_valid_uuid() -> None:
    a = derive_source_id("case1", "DC01", "AB" * 32)
    b = derive_source_id("case1", "DC01", "ab" * 32)  # sha lowercased internally
    assert a == b
    assert UUID(a).version == 5
    assert derive_source_id("case1", "DC02", "ab" * 32) != a


def test_derive_source_id_rejects_blank_key() -> None:
    with pytest.raises(ValueError):
        derive_source_id("", "DC01", "ab")
    with pytest.raises(ValueError):
        derive_source_id("c", "", "ab")
    with pytest.raises(ValueError):
        derive_source_id("c", "DC01", "")


# --------------------------------------------------------------------------- #
#  reconcile_case_shape — each counted branch                                  #
# --------------------------------------------------------------------------- #
def _facts(sid: str, declared: str | None, did: str | None, fqdn: str | None) -> SourceDomainFacts:
    return SourceDomainFacts(
        source_id=sid,
        dc_label=sid,
        declared_domain=declared,
        derived_domain_id=did,
        derived_domain_fqdn=fqdn,
    )


def test_reconcile_clean_single_source_no_gaps() -> None:
    facts = [_facts("s1", "corp.example.com", "S-1-5-21-1", "corp.example.com")]
    assert reconcile_case_shape("single_domain", "single_dc", facts) == []


def test_reconcile_label_domain_mismatch_counted() -> None:
    facts = [_facts("s1", "prod.local", "S-1-5-21-1", "corp.local")]
    gaps = reconcile_case_shape("single_domain", "single_dc", facts)
    assert (GAP_LABEL_DOMAIN_MISMATCH, 1) in gaps


def test_reconcile_label_short_name_is_not_a_mismatch() -> None:
    # Operator typed the short NetBIOS-ish name; leading label matches -> no flag.
    facts = [_facts("s1", "corp", "S-1-5-21-1", "corp.example.com")]
    assert reconcile_case_shape("single_domain", "single_dc", facts) == []


def test_reconcile_multiple_domains_detected_counted() -> None:
    facts = [
        _facts("s1", None, "S-1-5-21-1", "a.example.com"),
        _facts("s2", None, "S-1-5-21-2", "b.example.com"),
    ]
    gaps = dict(reconcile_case_shape("single_domain", "single_dc", facts))
    assert gaps[GAP_MULTIPLE_DOMAINS] == 1  # distinct_domains - 1
    assert GAP_SAME_DOMAIN_TWO_DCS not in gaps


def test_reconcile_same_domain_two_dcs_counted() -> None:
    facts = [
        _facts("s1", None, "S-1-5-21-1", "a.example.com"),
        _facts("s2", None, "S-1-5-21-1", "a.example.com"),
    ]
    gaps = dict(reconcile_case_shape("multi_domain", "single_dc", facts))
    assert gaps[GAP_SAME_DOMAIN_TWO_DCS] == 1  # one redundant same-domain source
    assert GAP_MULTIPLE_DOMAINS not in gaps


# --------------------------------------------------------------------------- #
#  Writers + single/2-source fixtures                                          #
# --------------------------------------------------------------------------- #
def test_source_label_uniqueness_is_hard_error() -> None:
    con = _store()
    _source(con, source_id="s1", case_id="c1", dc_label="DC01", domain_id="S-1-5-21-1")
    with pytest.raises(duckdb.ConstraintException):
        _source(con, source_id="s2", case_id="c1", dc_label="DC01", domain_id="S-1-5-21-9")
    # Same label in a DIFFERENT case is fine.
    _source(con, source_id="s3", case_id="c2", dc_label="DC01", domain_id="S-1-5-21-1")


def test_single_source_one_observation_per_node_and_edge() -> None:
    con = _store()
    sid = derive_source_id("c1", "primary-dc", "ab" * 32)
    _add_principal(con, "n1", "S-1-5-21-1")
    _add_principal(con, "n2", "S-1-5-21-1")
    _add_edge(con, "e1", "n1", "n2")
    _source(con, source_id=sid, case_id="c1", dc_label="primary-dc", domain_id="S-1-5-21-1")

    written = write_source_observations(con, sid)
    assert written == 3  # 2 nodes + 1 edge
    rows = con.execute(
        "SELECT obj_kind, obj_id, directory_timestamp, is_deleted FROM source_observation "
        "WHERE source_id = ? ORDER BY obj_kind, obj_id",
        [sid],
    ).fetchall()
    assert [(r[0], r[1]) for r in rows] == [
        ("edge", "e1"),
        ("node", "n1"),
        ("node", "n2"),
    ]
    # directory_timestamp flows from provenance.whenChanged; is_deleted is FALSE.
    assert all(r[2] == datetime(2020, 1, 2, 3, 4, 5) for r in rows)
    assert all(r[3] is False for r in rows)
    # Node observations carry when_created; edge does not.
    node_wc = con.execute(
        "SELECT when_created FROM source_observation WHERE obj_kind='node' AND source_id=? LIMIT 1",
        [sid],
    ).fetchone()[0]
    assert node_wc == datetime(2021, 5, 5, 0, 0, 0)


def test_observations_rewrite_is_idempotent() -> None:
    con = _store()
    sid = derive_source_id("c1", "primary-dc", "ab" * 32)
    _add_principal(con, "n1", "S-1-5-21-1")
    _source(con, source_id=sid, case_id="c1", dc_label="primary-dc", domain_id="S-1-5-21-1")
    assert write_source_observations(con, sid) == 1
    assert write_source_observations(con, sid) == 1  # no PK blow-up, no dupes
    assert con.execute("SELECT COUNT(*) FROM source_observation").fetchone()[0] == 1


def test_two_source_multi_domain_fixture_no_bleed() -> None:
    con = _store()
    s1 = derive_source_id("c1", "DC-ROOT", "ab" * 32)
    s2 = derive_source_id("c1", "DC-CHILD", "cd" * 32)
    assert s1 != s2
    # Two distinct domains, distinct node_ids (forest-scoped objectGUID => no clash).
    _add_principal(con, "root-n1", "S-1-5-21-root")
    _add_principal(con, "child-n1", "S-1-5-21-child")
    _source(con, source_id=s1, case_id="c1", dc_label="DC-ROOT", domain_id="S-1-5-21-root")
    _source(con, source_id=s2, case_id="c1", dc_label="DC-CHILD", domain_id="S-1-5-21-child")

    # Each source observes ALL current canonical nodes in this shared store; the
    # scoping is the source_id filter (per-source view = WHERE source_id = ?).
    write_source_observations(con, s1)
    write_source_observations(con, s2)
    assert (
        con.execute("SELECT COUNT(*) FROM source_observation WHERE source_id = ?", [s1]).fetchone()[
            0
        ]
        == 2
    )
    # Two source rows, distinct ids, both present.
    assert con.execute("SELECT COUNT(*) FROM source").fetchone()[0] == 2

    # The multi_domain reconciliation over the two source rows counts the shape.
    rows = con.execute(
        "SELECT source_id, dc_label, declared_domain, domain_id, domain_fqdn FROM source "
        "WHERE case_id = ? ORDER BY source_id",
        ["c1"],
    ).fetchall()
    facts = [SourceDomainFacts(str(r[0]), str(r[1]), r[2], r[3], r[4]) for r in rows]
    # Declared single_domain but two domains present -> counted.
    assert (GAP_MULTIPLE_DOMAINS, 1) in reconcile_case_shape("single_domain", "single_dc", facts)
    # Declared multi_domain + single_dc, distinct domains -> consistent, no gap.
    assert reconcile_case_shape("multi_domain", "single_dc", facts) == []


def test_default_source_id_is_a_valid_uuid_sentinel() -> None:
    assert UUID(DEFAULT_SOURCE_ID).version == 5


# --------------------------------------------------------------------------- #
#  Untrusted per-source tag hardening (upload form fields)                     #
# --------------------------------------------------------------------------- #
def test_clean_source_tag_trims_and_blanks_to_none() -> None:
    from wraith.api.ingest import _clean_source_tag

    assert _clean_source_tag(None, "dc_label") is None
    assert _clean_source_tag("   ", "dc_label") is None
    assert _clean_source_tag("  DC01 ", "dc_label", reject_controls=True) == "DC01"


def test_clean_source_tag_rejects_overlong_with_422() -> None:
    from wraith.api.ingest import _clean_source_tag, _UploadRejected

    with pytest.raises(_UploadRejected) as ei:
        _clean_source_tag("x" * 257, "dc_label", reject_controls=True)
    assert ei.value.status_code == 422
    assert ei.value.reason == "dc_label_too_long"


def test_clean_source_tag_rejects_control_chars_in_dc_label_with_422() -> None:
    from wraith.api.ingest import _clean_source_tag, _UploadRejected

    # The \x1f seed-separator invariant in derive_source_id depends on this.
    with pytest.raises(_UploadRejected) as ei:
        _clean_source_tag("DC\x1f01", "dc_label", reject_controls=True)
    assert ei.value.status_code == 422
    assert ei.value.reason == "dc_label_invalid_chars"


# --------------------------------------------------------------------------- #
#  API upload layer — dc_label collision is a hard 409 (contract §1.3)         #
#  (gate layer-3: a dc_label collision across uploads => 409 dc_label_not_unique)
# --------------------------------------------------------------------------- #
def test_upload_dc_label_collision_is_hard_409(tmp_path: object) -> None:
    from wraith.api.ingest import UploadEntry, _index_put, _UploadRejected
    from wraith.case.catalog import artifact_kind
    from wraith.case.workspace import create_workspace

    ws = create_workspace(tmp_path, "c1")  # type: ignore[arg-type]
    ntds = artifact_kind("ntds_dit")
    assert ntds is not None
    addl = artifact_kind("additional_dc")
    assert addl is not None

    first = UploadEntry(
        source_file="ntds.dit",
        host_label=None,
        stored_rel_path="artifacts/ntds.dit",
        system_stored_rel_path=None,
        image_sha256="ab" * 32,
        size_bytes=1,
        dc_label="DC01",
    )
    _index_put(ws, ntds, first)

    # A DIFFERENT source (distinct stored path) reusing the SAME dc_label => 409.
    collide = UploadEntry(
        source_file="dc:DC01",
        host_label="dc01",
        stored_rel_path="artifacts/dc_dc01/ntds.dit",
        system_stored_rel_path=None,
        image_sha256="cd" * 32,
        size_bytes=1,
        dc_label="DC01",
    )
    with pytest.raises(_UploadRejected) as exc:
        _index_put(ws, addl, collide)
    assert exc.value.status_code == 409
    assert exc.value.reason == "dc_label_not_unique"

    # Re-uploading the SAME source (same stored path + label) is NOT a collision.
    _index_put(ws, ntds, first)
