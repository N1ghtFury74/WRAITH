"""M-MS4b — the opt-in multi-DC merge fold + divergence ledger + DC-vs-DC report.

SYNTHETIC only. These prove the PLUMBING, the §3.2 taxonomy, the §3.3 ladder, the
secret-divergence-redacted-never-picked discipline, idempotency, the opt-in
mechanism, and the DC-vs-DC report. They do NOT prove the four real divergence
shapes or the real ``replPropertyMetaData`` / ``msDS-ReplValueMetaData`` byte
parity — those need a real multi-DC capture with deliberate divergence (contract
§7.7), flagged untested-on-real.

The one real-``.dit`` regression (``c137`` ingested twice → one presented row per
node, ZERO spurious divergence) is marked ``real_dit`` + skipped without evidence,
and MUST be run SOLO (concurrent real-``.dit`` builds deadlock).
"""

from __future__ import annotations

import json
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.merge.fold import (
    COV_NODES_MERGED,
    GAP_GC_SOURCE_IN_SELECTION,
    GAP_NOTHING_TO_MERGE,
    GAP_REPL_BLOB_UNPARSEABLE,
    GAP_SECRET_DIVERGENCE,
    GAP_STAGING_ATTRS_UNPARSEABLE,
    GAP_TIER1_UNAVAILABLE,
    DivergenceType,
    EntityVerdict,
    NodeObservation,
    PresentedState,
    ResolvedBy,
    SecretFingerprint,
    classify_edge,
    classify_entity,
    compare_secrets,
    decode_node_stamps,
    default_safer_reading,
    merge_fold,
    presented_attribute,
    resolve_attribute,
    tier1_per_attribute,
    tier2_when_changed,
)
from wraith.model.store import (
    create_canonical_tables,
    create_divergence_table,
    create_edge_tables,
)
from wraith.parsing.repl_metadata import ReplAttributeStamp

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
_SRC_A = "11111111-1111-5111-8111-111111111111"
_SRC_B = "22222222-2222-5222-8222-222222222222"
_RUN = UUID(int=0xBEEF)


# --------------------------------------------------------------------------- #
#  Synthetic blob + store helpers                                             #
# --------------------------------------------------------------------------- #
def _make_blob(entries: list[tuple[int, int, int, int]], dsa: str) -> bytes:
    """Build a PROPERTY_META_DATA_EXT_VECTOR from (attid, version, dstime, usn)."""
    out = struct.pack("<III", 1, 0, len(entries))
    dsa_uuid = uuid.UUID(dsa)
    for attid, version, dstime, usn in entries:
        out += struct.pack("<IIq", attid, version, dstime)
        out += dsa_uuid.bytes_le
        out += struct.pack("<q", usn)
    return out


def _stamp(attid: int, version: int, dstime: int, usn: int) -> ReplAttributeStamp:
    return ReplAttributeStamp(
        attid=attid,
        version=version,
        time_changed=_EPOCH_1601,
        originating_dsa="00000000-0000-0000-0000-000000000000",
        originating_usn=usn,
    )


def _store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    create_divergence_table(con)
    return con


_PROV = (
    "struct_pack(source_file := 'ntds.dit', image_sha256 := 'ab', "
    "source_object_id := NULL, directory_timestamp := NULL, ingest_run_id := NULL)"
)


def _add_node_obs(
    con: duckdb.DuckDBPyConnection,
    obj_id: str,
    source_id: str,
    *,
    is_deleted: bool = False,
    when_changed: datetime | None = None,
    blob: bytes | None = None,
) -> None:
    con.execute(
        "INSERT INTO source_observation "
        "(obj_kind, obj_id, source_id, is_deleted, directory_timestamp, attr_metadata_blob) "
        "VALUES ('node', ?, ?, ?, ?, ?)",
        [obj_id, source_id, is_deleted, when_changed, blob],
    )


def _add_edge_obs(con: duckdb.DuckDBPyConnection, obj_id: str, source_id: str) -> None:
    con.execute(
        "INSERT INTO source_observation (obj_kind, obj_id, source_id, is_deleted) "
        "VALUES ('edge', ?, ?, FALSE)",
        [obj_id, source_id],
    )


def _add_staging_node(
    con: duckdb.DuckDBPyConnection, node_id: str, source_id: str, **attrs: object
) -> None:
    con.execute(
        f"INSERT INTO staging_object (node_id, attributes, forest_id, provenance, source_id) "
        f"VALUES (?, ?, 'f1', {_PROV}, ?)",
        [node_id, json.dumps(attrs), source_id],
    )


def _ledger(con: duckdb.DuckDBPyConnection) -> list[dict[str, object]]:
    rows = con.execute(
        "SELECT obj_kind, obj_id, attribute, value_by_source, divergence_type, "
        "resolution, resolved_value, resolved_by, counted, ingest_run_id "
        "FROM divergence ORDER BY obj_kind, obj_id, attribute"
    ).fetchall()
    cols = [
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
    ]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def _by_type(con: duckdb.DuckDBPyConnection, dtype: str) -> list[dict[str, object]]:
    return [r for r in _ledger(con) if r["divergence_type"] == dtype]


# =========================================================================== #
#  PURE: classify_entity (§3.2 entity taxonomy)                               #
# =========================================================================== #
def test_classify_entity_consistent_present_live_on_all() -> None:
    obs = [NodeObservation(_SRC_A, False, None, None), NodeObservation(_SRC_B, False, None, None)]
    assert classify_entity(obs, 2) is EntityVerdict.CONSISTENT


def test_classify_entity_deleted_on_source() -> None:
    obs = [NodeObservation(_SRC_A, True, None, None), NodeObservation(_SRC_B, False, None, None)]
    assert classify_entity(obs, 2) is EntityVerdict.DELETED_ON_SOURCE


def test_classify_entity_candidate_lingering_live_on_subset() -> None:
    obs = [NodeObservation(_SRC_B, False, None, None)]  # live on B, absent on A
    assert classify_entity(obs, 2) is EntityVerdict.CANDIDATE_LINGERING_OBJECT


def test_classify_entity_tombstone_only_subset_is_not_lingering() -> None:
    obs = [NodeObservation(_SRC_B, True, None, None)]  # tombstone on B only
    assert classify_entity(obs, 2) is EntityVerdict.CONSISTENT


# =========================================================================== #
#  PURE: classify_edge (§3.5)                                                 #
# =========================================================================== #
def test_classify_edge_subset_diverges_and_full_does_not() -> None:
    assert classify_edge([_SRC_A], 2) is True
    assert classify_edge([_SRC_A, _SRC_B], 2) is False
    assert classify_edge([], 2) is False  # never fabricate (no observation)


# =========================================================================== #
#  PURE: the §3.3 ladder primitives                                           #
# =========================================================================== #
def test_tier1_clear_winner_by_version() -> None:
    stamps = {_SRC_A: _stamp(1, 5, 10, 1), _SRC_B: _stamp(1, 9, 1, 1)}
    winner, tied = tier1_per_attribute(stamps)
    assert winner == _SRC_B and tied is False


def test_tier1_true_tie_not_resolved() -> None:
    stamps = {_SRC_A: _stamp(1, 7, 100, 50), _SRC_B: _stamp(1, 7, 100, 50)}
    winner, tied = tier1_per_attribute(stamps)
    assert winner is None and tied is True


def test_tier1_single_stamp_unavailable() -> None:
    assert tier1_per_attribute({_SRC_A: _stamp(1, 7, 1, 1)}) == (None, False)


def test_tier2_clear_single_newer() -> None:
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    assert tier2_when_changed({_SRC_A: older, _SRC_B: newer}) == _SRC_B


def test_tier2_tie_returns_none() -> None:
    same = datetime(2022, 1, 1, tzinfo=UTC)
    assert tier2_when_changed({_SRC_A: same, _SRC_B: same}) is None


def test_default_safer_reading_uac_prefers_enabled() -> None:
    # A: 0x202 (disabled), B: 0x200 (enabled). Safer = enabled (B's 0x200 == 512).
    safer = default_safer_reading("userAccountControl", {_SRC_A: 0x202, _SRC_B: 0x200})
    assert safer == 0x200


def test_default_safer_reading_admincount_prefers_one() -> None:
    assert default_safer_reading("adminCount", {_SRC_A: 0, _SRC_B: 1}) == 1


def test_default_safer_reading_unknown_attribute_is_none() -> None:
    assert default_safer_reading("description", {_SRC_A: "x", _SRC_B: "y"}) is None


# =========================================================================== #
#  PURE: widened default_safer_reading registry (attacker-lens correctness)   #
# =========================================================================== #
def test_safer_reading_uac_not_delegated_is_inverse() -> None:
    # Both ENABLED; A is delegable (NOT_DELEGATED clear), B is protected (0x100000
    # set). The dangerous reading is the delegable copy A — a pure NOT_DELEGATED
    # divergence must NOT tie and silently present the protected copy.
    assert default_safer_reading("userAccountControl", {_SRC_A: 0x200, _SRC_B: 0x100200}) == 0x200


def test_safer_reading_uac_dangerous_bits() -> None:
    # B has DONT_REQ_PREAUTH (0x400000) set -> more dangerous than plain enabled A.
    assert (
        default_safer_reading("userAccountControl", {_SRC_A: 0x200, _SRC_B: 0x400200}) == 0x400200
    )


def test_safer_reading_sidhistory_nonempty_dangerous() -> None:
    assert default_safer_reading("sIDHistory", {_SRC_A: [], _SRC_B: ["S-1-5-21-x-519"]}) == [
        "S-1-5-21-x-519"
    ]


def test_safer_reading_spn_more_entries_dangerous() -> None:
    val = default_safer_reading("servicePrincipalName", {_SRC_A: ["a"], _SRC_B: ["a", "b"]})
    assert val == ["a", "b"]


def test_safer_reading_keycredlink_and_rbcd_present_dangerous() -> None:
    assert default_safer_reading(
        "msDS-KeyCredentialLink", {_SRC_A: [], _SRC_B: [{"__bytes_hex__": "ab"}]}
    ) == [{"__bytes_hex__": "ab"}]
    assert default_safer_reading(
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        {_SRC_A: None, _SRC_B: {"__bytes_hex__": "ff"}},
    ) == {"__bytes_hex__": "ff"}


def test_safer_reading_primarygroupid_more_privileged() -> None:
    # 512 Domain Admins is more dangerous than 513 Domain Users.
    assert default_safer_reading("primaryGroupID", {_SRC_A: 513, _SRC_B: 512}) == 512


# =========================================================================== #
#  PURE: decode_node_stamps — corrupt blob counted distinctly from "no blob"  #
# =========================================================================== #
def test_decode_node_stamps_counts_corrupt_distinct_from_absent() -> None:
    dsa = "11111111-1111-1111-1111-111111111111"
    obs = [
        NodeObservation(_SRC_A, False, None, _make_blob([(13, 5, 10, 1)], dsa)),  # valid
        NodeObservation(_SRC_B, False, None, b"\x01\x00\x00\x00corrupt"),  # corrupt
        NodeObservation("s3", False, None, None),  # no blob (absent, not corrupt)
    ]
    decoded, corrupt = decode_node_stamps(obs)
    assert corrupt == 1 and set(decoded) == {_SRC_A} and 13 in decoded[_SRC_A]


# =========================================================================== #
#  PURE: resolve_attribute down the ladder (new stamps_by_source signature)    #
# =========================================================================== #
def _stamps(va: int, vb: int, attid: int = 13) -> dict[str, ReplAttributeStamp]:
    return {_SRC_A: _stamp(attid, va, 10, 1), _SRC_B: _stamp(attid, vb, 10, 1)}


def test_resolve_tier1_per_attr_meta() -> None:
    res = resolve_attribute(
        "description",
        {_SRC_A: "old", _SRC_B: "new"},
        {_SRC_A: None, _SRC_B: None},
        stamps_by_source=_stamps(2, 9),  # B newer by version
        safer_reading=default_safer_reading,
    )
    assert res.resolved_by is ResolvedBy.PER_ATTR_META
    assert res.resolved_value == "new" and res.winning_source == _SRC_B
    assert res.resolution == "per_attr_meta" and res.tier1_available is True


def test_resolve_tier1_winner_value_absent_descends_never_null_resolved() -> None:
    # Tier-1 winner is B but B's value is absent from staging -> must NOT emit a
    # "resolved" row with a null value; descend to tier-2 (A older, B newer, B absent)
    # -> tier-3 (description unknown) -> unresolved, nothing picked.
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    res = resolve_attribute(
        "description",
        {_SRC_A: "only-A"},
        {_SRC_A: older, _SRC_B: newer},
        stamps_by_source=_stamps(2, 9),  # B wins tier-1 but has no value
        safer_reading=default_safer_reading,
    )
    assert res.resolution == "unresolved" and res.resolved_by is None
    assert res.resolved_value is None and res.tier1_available is True


def test_resolve_tier1_tie_falls_to_tier3_not_tier2() -> None:
    # Stamps tie at tier-1; whenChanged would favour B, but a TIED stamp is NOT
    # resolved and must NOT be overridden by the blunter object-level signal.
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    res = resolve_attribute(
        "description",
        {_SRC_A: "x", _SRC_B: "y"},
        {_SRC_A: None, _SRC_B: newer},
        stamps_by_source=_stamps(5, 5),  # identical version -> TIED
        safer_reading=default_safer_reading,
    )
    # description has no danger ordering -> unresolved, nothing picked.
    assert res.resolution == "unresolved" and res.resolved_by is None
    assert res.resolved_value is None and res.tier1_available is True


def test_resolve_tier2_when_changed_when_no_blob() -> None:
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    res = resolve_attribute(
        "description",
        {_SRC_A: "old", _SRC_B: "new"},
        {_SRC_A: older, _SRC_B: newer},
        stamps_by_source={},  # tier-1 unavailable
        safer_reading=default_safer_reading,
    )
    assert res.resolved_by is ResolvedBy.WHEN_CHANGED
    assert res.resolved_value == "new" and res.tier1_available is False


def test_resolve_tier3_safer_reading_uac() -> None:
    res = resolve_attribute(
        "userAccountControl",
        {_SRC_A: 0x202, _SRC_B: 0x200},  # A disabled, B enabled
        {_SRC_A: None, _SRC_B: None},  # equal whenChanged -> no tier-2
        stamps_by_source={},  # no tier-1
        safer_reading=default_safer_reading,
    )
    assert res.resolution == "unresolved" and res.resolved_by is ResolvedBy.SAFER_READING
    assert res.resolved_value == 0x200  # the enabled (more dangerous) reading


def test_resolve_tier3_unknown_presents_nothing() -> None:
    res = resolve_attribute(
        "description",
        {_SRC_A: "x", _SRC_B: "y"},
        {_SRC_A: None, _SRC_B: None},
        stamps_by_source={},
        safer_reading=default_safer_reading,
    )
    assert res.resolution == "unresolved" and res.resolved_by is None
    assert res.resolved_value is None


# =========================================================================== #
#  PURE: compare_secrets (redacted digests only)                              #
# =========================================================================== #
def _fp(digest: str) -> frozenset[SecretFingerprint]:
    return frozenset({SecretFingerprint("nt_hash", "", digest)})


def test_compare_secrets_differs() -> None:
    assert compare_secrets({_SRC_A: _fp("aaaa"), _SRC_B: _fp("bbbb")}) is True


def test_compare_secrets_identical_no_divergence() -> None:
    assert compare_secrets({_SRC_A: _fp("aaaa"), _SRC_B: _fp("aaaa")}) is False


def test_compare_secrets_holder_set_divergence() -> None:
    # A holds a secret, B (observing) holds none -> un-replicated / missing-on-B.
    assert compare_secrets({_SRC_A: _fp("aaaa"), _SRC_B: frozenset()}) is True
    # two identical holders + a third observing source with none -> still divergence
    # (the third is missing the replicated secret) — named, never dropped.
    assert compare_secrets({_SRC_A: _fp("aaaa"), _SRC_B: _fp("aaaa"), "s3": frozenset()}) is True
    # no secret material anywhere -> no divergence.
    assert compare_secrets({_SRC_A: frozenset(), _SRC_B: frozenset()}) is False
    # single observing source -> nothing to compare.
    assert compare_secrets({_SRC_A: _fp("aaaa")}) is False


def test_compare_secrets_history_label_present_on_one_only() -> None:
    a = frozenset(
        {SecretFingerprint("nt_hash", "", "h"), SecretFingerprint("nt_hash", "history1", "x")}
    )
    b = frozenset({SecretFingerprint("nt_hash", "", "h")})
    assert compare_secrets({_SRC_A: a, _SRC_B: b}) is True


# =========================================================================== #
#  FOLD: scenario 1 — object deleted on one DC                                #
# =========================================================================== #
def test_fold_deleted_on_source() -> None:
    con = _store()
    _add_node_obs(con, "nodeX", _SRC_A, is_deleted=True)
    _add_node_obs(con, "nodeX", _SRC_B, is_deleted=False)
    _add_staging_node(con, "nodeX", _SRC_A, sAMAccountName="x")
    _add_staging_node(con, "nodeX", _SRC_B, sAMAccountName="x")

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    rows = _by_type(con, DivergenceType.DELETED_ON_SOURCE.value)
    assert len(rows) == 1 and result.deleted_on_source == 1
    assert rows[0]["resolution"] == "present_live"
    assert _SRC_B in json.loads(str(rows[0]["resolved_value"]))["present_live_from"]


# =========================================================================== #
#  FOLD: scenario 2 — divergent membership (edge on A not B)                   #
# =========================================================================== #
def test_fold_edge_membership_divergence_union_never_fabricate() -> None:
    con = _store()
    # both DCs assert edge1; only A asserts edge2 (divergent membership).
    _add_edge_obs(con, "edge1", _SRC_A)
    _add_edge_obs(con, "edge1", _SRC_B)
    _add_edge_obs(con, "edge2", _SRC_A)
    # register the source set so selected_count == 2
    _add_node_obs(con, "n", _SRC_A)
    _add_node_obs(con, "n", _SRC_B)

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    rows = _by_type(con, DivergenceType.EDGE_MEMBERSHIP_DIVERGENCE.value)
    assert len(rows) == 1 and result.edge_membership_divergences == 1
    assert rows[0]["obj_id"] == "edge2"  # edge1 (on both) is consistent, no row
    present = json.loads(str(rows[0]["resolved_value"]))["present_on"]
    assert present == [_SRC_A]  # kept present-on-A, never dropped


# =========================================================================== #
#  FOLD: scenario 3 — un-replicated secret (hash differs), redacted/never pick #
# =========================================================================== #
def test_fold_secret_divergence_redacted_never_plaintext() -> None:
    con = _store()
    _add_node_obs(con, "userP", _SRC_A)
    _add_node_obs(con, "userP", _SRC_B)
    _add_staging_node(con, "userP", _SRC_A, sAMAccountName="p")
    _add_staging_node(con, "userP", _SRC_B, sAMAccountName="p")
    plaintextish_a = "aad3b435b51404eeaad3b435b51404ee"  # a (fake) hash digest
    fingerprints = {
        ("userP", _SRC_A): _fp("digest-A"),
        ("userP", _SRC_B): _fp("digest-B"),
    }

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, secret_fingerprints=fingerprints)

    rows = _by_type(con, DivergenceType.SECRET_DIVERGENCE.value)
    assert len(rows) == 1 and result.secret_divergences == 1
    row = rows[0]
    assert row["resolution"] == "unresolved" and row["resolved_by"] is None
    assert row["resolved_value"] is None  # secrets are NEVER picked
    vbs = json.loads(str(row["value_by_source"]))
    assert vbs == {
        _SRC_A: {"present": True, "differs": True},
        _SRC_B: {"present": True, "differs": True},
    }
    # No digest / plaintext anywhere in the ledger row.
    blob = json.dumps(_ledger(con), default=str)
    assert "digest-A" not in blob and "digest-B" not in blob and plaintextish_a not in blob


# =========================================================================== #
#  FOLD: scenario 4 — planted lingering object                                #
# =========================================================================== #
def test_fold_candidate_lingering_object() -> None:
    con = _store()
    # live on B, absent on A; plus a consistent node so the source set is 2.
    _add_node_obs(con, "linger", _SRC_B, is_deleted=False)
    _add_node_obs(con, "common", _SRC_A)
    _add_node_obs(con, "common", _SRC_B)

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    rows = _by_type(con, DivergenceType.CANDIDATE_LINGERING_OBJECT.value)
    assert len(rows) == 1 and result.candidate_lingering_objects == 1
    assert rows[0]["obj_id"] == "linger" and rows[0]["resolution"] == "surfaced"
    assert json.loads(str(rows[0]["resolved_value"]))["present_on"] == [_SRC_B]


# =========================================================================== #
#  FOLD: attribute divergence resolved at EACH tier + counters                #
# =========================================================================== #
def test_fold_attribute_tier1_resolves() -> None:
    con = _store()
    dsa_a = "11111111-1111-1111-1111-111111111111"
    dsa_b = "22222222-2222-2222-2222-222222222222"
    _add_node_obs(con, "u", _SRC_A, blob=_make_blob([(13, 2, 10, 1)], dsa_a))
    _add_node_obs(con, "u", _SRC_B, blob=_make_blob([(13, 9, 10, 1)], dsa_b))  # B newer
    _add_staging_node(con, "u", _SRC_A, description="old")
    _add_staging_node(con, "u", _SRC_B, description="new")

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, attid_by_name={"description": 13})

    rows = [r for r in _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value)]
    assert len(rows) == 1 and result.attribute_divergences == 1
    assert rows[0]["resolved_by"] == "per_attr_meta"
    assert json.loads(str(rows[0]["resolved_value"])) == "new"
    assert result.tier1_unavailable == 0 and result.attribute_unresolved == 0


def test_fold_attribute_tier2_when_changed() -> None:
    con = _store()
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    _add_node_obs(con, "u", _SRC_A, when_changed=older)  # no blob -> tier-1 unavailable
    _add_node_obs(con, "u", _SRC_B, when_changed=newer)
    _add_staging_node(con, "u", _SRC_A, description="old")
    _add_staging_node(con, "u", _SRC_B, description="new")

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    rows = _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value)
    assert len(rows) == 1 and rows[0]["resolved_by"] == "whenChanged"
    assert json.loads(str(rows[0]["resolved_value"])) == "new"
    assert result.tier1_unavailable == 1


def test_fold_attribute_tier3_safer_reading_uac() -> None:
    con = _store()
    _add_node_obs(con, "u", _SRC_A)  # no blobs, equal (NULL) whenChanged
    _add_node_obs(con, "u", _SRC_B)
    _add_staging_node(con, "u", _SRC_A, userAccountControl=0x202)  # disabled
    _add_staging_node(con, "u", _SRC_B, userAccountControl=0x200)  # enabled

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    rows = _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value)
    assert len(rows) == 1 and rows[0]["resolution"] == "unresolved"
    assert rows[0]["resolved_by"] == "safer_reading"
    assert json.loads(str(rows[0]["resolved_value"])) == 0x200
    assert result.attribute_unresolved == 1


def test_fold_attribute_tied_not_picked_counted() -> None:
    con = _store()
    dsa_a = "11111111-1111-1111-1111-111111111111"
    dsa_b = "22222222-2222-2222-2222-222222222222"
    # identical stamps -> TIED; description has no danger order -> nothing picked.
    _add_node_obs(con, "u", _SRC_A, blob=_make_blob([(13, 5, 10, 1)], dsa_a))
    _add_node_obs(con, "u", _SRC_B, blob=_make_blob([(13, 5, 10, 1)], dsa_b))
    _add_staging_node(con, "u", _SRC_A, description="x")
    _add_staging_node(con, "u", _SRC_B, description="y")

    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, attid_by_name={"description": 13})

    rows = _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value)
    assert len(rows) == 1 and rows[0]["resolution"] == "unresolved"
    assert rows[0]["resolved_by"] is None and rows[0]["resolved_value"] is None
    assert result.attribute_unresolved == 1


# =========================================================================== #
#  FOLD: ledger + DC-vs-DC report + presented overlay + counters              #
# =========================================================================== #
def test_fold_report_and_counts_and_overlay() -> None:
    con = _store()
    # one attribute divergence (tier-2) + one deleted_on_source + one edge divergence.
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    _add_node_obs(con, "u", _SRC_A, when_changed=older)
    _add_node_obs(con, "u", _SRC_B, when_changed=newer)
    _add_staging_node(con, "u", _SRC_A, description="old")
    _add_staging_node(con, "u", _SRC_B, description="new")
    _add_node_obs(con, "d", _SRC_A, is_deleted=True)
    _add_node_obs(con, "d", _SRC_B, is_deleted=False)
    _add_staging_node(con, "d", _SRC_A, sAMAccountName="d")
    _add_staging_node(con, "d", _SRC_B, sAMAccountName="d")
    _add_edge_obs(con, "e1", _SRC_A)  # edge on A only

    run = IngestRun("case-x", "op", ingest_run_id=uuid.uuid4())
    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, run=run)

    rep = result.report
    assert rep.source_ids == tuple(sorted([_SRC_A, _SRC_B]))
    assert rep.counts_by_type[DivergenceType.ATTRIBUTE_DIVERGENCE.value] == 1
    assert rep.counts_by_type[DivergenceType.DELETED_ON_SOURCE.value] == 1
    assert rep.counts_by_type[DivergenceType.EDGE_MEMBERSHIP_DIVERGENCE.value] == 1
    assert rep.total == 3
    # counters surfaced on the IngestRun (never silent).
    assert run.coverage_counts.get(COV_NODES_MERGED) == 2
    assert run.skip_counts.get(GAP_TIER1_UNAVAILABLE) == 1
    # read-time presented overlay returns the tier-2 resolved value.
    state, value = presented_attribute(con, "u", "description", _RUN)
    assert state is PresentedState.RESOLVED and value == "new"
    # a non-diverged attribute has no overlay.
    assert presented_attribute(con, "u", "sAMAccountName", _RUN) == (
        PresentedState.NO_DIVERGENCE,
        None,
    )


# =========================================================================== #
#  FOLD: determinism + idempotency + opt-in + <2-source no-op                 #
# =========================================================================== #
def _two_source_divergent_store() -> duckdb.DuckDBPyConnection:
    con = _store()
    older = datetime(2021, 1, 1, tzinfo=UTC)
    newer = datetime(2023, 1, 1, tzinfo=UTC)
    _add_node_obs(con, "u", _SRC_A, when_changed=older)
    _add_node_obs(con, "u", _SRC_B, when_changed=newer)
    _add_staging_node(con, "u", _SRC_A, description="old")
    _add_staging_node(con, "u", _SRC_B, description="new")
    return con


def test_fold_is_deterministic_and_idempotent() -> None:
    con = _two_source_divergent_store()
    merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)
    first = _ledger(con)
    # re-run deletes this run's rows first -> identical ledger, no duplication.
    merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)
    second = _ledger(con)
    assert first == second
    assert con.execute("SELECT COUNT(*) FROM divergence").fetchone()[0] == len(first)


def test_fold_order_independent() -> None:
    con1 = _two_source_divergent_store()
    con2 = _two_source_divergent_store()
    merge_fold(con1, [_SRC_A, _SRC_B], run_id=_RUN)
    merge_fold(con2, [_SRC_B, _SRC_A], run_id=_RUN)  # reversed selection order
    assert _ledger(con1) == _ledger(con2)


def test_fold_single_source_is_counted_noop() -> None:
    con = _two_source_divergent_store()
    run = IngestRun("c", "op", ingest_run_id=uuid.uuid4())
    result = merge_fold(con, [_SRC_A], run_id=_RUN, run=run)
    assert con.execute("SELECT COUNT(*) FROM divergence").fetchone()[0] == 0
    assert result.report.total == 0
    assert run.skip_counts.get(GAP_NOTHING_TO_MERGE) == 1


def test_merge_is_opt_in_not_run_at_ingest() -> None:
    # A freshly created multi-source store (no fold invoked) has an EMPTY ledger:
    # merge is a separate explicit operation, never a pipeline/ingest step.
    con = _two_source_divergent_store()
    assert con.execute("SELECT COUNT(*) FROM divergence").fetchone()[0] == 0


def test_secret_divergence_counted_gap_surfaced() -> None:
    con = _store()
    _add_node_obs(con, "p", _SRC_A)
    _add_node_obs(con, "p", _SRC_B)
    run = IngestRun("c", "op", ingest_run_id=uuid.uuid4())
    merge_fold(
        con,
        [_SRC_A, _SRC_B],
        run_id=_RUN,
        secret_fingerprints={("p", _SRC_A): _fp("A"), ("p", _SRC_B): _fp("B")},
        run=run,
    )
    assert run.skip_counts.get(GAP_SECRET_DIVERGENCE) == 1


# =========================================================================== #
#  FOLD: honesty/hardening fixes (staging-unparseable, blob-corrupt, GC,       #
#  secret naming, presented-contested, edges_reconciled honesty)               #
# =========================================================================== #
def test_fold_staging_unparseable_excluded_and_counted() -> None:
    con = _store()
    _add_node_obs(con, "u", _SRC_A)
    _add_node_obs(con, "u", _SRC_B)
    # A has valid attrs; B's staging JSON is a valid-but-NON-OBJECT shape (the DuckDB
    # JSON column rejects truly-malformed text, so a JSON array is the realistic
    # "unexpected shape" case). It is EXCLUDED (not "no attrs"), so NO spurious
    # present-on-A/absent-on-B flood, and the gap is counted.
    _add_staging_node(con, "u", _SRC_A, description="x", sAMAccountName="u")
    con.execute(
        f"INSERT INTO staging_object (node_id, attributes, forest_id, provenance, source_id) "
        f"VALUES ('u', '[1,2,3]', 'f1', {_PROV}, ?)",
        [_SRC_B],
    )
    run = IngestRun("c", "op", ingest_run_id=uuid.uuid4())
    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, run=run)

    assert result.staging_attrs_unparseable == 1
    assert run.skip_counts.get(GAP_STAGING_ATTRS_UNPARSEABLE) == 1
    # Only one parseable source -> no attribute comparison -> zero attribute rows.
    assert result.attribute_divergences == 0
    assert _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value) == []


def test_fold_corrupt_blob_counted_distinct_from_absent() -> None:
    con = _store()
    dsa = "11111111-1111-1111-1111-111111111111"
    _add_node_obs(con, "u", _SRC_A, blob=_make_blob([(13, 2, 10, 1)], dsa))
    _add_node_obs(con, "u", _SRC_B, blob=b"\x01\x00\x00\x00corrupt")  # present but corrupt
    _add_staging_node(con, "u", _SRC_A, description="old")
    _add_staging_node(con, "u", _SRC_B, description="new")
    run = IngestRun("c", "op", ingest_run_id=uuid.uuid4())
    result = merge_fold(
        con, [_SRC_A, _SRC_B], run_id=_RUN, attid_by_name={"description": 13}, run=run
    )

    assert result.repl_blob_unparseable == 1
    assert run.skip_counts.get(GAP_REPL_BLOB_UNPARSEABLE) == 1
    # only one decodable stamp -> tier-1 unavailable -> degrades (no crash).
    rows = _by_type(con, DivergenceType.ATTRIBUTE_DIVERGENCE.value)
    assert len(rows) == 1 and result.tier1_unavailable == 1


def _add_source_row(con: duckdb.DuckDBPyConnection, source_id: str, *, gc: bool) -> None:
    con.execute(
        "INSERT INTO source (source_id, case_id, dc_label, forest_id, is_global_catalog, "
        "ntds_image_sha256, ingest_run_id, ingested_at) "
        "VALUES (?, 'c', ?, 'f1', ?, 'sha', ?, now())",
        [source_id, f"lbl-{source_id[:4]}", gc, str(_RUN)],
    )


def test_fold_gc_source_backstop_counted() -> None:
    con = _store()
    _add_source_row(con, _SRC_A, gc=True)  # a GC partial-replica source
    _add_source_row(con, _SRC_B, gc=False)
    _add_node_obs(con, "u", _SRC_A)
    _add_node_obs(con, "u", _SRC_B)
    run = IngestRun("c", "op", ingest_run_id=uuid.uuid4())
    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN, run=run)

    assert result.gc_sources_in_selection == 1
    assert run.skip_counts.get(GAP_GC_SOURCE_IN_SELECTION) == 1


def test_fold_secret_unreplicated_names_absent_dc() -> None:
    con = _store()
    _add_node_obs(con, "userP", _SRC_A)
    _add_node_obs(con, "userP", _SRC_B)
    # A holds the secret; B (observing) holds none -> un-replicated / missing-on-B.
    result = merge_fold(
        con,
        [_SRC_A, _SRC_B],
        run_id=_RUN,
        secret_fingerprints={("userP", _SRC_A): _fp("only-A")},
    )
    rows = _by_type(con, DivergenceType.SECRET_DIVERGENCE.value)
    assert len(rows) == 1 and result.secret_divergences == 1
    vbs = json.loads(str(rows[0]["value_by_source"]))
    # B is NAMED as absent (present:false), distinct from A's present-but-not-differing.
    assert vbs == {
        _SRC_A: {"present": True, "differs": False},
        _SRC_B: {"present": False, "differs": False},
    }
    assert "only-A" not in json.dumps(_ledger(con), default=str)


def test_fold_presented_contested_unresolved_state() -> None:
    con = _store()
    _add_node_obs(con, "u", _SRC_A)  # no blobs, equal whenChanged -> tier-3
    _add_node_obs(con, "u", _SRC_B)
    _add_staging_node(con, "u", _SRC_A, description="x")  # no danger order -> unresolved
    _add_staging_node(con, "u", _SRC_B, description="y")
    merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    # diverged but unresolved -> CONTESTED (consumer must badge, not show benign).
    state, value = presented_attribute(con, "u", "description", _RUN)
    assert state is PresentedState.CONTESTED_UNRESOLVED and value is None


def test_fold_edges_reconciled_metric_honesty() -> None:
    con = _store()
    _add_node_obs(con, "n", _SRC_A)
    _add_node_obs(con, "n", _SRC_B)
    _add_edge_obs(con, "both", _SRC_A)  # edge on both -> a real reconciliation
    _add_edge_obs(con, "both", _SRC_B)
    _add_edge_obs(con, "onlyA", _SRC_A)  # edge on one -> a divergence, NOT reconciled
    result = merge_fold(con, [_SRC_A, _SRC_B], run_id=_RUN)

    assert result.edges_reconciled == 1  # only the >=2-source edge
    assert result.edge_membership_divergences == 1  # the single-source edge


# =========================================================================== #
#  REGRESSION (real .dit, SOLO) — c137 ingested twice => zero spurious div.    #
# =========================================================================== #
_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_evidence = _NTDS.is_file()


@pytest.mark.real_dit
@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit; run SOLO")
def test_regression_c137_ingested_twice_zero_spurious_divergence(tmp_path: Path) -> None:
    """Same dit ingested as two sources => one presented row per node, ZERO spurious
    divergence (identical copies). Must be run SOLO (real-.dit builds deadlock)."""
    from wraith.export.pipeline import PipelineInputs, run_multi_source_pipeline
    from wraith.model.store import open_canonical_store

    store = tmp_path / "canonical.duckdb"
    con = open_canonical_store(store)
    run = IngestRun("C137", "tester", ingest_run_id=UUID(int=0x6A7E))
    sys_hive = _SYSTEM if _SYSTEM.is_file() else None
    sources = (
        PipelineInputs(
            ntds_path=_NTDS,
            forest_id="forest-c137",
            system_hive_path=sys_hive,
            dc_label="DC-A",
            declared_domain="c137.local",
        ),
        PipelineInputs(
            ntds_path=_NTDS,
            forest_id="forest-c137",
            system_hive_path=sys_hive,
            dc_label="DC-B",
            declared_domain="c137.local",
        ),
    )
    try:
        run_multi_source_pipeline(con, run, sources, output_dir=tmp_path / "bh")
        source_ids = [str(r[0]) for r in con.execute("SELECT source_id FROM source").fetchall()]
        assert len(source_ids) == 2
        # one presented (canonical) row per node id — single-PK guarantees it.
        canon = con.execute("SELECT COUNT(*) FROM principal").fetchone()[0]
        distinct = con.execute("SELECT COUNT(DISTINCT node_id) FROM principal").fetchone()[0]
        assert canon == distinct
        result = merge_fold(con, source_ids, run_id=run.ingest_run_id)
        # identical copies -> NO entity/edge/attribute/secret divergence at all.
        assert result.report.total == 0, result.report.counts_by_type
        assert result.nodes_reconciled > 0  # it really did fold real nodes
    finally:
        con.close()
