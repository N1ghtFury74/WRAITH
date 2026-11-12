"""Coder-side sanity for the M6 BloodHound CE export adapter — not the gate.

Two layers:

* **Synthetic store** (``test_syn_*``): builds a tiny in-memory canonical store
  exercising every edge encoding (ACE / Members / ChildObjects / Links /
  AllowedToDelegate / AllowedToAct / HasSIDHistory / LocalAdmins / Trusts) plus
  every drop disposition (composed / native / trust-postprocess / adcs-pending /
  esc4 / unmapped / target-not-bh-node), and asserts the ObjectIdentifier
  mapping, the ``{data, meta}`` envelope, the no-silent-drop ledger invariant,
  the DCSync AllExtendedRights re-add, that ``highvalue`` is NOT pre-set, and
  byte-level determinism.
* **Real DC** (``test_real_*``, skipped without ``eviedence_test``): asserts the
  no-silent-drop invariant + determinism against the committed CTF ``ntds.dit``
  through the full analysis pipeline.

The authoritative three-layer gate is the tester's; these are coder sanity.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from wraith.export.bloodhound import (
    BASE_META_TYPE,
    DCONLY_METHODS,
    DEFAULT_INGEST_VERSION,
    FILE_TYPES,
    ExportConfig,
    build_export,
    export_bloodhound,
)
from wraith.model.store import (
    create_canonical_tables,
    create_edge_tables,
    open_canonical_store_readonly,
)

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_SAM = _REPO / "eviedence_test" / "Registry" / "SAM"
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL"
_evidence = _NTDS.is_file()

FOREST = "forest-test"
DOM = "S-1-5-21-10-20-30"


# =============================================================================
# synthetic-store fixture
# =============================================================================
def _mk_store() -> duckdb.DuckDBPyConnection:
    """Build an in-memory canonical store covering every export encoding."""
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)

    def principal(
        node: str, sid: str | None, ptype: str, guid: str | None = None, uac: int = 0
    ) -> None:
        con.execute(
            "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
            "samaccountname, uac_flags, forest_id, domain_id, domain_fqdn) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [node, sid, guid, ptype, node, uac, FOREST, DOM, "test.local"],
        )

    def container(node: str, ctype: str, sid: str | None, guid: str | None) -> None:
        con.execute(
            "INSERT INTO container (node_id, object_sid, object_guid, container_type, "
            "forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?)",
            [node, sid, guid, ctype, FOREST, DOM, "test.local"],
        )

    def gpo(node: str, guid: str) -> None:
        con.execute(
            "INSERT INTO gpo (node_id, object_guid, display_name, forest_id, domain_id) "
            "VALUES (?,?,?,?,?)",
            [node, guid, node, FOREST, DOM],
        )

    def adcs(node: str, guid: str, atype: str) -> None:
        con.execute(
            "INSERT INTO adcs (node_id, object_guid, name, adcs_type, forest_id, domain_id) "
            "VALUES (?,?,?,?,?,?)",
            [node, guid, node, atype, FOREST, DOM],
        )

    def edge(kind: str, src: str, tgt: str, inherited: bool = False) -> None:
        con.execute(
            "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, is_inherited, "
            "forest_id, domain_id) VALUES (?,?,?,?,?,?,?)",
            [f"{kind}:{src}:{tgt}", kind, src, tgt, inherited, FOREST, DOM],
        )

    # staging_object: records which targets are real directory objects (for the
    # target_not_bh_node vs target_unresolved split).
    def staging(node: str) -> None:
        con.execute(
            "INSERT INTO staging_object (node_id, forest_id) VALUES (?,?)",
            [node, FOREST],
        )

    # Nodes
    principal("u_attacker", f"{DOM}-1105", "User")
    principal("u_victim", f"{DOM}-1106", "User", uac=0x80000)  # unconstrained deleg
    principal("c_host", f"{DOM}-1001", "Computer")
    principal("g_dmadmins", f"{DOM}-512", "Group")
    container("dom", "Domain", DOM, "00000000-0000-0000-0000-0000000000d0")
    container("ou1", "OU", None, "11111111-1111-1111-1111-111111111111")
    gpo("gpo1", "22222222-2222-2222-2222-222222222222")
    adcs("tmpl1", "33333333-3333-3333-3333-333333333333", "CertTemplate")
    adcs("ca1", "44444444-4444-4444-4444-444444444444", "EnterpriseCA")
    # a directory object that is NOT a BH node type (e.g. schema object)
    staging("schema_obj")

    # Edges — every encoding
    edge("GenericAll", "u_attacker", "c_host", inherited=True)  # ACE
    edge("WriteDacl", "u_attacker", "ou1")  # ACE on OU
    edge("MemberOf", "u_attacker", "g_dmadmins")  # Members
    edge("Contains", "ou1", "c_host")  # ChildObjects
    edge("GPLink", "gpo1", "ou1")  # Links
    edge("AllowedToDelegate", "c_host", "u_victim")  # on source
    edge("AllowedToAct", "u_attacker", "c_host")  # on target computer
    edge("HasSIDHistory", "u_attacker", "u_victim")  # on source
    edge("AdminTo", "g_dmadmins", "c_host")  # LocalAdmins
    # DCSync holders -> domain (dropped_composed, re-adds AllExtendedRights)
    edge("GetChanges", "g_dmadmins", "dom")
    edge("GetChangesAll", "g_dmadmins", "dom")
    edge("DCSync", "g_dmadmins", "dom")
    # native drops
    edge("WRAITH:SeBackupPrivilege", "u_attacker", "c_host")
    edge("WritePublicInformation", "u_attacker", "c_host")
    # adcs topology (pending lane)
    edge("EnterpriseCAFor", "ca1", "dom")
    # esc4 without a trusted CA -> esc4_no_ca
    edge("WraithESC4TemplateControl", "u_attacker", "tmpl1")
    # target not a BH node (schema object present in staging)
    edge("GenericWrite", "u_attacker", "schema_obj")
    # target truly absent (nowhere)
    edge("Owns", "u_attacker", "ghost_obj")
    # unmapped kind (loud)
    edge("TotallyNovelKind", "u_attacker", "c_host")

    # trust row -> domain Trusts[]
    con.execute(
        "INSERT INTO trust (node_id, source_domain_id, target_domain_id, direction, "
        "trust_type, transitive, sid_filtering, forest_id, domain_id) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ["t1", DOM, "S-1-5-21-99-99-99", "outbound", "external", True, False, FOREST, DOM],
    )
    return con


@pytest.fixture()
def store() -> Iterator[duckdb.DuckDBPyConnection]:
    con = _mk_store()
    yield con
    con.close()


def _nodes_by_oid(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {n["ObjectIdentifier"]: n for n in payload["data"]}  # type: ignore[index,union-attr]


# =============================================================================
# LAYER 1 — synthetic encodings + ledger
# =============================================================================
def test_syn_file_set_and_meta(store: duckdb.DuckDBPyConnection) -> None:
    """All 13 per-type files exist with the pinned meta envelope."""
    payloads, _ = build_export(store)
    assert set(payloads) == set(FILE_TYPES)
    users = payloads["users"]["meta"]
    assert users == {
        "methods": DCONLY_METHODS,
        "type": "users",
        "count": 2,
        "version": DEFAULT_INGEST_VERSION,
    }


def test_syn_object_identifier_mapping(store: duckdb.DuckDBPyConnection) -> None:
    """SID-keyed types use uppercased SID; GUID-keyed use brace-wrapped GUID."""
    payloads, _ = build_export(store)
    users = _nodes_by_oid(payloads["users"])
    assert f"{DOM}-1105" in users  # uppercased SID
    ous = _nodes_by_oid(payloads["ous"])
    assert "{11111111-1111-1111-1111-111111111111}" in ous
    gpos = _nodes_by_oid(payloads["gpos"])
    assert "{22222222-2222-2222-2222-222222222222}" in gpos


def test_syn_ace_on_target(store: duckdb.DuckDBPyConnection) -> None:
    """ACL edges land as Aces[] on the TARGET node, RightName == kind."""
    payloads, _ = build_export(store)
    host = _nodes_by_oid(payloads["computers"])[f"{DOM}-1001"]
    aces = {(a["PrincipalSID"], a["RightName"], a["IsInherited"]) for a in host["Aces"]}
    assert (f"{DOM}-1105", "GenericAll", True) in aces


def test_syn_structural_arrays(store: duckdb.DuckDBPyConnection) -> None:
    """Members / ChildObjects / Links / AllowedTo* / HasSIDHistory land correctly."""
    payloads, _ = build_export(store)
    grp = _nodes_by_oid(payloads["groups"])[f"{DOM}-512"]
    assert {m["ObjectIdentifier"] for m in grp["Members"]} == {f"{DOM}-1105"}
    ou = _nodes_by_oid(payloads["ous"])["{11111111-1111-1111-1111-111111111111}"]
    assert {c["ObjectIdentifier"] for c in ou["ChildObjects"]} == {f"{DOM}-1001"}
    assert ou["Links"] == [{"IsEnforced": False, "GUID": "{22222222-2222-2222-2222-222222222222}"}]
    host = _nodes_by_oid(payloads["computers"])[f"{DOM}-1001"]
    assert {a["ObjectIdentifier"] for a in host["AllowedToAct"]} == {f"{DOM}-1105"}
    assert {a["ObjectIdentifier"] for a in host["AllowedToDelegate"]} == {f"{DOM}-1106"}
    # HasSIDHistory source is the attacker USER -> lands on that user's node.
    attacker = _nodes_by_oid(payloads["users"])[f"{DOM}-1105"]
    assert {a["ObjectIdentifier"] for a in attacker["HasSIDHistory"]} == {f"{DOM}-1106"}
    assert {a["ObjectIdentifier"] for a in host["LocalAdmins"]["Results"]} == {f"{DOM}-512"}
    assert host["LocalAdmins"]["Collected"] is True


def test_syn_dcsync_reinforced(store: duckdb.DuckDBPyConnection) -> None:
    """DCSync is dropped-as-composed but re-adds AllExtendedRights on the domain."""
    payloads, result = build_export(store)
    dom = _nodes_by_oid(payloads["domains"])[DOM]
    rights = {(a["PrincipalSID"], a["RightName"]) for a in dom["Aces"]}
    assert (f"{DOM}-512", "AllExtendedRights") in rights
    assert (f"{DOM}-512", "GetChanges") in rights
    assert (f"{DOM}-512", "GetChangesAll") in rights
    dcsync = next(d for d in result.dispositions if d.kind == "DCSync")
    assert dcsync.exported == 0
    assert dcsync.dropped == {"composed_by_bhce": 1}


def test_syn_trusts_on_domain(store: duckdb.DuckDBPyConnection) -> None:
    """The trust table populates the domain Trusts[] array (direction mapped)."""
    payloads, _ = build_export(store)
    dom = _nodes_by_oid(payloads["domains"])[DOM]
    assert dom["Trusts"] == [
        {
            "TargetDomainSid": "S-1-5-21-99-99-99",
            "TargetDomainName": None,
            "IsTransitive": True,
            "TrustDirection": 2,
            "TrustType": "external",
            "SidFilteringEnabled": False,
            "TGTDelegationEnabled": False,
        }
    ]


def test_syn_no_highvalue_preset(store: duckdb.DuckDBPyConnection) -> None:
    """highvalue / Tier-0 tags are NOT pre-set (BHCE derives them post-ingest)."""
    payloads, _ = build_export(store)
    for meta_type in FILE_TYPES:
        for node in payloads[meta_type]["data"]:  # type: ignore[attr-defined]
            assert "highvalue" not in node["Properties"]
            assert "system_tags" not in node["Properties"]


def test_syn_dispositions_cover_every_kind(store: duckdb.DuckDBPyConnection) -> None:
    """Every edge kind is accounted for; no silent drops; unmapped is LOUD."""
    _, result = build_export(store)
    # per-kind invariant
    for d in result.dispositions:
        assert d.exported + sum(d.dropped.values()) == d.count
    # overall invariant
    assert result.edges_exported + result.edges_dropped == result.edges_total
    byk = {d.kind: d for d in result.dispositions}
    assert byk["WRAITH:SeBackupPrivilege"].dropped == {"native": 1}
    assert byk["WritePublicInformation"].dropped == {"native": 1}
    assert byk["EnterpriseCAFor"].dropped == {"adcs_pending_spike": 1}
    assert byk["WraithESC4TemplateControl"].dropped == {"esc4_no_ca": 1}
    assert byk["GenericWrite"].dropped == {"target_not_bh_node": 1}
    assert byk["Owns"].dropped == {"target_unresolved": 1}
    assert byk["TotallyNovelKind"].dropped == {"unmapped": 1}
    assert result.unmapped_kinds == {"TotallyNovelKind": 1}


def test_syn_esc4_composed_with_trusted_ca(store: duckdb.DuckDBPyConnection) -> None:
    """ESC4 becomes esc4_composed when the template is published to an NTAuth CA."""
    # publish tmpl1 -> ca1 and trust ca1 for NTAuth
    store.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, domain_id) "
        "VALUES (?,?,?,?,?,?)",
        ["PublishedTo:tmpl1:ca1", "PublishedTo", "tmpl1", "ca1", FOREST, DOM],
    )
    store.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, domain_id) "
        "VALUES (?,?,?,?,?,?)",
        ["TrustedForNTAuth:ca1:nt", "TrustedForNTAuth", "ca1", "ntstore", FOREST, DOM],
    )
    _, result = build_export(store)
    esc4 = next(d for d in result.dispositions if d.kind == "WraithESC4TemplateControl")
    assert esc4.dropped == {"esc4_composed": 1}


def test_syn_determinism(store: duckdb.DuckDBPyConnection) -> None:
    """build_export is byte-stable across two runs over the same store."""
    from wraith.common.determinism import canonical_json

    p1, _ = build_export(store)
    p2, _ = build_export(store)
    assert canonical_json(p1) == canonical_json(p2)


def test_syn_write_files_and_zip(store: duckdb.DuckDBPyConnection, tmp_path: Path) -> None:
    """export_bloodhound writes all type files + ledger + a deterministic zip."""
    r1 = export_bloodhound(store, tmp_path / "a")
    r2 = export_bloodhound(store, tmp_path / "b")
    for meta_type in FILE_TYPES:
        a = (tmp_path / "a" / f"{meta_type}.json").read_bytes()
        b = (tmp_path / "b" / f"{meta_type}.json").read_bytes()
        assert a == b
    assert (tmp_path / "a" / "export_ledger.json").is_file()
    assert (tmp_path / "a" / "bloodhound.zip").is_file()
    ledger = json.loads((tmp_path / "a" / "export_ledger.json").read_text())
    assert ledger["edges_exported"] + ledger["edges_dropped"] == ledger["edges_total"]
    assert r1.output_dir is not None and r2.output_dir is not None
    # zip bytes deterministic
    assert (tmp_path / "a" / "bloodhound.zip").read_bytes() == (
        tmp_path / "b" / "bloodhound.zip"
    ).read_bytes()


def test_syn_configurable_version() -> None:
    """meta.version is configurable (pin to the bundled BHCE image)."""
    con = _mk_store()
    try:
        payloads, _ = build_export(con, ExportConfig(ingest_version=5, methods=0))
        assert payloads["users"]["meta"]["version"] == 5
        assert payloads["users"]["meta"]["methods"] == 0
    finally:
        con.close()


# =============================================================================
# LAYER 1b — reviewer-hardening fixes (determinism / base nodes / gplink / zip / RO)
# =============================================================================
def test_syn_ace_inherited_total_order(store: duckdb.DuckDBPyConnection) -> None:
    """Two ACEs identical except IsInherited keep a TOTAL, stable order by key.

    The store already holds a GenericAll(u_attacker -> c_host, inherited=True);
    add an inherited=False twin. The emitted Aces[] must contain both, sorted by
    (PrincipalSID, RightName, IsInherited) so False precedes True regardless of
    DB read order (determinism total-by-construction, not incidental).
    """
    store.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, is_inherited, "
        "forest_id, domain_id) VALUES (?,?,?,?,?,?,?)",
        [
            "GenericAll:u_attacker:c_host:ni",
            "GenericAll",
            "u_attacker",
            "c_host",
            False,
            FOREST,
            DOM,
        ],
    )
    payloads, _ = build_export(store)
    host = _nodes_by_oid(payloads["computers"])[f"{DOM}-1001"]
    gen = [
        a
        for a in host["Aces"]
        if a["PrincipalSID"] == f"{DOM}-1105" and a["RightName"] == "GenericAll"
    ]
    assert [a["IsInherited"] for a in gen] == [False, True]


def _base_store() -> duckdb.DuckDBPyConnection:
    """A store with a SID-less, GUID-less principal referenced by a MemberOf edge."""
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    # A principal with NO objectSID and NO objectGUID -> synthetic ObjectIdentifier.
    con.execute(
        "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
        "samaccountname, forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?,?)",
        ["u_ghost", None, None, "User", "ghost", FOREST, DOM, "test.local"],
    )
    con.execute(
        "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
        "samaccountname, forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?,?)",
        ["g_grp", f"{DOM}-512", None, "Group", "grp", FOREST, DOM, "test.local"],
    )
    con.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, domain_id) "
        "VALUES (?,?,?,?,?,?)",
        ["MemberOf:u_ghost:g_grp", "MemberOf", "u_ghost", "g_grp", FOREST, DOM],
    )
    return con


def test_syn_synthetic_node_emitted_as_base() -> None:
    """A SID/GUID-less node is emitted as a BH Base node (no dangling reference)."""
    con = _base_store()
    try:
        payloads, result = build_export(con)
        assert BASE_META_TYPE in payloads  # overflow file emitted
        base_oids = {n["ObjectIdentifier"] for n in payloads[BASE_META_TYPE]["data"]}
        assert "WRAITH:u_ghost" in base_oids
        # the group's Members[] reference now resolves to an emitted node
        grp = _nodes_by_oid(payloads["groups"])[f"{DOM}-512"]
        member_oids = {m["ObjectIdentifier"] for m in grp["Members"]}
        assert "WRAITH:u_ghost" in member_oids
        assert member_oids <= base_oids | {
            n["ObjectIdentifier"] for mt in FILE_TYPES for n in payloads[mt]["data"]
        }  # no dangling: every member is an emitted node
        assert result.skip_counts.get("node_emitted_as_base") == 1
        # ledger invariant still holds
        assert result.edges_exported + result.edges_dropped == result.edges_total
    finally:
        con.close()


def test_syn_base_file_absent_without_synthetics(store: duckdb.DuckDBPyConnection) -> None:
    """A normal store (every node keyed) keeps the standard 13-file set (no base)."""
    payloads, _ = build_export(store)
    assert BASE_META_TYPE not in payloads
    assert set(payloads) == set(FILE_TYPES)


def test_syn_gplink_malformed_counted() -> None:
    """A gplink element with no gpo_node_id is a COUNTED gap, not silently ignored."""
    con = duckdb.connect(":memory:")
    try:
        create_canonical_tables(con)
        create_edge_tables(con)
        con.execute(
            "INSERT INTO container (node_id, object_guid, container_type, gplinks, "
            "forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?)",
            [
                "ou_bad",
                "11111111-1111-1111-1111-111111111111",
                "OU",
                [{"gpo_node_id": None, "enforced": True, "link_order": 1}],
                FOREST,
                DOM,
                "test.local",
            ],
        )
        _, result = build_export(con)
        assert result.skip_counts.get("export.gplink_malformed") == 1
    finally:
        con.close()


def test_syn_zip_fields_pinned(store: duckdb.DuckDBPyConnection, tmp_path: Path) -> None:
    """Zip entries pin the host-varying fields so archive bytes match across hosts.

    ``create_system`` is forced to 3 (defaults 0 on Windows / 3 on Unix) and
    ``external_attr`` is set to 0 at write time; the stdlib normalizes a 0
    external_attr to a FIXED constant deterministically, so every entry carries
    the same value and the archive is byte-identical regardless of host OS.
    """
    export_bloodhound(store, tmp_path / "z1")
    export_bloodhound(store, tmp_path / "z2")
    with zipfile.ZipFile(tmp_path / "z1" / "bloodhound.zip") as zf:
        infos = zf.infolist()
        assert infos  # non-empty
        for info in infos:
            assert info.create_system == 3  # host-independent (not 0 on Windows)
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
        # external_attr is uniform across entries (host-independent constant).
        assert len({info.external_attr for info in infos}) == 1
    # archive bytes are reproducible
    assert (tmp_path / "z1" / "bloodhound.zip").read_bytes() == (
        tmp_path / "z2" / "bloodhound.zip"
    ).read_bytes()


def test_syn_readonly_export(tmp_path: Path) -> None:
    """A file-backed store exports correctly over a READ-ONLY connection."""
    db = tmp_path / "canonical.duckdb"
    con = duckdb.connect(str(db))
    create_canonical_tables(con)
    create_edge_tables(con)
    con.execute(
        "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
        "samaccountname, forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?,?)",
        ["u1", f"{DOM}-1105", None, "User", "u1", FOREST, DOM, "test.local"],
    )
    con.execute(
        "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
        "samaccountname, forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?,?)",
        ["g1", f"{DOM}-512", None, "Group", "g1", FOREST, DOM, "test.local"],
    )
    con.execute(
        "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, domain_id) "
        "VALUES (?,?,?,?,?,?)",
        ["MemberOf:u1:g1", "MemberOf", "u1", "g1", FOREST, DOM],
    )
    con.close()

    ro = open_canonical_store_readonly(db)
    try:
        payloads, result = build_export(ro)
        assert result.edges_exported + result.edges_dropped == result.edges_total
        assert set(payloads) == set(FILE_TYPES)
        grp = _nodes_by_oid(payloads["groups"])[f"{DOM}-512"]
        assert {m["ObjectIdentifier"] for m in grp["Members"]} == {f"{DOM}-1105"}
    finally:
        ro.close()


def test_syn_readonly_missing_raises(tmp_path: Path) -> None:
    """open_canonical_store_readonly fails loudly on a missing database file."""
    with pytest.raises(FileNotFoundError):
        open_canonical_store_readonly(tmp_path / "does_not_exist.duckdb")


# =============================================================================
# LAYER 1b — M-MS3 cross-domain vocabulary (ForeignIdentity edge + Foreign stub)
# =============================================================================
#: A foreign (un-ingested) domain SID for the cross-domain stub scenario.
_FOREIGN_DOM = "S-1-5-21-77-88-99"


def _mk_cross_domain_store() -> duckdb.DuckDBPyConnection:
    """Build a store exercising the M-MS3 ``ForeignIdentity`` edge + ``Foreign`` stub.

    * ``u_local`` (real local user) --HasSIDHistory--> ``foreign_stub`` (a
      ``principal_type='Foreign'`` stub in an un-ingested domain).
    * ``foreign_stub`` --ForeignIdentity--> ``fsp_stub`` (the FSP alias edge).
    """
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)

    def principal(node: str, sid: str, ptype: str) -> None:
        con.execute(
            "INSERT INTO principal (node_id, object_sid, object_guid, principal_type, "
            "samaccountname, forest_id, domain_id, domain_fqdn) VALUES (?,?,?,?,?,?,?,?)",
            [node, sid, None, ptype, node, FOREST, DOM, "test.local"],
        )

    def edge(kind: str, src: str, tgt: str) -> None:
        con.execute(
            "INSERT INTO edge (edge_id, kind, source_node_id, target_node_id, forest_id, "
            "domain_id) VALUES (?,?,?,?,?,?)",
            [f"{kind}:{src}:{tgt}", kind, src, tgt, FOREST, DOM],
        )

    principal("u_local", f"{DOM}-1105", "User")
    principal("foreign_stub", f"{_FOREIGN_DOM}-500", "Foreign")
    principal("fsp_stub", f"{_FOREIGN_DOM}-1200", "User")
    edge("HasSIDHistory", "u_local", "foreign_stub")
    edge("ForeignIdentity", "foreign_stub", "fsp_stub")
    return con


def test_syn_foreign_identity_dropped_composed_not_unmapped() -> None:
    """A ``ForeignIdentity`` edge is dropped as ``composed_by_bhce`` — never unmapped."""
    con = _mk_cross_domain_store()
    try:
        _, result = build_export(con)
        disp = {d.kind: d for d in result.dispositions}
        fi = disp["ForeignIdentity"]
        assert fi.count == 1
        assert fi.exported == 0
        assert dict(fi.dropped) == {"composed_by_bhce": 1}
        # Not routed to the loud unmapped lane, not silently vanished.
        assert "ForeignIdentity" not in result.unmapped_kinds
        assert "unmapped" not in fi.dropped
    finally:
        con.close()


def test_syn_foreign_stub_emitted_as_base_and_edge_resolves() -> None:
    """A ``Foreign`` stub is a BH ``Base`` node; its HasSIDHistory edge resolves."""
    con = _mk_cross_domain_store()
    try:
        payloads, result = build_export(con)
        # The Foreign stub lands in the Base overflow file, keyed by its SID.
        assert BASE_META_TYPE in payloads
        base_oids = {n["ObjectIdentifier"] for n in payloads[BASE_META_TYPE]["data"]}
        stub_oid = f"{_FOREIGN_DOM}-500"
        assert stub_oid in base_oids
        assert result.skip_counts.get("node_emitted_as_base", 0) >= 1
        # The HasSIDHistory edge resolved (exported, no endpoint_unresolved).
        disp = {d.kind: d for d in result.dispositions}
        hsh = disp["HasSIDHistory"]
        assert hsh.exported == 1
        assert dict(hsh.dropped) == {}
        # The edge endpoint on u_local points at the Base-emitted stub SID.
        u_local = _nodes_by_oid(payloads["users"])[f"{DOM}-1105"]
        assert {h["ObjectIdentifier"] for h in u_local["HasSIDHistory"]} == {stub_oid}
    finally:
        con.close()


def test_syn_cross_domain_no_unmapped_and_ledger_balanced() -> None:
    """No export path emits ``unmapped`` for the cross-domain kinds; ledger balances."""
    con = _mk_cross_domain_store()
    try:
        _, result = build_export(con)
        assert result.unmapped_kinds == {}
        assert result.edges_exported + result.edges_dropped == result.edges_total
    finally:
        con.close()


# =============================================================================
# LAYER 2 — real DC (guarded)
# =============================================================================
@pytest.mark.skipif(not _evidence, reason="needs eviedence_test ntds.dit")
def test_real_pipeline_no_silent_drop(tmp_path: Path) -> None:
    """Full pipeline on the real DC: every edge accounted, 0 unmapped, deterministic."""
    from wraith.case.ingest_run import IngestRun
    from wraith.export.pipeline import PipelineInputs, SamHostInput, run_analysis_pipeline

    run = IngestRun("SANITY", "coder", ingest_run_id=UUID(int=0xC6))
    inputs = PipelineInputs(
        ntds_path=_NTDS,
        forest_id="forest-c137",
        system_hive_path=_SYSTEM if _SYSTEM.is_file() else None,
        sam_hosts=(
            (SamHostInput(sam_path=_SAM, system_hive_path=_SYSTEM),) if _SAM.is_file() else ()
        ),
        sysvol_root=_SYSVOL if _SYSVOL.is_dir() else None,
    )
    con = duckdb.connect(":memory:")
    try:
        res = run_analysis_pipeline(con, run, inputs, output_dir=tmp_path / "bh")
        er = res.export_result
        assert er.edges_exported + er.edges_dropped == er.edges_total
        assert not er.unmapped_kinds
        # determinism against a second export of the same store
        p1, _ = build_export(con)
        p2, _ = build_export(con)
        from wraith.common.determinism import canonical_json

        assert canonical_json(p1) == canonical_json(p2)
    finally:
        con.close()
