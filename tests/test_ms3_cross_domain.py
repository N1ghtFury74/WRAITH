"""M-MS3 — cross-domain edge derivation (coder-side tests).

All SYNTHETIC (contract §6 M-MS3: trust-direction BHCE round-trip, FSP
``principal_type`` distribution, and ``trust_type`` FQDN inference are
untested-on-real until a GOAD / real forest capture). Layers:

* **Pure decoders / inference** — ``trustAttributes`` bits, ``trustType`` label,
  parent-child vs tree-root FQDN inference (+ undetermined), ``domain_sid_of``,
  foreign-principal resolve-vs-stub.
* **Trust edges** — attack-direction (trusted -> trusting) over a 2-domain store,
  inferred intra-forest subtype, partner resolved to the ingested Domain node.
* **FSP** — resolve to the real foreign principal (type from the resolved
  principal, NEVER a blind ``Group``) vs a counted ``fsp_owning_domain_not_ingested``
  stub.
* **sIDHistory** — cross-domain resolve vs counted stub; same-domain unaffected.
* **GC partial-replica** — a GC shadow is excluded from authoritative resolution
  and counted; it never wins over / stands in for a full-domain copy.
* **Per-source tagging** — every cross-domain edge is registered under its
  originating ``source_id`` in ``source_observation``.
* **Single-domain regression** — on a single-domain store the pass emits ZERO
  cross-domain edges and leaves existing output intact.
* **Materialization-scoping fix** — a ``source_id``-scoped drill-in never surfaces
  a foreign-source node as a result row; the drop is counted.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import duckdb

from wraith.api.graph import build_slice
from wraith.api.store import (
    GAP_FOREIGN_SOURCE_ENDPOINT,
    ScopedStoreReader,
    StoreReader,
)
from wraith.case.ingest_run import IngestRun
from wraith.edges.cross_domain import (
    FOREIGN_PRINCIPAL_TYPE,
    KIND_FOREIGN_IDENTITY,
    TRUST_TYPE_PARENT_CHILD,
    TRUST_TYPE_TREE_ROOT,
    TRUST_TYPE_UNDETERMINED,
    DomainRegistry,
    IngestedDomain,
    build_domain_registry,
    classify_trust,
    decode_trust_attribute_facts,
    derive_cross_domain_edges,
    domain_sid_of,
    infer_intra_forest_trust_type,
    resolve_foreign_principal,
    trust_type_label,
)
from wraith.edges.derivations import (
    KIND_CROSS_FOREST_TRUST,
    KIND_HAS_SID_HISTORY,
    KIND_SAME_FOREST_TRUST,
)
from wraith.model.store import (
    create_canonical_tables,
    create_edge_tables,
    create_ledger_table,
)
from wraith.normalize.decoders import (
    TRUST_ATTR_FOREST_TRANSITIVE,
    TRUST_ATTR_QUARANTINED_DOMAIN,
    TRUST_ATTR_WITHIN_FOREST,
    TRUST_TYPE_MIT,
    TRUST_TYPE_UPLEVEL,
)

FOREST = "f1"
DOM_A = "S-1-5-21-1-1-1"  # child.corp.local
DOM_B = "S-1-5-21-2-2-2"  # corp.local (parent of A)
DOM_C = "S-1-5-21-3-3-3"  # NOT ingested
RUN_ID = "00000000-0000-0000-0000-000000000000"
IMG = "a" * 64


def _prov(oid: str | None = None) -> dict[str, object]:
    return {
        "source_file": "ntds.dit",
        "image_sha256": IMG,
        "source_object_id": oid,
        "directory_timestamp": None,
        "ingest_run_id": RUN_ID,
    }


def _store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    create_ledger_table(con)
    return con


def _run() -> IngestRun:
    return IngestRun(case_id="c1", operator="t", ingest_run_id=UUID(RUN_ID))


def _source(
    con: duckdb.DuckDBPyConnection,
    *,
    source_id: str,
    dc_label: str,
    domain_id: str,
    domain_fqdn: str,
    is_gc: bool = False,
) -> None:
    con.execute(
        "INSERT INTO source (source_id,case_id,dc_label,forest_id,domain_id,domain_fqdn,"
        "declared_domain,ntds_image_sha256,system_image_sha256,is_global_catalog,"
        "ingest_run_id,ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,now())",
        [
            source_id,
            "c1",
            dc_label,
            FOREST,
            domain_id,
            domain_fqdn,
            domain_fqdn,
            "ab" * 32,
            None,
            is_gc,
            RUN_ID,
        ],
    )


def _domain_container(con: duckdb.DuckDBPyConnection, *, node_id: str, sid: str, fqdn: str) -> None:
    con.execute(
        "INSERT INTO container (node_id,object_guid,object_sid,distinguished_name,"
        "container_type,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        [node_id, node_id, sid, f"DC={fqdn}", "Domain", FOREST, sid, fqdn, _prov()],
    )


def _principal(
    con: duckdb.DuckDBPyConnection,
    *,
    node_id: str,
    sid: str,
    domain_id: str,
    domain_fqdn: str,
    ptype: str = "User",
    dn: str | None = None,
    sid_history: list[str] | None = None,
) -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,object_guid,principal_type,samaccountname,"
        "distinguished_name,uac_flags,enabled,admincount,spns,sid_history,"
        "forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            node_id,
            sid,
            node_id,
            ptype,
            node_id,
            dn,
            512,
            True,
            0,
            [],
            sid_history or [],
            FOREST,
            domain_id,
            domain_fqdn,
            _prov(node_id),
        ],
    )


def _trust(
    con: duckdb.DuckDBPyConnection,
    *,
    node_id: str,
    local_sid: str,
    target_sid: str | None,
    direction: str,
    attrs: int,
    domain_id: str,
    domain_fqdn: str,
    trust_type: int | None = TRUST_TYPE_UPLEVEL,
    trust_key_ref: str | None = None,
) -> None:
    con.execute(
        "INSERT INTO trust (node_id,source_domain_id,target_domain_id,direction,trust_type,"
        "trust_attributes,transitive,sid_filtering,trust_key_ref,"
        "forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            node_id,
            local_sid,
            target_sid,
            direction,
            trust_type,
            attrs,
            True,
            False,
            trust_key_ref,
            FOREST,
            domain_id,
            domain_fqdn,
            _prov(node_id),
        ],
    )


def _observe_node(con: duckdb.DuckDBPyConnection, node_id: str, source_id: str) -> None:
    con.execute(
        "INSERT INTO source_observation (obj_kind,obj_id,source_id,is_deleted) "
        "VALUES ('node',?,?,FALSE)",
        [node_id, source_id],
    )


def _edges(con: duckdb.DuckDBPyConnection) -> list[tuple[str, str, str]]:
    return [
        (str(k), str(s), str(t))
        for k, s, t in con.execute(
            "SELECT kind, source_node_id, target_node_id FROM edge ORDER BY kind, source_node_id"
        ).fetchall()
    ]


# --------------------------------------------------------------------------- #
#  Layer 1 — pure decoders / inference                                        #
# --------------------------------------------------------------------------- #
def test_decode_trust_attribute_facts() -> None:
    f = decode_trust_attribute_facts(
        TRUST_ATTR_WITHIN_FOREST | TRUST_ATTR_FOREST_TRANSITIVE | TRUST_ATTR_QUARANTINED_DOMAIN
    )
    assert f.within_forest and f.forest_transitive and f.quarantined_sid_filtering
    assert not f.non_transitive and not f.cross_organization and not f.treat_as_external
    assert f.raw is not None
    none = decode_trust_attribute_facts(None)
    assert not any(
        [
            none.within_forest,
            none.forest_transitive,
            none.quarantined_sid_filtering,
            none.non_transitive,
            none.cross_organization,
            none.treat_as_external,
        ]
    )
    assert none.raw is None


def test_trust_type_label() -> None:
    assert trust_type_label(TRUST_TYPE_UPLEVEL) == "uplevel"
    assert trust_type_label(TRUST_TYPE_MIT) == "mit"
    assert trust_type_label(None) == "unknown"
    assert trust_type_label(99) == "unknown"


def test_infer_intra_forest_trust_type() -> None:
    # Contiguous namespace -> parent-child.
    assert (
        infer_intra_forest_trust_type("child.corp.local", "corp.local") == TRUST_TYPE_PARENT_CHILD
    )
    assert (
        infer_intra_forest_trust_type("corp.local", "child.corp.local") == TRUST_TYPE_PARENT_CHILD
    )
    # Disjoint namespaces sharing only the forest -> tree-root.
    assert infer_intra_forest_trust_type("corp.local", "fabrikam.local") == TRUST_TYPE_TREE_ROOT
    # A non-dotted suffix must NOT be mistaken for a child (notcorp.local vs corp.local).
    assert infer_intra_forest_trust_type("notcorp.local", "corp.local") == TRUST_TYPE_TREE_ROOT
    # Unknown FQDN -> undetermined (never guessed).
    assert infer_intra_forest_trust_type(None, "corp.local") == TRUST_TYPE_UNDETERMINED
    assert infer_intra_forest_trust_type("corp.local", None) == TRUST_TYPE_UNDETERMINED
    assert infer_intra_forest_trust_type("corp.local", "corp.local") == TRUST_TYPE_UNDETERMINED


def test_domain_sid_of() -> None:
    assert domain_sid_of("S-1-5-21-1-1-1-1105") == "S-1-5-21-1-1-1"
    assert domain_sid_of("S-1-5-21-1-1-1") == "S-1-5-21-1-1-1"
    assert domain_sid_of("S-1-5-32-544") is None
    assert domain_sid_of("S-1-1-0") is None
    assert domain_sid_of(None) is None
    assert domain_sid_of("garbage") is None


def test_classify_trust_external_is_undetermined_subtype() -> None:
    # A forest/external trust (no WITHIN_FOREST) does not get a parent-child subtype.
    facts = classify_trust(
        DOM_A,
        DOM_B,
        TRUST_TYPE_UPLEVEL,
        TRUST_ATTR_FOREST_TRANSITIVE,
        "a.local",
        "b.local",
        partner_ingested=True,
    )
    assert not facts.attributes.within_forest
    assert facts.inferred_intra_forest_type == TRUST_TYPE_UNDETERMINED
    assert facts.type_label == "uplevel"


def test_resolve_foreign_principal_resolve_vs_stub() -> None:
    reg = DomainRegistry(
        domains={DOM_B: IngestedDomain(DOM_B, "b.local", FOREST, "dnode_b", False)},
        principal_by_sid={f"{DOM_B}-1105": ("real_b", "Computer")},
    )
    # Resolved -> real node + real type.
    hit = resolve_foreign_principal(f"{DOM_B}-1105", reg, FOREST)
    assert hit.resolved and hit.node_id == "real_b" and hit.principal_type == "Computer"
    assert hit.owning_domain_ingested
    # Owning domain ingested but no principal matched -> stub, Foreign type, counted.
    gap = resolve_foreign_principal(f"{DOM_B}-9999", reg, FOREST)
    assert not gap.resolved and gap.principal_type == FOREIGN_PRINCIPAL_TYPE
    assert gap.owning_domain_ingested
    # Owning domain NOT ingested -> stub, Foreign, owning_domain_ingested False.
    miss = resolve_foreign_principal(f"{DOM_C}-1105", reg, FOREST)
    assert not miss.resolved and miss.principal_type == FOREIGN_PRINCIPAL_TYPE
    assert not miss.owning_domain_ingested


# --------------------------------------------------------------------------- #
#  Layer 2 — trust edges over a 2-domain store                                #
# --------------------------------------------------------------------------- #
def _two_domain_base(con: duckdb.DuckDBPyConnection) -> None:
    _source(
        con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="child.corp.local"
    )
    _source(con, source_id="src-B", dc_label="DC-B", domain_id=DOM_B, domain_fqdn="corp.local")
    _domain_container(con, node_id="dnode_a", sid=DOM_A, fqdn="child.corp.local")
    _domain_container(con, node_id="dnode_b", sid=DOM_B, fqdn="corp.local")
    _observe_node(con, "dnode_a", "src-A")
    _observe_node(con, "dnode_b", "src-B")


def test_trust_edge_attack_direction_and_inferred_parent_child() -> None:
    con = _store()
    _two_domain_base(con)
    # A (child) has an inbound, within-forest trust to B (parent): A is TRUSTED.
    _trust(
        con,
        node_id="t1",
        local_sid=DOM_A,
        target_sid=DOM_B,
        direction="inbound",
        attrs=TRUST_ATTR_WITHIN_FOREST,
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
    )
    _observe_node(con, "t1", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    # Attack direction: inbound -> local(A) is trusted -> edge A(dnode_a) -> B(dnode_b).
    edges = _edges(con)
    assert (KIND_SAME_FOREST_TRUST, "dnode_a", "dnode_b") in edges
    assert res.trust_edges == 1
    assert res.trust_parent_child == 1
    assert res.trust_tree_root == 0
    assert res.trust_type_undetermined == 0
    assert res.trust_partner_resolved == 1  # B's real Domain node was used
    assert res.trust_partner_not_ingested == 0
    assert run.coverage_counts.get("edges.xd_trust_parent_child") == 1


def test_trust_tree_root_and_partner_not_ingested_stub() -> None:
    con = _store()
    # Only A ingested; its trust points at non-ingested C (cross-forest external).
    _source(con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="corp.local")
    _domain_container(con, node_id="dnode_a", sid=DOM_A, fqdn="corp.local")
    _observe_node(con, "dnode_a", "src-A")
    _trust(
        con,
        node_id="t1",
        local_sid=DOM_A,
        target_sid=DOM_C,
        direction="outbound",
        attrs=TRUST_ATTR_FOREST_TRANSITIVE | TRUST_ATTR_QUARANTINED_DOMAIN,
        domain_id=DOM_A,
        domain_fqdn="corp.local",
    )
    _observe_node(con, "t1", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    edges = _edges(con)
    # Cross-forest trust, outbound -> local is TRUSTING -> edge other -> local.
    assert any(k == KIND_CROSS_FOREST_TRUST for k, _, _ in edges)
    assert res.trust_partner_not_ingested == 1
    assert res.trust_partner_resolved == 0
    # Not intra-forest -> no parent-child/tree-root attribution.
    assert res.trust_parent_child == 0 and res.trust_tree_root == 0


def test_trust_undetermined_when_partner_fqdn_unknown() -> None:
    con = _store()
    # Intra-forest trust but the partner domain is not ingested (no FQDN) -> undetermined.
    _source(
        con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="child.corp.local"
    )
    _domain_container(con, node_id="dnode_a", sid=DOM_A, fqdn="child.corp.local")
    _observe_node(con, "dnode_a", "src-A")
    _trust(
        con,
        node_id="t1",
        local_sid=DOM_A,
        target_sid=DOM_B,
        direction="bidirectional",
        attrs=TRUST_ATTR_WITHIN_FOREST,
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
    )
    _observe_node(con, "t1", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)
    assert res.trust_type_undetermined == 1
    assert res.trust_parent_child == 0 and res.trust_tree_root == 0
    # Bidirectional -> two attack edges.
    assert res.trust_edges == 2


# --------------------------------------------------------------------------- #
#  Layer 3 — FSP resolve vs counted stub                                      #
# --------------------------------------------------------------------------- #
def test_fsp_resolves_to_real_principal_with_its_type() -> None:
    con = _store()
    _two_domain_base(con)
    # Real computer in B.
    _principal(
        con,
        node_id="comp_b",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="Computer",
    )
    _observe_node(con, "comp_b", "src-B")
    # FSP stub in A whose RDN SID is that B computer; M3 default-typed it Group.
    _principal(
        con,
        node_id="fsp_a",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=f"CN={DOM_B}-1105,CN=ForeignSecurityPrincipals,DC=child,DC=corp,DC=local",
    )
    _observe_node(con, "fsp_a", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    # ForeignIdentity edge: REAL computer -> local FSP stub; type from the resolved.
    assert (KIND_FOREIGN_IDENTITY, "comp_b", "fsp_a") in _edges(con)
    assert res.fsp_resolved == 1
    assert res.fsp_owning_domain_not_ingested == 0
    assert res.fsp_principal_type_by_kind.get("Computer") == 1  # NOT a blind Group
    assert res.fsp_principal_type_by_kind.get(FOREIGN_PRINCIPAL_TYPE, 0) == 0


def test_fsp_owning_domain_not_ingested_is_counted_stub() -> None:
    con = _store()
    _two_domain_base(con)
    # FSP in A for a principal in C (NOT ingested) -> counted, Foreign type, no edge.
    _principal(
        con,
        node_id="fsp_c",
        sid=f"{DOM_C}-1200",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=f"CN={DOM_C}-1200,CN=ForeignSecurityPrincipals,DC=child,DC=corp,DC=local",
    )
    _observe_node(con, "fsp_c", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    assert all(k != KIND_FOREIGN_IDENTITY for k, _, _ in _edges(con))
    assert res.fsp_resolved == 0
    assert res.fsp_owning_domain_not_ingested == 1
    assert res.fsp_principal_type_by_kind.get(FOREIGN_PRINCIPAL_TYPE) == 1
    assert run.skip_counts.get("edges.xd_fsp_owning_domain_not_ingested") == 1
    assert run.skip_counts.get("edges.xd_fsp_principal_type_unknown") == 1


# --------------------------------------------------------------------------- #
#  Layer 4 — sIDHistory cross-domain resolve vs stub                          #
# --------------------------------------------------------------------------- #
def test_sidhistory_cross_domain_resolves_when_ingested() -> None:
    con = _store()
    _two_domain_base(con)
    _principal(
        con,
        node_id="old_b",
        sid=f"{DOM_B}-1500",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="User",
    )
    _observe_node(con, "old_b", "src-B")
    # Migrated identity in A carrying the old B SID in sIDHistory.
    _principal(
        con,
        node_id="user_a",
        sid=f"{DOM_A}-1600",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="User",
        sid_history=[f"{DOM_B}-1500"],
    )
    _observe_node(con, "user_a", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    assert (KIND_HAS_SID_HISTORY, "user_a", "old_b") in _edges(con)
    assert res.sidhistory_cross_domain == 1
    assert res.sidhistory_owning_domain_not_ingested == 0


def test_sidhistory_cross_domain_not_ingested_is_counted_stub() -> None:
    con = _store()
    _two_domain_base(con)
    _principal(
        con,
        node_id="user_a",
        sid=f"{DOM_A}-1600",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="User",
        sid_history=[f"{DOM_C}-1500"],
    )
    _observe_node(con, "user_a", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    # An edge is emitted to a stub (never dangling), but the far domain is counted.
    assert any(k == KIND_HAS_SID_HISTORY and s == "user_a" for k, s, _ in _edges(con))
    assert res.sidhistory_cross_domain == 1
    assert res.sidhistory_owning_domain_not_ingested == 1


# --------------------------------------------------------------------------- #
#  Layer 5 — GC partial-replica tagging                                       #
# --------------------------------------------------------------------------- #
def test_gc_shadow_excluded_and_counted() -> None:
    con = _store()
    # A full domain A; a GC source whose home is A but which shadows a B principal.
    _source(con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="corp.local")
    _source(
        con,
        source_id="src-GC",
        dc_label="GC",
        domain_id=DOM_A,
        domain_fqdn="corp.local",
        is_gc=True,
    )
    _domain_container(con, node_id="dnode_a", sid=DOM_A, fqdn="corp.local")
    _observe_node(con, "dnode_a", "src-A")
    # A B-domain principal present ONLY as a GC shadow (observed by the GC source,
    # whose home domain A != the principal's domain B). No full-domain-B source.
    _principal(
        con,
        node_id="shadow_b",
        sid=f"{DOM_B}-1700",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="User",
    )
    _observe_node(con, "shadow_b", "src-GC")

    reg = build_domain_registry(con)
    # The shadow is NOT an authoritative resolution target, and it is counted.
    assert f"{DOM_B}-1700" not in reg.principal_by_sid
    assert reg.gc_shadow_count == 1
    # Resolving the shadow SID yields a stub, never the partial shadow node.
    hit = resolve_foreign_principal(f"{DOM_B}-1700", reg, FOREST)
    assert hit.node_id != "shadow_b"
    assert not hit.resolved


def test_full_copy_wins_over_gc_shadow() -> None:
    con = _store()
    # Domain B has a FULL source AND is shadowed on a GC. The full copy must win.
    _source(con, source_id="src-B", dc_label="DC-B", domain_id=DOM_B, domain_fqdn="corp.local")
    _source(
        con,
        source_id="src-GC",
        dc_label="GC",
        domain_id=DOM_A,
        domain_fqdn="a.local",
        is_gc=True,
    )
    _principal(
        con,
        node_id="full_b",
        sid=f"{DOM_B}-1700",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="Computer",
    )
    _observe_node(con, "full_b", "src-B")
    # The GC shadow of the SAME principal (same SID) observed under the GC source.
    _principal(
        con,
        node_id="shadow_b",
        sid=f"{DOM_B}-1700",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="Computer",
    )
    _observe_node(con, "shadow_b", "src-GC")

    reg = build_domain_registry(con)
    assert reg.principal_by_sid.get(f"{DOM_B}-1700") == ("full_b", "Computer")
    assert reg.gc_shadow_count == 1


# --------------------------------------------------------------------------- #
#  Layer 6 — per-source edge tagging                                          #
# --------------------------------------------------------------------------- #
def test_cross_domain_edges_tagged_to_originating_source() -> None:
    con = _store()
    _two_domain_base(con)
    _trust(
        con,
        node_id="t1",
        local_sid=DOM_A,
        target_sid=DOM_B,
        direction="inbound",
        attrs=TRUST_ATTR_WITHIN_FOREST,
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
    )
    _observe_node(con, "t1", "src-A")
    run = _run()
    derive_cross_domain_edges(con, run)

    # The trust edge's source_observation is tagged to src-A (where the TDO lives).
    rows = con.execute(
        "SELECT o.source_id FROM source_observation o JOIN edge e ON o.obj_id = e.edge_id "
        "WHERE o.obj_kind = 'edge' AND e.kind = ?",
        [KIND_SAME_FOREST_TRUST],
    ).fetchall()
    assert rows and all(str(r[0]) == "src-A" for r in rows)


# --------------------------------------------------------------------------- #
#  Layer 7 — single-domain regression (ZERO spurious cross-domain edges)      #
# --------------------------------------------------------------------------- #
def test_single_domain_emits_no_cross_domain_edges() -> None:
    con = _store()
    _source(con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="corp.local")
    _domain_container(con, node_id="dnode_a", sid=DOM_A, fqdn="corp.local")
    _observe_node(con, "dnode_a", "src-A")
    # A couple of ordinary same-domain principals; no trust, no FSP, no sIDHistory.
    _principal(con, node_id="u1", sid=f"{DOM_A}-1001", domain_id=DOM_A, domain_fqdn="corp.local")
    _principal(
        con,
        node_id="g1",
        sid=f"{DOM_A}-512",
        domain_id=DOM_A,
        domain_fqdn="corp.local",
        ptype="Group",
    )
    _observe_node(con, "u1", "src-A")
    _observe_node(con, "g1", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    assert res.edges_written == 0
    assert res.trust_edges == 0 and res.fsp_edges == 0
    assert res.sidhistory_cross_domain == 0 and res.sidhistory_same_domain == 0
    assert con.execute("SELECT count(*) FROM edge").fetchone()[0] == 0


# --------------------------------------------------------------------------- #
#  Layer 8 — materialization-scoping fix (M-MS2 carry-over)                    #
# --------------------------------------------------------------------------- #
def _scoped(base: StoreReader, source_id: str) -> ScopedStoreReader:
    return ScopedStoreReader(base._con, base.db_path, source_id)  # noqa: SLF001


def test_scoped_drillin_never_surfaces_foreign_source_node() -> None:
    con = _store()
    _two_domain_base(con)
    # A real B computer, and A's FSP stub for it -> a cross-domain ForeignIdentity
    # edge (comp_b -> fsp_a) observed by src-A.
    _principal(
        con,
        node_id="comp_b",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="Computer",
    )
    _observe_node(con, "comp_b", "src-B")
    _principal(
        con,
        node_id="fsp_a",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=f"CN={DOM_B}-1105,CN=ForeignSecurityPrincipals,DC=child,DC=corp,DC=local",
    )
    _observe_node(con, "fsp_a", "src-A")
    run = _run()
    derive_cross_domain_edges(con, run)

    base = StoreReader(con, Path(":memory:"))
    scoped_a = _scoped(base, "src-A")

    # A seeded drill-in from the A-side FSP stub must NOT pull comp_b (a src-B node)
    # into the scoped view, and must count the scoped-out foreign endpoint.
    sl = build_slice(scoped_a, seed_node_ids=["fsp_a"], depth=1)
    ids = {n.node_id for n in sl.nodes}
    assert "comp_b" not in ids
    assert ids <= {"fsp_a"}
    assert sl.counted_gaps.get(GAP_FOREIGN_SOURCE_ENDPOINT, 0) >= 1
    # The dangling cross-source edge is dropped (never rendered to a foreign node).
    assert all(e.source in ids and e.target in ids for e in sl.edges)


def test_unscoped_drillin_still_shows_cross_domain_node() -> None:
    con = _store()
    _two_domain_base(con)
    _principal(
        con,
        node_id="comp_b",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_B,
        domain_fqdn="corp.local",
        ptype="Computer",
    )
    _observe_node(con, "comp_b", "src-B")
    _principal(
        con,
        node_id="fsp_a",
        sid=f"{DOM_B}-1105",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=f"CN={DOM_B}-1105,CN=ForeignSecurityPrincipals,DC=child,DC=corp,DC=local",
    )
    _observe_node(con, "fsp_a", "src-A")
    run = _run()
    derive_cross_domain_edges(con, run)

    base = StoreReader(con, Path(":memory:"))
    # Unscoped: comp_b is a canonical node, so a drill-in reaches it normally and
    # the foreign-source gap is NOT raised (no scoping on the base reader).
    sl = build_slice(base, seed_node_ids=["fsp_a"], depth=1)
    ids = {n.node_id for n in sl.nodes}
    assert "comp_b" in ids
    assert sl.counted_gaps.get(GAP_FOREIGN_SOURCE_ENDPOINT, 0) == 0


# --------------------------------------------------------------------------- #
#  Layer 9 — fix-cycle: distinct FSP / trust gap labelling                     #
# --------------------------------------------------------------------------- #
def test_fsp_unresolved_in_ingested_domain_is_its_own_gap() -> None:
    con = _store()
    _two_domain_base(con)  # both A and B ingested
    # FSP in A for a B SID that matches NO live principal in B (orphaned / stale).
    _principal(
        con,
        node_id="fsp_orphan",
        sid=f"{DOM_B}-7777",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=f"CN={DOM_B}-7777,CN=ForeignSecurityPrincipals,DC=child,DC=corp,DC=local",
    )
    _observe_node(con, "fsp_orphan", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)

    # Domain B WAS ingested, so this is NOT "owning_domain_not_ingested" — it is a
    # distinct hunt signal (a dangling cross-domain ACE / stale foreign SID).
    assert res.fsp_principal_unresolved_in_ingested_domain == 1
    assert res.fsp_owning_domain_not_ingested == 0
    assert res.fsp_resolved == 0
    assert all(k != KIND_FOREIGN_IDENTITY for k, _, _ in _edges(con))
    assert run.skip_counts.get("edges.xd_fsp_principal_unresolved_in_ingested_domain") == 1
    assert run.skip_counts.get("edges.xd_fsp_owning_domain_not_ingested", 0) == 0


def test_fsp_null_dn_foreign_sid_is_not_authoritative() -> None:
    con = _store()
    _two_domain_base(con)
    # A NULL-DN local object in A carrying a FOREIGN (B) SID — FSP-shaped. It must
    # NOT resolve its own SID (the structural NULL-DN hardening).
    _principal(
        con,
        node_id="fsp_nulldn",
        sid=f"{DOM_B}-8888",
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
        ptype="Group",
        dn=None,
    )
    _observe_node(con, "fsp_nulldn", "src-A")
    reg = build_domain_registry(con)
    assert f"{DOM_B}-8888" not in reg.principal_by_sid


def test_trust_partner_sid_missing_is_its_own_gap() -> None:
    con = _store()
    _two_domain_base(con)
    # A trust object with no partner (target_domain_id) SID -> un-wireable, NOT a
    # subtype ambiguity.
    _trust(
        con,
        node_id="t_nopartner",
        local_sid=DOM_A,
        target_sid=None,
        direction="inbound",
        attrs=TRUST_ATTR_WITHIN_FOREST,
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
    )
    _observe_node(con, "t_nopartner", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)
    assert res.trust_partner_sid_missing == 1
    assert res.trust_type_undetermined == 0
    assert res.trust_edges == 0


def test_disabled_trust_is_counted_not_silent() -> None:
    con = _store()
    _two_domain_base(con)
    _trust(
        con,
        node_id="t_disabled",
        local_sid=DOM_A,
        target_sid=DOM_B,
        direction="disabled",
        attrs=TRUST_ATTR_WITHIN_FOREST,
        domain_id=DOM_A,
        domain_fqdn="child.corp.local",
    )
    _observe_node(con, "t_disabled", "src-A")
    run = _run()
    res = derive_cross_domain_edges(con, run)
    # Present-but-disabled: no traversal edge, but counted (never a silent no-op).
    assert res.trust_disabled == 1
    assert res.trust_edges == 0
    assert run.coverage_counts.get("edges.xd_trust_disabled") == 1


def test_in_scope_node_ids_empty_input_guard() -> None:
    con = _store()
    _source(con, source_id="src-A", dc_label="DC-A", domain_id=DOM_A, domain_fqdn="corp.local")
    _principal(con, node_id="u1", sid=f"{DOM_A}-1001", domain_id=DOM_A, domain_fqdn="corp.local")
    _observe_node(con, "u1", "src-A")
    base = StoreReader(con, Path(":memory:"))
    # The empty-input guard short-circuits before any query (base + scoped).
    assert base.in_scope_node_ids([]) == set()
    assert _scoped(base, "src-A").in_scope_node_ids([]) == set()
    # Sanity: the scoped reader still scopes a non-empty set correctly.
    assert _scoped(base, "src-A").in_scope_node_ids(["u1", "ghost"]) == {"u1"}
