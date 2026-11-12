"""Unit tests for the M7 API pure-logic layer (no real DC needed, CI-safe).

Covers the deterministic layout, the networkx pathfinder, the transparent risk
model, graph-slice truncation/determinism, UAC decoding, and Tier-0 classing —
all against small in-memory DuckDB stores or pure inputs.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from wraith.api.dossier import build_dossier, decode_uac
from wraith.api.graph import build_slice
from wraith.api.layout import radial_layout
from wraith.api.models import GraphSlice
from wraith.api.paths import build_path_graph, find_paths
from wraith.api.risk import score_nodes
from wraith.api.store import EdgeRow, StoreReader, Tier0Sets
from wraith.api.tiering import (
    MAX_PATH_HOPS,
    TIER0_SID_SUFFIXES,
    TIER0_TARGET_SUFFIXES,
    is_control_edge,
    sid_is_gpo_creator,
    sid_is_tier0,
)
from wraith.common.determinism import canonical_json
from wraith.model.store import create_canonical_tables, create_edge_tables

FOREST = "f"
DOM = "S-1-5-21-10-20-30"
PROV = {"source_file": "ntds.dit", "image_sha256": "a" * 64}


def _mem_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con, StoreReader(con, Path(":memory:"))


def _principal(con: duckdb.DuckDBPyConnection, node: str, sid: str, **kw: object) -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
        "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            node,
            sid,
            kw.get("ptype", "User"),
            kw.get("sam", node),
            kw.get("uac", 512),
            kw.get("enabled", True),
            kw.get("admincount", 0),
            kw.get("spns", []),
            kw.get("sid_history", []),
            FOREST,
            DOM,
            "t.local",
            {
                **PROV,
                "source_object_id": node,
                "directory_timestamp": None,
                "ingest_run_id": "00000000-0000-0000-0000-000000000000",
            },
        ],
    )


def _container(
    con: duckdb.DuckDBPyConnection, node: str, ctype: str, sid: str | None, **kw: object
) -> None:
    con.execute(
        "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
        "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
        [
            node,
            sid,
            kw.get("dn", node),
            ctype,
            FOREST,
            DOM,
            "t.local",
            {
                **PROV,
                "source_object_id": node,
                "directory_timestamp": None,
                "ingest_run_id": "00000000-0000-0000-0000-000000000000",
            },
        ],
    )


def _eff(con: duckdb.DuckDBPyConnection, member: str, group: str) -> None:
    con.execute(
        "INSERT INTO effective_membership (member_node_id,group_node_id,forest_id,domain_id) "
        "VALUES (?,?,?,?)",
        [member, group, FOREST, DOM],
    )


def _t0sets(
    *,
    targets: tuple[str, ...] = (),
    groups: tuple[str, ...] = (),
    classified: tuple[str, ...] = (),
    domain_objects: tuple[str, ...] = (),
    members: tuple[str, ...] = (),
    gpo_creators: tuple[str, ...] = (),
) -> Tier0Sets:
    return Tier0Sets(
        classified_ids=frozenset(classified),
        target_ids=targets,
        group_target_ids=frozenset(groups),
        domain_object_ids=frozenset(domain_objects),
        member_ids=frozenset(members),
        gpo_creator_ids=frozenset(gpo_creators),
    )


def _edge(con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str) -> None:
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            f"{kind}:{src}:{tgt}",
            kind,
            src,
            tgt,
            "confirmed",
            FOREST,
            DOM,
            "t.local",
            {
                **PROV,
                "source_object_id": None,
                "directory_timestamp": None,
                "ingest_run_id": "00000000-0000-0000-0000-000000000000",
            },
        ],
    )


def _edge_conf(
    con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str, confidence: str
) -> None:
    """Insert one edge with an explicit confidence (confirmed / inferred)."""
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            f"{kind}:{src}:{tgt}:{confidence}",
            kind,
            src,
            tgt,
            confidence,
            FOREST,
            DOM,
            "t.local",
            {
                **PROV,
                "source_object_id": None,
                "directory_timestamp": None,
                "ingest_run_id": "00000000-0000-0000-0000-000000000000",
            },
        ],
    )


def _staging(
    con: duckdb.DuckDBPyConnection,
    node: str,
    *,
    name: str | None = None,
    object_class: list[str] | None = None,
    sid: str | None = None,
) -> None:
    """Insert a bare ``staging_object`` row (a not-modeled / infra / leaf object).

    ``attributes`` carries the RDN ``name`` the Base projection resolves as the
    label; ``object_class`` is stored most-derived-first (as the normalizer does).
    """
    attrs = "{}" if name is None else canonical_json({"name": name})
    con.execute(
        "INSERT INTO staging_object (node_id,dnt,object_guid,object_sid,object_class,raw_sd,"
        "attributes,forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            node,
            0,
            None,
            sid,
            object_class or ["top"],
            None,
            attrs,
            FOREST,
            DOM,
            "t.local",
            {
                **PROV,
                "source_object_id": node,
                "directory_timestamp": None,
                "ingest_run_id": "00000000-0000-0000-0000-000000000000",
            },
        ],
    )


# --- research 11: Base-object projection + unresolved gap + member confidence -
def test_base_object_edge_endpoint_resolves_to_name() -> None:
    """An ACL target that is only a staging_object resolves to its RDN name, not a hash."""
    con, reader = _mem_store()
    try:
        _principal(con, "admins", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _staging(con, "ridset01", name="RID Set", object_class=["rIDSet", "top"])
        _edge(con, "GenericAll", "admins", "ridset01")

        d = build_dossier(reader, "admins")
        assert d is not None
        out = {e.other.node_id: e.other for e in d.outbound_edges}
        assert out["ridset01"].label == "RID Set"  # the RDN name, NOT the node-id hash
        assert out["ridset01"].kind == "Base"
        assert d.counted_gaps == {}  # fully resolved -> no unresolved gap
    finally:
        con.close()


def test_base_object_dossier_not_404() -> None:
    """GET /nodes/{id} for a former-hash object returns a Base dossier, never None/404."""
    con, reader = _mem_store()
    try:
        _principal(con, "admins", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _staging(con, "scp01", name="SCP-Thing", object_class=["serviceConnectionPoint", "top"])
        _edge(con, "Owns", "admins", "scp01")

        d = build_dossier(reader, "scp01")
        assert d is not None  # was a 404 before Fix A
        assert d.kind == "Base"
        assert d.label == "SCP-Thing"
        assert d.description == "serviceConnectionPoint"  # most-derived objectClass surfaced
        # inbound controller resolves to a real name (the group), not a hash
        inbound = {e.other.node_id: e.other for e in d.inbound_edges}
        assert inbound["admins"].label == "Domain Admins"
        # provenance preserved on the Base node
        assert d.provenance.source_object_id == "scp01"
        assert d.provenance.image_sha256 == "a" * 64
        assert any("not an attack-modeled entity" in s.lower() for s in d.exec_summary)
    finally:
        con.close()


def test_base_object_endpoint_only_not_counted() -> None:
    """Base objects are endpoint-only + on-demand (owner decision 2026-10-29).

    They are EXCLUDED from the canonical count / kind-counts (so they never inflate
    ``node_count`` or overprint the canvas) yet remain resolvable on demand via the
    full ``all_nodes`` / ``nodes_by_ids`` projection, carrying the structural
    ``Base`` kind (so a materialized endpoint / dossier is honest).
    """
    con, reader = _mem_store()
    try:
        _staging(con, "leaf01", name="Leaf", object_class=["rIDManager", "top"])
        # canonical count / kind-counts exclude the Base leaf entirely
        assert reader.node_count() == 0
        assert "Base" not in reader.node_kind_counts()
        assert all(n.node_id != "leaf01" for n in reader.canonical_nodes())
        # ...but it still resolves on demand (dossiers / endpoint materialization)
        assert [n.kind for n in reader.all_nodes() if n.node_id == "leaf01"] == ["Base"]
        assert [n.kind for n in reader.nodes_by_ids(["leaf01"])] == ["Base"]
    finally:
        con.close()


def test_graph_dossier_consistency_base_endpoint() -> None:
    """An ACL edge to a Base object appears in BOTH the graph slice and the dossier."""
    con, reader = _mem_store()
    try:
        _principal(con, "admins", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _staging(con, "ridset01", name="RID Set", object_class=["rIDSet", "top"])
        _edge(con, "GenericAll", "admins", "ridset01")

        sl = build_slice(reader, seed_node_ids=["admins"], depth=1, limit=5000)
        slice_node_ids = {n.node_id for n in sl.nodes}
        slice_edge_targets = {e.target for e in sl.edges}
        assert "ridset01" in slice_node_ids  # graph now KNOWS the endpoint (Fix A)
        assert "ridset01" in slice_edge_targets  # and keeps the edge (both endpoints known)

        d = build_dossier(reader, "admins")
        assert d is not None
        assert "ridset01" in {e.other.node_id for e in d.outbound_edges}  # dossier agrees
    finally:
        con.close()


def test_narrowed_slice_never_materializes_base() -> None:
    """A NARROWED view (``tier0_only``/``node_kinds``) stays canonical-only: no Base.

    Regression pin (owner 2026-10-29): a seeded ``tier0_only`` slice must NOT pull the
    Base leaf population back into a view the user explicitly narrowed (the real c137
    ``tier0_only`` slice was flooding 3440/3450 ``Base`` nodes). Materialization is a
    property of an UNFILTERED drill-in only — so here the same ``admins`` seed that
    materialises ``ridset01`` in the plain slice (see the consistency test above)
    yields ZERO ``Base`` nodes once narrowed, and ``returned <= total_matched`` holds.
    """
    con, reader = _mem_store()
    try:
        _principal(con, "admins", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _staging(con, "ridset01", name="RID Set", object_class=["rIDSet", "top"])
        _edge(con, "GenericAll", "admins", "ridset01")

        # tier0_only narrowing: the Base endpoint is OUT of scope (ordinary scoping,
        # not a counted gap) and is never materialized back in.
        t0 = build_slice(reader, seed_node_ids=["admins"], depth=1, tier0_only=True, limit=5000)
        assert all(n.kind != "Base" for n in t0.nodes)
        assert t0.returned <= t0.total_matched
        assert not t0.counted_gaps  # dropped-as-out-of-scope is NOT a gap

        # node_kinds narrowing to a canonical kind likewise excludes Base.
        nk = build_slice(
            reader, seed_node_ids=["admins"], depth=1, node_kinds=["Group"], limit=5000
        )
        assert all(n.kind != "Base" for n in nk.nodes)
        assert nk.returned <= nk.total_matched
    finally:
        con.close()


def test_unresolved_edge_endpoint_counted() -> None:
    """A genuinely dangling endpoint -> explicit Unresolved marker + counted gap."""
    con, reader = _mem_store()
    try:
        _principal(con, "admins", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        # edge to an id with NO row in any table (not even staging_object)
        _edge(con, "GenericAll", "admins", "ghost01")

        d = build_dossier(reader, "admins")
        assert d is not None
        ghost = next(e.other for e in d.outbound_edges if e.other.node_id == "ghost01")
        assert ghost.label == "unresolved object"  # never the bare hash
        assert ghost.kind == "Unresolved"
        assert ghost.node_id == "ghost01"  # raw id kept on the forensic line
        assert d.counted_gaps == {"dossier.unresolved_edge_endpoint": 1}
    finally:
        con.close()


def test_group_member_confidence_direct_nested_and_inferred() -> None:
    """Member confidence: confirmed for stored links, inferred via special identity."""
    con, reader = _mem_store()
    try:
        _principal(con, "grp", "S-1-5-21-10-20-30-1300", ptype="Group", sam="TargetGroup")
        _principal(con, "alice", "S-1-5-21-10-20-30-1105", sam="alice")  # direct confirmed
        _principal(con, "mid", "S-1-5-21-10-20-30-1301", ptype="Group", sam="Mid")
        _principal(con, "bob", "S-1-5-21-10-20-30-1106", sam="bob")  # nested confirmed
        _principal(con, "eve", "S-1-5-21-10-20-30-1107", sam="eve")  # inferred only
        # effective closure: all four are effective members of grp
        for m in ("alice", "mid", "bob", "eve"):
            _eff(con, m, "grp")
        # confirmed MemberOf chain: alice -> grp (direct); bob -> mid -> grp (nested)
        _edge_conf(con, "MemberOf", "alice", "grp", "confirmed")
        _edge_conf(con, "MemberOf", "mid", "grp", "confirmed")
        _edge_conf(con, "MemberOf", "bob", "mid", "confirmed")
        # eve reaches grp ONLY via an inferred special-identity hop
        _edge_conf(con, "MemberOf", "eve", "grp", "inferred")

        d = build_dossier(reader, "grp")
        assert d is not None
        members = {m.node_id: m for m in d.group_members}
        assert members["alice"].is_nested is False and members["alice"].confidence == "confirmed"
        assert members["bob"].is_nested is True and members["bob"].confidence == "confirmed"
        assert members["mid"].confidence == "confirmed"
        assert members["eve"].confidence == "inferred"  # special-identity-only fold-in
    finally:
        con.close()


# --- tiering ------------------------------------------------------------------
def test_sid_is_tier0() -> None:
    assert sid_is_tier0("S-1-5-21-1-2-3-512")  # Domain Admins
    assert sid_is_tier0("S-1-5-32-544")  # builtin Administrators
    assert not sid_is_tier0("S-1-5-21-1-2-3-1104")  # ordinary user
    assert not sid_is_tier0(None)


def test_is_control_edge() -> None:
    assert is_control_edge("GenericAll")
    assert is_control_edge("DCSync")
    assert not is_control_edge("Contains")
    assert not is_control_edge("GPLink")


# --- layout -------------------------------------------------------------------
def test_radial_layout_deterministic_and_rooted() -> None:
    nodes = [f"n{i}" for i in range(20)]
    edges = [("n0", f"n{i}") for i in range(1, 10)] + [("n5", "n11"), ("n11", "n12")]
    a = radial_layout(nodes, edges)
    b = radial_layout(nodes, edges)
    assert a == b  # deterministic
    assert set(a) == set(nodes)  # every node placed
    assert a["n0"] == (0.0, 0.0)  # highest-degree root at origin


def test_radial_layout_empty() -> None:
    assert radial_layout([], []) == {}


# --- pathfinder ---------------------------------------------------------------
def test_pathfinder_shortest_and_cutoff() -> None:
    con, reader = _mem_store()
    try:
        _principal(con, "u", "S-1-5-21-10-20-30-1104", sam="user")
        _principal(con, "g1", "S-1-5-21-10-20-30-1200", ptype="Group", sam="mid")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _edge(con, "MemberOf", "u", "g1")
        _edge(con, "MemberOf", "g1", "da")

        res = find_paths(reader, source_node_ids=["u"], target="tier0", max_hops=8)
        assert res.paths_found == 1
        assert res.paths[0].length == 2
        assert [e.kind for e in res.paths[0].edges] == ["MemberOf", "MemberOf"]
        assert res.paths[0].target_label == "Domain Admins"

        # cutoff shorter than the path -> no path found
        res2 = find_paths(reader, source_node_ids=["u"], target="tier0", max_hops=1)
        assert res2.paths_found == 0
    finally:
        con.close()


def test_pathfinder_truncation() -> None:
    edges = [
        EdgeRow(f"e{i}", "GenericAll", f"s{i}", "da", "confirmed", False, None, None)
        for i in range(5)
    ]
    pg = build_path_graph(edges)
    assert pg.graph.number_of_edges() == 5


# --- risk ---------------------------------------------------------------------
def test_risk_kerberoastable_and_tier0_and_dcsync() -> None:
    principals = [
        {
            "node_id": "svc",
            "principal_type": "User",
            "object_sid": "S-1-5-21-10-20-30-1150",
            "samaccountname": "svc",
            "uac_flags": 512,
            "enabled": True,
            "spns": ["HTTP/web"],
            "sid_history": [],
            "admincount": 0,
            "label": "svc",
            "domain_fqdn": "t.local",
        },
        {
            "node_id": "da",
            "principal_type": "Group",
            "object_sid": "S-1-5-21-10-20-30-512",
            "samaccountname": "Domain Admins",
            "uac_flags": None,
            "enabled": None,
            "spns": [],
            "sid_history": [],
            "admincount": 1,
            "label": "Domain Admins",
            "domain_fqdn": "t.local",
        },
    ]
    edges = [
        EdgeRow("e1", "GenericAll", "svc", "da", "confirmed", False, None, None),
        EdgeRow("e2", "DCSync", "da", "dom", "confirmed", False, None, None),
    ]
    scored = score_nodes(principals, edges, _t0sets(targets=("da",), groups=("da",)))
    by_id = {nr.node_id: nr for nr in scored}

    svc_codes = {f.code for f in by_id["svc"].factors}
    assert "KERBEROASTABLE" in svc_codes
    assert "TIER0_REACHABLE" in svc_codes  # svc -> da via GenericAll
    assert "OUTBOUND_CONTROL" in svc_codes

    da_codes = {f.code for f in by_id["da"].factors}
    assert "TIER0" in da_codes
    assert "DCSYNC_HOLDER" in da_codes
    assert by_id["da"].tier == 0
    # transparency: score equals the sum of its factor weights
    assert by_id["da"].score == sum(f.weight for f in by_id["da"].factors)
    # ranking: the Tier-0 DCSync holder outranks the service account
    assert scored[0].node_id == "da"


# --- graph slice --------------------------------------------------------------
def test_slice_truncation_and_determinism() -> None:
    con, reader = _mem_store()
    try:
        for i in range(10):
            _principal(con, f"n{i}", f"S-1-5-21-10-20-30-{2000 + i}", sam=f"n{i}")
        for i in range(9):
            _edge(con, "MemberOf", f"n{i}", f"n{i + 1}")

        sl = build_slice(reader, limit=5, layout="none")
        assert isinstance(sl, GraphSlice)
        assert sl.total_matched == 10
        assert sl.returned == 5
        assert sl.truncated is True
        # deterministic: cap takes the node_id-sorted first 5, twice identically
        sl2 = build_slice(reader, limit=5, layout="none")
        assert canonical_json(sl.model_dump()) == canonical_json(sl2.model_dump())

        # node-kind filter + seed BFS
        seeded = build_slice(reader, seed_node_ids=["n0"], depth=2, layout="none")
        ids = {n.node_id for n in seeded.nodes}
        assert ids == {"n0", "n1", "n2"}
    finally:
        con.close()


def test_slice_server_layout_assigns_positions() -> None:
    con, reader = _mem_store()
    try:
        for i in range(10):
            _principal(con, f"n{i}", f"S-1-5-21-10-20-30-{3000 + i}", sam=f"n{i}")
        _edge(con, "MemberOf", "n0", "n1")
        sl = build_slice(reader, layout="server")
        assert sl.layout == "server"
        assert all(n.x is not None and n.y is not None for n in sl.nodes)
    finally:
        con.close()


# --- UAC decode ---------------------------------------------------------------
def test_decode_uac() -> None:
    # 0x80000 TRUSTED_FOR_DELEGATION | 0x400000 DONT_REQ_PREAUTH | 0x2 ACCOUNTDISABLE
    u = decode_uac(0x80000 | 0x400000 | 0x2)
    assert u.trusted_for_delegation is True
    assert u.dont_require_preauth is True
    assert u.account_disabled is True
    assert u.enabled is False
    assert decode_uac(None).raw is None


# --- Tier-0 definition (domain-expert gates G1/G2/G3) -------------------------
def test_tier0_suffix_sets_corrected() -> None:
    """G2/G3: -520 is not Tier-0; -516 is a traversal target."""
    assert "-520" not in TIER0_SID_SUFFIXES  # G2: GPCO dropped from Tier-0
    assert "-516" in TIER0_SID_SUFFIXES  # DCs still classified Tier-0
    assert "-516" in TIER0_TARGET_SUFFIXES  # G3: DCs are now a traversal target
    assert "-520" not in TIER0_TARGET_SUFFIXES
    # krbtgt/-500/-518 are classified Tier-0 but NOT traversal destinations
    assert "-502" in TIER0_SID_SUFFIXES
    assert "-502" not in TIER0_TARGET_SUFFIXES
    assert sid_is_gpo_creator("S-1-5-21-1-2-3-520")
    assert not sid_is_tier0("S-1-5-21-1-2-3-520")  # GPCO not Tier-0


def test_domain_object_is_tier0_target_and_classified() -> None:
    """G1: the Domain root object is a Tier-0 target + classified + high-value."""
    con, reader = _mem_store()
    try:
        # the domain object: a container with the bare domain SID (no RID suffix)
        _container(con, "dom", "Domain", DOM, dn="DC=t,DC=local")
        # a principal that holds WriteDacl on the Domain object -> self-grant DCSync
        _principal(con, "attacker", "S-1-5-21-10-20-30-1337", sam="attacker")
        _edge(con, "WriteDacl", "attacker", "dom")

        sets = reader.tier0_sets()
        assert "dom" in sets.domain_object_ids
        assert "dom" in sets.target_ids  # pathfinding destination (G1/G3)
        assert "dom" in sets.classified_ids  # high-value classification
        assert "dom" not in sets.group_target_ids  # it is a container, not a group

        # WriteDacl-on-domain now yields a path to Tier-0 (the domain object)
        res = find_paths(reader, source_node_ids=["attacker"], target="tier0")
        assert res.paths_found >= 1
        assert "dom" in {p.target_node_id for p in res.paths}
    finally:
        con.close()


def test_dcsync_on_domain_reaches_tier0() -> None:
    """G1: a DCSync edge targets the Domain object -> holder reaches Tier-0."""
    con, reader = _mem_store()
    try:
        _container(con, "dom", "Domain", DOM, dn="DC=t,DC=local")
        _principal(con, "svc", "S-1-5-21-10-20-30-1150", sam="svc")
        _edge(con, "DCSync", "svc", "dom")
        res = find_paths(reader, source_node_ids=["svc"], target="tier0")
        assert "dom" in {p.target_node_id for p in res.paths}
        assert res.paths_found >= 1
    finally:
        con.close()


def test_membership_into_tier0_group_inherits_tier0() -> None:
    """H1: a current effective member of a Tier-0 group IS Tier-0 (~100), not 40."""
    con, reader = _mem_store()
    try:
        _principal(con, "u", "S-1-5-21-10-20-30-1104", sam="user")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _edge(con, "MemberOf", "u", "da")
        _eff(con, "u", "da")  # u is an effective member of Domain Admins

        scored = score_nodes(
            reader.principal_risk_inputs(), reader.all_edges(), reader.tier0_sets()
        )
        u = next(nr for nr in scored if nr.node_id == "u")
        codes = {f.code for f in u.factors}
        assert "TIER0" in codes  # inherits Tier-0 by possession
        assert "TIER0_REACHABLE" not in codes  # NOT merely reachable
        assert "CLOSE_TO_TIER0" not in codes
        assert u.tier == 0
        assert u.score >= 100
    finally:
        con.close()


def test_h2_structural_hop_into_tier0_group_blocked() -> None:
    """H2: Contains/GPLink is not a valid terminal hop into a Tier-0 group."""
    con, reader = _mem_store()
    try:
        # an OU that CONTAINS Domain Admins (structural) + a GenericAll controller
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _container(con, "ou", "OU", None, dn="OU=X,DC=t,DC=local")
        _principal(con, "ctrl", "S-1-5-21-10-20-30-1500", sam="ctrl")
        _edge(con, "Contains", "ou", "da")  # containing a group != controlling it
        _edge(con, "GenericAll", "ctrl", "da")  # real control hop

        # OU can only reach DA via a terminal Contains -> no path (false path blocked)
        res_ou = find_paths(reader, source_node_ids=["ou"], target="tier0")
        assert res_ou.paths_found == 0
        # the real controller still reaches DA
        res_ctrl = find_paths(reader, source_node_ids=["ctrl"], target="tier0")
        assert res_ctrl.paths_found == 1
        assert res_ctrl.paths[0].edges[-1].kind == "GenericAll"
    finally:
        con.close()


def test_gpco_scored_small_not_tier0() -> None:
    """G2: GPCO (-520) gets a small factor, never TIER0=100."""
    principals = [
        {
            "node_id": "gpco",
            "principal_type": "Group",
            "object_sid": "S-1-5-21-10-20-30-520",
            "samaccountname": "Group Policy Creator Owners",
            "uac_flags": None,
            "enabled": None,
            "spns": [],
            "sid_history": [],
            "admincount": 0,
            "label": "GPCO",
            "domain_fqdn": "t.local",
        },
    ]
    scored = score_nodes(principals, [], _t0sets(gpo_creators=("gpco",)))
    codes = {f.code for f in scored[0].factors}
    assert "GPO_CREATOR" in codes
    assert "TIER0" not in codes
    assert scored[0].tier is None


# --- pathfinding bound (reviewer MAJOR) ---------------------------------------
def test_pathfinding_is_bounded() -> None:
    """max_hops is clamped to the hard cap; a wide graph is capped, not hung."""
    con, reader = _mem_store()
    try:
        # a dense fan-in so all_simple_paths could explode without a bound
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        for i in range(30):
            _principal(con, f"n{i}", f"S-1-5-21-10-20-30-{4000 + i}", sam=f"n{i}")
        for i in range(30):
            for j in range(30):
                if i != j:
                    _edge(con, "GenericAll", f"n{i}", f"n{j}")
        for i in range(30):
            _edge(con, "GenericAll", f"n{i}", "da")

        res = find_paths(
            reader,
            source_node_ids=["n0"],
            target="tier0",
            max_hops=9999,  # over the cap
            max_paths=5,
            all_simple=True,
        )
        assert res.max_hops == MAX_PATH_HOPS  # clamped, not 9999
        assert res.paths_found <= 5
        assert res.truncated is True  # bounded enumeration reported honestly
    finally:
        con.close()


def test_over_budget_distinct_from_unreachable() -> None:
    """Honesty nit: a reachable-but-over-budget target is not called unreachable."""
    con, reader = _mem_store()
    try:
        _principal(con, "u", "S-1-5-21-10-20-30-1104", sam="user")
        _principal(con, "a", "S-1-5-21-10-20-30-1200", sam="a")
        _principal(con, "b", "S-1-5-21-10-20-30-1201", sam="b")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        # u -> a -> b -> da is 3 hops; with max_hops=2 it is reachable but over budget
        _edge(con, "GenericAll", "u", "a")
        _edge(con, "GenericAll", "a", "b")
        _edge(con, "GenericAll", "b", "da")
        res = find_paths(reader, source_node_ids=["u"], target="tier0", max_hops=2)
        da_id = "da"
        assert res.paths_found == 0
        assert da_id in res.over_budget_targets
        assert da_id not in res.unreachable_targets
    finally:
        con.close()


def test_search_escapes_like_wildcards() -> None:
    """MINOR: a user '%'/'_' is matched literally, not as a wildcard."""
    con, reader = _mem_store()
    try:
        _principal(con, "p1", "S-1-5-21-10-20-30-1104", sam="alice")
        _principal(con, "p2", "S-1-5-21-10-20-30-1105", sam="a%b")
        # '%' must match the literal name 'a%b', not every name containing 'a'
        hits = reader.search("a%b", 50)
        sams = {h.node_id for h in hits}
        assert "p2" in sams
        assert "p1" not in sams
    finally:
        con.close()


def test_nodes_page_filter_sort_and_paging() -> None:
    """Browse-by-type page: kind filter, SQL name sort, +1 truncation, q, risk/tier."""
    con, reader = _mem_store()
    try:
        _principal(con, "u1", "S-1-5-21-10-20-30-1104", sam="alice")
        _principal(con, "u2", "S-1-5-21-10-20-30-1105", sam="bob")
        _principal(con, "u3", "S-1-5-21-10-20-30-1106", sam="carol")
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _container(con, "ou", "OU", None, dn="OU=X,DC=t,DC=local")

        # kind filter + deterministic name ordering
        users = reader.nodes_page(kind="User", sort="name", limit=50)
        assert users.total_matched == 3
        assert [r.node_id for r in users.rows] == ["u1", "u2", "u3"]
        assert users.truncated is False

        # paging + truncated detected via the LIMIT ?+1 probe
        pg = reader.nodes_page(kind="User", sort="name", limit=2, offset=0)
        assert pg.total_matched == 3 and len(pg.rows) == 2 and pg.truncated is True
        pg2 = reader.nodes_page(kind="User", sort="name", limit=2, offset=2)
        assert len(pg2.rows) == 1 and pg2.truncated is False

        # q is case-insensitive and escaped
        q = reader.nodes_page(q="ALICE", sort="name", limit=50)
        assert [r.node_id for r in q.rows] == ["u1"]

        # risk sort: scored desc first, unscored (u3, ou) last by node_id asc
        risk_map = {"u1": 5, "u2": 20, "da": 100}
        r = reader.nodes_page(
            sort="risk", order="desc", limit=50, risk_by_id=risk_map, tier0_ids=frozenset({"da"})
        )
        assert [x.node_id for x in r.rows] == ["da", "u2", "u1", "ou", "u3"]

        # tier sort: the Tier-0 node first, the rest last by node_id
        t = reader.nodes_page(sort="tier", order="asc", limit=50, tier0_ids=frozenset({"da"}))
        assert t.rows[0].node_id == "da"
    finally:
        con.close()


def test_nodes_page_bounds_limit() -> None:
    """The page size is hard-capped regardless of the requested limit (NODES_PAGE_MAX)."""
    from wraith.api.store import NODES_PAGE_MAX

    con, reader = _mem_store()
    try:
        for i in range(5):
            _principal(con, f"n{i}", f"S-1-5-21-10-20-30-{6000 + i}", sam=f"n{i}")
        res = reader.nodes_page(limit=10_000)
        assert res.total_matched == 5
        # limit clamped: a 5-node store returns all 5, but the cap still applies
        assert len(res.rows) <= NODES_PAGE_MAX
    finally:
        con.close()


# --- guided dossier (doc 21): glossary, group members, exec summary ----------
def test_glossary_covers_every_engine_edge_kind() -> None:
    """The static glossary covers every edge kind the engine emits (no counted gap)."""
    from wraith.api.rights_glossary import (
        ENGINE_EDGE_KINDS,
        attribute_name_for_guid,
        build_glossary,
    )
    from wraith.edges.guid_map import GUID_SERVICE_PRINCIPAL_NAME

    g = build_glossary()
    assert g.counted_gaps == {}  # every engine kind has an authored entry
    assert ENGINE_EDGE_KINDS.issubset(set(g.edges))
    # a representative truth-contract check: GenericWrite explicitly disclaims the
    # password reset (it is a control-access right, not a property write).
    assert "does not reset a password" in g.edges["GenericWrite"].grants.lower()
    assert "reset the password" in g.edges["ForceChangePassword"].action.lower()
    # the attribute-name resolver maps a scoped GUID to its readable name
    assert attribute_name_for_guid(GUID_SERVICE_PRINCIPAL_NAME) == "servicePrincipalName"
    assert attribute_name_for_guid(None) is None
    assert attribute_name_for_guid("00000000-0000-0000-0000-000000000000") is None


def test_group_dossier_members_and_exec_summary_deterministic() -> None:
    """A Group dossier lists effective members (direct vs nested) + a stable summary."""
    con, reader = _mem_store()
    try:
        # Tier-0 Domain Admins group (RID -512), one direct + one nested member, and
        # a non-Tier-0 controller holding GenericAll into the group.
        _principal(con, "gda", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _principal(con, "alice", "S-1-5-21-10-20-30-1105", sam="alice", spns=["HTTP/a"])
        _principal(con, "bob", "S-1-5-21-10-20-30-1106", sam="bob")
        _principal(con, "helpdesk", "S-1-5-21-10-20-30-1107", ptype="Group", sam="HELPDESK")
        _eff(con, "alice", "gda")
        _eff(con, "bob", "gda")
        _edge(con, "MemberOf", "alice", "gda")  # alice is a DIRECT member
        _edge(con, "GenericAll", "helpdesk", "gda")
        _edge(con, "GenericAll", "helpdesk", "alice")

        d = build_dossier(reader, "gda")
        assert d is not None
        assert d.kind == "Group"
        members = {m.node_id: m for m in d.group_members}
        assert set(members) == {"alice", "bob"}
        assert members["alice"].is_nested is False  # direct (inbound MemberOf)
        assert members["bob"].is_nested is True  # nested (closure only)
        assert all(m.is_tier0 for m in d.group_members)  # members of a Tier-0 group
        # exec summary: fixed order, Tier-0 group identity + member counts stated
        assert d.exec_summary
        assert "security group" in d.exec_summary[0]
        assert "Tier-0" in d.exec_summary[0]
        assert any("effective member(s)" in s for s in d.exec_summary)
        # deterministic: identical store -> byte-identical summary + members
        d2 = build_dossier(reader, "gda")
        assert d2 is not None
        assert canonical_json(d.model_dump()) == canonical_json(d2.model_dump())

        # a non-Tier-0 controller reaches Tier-0 in 1 hop (structured field, add #3)
        hd = build_dossier(reader, "helpdesk")
        assert hd is not None and hd.risk is not None
        assert hd.risk.tier0_hops == 1
        # its outbound GenericAll edge into the Tier-0 group is badged on the endpoint
        out_gda = next(e for e in hd.outbound_edges if e.other.node_id == "gda")
        assert out_gda.other.is_tier0 is True and out_gda.other.tier == 0
    finally:
        con.close()


def test_decode_uac_reversible_password() -> None:
    """The decoded UAC block now surfaces the reversible-encryption flag (0x80)."""
    assert decode_uac(0x80).reversible_password is True
    assert decode_uac(0x200).reversible_password is False  # NORMAL_ACCOUNT only


@pytest.mark.parametrize("n", [0, 1, 250, 251])
def test_slice_layout_threshold(n: int) -> None:
    """`auto` precomputes positions only at/above the threshold."""
    con, reader = _mem_store()
    try:
        for i in range(n):
            _principal(con, f"n{i}", f"S-1-5-21-10-20-30-{5000 + i}", sam=f"n{i}")
        sl = build_slice(reader, limit=5000, layout="auto")
        if n >= 250:
            assert sl.layout == "server"
        else:
            assert sl.layout == "none"
    finally:
        con.close()
