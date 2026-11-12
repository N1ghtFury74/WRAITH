"""Minimal coder-side sanity for Module 4 pure seams (the gate is the tester's).

Covers the correctness crux (schema-resolved member link_base, the member->group
direction SWAP), the live-link predicate, primary-group/special-identity
synthesis, the cycle-guarded closure, and that the §4 edge DDL creates cleanly.
It does NOT drive the full resolver against a real ``.dit`` (that is the tester's
parity/golden layer, pinned from the dev run in docs/modules/04-membership.md).
"""

from __future__ import annotations

from uuid import UUID

import duckdb

from wraith.common.determinism import stable_id
from wraith.edges.membership import (
    DERIVATION_LINK,
    AccountInput,
    LinkInput,
    PrincipalIndex,
    Scoping,
    build_link_memberof_edges,
    build_primary_group_edges,
    build_special_identity_edges,
    compute_effective_membership,
    is_live_link,
    resolve_member_link_base,
    resolve_primary_group_node,
)
from wraith.edges.models import EdgeRow
from wraith.model.store import create_edge_tables
from wraith.normalize.identity import node_id_for_sid
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

_RUN = UUID("00000000-0000-0000-0000-0000000000c4")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="a" * 64,
    source_object_id="link:1",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)
_SCOPING = Scoping(forest_id="f", domain_id="S-1-5-21-1-2-3", domain_fqdn="c137.local")


def _schema_with_member_link_id(link_id: int) -> NtdsSchema:
    """Build a minimal NtdsSchema exposing member's linkID via a raw record."""
    return NtdsSchema(
        column_to_ldap={},
        ldap_to_column={"lDAPDisplayName": "ATTm131532", "linkID": "ATTj131122"},
        attributes_by_ldap={},
        attributes_by_internal_id={},
        classes_by_ldap={},
        extended_rights_by_guid={},
        raw_attribute_records=(
            {"ATTm131532": "memberOf", "ATTj131122": link_id + 1},
            {"ATTm131532": "member", "ATTj131122": link_id},
        ),
        raw_class_records=(),
        raw_right_records=(),
        skipped_schema_records=0,
        unmapped_columns=(),
    )


def test_resolve_member_link_base_from_schema() -> None:
    # linkID 2 (forward) -> link_base 1, the real-DC-confirmed value.
    assert resolve_member_link_base(_schema_with_member_link_id(2)) == 1
    # A non-standard even linkID still resolves as linkID >> 1.
    assert resolve_member_link_base(_schema_with_member_link_id(94)) == 47
    # Absent linkID column -> None (surfaced gap), never a crash.
    empty = _schema_with_member_link_id(2)
    stripped = NtdsSchema(
        column_to_ldap={},
        ldap_to_column={"lDAPDisplayName": "ATTm131532"},
        attributes_by_ldap={},
        attributes_by_internal_id={},
        classes_by_ldap={},
        extended_rights_by_guid={},
        raw_attribute_records=empty.raw_attribute_records,
        raw_class_records=(),
        raw_right_records=(),
        skipped_schema_records=0,
        unmapped_columns=(),
    )
    assert resolve_member_link_base(stripped) is None


def test_is_live_link_sentinels() -> None:
    assert is_live_link(None, None) is True  # dev-DIT sentinel (NULL)
    assert is_live_link(0, 0) is True
    assert is_live_link(1, None) is False  # tombstoned
    assert is_live_link(None, 1) is False  # deactivated


def test_link_edge_direction_is_swapped() -> None:
    # M3 stores source=GROUP, target=MEMBER. The MemberOf edge must SWAP:
    # source=member, target=group.
    link = LinkInput(
        link_base=1,
        source_node_id="group-da",
        target_node_id="user-admin",
        link_deltime=None,
        link_deactivetime=None,
        provenance=_PROV,
    )
    edges, gaps = build_link_memberof_edges([link], 1, _SCOPING)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.source_node_id == "user-admin"  # member
    assert edge.target_node_id == "group-da"  # group
    assert edge.kind == "MemberOf" and edge.derivation == DERIVATION_LINK
    assert edge.confidence == "confirmed" and edge.is_inherited is False
    assert edge.edge_id == stable_id("MemberOf", "user-admin", "group-da", DERIVATION_LINK)
    assert gaps.tombstoned == 0 and gaps.unresolved_endpoint == 0


def test_link_edge_filters_and_counts_gaps() -> None:
    links = [
        LinkInput(2, "g", "m", None, None, _PROV),  # non-member link_base
        LinkInput(1, "g", "m", 1, None, _PROV),  # tombstoned
        LinkInput(1, None, "m", None, None, _PROV),  # unresolved endpoint
    ]
    edges, gaps = build_link_memberof_edges(links, 1, _SCOPING)
    assert edges == []
    assert (gaps.non_member, gaps.tombstoned, gaps.unresolved_endpoint) == (1, 1, 1)


def test_primary_group_resolution_and_edges() -> None:
    group_sid = "S-1-5-21-1-2-3-513"
    group_node = "node-domain-users"
    index = PrincipalIndex(
        sid_to_node={group_sid: group_node},
        group_nodes=frozenset({group_node}),
        all_nodes=frozenset({group_node, "node-user"}),
    )
    assert resolve_primary_group_node(513, "S-1-5-21-1-2-3", "f", index) == group_node
    # Non-Group / missing -> None.
    assert resolve_primary_group_node(9999, "S-1-5-21-1-2-3", "f", index) is None

    accounts = [
        AccountInput("node-user", 513, "User", _PROV),
        AccountInput("node-group", None, "Group", _PROV),  # skipped (no PGID)
        AccountInput("node-bad", 9999, "Computer", _PROV),  # unresolved
    ]
    edges, unresolved = build_primary_group_edges(accounts, _SCOPING, index)
    assert len(edges) == 1 and unresolved == 1
    assert edges[0].source_node_id == "node-user" and edges[0].target_node_id == group_node
    assert edges[0].derivation == "SYNTH:primarygroup"


def test_special_identity_edges_inferred() -> None:
    domain = "S-1-5-21-1-2-3"
    du = node_id_for_sid("f", domain, f"{domain}-513")
    dc = node_id_for_sid("f", domain, f"{domain}-515")
    au = node_id_for_sid("f", domain, "S-1-5-11")
    ev = node_id_for_sid("f", domain, "S-1-1-0")
    index = PrincipalIndex(
        sid_to_node={},
        group_nodes=frozenset({du, dc, au, ev}),
        all_nodes=frozenset({du, dc, au, ev}),
    )
    edges, unresolved = build_special_identity_edges(_SCOPING, index, _PROV)
    assert unresolved == 0 and len(edges) == 3
    assert all(e.derivation == "SYNTH:specialidentity" for e in edges)
    assert all(e.confidence == "inferred" for e in edges)
    # Domain Users -> Authenticated Users among them.
    assert (du, au) in {(e.source_node_id, e.target_node_id) for e in edges}


def _edge(member: str, group: str) -> EdgeRow:
    return EdgeRow(
        edge_id=stable_id("MemberOf", member, group, DERIVATION_LINK),
        kind="MemberOf",
        source_node_id=member,
        target_node_id=group,
        is_inherited=False,
        derivation=DERIVATION_LINK,
        access_mask=None,
        object_type_guid=None,
        confidence="confirmed",
        forest_id="f",
        domain_id="S-1-5-21-1-2-3",
        domain_fqdn="c137.local",
        provenance=_PROV,
    )


def test_closure_transitive_and_cycle_safe() -> None:
    # u in g1, g1 in g2  => u effectively in g1 and g2; g1 effectively in g2.
    edges = [_edge("u", "g1"), _edge("g1", "g2")]
    rows = compute_effective_membership(edges, _SCOPING)
    pairs = {(r.member_node_id, r.group_node_id) for r in rows}
    assert pairs == {("u", "g1"), ("u", "g2"), ("g1", "g2")}

    # Cycle A in B, B in A must terminate; reflexive pairs dropped.
    cyclic = [_edge("a", "b"), _edge("b", "a")]
    crows = compute_effective_membership(cyclic, _SCOPING)
    cpairs = {(r.member_node_id, r.group_node_id) for r in crows}
    assert cpairs == {("a", "b"), ("b", "a")}  # no (a,a)/(b,b)


def test_create_edge_tables_smoke() -> None:
    con = duckdb.connect(":memory:")
    create_edge_tables(con)
    tables = {row[0] for row in con.execute("SHOW TABLES").fetchall()}
    assert {"edge", "effective_membership"} <= tables
    con.close()
