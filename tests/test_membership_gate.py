"""Independent gate suite — Module 4 (the Membership Resolver).

Authored by ``wraith-tester`` (the gatekeeper). This is the AUTHORITATIVE gate;
it does NOT trust the coder's ``test_membership_sanity.py``. It re-derives every
pure invariant on hand-built inputs and drives the full real pipeline
(2a parse -> M3 normalize -> M4 resolve) against the (untrusted, gitignored)
``eviedence_test`` DC, pinning the OBSERVED FACTS.

Layers:
  * Layer 1 (unit/golden)   — the PURE seams on crafted inputs with KNOWN output:
                              the live-link predicate, the cycle-guarded closure
                              (CYCLE + nested chain + reflexive-free), the
                              schema-resolved member link_base (and None-not-crash),
                              primary-group resolution, and edge_id determinism.
  * Layer 2 (golden/live)   — the full chain against the real DC, pinning the
                              documented facts: per-derivation edge counts
                              (25/11/3=39), the confidence split (36/3), the
                              effective_pair count (70), the member->group
                              DIRECTION crux (Administrator->Domain Admins yes,
                              reverse no), effective members of Domain Admins
                              ({Administrator, ricksanchez}) and Everyone (12),
                              Administrator's implicit Domain Users primary-group
                              edge, and resolve_member_link_base == 1.
  * Layer 3 (robustness)    — tombstoned / unresolved-endpoint / primarygroup-
                              unresolved degrade to COUNTED gaps (never a crash or
                              a dangling/half-null edge); edge-table rowcount ==
                              emitted count; PK uniqueness (edge_id and
                              effective_membership (member,group)).
  * Layer 4 (determinism)   — two independent full runs -> byte-identical ``edge``
                              and ``effective_membership`` rows.
  * Layer 5 (shape)         — the §4 ``edge`` row shape matches frozen (MemberOf
                              carries NULL access_mask/object_type_guid, the
                              scoping block, and a provenance struct).

M4 touches no secrets; no value is ever printed or asserted on. Evidence is
read-only and never copied into the repo; every evidence test skips cleanly when
the ``.dit`` is absent (CI-safe).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from wraith.acquisition.hashing import sha256_file
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.common.determinism import stable_id
from wraith.edges import (
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
    resolve_membership,
    resolve_primary_group_node,
)
from wraith.edges.models import EdgeRow, MembershipResult
from wraith.model.store import create_edge_tables
from wraith.normalize import normalize
from wraith.parsing import open_ntds
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

# --- anchors -----------------------------------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"

FOREST = "forest-c137"
_CASE = "GATE-M4"
_RUN = UUID("00000000-0000-0000-0000-0000000000a4")

# Independently-established ground truth (from the M3 gate + the Module-4 dev run
# documented in docs/modules/04-membership.md). Pinned so a silent regression in
# the swap/count/closure is caught, not waved through.
_DOMAIN_SID = "S-1-5-21-2232410529-1445159330-2725690660"
_DOMAIN_FQDN = "c137.local"

_EXPECT_DIRECT = 25  # LINK:member
_EXPECT_PRIMARY = 11  # SYNTH:primarygroup
_EXPECT_SYNTH = 3  # SYNTH:specialidentity
_EXPECT_TOTAL = 39
_EXPECT_CONFIRMED = 36
_EXPECT_INFERRED = 3
_EXPECT_EFFECTIVE = 70
_EXPECT_MEMBER_LINK_BASE = 1
_EXPECT_DA_MEMBERS = {"Administrator", "ricksanchez"}
_EXPECT_EVERYONE_EFFECTIVE = 12

_evidence_present = _NTDS.is_file()
_needs_evidence = pytest.mark.skipif(
    not _evidence_present, reason="needs eviedence_test NTDS ntds.dit present"
)

_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="a" * 64,
    source_object_id="link:1",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)
_SCOPING = Scoping(forest_id=FOREST, domain_id="S-1-5-21-9-8-7", domain_fqdn="x.local")


# =============================================================================
# Layer 1 — PURE seams (no evidence)
# =============================================================================


def _schema_with_attr_records(records: tuple[dict[str, object], ...]) -> NtdsSchema:
    """Build a minimal NtdsSchema whose raw attributeSchema records are `records`."""
    return NtdsSchema(
        column_to_ldap={},
        ldap_to_column={"lDAPDisplayName": "ATTm131532", "linkID": "ATTj131122"},
        attributes_by_ldap={},
        attributes_by_internal_id={},
        classes_by_ldap={},
        extended_rights_by_guid={},
        raw_attribute_records=records,
        raw_class_records=(),
        raw_right_records=(),
        skipped_schema_records=0,
        unmapped_columns=(),
    )


def test_is_live_link_predicate() -> None:
    """Proves: a link is live iff BOTH deltime and deactivetime are the unset
    sentinel (NULL or 0); any non-zero on either side is a tombstone/deactivation
    and is NOT live (so it cannot over-report membership)."""
    assert is_live_link(None, None) is True
    assert is_live_link(0, 0) is True
    assert is_live_link(0, None) is True
    assert is_live_link(None, 0) is True
    assert is_live_link(1, None) is False  # tombstoned
    assert is_live_link(None, 1) is False  # deactivated
    assert is_live_link(1, 1) is False
    assert is_live_link(123456789, 0) is False


def _edge(member: str, group: str, derivation: str = "LINK:member") -> EdgeRow:
    """Construct a MemberOf EdgeRow (member -> group) with the canonical edge_id."""
    return EdgeRow(
        edge_id=stable_id("MemberOf", member, group, derivation),
        kind="MemberOf",
        source_node_id=member,
        target_node_id=group,
        is_inherited=False,
        derivation=derivation,
        access_mask=None,
        object_type_guid=None,
        confidence="confirmed",
        forest_id=FOREST,
        domain_id=_SCOPING.domain_id,
        domain_fqdn=_SCOPING.domain_fqdn,
        provenance=_PROV,
    )


def test_closure_nested_chain() -> None:
    """Proves: a nested chain A in B in C yields A effective-in B AND C, and B
    effective-in C — the transitive expansion the materialized table must carry."""
    edges = [_edge("A", "B"), _edge("B", "C")]
    pairs = {
        (r.member_node_id, r.group_node_id) for r in compute_effective_membership(edges, _SCOPING)
    }
    assert pairs == {("A", "B"), ("A", "C"), ("B", "C")}


def test_closure_cycle_terminates_reflexive_free() -> None:
    """Proves (the cycle-guard crux): a membership CYCLE A in B, B in A terminates
    (no infinite loop) and produces NO reflexive self-pair — exactly {(A,B),(B,A)}.
    AD permits such cycles; a broken guard would hang or emit (A,A)/(B,B)."""
    edges = [_edge("A", "B"), _edge("B", "A")]
    pairs = {
        (r.member_node_id, r.group_node_id) for r in compute_effective_membership(edges, _SCOPING)
    }
    assert pairs == {("A", "B"), ("B", "A")}
    assert ("A", "A") not in pairs and ("B", "B") not in pairs


def test_closure_three_node_cycle_terminates() -> None:
    """Proves: a longer cycle A in B in C in A terminates and stays reflexive-free
    (every node effective-in the other two, never in itself)."""
    edges = [_edge("A", "B"), _edge("B", "C"), _edge("C", "A")]
    rows = compute_effective_membership(edges, _SCOPING)
    pairs = {(r.member_node_id, r.group_node_id) for r in rows}
    assert pairs == {
        ("A", "B"),
        ("A", "C"),
        ("B", "A"),
        ("B", "C"),
        ("C", "A"),
        ("C", "B"),
    }
    assert all(r.member_node_id != r.group_node_id for r in rows)


def test_closure_is_sorted_and_scoped() -> None:
    """Proves: the closure is emitted sorted by (group, member) and every row
    carries the run's scoping block (byte-reproducible, correctly scoped)."""
    edges = [_edge("A", "B"), _edge("B", "C")]
    rows = compute_effective_membership(edges, _SCOPING)
    keys = [(r.group_node_id, r.member_node_id) for r in rows]
    assert keys == sorted(keys)
    assert all(r.forest_id == FOREST and r.domain_id == _SCOPING.domain_id for r in rows)


def test_resolve_member_link_base_shift_and_absent() -> None:
    """Proves: member's link_base is linkID>>1 (linkID 2 -> 1, the real-DC value;
    a non-standard even 94 -> 47), and a schema that does NOT surface member's
    linkID degrades to None (a surfaced gap) rather than crashing."""
    s2 = _schema_with_attr_records(
        (
            {"ATTm131532": "memberOf", "ATTj131122": 3},
            {"ATTm131532": "member", "ATTj131122": 2},
        )
    )
    assert resolve_member_link_base(s2) == 1
    s94 = _schema_with_attr_records(({"ATTm131532": "member", "ATTj131122": 94},))
    assert resolve_member_link_base(s94) == 47

    # member present but no linkID value -> None, not a crash.
    s_no_linkid = _schema_with_attr_records(({"ATTm131532": "member"},))
    assert resolve_member_link_base(s_no_linkid) is None
    # member absent entirely -> None.
    s_no_member = _schema_with_attr_records(({"ATTm131532": "memberOf", "ATTj131122": 3},))
    assert resolve_member_link_base(s_no_member) is None
    # linkID column unmapped -> None (ldap_to_column lacks "linkID").
    s_unmapped = NtdsSchema(
        column_to_ldap={},
        ldap_to_column={"lDAPDisplayName": "ATTm131532"},
        attributes_by_ldap={},
        attributes_by_internal_id={},
        classes_by_ldap={},
        extended_rights_by_guid={},
        raw_attribute_records=({"ATTm131532": "member", "ATTj131122": 2},),
        raw_class_records=(),
        raw_right_records=(),
        skipped_schema_records=0,
        unmapped_columns=(),
    )
    assert resolve_member_link_base(s_unmapped) is None


def test_link_edge_swaps_member_and_group() -> None:
    """Proves (the DIRECTION crux): M3 stores source=GROUP/target=MEMBER; the
    emitted MemberOf edge SWAPS them so source=member, target=group, with the
    canonical edge_id and confirmed confidence."""
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
    e = edges[0]
    assert (e.source_node_id, e.target_node_id) == ("user-admin", "group-da")
    assert e.kind == "MemberOf" and e.derivation == "LINK:member"
    assert e.confidence == "confirmed" and e.is_inherited is False
    assert e.edge_id == stable_id("MemberOf", "user-admin", "group-da", "LINK:member")
    assert (gaps.tombstoned, gaps.unresolved_endpoint, gaps.non_member) == (0, 0, 0)


def test_resolve_primary_group_node_requires_group_type() -> None:
    """Proves: a primaryGroupID resolves to its <domain>-<rid> group node only when
    that node exists AND is typed Group; a missing/non-Group target -> None (a
    counted skip, never a dangling edge). domain_id None -> None."""
    group_sid = f"{_DOMAIN_SID}-513"
    group_node = "node-domain-users"
    index = PrincipalIndex(
        sid_to_node={group_sid: group_node},
        group_nodes=frozenset({group_node}),
        all_nodes=frozenset({group_node, "node-user"}),
    )
    assert resolve_primary_group_node(513, _DOMAIN_SID, FOREST, index) == group_node
    assert resolve_primary_group_node(9999, _DOMAIN_SID, FOREST, index) is None
    assert resolve_primary_group_node(513, None, FOREST, index) is None


def test_build_primary_group_edges_counts_and_direction() -> None:
    """Proves: only User/Computer with a resolvable primaryGroupID emit a
    SYNTH:primarygroup member->group edge; a Group or a missing PGID is a silent
    non-gap skip; an unresolvable PGID is a COUNTED gap."""
    group_sid = f"{_DOMAIN_SID}-513"
    group_node = "node-domain-users"
    index = PrincipalIndex(
        sid_to_node={group_sid: group_node},
        group_nodes=frozenset({group_node}),
        all_nodes=frozenset({group_node, "node-user"}),
    )
    accounts = [
        AccountInput("node-user", 513, "User", _PROV),  # resolves -> 1 edge
        AccountInput("node-group", None, "Group", _PROV),  # group, no PGID -> skip
        AccountInput("node-comp-nopgid", None, "Computer", _PROV),  # no PGID -> skip
        AccountInput("node-bad", 9999, "Computer", _PROV),  # unresolved -> counted
    ]
    scoping = Scoping(forest_id=FOREST, domain_id=_DOMAIN_SID, domain_fqdn=_DOMAIN_FQDN)
    edges, unresolved = build_primary_group_edges(accounts, scoping, index)
    assert len(edges) == 1 and unresolved == 1
    assert (edges[0].source_node_id, edges[0].target_node_id) == ("node-user", group_node)
    assert edges[0].derivation == "SYNTH:primarygroup" and edges[0].confidence == "confirmed"


def test_edge_id_is_stable_id_of_kind_source_target_derivation() -> None:
    """Proves: edge_id == stable_id(kind, source, target, derivation) and is
    DERIVATION-sensitive — the same (member,group) via two derivations yields two
    distinct ids (so a stored-link + primary-group fact are two rows, by design)."""
    link_edge = build_link_memberof_edges([LinkInput(1, "g", "m", None, None, _PROV)], 1, _SCOPING)[
        0
    ][0]
    assert link_edge.edge_id == stable_id("MemberOf", "m", "g", "LINK:member")
    # Deterministic: recomputing yields the identical id.
    again = build_link_memberof_edges([LinkInput(1, "g", "m", None, None, _PROV)], 1, _SCOPING)[0][
        0
    ]
    assert again.edge_id == link_edge.edge_id
    # Derivation-sensitive.
    assert stable_id("MemberOf", "m", "g", "LINK:member") != stable_id(
        "MemberOf", "m", "g", "SYNTH:primarygroup"
    )


# =============================================================================
# Layer 3 (pure part) — robustness: counted gaps, no dangling edges
# =============================================================================


def test_link_gaps_counted_never_crash() -> None:
    """Proves (robustness): a non-member link_base, a tombstoned link, and an
    unresolved (None) endpoint each produce ZERO edges and are COUNTED — never a
    half-null/dangling edge, never an exception."""
    links = [
        LinkInput(2, "g", "m", None, None, _PROV),  # non-member link_base
        LinkInput(1, "g", "m", 1, None, _PROV),  # tombstoned (deltime)
        LinkInput(1, "g", "m", None, 1, _PROV),  # deactivated
        LinkInput(1, None, "m", None, None, _PROV),  # unresolved group endpoint
        LinkInput(1, "g", None, None, None, _PROV),  # unresolved member endpoint
    ]
    edges, gaps = build_link_memberof_edges(links, 1, _SCOPING)
    assert edges == []
    assert gaps.non_member == 1
    assert gaps.tombstoned == 2
    assert gaps.unresolved_endpoint == 2


def test_special_identity_unresolved_endpoint_counted() -> None:
    """Proves: a special-identity pair whose endpoint resolves to no existing node
    is skipped + counted (never a dangling edge). With no nodes present, all three
    pairs are unresolved and zero edges emit."""
    empty = PrincipalIndex(sid_to_node={}, group_nodes=frozenset(), all_nodes=frozenset())
    scoping = Scoping(forest_id=FOREST, domain_id=_DOMAIN_SID, domain_fqdn=_DOMAIN_FQDN)
    edges, unresolved = build_special_identity_edges(scoping, empty, _PROV)
    assert edges == [] and unresolved == 3


# =============================================================================
# Live scaffolding (Layers 2, 4, 5) — full 2a -> M3 -> M4 chain
# =============================================================================


def _register(run: IngestRun) -> IngestRun:
    """Register ntds.dit so normalize can mint object/link provenance."""
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref=str(_NTDS.resolve()),
            size_bytes=_NTDS.stat().st_size,
            image_sha256=sha256_file(_NTDS),
        )
    )
    return run


@dataclass
class _Live:
    """A materialised full chain: the membership result + open store + identity."""

    result: MembershipResult
    con: duckdb.DuckDBPyConnection
    domain_id: str
    domain_fqdn: str
    member_link_base: int | None


def _run_full_chain(con: duckdb.DuckDBPyConnection, run_id: UUID) -> _Live:
    """Parse -> normalize -> resolve_membership into `con`; return the outcome."""
    run = _register(IngestRun(_CASE, "wraith-tester", ingest_run_id=run_id))
    with open_ntds(_NTDS, run) as parsed:
        norm = normalize(parsed, run, con, forest_id=FOREST)
        ident = norm.identity
        member_link_base = resolve_member_link_base(parsed.schema)
        result = resolve_membership(
            con,
            run,
            parsed.schema,
            forest_id=FOREST,
            domain_id=ident.domain_id,
            domain_fqdn=ident.domain_fqdn,
        )
    return _Live(
        result=result,
        con=con,
        domain_id=ident.domain_id,
        domain_fqdn=ident.domain_fqdn,
        member_link_base=member_link_base,
    )


@pytest.fixture(scope="module")
def m4_live() -> Iterator[_Live]:
    """Drive the real 2a -> M3 -> M4 chain once into a throwaway in-memory store."""
    if not _evidence_present:  # pragma: no cover - CI guard
        pytest.skip("needs eviedence_test ntds.dit")
    con = duckdb.connect(":memory:")
    live = _run_full_chain(con, _RUN)
    yield live
    con.close()


def _node_for_sam(con: duckdb.DuckDBPyConnection, sam: str) -> str:
    row = con.execute("SELECT node_id FROM principal WHERE samaccountname = ?", [sam]).fetchone()
    assert row is not None, f"principal {sam!r} not found"
    return row[0]


# =============================================================================
# Layer 2 — golden against the real DC
# =============================================================================


@_needs_evidence
def test_live_identity_matches_m3(m4_live: _Live) -> None:
    """Proves: the chain scoping matches the M3-gated identity (same domain SID +
    FQDN) — M4 edges are scoped to the right domain."""
    assert m4_live.domain_id == _DOMAIN_SID
    assert m4_live.domain_fqdn == _DOMAIN_FQDN


@_needs_evidence
def test_live_member_link_base_is_one(m4_live: _Live) -> None:
    """Proves: member's link_base resolves from the real schema to 1 (linkID 2>>1)
    — the dev-rumoured 47 is a different linked attribute; the public fact holds."""
    assert m4_live.member_link_base == _EXPECT_MEMBER_LINK_BASE
    assert m4_live.result.member_link_base == _EXPECT_MEMBER_LINK_BASE


@_needs_evidence
def test_live_per_derivation_counts_exact(m4_live: _Live) -> None:
    """Proves: the exact per-derivation direct-edge counts (LINK:member 25,
    SYNTH:primarygroup 11, SYNTH:specialidentity 3 = 39) — a miscount in any of
    the three builders would move these."""
    r = m4_live.result
    assert r.edges_direct == _EXPECT_DIRECT
    assert r.edges_primarygroup == _EXPECT_PRIMARY
    assert r.edges_synthetic == _EXPECT_SYNTH
    assert r.edges_total == _EXPECT_TOTAL


@_needs_evidence
def test_live_confidence_split_and_effective_count(m4_live: _Live) -> None:
    """Proves: the confidence split is 36 confirmed / 3 inferred, and the
    transitive closure materializes exactly 70 effective pairs."""
    con = m4_live.con
    confirmed = con.execute("SELECT count(*) FROM edge WHERE confidence = 'confirmed'").fetchone()[
        0
    ]
    inferred = con.execute("SELECT count(*) FROM edge WHERE confidence = 'inferred'").fetchone()[0]
    assert confirmed == _EXPECT_CONFIRMED
    assert inferred == _EXPECT_INFERRED
    assert m4_live.result.effective_pairs == _EXPECT_EFFECTIVE
    eff_rows = con.execute("SELECT count(*) FROM effective_membership").fetchone()[0]
    assert eff_rows == _EXPECT_EFFECTIVE


@_needs_evidence
def test_live_admin_to_domain_admins_direction(m4_live: _Live) -> None:
    """Proves (the DIRECTION crux): a MemberOf edge Administrator->Domain Admins
    EXISTS and the reverse (Domain Admins->Administrator) does NOT — a flipped swap
    would invert every privilege path."""
    con = m4_live.con
    admin = _node_for_sam(con, "Administrator")
    da = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", [f"{_DOMAIN_SID}-512"]
    ).fetchone()
    assert da is not None, "Domain Admins principal not found"
    da_node = da[0]
    fwd = con.execute(
        "SELECT count(*) FROM edge WHERE kind='MemberOf' AND source_node_id=? AND target_node_id=?",
        [admin, da_node],
    ).fetchone()[0]
    rev = con.execute(
        "SELECT count(*) FROM edge WHERE kind='MemberOf' AND source_node_id=? AND target_node_id=?",
        [da_node, admin],
    ).fetchone()[0]
    assert fwd == 1, "Administrator->Domain Admins MemberOf must exist"
    assert rev == 0, "reverse Domain Admins->Administrator MUST NOT exist"


@_needs_evidence
def test_live_effective_members_of_domain_admins(m4_live: _Live) -> None:
    """Proves: the effective members of Domain Admins are exactly
    {Administrator, ricksanchez} (the group->member spot check through the
    materialized closure)."""
    con = m4_live.con
    da = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", [f"{_DOMAIN_SID}-512"]
    ).fetchone()[0]
    sams = con.execute(
        "SELECT p.samaccountname FROM effective_membership em "
        "JOIN principal p ON p.node_id = em.member_node_id "
        "WHERE em.group_node_id = ?",
        [da],
    ).fetchall()
    got = {s[0] for s in sams}
    assert (
        got == _EXPECT_DA_MEMBERS
    ), f"Domain Admins effective members {got} != {_EXPECT_DA_MEMBERS}"  # noqa: E501


@_needs_evidence
def test_live_effective_members_of_everyone(m4_live: _Live) -> None:
    """Proves: the special-identity chain gives Everyone whole-domain reach — 12
    effective members (the documented transitive total)."""
    con = m4_live.con
    # Resolve the Everyone node via its SID in the principal table (the same stub
    # M3 materialized and M4 linked to) rather than recomputing the stub id.
    ev = con.execute("SELECT node_id FROM principal WHERE object_sid = 'S-1-1-0'").fetchone()
    assert ev is not None, "Everyone (S-1-1-0) stub principal not found"
    count = con.execute(
        "SELECT count(*) FROM effective_membership WHERE group_node_id = ?", [ev[0]]
    ).fetchone()[0]
    assert count == _EXPECT_EVERYONE_EFFECTIVE


@_needs_evidence
def test_live_administrator_primary_group_domain_users(m4_live: _Live) -> None:
    """Proves: Administrator's implicit Domain Users membership is surfaced as a
    SYNTH:primarygroup edge (the stealth path a link-only scan would miss)."""
    con = m4_live.con
    admin = _node_for_sam(con, "Administrator")
    du = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", [f"{_DOMAIN_SID}-513"]
    ).fetchone()
    assert du is not None, "Domain Users principal not found"
    hit = con.execute(
        "SELECT count(*) FROM edge WHERE kind='MemberOf' AND source_node_id=? "
        "AND target_node_id=? AND derivation='SYNTH:primarygroup'",
        [admin, du[0]],
    ).fetchone()[0]
    assert hit == 1, "Administrator must carry a SYNTH:primarygroup edge to Domain Users"


@_needs_evidence
def test_live_no_counted_gaps_on_clean_dit(m4_live: _Live) -> None:
    """Proves: the clean dev DIT surfaces NO M4 gaps — the counted-gap taxonomy is
    present but zero (nothing silently dropped, nothing spuriously skipped)."""
    skips = m4_live.result.skip_counts
    for key in (
        "membership.link_tombstoned",
        "membership.link_unresolved_endpoint",
        "membership.primarygroup_unresolved",
        "membership.specialidentity_unresolved",
        "membership.member_link_base_unresolved",
    ):
        assert skips.get(key, 0) == 0, f"unexpected M4 gap {key} = {skips.get(key)}"


# =============================================================================
# Layer 3 (live part) — rowcount integrity + PK uniqueness + no dangling edges
# =============================================================================


@_needs_evidence
def test_live_edge_rowcount_equals_emitted(m4_live: _Live) -> None:
    """Proves: the edge table holds exactly the emitted count (the writer wrote
    every row and only those; counts are not in-memory bookkeeping)."""
    con = m4_live.con
    rows = con.execute("SELECT count(*) FROM edge").fetchone()[0]
    assert rows == m4_live.result.edges_total == _EXPECT_TOTAL


@_needs_evidence
def test_live_edge_pk_unique(m4_live: _Live) -> None:
    """Proves: edge_id is a true PK — COUNT == COUNT DISTINCT (no duplicate edge
    rows survived the de-dup)."""
    con = m4_live.con
    total, distinct = con.execute("SELECT count(*), count(DISTINCT edge_id) FROM edge").fetchone()
    assert total == distinct


@_needs_evidence
def test_live_effective_pk_unique(m4_live: _Live) -> None:
    """Proves: (member_node_id, group_node_id) is unique in effective_membership
    and never reflexive (no row where member == group)."""
    con = m4_live.con
    total, distinct = con.execute(
        "SELECT count(*), count(DISTINCT (member_node_id, group_node_id)) FROM effective_membership"
    ).fetchone()
    assert total == distinct
    reflexive = con.execute(
        "SELECT count(*) FROM effective_membership WHERE member_node_id = group_node_id"
    ).fetchone()[0]
    assert reflexive == 0


@_needs_evidence
def test_live_no_dangling_edge_endpoints(m4_live: _Live) -> None:
    """Proves: every MemberOf edge endpoint is a real principal node (no dangling
    source/target survived the resolve) — endpoints exist in the principal table."""
    con = m4_live.con
    nodes = {r[0] for r in con.execute("SELECT node_id FROM principal").fetchall()}
    for src, tgt in con.execute("SELECT source_node_id, target_node_id FROM edge").fetchall():
        assert src in nodes, f"dangling edge source {src}"
        assert tgt in nodes, f"dangling edge target {tgt}"


# =============================================================================
# Layer 5 — frozen §4 edge row shape
# =============================================================================


@_needs_evidence
def test_live_edge_shape_matches_frozen(m4_live: _Live) -> None:
    """Proves: the §4 edge columns match the frozen contract and every MemberOf
    row has NULL access_mask/object_type_guid, is_inherited=False, a MemberOf kind,
    a derivation in the three allowed values, and a populated provenance struct
    with the scoping block."""
    con = m4_live.con
    cols = [r[0] for r in con.execute("DESCRIBE edge").fetchall()]
    assert cols == [
        "edge_id",
        "kind",
        "source_node_id",
        "target_node_id",
        "is_inherited",
        "derivation",
        "access_mask",
        "object_type_guid",
        "confidence",
        "forest_id",
        "domain_id",
        "domain_fqdn",
        "provenance",
    ]
    # MemberOf invariants across all rows.
    bad = con.execute(
        "SELECT count(*) FROM edge WHERE kind <> 'MemberOf' "
        "OR access_mask IS NOT NULL OR object_type_guid IS NOT NULL "
        "OR is_inherited <> FALSE"
    ).fetchone()[0]
    assert bad == 0
    derivs = {r[0] for r in con.execute("SELECT DISTINCT derivation FROM edge").fetchall()}
    assert derivs <= {"LINK:member", "SYNTH:primarygroup", "SYNTH:specialidentity"}
    # Scoping + provenance populated on a sample row.
    row = con.execute("SELECT forest_id, domain_id, provenance FROM edge LIMIT 1").fetchone()
    assert row[0] == FOREST and row[1] == _DOMAIN_SID
    prov = row[2]
    assert set(prov.keys()) == {
        "source_file",
        "image_sha256",
        "source_object_id",
        "directory_timestamp",
        "ingest_run_id",
    }


# =============================================================================
# Layer 4 — determinism (two full runs -> byte-identical rows)
# =============================================================================


@_needs_evidence
def test_determinism_two_full_runs_byte_identical() -> None:
    """Proves: two independent full 2a->M3->M4 runs of the SAME .dit under the SAME
    run_id produce byte-identical edge + effective_membership rows (the determinism
    guarantee — a non-deterministic write ordering would diverge)."""
    dumps: list[tuple[list[tuple], list[tuple]]] = []
    for _ in range(2):
        con = duckdb.connect(":memory:")
        _run_full_chain(con, _RUN)
        edges = con.execute("SELECT * FROM edge ORDER BY edge_id").fetchall()
        eff = con.execute(
            "SELECT * FROM effective_membership ORDER BY group_node_id, member_node_id"
        ).fetchall()
        dumps.append((edges, eff))
        con.close()
    assert dumps[0][0] == dumps[1][0], "edge rows differ across runs"
    assert dumps[0][1] == dumps[1][1], "effective_membership rows differ across runs"


# =============================================================================
# edge-table DDL smoke (no evidence)
# =============================================================================


def test_create_edge_tables_idempotent() -> None:
    """Proves: create_edge_tables creates both edge + effective_membership and is
    idempotent (safe for later edge modules to call again)."""
    con = duckdb.connect(":memory:")
    create_edge_tables(con)
    create_edge_tables(con)  # idempotent
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    assert {"edge", "effective_membership"} <= tables
    con.close()
