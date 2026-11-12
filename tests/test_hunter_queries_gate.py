"""Doc 20 GATE — the Threat-Hunter analysis query library (46 new catalog entries).

The authoritative gate for the additive hunter-analysis expansion (doc 20 on top
of the gated doc-15 catalog). Three layers:

This suite is pinned to the CORRECTED truth contract after the domain-expert found
5 defects (now fixed in production): (#1) AddSelf is INCLUDED in add-member; (#2)
Protected Users (-525) removed from the privileged union (standalone query kept);
(#3) controllers-of-tier0 / shadow-admins credit GenericWrite over a Tier-0
PRINCIPAL but NOT over the Domain object/containers; (#4) admincount-orphans is
stale USER residue minus privileged members minus krbtgt(-502)/Administrator(-500);
(#5) reset/write-SPN/shadow-cred are ACCOUNT-scoped (target must be a User/Computer).

* **Layer 1 — golden / synthetic.** Hand-built in-memory stores with KNOWN
  contents assert the corrected truth contract EXACTLY (doc 20 §4): the
  capability->edge-kind maps, that a looser-right-only / wrong-target-class holder
  is EXCLUDED (GenericWrite-only is not a password resetter; AllExtendedRights-only
  cannot WriteSPN; AddSelf INTO a priv group IS add-member but AddSelf into a
  non-priv target is not; GenericAll over a group/OU is not account control;
  GenericWrite over a Tier-0 user IS controllers-of-tier0 but over the domain object
  is NOT), that nested privileged-group membership is surfaced, and that every
  empty/absent branch is a NAMED counted gap (never silent, never a whole-forest
  expansion of an empty seed).
* **Layer 2 — INDEPENDENT re-derivation on real c137.** For every "who can X"
  query the holder set is re-derived straight from the edge/principal tables here in
  the test and compared to the query result EXACTLY, and the c137 oracle is pinned.
* **Layer 3 — property / robustness.** Determinism (same store -> identical
  output), read-only (store SHA-256 unchanged), bounded (a maxed run stays capped),
  and no plaintext-secret key in any response.

The c137 layer reuses the committed canonical store via ``WRAITH_GATE_PREBUILT_DB``
(the DIT is NOT rebuilt here — dissect is not importable in this environment and a
rebuild would thrash). It skips cleanly when no prebuilt store is provided.

CORRECTED independent c137 re-derivation (recomputed from the tables in this suite):
  reset-password 4 (was 12) · writespn 5 (was 14) · shadowcred 4 (was 13) ·
  controllers-of-domain 3 · controllers-of-tier0 3 · shadow-admins-tier0 0 ·
  add-member(->priv group) 4 (kind-set now incl. AddSelf) · controls-many(>=10) 8 ·
  admincount broad 14 · admincount-orphans 0 (was 10) · all-privileged union 5 (14
  suffixes, -525 removed) · Protected Users present/0 members (standalone) ·
  DnsAdmins present/0 members · -526/-527 (Key/Enterprise-Key Admins) absent ·
  trusts 0 · AllowedToAct 0 · AllowedToDelegate 0 · AdminTo 1 (Domain Admins -> the DC,
  from the DC host-SAM BUILTIN\\Administrators alias, M9/gate-09 ground truth — NOT 0) ·
  AddAllowedToAct 312 · 1 DC computer.
"""

from __future__ import annotations

import collections
import hashlib
import os
import time
from collections.abc import Iterator
from pathlib import Path

import duckdb
import pytest
from fastapi.testclient import TestClient

from wraith.api.app import create_app
from wraith.api.queries import (
    ACL_ADDMEMBER_PRIVGROUP,
    ACL_CONTROLLERS_OF_DOMAIN,
    ACL_CONTROLLERS_OF_TIER0,
    ACL_RESET_PASSWORD,
    ACL_SHADOWCRED,
    ACL_WRITESPN,
    ADD_MEMBER_KINDS,
    CATALOG,
    CONTROLS_MANY,
    CONTROLS_MANY_THRESHOLD,
    FULL_CONTROL_KINDS,
    RESET_PASSWORD_KINDS,
    SET_ADMIN_ON_DC,
    SET_ADMINCOUNT,
    SET_ADMINCOUNT_ORPHANS,
    SET_ALL_PRIVILEGED,
    SET_CONSTRAINED_DELEGATION,
    SET_DNSADMINS,
    SET_DOMAIN_ADMINS,
    SET_KEY_ADMINS,
    SET_PROTECTED_USERS,
    SET_RBCD_CONFIGURED,
    SET_RBCD_WRITABLE,
    SET_TRUSTS,
    SET_UNCONSTRAINED,
    SHADOW_CRED_KINDS,
    TRUST_KINDS,
    WRITE_SPN_KINDS,
    resolve_source_sets,
    run_query,
)
from wraith.api.store import StoreReader
from wraith.api.tiering import PRIVILEGED_GROUP_SID_SUFFIXES
from wraith.common.determinism import canonical_json
from wraith.model.store import create_canonical_tables, create_edge_tables

API = "/api/v1"

#: The 10 doc-15 (v1) catalog ids that predate the hunter library; everything else
#: in the catalog is a doc-20 addition (there must be exactly 46 of them).
_V1_IDS = frozenset(
    {
        "paths-to-tier0",
        "paths-from-kerberoastable",
        "paths-from-asrep",
        "paths-from-domain-users",
        "paths-to-unconstrained",
        "set-tier0",
        "set-dcsync",
        "set-kerberoastable",
        "set-asrep",
        "set-unconstrained",
    }
)

#: The exact set of out-of-scope entries the gate requires to be supported=False
#: (doc 20 §5.6/§5.7/§5.9): privileged-old-password, unsupported-os, FSP, owned,
#: trust-abuse, azure. NOTE: the three AD CS entries (set-enrollment-rights /
#: set-adcs-topology / paths-to-adcs-esc) are now supported=True (ESC pass is
#: pipeline-wired; doc 16 §D) and carry data_confidence='synthetic-only'.
_EXPECTED_UNSUPPORTED = frozenset(
    {
        "set-privileged-old-password",
        "set-unsupported-os",
        "set-foreign-security-principals",
        "paths-from-owned",
        "trust-abuse-paths",
        "azure-paths",
    }
)

#: The three AD CS queries are supported but synthetic-only (doc 16 §D): they run
#: (empty+counted on a non-ADCS store) and MUST be badged ``synthetic-only``.
_EXPECTED_SYNTHETIC_ONLY = frozenset(
    {"set-enrollment-rights", "set-adcs-topology", "paths-to-adcs-esc"}
)

_VALID_CATEGORIES = frozenset(
    {
        "Privileged Access",
        "Dangerous ACLs",
        "Shadow Admins",
        "Credential Exposure",
        "Delegation",
        "Stale/Risk",
        "Topology",
        "ADCS",
    }
)
_VALID_DATA_CONFIDENCE = frozenset({"real", "synthetic-only", "none"})


# ========================================================================= #
#  Synthetic-store helpers (golden fixtures with KNOWN contents)            #
# ========================================================================= #

_FOREST = "f"
_DOM = "S-1-5-21-10-20-30"
_RUN = "00000000-0000-0000-0000-000000000000"
_PROV = {
    "source_file": "ntds.dit",
    "image_sha256": "a" * 64,
    "source_object_id": None,
    "directory_timestamp": None,
    "ingest_run_id": _RUN,
}


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
            _FOREST,
            _DOM,
            "t.local",
            {**_PROV, "source_object_id": node},
        ],
    )


def _container(con: duckdb.DuckDBPyConnection, node: str, ctype: str, sid: str | None) -> None:
    con.execute(
        "INSERT INTO container (node_id,object_sid,distinguished_name,container_type,"
        "forest_id,domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?)",
        [node, sid, node, ctype, _FOREST, _DOM, "t.local", {**_PROV, "source_object_id": node}],
    )


def _edge(con: duckdb.DuckDBPyConnection, kind: str, src: str, tgt: str) -> None:
    con.execute(
        "INSERT INTO edge (edge_id,kind,source_node_id,target_node_id,confidence,forest_id,"
        "domain_id,domain_fqdn,provenance) VALUES (?,?,?,?,?,?,?,?,?)",
        [f"{kind}:{src}:{tgt}", kind, src, tgt, "confirmed", _FOREST, _DOM, "t.local", _PROV],
    )


def _effmem(con: duckdb.DuckDBPyConnection, member: str, group: str) -> None:
    con.execute(
        "INSERT INTO effective_membership (member_node_id,group_node_id,forest_id,domain_id) "
        "VALUES (?,?,?,?)",
        [member, group, _FOREST, _DOM],
    )


# ========================================================================= #
#  LAYER 1 — golden / synthetic truth-contract                              #
# ========================================================================= #


def test_truth_contract_acl_holder_kinds_exact() -> None:
    """A crafted DACL with KNOWN ACEs -> each "who can X" holder set is EXACTLY the
    corrected §4 kinds, ACCOUNT-SCOPED (DE defect #5): reset/write-SPN/shadow-cred
    only count control over a User/Computer target (a password/SPN/keyCredentialLink
    exists only on an account), and a looser-right-only holder is EXCLUDED. All
    exclusions are load-bearing (the excluded principals/edges exist in the store)."""
    con, reader = _mem_store()
    try:
        _principal(con, "v", "S-1-5-21-10-20-30-1200", sam="victim")  # User account target
        _principal(con, "vg", "S-1-5-21-10-20-30-1300", ptype="Group", sam="vgroup")  # group
        _container(con, "vou", "OU", None)  # container target (no password/SPN)
        # one holder per edge kind, all pointing at the User-account victim.
        _edge(con, "ForceChangePassword", "fcp", "v")
        _edge(con, "AllExtendedRights", "aer", "v")
        _edge(con, "WriteSPN", "wspn", "v")
        _edge(con, "AddKeyCredentialLink", "akcl", "v")
        _edge(con, "GenericWrite", "gw", "v")
        _edge(con, "GenericAll", "ga", "v")
        # account-scope exclusion: GenericAll over a GROUP / an OU is NOT "can reset a
        # password / write an SPN / add a key credential".
        _edge(con, "GenericAll", "ga_grp", "vg")
        _edge(con, "GenericAll", "ga_ou", "vou")
        for i, n in enumerate(("fcp", "aer", "wspn", "akcl", "gw", "ga", "ga_grp", "ga_ou")):
            _principal(con, n, f"S-1-5-21-10-20-30-{1000 + i}", sam=n)

        sets = resolve_source_sets(reader)
        # reset = {ForceChangePassword, AllExtendedRights, GenericAll} — GenericWrite OUT.
        assert set(sets.reset_password_holders) == {"fcp", "aer", "ga"}
        assert "gw" not in sets.reset_password_holders  # load-bearing exclusion
        assert "wspn" not in sets.reset_password_holders
        # writespn = {WriteSPN, GenericWrite, GenericAll} — AllExtendedRights OUT.
        assert set(sets.write_spn_holders) == {"wspn", "gw", "ga"}
        assert "aer" not in sets.write_spn_holders  # load-bearing exclusion
        # shadowcred = {AddKeyCredentialLink, GenericWrite, GenericAll}.
        assert set(sets.shadow_cred_holders) == {"akcl", "gw", "ga"}
        assert "aer" not in sets.shadow_cred_holders
        assert "fcp" not in sets.shadow_cred_holders
        # ACCOUNT-SCOPE exclusion (DE defect #5): control over a group/OU is NOT a
        # password/SPN/key-credential capability.
        for holder in ("ga_grp", "ga_ou"):
            assert holder not in sets.reset_password_holders
            assert holder not in sets.write_spn_holders
            assert holder not in sets.shadow_cred_holders
    finally:
        con.close()


def test_truth_contract_controllers_and_addmember_targeted() -> None:
    """controllers-of-domain = FULL_CONTROL into the Domain object (GenericWrite NOT
    credited); add-member now INCLUDES AddSelf (DE defect #1): add-member =
    {AddMember,AddSelf,GenericWrite,GenericAll,WriteDacl} INTO a privileged group. An
    AddSelf-into-a-NON-priv target is still EXCLUDED."""
    con, reader = _mem_store()
    try:
        _container(con, "dom", "Domain", _DOM)  # the Domain root object (bare SID)
        _principal(con, "pg", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _principal(con, "nonpriv", "S-1-5-21-10-20-30-1300", ptype="Group", sam="HR")
        holders = (
            "cd_ga",
            "cd_wd",
            "cd_wo",
            "cd_own",
            "cd_gw",
            "am_add",
            "am_gw",
            "am_self",
            "am_self_nonpriv",
        )
        for i, n in enumerate(holders):
            _principal(con, n, f"S-1-5-21-10-20-30-{2000 + i}", sam=n)
        # controllers-of-domain: the four FULL_CONTROL kinds INTO the Domain object.
        _edge(con, "GenericAll", "cd_ga", "dom")
        _edge(con, "WriteDacl", "cd_wd", "dom")
        _edge(con, "WriteOwner", "cd_wo", "dom")
        _edge(con, "Owns", "cd_own", "dom")
        _edge(con, "GenericWrite", "cd_gw", "dom")  # GenericWrite is NOT full control
        # add-member INTO the privileged group — AddSelf now a DIRECT self-elevation.
        _edge(con, "AddMember", "am_add", "pg")
        _edge(con, "GenericWrite", "am_gw", "pg")
        _edge(con, "AddSelf", "am_self", "pg")  # AddSelf INTO a priv group -> INCLUDED
        _edge(con, "AddSelf", "am_self_nonpriv", "nonpriv")  # non-priv target -> excluded

        sets = resolve_source_sets(reader)
        assert set(sets.controllers_of_domain) == {"cd_ga", "cd_wd", "cd_wo", "cd_own"}
        assert "cd_gw" not in sets.controllers_of_domain  # GenericWrite on domain excluded
        # AddSelf is now INCLUDED (corrected contract, DE defect #1).
        assert set(sets.add_member_privgroup_holders) == {"am_add", "am_gw", "am_self"}
        assert "am_self" in sets.add_member_privgroup_holders  # load-bearing inclusion
        assert "am_self_nonpriv" not in sets.add_member_privgroup_holders  # non-priv target
    finally:
        con.close()


def test_truth_contract_controllers_of_tier0_writes() -> None:
    """controllers-of-tier0 (DE defect #3): GenericWrite over a Tier-0 PRINCIPAL
    (User/Computer/Group) IS credited, but GenericWrite over the Domain object is
    NOT (GenericWrite on the domain object is not DCSync). shadow-admins-tier0 is the
    same population minus Tier-0/privileged members."""
    con, reader = _mem_store()
    try:
        _container(con, "dom", "Domain", _DOM)  # Tier-0 by classification, a container
        _principal(con, "admin", "S-1-5-21-10-20-30-500", sam="Administrator")  # Tier-0 user
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        for i, n in enumerate(("gw_t0u", "gw_dom", "ga_da")):
            _principal(con, n, f"S-1-5-21-10-20-30-{3000 + i}", sam=n)
        _edge(con, "GenericWrite", "gw_t0u", "admin")  # GW over a Tier-0 user -> caught
        _edge(con, "GenericWrite", "gw_dom", "dom")  # GW over the domain object -> NOT credited
        _edge(con, "GenericAll", "ga_da", "da")  # full control over a Tier-0 group -> caught

        sets = resolve_source_sets(reader)
        assert "gw_t0u" in sets.controllers_of_tier0  # GenericWrite over Tier-0 user caught
        assert "ga_da" in sets.controllers_of_tier0
        assert "gw_dom" not in sets.controllers_of_tier0  # GenericWrite on domain NOT credited
        # shadow admins = that set minus Tier-0 itself minus privileged members; neither
        # gw_t0u nor ga_da is Tier-0/privileged, so both are shadow admins.
        assert {"gw_t0u", "ga_da"} <= set(sets.shadow_admins_tier0)
        assert "gw_dom" not in sets.shadow_admins_tier0
    finally:
        con.close()


def test_nested_privileged_membership_surfaced() -> None:
    """set-domain-admins surfaces a NESTED effective member of the -512 group.

    KNOWN closure: user ``deep`` is a member of ``mid`` which is a member of Domain
    Admins; the M4 ``effective_membership`` closure therefore carries (deep, DA) and
    (mid, DA). The query must surface ``deep`` (nested) in its slice, and its
    source_count must equal the effective-member count (nested, NOT the 1 direct)."""
    con, reader = _mem_store()
    try:
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        _principal(con, "mid", "S-1-5-21-10-20-30-1400", ptype="Group", sam="mid")
        _principal(con, "deep", "S-1-5-21-10-20-30-1401", sam="deep")
        _principal(con, "direct", "S-1-5-21-10-20-30-1402", sam="direct")
        _edge(con, "MemberOf", "mid", "da")
        _edge(con, "MemberOf", "deep", "mid")
        _edge(con, "MemberOf", "direct", "da")
        # the M4 transitive closure (what effective_members_of reads).
        _effmem(con, "mid", "da")
        _effmem(con, "deep", "da")  # NESTED member, reachable only through mid
        _effmem(con, "direct", "da")
        _effmem(con, "deep", "mid")

        sets = resolve_source_sets(reader)
        members = set(sets.privileged_members_by_suffix["-512"])
        assert members == {"mid", "deep", "direct"}
        assert "deep" in members  # the nested member is present by construction

        res = run_query(reader, SET_DOMAIN_ADMINS, max_hops=8, max_paths=25)
        assert res.kind == "set" and res.slice is not None
        node_ids = {n.node_id for n in res.slice.nodes}
        assert "deep" in node_ids  # nested member surfaced in the slice
        assert "da" in node_ids
        assert res.counted_gaps == {}
    finally:
        con.close()


def test_privileged_group_empty_and_absent_gaps() -> None:
    """Group present with 0 effective members -> empty_source_set, group still in the
    slice; a group whose RID is absent (no -526 node) -> privileged_group_absent,
    never a silent empty answer."""
    con, reader = _mem_store()
    try:
        # Domain Admins present but with NO members.
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        res = run_query(reader, SET_DOMAIN_ADMINS, max_hops=8, max_paths=25)
        assert res.counted_gaps == {"empty_source_set": 1}
        assert res.slice is not None
        assert "da" in {n.node_id for n in res.slice.nodes}  # group still present

        # Key Admins (-526) group does NOT exist in this store.
        res2 = run_query(reader, SET_KEY_ADMINS, max_hops=8, max_paths=25)
        assert res2.counted_gaps == {"privileged_group_absent": 1}
        assert res2.slice is not None and res2.slice.nodes == []
    finally:
        con.close()


def test_dnsadmins_absent_counts_gap() -> None:
    """No DnsAdmins group (no fixed RID) -> dnsadmins_group_absent, empty slice."""
    con, reader = _mem_store()
    try:
        _principal(con, "da", "S-1-5-21-10-20-30-512", ptype="Group", sam="Domain Admins")
        res = run_query(reader, SET_DNSADMINS, max_hops=8, max_paths=25)
        assert res.counted_gaps == {"dnsadmins_group_absent": 1}
        assert res.slice is not None and res.slice.nodes == []
    finally:
        con.close()


def test_protected_users_resolves_standalone_but_not_in_union() -> None:
    """Protected Users (-525) was REMOVED from PRIVILEGED_GROUP_SID_SUFFIXES (DE
    defect #2) so it no longer inflates the privileged union / shadow-admin
    exclusion — yet its standalone hygiene query still resolves (NOT a gap) and
    surfaces its member."""
    con, reader = _mem_store()
    try:
        _principal(con, "pu", "S-1-5-21-10-20-30-525", ptype="Group", sam="Protected Users")
        _principal(con, "puser", "S-1-5-21-10-20-30-1700", sam="puser")
        _edge(con, "MemberOf", "puser", "pu")
        _effmem(con, "puser", "pu")

        # -525 is NOT in the frozen union suffix set.
        assert "-525" not in PRIVILEGED_GROUP_SID_SUFFIXES
        sets = resolve_source_sets(reader)
        # the standalone -525 query still resolves its (nested) membership ...
        assert set(sets.privileged_members_by_suffix["-525"]) == {"puser"}
        # ... but the Protected-Users member is NOT folded into the privileged union.
        assert "puser" not in sets.all_privileged_members

        res = run_query(reader, SET_PROTECTED_USERS, max_hops=8, max_paths=25)
        assert res.counted_gaps == {}  # present with a member -> NOT a gap
        assert "puser" in {n.node_id for n in (res.slice.nodes if res.slice else [])}
    finally:
        con.close()


def test_empty_set_queries_never_expand_to_whole_forest() -> None:
    """A set query whose defining set is empty returns an EMPTY slice + a counted gap
    (never build_slice's whole-forest expansion of an empty seed)."""
    con, reader = _mem_store()
    try:
        # a store with unrelated principals but no ACL/trust/delegation edges at all.
        for n in ("a", "b"):
            _principal(con, n, f"S-1-5-21-10-20-30-110{ord(n)}", sam=n)
        for qid, gap in (
            (ACL_RESET_PASSWORD, "empty_source_set"),
            (SET_CONSTRAINED_DELEGATION, "empty_source_set"),
            (SET_RBCD_WRITABLE, "empty_source_set"),
            (SET_TRUSTS, "no_trust_edges"),
        ):
            res = run_query(reader, qid, max_hops=8, max_paths=25)
            assert res.slice is not None, qid
            assert res.slice.nodes == [], (qid, "empty seed must NOT expand to the forest")
            assert res.slice.total_matched == 0, qid
            assert res.counted_gaps == {gap: 1}, (qid, res.counted_gaps)
    finally:
        con.close()


# ========================================================================= #
#  LAYER 2 — real c137 catalog integrity + INDEPENDENT re-derivation        #
# ========================================================================= #

_PREBUILT = os.environ.get("WRAITH_GATE_PREBUILT_DB")
_HAVE_C137 = bool(_PREBUILT and Path(_PREBUILT).is_file())
c137 = pytest.mark.skipif(not _HAVE_C137, reason="needs WRAITH_GATE_PREBUILT_DB c137 store")


@pytest.fixture(scope="module")
def db_path() -> Path:
    assert _PREBUILT is not None
    return Path(_PREBUILT)


@pytest.fixture(scope="module")
def reader(db_path: Path) -> Iterator[StoreReader]:
    r = StoreReader.open(db_path)
    try:
        yield r
    finally:
        r.close()


@pytest.fixture(scope="module")
def client(db_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(db_path)) as c:
        yield c


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _src_from_edges(
    reader: StoreReader, kinds: frozenset[str], target_in: set[str] | None = None
) -> set[str]:
    """INDEPENDENT re-derivation: distinct edge sources of ``kinds`` (optionally into
    ``target_in``), computed here in the test with a plain loop — NOT via the module
    under test — so a bug in the resolver cannot hide."""
    out: set[str] = set()
    for e in reader.all_edges():
        if e.kind not in kinds:
            continue
        if target_in is not None and e.target_node_id not in target_in:
            continue
        out.add(e.source_node_id)
    return out


def _run(client: TestClient, qid: str) -> dict[str, object]:
    r = client.post(f"{API}/analysis/queries/{qid}/run")
    assert r.status_code == 200, (qid, r.text)
    body: dict[str, object] = r.json()
    return body


def test_catalog_has_46_new_entries() -> None:
    """The hunter library adds EXACTLY 46 new entries over the 10 doc-15 queries."""
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids)), "catalog ids must be unique"
    new_ids = {i for i in ids if i not in _V1_IDS}
    assert len(new_ids) == 46, f"expected 46 doc-20 additions, got {len(new_ids)}"


@c137
def test_catalog_integrity_c137(client: TestClient) -> None:
    """GET lists every entry with a valid category/supported/data_confidence; the
    exact out-of-scope set is supported=False with a reason + source_count=None; the
    46 new entries are all present."""
    listed = client.get(f"{API}/analysis/queries").json()
    assert len(listed) == len(CATALOG)
    by_id = {q["id"]: q for q in listed}
    unsupported_ids = set()
    for q in listed:
        assert q["category"] in _VALID_CATEGORIES, q["id"]
        assert isinstance(q["supported"], bool), q["id"]
        assert q["data_confidence"] in _VALID_DATA_CONFIDENCE, q["id"]
        assert q["kind"] in ("path", "set"), q["id"]
        if not q["supported"]:
            unsupported_ids.add(q["id"])
            assert q["reason"], q["id"]
            assert q["source_count"] is None, q["id"]
    assert unsupported_ids == _EXPECTED_UNSUPPORTED
    # the three AD CS queries are supported but honestly badged synthetic-only (doc 16).
    for qid in _EXPECTED_SYNTHETIC_ONLY:
        assert by_id[qid]["supported"] is True, qid
        assert by_id[qid]["data_confidence"] == "synthetic-only", qid
    # the 46 new entries are all listed.
    assert {i for i in by_id if i not in _V1_IDS} == {s.id for s in CATALOG if s.id not in _V1_IDS}


@c137
def test_each_supported_query_returns_expected_kind(client: TestClient) -> None:
    """POST run for every SUPPORTED query returns path XOR slice (never both/neither);
    unsupported -> 422 (never a silent run)."""
    for spec in CATALOG:
        if not spec.supported:
            r = client.post(f"{API}/analysis/queries/{spec.id}/run")
            assert r.status_code == 422, (spec.id, r.status_code)
            continue
        body = _run(client, spec.id)
        assert body["query_id"] == spec.id
        assert body["kind"] == spec.kind
        if spec.kind == "path":
            assert body["paths"] is not None and body["slice"] is None, spec.id
        else:
            assert body["slice"] is not None and body["paths"] is None, spec.id


@c137
def test_independent_rederivation_acl_holders(client: TestClient, reader: StoreReader) -> None:
    """THE key gate: re-derive each "who can X" holder set straight from the edge
    table and assert the query's live source_count equals it AND equals the pinned
    c137 oracle. Also prove the GenericWrite-only exclusion is load-bearing on c137."""
    listed = {q["id"]: q for q in client.get(f"{API}/analysis/queries").json()}
    t0 = reader.tier0_sets()
    domain_obj = set(t0.domain_object_ids)
    classified = set(t0.classified_ids)

    # ACCOUNT scope (corrected contract, DE defect #5): reset/write-SPN/shadow-cred
    # only count control over a User/Computer principal. Re-derived independently.
    account_set = {
        str(p["node_id"])
        for p in reader.principal_risk_inputs()
        if str(p["principal_type"]) in ("User", "Computer")
    }
    # Tier-0 PRINCIPAL ids (User/Computer/Group among the classified), independently.
    tier0_principal = {
        n.node_id
        for n in reader.nodes_by_ids(sorted(classified))
        if n.kind in ("User", "Computer", "Group")
    }
    # privileged-group ids (the add-member target anchor), re-derived independently.
    priv_group_ids: set[str] = set()
    for suf in PRIVILEGED_GROUP_SID_SUFFIXES:
        priv_group_ids.update(reader.tier0_node_ids((suf,)))

    reset = _src_from_edges(reader, RESET_PASSWORD_KINDS, account_set)
    wspn = _src_from_edges(reader, WRITE_SPN_KINDS, account_set)
    shadow = _src_from_edges(reader, SHADOW_CRED_KINDS, account_set)
    ctrl_dom = _src_from_edges(reader, FULL_CONTROL_KINDS, domain_obj)
    # controllers-of-tier0 = FULL into classified UNION (FULL|GenericWrite) into a
    # Tier-0 principal — NOT GenericWrite over the domain object/containers.
    ctrl_t0 = _src_from_edges(reader, FULL_CONTROL_KINDS, classified) | _src_from_edges(
        reader, FULL_CONTROL_KINDS | {"GenericWrite"}, tier0_principal
    )
    add_mem = _src_from_edges(reader, ADD_MEMBER_KINDS, priv_group_ids)

    # pinned CORRECTED c137 oracle (independent re-derivation, this suite's docstring).
    assert len(reset) == 4  # was 12 before the account-scope fix
    assert len(wspn) == 5  # was 14
    assert len(shadow) == 4  # was 13
    assert len(ctrl_dom) == 3  # unchanged
    assert len(ctrl_t0) == 3
    assert len(add_mem) == 4  # AddSelf added no new holder on c137, kind-set includes it
    # the corrected add-member kind-set DOES include AddSelf.
    assert "AddSelf" in ADD_MEMBER_KINDS

    # the query source_count matches the independent re-derivation EXACTLY.
    assert listed[ACL_RESET_PASSWORD]["source_count"] == len(reset)
    assert listed[ACL_WRITESPN]["source_count"] == len(wspn)
    assert listed[ACL_SHADOWCRED]["source_count"] == len(shadow)
    assert listed[ACL_CONTROLLERS_OF_DOMAIN]["source_count"] == len(ctrl_dom)
    assert listed[ACL_CONTROLLERS_OF_TIER0]["source_count"] == len(ctrl_t0)
    assert listed[ACL_ADDMEMBER_PRIVGROUP]["source_count"] == len(add_mem)

    # and the resolver's actual membership equals the re-derivation (not just counts).
    sets = resolve_source_sets(reader)
    assert set(sets.reset_password_holders) == reset
    assert set(sets.write_spn_holders) == wspn
    assert set(sets.shadow_cred_holders) == shadow
    assert set(sets.controllers_of_domain) == ctrl_dom
    assert set(sets.controllers_of_tier0) == ctrl_t0
    assert set(sets.add_member_privgroup_holders) == add_mem

    # load-bearing exclusion on real data: a GenericWrite-only source is NOT a reset
    # holder (c137 has at least one such principal).
    by_src: dict[str, set[str]] = collections.defaultdict(set)
    for e in reader.all_edges():
        by_src[e.source_node_id].add(e.kind)
    gw_only = {
        s for s, ks in by_src.items() if "GenericWrite" in ks and not (ks & RESET_PASSWORD_KINDS)
    }
    assert gw_only, "c137 must have a GenericWrite-only principal for the exclusion to bite"
    assert gw_only.isdisjoint(reset)


@c137
def test_privileged_group_membership_c137(client: TestClient, reader: StoreReader) -> None:
    """set-domain-admins == effective_members_of(-512); the all-privileged union == 5;
    absent RIDs (-526/-527) -> privileged_group_absent; present-but-empty -> counted."""
    # set-domain-admins == the -512 effective-member closure, independently read.
    da_members = set(reader.effective_members_of(reader.tier0_node_ids(("-512",))))
    sets = resolve_source_sets(reader)
    assert set(sets.privileged_members_by_suffix["-512"]) == da_members
    listed = {q["id"]: q for q in client.get(f"{API}/analysis/queries").json()}
    assert listed[SET_DOMAIN_ADMINS]["source_count"] == len(da_members)

    # corrected union suffix set: Protected Users (-525) removed (DE defect #2) -> 14.
    assert len(PRIVILEGED_GROUP_SID_SUFFIXES) == 14
    assert "-525" not in PRIVILEGED_GROUP_SID_SUFFIXES

    # union of all §7 privileged-group effective members (independent re-derivation).
    union: set[str] = set()
    absent_suffixes: list[str] = []
    for suf in PRIVILEGED_GROUP_SID_SUFFIXES:
        gids = reader.tier0_node_ids((suf,))
        if not gids:
            absent_suffixes.append(suf)
        union.update(reader.effective_members_of(gids))
    assert len(union) == 5
    assert listed[SET_ALL_PRIVILEGED]["source_count"] == len(union)
    # -526 / -527 are absent on c137.
    assert "-526" in absent_suffixes and "-527" in absent_suffixes

    # the absent-RID query counts the gap; a present-but-empty one counts empty_source.
    res526 = run_query(reader, SET_KEY_ADMINS, max_hops=8, max_paths=25)
    assert res526.counted_gaps == {"privileged_group_absent": 1}
    assert res526.slice is not None and res526.slice.nodes == []

    # Protected Users (-525) still resolves STANDALONE (present on c137 with 0 members
    # -> present-but-empty counted gap, NOT privileged_group_absent, NOT a silent run).
    pu_gids = reader.tier0_node_ids(("-525",))
    assert pu_gids, "c137 has a Protected Users (-525) group"
    res525 = run_query(reader, SET_PROTECTED_USERS, max_hops=8, max_paths=25)
    assert res525.counted_gaps == {"empty_source_set": 1}
    assert res525.slice is not None
    assert set(pu_gids) <= {n.node_id for n in res525.slice.nodes}  # group still present


@c137
def test_controls_many_and_admincount_c137(client: TestClient, reader: StoreReader) -> None:
    """controls-many(>=10), the broad admincount set, and admincount-ORPHANS re-derived
    independently match the query. Orphans is the CORRECTED (DE defect #4) population:
    adminCount USERS minus privileged members minus krbtgt(-502)/Administrator(-500)."""
    from wraith.api.risk import _control_counts

    _inb, outbound = _control_counts(reader.all_edges())
    cm = {n for n, controlled in outbound.items() if len(controlled) >= CONTROLS_MANY_THRESHOLD}
    assert len(cm) == 8

    prin = reader.principal_risk_inputs()
    admincount = {
        str(p["node_id"]) for p in prin if isinstance(p["admincount"], int) and p["admincount"]
    }
    assert len(admincount) == 14  # broad set unchanged

    # independent admincount-orphans re-derivation (the corrected contract).
    union: set[str] = set()
    for suf in PRIVILEGED_GROUP_SID_SUFFIXES:
        union.update(reader.effective_members_of(reader.tier0_node_ids((suf,))))
    orphans = {
        str(p["node_id"])
        for p in prin
        if isinstance(p["admincount"], int)
        and p["admincount"]
        and str(p["principal_type"]) == "User"
        and not (
            str(p["object_sid"] or "").endswith("-502")
            or str(p["object_sid"] or "").endswith("-500")
        )
        and str(p["node_id"]) not in union
    }
    assert len(orphans) == 0  # was 10 before the fix (operator groups / krbtgt excluded)

    sets = resolve_source_sets(reader)
    assert set(sets.controls_many) == cm
    assert set(sets.admincount_set) == admincount
    assert set(sets.admincount_orphans) == orphans
    listed = {q["id"]: q for q in client.get(f"{API}/analysis/queries").json()}
    assert listed[CONTROLS_MANY]["source_count"] == 8
    assert listed[SET_ADMINCOUNT]["source_count"] == 14
    assert listed[SET_ADMINCOUNT_ORPHANS]["source_count"] == 0


@c137
def test_counted_gaps_for_absent_topology_delegation(
    client: TestClient, reader: StoreReader
) -> None:
    """c137 has no trust / AllowedToAct / AllowedToDelegate edges, so those queries
    carry their NAMED gap (nothing silent). It DOES have exactly one AdminTo edge
    (ground truth, see below) and it is HOST-SAM-derived (``SAM:AdminTo``), NOT
    GPO-derived — so admin-on-dc surfaces that holder but honestly badges it
    ``synthetic-only`` and counts the ``admin_on_dc_synthetic_only`` gap (DE hunt-audit
    defect #2): a real capability is reported, but its synthetic-until-host-images
    origin is never dressed up as real SYSVOL provenance."""
    edges = reader.all_edges()
    assert sum(1 for e in edges if e.kind in TRUST_KINDS) == 0
    assert sum(1 for e in edges if e.kind == "AllowedToAct") == 0
    assert sum(1 for e in edges if e.kind == "AllowedToDelegate") == 0
    # GROUND TRUTH, not drift: c137 has exactly ONE AdminTo edge — Domain Admins (-512)
    # -> the DC computer (CITADEL-DC01$) — derived from the DC's host-SAM
    # Builtin\Aliases\00000220 (BUILTIN\Administrators) by M9 (gate 09). Gate 09
    # validated that C-blob on the real DC SAM: 2 members, RID-500 LOCAL (no edge) and
    # Domain Admins DOMAIN (this edge). The producer is correct; the earlier "AdminTo 0"
    # premise simply predated M9's SAM edges being present in the canonical store.
    admin_to = [e for e in edges if e.kind == "AdminTo"]
    assert len(admin_to) == 1

    assert _run(client, SET_TRUSTS)["counted_gaps"] == {"no_trust_edges": 1}
    assert _run(client, SET_RBCD_CONFIGURED)["counted_gaps"] == {"empty_source_set": 1}
    assert _run(client, SET_CONSTRAINED_DELEGATION)["counted_gaps"] == {"empty_source_set": 1}
    # c137 has exactly one DC computer, and the lone AdminTo edge lands on it, so
    # admin-on-dc is NOT no_domain_controller and NOT empty_source_set: it reports the
    # real holder (Domain Admins). But the edge is host-SAM-derived (SAM:AdminTo), not
    # GPO-derived, so the run honestly counts the synthetic-only gap (DE defect #2).
    sets = resolve_source_sets(reader)
    assert len(sets.dc_computer_ids) == 1
    assert admin_to[0].target_node_id in set(sets.dc_computer_ids)
    assert set(sets.admin_on_dc_holders) == {admin_to[0].source_node_id}
    assert admin_to[0].derivation == "SAM:AdminTo"
    assert sets.admin_on_dc_gpo_derived is False
    assert _run(client, SET_ADMIN_ON_DC)["counted_gaps"] == {"admin_on_dc_synthetic_only": 1}
    # the honest badge flips to synthetic-only (was "real"): no GPO-derived AdminTo->DC.
    listed = {q["id"]: q for q in client.get(f"{API}/analysis/queries").json()}
    assert listed[SET_ADMIN_ON_DC]["data_confidence"] == "synthetic-only"
    # RBCD-writable DOES have holders on c137 (AddAllowedToAct edges) -> no gap.
    assert _run(client, SET_RBCD_WRITABLE)["counted_gaps"] == {}


# ========================================================================= #
#  LAYER 3 — property / robustness (determinism, read-only, bounded, secret)#
# ========================================================================= #


@c137
def test_determinism_all_supported_queries(reader: StoreReader) -> None:
    """Same store, two runs of every supported query -> byte-identical output."""
    for spec in CATALOG:
        if not spec.supported:
            continue
        a = run_query(reader, spec.id, max_hops=8, max_paths=25)
        b = run_query(reader, spec.id, max_hops=8, max_paths=25)
        assert canonical_json(a.model_dump()) == canonical_json(b.model_dump()), spec.id


@c137
def test_bounded_and_timely(reader: StoreReader) -> None:
    """A maxed run of every supported query stays bounded and completes quickly."""
    start = time.time()
    for spec in CATALOG:
        if not spec.supported:
            continue
        res = run_query(reader, spec.id, max_hops=15, max_paths=500)
        if res.kind == "path":
            assert res.paths is not None and res.paths.paths_found <= 500
        else:
            assert res.slice is not None and res.slice.returned <= res.slice.total_matched + 0
            assert len(res.slice.nodes) == res.slice.returned
    assert time.time() - start < 60.0


@c137
def test_set_unconstrained_slice_has_no_base(reader: StoreReader) -> None:
    """A seeded SET query is a RESULT view, not a drill-in: canonical-only, no Base.

    Regression pin (owner 2026-10-29): on the real c137 store ``set-unconstrained``
    was filling ``returned`` with ``Base`` endpoints. A SET query must stay canonical
    (``expand_base_endpoints=False`` in ``emit()``), so NO rendered node is ``Base``
    and ``returned <= total_matched`` still holds.
    """
    res = run_query(reader, SET_UNCONSTRAINED, max_hops=8, max_paths=25)
    assert res.slice is not None
    assert all(n.kind != "Base" for n in res.slice.nodes)
    assert res.slice.returned <= res.slice.total_matched
    assert len(res.slice.nodes) == res.slice.returned


@c137
def test_store_read_only_sha256_unchanged(db_path: Path, client: TestClient) -> None:
    """Running the whole hunter surface never mutates the store (SHA-256 stable)."""
    before = _sha256(db_path)
    client.get(f"{API}/analysis/queries")
    for spec in CATALOG:
        if spec.supported:
            client.post(f"{API}/analysis/queries/{spec.id}/run")
    assert _sha256(db_path) == before


@c137
def test_no_secret_key_in_any_response(client: TestClient) -> None:
    """No hunter response serialises a plaintext-secret key (structural, key-based —
    benign labels like 'Allowed RODC Password Replication' must not false-positive)."""
    banned = {
        "plaintext",
        "nthash",
        "lmhash",
        "nt_hash",
        "lm_hash",
        "secret_value",
        "cleartext",
        "pek",
        "password",
    }

    def _keys(obj: object) -> set[str]:
        found: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                found.add(str(k).lower())
                found |= _keys(v)
        elif isinstance(obj, list):
            for item in obj:
                found |= _keys(item)
        return found

    payloads = [client.get(f"{API}/analysis/queries").json()]
    for qid in (
        ACL_RESET_PASSWORD,
        SET_DOMAIN_ADMINS,
        SET_ADMINCOUNT,
        ACL_CONTROLLERS_OF_DOMAIN,
        "paths-to-tier0",
    ):
        payloads.append(_run(client, qid))
    for payload in payloads:
        assert _keys(payload) & banned == set(), payload
