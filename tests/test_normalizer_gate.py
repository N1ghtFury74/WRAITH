"""Independent gate suite — Module 3 (the Object Normalizer).

Authored by ``wraith-tester`` (the gatekeeper). This is the AUTHORITATIVE gate;
it does NOT trust the coder's ``test_normalizer_sanity.py``. It drives the real
2a -> M3 pipeline and the real 2b -> M3 ``secret_refs`` join against the
(untrusted, gitignored) ``eviedence_test`` DC. Layers:

  * Layer 1 (unit/golden)   — the PURE decoders/classifiers/identity seam on
                              hand-built inputs with KNOWN expected output. No
                              evidence, no Impacket.
  * Layer 2 (golden/live)   — the full ``normalize`` against the real DC, pinning
                              the OBSERVED FACTS (identity, exact entity/staging
                              counts, gap taxonomy, Administrator/krbtgt rows,
                              gPLink resolution, domain head + DC OU).
  * Layer 3 (2b -> M3 join) — a REAL ``extract_secrets`` with the SAME forest_id,
                              its ``node_secret_refs`` passed into ``normalize``;
                              asserts Administrator & krbtgt Principals carry
                              their secret_refs BY COUNT + secret_id set, and that
                              M3's node_id == 2b's node_id. Values never touched.
  * Layer 4 (robustness)    — pure no-crash on junk, PK dedup, byte-identical
                              determinism (two runs), lossless attribute round-trip.
  * Layer 5 (no-leak)       — the recovered Administrator/krbtgt NT hashes appear
                              NOWHERE in any canonical/staging row or the run log.

CRITICAL: no recovered secret VALUE is ever printed, logged, or asserted on;
every secret assertion is on counts/ids/round-trips/substring-ABSENCE. Evidence
is read-only and never copied into the repo. Every evidence/Impacket test skips
cleanly when either is absent (CI-safe).
"""

from __future__ import annotations

import importlib.util
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from wraith.acquisition.hashing import sha256_file
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.common.determinism import stable_id
from wraith.normalize import (
    DirectoryIndex,
    IndexEntry,
    classify,
    decode_filetime,
    decode_trust_direction,
    decode_trust_sid_filtering,
    decode_trust_transitive,
    decode_trust_type,
    decode_uac_enabled,
    is_domain_specific_sid,
    node_id_for_sid,
    normalize,
    parse_gplink,
    resolve_forest_id,
    to_naive_utc,
)
from wraith.normalize.classify import EntityKind
from wraith.normalize.models import encode_raw_attributes
from wraith.parsing import compute_node_id, open_ntds

# --- anchors -----------------------------------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"

FOREST = "forest-c137"
_CASE = "GATE-M3"
_PASSPHRASE = b"gate-m3-throwaway-passphrase"
_RUN = UUID("00000000-0000-0000-0000-0000000000a3")
_RUN_B = UUID("00000000-0000-0000-0000-0000000000b3")

# Independently-established ground truth (from the 2a/2b structural gates + the
# Module-3 dev run documented in docs/modules/03-normalizer.md). Pinned here so a
# silent regression in classification/decode/scoping is caught, not waved through.
_DOMAIN_SID = "S-1-5-21-2232410529-1445159330-2725690660"
_DOMAIN_FQDN = "c137.local"
_ADMIN_DN = "CN=Administrator,CN=Users,DC=C137,DC=local"

_EXPECT_ENTITY = {"principal": 91, "container": 295, "gpo": 3, "trust": 0, "adcs": 1}
_EXPECT_PTYPE = {"Group": 77, "User": 12, "Computer": 2}
_EXPECT_STAGING = {"staging_object": 3833, "staging_link": 84}
_EXPECT_STUBS = 3
_EXPECT_SKIPS = {
    "normalizer.not_modeled": 3363,
    "normalizer.unclassified": 39,
    "normalizer.deleted_skipped": 44,
    "normalizer.no_identity": 1,
    "normalizer.orphan_parent": 1,
}

_impacket_present = importlib.util.find_spec("impacket") is not None
_evidence_present = _NTDS.is_file() and _SYSTEM.is_file()

_needs_evidence = pytest.mark.skipif(
    not _evidence_present, reason="needs eviedence_test NTDS + SYSTEM present"
)
_needs_secrets = pytest.mark.skipif(
    not (_impacket_present and _evidence_present),
    reason="2b->M3 join needs Impacket importable AND eviedence_test present",
)


# =============================================================================
# Layer 1 — PURE decoders / classifiers / identity (no evidence, no Impacket)
# =============================================================================


def test_decode_filetime_golden_epoch_and_sentinels() -> None:
    """Proves: FILETIME 100-ns ticks decode to the exact naive-UTC datetime (the
    1601->1970 constant 116444736000000000 == 1970-01-01), and unset/never/absent
    values degrade to None without raising."""
    assert decode_filetime(116444736000000000) == datetime(1970, 1, 1)
    # A constructed golden: build ticks from a known datetime, decode back exactly.
    known = datetime(2020, 9, 18, 13, 45, 30)
    ticks = int((known - datetime(1601, 1, 1)) / timedelta(microseconds=1)) * 10
    assert decode_filetime(ticks) == known
    assert decode_filetime(0) is None
    assert decode_filetime(-1) is None
    assert decode_filetime(0x7FFFFFFFFFFFFFFF) is None  # never/never-expires
    assert decode_filetime(None) is None


def test_decode_filetime_distinct_from_seconds_encoding() -> None:
    """Proves: decode_filetime treats its input as 100-ns ticks (NOT seconds) —
    1_000_000_000 seconds-worth of ticks is ~1601, not ~1633 — guarding the
    research item-2 'wrong by centuries' hazard."""
    one_billion_seconds_as_ticks = 1_000_000_000 * 10_000_000
    dt = decode_filetime(one_billion_seconds_as_ticks)
    assert dt is not None and dt.year == 1632  # 1601 + ~31.7y, not 1970+


def test_to_naive_utc_strips_tz_deterministically() -> None:
    """Proves: a tz-aware UTC datetime is converted to naive UTC; a naive value is
    unchanged; None stays None (canonical rows are naive-UTC)."""
    aware = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert to_naive_utc(aware) == datetime(2020, 1, 2, 3, 4, 5)
    assert to_naive_utc(aware).tzinfo is None
    naive = datetime(2021, 6, 7, 8, 9, 10)
    assert to_naive_utc(naive) == naive
    assert to_naive_utc(None) is None


def test_decode_uac_enabled_flags() -> None:
    """Proves: ACCOUNTDISABLE (0x2) -> disabled; a normal account (0x200) ->
    enabled; krbtgt-style 514 (0x202) -> disabled; None -> None (unknown)."""
    assert decode_uac_enabled(0x200) is True
    assert decode_uac_enabled(0x0002) is False
    assert decode_uac_enabled(0x202) is False
    assert decode_uac_enabled(514) is False
    assert decode_uac_enabled(0) is True
    assert decode_uac_enabled(None) is None


def test_parse_gplink_flags_0_1_2_3_and_order() -> None:
    """Proves: each gPLink per-entry flag decodes correctly — 0 (none), 1
    (disabled), 2 (enforced), 3 (both) — in left-to-right link order, with the
    GPC cn GUID lowercased + brace-stripped."""
    raw = (
        "[LDAP://CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,"
        "DC=c137,DC=local;0]"
        "[LDAP://CN={22222222-2222-2222-2222-222222222222},CN=Policies;1]"
        "[LDAP://CN={33333333-3333-3333-3333-333333333333},CN=Policies;2]"
        "[LDAP://CN={44444444-4444-4444-4444-444444444444},CN=Policies;3]"
    )
    entries = parse_gplink(raw)
    assert [e.link_order for e in entries] == [0, 1, 2, 3]
    assert entries[0].gpo_cn_guid == "11111111-1111-1111-1111-111111111111"
    assert (entries[0].disabled, entries[0].enforced) == (False, False)
    assert (entries[1].disabled, entries[1].enforced) == (True, False)
    assert (entries[2].disabled, entries[2].enforced) == (False, True)
    assert (entries[3].disabled, entries[3].enforced) == (True, True)


def test_parse_gplink_empty_and_unparseable_entry_skipped() -> None:
    """Proves: a missing/blank value -> []; an entry whose DN has no CN={GUID} is
    skipped (counted by the caller), never crashes."""
    assert parse_gplink(None) == []
    assert parse_gplink("") == []
    only_bad = parse_gplink("[LDAP://OU=NoGuidHere,DC=c137,DC=local;0]")
    assert only_bad == []


def test_decode_trust_direction_enum() -> None:
    """Proves: trustDirection 0/1/2/3 -> disabled/inbound/outbound/bidirectional;
    unknown or absent -> None."""
    assert decode_trust_direction(0) == "disabled"
    assert decode_trust_direction(1) == "inbound"
    assert decode_trust_direction(2) == "outbound"
    assert decode_trust_direction(3) == "bidirectional"
    assert decode_trust_direction(9) is None
    assert decode_trust_direction(None) is None


def test_decode_trust_type_precedence() -> None:
    """Proves: trustType MIT(3) -> realm; FOREST_TRANSITIVE(0x8) -> forest;
    WITHIN_FOREST(0x20) -> parent-child; otherwise external; both absent -> None."""
    assert decode_trust_type(3, 0) == "realm"
    assert decode_trust_type(2, 0x8) == "forest"
    assert decode_trust_type(2, 0x20) == "parent-child"
    assert decode_trust_type(2, 0) == "external"
    assert decode_trust_type(None, None) is None


def test_decode_trust_transitive_and_sid_filtering_bits() -> None:
    """Proves: NON_TRANSITIVE(0x1) -> transitive False (else True);
    QUARANTINED_DOMAIN(0x4) -> sid_filtering True (else False); absent -> None."""
    assert decode_trust_transitive(0x1) is False
    assert decode_trust_transitive(0x0) is True
    assert decode_trust_transitive(0x8) is True  # forest-transitive is transitive
    assert decode_trust_transitive(None) is None
    assert decode_trust_sid_filtering(0x4) is True
    assert decode_trust_sid_filtering(0x0) is False
    assert decode_trust_sid_filtering(0x8) is False
    assert decode_trust_sid_filtering(None) is None


# sAMAccountType public constants (MS-SAMR) used to drive classification.
_SAM_GROUP = 0x10000000
_SAM_ALIAS = 0x20000000
_SAM_USER = 0x30000000
_SAM_MACHINE = 0x30000001
_SAM_TRUST = 0x30000002


def test_classify_computer_before_user_sam_authoritative() -> None:
    """Proves: a machine sAMAccountType -> Computer even though 'user' is in the
    class chain (computer subclasses user — misorder would misfile every host)."""
    k = classify(["computer", "user", "person", "top"], "computer", _SAM_MACHINE, "CN=H,DC=c")
    assert k.entity is EntityKind.PRINCIPAL and k.principal_type == "Computer"


def test_classify_computer_before_user_class_fallback() -> None:
    """Proves: with NO sAMAccountType, class membership still types 'computer'
    before 'user' (the subclass-ordering guard in the fallback path)."""
    k = classify(["user", "computer", "person", "top"], "computer", None, None)
    assert k.principal_type == "Computer"


def test_classify_user_group_trust_fsp() -> None:
    """Proves: user/group/trust-account/alias/FSP each type correctly; a trust
    sAMAccountType is a User principal, an FSP is a Group stub flagged is_fsp."""
    assert classify(["user", "top"], "user", _SAM_USER, None).principal_type == "User"
    assert classify(["group", "top"], "group", _SAM_GROUP, None).principal_type == "Group"
    assert classify(["group", "top"], "group", _SAM_ALIAS, None).principal_type == "Group"
    assert classify(["user", "top"], "user", _SAM_TRUST, None).principal_type == "User"
    fsp = classify(["foreignSecurityPrincipal", "top"], "foreignSecurityPrincipal", None, None)
    assert fsp.entity is EntityKind.PRINCIPAL and fsp.is_fsp and fsp.principal_type == "Group"


def test_classify_containers_and_gpo_and_trust() -> None:
    """Proves: domainDNS -> Domain, organizationalUnit -> OU, container ->
    Container, groupPolicyContainer -> GPO, trustedDomain -> TRUST."""
    assert classify(["domainDNS", "top"], "domainDNS", None, None).container_type == "Domain"
    assert classify(["organizationalUnit"], "organizationalUnit", None, None).container_type == "OU"
    assert classify(["container"], "container", None, None).container_type == "Container"
    assert classify(["groupPolicyContainer"], "groupPolicyContainer", None, None).entity is (
        EntityKind.GPO
    )
    assert classify(["trustedDomain"], "trustedDomain", None, None).entity is EntityKind.TRUST


def test_classify_adcs_discriminants() -> None:
    """Proves: pKICertificateTemplate -> CertTemplate; pKIEnrollmentService ->
    EnterpriseCA; certificationAuthority discriminated by container DN into
    RootCA / NTAuthStore / AIACA."""
    assert classify(["pKICertificateTemplate"], "pKICertificateTemplate", None, None).adcs_type == (
        "CertTemplate"
    )
    assert classify(["pKIEnrollmentService"], "pKIEnrollmentService", None, None).adcs_type == (
        "EnterpriseCA"
    )
    ca = "certificationAuthority"
    assert classify([ca], ca, None, "CN=X,CN=Certification Authorities,DC=c").adcs_type == "RootCA"
    assert classify([ca], ca, None, "CN=X,CN=NTAuthCertificates,DC=c").adcs_type == "NTAuthStore"
    assert classify([ca], ca, None, "CN=X,CN=AIA,DC=c").adcs_type == "AIACA"


def test_classify_not_modeled_vs_unclassified() -> None:
    """Proves: a recognized infra class (displaySpecifier) -> counted not_modeled;
    an unrecognized class that looks like nothing -> unclassified (review signal),
    never silently dropped."""
    nm = classify(["displaySpecifier", "top"], "displaySpecifier", None, None)
    assert nm.entity is EntityKind.SKIP and nm.skip_reason == "not_modeled"
    uc = classify(["totallyMadeUpClass", "top"], "totallyMadeUpClass", None, None)
    assert uc.entity is EntityKind.SKIP and uc.skip_reason == "unclassified"


def test_node_id_for_sid_scoping_and_no_collision() -> None:
    """Proves: a domain-specific S-1-5-21 SID is GLOBALLY unique (same node across
    two domain_ids, == compute_node_id SID-fallback — the 2b invariant), while a
    BUILTIN S-1-5-32-544 SID is DOMAIN-SCOPED (distinct across two domain_ids) and
    never collides with a domain SID."""
    assert is_domain_specific_sid("S-1-5-21-1-2-3-500") is True
    assert is_domain_specific_sid("S-1-5-32-544") is False
    assert is_domain_specific_sid("garbage") is False

    dom_sid = f"{_DOMAIN_SID}-500"
    a = node_id_for_sid(FOREST, "dom-A", dom_sid)
    b = node_id_for_sid(FOREST, "dom-B", dom_sid)
    assert a == b == stable_id(FOREST, dom_sid) == compute_node_id(FOREST, None, dom_sid)

    wk_a = node_id_for_sid(FOREST, "dom-A", "S-1-5-32-544")
    wk_b = node_id_for_sid(FOREST, "dom-B", "S-1-5-32-544")
    assert wk_a != wk_b  # domain-scoped: no cross-domain collision
    assert wk_a == stable_id(FOREST, "dom-A", "S-1-5-32-544")
    assert len({a, wk_a, wk_b}) == 3  # domain SID and BUILTIN SIDs are all distinct


def test_resolve_forest_id_lookup_order() -> None:
    """Proves: an exact fqdn map hit wins; a NetBIOS leading-label hit next; a
    single-entry map is used as the single forest; else a deterministic SID
    derivation; and no-info raises ValueError (nothing to scope to)."""
    assert resolve_forest_id({"c137.local": "F1"}, "c137.local", _DOMAIN_SID) == "F1"
    assert resolve_forest_id({"C137": "F2"}, "c137.local", _DOMAIN_SID) == "F2"
    assert resolve_forest_id({"other": "F3"}, None, None) == "F3"  # single-entry
    assert resolve_forest_id({}, "x.local", _DOMAIN_SID) == stable_id("forest", _DOMAIN_SID)
    with pytest.raises(ValueError):
        resolve_forest_id({}, None, None)


def test_dn_reconstruction_and_parent_resolution() -> None:
    """Proves: DirectoryIndex rebuilds a DN from RDN + parent_dnt walk with the
    right prefixes (DC/OU/CN), derives the domain FQDN, resolves parent node ids,
    and flags a dangling parent as unresolved (orphan) while a top-level object is
    resolved."""
    idx = DirectoryIndex()
    idx.add(IndexEntry(1, None, "$ROOT_OBJECT$", frozenset({"top"}), "root", None, None))
    idx.add(IndexEntry(2, 1, "local", frozenset(), "n-local", None, None))
    idx.add(IndexEntry(3, 2, "C137", frozenset({"domainDNS", "domain"}), "n-dom", _DOMAIN_SID, "g"))
    idx.add(
        IndexEntry(
            4, 3, "Domain Controllers", frozenset({"organizationalUnit"}), "n-ou", None, "g2"
        )
    )
    idx.add(IndexEntry(5, 4, "DC01", frozenset({"computer"}), "n-dc", f"{_DOMAIN_SID}-1000", "g3"))
    idx.add(IndexEntry(99, 42, "Orphan", frozenset({"user"}), "n-orph", None, "g4"))
    assert idx.reconstruct_dn(5) == "CN=DC01,OU=Domain Controllers,DC=C137,DC=local"
    assert idx.domain_fqdn_for(3) == "c137.local"
    assert idx.parent_node_id(5) == "n-ou"
    assert idx.parent_resolved(3) is True  # parent is the NC-root sentinel chain
    assert idx.parent_resolved(99) is False  # parent_dnt 42 is dangling -> orphan


def test_pure_decoders_never_raise_on_junk() -> None:
    """Proves (robustness): every pure seam degrades gracefully on hostile input
    (huge/negative/None, empty strings) — a counted gap, never an exception."""
    assert decode_filetime(10**30) is None  # calendar overflow -> None
    assert decode_filetime(-(10**30)) is None
    assert classify([], None, None, None).entity is EntityKind.SKIP
    assert classify(["x"], None, 123456, "").entity is EntityKind.SKIP
    assert parse_gplink("[malformed") == []
    assert node_id_for_sid(FOREST, None, "S-1-5-32-544")  # domain_id None tolerated
    assert encode_raw_attributes({}) == "{}"


# =============================================================================
# Layer 4 (pure part) — lossless raw-attribute round-trip
# =============================================================================


def test_encode_raw_attributes_lossless_and_bytes_tagged() -> None:
    """Proves: encode_raw_attributes losslessly preserves bytes (as a
    {"__bytes_hex__": hex} tag), datetimes, nested lists/dicts, and scalars in a
    deterministic canonical JSON (so M5 can reconstruct RBCD/keyCredentialLink raw
    blobs), and the encoding is byte-identical across calls."""
    raw_bytes = bytes(range(16))
    attrs = {
        "nTSecurityDescriptor": raw_bytes,
        "whenChanged": datetime(2020, 9, 18, 1, 2, 3),
        "servicePrincipalName": ["HOST/a", "HOST/b"],
        "nested": {"inner": b"\xde\xad", "n": 7},
        "count": 42,
        "flag": True,
    }
    out = encode_raw_attributes(attrs)
    assert out == encode_raw_attributes(attrs)  # deterministic
    decoded = json.loads(out)
    assert decoded["nTSecurityDescriptor"] == {"__bytes_hex__": raw_bytes.hex()}
    assert bytes.fromhex(decoded["nTSecurityDescriptor"]["__bytes_hex__"]) == raw_bytes
    assert decoded["nested"]["inner"] == {"__bytes_hex__": "dead"}
    assert decoded["servicePrincipalName"] == ["HOST/a", "HOST/b"]
    assert decoded["count"] == 42 and decoded["flag"] is True
    assert decoded["whenChanged"] == {"__datetime__": "2020-09-18T01:02:03"}


# =============================================================================
# Live scaffolding (Layers 2, 3, 4-determinism, 5)
# =============================================================================


def _register(run: IngestRun) -> IngestRun:
    """Register ntds.dit (+ SYSTEM) on the run so provenance is mandatory-present."""
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref=str(_NTDS.resolve()),
            size_bytes=_NTDS.stat().st_size,
            image_sha256=sha256_file(_NTDS),
        )
    )
    if _SYSTEM.is_file():
        run.add_artifact(
            ArtifactInput(
                source_file="SYSTEM",
                abs_path_or_ref=str(_SYSTEM.resolve()),
                size_bytes=_SYSTEM.stat().st_size,
                image_sha256=sha256_file(_SYSTEM),
            )
        )
    return run


@dataclass
class _Norm:
    """A materialised live normalize (no secrets): result + open connection."""

    result: object
    con: duckdb.DuckDBPyConnection


@pytest.fixture(scope="module")
def norm_live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Norm]:
    """Parse the real .dit and normalize it (no secret_refs) into a throwaway
    in-memory canonical store. Shared read-only across the Layer-2 golden tests."""
    if not _evidence_present:  # pragma: no cover - CI guard
        pytest.skip("needs eviedence_test")
    con = duckdb.connect(":memory:")
    run = _register(IngestRun(_CASE, "wraith-tester", ingest_run_id=_RUN))
    with open_ntds(_NTDS, run) as parsed:
        result = normalize(parsed, run, con, forest_id=FOREST)
    yield _Norm(result=result, con=con)
    con.close()


# =============================================================================
# Layer 2 — golden against the real DC
# =============================================================================


@_needs_evidence
def test_live_identity(norm_live: _Norm) -> None:
    """Proves: the domainDNS identity resolves to the known domain SID, FQDN and
    the configured forest_id (scoping is correct)."""
    ident = norm_live.result.identity
    assert ident.domain_id == _DOMAIN_SID
    assert ident.domain_fqdn == _DOMAIN_FQDN
    assert ident.forest_id == FOREST


@_needs_evidence
def test_live_entity_counts_exact(norm_live: _Norm) -> None:
    """Proves: the exact per-table entity counts match the documented observed
    facts — a misclassified/dropped attack-relevant object would move these."""
    assert dict(norm_live.result.entity_counts) == _EXPECT_ENTITY


@_needs_evidence
def test_live_principal_type_counts_exact(norm_live: _Norm) -> None:
    """Proves: User/Computer/Group split (incl. the 3 well-known stubs) is exact."""
    assert dict(norm_live.result.principal_type_counts) == _EXPECT_PTYPE
    assert norm_live.result.wellknown_stub_count == _EXPECT_STUBS


@_needs_evidence
def test_live_staging_counts_exact(norm_live: _Norm) -> None:
    """Proves: staging_object/staging_link counts are exact, and the identity
    balance holds: staging_object + no_identity == total 2a objects."""
    assert dict(norm_live.result.staging_counts) == _EXPECT_STAGING
    skips = norm_live.result.skip_counts
    objects_parsed = norm_live.result.coverage_counts["ntds.objects_parsed"]
    assert _EXPECT_STAGING["staging_object"] + skips["normalizer.no_identity"] == objects_parsed


@_needs_evidence
def test_live_gap_taxonomy_exact(norm_live: _Norm) -> None:
    """Proves: every counted normalizer gap matches the observed taxonomy — gaps
    are surfaced, never silent, and the numbers have not drifted."""
    skips = norm_live.result.skip_counts
    for key, expected in _EXPECT_SKIPS.items():
        assert skips.get(key, 0) == expected, f"{key}: {skips.get(key, 0)} != {expected}"


@_needs_evidence
def test_live_table_rowcounts_match_result(norm_live: _Norm) -> None:
    """Proves: the DuckDB tables actually hold the rows the result claims (the
    writer wrote them; the counts are not just in-memory bookkeeping)."""
    con = norm_live.con
    for table, expected in {**_EXPECT_ENTITY, **_EXPECT_STAGING}.items():
        got = con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
        assert got == expected, f"{table}: {got} != {expected}"


@_needs_evidence
def test_live_pk_dedup_no_duplicate_node_ids(norm_live: _Norm) -> None:
    """Proves: every node table is deduped by node_id (COUNT == COUNT DISTINCT) —
    no duplicate canonical rows for one entity."""
    con = norm_live.con
    for table in ("principal", "container", "gpo", "adcs", "staging_object"):
        total, distinct = con.execute(
            f"SELECT count(*), count(DISTINCT node_id) FROM {table}"  # noqa: S608
        ).fetchone()
        assert total == distinct, f"{table}: {total} rows but {distinct} distinct node_id"


@_needs_evidence
def test_live_administrator_row(norm_live: _Norm) -> None:
    """Proves: Administrator is an enabled User with the exact reconstructed DN,
    its node_id == compute_node_id(forest, objectGUID), and its staging raw_sd is
    the documented 1356-byte self-relative SD (SD home for M5)."""
    con = norm_live.con
    row = con.execute(
        "SELECT node_id, principal_type, enabled, distinguished_name, object_guid, object_sid "
        "FROM principal WHERE samaccountname = 'Administrator'"
    ).fetchone()
    assert row is not None, "Administrator principal missing"
    node_id, ptype, enabled, dn, guid, sid = row
    assert ptype == "User"
    assert enabled is True
    assert dn == _ADMIN_DN
    assert node_id == compute_node_id(FOREST, guid, sid)
    raw_sd = con.execute(
        "SELECT raw_sd FROM staging_object WHERE node_id = ?", [node_id]
    ).fetchone()[0]
    assert raw_sd is not None and len(bytes(raw_sd)) == 1356


@_needs_evidence
def test_live_krbtgt_row(norm_live: _Norm) -> None:
    """Proves: krbtgt is a DISABLED User (uac 514) that carries at least one SPN —
    the KDC account is correctly typed and its account-state decoded."""
    con = norm_live.con
    row = con.execute(
        "SELECT principal_type, enabled, uac_flags, spns FROM principal "
        "WHERE samaccountname = 'krbtgt'"
    ).fetchone()
    assert row is not None, "krbtgt principal missing"
    ptype, enabled, uac, spns = row
    assert ptype == "User"
    assert enabled is False
    assert uac == 514
    assert spns and len(spns) >= 1


@_needs_evidence
def test_live_gplink_resolves_to_real_gpo_nodes(norm_live: _Norm) -> None:
    """Proves: at least one container's gPLink resolved (via the GPC cn-GUID map)
    to a node_id that is an actual row in the gpo table — the link is a real
    reference, not a dangling GUID."""
    con = norm_live.con
    gpo_nodes = {r[0] for r in con.execute("SELECT node_id FROM gpo").fetchall()}
    assert gpo_nodes, "no GPO nodes to link to"
    linked = con.execute(
        "SELECT node_id, gplinks FROM container WHERE length(gplinks) > 0"
    ).fetchall()
    assert linked, "no container carries a resolved gPLink"
    seen = 0
    for _node, gplinks in linked:
        for link in gplinks:
            assert link["gpo_node_id"] in gpo_nodes
            seen += 1
    assert seen >= 1


@_needs_evidence
def test_live_domain_head_and_dc_ou_present(norm_live: _Norm) -> None:
    """Proves: the domain head (container_type Domain) and the Domain Controllers
    OU both normalize — the core tree landmarks are present and correctly typed."""
    con = norm_live.con
    domains = con.execute(
        "SELECT count(*) FROM container WHERE container_type = 'Domain'"
    ).fetchone()[0]
    assert domains >= 1
    dc_ou = con.execute(
        "SELECT count(*) FROM container WHERE container_type = 'OU' "
        "AND distinguished_name ILIKE '%Domain Controllers%'"
    ).fetchone()[0]
    assert dc_ou >= 1


@_needs_evidence
def test_live_staging_attributes_json_parses_and_is_lossless(norm_live: _Norm) -> None:
    """Proves: a real staging_object.attributes column is valid JSON, re-encodes
    byte-identically (deterministic), and carries at least one bytes->hex tag
    (lossless binary preservation for M5)."""
    con = norm_live.con
    node_id = con.execute(
        "SELECT node_id FROM principal WHERE samaccountname = 'Administrator'"
    ).fetchone()[0]
    attrs_json = con.execute(
        "SELECT attributes FROM staging_object WHERE node_id = ?", [node_id]
    ).fetchone()[0]
    decoded = json.loads(attrs_json)
    assert isinstance(decoded, dict) and decoded
    assert encode_raw_attributes(decoded) == encode_raw_attributes(json.loads(attrs_json))

    # Binary attribute values arrive as single-element lists wrapping the bytes,
    # so the {"__bytes_hex__": ...} tag is nested — walk the structure for it.
    tags: list[str] = []

    def _walk(v: object) -> None:
        if isinstance(v, dict):
            if "__bytes_hex__" in v:
                tags.append(v["__bytes_hex__"])
            else:
                for inner in v.values():
                    _walk(inner)
        elif isinstance(v, list):
            for inner in v:
                _walk(inner)

    _walk(decoded)
    assert tags, "expected binary attributes (objectGUID/SID/...) preserved as hex"
    for hex_str in tags:
        bytes.fromhex(hex_str)  # every tag is valid, round-trippable hex


# =============================================================================
# Layer 4 — determinism (two full runs -> byte-identical canonical rows)
# =============================================================================

_ALL_TABLES = ("principal", "container", "gpo", "trust", "adcs", "staging_object", "staging_link")


def _dump(con: duckdb.DuckDBPyConnection, table: str, order: str) -> list[tuple]:
    return con.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()  # noqa: S608


@_needs_evidence
def test_determinism_two_runs_byte_identical() -> None:
    """Proves: two independent normalize runs of the SAME .dit under the SAME
    run_id produce byte-identical canonical + staging rows across every table
    (the determinism guarantee — identical inputs -> identical outputs)."""
    orders = {t: "node_id" for t in _ALL_TABLES}
    orders["staging_link"] = "link_base, source_node_id, target_node_id, link_dnt, backlink_dnt"

    dumps = []
    for _ in range(2):
        con = duckdb.connect(":memory:")
        run = _register(IngestRun(_CASE, "wraith-tester", ingest_run_id=_RUN))
        with open_ntds(_NTDS, run) as parsed:
            normalize(parsed, run, con, forest_id=FOREST)
        dumps.append({t: _dump(con, t, orders[t]) for t in _ALL_TABLES})
        con.close()

    for table in _ALL_TABLES:
        assert dumps[0][table] == dumps[1][table], f"{table} rows differ across runs"


# =============================================================================
# Layer 3 + 5 — REAL 2b -> M3 secret_refs join + no-leak
# =============================================================================


@dataclass
class _Secrets:
    """A materialised live extract+normalize with secrets joined + log capture."""

    con: duckdb.DuckDBPyConnection
    refs: object  # node_secret_refs: node_id -> (StoredSecretRef, ...)
    store: object
    dek: bytes
    guid_sid: dict[str, tuple[str, str]]  # sam -> (guid, sid)
    log_path: Path


@pytest.fixture(scope="module")
def norm_secrets(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Secrets]:
    """Run the REAL 2b extract_secrets (same forest_id) then normalize with its
    node_secret_refs, into a throwaway store. Captures the wraith log so a leak
    would be caught. Skips unless Impacket + evidence are both present."""
    if not (_impacket_present and _evidence_present):  # pragma: no cover - CI guard
        pytest.skip("2b->M3 join needs Impacket + eviedence_test")

    from wraith.parsing import ImpacketReadPath, extract_secrets
    from wraith.secrets import SecretStore, create_keyring, load_keyring, unwrap_dek, write_keyring

    ws = tmp_path_factory.mktemp("case-m3")
    (ws / "secrets").mkdir()
    (ws / "logs").mkdir()
    keyring_path = ws / "secrets" / "keyring.json"
    store_path = ws / "secrets" / "store.duckdb"
    log_path = ws / "logs" / "run.log"

    keyring, _d0 = create_keyring(_CASE, _PASSPHRASE)
    write_keyring(keyring_path, keyring)
    dek = unwrap_dek(load_keyring(keyring_path), _PASSPHRASE)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    wlog = logging.getLogger("wraith")
    prev_level = wlog.level
    wlog.setLevel(logging.DEBUG)
    wlog.addHandler(handler)

    store = SecretStore.open(store_path, _CASE)
    con = duckdb.connect(":memory:")
    run = _register(IngestRun(_CASE, "wraith-tester", ingest_run_id=_RUN_B))
    try:
        with open_ntds(_NTDS, run) as parsed:
            guid_sid = {
                o.sam_account_name: (o.object_guid, o.object_sid)
                for o in parsed.objects()
                if o.sam_account_name in ("Administrator", "krbtgt")
            }
            sec = extract_secrets(
                ntds_path=_NTDS,
                system_hive_path=_SYSTEM,
                parsed=parsed,
                store=store,
                dek=dek,
                run=run,
                forest_id=FOREST,
                read_path=ImpacketReadPath.DISSECT_SHIM,
            )
            normalize(parsed, run, con, forest_id=FOREST, node_secret_refs=sec.node_secret_refs)
    finally:
        handler.flush()
        handler.close()
        wlog.removeHandler(handler)
        wlog.setLevel(prev_level)

    yield _Secrets(
        con=con,
        refs=sec.node_secret_refs,
        store=store,
        dek=dek,
        guid_sid=guid_sid,
        log_path=log_path,
    )
    store.close()
    con.close()


@_needs_secrets
@pytest.mark.parametrize("sam", ["Administrator", "krbtgt"])
def test_2b_to_m3_secret_refs_join(norm_secrets: _Secrets, sam: str) -> None:
    """Proves (THE join): the Principal M3 minted for Administrator/krbtgt carries
    exactly the secret_refs 2b stored for it — matched BY COUNT and by secret_id
    SET — and M3's principal.node_id == 2b's node_id (same compute_node_id). This
    is the cross-module invariant; a broken join would orphan every secret."""
    guid, sid = norm_secrets.guid_sid[sam]
    assert guid is not None
    node = compute_node_id(FOREST, guid, sid)
    assert node is not None and node == stable_id(FOREST, guid)  # GUID-preferred

    twob_refs = norm_secrets.refs.get(node, ())
    twob_ids = {r.secret_id for r in twob_refs}
    assert len(twob_ids) >= 1, f"{sam} has no 2b secret refs to join"

    row = norm_secrets.con.execute(
        "SELECT node_id, secret_refs FROM principal WHERE samaccountname = ?", [sam]
    ).fetchone()
    assert row is not None, f"{sam} principal missing"
    m3_node, m3_refs = row
    assert m3_node == node, "M3 node_id must equal 2b node_id"
    m3_ids = {r["secret_id"] for r in m3_refs}
    assert len(m3_refs) == len(twob_refs)  # by count
    assert m3_ids == twob_ids  # same stored refs, joined by node_id


@_needs_secrets
def test_2b_to_m3_secret_ref_struct_shape_is_reference_only(norm_secrets: _Secrets) -> None:
    """Proves: each attached secret_ref is a reference struct only
    (secret_id/secret_type/label/decrypted/decryptable_offline) — no payload/plaintext
    field is present on the canonical row."""
    guid, sid = norm_secrets.guid_sid["Administrator"]
    node = compute_node_id(FOREST, guid, sid)
    refs = norm_secrets.con.execute(
        "SELECT secret_refs FROM principal WHERE node_id = ?", [node]
    ).fetchone()[0]
    assert refs
    for ref in refs:
        assert set(ref.keys()) == {
            "secret_id",
            "secret_type",
            "label",
            "decrypted",
            "decryptable_offline",
        }


@_needs_secrets
def test_no_plaintext_leaks_into_canonical_or_staging_or_log(norm_secrets: _Secrets) -> None:
    """Proves (NO-LEAK): the recovered Administrator & krbtgt NT hashes appear
    NOWHERE — not in any principal/staging canonical row (refs, raw_sd, attributes)
    and not in the run log. Known bytes are held transiently and checked by
    substring-ABSENCE only; never printed."""
    from wraith.secrets import SecretType

    known: list[bytes] = []
    for sam in ("Administrator", "krbtgt"):
        guid, sid = norm_secrets.guid_sid[sam]
        node = compute_node_id(FOREST, guid, sid)
        for ref in norm_secrets.refs.get(node, ()):
            if ref.secret_type is SecretType.NT_HASH:
                revealed = norm_secrets.store.reveal(ref.secret_id, norm_secrets.dek)
                known.append(revealed.get_secret_value())
    assert known, "no known NT hashes to scan for"

    con = norm_secrets.con
    # Serialise every principal + staging_object row to raw bytes and scan.
    blobs: list[bytes] = []
    for (vals,) in [(r,) for r in con.execute("SELECT * FROM principal").fetchall()]:
        blobs.append(repr(vals).encode("utf-8", "surrogatepass"))
    for row in con.execute("SELECT attributes, raw_sd FROM staging_object").fetchall():
        attrs_json, raw_sd = row
        blobs.append(attrs_json.encode("utf-8"))
        if raw_sd is not None:
            blobs.append(bytes(raw_sd))
    haystack = b"".join(blobs)
    haystack_lower = haystack.lower()

    for value in known:
        assert value not in haystack
        assert value.hex().encode("ascii") not in haystack_lower

    log_bytes = norm_secrets.log_path.read_bytes()
    log_lower = log_bytes.lower()
    for value in known:
        assert value not in log_bytes
        assert value.hex().encode("ascii") not in log_lower
