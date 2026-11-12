"""Independent GATE suite — Module 5 (the Edge Engine, slices 5A + 5B).

Authored by ``wraith-tester`` (the gatekeeper). AUTHORITATIVE gate; does NOT trust
the coder's ``test_edge_engine_5a_sanity.py`` / ``test_edge_engine_5b_sanity.py``.
Every fixture and expected value here is re-derived independently.

The CTF DC (``eviedence_test/NTDS/ntds.dit``) has ZERO delegation / RBCD / gMSA /
SID-history / trusts / CertTemplates, so the whole 5B builder surface has NO
real-data coverage. This suite therefore builds crafted/synthetic fixtures for
EVERY 5B builder (constrained delegation, RBCD, gMSA, SID-history, trust,
ADCS enroll + PublishedTo, node flags) and additionally drives the 5B
orchestrator wiring end-to-end against a hand-built synthetic store.

Layers:
  1. 5A unit/golden on crafted SR_SECURITY_DESCRIPTOR bytes with KNOWN ACEs.
  2. 5B crafted fixtures — every non-SD builder (the untested-on-real-data core).
  3. property/robustness — malformed SD counted, mint scheme, dedup/mask-OR, PK.
  4. determinism — two full compute_edges runs byte-identical.
  5. 5A golden vs the real DC — pins the OBSERVED FACTS.
  6. 5B orchestrator end-to-end on a synthetic store (RBCD/trust/sidhistory wiring).

No secret value is ever read, asserted on, or printed. Evidence is read-only and
never copied into the repo; every evidence/real test skips cleanly when the
``.dit`` is absent (CI-safe).
"""

from __future__ import annotations

import uuid
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
    AccessMask,
    M5Result,
    NodeResolver,
    PkiFlagGuids,
    TrustInput,
    build_ace_edges,
    build_adcs_enrollment_edges,
    build_constrained_delegation_edges,
    build_dcsync_edge,
    build_gmsa_read_edges,
    build_owner_edge,
    build_published_to_edges,
    build_rbcd_edges,
    build_sid_history_edges,
    build_spn_index,
    build_trust_edges,
    classify_ace,
    classify_adcs_ace,
    compute_edges,
    compute_node_flags,
    is_asrep_roastable,
    is_kerberoastable,
    is_sid_filtered,
    is_unconstrained_delegation,
    is_within_forest,
    merge_mask,
    parse_sd,
    resolve_laps_guids,
    resolve_membership,
    resolve_pki_flag_guids,
    resolve_spn_target,
)
from wraith.edges.acl import _unsigned_mask
from wraith.edges.guid_map import (
    GUID_CERTIFICATE_AUTOENROLLMENT,
    GUID_CERTIFICATE_ENROLLMENT,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_GET_CHANGES,
    GUID_GPLINK,
    GUID_MEMBER,
    GUID_PUBLIC_INFORMATION,
)
from wraith.edges.models import EdgeRow
from wraith.edges.node_flags import is_coercible_unconstrained
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize import normalize
from wraith.normalize.identity import WELLKNOWN_SOURCE_FILE, node_id_for_sid
from wraith.parsing import open_ntds
from wraith.parsing.schema import AttributeDef, NtdsSchema
from wraith.provenance.models import ProvenanceStruct

# --- anchors -----------------------------------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"

FOREST = "forest-c137"
_CASE = "GATE-M5"
_RUN = UUID("00000000-0000-0000-0000-0000000000a5")

# Independently-established ground truth (confirmed by a tester dev run of the
# full 2a -> M3 -> M4 -> M5 chain against the real DC). Pinned so a silent
# regression in the edge engine is caught, not waved through.
_DOMAIN_SID = "S-1-5-21-2232410529-1445159330-2725690660"
_DOMAIN_FQDN = "c137.local"
_BUILTIN_ADMINS = "S-1-5-32-544"

_EXPECT_NON_MEMBEROF = 30263  # completion pass: +371 vs 29892 (= 369 Contains + 2 GPLink)
_EXPECT_EDGE_TOTAL = 30302  # incl. M4's 39 MemberOf (30263 + 39)
_EXPECT_OWNS = 3714
_EXPECT_DCSYNC = 3
# Completion-pass offline-derivable parity edges (re-derived vs the real DC).
_EXPECT_CONTAINS = 369  # 281 container-targets + 88 principal-targets (0 GPO/ADCS)
_EXPECT_CONTAINS_CONTAINER_TARGETS = 281
_EXPECT_CONTAINS_PRINCIPAL_TARGETS = 88
_EXPECT_GPLINK = 2
_EXPECT_COERCE_TO_TGT = 0  # lone unconstrained principal is the DC -> suppressed
_EXPECT_WRITE_GPLINK = 0
_EXPECT_WRITE_PUBLIC_INFORMATION = 0
_DCSYNC_HOLDERS = {
    _BUILTIN_ADMINS,  # explicit GetChanges + GetChangesAll ACEs on the domain head
    f"{_DOMAIN_SID}-512",  # Domain Admins — AllExtendedRights on domain head -> both repl rights
    f"{_DOMAIN_SID}-519",  # Enterprise Admins — same
}
_EXPECT_STUBS = 0
_EXPECT_UNCONSTRAINED = 1
_EXPECT_KERBEROASTABLE = 0
_EXPECT_ASREP = 0
_EXPECT_PER_KIND = {
    "AllExtendedRights": 6440,
    "GenericWrite": 6459,
    "WriteDacl": 6455,
    "WriteOwner": 6455,
    "GetChanges": 20,
    "GetChangesAll": 15,
    "WriteSPN": 4,
}
_EXPECT_GAPS = {
    "edges.deny_ace_skipped": 52,
    "edges.inherit_only_skipped": 5180,
    "edges.noise_trustee_skipped": 3850,
    "edges.unmapped_objecttype": 695,  # unchanged: no gP-Link/Public-Info scoped ACEs here
    "edges.sd_parse_error": 1,
    "edges.contains_parent_unresolved": 13,  # principals whose parent DN is a non-modeled container
}

_evidence_present = _NTDS.is_file()
_needs_evidence = pytest.mark.skipif(
    not _evidence_present, reason="needs eviedence_test NTDS ntds.dit present"
)

_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="b" * 64,
    source_object_id="node-obj:sd",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)
_SCOPING = (FOREST, _DOMAIN_SID, _DOMAIN_FQDN)
_UNMAPPED_GUID = "11111111-2222-3333-4444-555555555555"


# =============================================================================
# Crafted SR_SECURITY_DESCRIPTOR builder (hand-built bytes with KNOWN contents)
# =============================================================================


@dataclass(frozen=True)
class _Ace:
    """A crafted ACE spec: (allow?, object?, mask, trustee, object_type, flags)."""

    allow: bool
    mask: int
    trustee: str
    object_type: str | None = None
    inherited: bool = False
    inherit_only: bool = False


def _build_sd(aces: list[_Ace], owner: str | None = "S-1-5-21-1-2-3-500") -> bytes:
    """Hand-build a self-relative SD BLOB with the given owner + ACEs (impacket)."""
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_DENIED_OBJECT_ACE,
        ACCESS_MASK,
        ACE,
        ACL,
        LDAP_SID,
        SR_SECURITY_DESCRIPTOR,
    )

    def sid(s: str) -> LDAP_SID:
        v = LDAP_SID()
        v.fromCanonical(s)
        return v

    built: list[ACE] = []
    for spec in aces:
        ace = ACE()
        flags = 0
        if spec.inherited:
            flags |= ACE.INHERITED_ACE
        if spec.inherit_only:
            flags |= 0x08  # INHERIT_ONLY_ACE
        ace["AceFlags"] = flags
        if spec.object_type is not None:
            body_cls = ACCESS_ALLOWED_OBJECT_ACE if spec.allow else ACCESS_DENIED_OBJECT_ACE
            ace["AceType"] = body_cls.ACE_TYPE
            body = body_cls()
            body["Mask"] = ACCESS_MASK()
            body["Mask"]["Mask"] = spec.mask
            body["ObjectType"] = uuid.UUID(spec.object_type).bytes_le
            body["InheritedObjectType"] = b""
            body["Flags"] = body_cls.ACE_OBJECT_TYPE_PRESENT
            body["Sid"] = sid(spec.trustee)
        else:
            body_cls = ACCESS_ALLOWED_ACE if spec.allow else ACCESS_DENIED_ACE
            ace["AceType"] = body_cls.ACE_TYPE
            body = body_cls()
            body["Mask"] = ACCESS_MASK()
            body["Mask"]["Mask"] = spec.mask
            body["Sid"] = sid(spec.trustee)
        ace["Ace"] = body
        built.append(ace)

    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = built
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = sid(owner) if owner is not None else b""
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = acl
    return sd.getData()


def _resolver(
    sid_to_node: dict[str, str] | None = None, all_nodes: set[str] | None = None
) -> NodeResolver:
    return NodeResolver(
        forest_id=FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn=_DOMAIN_FQDN,
        sid_to_node=dict(sid_to_node or {}),
        all_nodes=set(all_nodes or set()),
        ingest_run_id=_RUN,
    )


# =============================================================================
# LAYER 1 — 5A unit/golden on crafted SDs (no evidence)
# =============================================================================


def test_classify_generic_all_dominates_suppresses_subrights() -> None:
    """Proves: GENERIC_ALL dominates — with WRITE_DACL/WRITE_OWNER/WRITE_PROP all
    set, ONLY GenericAll is emitted (the sub-rights it subsumes are suppressed, so
    the graph is not polluted with redundant edges)."""
    mask = int(
        AccessMask.GENERIC_ALL
        | AccessMask.WRITE_DACL
        | AccessMask.WRITE_OWNER
        | AccessMask.DS_WRITE_PROP
    )
    res = classify_ace(mask, None, frozenset())
    assert [f.kind for f in res.facts] == ["GenericAll"]
    assert res.unmapped_objecttype is False


def test_classify_write_dac_to_writedacl() -> None:
    """Proves: WRITE_DAC -> WriteDacl (whole-object, object-type independent)."""
    res = classify_ace(int(AccessMask.WRITE_DACL), None, frozenset())
    assert [f.kind for f in res.facts] == ["WriteDacl"]
    res2 = classify_ace(int(AccessMask.WRITE_OWNER), None, frozenset())
    assert [f.kind for f in res2.facts] == ["WriteOwner"]


def test_classify_member_write_and_self() -> None:
    """Proves: a member-GUID WRITE_PROP -> AddMember (scoped), and the same GUID
    with SELF -> AddSelf — distinct scoped kinds keyed by (mask-bit, GUID)."""
    wp = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_MEMBER, frozenset())
    assert [f.kind for f in wp.facts] == ["AddMember"] and wp.facts[0].scoped is True
    sf = classify_ace(int(AccessMask.DS_SELF), GUID_MEMBER, frozenset())
    assert [f.kind for f in sf.facts] == ["AddSelf"]


def test_classify_forcechangepassword_extended_right() -> None:
    """Proves: a CONTROL_ACCESS ACE scoped to the ForceChangePassword extended-right
    GUID -> ForceChangePassword (not AllExtendedRights — object-type gating)."""
    res = classify_ace(int(AccessMask.DS_CONTROL_ACCESS), GUID_FORCE_CHANGE_PASSWORD, frozenset())
    assert [f.kind for f in res.facts] == ["ForceChangePassword"]


def test_classify_write_gplink_and_public_information_mapped() -> None:
    """Proves (completion pass, classify level): a WRITE_PROP ACE scoped to the
    gP-Link attribute GUID -> WriteGPLink, and to the Public-Information
    property-set GUID -> WritePublicInformation — both SCOPED (carry the GUID),
    NOT a generic-write fallback. Real-DC count for both is 0 (no such ACEs on this
    DC), so this classify-level test is the ONLY coverage of the mapping; it must
    hold regardless of the evidence fixture."""
    gpl = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_GPLINK, frozenset())
    assert [f.kind for f in gpl.facts] == ["WriteGPLink"]
    assert gpl.facts[0].scoped is True and gpl.unmapped_objecttype is False
    pub = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_PUBLIC_INFORMATION, frozenset())
    assert [f.kind for f in pub.facts] == ["WritePublicInformation"]
    assert pub.facts[0].scoped is True and pub.unmapped_objecttype is False


def test_coercible_unconstrained_predicate_suppresses_dc() -> None:
    """Proves (completion pass, predicate level): the CoerceToTGT gate fires for a
    non-DC unconstrained host (TRUSTED_FOR_DELEGATION set, SERVER_TRUST_ACCOUNT
    clear) but is SUPPRESSED for a DC (both bits set) — even though the DC still
    counts as unconstrained for the node-flag tally. This is the exact mechanism by
    which the real DC's lone unconstrained principal yields 0 CoerceToTGT edges."""
    dc_uac = 0x80000 | 0x2000  # TRUSTED_FOR_DELEGATION + SERVER_TRUST_ACCOUNT
    assert is_unconstrained_delegation(dc_uac) is True  # still an unconstrained node
    assert is_coercible_unconstrained(dc_uac) is False  # but NOT a coercion edge
    non_dc = 0x80000  # unconstrained workstation/server, not a DC
    assert is_coercible_unconstrained(non_dc) is True
    assert is_coercible_unconstrained(None) is False


def test_classify_unmapped_scoped_guid_surfaced_not_fallback() -> None:
    """Proves: a scoped WRITE_PROP with an UNKNOWN ObjectType is flagged
    unmapped_objecttype and emits NO edge (never a generic-write false positive)."""
    res = classify_ace(int(AccessMask.DS_WRITE_PROP), _UNMAPPED_GUID, frozenset())
    assert res.facts == () and res.unmapped_objecttype is True


def test_classify_mask_bit31_roundtrips_unsigned() -> None:
    """Proves (schema v1.1): a mask with bit 31 (0x80000000, GENERIC_READ) set is
    stored UNSIGNED (a non-negative BIGINT value) and is lossless."""
    mask = 0x80000000 | int(AccessMask.WRITE_DACL)
    enc = _unsigned_mask(mask)
    assert enc >= 0  # stored unsigned — never a negative int32
    assert enc == mask
    # classify still reads the low bits correctly through the high bit.
    res = classify_ace(mask, None, frozenset())
    assert "WriteDacl" in {f.kind for f in res.facts}


def test_parse_sd_allow_only_deny_and_inherit_only_counted() -> None:
    """Proves (parse policy): ALLOW ACEs are kept; a DENY ACE is counted+skipped;
    an INHERIT_ONLY ACE is counted+skipped; the INHERITED flag maps to is_inherited;
    the owner SID is read; an ObjectType GUID decodes little-endian."""
    sd = _build_sd(
        [
            _Ace(
                True,
                int(AccessMask.DS_CONTROL_ACCESS),
                "S-1-5-21-1-2-3-512",
                GUID_GET_CHANGES,
                inherited=True,
            ),
            _Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-519"),
            _Ace(False, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-513"),  # DENY
            _Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-520", inherit_only=True),
        ]
    )
    parsed = parse_sd(sd)
    assert parsed is not None
    assert parsed.owner_sid == "S-1-5-21-1-2-3-500"
    assert parsed.had_dacl is True
    assert parsed.deny_skipped == 1
    assert parsed.inherit_only_skipped == 1
    assert len(parsed.aces) == 2
    gc = parsed.aces[0]
    assert gc.object_type_guid == GUID_GET_CHANGES and gc.is_inherited is True
    assert parsed.aces[1].object_type_guid is None and parsed.aces[1].is_inherited is False


def test_build_ace_edges_direction_and_scope() -> None:
    """Proves (the direction crux): source = trustee (right holder), target = the
    object; a scoped fact carries its ObjectType GUID, a whole-object fact NULLs it;
    the inherited flag propagates; the raw mask is stored (recoverable)."""
    sd = _build_sd(
        [
            _Ace(
                True,
                int(AccessMask.DS_WRITE_PROP),
                "S-1-5-21-1-2-3-1111",
                GUID_MEMBER,
                inherited=True,
            ),
            _Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-519"),
        ]
    )
    parsed = parse_sd(sd)
    assert parsed is not None
    r = _resolver(
        {"S-1-5-21-1-2-3-1111": "n-trustee", "S-1-5-21-1-2-3-519": "n-admins"},
        {"n-trustee", "n-admins", "n-obj"},
    )
    edges, gaps = build_ace_edges(
        parsed.aces, "n-obj", None, frozenset(), r, _PROV, FOREST, _DOMAIN_SID, _DOMAIN_FQDN
    )
    by_kind = {e.kind: e for e in edges}
    am = by_kind["AddMember"]
    assert am.source_node_id == "n-trustee" and am.target_node_id == "n-obj"
    assert am.object_type_guid == GUID_MEMBER and am.is_inherited is True
    assert (am.access_mask & 0xFFFFFFFF) == int(AccessMask.DS_WRITE_PROP)
    assert by_kind["GenericAll"].object_type_guid is None
    assert gaps.noise_trustee_skipped == 0 and gaps.unmapped_objecttype == 0


def test_build_ace_edges_deny_and_unmapped_counted_no_crash() -> None:
    """Proves (error paths degrade to counted gaps): a DENY ACE never emits; an
    unmapped-ObjectType scoped ACE is counted (unmapped_objecttype) and emits no
    edge; a noise trustee (S-1-5-18) is counted and skipped."""
    sd = _build_sd(
        [
            _Ace(True, int(AccessMask.DS_WRITE_PROP), "S-1-5-21-1-2-3-1111", _UNMAPPED_GUID),
            _Ace(False, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-513"),
            _Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-18"),  # noise trustee
        ]
    )
    parsed = parse_sd(sd)
    assert parsed is not None and parsed.deny_skipped == 1
    r = _resolver(all_nodes={"n-obj"})
    edges, gaps = build_ace_edges(
        parsed.aces, "n-obj", None, frozenset(), r, _PROV, FOREST, _DOMAIN_SID, _DOMAIN_FQDN
    )
    assert edges == []
    assert gaps.unmapped_objecttype == 1
    assert gaps.noise_trustee_skipped == 1


def test_owner_edge_skips_noise_and_self() -> None:
    """Proves: the Owns edge skips noise (S-1-5-18) and reflexive self-owners
    (owner SID == object SID) — returned as None for the caller to count."""
    r = _resolver(all_nodes={"n-obj"})
    assert build_owner_edge("S-1-5-18", "n-obj", None, r, _PROV, FOREST, "d", "fq") is None
    self_sid = "S-1-5-21-1-2-3-500"
    assert build_owner_edge(self_sid, "n-obj", self_sid, r, _PROV, FOREST, "d", "fq") is None
    # A real owner emits an Owns edge owner -> object.
    e = build_owner_edge(
        "S-1-5-21-1-2-3-519",
        "n-obj",
        "S-1-5-21-1-2-3-500",
        r,
        _PROV,
        FOREST,
        _DOMAIN_SID,
        _DOMAIN_FQDN,
    )
    assert e is not None and e.kind == "Owns" and e.target_node_id == "n-obj"
    assert e.derivation == "SD:Owner"


def test_dcsync_builder_edge_shape() -> None:
    """Proves: build_dcsync_edge emits one DCSync principal -> domain edge with
    the SYNTH:DCSync derivation and NULL mask/object-type (not an ACL grant)."""
    e = build_dcsync_edge("n-admins", "n-domain", _PROV, FOREST, _DOMAIN_SID, _DOMAIN_FQDN)
    assert e.kind == "DCSync" and e.derivation == "SYNTH:DCSync"
    assert e.source_node_id == "n-admins" and e.target_node_id == "n-domain"
    assert e.access_mask is None and e.object_type_guid is None
    assert e.edge_id == stable_id("DCSync", "n-admins", "n-domain", "SYNTH:DCSync")


def test_resolve_laps_guids_absent_present_and_unresolvable() -> None:
    """Proves: LAPS GUID resolution — absent attr -> empty/0 (no LAPS, not an
    error); present with a schemaIDGUID -> that GUID; present but no schemaIDGUID
    -> counted unresolvable."""

    def attr(name: str, guid: str | None) -> AttributeDef:
        return AttributeDef(
            internal_id=1,
            ldap_display_name=name,
            schema_id_guid=guid,
            msds_intid=None,
            column_name=None,
        )

    def schema(by_ldap: dict[str, AttributeDef]) -> NtdsSchema:
        return NtdsSchema(
            column_to_ldap={},
            ldap_to_column={},
            attributes_by_ldap=by_ldap,
            attributes_by_internal_id={},
            classes_by_ldap={},
            extended_rights_by_guid={},
            raw_attribute_records=(),
            raw_class_records=(),
            raw_right_records=(),
            skipped_schema_records=0,
            unmapped_columns=(),
        )

    guids, unresolvable = resolve_laps_guids(schema({}))
    assert guids == frozenset() and unresolvable == 0
    g, u = resolve_laps_guids(schema({"ms-Mcs-AdmPwd": attr("ms-Mcs-AdmPwd", "AAAA-GUID".lower())}))
    assert "aaaa-guid" in g and u == 0
    _g, u2 = resolve_laps_guids(schema({"msLAPS-Password": attr("msLAPS-Password", None)}))
    assert u2 == 1


# =============================================================================
# LAYER 2 — 5B crafted fixtures (NO real-data coverage; crafted here only)
# =============================================================================


def test_constrained_delegation_resolved_and_unresolved_counted() -> None:
    """Proves (AllowedToDelegate): a listed target SPN resolving (exact or host
    fallback) emits principal -> service-host; an unresolvable SPN is counted."""
    index = build_spn_index([("n-host", ["HOST/DC01.c137.local"])])
    assert resolve_spn_target("cifs/DC01.c137.local", index) == "n-host"  # host fallback
    res = build_constrained_delegation_edges(
        "n-src", ["cifs/DC01.c137.local", "http/missing.c137.local"], index, _PROV, _SCOPING
    )
    assert len(res.edges) == 1 and res.skipped == 1
    e = res.edges[0]
    assert e.kind == "AllowedToDelegate" and e.derivation == "ATTR:AllowedToDelegate"
    assert e.source_node_id == "n-src" and e.target_node_id == "n-host"


def test_rbcd_edges_per_allow_trustee() -> None:
    """Proves (AllowedToAct / RBCD): the attribute value IS an SD; each ALLOW
    trustee -> an AllowedToAct edge trustee -> computer."""
    sd = _build_sd([_Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-1104")], owner=None)
    r = _resolver({"S-1-5-21-1-2-3-1104": "n-svc"}, {"n-svc", "n-comp"})
    edges, failed = build_rbcd_edges("n-comp", sd, r, _PROV, _SCOPING)
    assert failed is False and len(edges) == 1
    e = edges[0]
    assert e.kind == "AllowedToAct" and e.derivation == "ATTR:RBCD"
    assert e.source_node_id == "n-svc" and e.target_node_id == "n-comp"


def test_gmsa_read_edges_per_allow_trustee() -> None:
    """Proves (ReadGMSAPassword): msDS-GroupMSAMembership is an SD; each ALLOW
    trustee -> a ReadGMSAPassword edge trustee -> gMSA."""
    sd = _build_sd([_Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-1104")], owner=None)
    r = _resolver({"S-1-5-21-1-2-3-1104": "n-svc"}, {"n-svc", "n-gmsa"})
    edges, failed = build_gmsa_read_edges("n-gmsa", sd, r, _PROV, _SCOPING)
    assert failed is False and len(edges) == 1
    assert edges[0].kind == "ReadGMSAPassword" and edges[0].derivation == "ATTR:gMSAMembership"
    assert edges[0].source_node_id == "n-svc" and edges[0].target_node_id == "n-gmsa"


def test_rbcd_malformed_sd_counted_no_crash() -> None:
    """Proves: a malformed RBCD attribute SD yields no edges and a counted failure
    flag (never a crash)."""
    r = _resolver(all_nodes={"n-comp"})
    edges, failed = build_rbcd_edges("n-comp", b"\x01\x00garbage", r, _PROV, _SCOPING)
    assert edges == [] and failed is True


def test_sid_history_edge_mints_foreign_sid() -> None:
    """Proves (HasSIDHistory): principal -> each historical SID node; a foreign SID
    with no object is minted (mint-on-miss) so the edge is never dangling."""
    r = _resolver(all_nodes={"n-user"})
    edges = build_sid_history_edges("n-user", ["S-1-5-21-9-9-9-500"], r, _PROV, _SCOPING)
    assert len(edges) == 1
    assert edges[0].kind == "HasSIDHistory" and edges[0].derivation == "ATTR:SIDHistory"
    assert edges[0].source_node_id == "n-user"
    assert len(r.minted) == 1
    assert r.minted[edges[0].target_node_id].object_sid == "S-1-5-21-9-9-9-500"


def _trust(direction: str, attrs: int, *, key: bool = False) -> TrustInput:
    return TrustInput(
        local_domain_node_id="n-domain",
        other_domain_sid="S-1-5-21-7-7-7",
        direction=direction,
        trust_attributes=attrs,
        has_trust_key=key,
        provenance=_PROV,
    )


def test_trust_within_forest_classification_and_sid_filter_predicates() -> None:
    """Proves: WITHIN_FOREST (0x20) -> SameForest; absence -> CrossForest; and
    QUARANTINED (0x04) drives is_sid_filtered."""
    assert is_within_forest(0x20) is True and is_within_forest(0x0) is False
    assert is_within_forest(None) is False
    assert is_sid_filtered(0x04) is True and is_sid_filtered(0x0) is False
    assert is_sid_filtered(None) is False


def test_trust_direction_inbound_outbound_bidirectional_disabled() -> None:
    """Proves (attack direction = trusted -> trusting, per [MS-ADTS] 6.1.6.7.12):
    inbound -> local->other; outbound -> other->local; bidirectional -> both;
    disabled -> none. SameForest vs CrossForest follows the raw trustAttributes bit.
    INBOUND means the local domain is TRUSTED by the partner (local is the trusted
    side), so the attack edge runs OUT of local; OUTBOUND is the reverse."""
    # inbound (local is TRUSTED by the partner) + within-forest -> SameForest,
    # attack edge local -> other.
    r = _resolver()
    inb, u = build_trust_edges(_trust("inbound", 0x20), r, _SCOPING)
    assert u == 0 and len(inb) == 1
    other = r.resolve_or_mint("S-1-5-21-7-7-7")
    assert inb[0].kind == "SameForestTrust"
    assert inb[0].source_node_id == "n-domain" and inb[0].target_node_id == other
    # outbound (local is TRUSTING) + external -> CrossForest, attack edge other -> local.
    r2 = _resolver()
    outb, _ = build_trust_edges(_trust("outbound", 0x0), r2, _SCOPING)
    other2 = r2.resolve_or_mint("S-1-5-21-7-7-7")
    assert outb[0].kind == "CrossForestTrust"
    assert outb[0].source_node_id == other2 and outb[0].target_node_id == "n-domain"
    # bidirectional -> two trust edges.
    bi, _ = build_trust_edges(_trust("bidirectional", 0x0), _resolver(), _SCOPING)
    assert [e.kind for e in bi].count("CrossForestTrust") == 2
    # disabled -> no edge.
    dis, _ = build_trust_edges(_trust("disabled", 0x0), _resolver(), _SCOPING)
    assert dis == []


def test_trust_has_trust_keys_when_key_present() -> None:
    """Proves: HasTrustKeys (local -> other, ATTR:TrustKeys) is emitted only when a
    trust-account key was recovered."""
    r = _resolver()
    edges, _ = build_trust_edges(_trust("outbound", 0x0, key=True), r, _SCOPING)
    hk = [e for e in edges if e.kind == "HasTrustKeys"]
    assert len(hk) == 1 and hk[0].derivation == "ATTR:TrustKeys"
    assert hk[0].source_node_id == "n-domain"
    none_key, _ = build_trust_edges(_trust("outbound", 0x0, key=False), _resolver(), _SCOPING)
    assert [e for e in none_key if e.kind == "HasTrustKeys"] == []


def test_trust_partner_sid_absent_counted() -> None:
    """Proves: a TDO with no partner SID produces no edge and a counted
    trust_partner_unresolved gap."""
    ti = TrustInput("n-domain", None, "outbound", 0x0, False, _PROV)
    edges, unresolved = build_trust_edges(ti, _resolver(), _SCOPING)
    assert edges == [] and unresolved == 1


def test_adcs_enroll_autoenroll_and_pki_flag_edges() -> None:
    """Proves (ADCS base facts): a CONTROL_ACCESS ACE on the Certificate-Enrollment
    GUID -> Enroll; on AutoEnrollment -> AutoEnroll; a WRITE_PROP on the resolved
    enrollment-flag schemaIDGUID -> WritePKIEnrollmentFlag — all trustee -> template."""
    pki_guid = "eeee1111-0000-0000-0000-000000000000"
    pki = PkiFlagGuids(enrollment_flag=pki_guid, name_flag=None)
    # classifier-level.
    assert [
        f.kind
        for f in classify_adcs_ace(
            int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_ENROLLMENT, pki
        ).facts
    ] == ["Enroll"]
    assert [
        f.kind
        for f in classify_adcs_ace(
            int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_AUTOENROLLMENT, pki
        ).facts
    ] == ["AutoEnroll"]
    assert [
        f.kind for f in classify_adcs_ace(int(AccessMask.DS_WRITE_PROP), pki_guid, pki).facts
    ] == ["WritePKIEnrollmentFlag"]
    # builder-level on a crafted CertTemplate SD.
    sd = _build_sd(
        [
            _Ace(
                True,
                int(AccessMask.DS_CONTROL_ACCESS),
                "S-1-5-21-1-2-3-1200",
                GUID_CERTIFICATE_ENROLLMENT,
            )
        ],
        owner=None,
    )
    r = _resolver({"S-1-5-21-1-2-3-1200": "n-ppl"}, {"n-ppl", "n-template"})
    edges, failed = build_adcs_enrollment_edges(
        "n-template", sd, pki, frozenset({"S-1-5-18"}), r, _PROV, _SCOPING
    )
    assert failed is False and len(edges) == 1
    assert edges[0].kind == "Enroll" and edges[0].target_node_id == "n-template"


def test_adcs_published_to_template_to_ca() -> None:
    """Proves (PublishedTo): a CA's published template name resolves (ci) to its
    CertTemplate node -> edge template -> CA; an unresolved name is counted."""
    mapping = {"webserver": "n-template"}
    edges, unresolved = build_published_to_edges(
        "n-ca", ["WebServer", "GhostTemplate"], mapping, _PROV, _SCOPING
    )
    assert len(edges) == 1 and unresolved == 1
    assert edges[0].kind == "PublishedTo" and edges[0].derivation == "ADCS:PublishedTo"
    assert edges[0].source_node_id == "n-template" and edges[0].target_node_id == "n-ca"


def test_resolve_pki_flag_guids_present_and_unresolvable() -> None:
    """Proves: the two PKI-flag attributes resolve from the schema like LAPS; a
    present attr with no schemaIDGUID is a counted unresolvable."""

    def attr(name: str, guid: str | None) -> AttributeDef:
        return AttributeDef(
            internal_id=1,
            ldap_display_name=name,
            schema_id_guid=guid,
            msds_intid=None,
            column_name=None,
        )

    def schema(by_ldap: dict[str, AttributeDef]) -> NtdsSchema:
        return NtdsSchema(
            column_to_ldap={},
            ldap_to_column={},
            attributes_by_ldap=by_ldap,
            attributes_by_internal_id={},
            classes_by_ldap={},
            extended_rights_by_guid={},
            raw_attribute_records=(),
            raw_class_records=(),
            raw_right_records=(),
            skipped_schema_records=0,
            unmapped_columns=(),
        )

    g, u = resolve_pki_flag_guids(
        schema({"msPKI-Enrollment-Flag": attr("msPKI-Enrollment-Flag", "dead-beef")})
    )
    assert g.enrollment_flag == "dead-beef" and g.name_flag is None and u == 0
    _g2, u2 = resolve_pki_flag_guids(
        schema({"msPKI-Certificate-Name-Flag": attr("msPKI-Certificate-Name-Flag", None)})
    )
    assert u2 == 1


def test_node_flags_crafted_principals() -> None:
    """Proves (node-flag predicates): unconstrained = UAC 0x80000; AS-REP =
    UAC 0x400000; kerberoastable = enabled User with an SPN, excluding krbtgt and
    non-User types and disabled accounts."""
    assert is_unconstrained_delegation(0x80000) is True
    assert is_unconstrained_delegation(0x200) is False
    assert is_unconstrained_delegation(None) is False
    assert is_asrep_roastable(0x400000) is True and is_asrep_roastable(0x0) is False
    assert is_kerberoastable("User", True, ["MSSQL/db"], "svc") is True
    assert is_kerberoastable("User", True, ["kadmin/x"], "krbtgt") is False  # krbtgt excluded
    assert is_kerberoastable("User", False, ["MSSQL/db"], "svc") is False  # disabled
    assert is_kerberoastable("Computer", True, ["HOST/x"], "c$") is False  # not a User
    assert is_kerberoastable("User", True, [], "svc") is False  # no SPN
    flags = compute_node_flags("User", 0x80000 | 0x400000, True, ["x/y"], "svc")
    assert flags.unconstrained_delegation and flags.asrep_roastable and flags.kerberoastable


# =============================================================================
# LAYER 3 — property / robustness (no evidence)
# =============================================================================


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\x01\x00\x04\x80garbage", b"\xff" * 8])
def test_parse_sd_malformed_returns_none_no_crash(raw: bytes) -> None:
    """Proves: a zero-byte / truncated / garbage SD never raises — it degrades to
    None (which the orchestrator counts as sd_parse_error)."""
    assert parse_sd(raw) is None


def test_mint_scheme_object_sid_first_not_naive_recompute() -> None:
    """Proves (mint-on-miss == M3's scheme): a SID already mapped to an existing
    node resolves to THAT node (object_sid-first), NOT a naive node_id_for_sid
    recompute; a miss mints exactly node_id_for_sid(...) with synthetic provenance."""
    weird = "real-object-node-not-sid-derived"
    sid = "S-1-5-21-1-2-3-500"
    r = _resolver({sid: weird}, {weird})
    assert r.resolve_or_mint(sid) == weird
    assert weird != node_id_for_sid(FOREST, _DOMAIN_SID, sid)  # proves not a recompute
    assert r.minted == {}
    # Miss -> mints exactly node_id_for_sid; dedups on repeat.
    miss_sid = "S-1-5-21-1-2-3-4242"
    n1 = r.resolve_or_mint(miss_sid)
    n2 = r.resolve_or_mint(miss_sid)
    assert n1 == n2 == node_id_for_sid(FOREST, _DOMAIN_SID, miss_sid)
    assert list(r.minted) == [n1]
    assert r.minted[n1].provenance.source_file == WELLKNOWN_SOURCE_FILE


def test_merge_mask_ors_unsigned_bits() -> None:
    """Proves (dedup mask-OR): two ACL edges with the same edge_id but different
    masks collapse to one row whose stored mask is the unsigned OR of both."""

    def acl_edge(mask: int) -> EdgeRow:
        return EdgeRow(
            edge_id="E",
            kind="GenericWrite",
            source_node_id="s",
            target_node_id="t",
            is_inherited=False,
            derivation="ACE:GenericWrite",
            access_mask=_unsigned_mask(mask),
            object_type_guid=None,
            confidence="confirmed",
            forest_id=FOREST,
            domain_id=_DOMAIN_SID,
            domain_fqdn=_DOMAIN_FQDN,
            provenance=_PROV,
        )

    merged = merge_mask(acl_edge(0x20), acl_edge(0x80000000))
    assert (merged.access_mask & 0xFFFFFFFF) == (0x20 | 0x80000000)


def test_edge_id_is_stable_id_and_derivation_sensitive() -> None:
    """Proves: edge_id == stable_id(kind, source, target, derivation) and is
    derivation-sensitive (GetChanges-ACE vs DCSync-synth on same pair are 2 rows)."""
    assert build_dcsync_edge("s", "t", _PROV, FOREST, _DOMAIN_SID, _DOMAIN_FQDN).edge_id == (
        stable_id("DCSync", "s", "t", "SYNTH:DCSync")
    )
    assert stable_id("GetChanges", "s", "t", "ACE:GetChanges") != stable_id(
        "DCSync", "s", "t", "SYNTH:DCSync"
    )


# =============================================================================
# Live scaffolding — the full 2a -> M3 -> M4 -> M5 chain against the real DC
# =============================================================================


def _register(run: IngestRun) -> IngestRun:
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
    result: M5Result
    con: duckdb.DuckDBPyConnection
    domain_id: str


def _run_full_chain(con: duckdb.DuckDBPyConnection, run_id: UUID) -> _Live:
    """Parse -> normalize -> M4 resolve_membership -> M5 compute_edges into `con`."""
    run = _register(IngestRun(_CASE, "wraith-tester", ingest_run_id=run_id))
    with open_ntds(_NTDS, run) as parsed:
        norm = normalize(parsed, run, con, forest_id=FOREST)
        ident = norm.identity
        resolve_membership(
            con,
            run,
            parsed.schema,
            forest_id=FOREST,
            domain_id=ident.domain_id,
            domain_fqdn=ident.domain_fqdn,
        )
        result = compute_edges(
            con,
            run,
            parsed.schema,
            forest_id=FOREST,
            domain_id=ident.domain_id,
            domain_fqdn=ident.domain_fqdn,
        )
    return _Live(result=result, con=con, domain_id=ident.domain_id)


@pytest.fixture(scope="module")
def m5_live() -> Iterator[_Live]:
    if not _evidence_present:  # pragma: no cover - CI guard
        pytest.skip("needs eviedence_test ntds.dit")
    con = duckdb.connect(":memory:")
    live = _run_full_chain(con, _RUN)
    yield live
    con.close()


# =============================================================================
# LAYER 5 — 5A golden vs the real DC (pins the OBSERVED FACTS)
# =============================================================================


@_needs_evidence
def test_live_identity_and_totals(m5_live: _Live) -> None:
    """Proves: the chain scopes to the M3-gated identity and writes exactly the
    observed totals — 30,263 non-MemberOf edges and 30,302 edge rows incl. M4's 39
    MemberOf (completion pass: +371 vs the pre-completion 29,892 = 369 Contains +
    2 GPLink)."""
    con = m5_live.con
    assert m5_live.domain_id == _DOMAIN_SID
    total = con.execute("SELECT count(*) FROM edge").fetchone()[0]
    non_mo = con.execute("SELECT count(*) FROM edge WHERE kind <> 'MemberOf'").fetchone()[0]
    assert non_mo == _EXPECT_NON_MEMBEROF
    assert total == _EXPECT_EDGE_TOTAL
    assert m5_live.result.edges_total == _EXPECT_NON_MEMBEROF  # M5 pass distinct


@_needs_evidence
def test_live_per_kind_counts_exact(m5_live: _Live) -> None:
    """Proves: the exact per-kind edge counts (AllExtendedRights 6440,
    GenericWrite 6459, WriteDacl/WriteOwner 6455, GetChanges 20, GetChangesAll 15,
    WriteSPN 4) and Owns 3714 — all UNCHANGED by the completion pass; a miscount in
    any builder would move these."""
    con = m5_live.con
    counts = dict(con.execute("SELECT kind, count(*) FROM edge GROUP BY kind").fetchall())
    for kind, expected in _EXPECT_PER_KIND.items():
        assert counts.get(kind, 0) == expected, f"{kind}: {counts.get(kind)} != {expected}"
    assert counts.get("Owns", 0) == _EXPECT_OWNS


@_needs_evidence
def test_live_dcsync_three_default_tier0_holders(m5_live: _Live) -> None:
    """Proves (the DCSync crux, corrected): the domain head has exactly THREE
    DCSync holders by default — BUILTIN\\Administrators (explicit GetChanges +
    GetChangesAll ACEs) plus Domain Admins (-512) and Enterprise Admins (-519),
    which hold AllExtendedRights on the domain object and so acquire BOTH
    replication rights (expanded the way BloodHound/SharpHound do). All three point
    at the domain; there is no reverse edge. Domain Controllers (-516), which has
    GetChangesAll but NOT GetChanges, is correctly NOT a holder. (The prior
    assertion of a single BUILTIN\\Administrators holder was a false negative:
    DA/EA do not inherit this via MemberOf — they hold the rights directly.)"""
    con = m5_live.con
    rows = con.execute(
        "SELECT p.object_sid, e.target_node_id FROM edge e "
        "JOIN principal p ON p.node_id = e.source_node_id WHERE e.kind = 'DCSync'"
    ).fetchall()
    assert len(rows) == _EXPECT_DCSYNC
    domain_node = con.execute(
        "SELECT node_id FROM container WHERE container_type='Domain' AND object_sid=?",
        [_DOMAIN_SID],
    ).fetchone()[0]
    holders = {sid for sid, _ in rows}
    assert holders == _DCSYNC_HOLDERS
    assert all(target == domain_node for _, target in rows)
    # Domain Controllers (-516) has GetChangesAll but not GetChanges -> not a holder.
    assert f"{_DOMAIN_SID}-516" not in holders
    # No reverse DCSync (domain -> anything).
    rev = con.execute(
        "SELECT count(*) FROM edge WHERE kind='DCSync' AND source_node_id=?", [domain_node]
    ).fetchone()[0]
    assert rev == 0


@_needs_evidence
def test_live_administrator_500_has_no_nonmemberof_outbound(m5_live: _Live) -> None:
    """Proves: the -500 Administrator USER has 0 non-MemberOf outbound edges (its
    power is via group membership, not a direct ACL grant) — guards against a
    spurious self/principal edge."""
    con = m5_live.con
    admin = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", [f"{_DOMAIN_SID}-500"]
    ).fetchone()
    assert admin is not None
    cnt = con.execute(
        "SELECT count(*) FROM edge WHERE source_node_id=? AND kind<>'MemberOf'", [admin[0]]
    ).fetchone()[0]
    assert cnt == 0


@_needs_evidence
def test_live_gap_taxonomy_exact(m5_live: _Live) -> None:
    """Proves: the counted-gap taxonomy matches the observed facts exactly
    (deny 52, inherit_only 5180, noise_trustee 3850, unmapped_objecttype 695,
    sd_parse_error 1) — nothing silently dropped, nothing spuriously skipped."""
    skips = m5_live.result.skip_counts
    for key, expected in _EXPECT_GAPS.items():
        assert skips.get(key, 0) == expected, f"{key}: {skips.get(key)} != {expected}"


@_needs_evidence
def test_live_zero_stubs_minted(m5_live: _Live) -> None:
    """Proves: 0 stub Principals are minted on this DC (every ACE trustee / owner
    resolves to a real or M3-stub node) — no dangling edge target, no over-mint."""
    assert m5_live.result.stubs_minted == _EXPECT_STUBS


@_needs_evidence
def test_live_node_flags_tally(m5_live: _Live) -> None:
    """Proves: node-flag tallies match the DC — 1 unconstrained-delegation
    (the DC computer account), 0 kerberoastable, 0 AS-REP."""
    nf = m5_live.result.node_flags
    assert nf.unconstrained_delegation == _EXPECT_UNCONSTRAINED
    assert nf.kerberoastable == _EXPECT_KERBEROASTABLE
    assert nf.asrep_roastable == _EXPECT_ASREP


@_needs_evidence
def test_live_edge_pk_unique_and_no_dangling(m5_live: _Live) -> None:
    """Proves: edge_id is a true PK (count == distinct) and every edge endpoint is
    a real principal/container node (no dangling source/target survived)."""
    con = m5_live.con
    total, distinct = con.execute("SELECT count(*), count(DISTINCT edge_id) FROM edge").fetchone()
    assert total == distinct
    # The node universe = every staged object (ACL edge targets) + every entity
    # table (principals incl. minted stubs, containers, GPOs, ADCS objects).
    nodes = {r[0] for r in con.execute("SELECT node_id FROM staging_object").fetchall()}
    nodes |= {r[0] for r in con.execute("SELECT node_id FROM principal").fetchall()}
    nodes |= {r[0] for r in con.execute("SELECT node_id FROM container").fetchall()}
    nodes |= {r[0] for r in con.execute("SELECT node_id FROM gpo").fetchall()}
    nodes |= {r[0] for r in con.execute("SELECT node_id FROM adcs").fetchall()}
    missing = con.execute("SELECT source_node_id, target_node_id FROM edge").fetchall()
    for src, tgt in missing:
        assert src in nodes, f"dangling source {src}"
        assert tgt in nodes, f"dangling target {tgt}"


@_needs_evidence
def test_live_acl_edge_shape(m5_live: _Live) -> None:
    """Proves (frozen §4 shape): ACL edges carry access_mask; whole-object kinds
    NULL object_type_guid while scoped kinds populate it; non-ACL kinds NULL both;
    every row is confidence='confirmed' with a populated provenance struct."""
    con = m5_live.con
    # Whole-object kinds never carry an object_type_guid.
    bad_whole = con.execute(
        "SELECT count(*) FROM edge WHERE kind IN "
        "('GenericAll','GenericWrite','WriteDacl','WriteOwner','AllExtendedRights') "
        "AND object_type_guid IS NOT NULL"
    ).fetchone()[0]
    assert bad_whole == 0
    # Scoped ACL kinds carry a GUID.
    scoped_null = con.execute(
        "SELECT count(*) FROM edge WHERE kind IN ('GetChanges','GetChangesAll','WriteSPN') "
        "AND object_type_guid IS NULL"
    ).fetchone()[0]
    assert scoped_null == 0
    # Non-ACL M5 kinds (Owns/DCSync) NULL mask + object_type.
    bad_nonacl = con.execute(
        "SELECT count(*) FROM edge WHERE kind IN ('Owns','DCSync') "
        "AND (access_mask IS NOT NULL OR object_type_guid IS NOT NULL)"
    ).fetchone()[0]
    assert bad_nonacl == 0
    unconf = con.execute(
        "SELECT count(*) FROM edge WHERE kind<>'MemberOf' AND confidence<>'confirmed'"
    ).fetchone()[0]
    assert unconf == 0
    prov = con.execute("SELECT provenance FROM edge WHERE kind='Owns' LIMIT 1").fetchone()[0]
    assert set(prov.keys()) == {
        "source_file",
        "image_sha256",
        "source_object_id",
        "directory_timestamp",
        "ingest_run_id",
    }


# =============================================================================
# LAYER 5b — completion-pass parity edges vs the real DC (Contains / GPLink /
# CoerceToTGT / WriteGPLink / WritePublicInformation)
# =============================================================================


@_needs_evidence
def test_live_contains_count_and_all_sources_are_containers(m5_live: _Live) -> None:
    """Proves (Contains): exactly 369 Contains edges; EVERY source is a row in the
    ``container`` table (the 'all sources are containers' invariant — a principal /
    GPO / ADCS object is never a Contains source); targets split 281 container +
    88 principal, with ZERO Contains edges aimed at a GPO or ADCS object (those
    carry no reconstructed DN in v1, the documented gap)."""
    con = m5_live.con
    total = con.execute("SELECT count(*) FROM edge WHERE kind='Contains'").fetchone()[0]
    assert total == _EXPECT_CONTAINS
    non_container_src = con.execute(
        "SELECT count(*) FROM edge WHERE kind='Contains' "
        "AND source_node_id NOT IN (SELECT node_id FROM container)"
    ).fetchone()[0]
    assert non_container_src == 0, "a Contains source is not a container"
    to_container = con.execute(
        "SELECT count(*) FROM edge WHERE kind='Contains' "
        "AND target_node_id IN (SELECT node_id FROM container)"
    ).fetchone()[0]
    to_principal = con.execute(
        "SELECT count(*) FROM edge WHERE kind='Contains' "
        "AND target_node_id IN (SELECT node_id FROM principal)"
    ).fetchone()[0]
    assert to_container == _EXPECT_CONTAINS_CONTAINER_TARGETS
    assert to_principal == _EXPECT_CONTAINS_PRINCIPAL_TARGETS
    assert to_container + to_principal == total  # no other target class
    to_gpo = con.execute(
        "SELECT count(*) FROM edge WHERE kind='Contains' "
        "AND target_node_id IN (SELECT node_id FROM gpo)"
    ).fetchone()[0]
    to_adcs = con.execute(
        "SELECT count(*) FROM edge WHERE kind='Contains' "
        "AND target_node_id IN (SELECT node_id FROM adcs)"
    ).fetchone()[0]
    assert to_gpo == 0 and to_adcs == 0


@_needs_evidence
def test_live_contains_reaches_contained_principal_ou_genericall(m5_live: _Live) -> None:
    """Proves (Contains attack relevance — requirement 3): principal containment,
    resolved via the M3-reconstructed distinguished_name + parent-DN lookup (since
    M3 persists parent_node_id only on the container table), does NOT drop
    attack-relevant containment. Spot-check: the 'Domain Controllers' OU Contains
    the DC computer PRINCIPAL (not just child containers); and at least one
    container that is itself the target of a GenericAll/Owns-class right Contains a
    principal — i.e. OU-level control still reaches the accounts inside it."""
    con = m5_live.con
    dc_ou = con.execute(
        "SELECT node_id FROM container "
        "WHERE lower(distinguished_name) LIKE 'ou=domain controllers,%' LIMIT 1"
    ).fetchone()
    assert dc_ou is not None, "Domain Controllers OU not found"
    dc_children = con.execute(
        "SELECT p.samaccountname FROM edge e JOIN principal p ON p.node_id = e.target_node_id "
        "WHERE e.kind='Contains' AND e.source_node_id = ?",
        [dc_ou[0]],
    ).fetchall()
    # The OU contains the DC computer account as a PRINCIPAL child (DN-resolved).
    assert any(sam and sam.upper().startswith("CITADEL-DC01") for (sam,) in dc_children)
    # A container that someone has container-takeover rights over AND that Contains
    # a principal => OU-level control reaches contained accounts (not missed).
    reaching = con.execute(
        "SELECT count(DISTINCT c.source_node_id) FROM edge c "
        "WHERE c.kind='Contains' "
        "AND c.target_node_id IN (SELECT node_id FROM principal) "
        "AND c.source_node_id IN (SELECT target_node_id FROM edge WHERE kind IN "
        "('GenericAll','GenericWrite','WriteDacl','WriteOwner','Owns'))"
    ).fetchone()[0]
    assert reaching > 0


@_needs_evidence
def test_live_gplink_two_verified_gpo_to_container(m5_live: _Live) -> None:
    """Proves (GPLink): exactly 2 edges, each GPO -> linked container in the
    CONFIRMED BloodHound direction; the two are 'Default Domain Policy' ->
    DC=C137,DC=local and 'Default Domain Controllers Policy' ->
    OU=Domain Controllers,DC=C137,DC=local. Every GPLink source is a GPO row and
    every target is a container row (direction crux)."""
    con = m5_live.con
    total = con.execute("SELECT count(*) FROM edge WHERE kind='GPLink'").fetchone()[0]
    assert total == _EXPECT_GPLINK
    wrong_dir = con.execute(
        "SELECT count(*) FROM edge WHERE kind='GPLink' "
        "AND (source_node_id NOT IN (SELECT node_id FROM gpo) "
        "OR target_node_id NOT IN (SELECT node_id FROM container))"
    ).fetchone()[0]
    assert wrong_dir == 0, "GPLink not strictly GPO -> container"
    pairs = con.execute(
        "SELECT g.display_name, c.distinguished_name FROM edge e "
        "JOIN gpo g ON g.node_id = e.source_node_id "
        "JOIN container c ON c.node_id = e.target_node_id WHERE e.kind='GPLink'"
    ).fetchall()
    normalized = {(name, dn.lower()) for name, dn in pairs}
    assert normalized == {
        ("Default Domain Policy", "dc=c137,dc=local"),
        ("Default Domain Controllers Policy", "ou=domain controllers,dc=c137,dc=local"),
    }


@_needs_evidence
def test_live_coerce_to_tgt_dc_self_suppressed(m5_live: _Live) -> None:
    """Proves (CoerceToTGT): 0 edges on this DC. The ONLY principal carrying
    TRUSTED_FOR_DELEGATION is the DC computer (CITADEL-DC01$), which also sets
    SERVER_TRUST_ACCOUNT (0x2000) and is therefore suppressed by
    ``is_coercible_unconstrained`` — so the node-flag tally still counts 1
    unconstrained principal while 0 CoerceToTGT edges are emitted (the DC-self
    suppression rationale, asserted end-to-end on real data)."""
    con = m5_live.con
    assert con.execute("SELECT count(*) FROM edge WHERE kind='CoerceToTGT'").fetchone()[0] == (
        _EXPECT_COERCE_TO_TGT
    )
    unconstrained = con.execute(
        "SELECT samaccountname, uac_flags FROM principal WHERE (uac_flags & 524288) <> 0"
    ).fetchall()
    assert len(unconstrained) == 1  # the lone unconstrained principal
    _sam, uac = unconstrained[0]
    assert is_unconstrained_delegation(uac) is True  # it IS unconstrained (node flag)
    assert is_coercible_unconstrained(uac) is False  # but a DC -> suppressed (no edge)
    # Node-flag tally still counts the DC as unconstrained (1), parity with BH.
    assert m5_live.result.node_flags.unconstrained_delegation == _EXPECT_UNCONSTRAINED


@_needs_evidence
def test_live_write_gplink_and_public_information_zero_here(m5_live: _Live) -> None:
    """Proves (WriteGPLink / WritePublicInformation): 0 of each on this DC (no
    WRITE_PROP ACEs scoped to the gP-Link / Public-Information GUIDs), AND the
    unmapped_objecttype gap is UNCHANGED at 695 — i.e. adding the two mappings did
    not reclassify anything on this fixture (the mapping is proven at classify
    level in ``test_classify_write_gplink_and_public_information_mapped``)."""
    con = m5_live.con
    counts = dict(con.execute("SELECT kind, count(*) FROM edge GROUP BY kind").fetchall())
    assert counts.get("WriteGPLink", 0) == _EXPECT_WRITE_GPLINK
    assert counts.get("WritePublicInformation", 0) == _EXPECT_WRITE_PUBLIC_INFORMATION
    assert m5_live.result.skip_counts.get("edges.unmapped_objecttype", 0) == 695


@_needs_evidence
def test_live_contains_parent_unresolved_gap(m5_live: _Live) -> None:
    """Proves (counted gap): 13 principals whose reconstructed parent DN resolves to
    a non-modeled container are counted as ``edges.contains_parent_unresolved`` —
    surfaced, not silently dropped (these are objects under system/not-modeled
    containers, an expected offline gap, not a WRAITH bug)."""
    assert m5_live.result.skip_counts.get("edges.contains_parent_unresolved", 0) == 13


# =============================================================================
# LAYER 4 — determinism (two full runs -> byte-identical edge rows)
# =============================================================================


@_needs_evidence
def test_determinism_two_full_runs_byte_identical() -> None:
    """Proves (determinism): two independent full 2a->M3->M4->M5 runs of the SAME
    .dit under the SAME run_id produce byte-identical edge rows (ordering,
    dedup, mask-OR and mint are all deterministic)."""
    dumps = []
    for _ in range(2):
        con = duckdb.connect(":memory:")
        _run_full_chain(con, _RUN)
        dumps.append(con.execute("SELECT * FROM edge ORDER BY edge_id").fetchall())
        con.close()
    assert dumps[0] == dumps[1], "edge rows differ across runs"


# =============================================================================
# LAYER 6 — 5B orchestrator end-to-end on a hand-built SYNTHETIC store
# (exercises the attribute decode + SQL wiring that the real DC never triggers)
# =============================================================================


def _prov_dict() -> dict[str, object]:
    return {
        "source_file": "ntds.dit",
        "image_sha256": "a" * 64,
        "source_object_id": "syn",
        "directory_timestamp": None,
        "ingest_run_id": str(_RUN),
    }


def test_synthetic_5b_orchestrator_wiring() -> None:
    """Proves (5B wiring the real DC never exercises): compute_edges decodes a
    staged msDS-AllowedToActOnBehalfOfOtherIdentity SD into an AllowedToAct edge,
    a sid_history array into HasSIDHistory (minting the foreign SID), and a trust
    row into a CrossForestTrust edge — through the real orchestrator + SQL."""
    import json

    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    prov = _prov_dict()

    # A computer (RBCD target) + the attacker principal referenced by the RBCD SD.
    con.execute(
        "INSERT INTO principal (node_id, object_sid, principal_type, samaccountname, "
        "sid_history, forest_id, provenance) VALUES (?,?,?,?,?,?,?)",
        ["n-attacker", "S-1-5-21-1-2-3-1104", "Computer", "ATK$", None, "f", prov],
    )
    rbcd_sd = _build_sd(
        [_Ace(True, int(AccessMask.GENERIC_ALL), "S-1-5-21-1-2-3-1104")], owner=None
    )
    con.execute(
        "INSERT INTO principal (node_id, object_sid, principal_type, samaccountname, "
        "sid_history, forest_id, provenance) VALUES (?,?,?,?,?,?,?)",
        [
            "n-victim",
            "S-1-5-21-1-2-3-2000",
            "Computer",
            "VICTIM$",
            ["S-1-5-21-9-9-9-500"],
            "f",
            prov,
        ],
    )
    con.execute(
        "INSERT INTO container (node_id, object_sid, container_type, forest_id, provenance) "
        "VALUES (?,?,?,?,?)",
        ["n-domain", _DOMAIN_SID, "Domain", "f", prov],
    )
    attrs = {"msDS-AllowedToActOnBehalfOfOtherIdentity": {"__bytes_hex__": rbcd_sd.hex()}}
    con.execute(
        "INSERT INTO staging_object (node_id, object_sid, raw_sd, attributes, forest_id, "
        "provenance) VALUES (?,?,?,?,?,?)",
        ["n-victim", "S-1-5-21-1-2-3-2000", None, json.dumps(attrs), "f", prov],
    )
    con.execute(
        "INSERT INTO trust (node_id, target_domain_id, direction, trust_attributes, "
        "trust_key_ref, forest_id, provenance) VALUES (?,?,?,?,?,?,?)",
        ["n-trust", "S-1-5-21-7-7-7", "outbound", 0, None, "f", prov],
    )

    run = IngestRun(_CASE, "wraith-tester", ingest_run_id=_RUN)
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit", abs_path_or_ref="x", size_bytes=1, image_sha256="a" * 64
        )
    )
    res = compute_edges(
        con, run, _empty_schema(), forest_id="f", domain_id=_DOMAIN_SID, domain_fqdn=_DOMAIN_FQDN
    )

    assert res.derivations.rbcd == 1
    assert res.derivations.sidhistory == 1
    assert res.derivations.trust == 1
    rbcd = con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind='AllowedToAct'"
    ).fetchone()
    assert rbcd == ("n-attacker", "n-victim")
    sh = con.execute("SELECT source_node_id FROM edge WHERE kind='HasSIDHistory'").fetchone()
    assert sh == ("n-victim",)
    # Two foreign SIDs minted via the shared resolver: the sid_history SID and
    # the cross-forest trust partner SID (both objectless -> mint-on-miss stubs).
    assert res.stubs_minted == 2
    # OUTBOUND trust: local (n-domain) is the TRUSTING side, the partner is TRUSTED,
    # so the attack edge runs partner -> local (trusted -> trusting, [MS-ADTS]
    # 6.1.6.7.12). The partner SID was minted on miss; the source is that stub, the
    # target is the local domain.
    partner_stub = con.execute(
        "SELECT node_id FROM principal WHERE object_sid = ?", ["S-1-5-21-7-7-7"]
    ).fetchone()[0]
    tr = con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind='CrossForestTrust'"
    ).fetchone()
    assert tr == (partner_stub, "n-domain")
    con.close()


def _empty_schema() -> NtdsSchema:
    return NtdsSchema(
        column_to_ldap={},
        ldap_to_column={},
        attributes_by_ldap={},
        attributes_by_internal_id={},
        classes_by_ldap={},
        extended_rights_by_guid={},
        raw_attribute_records=(),
        raw_class_records=(),
        raw_right_records=(),
        skipped_schema_records=0,
        unmapped_columns=(),
    )
