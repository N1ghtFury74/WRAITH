"""Minimal coder-side sanity for the slice-5B non-SD derivations (not the gate).

Covers the correctness cruxes on hand-built inputs with KNOWN output: SPN target
resolution (exact + host fallback), the RBCD/gMSA attribute-SD trustee builders
(reusing the 5A parse seam), SID-history mint-on-miss, the trust attack-direction
swap + SameForest/CrossForest classification + HasTrustKeys, the ADCS enrollment
classifier, and the node-flag predicates (incl. the krbtgt exclusion). The
authoritative three-layer gate is the tester's.
"""

from __future__ import annotations

import uuid

from wraith.edges.acl import NodeResolver
from wraith.edges.derivations import (
    DERIVATION_CROSS_FOREST,
    DERIVATION_SAME_FOREST,
    KIND_ALLOWED_TO_ACT,
    KIND_COERCE_TO_TGT,
    KIND_CONTAINS,
    KIND_CROSS_FOREST_TRUST,
    KIND_GPLINK,
    KIND_HAS_SID_HISTORY,
    KIND_HAS_TRUST_KEYS,
    KIND_READ_GMSA_PASSWORD,
    KIND_SAME_FOREST_TRUST,
    TrustInput,
    build_coerce_to_tgt_edge,
    build_constrained_delegation_edges,
    build_contains_edge,
    build_gmsa_read_edges,
    build_gplink_edges,
    build_rbcd_edges,
    build_sid_history_edges,
    build_spn_index,
    build_trust_edges,
    parent_dn,
    resolve_spn_target,
    spn_host,
)
from wraith.edges.guid_map import (
    GUID_CERTIFICATE_AUTOENROLLMENT,
    GUID_CERTIFICATE_ENROLLMENT,
    AccessMask,
    PkiFlagGuids,
    classify_ace,
    classify_adcs_ace,
)
from wraith.edges.node_flags import (
    compute_node_flags,
    is_asrep_roastable,
    is_coercible_unconstrained,
    is_domain_controller,
    is_kerberoastable,
    is_unconstrained_delegation,
)
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000005b")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="c" * 64,
    source_object_id="node:attr",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)
_SCOPING = ("f", "S-1-5-21-1-2-3", "c137.local")


def _resolver() -> NodeResolver:
    return NodeResolver(
        forest_id="f",
        domain_id="S-1-5-21-1-2-3",
        domain_fqdn="c137.local",
        sid_to_node={"S-1-5-21-1-2-3-1104": "node-svc"},
        all_nodes={"node-svc", "node-comp", "node-domain"},
        ingest_run_id=_RUN,
    )


# --- SPN resolution ----------------------------------------------------------


def test_spn_host_extraction() -> None:
    assert spn_host("cifs/dc01.corp.local:1433/svc") == "dc01.corp.local"
    assert spn_host("HOST/DC01") == "dc01"
    assert spn_host("malformed") is None


def test_spn_index_exact_and_host_fallback() -> None:
    index = build_spn_index([("node-comp", ["HOST/DC01.corp.local", "HOST/DC01"])])
    assert resolve_spn_target("host/dc01.corp.local", index) == "node-comp"  # exact (ci)
    # A different service class on the same host resolves via host fallback.
    assert resolve_spn_target("cifs/DC01.corp.local", index) == "node-comp"
    assert resolve_spn_target("cifs/unknown.corp.local", index) is None


def test_constrained_delegation_edges_and_gap() -> None:
    index = build_spn_index([("node-comp", ["HOST/DC01.corp.local"])])
    result = build_constrained_delegation_edges(
        "node-src", ["cifs/DC01.corp.local", "http/missing.corp.local"], index, _PROV, _SCOPING
    )
    assert len(result.edges) == 1 and result.skipped == 1
    assert result.edges[0].source_node_id == "node-src"
    assert result.edges[0].target_node_id == "node-comp"
    assert result.edges[0].derivation == "ATTR:AllowedToDelegate"


# --- RBCD / gMSA (attribute SD) ----------------------------------------------


def _single_allow_sd(trustee: str) -> bytes:
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_MASK,
        ACE,
        ACL,
        LDAP_SID,
        SR_SECURITY_DESCRIPTOR,
    )

    sid = LDAP_SID()
    sid.fromCanonical(trustee)
    ace = ACE()
    ace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    body = ACCESS_ALLOWED_ACE()
    body["Mask"] = ACCESS_MASK()
    body["Mask"]["Mask"] = int(AccessMask.GENERIC_ALL)
    body["Sid"] = sid
    ace["Ace"] = body
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = [ace]
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = sid
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = acl
    return bytes(sd.getData())


def test_rbcd_edge_trustee_to_computer() -> None:
    r = _resolver()
    edges, failed = build_rbcd_edges(
        "node-comp", _single_allow_sd("S-1-5-21-1-2-3-1104"), r, _PROV, _SCOPING
    )
    assert failed is False and len(edges) == 1
    e = edges[0]
    assert e.kind == KIND_ALLOWED_TO_ACT and e.derivation == "ATTR:RBCD"
    assert e.source_node_id == "node-svc" and e.target_node_id == "node-comp"


def test_gmsa_read_edge() -> None:
    r = _resolver()
    edges, failed = build_gmsa_read_edges(
        "node-comp", _single_allow_sd("S-1-5-21-1-2-3-1104"), r, _PROV, _SCOPING
    )
    assert failed is False and len(edges) == 1
    assert edges[0].kind == KIND_READ_GMSA_PASSWORD and edges[0].derivation == "ATTR:gMSAMembership"


def test_rbcd_malformed_sd_counted() -> None:
    r = _resolver()
    edges, failed = build_rbcd_edges("node-comp", b"\x01garbage", r, _PROV, _SCOPING)
    assert edges == [] and failed is True


# --- SID history -------------------------------------------------------------


def test_sid_history_mint_on_miss() -> None:
    r = _resolver()
    edges = build_sid_history_edges("node-comp", ["S-1-5-21-9-9-9-500"], r, _PROV, _SCOPING)
    assert len(edges) == 1
    assert edges[0].kind == KIND_HAS_SID_HISTORY and edges[0].derivation == "ATTR:SIDHistory"
    assert edges[0].source_node_id == "node-comp"
    assert len(r.minted) == 1  # the historical SID had no node -> stub minted


# --- Trust edges -------------------------------------------------------------


def _trust(direction: str, attrs: int, key: bool = False) -> TrustInput:
    return TrustInput(
        local_domain_node_id="node-domain",
        other_domain_sid="S-1-5-21-7-7-7",
        direction=direction,
        trust_attributes=attrs,
        has_trust_key=key,
        provenance=_PROV,
    )


def test_trust_direction_outbound_crossforest() -> None:
    # [MS-ADTS]: OUTBOUND = local trusts partner -> local is TRUSTING, partner is
    # TRUSTED. Attack flows trusted->trusting = other -> local. External = CrossForest.
    r = _resolver()
    edges, unresolved = build_trust_edges(_trust("outbound", 0x0), r, _SCOPING)
    assert unresolved == 0 and len(edges) == 1
    e = edges[0]
    assert e.kind == KIND_CROSS_FOREST_TRUST and e.derivation == DERIVATION_CROSS_FOREST
    other = r.resolve_or_mint("S-1-5-21-7-7-7")
    assert e.source_node_id == other and e.target_node_id == "node-domain"


def test_trust_direction_inbound_sameforest() -> None:
    # [MS-ADTS]: INBOUND = partner trusts local -> local is TRUSTED, partner is
    # TRUSTING. Attack flows trusted->trusting = local -> other. 0x20 = SameForest.
    r = _resolver()
    edges, _ = build_trust_edges(_trust("inbound", 0x20), r, _SCOPING)
    assert len(edges) == 1
    e = edges[0]
    assert e.kind == KIND_SAME_FOREST_TRUST and e.derivation == DERIVATION_SAME_FOREST
    other = r.resolve_or_mint("S-1-5-21-7-7-7")
    assert e.source_node_id == "node-domain" and e.target_node_id == other


def test_trust_bidirectional_covers_both_attack_directions() -> None:
    # bidirectional -> both (other->local) and (local->other).
    r = _resolver()
    edges, _ = build_trust_edges(_trust("bidirectional", 0x0), r, _SCOPING)
    other = r.resolve_or_mint("S-1-5-21-7-7-7")
    pairs = {
        (e.source_node_id, e.target_node_id) for e in edges if e.kind == KIND_CROSS_FOREST_TRUST
    }
    assert pairs == {(other, "node-domain"), ("node-domain", other)}


def test_trust_bidirectional_two_edges_plus_trust_keys() -> None:
    r = _resolver()
    edges, _ = build_trust_edges(_trust("bidirectional", 0x0, key=True), r, _SCOPING)
    kinds = [e.kind for e in edges]
    assert kinds.count(KIND_CROSS_FOREST_TRUST) == 2
    assert KIND_HAS_TRUST_KEYS in kinds
    hk = next(e for e in edges if e.kind == KIND_HAS_TRUST_KEYS)
    assert hk.derivation == "ATTR:TrustKeys" and hk.source_node_id == "node-domain"


def test_trust_disabled_no_edge() -> None:
    r = _resolver()
    edges, _ = build_trust_edges(_trust("disabled", 0x0), r, _SCOPING)
    assert edges == []


# --- ADCS enrollment classifier ----------------------------------------------


def test_classify_ace_handled_elsewhere_not_unmapped() -> None:
    # M-1: a scoped control-access ACE with an ADCS enroll GUID (mapped by 5B) must
    # NOT inflate `unmapped_objecttype` in the 5A classifier when flagged handled.
    handled = frozenset({GUID_CERTIFICATE_ENROLLMENT})
    res = classify_ace(
        int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_ENROLLMENT, frozenset(), handled
    )
    assert res.facts == () and res.unmapped_objecttype is False
    # Without the handled set, the same ACE IS flagged unmapped (the gap is real).
    res2 = classify_ace(int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_ENROLLMENT, frozenset())
    assert res2.facts == () and res2.unmapped_objecttype is True


def test_classify_adcs_enroll_and_autoenroll() -> None:
    pki = PkiFlagGuids(enrollment_flag="eeee1111-0000-0000-0000-000000000000", name_flag=None)
    enroll = classify_adcs_ace(int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_ENROLLMENT, pki)
    assert [f.kind for f in enroll.facts] == ["Enroll"]
    auto = classify_adcs_ace(
        int(AccessMask.DS_CONTROL_ACCESS), GUID_CERTIFICATE_AUTOENROLLMENT, pki
    )
    assert [f.kind for f in auto.facts] == ["AutoEnroll"]
    wflag = classify_adcs_ace(
        int(AccessMask.DS_WRITE_PROP), "eeee1111-0000-0000-0000-000000000000", pki
    )
    assert [f.kind for f in wflag.facts] == ["WritePKIEnrollmentFlag"]
    # Whole-object control is NOT re-emitted by the ADCS classifier (5A covers it).
    assert classify_adcs_ace(int(AccessMask.GENERIC_ALL), None, pki).facts == ()


# --- Node flags --------------------------------------------------------------


def test_node_flags() -> None:
    assert is_unconstrained_delegation(0x80000) is True
    assert is_unconstrained_delegation(0x200) is False
    assert is_asrep_roastable(0x400000) is True
    # kerberoastable: enabled user with SPN, excluding krbtgt.
    assert is_kerberoastable("User", True, ["MSSQL/db"], "svc") is True
    assert is_kerberoastable("User", True, ["kadmin/changepw"], "krbtgt") is False
    assert is_kerberoastable("User", False, ["MSSQL/db"], "svc") is False
    assert is_kerberoastable("Computer", True, ["HOST/x"], "comp$") is False
    flags = compute_node_flags("User", 0x80000 | 0x400000, True, ["x/y"], "svc")
    assert flags.unconstrained_delegation and flags.asrep_roastable and flags.kerberoastable


# --- Structural edges: Contains / GPLink / CoerceToTGT -----------------------


def test_parent_dn_strips_leading_rdn() -> None:
    assert parent_dn("CN=svc,OU=Sales,DC=c137,DC=local") == "OU=Sales,DC=c137,DC=local"
    assert parent_dn("DC=local") is None  # single component -> no parent
    # An escaped comma in the leading RDN is not treated as a separator.
    assert parent_dn(r"CN=last\,first,OU=X,DC=c") == "OU=X,DC=c"


def test_contains_edge_container_to_child() -> None:
    # Direction: container (source) -> contained child (target).
    e = build_contains_edge("n-ou", "n-user", _PROV, _SCOPING)
    assert e is not None
    assert e.kind == KIND_CONTAINS and e.derivation == "STRUCT:parent"
    assert e.source_node_id == "n-ou" and e.target_node_id == "n-user"
    assert e.access_mask is None and e.object_type_guid is None
    # Reflexive parent==child -> None (caller counts as resolved-but-skipped).
    assert build_contains_edge("n-ou", "n-ou", _PROV, _SCOPING) is None


def test_gplink_edges_gpo_to_container() -> None:
    # Direction: GPO (source) -> linked container (target); one edge per link,
    # deduped on gpo_node_id; a link with no gpo_node_id is skipped.
    gplinks = [
        {"gpo_node_id": "n-gpo-1", "enforced": True, "link_order": 1},
        {"gpo_node_id": "n-gpo-2", "enforced": False, "link_order": 2},
        {"gpo_node_id": "n-gpo-1", "enforced": False, "link_order": 3},  # dup -> skip
        {"gpo_node_id": None, "enforced": False, "link_order": 4},  # unresolved -> skip
    ]
    edges = build_gplink_edges("n-ou", gplinks, _PROV, _SCOPING)
    assert {(e.source_node_id, e.target_node_id) for e in edges} == {
        ("n-gpo-1", "n-ou"),
        ("n-gpo-2", "n-ou"),
    }
    assert all(e.kind == KIND_GPLINK and e.derivation == "ATTR:gPLink" for e in edges)


def test_coerce_to_tgt_predicate_and_edge() -> None:
    # Non-DC unconstrained host is coercible; a DC (SERVER_TRUST_ACCOUNT 0x2000) is not.
    assert is_domain_controller(0x2000) is True and is_domain_controller(0x1000) is False
    assert is_coercible_unconstrained(0x80000) is True  # unconstrained, not a DC
    assert is_coercible_unconstrained(0x80000 | 0x2000) is False  # DC -> suppressed
    assert is_coercible_unconstrained(0x1000) is False  # not unconstrained
    e = build_coerce_to_tgt_edge("n-host", "n-domain", _PROV, _SCOPING)
    assert e is not None
    assert e.kind == KIND_COERCE_TO_TGT and e.derivation == "FLAG:unconstrained"
    assert e.source_node_id == "n-host" and e.target_node_id == "n-domain"
    assert e.access_mask is None and e.object_type_guid is None
    assert build_coerce_to_tgt_edge("n-domain", "n-domain", _PROV, _SCOPING) is None
