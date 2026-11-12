"""Minimal coder-side sanity for the slice-5A SD/ACE seams (not the gate).

Covers the correctness cruxes of the ACL core on hand-built inputs with KNOWN
output: the GUID->edge classifier precedence (GENERIC_ALL dominates, scoped
object-type gating, unmapped-GUID surfaced, LAPS read), round-trip SD parsing via
the Impacket seam (ALLOW-only, DENY/INHERIT_ONLY counted, inherited flag), the
mint-on-miss resolver (object_sid-first, deduped stub), and the signed-int32 mask
encoding. The authoritative three-layer gate (golden/parity/property) is the
tester's and lands after slice 5B.
"""

from __future__ import annotations

import uuid

from wraith.edges.acl import (
    NodeResolver,
    _unsigned_mask,
    build_ace_edges,
    build_owner_edge,
    parse_sd,
)
from wraith.edges.guid_map import (
    GUID_GET_CHANGES,
    GUID_GPLINK,
    GUID_MEMBER,
    GUID_PUBLIC_INFORMATION,
    AccessMask,
    classify_ace,
)
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000005a")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="b" * 64,
    source_object_id="node-obj:sd",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)


# --- classify_ace precedence -------------------------------------------------


def test_generic_all_dominates() -> None:
    res = classify_ace(int(AccessMask.GENERIC_ALL | AccessMask.WRITE_DACL), None, frozenset())
    assert [f.kind for f in res.facts] == ["GenericAll"]
    assert res.unmapped_objecttype is False


def test_whole_object_write_bits() -> None:
    mask = int(AccessMask.WRITE_DACL | AccessMask.WRITE_OWNER | AccessMask.GENERIC_WRITE)
    res = classify_ace(mask, None, frozenset())
    assert {f.kind for f in res.facts} == {"WriteDacl", "WriteOwner", "GenericWrite"}


def test_scoped_addmember_vs_addself() -> None:
    wp = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_MEMBER, frozenset())
    assert [f.kind for f in wp.facts] == ["AddMember"] and wp.facts[0].scoped is True
    self_ace = classify_ace(int(AccessMask.DS_SELF), GUID_MEMBER, frozenset())
    assert [f.kind for f in self_ace.facts] == ["AddSelf"]


def test_control_access_getchanges_scoped() -> None:
    res = classify_ace(int(AccessMask.DS_CONTROL_ACCESS), GUID_GET_CHANGES, frozenset())
    assert [f.kind for f in res.facts] == ["GetChanges"]


def test_unmapped_scoped_guid_surfaced_not_fallback() -> None:
    res = classify_ace(
        int(AccessMask.DS_WRITE_PROP), "11111111-1111-1111-1111-111111111111", frozenset()
    )
    assert res.facts == () and res.unmapped_objecttype is True


def test_plain_read_unknown_guid_not_flagged() -> None:
    res = classify_ace(
        int(AccessMask.DS_READ_PROP), "11111111-1111-1111-1111-111111111111", frozenset()
    )
    assert res.facts == () and res.unmapped_objecttype is False


def test_laps_read_resolved() -> None:
    laps = frozenset({"aaaabbbb-cccc-dddd-eeee-ffff00001111"})
    res = classify_ace(int(AccessMask.DS_READ_PROP), "aaaabbbb-cccc-dddd-eeee-ffff00001111", laps)
    assert [f.kind for f in res.facts] == ["ReadLAPSPassword"]


def test_control_access_no_objecttype_is_all_extended() -> None:
    res = classify_ace(int(AccessMask.DS_CONTROL_ACCESS), None, frozenset())
    assert [f.kind for f in res.facts] == ["AllExtendedRights"]
    assert res.facts[0].scoped is False


def test_write_gplink_scoped_mapped() -> None:
    # WRITE_PROP on the gPLink attribute GUID -> WriteGPLink (scoped, trustee->obj).
    res = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_GPLINK, frozenset())
    assert [f.kind for f in res.facts] == ["WriteGPLink"]
    assert res.facts[0].scoped is True and res.unmapped_objecttype is False


def test_write_public_information_propset_mapped() -> None:
    # WRITE_PROP on the Public-Information property set -> WritePublicInformation.
    res = classify_ace(int(AccessMask.DS_WRITE_PROP), GUID_PUBLIC_INFORMATION, frozenset())
    assert [f.kind for f in res.facts] == ["WritePublicInformation"]
    assert res.facts[0].scoped is True and res.unmapped_objecttype is False


# --- parse_sd round-trip -----------------------------------------------------


def _build_sd() -> bytes:
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
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

    # ALLOW object ACE: GetChanges on the object, trustee ...-512, inherited.
    a1 = ACE()
    a1["AceType"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    a1["AceFlags"] = ACE.INHERITED_ACE
    b1 = ACCESS_ALLOWED_OBJECT_ACE()
    b1["Mask"] = ACCESS_MASK()
    b1["Mask"]["Mask"] = int(AccessMask.DS_CONTROL_ACCESS)
    b1["ObjectType"] = uuid.UUID(GUID_GET_CHANGES).bytes_le
    b1["InheritedObjectType"] = b""
    b1["Flags"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    b1["Sid"] = sid("S-1-5-21-1-2-3-512")
    a1["Ace"] = b1

    # ALLOW plain ACE: GenericAll, trustee ...-519.
    a2 = ACE()
    a2["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    a2["AceFlags"] = 0
    b2 = ACCESS_ALLOWED_ACE()
    b2["Mask"] = ACCESS_MASK()
    b2["Mask"]["Mask"] = int(AccessMask.GENERIC_ALL)
    b2["Sid"] = sid("S-1-5-21-1-2-3-519")
    a2["Ace"] = b2

    # DENY ACE (must be counted + skipped).
    a3 = ACE()
    a3["AceType"] = ACCESS_DENIED_ACE.ACE_TYPE
    a3["AceFlags"] = 0
    b3 = ACCESS_DENIED_ACE()
    b3["Mask"] = ACCESS_MASK()
    b3["Mask"]["Mask"] = int(AccessMask.GENERIC_ALL)
    b3["Sid"] = sid("S-1-5-21-1-2-3-513")
    a3["Ace"] = b3

    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = [a1, a2, a3]
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = sid("S-1-5-21-1-2-3-500")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = acl
    return bytes(sd.getData())


def test_parse_sd_allow_only_counts_deny() -> None:
    parsed = parse_sd(_build_sd())
    assert parsed is not None
    assert parsed.owner_sid == "S-1-5-21-1-2-3-500"
    assert parsed.had_dacl is True
    assert parsed.deny_skipped == 1
    assert len(parsed.aces) == 2
    getchanges = parsed.aces[0]
    assert getchanges.object_type_guid == GUID_GET_CHANGES
    assert getchanges.is_inherited is True
    genall = parsed.aces[1]
    assert genall.object_type_guid is None and genall.is_inherited is False


def test_parse_sd_malformed_returns_none() -> None:
    assert parse_sd(b"\x01\x00garbagegarbage") is None


# --- mint-on-miss + builders -------------------------------------------------


def _resolver() -> NodeResolver:
    return NodeResolver(
        forest_id="f",
        domain_id="S-1-5-21-1-2-3",
        domain_fqdn="c137.local",
        sid_to_node={"S-1-5-21-1-2-3-512": "node-dcs"},
        all_nodes={"node-dcs", "node-obj"},
        ingest_run_id=_RUN,
    )


def test_resolve_by_object_sid_first_no_mint() -> None:
    r = _resolver()
    assert r.resolve_or_mint("S-1-5-21-1-2-3-512") == "node-dcs"
    assert r.minted == {}


def test_mint_on_miss_dedup() -> None:
    r = _resolver()
    n1 = r.resolve_or_mint("S-1-5-21-1-2-3-9999")
    n2 = r.resolve_or_mint("S-1-5-21-1-2-3-9999")
    assert n1 == n2
    assert list(r.minted) == [n1]
    assert r.minted[n1].object_sid == "S-1-5-21-1-2-3-9999"


def test_owner_edge_skips_noise_and_self() -> None:
    r = _resolver()
    assert build_owner_edge("S-1-5-18", "node-obj", None, r, _PROV, "f", "d", "fq") is None
    self_sid = "S-1-5-21-1-2-3-500"
    assert build_owner_edge(self_sid, "node-obj", self_sid, r, _PROV, "f", "d", "fq") is None


def test_ace_edges_source_is_holder_target_is_object() -> None:
    parsed = parse_sd(_build_sd())
    assert parsed is not None
    r = _resolver()
    edges, gaps = build_ace_edges(
        parsed.aces, "node-obj", None, frozenset(), r, _PROV, "f", "d", "fq"
    )
    kinds = {e.kind: e for e in edges}
    assert "GetChanges" in kinds and "GenericAll" in kinds
    gc = kinds["GetChanges"]
    assert gc.source_node_id == "node-dcs" and gc.target_node_id == "node-obj"
    assert gc.object_type_guid == GUID_GET_CHANGES  # scoped carries the GUID
    assert gc.is_inherited is True
    assert kinds["GenericAll"].object_type_guid is None  # whole-object -> NULL
    assert gaps.noise_trustee_skipped == 0 and gaps.unmapped_objecttype == 0


def test_unsigned_mask_roundtrip() -> None:
    assert _unsigned_mask(0x10000000) == 0x10000000
    # Schema v1.1: a high-bit mask is stored UNSIGNED (non-negative), lossless.
    enc = _unsigned_mask(0xF0000000)
    assert enc >= 0 and enc == 0xF0000000
