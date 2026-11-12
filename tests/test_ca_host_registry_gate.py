"""Tester GATE for Module 08b — offline Enterprise-CA-host registry adapter.

Authoritative three-layer gate for ``wraith/analysis/ca_host_facts.py`` + the lit
``_compose_ca_host_edges`` family in ``wraith/analysis/adcs_esc.py`` (research
``docs/research/28-ca-host-registry-adapter.md``). Written independently of the
coder's suite.

Layers:
  1. unit/golden — ``parse_ca_security`` deny-before-allow + role-bit selection;
     the four value decoders against a fake Impacket reader (every SPIKE shape);
     the None-aware ``CaRegistryFacts`` properties (incl. the ESC11 CLEAR polarity).
  2. reference/parity — ManageCA/ManageCertificates (confirmed, HIVE provenance,
     principal->EnterpriseCA, BH-CE kind names) + ESC6a composed like ESC1, gated
     on ``attribute_san2 is True``; [MS-CSRA] bit-map cross-check.
  3. property/robustness — every counted-gap token fires on its own branch;
     false-positive-forbidden; unread(None)=>gap vs read-negative/()=>decided;
     name-mismatch stays a loud block; determinism under reversed ACE order; a real
     SOFTWARE/SYSTEM hive reads without crashing (the real-artifact anchor).

UNTESTED-ON-REAL: no real GOAD/Certipy CA hive yet; the real ``eviedence_test``
hives are a DC (no CertSvc CA), so the live ``PolicyModules\\Active`` subkey name,
``DisableExtensionList`` MULTI_SZ shape and a ``Security``-round-trips-to-Certipy
parity remain to confirm on a real CA capture.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

import tests.test_adcs_esc_gate as gx
from wraith.analysis import ca_host_facts as adapter
from wraith.analysis.adcs_esc import (
    ABSENT_CA_HOST_FACTS,
    CA_RIGHT_AUDITOR,
    CA_RIGHT_ENROLL,
    CA_RIGHT_MANAGE_CA,
    CA_RIGHT_MANAGE_CERTIFICATES,
    CA_RIGHT_OPERATOR,
    CA_RIGHT_READ,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    IF_ENFORCEENCRYPTICERTREQUEST,
    KIND_ESC6A,
    KIND_MANAGE_CA,
    KIND_MANAGE_CERTIFICATES,
    NODE_PROP_DCOM,
    NODE_PROP_ESC11,
    NODE_PROP_ESC16,
    OID_NTDS_CA_SECURITY_EXT,
    CaHostFacts,
    CaRegistryFacts,
    DcomRestrictions,
    normalize_ca_name,
)
from wraith.analysis.ca_host_facts import parse_ca_security
from wraith.provenance.models import ProvenanceStruct

# --- HIVE provenance anchor (distinct source_file from the ntds.dit CA node) ---
_RUN = uuid.UUID("00000000-0000-0000-0000-0000000061ea")
_HIVE_PROV = ProvenanceStruct(
    source_file="CAHOST/SYSTEM",
    image_sha256="c" * 64,
    source_object_id="CertSvc\\Configuration\\n-entca\\Security",
    directory_timestamp=None,
    ingest_run_id=_RUN,
)

# --- synthetic SIDs (reuse the gate harness' domain) --------------------------
_SID_OFFICER = f"{gx._DOMAIN_SID}-2201"
_SID_MANAGER = f"{gx._DOMAIN_SID}-2202"
_SID_ADMINS = gx._SID_ADMINS

_REPO = Path(__file__).resolve().parent.parent
_REAL_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_REAL_SOFTWARE = _REPO / "eviedence_test" / "Registry" / "SOFTWARE"
_needs_real = pytest.mark.skipif(
    not (_REAL_SYSTEM.is_file() and _REAL_SOFTWARE.is_file()),
    reason="needs eviedence_test Registry SYSTEM+SOFTWARE hives",
)


# =============================================================================
# Independent REAL security-descriptor builders (impacket ldaptypes)
# =============================================================================


def _ca_ace(mask: int, sid: str, *, deny: bool = False) -> object:
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_MASK,
        ACE,
        LDAP_SID,
    )

    ldap_sid = LDAP_SID()
    ldap_sid.fromCanonical(sid)
    cls = ACCESS_DENIED_ACE if deny else ACCESS_ALLOWED_ACE
    body = cls()
    body["Mask"] = ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = ldap_sid
    ace = ACE()
    ace["AceType"] = cls.ACE_TYPE
    ace["AceFlags"] = 0
    ace["Ace"] = body
    return ace


def _ca_security_sd(aces: list[object]) -> bytes:
    from impacket.ldap.ldaptypes import ACL, LDAP_SID, SR_SECURITY_DESCRIPTOR

    owner = LDAP_SID()
    owner.fromCanonical("S-1-5-18")
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = aces
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = owner
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = acl
    return bytes(sd.getData())


# =============================================================================
# A fake Impacket registry reader (drives the pure value decoders)
# =============================================================================


class _FakeReader:
    """Minimal ``getValue`` stand-in: path -> (ValueType, data); absent raises."""

    def __init__(self, values: dict[str, tuple[int, object]]) -> None:
        self._values = values

    def getValue(self, key_path: str) -> tuple[int, object]:  # noqa: N802 (impacket API)
        if key_path not in self._values:
            raise KeyError(key_path)
        return self._values[key_path]


# REG type ints are IGNORED by the decoders (they read data only); label for clarity.
_REG_SZ, _REG_BINARY, _REG_DWORD, _REG_MULTI_SZ = 1, 3, 4, 7


# =============================================================================
# LAYER 1 — unit/golden: the [MS-CSRA] bit map
# =============================================================================


def test_ca_right_bit_map_matches_ms_csra() -> None:
    # [MS-CSRA] §3.1.1.7 CA ACCESS_MASK role bits — the easiest thing to transpose.
    assert CA_RIGHT_MANAGE_CA == 0x00000001  # Administrator (ManageCA)
    assert CA_RIGHT_MANAGE_CERTIFICATES == 0x00000002  # Officer (ManageCertificates)
    assert CA_RIGHT_AUDITOR == 0x00000004
    assert CA_RIGHT_OPERATOR == 0x00000008
    assert CA_RIGHT_READ == 0x00000100
    assert CA_RIGHT_ENROLL == 0x00000200
    assert EDITF_ATTRIBUTESUBJECTALTNAME2 == 0x00040000  # ESC6
    assert IF_ENFORCEENCRYPTICERTREQUEST == 0x00000200  # ESC11 (CLEAR == vulnerable)
    assert OID_NTDS_CA_SECURITY_EXT == "1.3.6.1.4.1.311.25.2"  # ESC16


# =============================================================================
# LAYER 1 — parse_ca_security: role-bit selection + deny-before-allow
# =============================================================================


def test_parse_ca_security_selects_role_bits() -> None:
    sd = _ca_security_sd(
        [
            _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER),  # 0x1 -> ManageCA only
            _ca_ace(CA_RIGHT_MANAGE_CERTIFICATES, _SID_MANAGER),  # 0x2 -> ManageCert only
            _ca_ace(CA_RIGHT_READ | CA_RIGHT_ENROLL, _SID_ADMINS),  # neither role bit
        ]
    )
    parsed = parse_ca_security(sd)
    assert parsed is not None
    manage_ca, manage_cert = parsed
    assert manage_ca == frozenset({_SID_OFFICER})
    assert manage_cert == frozenset({_SID_MANAGER})


def test_parse_ca_security_both_bits_one_ace() -> None:
    sd = _ca_security_sd([_ca_ace(CA_RIGHT_MANAGE_CA | CA_RIGHT_MANAGE_CERTIFICATES, _SID_OFFICER)])
    manage_ca, manage_cert = parse_ca_security(sd)  # type: ignore[misc]
    assert _SID_OFFICER in manage_ca and _SID_OFFICER in manage_cert


def test_parse_ca_security_deny_removes_a_granted_bit() -> None:
    # Allow 0x3 then DENY 0x1 to the same SID: deny-before-allow strips ManageCA,
    # leaving ManageCertificates (effective = allow & ~deny).
    sd = _ca_security_sd(
        [
            _ca_ace(CA_RIGHT_MANAGE_CA | CA_RIGHT_MANAGE_CERTIFICATES, _SID_OFFICER),
            _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER, deny=True),
        ]
    )
    manage_ca, manage_cert = parse_ca_security(sd)  # type: ignore[misc]
    assert _SID_OFFICER not in manage_ca  # the denied bit is gone
    assert _SID_OFFICER in manage_cert  # the un-denied bit survives


def test_parse_ca_security_deny_removes_whole_grant() -> None:
    sd = _ca_security_sd(
        [
            _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER),
            _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER, deny=True),
        ]
    )
    manage_ca, manage_cert = parse_ca_security(sd)  # type: ignore[misc]
    assert _SID_OFFICER not in manage_ca and _SID_OFFICER not in manage_cert


def test_parse_ca_security_empty_dacl_is_decided_none_not_parse_error() -> None:
    manage_ca, manage_cert = parse_ca_security(_ca_security_sd([]))  # type: ignore[misc]
    assert manage_ca == frozenset() and manage_cert == frozenset()  # decided-none, NOT None


def test_parse_ca_security_unparseable_returns_none() -> None:
    assert parse_ca_security(b"not a security descriptor") is None  # parse error, distinct


def test_parse_ca_security_determinism_reversed_ace_order() -> None:
    aces = [
        _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER),
        _ca_ace(CA_RIGHT_MANAGE_CERTIFICATES, _SID_MANAGER),
        _ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER, deny=True),
    ]
    forward = parse_ca_security(_ca_security_sd(aces))
    reverse = parse_ca_security(_ca_security_sd(list(reversed(aces))))
    assert forward == reverse  # SID-level deny-before-allow is order-independent


# =============================================================================
# LAYER 1 — the four value decoders (every SPIKE-confirmed shape)
# =============================================================================


def test_read_sz_inline_int_and_utf16_bytes_and_empty_and_absent() -> None:
    long_name = "MyEnterpriseCA".encode("utf-16le") + b"\x00\x00"
    reader = _FakeReader(
        {
            "k\\inline": (_REG_SZ, 0x0059),  # <=4-byte inline int: UTF-16LE "Y"
            "k\\long": (_REG_BINARY, long_name),  # >4-byte UTF-16LE NUL-terminated
            "k\\empty": (_REG_SZ, ""),  # zero-length value -> None (unusable name)
        }
    )
    assert adapter._read_sz(reader, "k\\inline") == "Y"
    assert adapter._read_sz(reader, "k\\long") == "MyEnterpriseCA"
    assert adapter._read_sz(reader, "k\\empty") is None
    assert adapter._read_sz(reader, "k\\absent") is None  # absent -> None


def test_read_multi_sz_tokens_empty_and_absent() -> None:
    blob = ("1.3.6.1.4.1.311.25.2\x001.2.3\x00\x00").encode("utf-16le")
    reader = _FakeReader(
        {
            "k\\list": (_REG_MULTI_SZ, blob),
            "k\\emptystr": (_REG_MULTI_SZ, ""),  # read-empty -> () DECIDED (no gap)
        }
    )
    assert adapter._read_multi_sz(reader, "k\\list") == ("1.3.6.1.4.1.311.25.2", "1.2.3")
    assert adapter._read_multi_sz(reader, "k\\emptystr") == ()  # decided-empty, not None
    assert adapter._read_multi_sz(reader, "k\\absent") is None  # unread -> None (gap)


def test_read_binary_bytes_inline_int_and_absent() -> None:
    reader = _FakeReader(
        {
            "k\\sd": (_REG_BINARY, b"\x01\x00\x04\x80rest-of-descriptor"),
            "k\\inline": (_REG_DWORD, 0x0059),  # an int is not a descriptor -> None
        }
    )
    assert adapter._read_binary(reader, "k\\sd") == b"\x01\x00\x04\x80rest-of-descriptor"
    assert adapter._read_binary(reader, "k\\inline") is None
    assert adapter._read_binary(reader, "k\\absent") is None


# =============================================================================
# LAYER 1 — None-aware CaRegistryFacts properties (+ ESC11 CLEAR polarity)
# =============================================================================


def _facts(**over: object) -> CaRegistryFacts:
    base: dict[str, object] = dict(
        ca_name="n-entca",
        host_fqdn=None,
        security_sd=b"present",
        manage_ca_sids=frozenset(),
        manage_cert_sids=frozenset(),
        edit_flags=None,
        interface_flags=None,
        disable_extension_list=None,
        policy_module_resolved=True,
        provenance=_HIVE_PROV,
    )
    base.update(over)
    return CaRegistryFacts(**base)  # type: ignore[arg-type]


def test_attribute_san2_property() -> None:
    assert _facts(edit_flags=EDITF_ATTRIBUTESUBJECTALTNAME2).attribute_san2 is True
    assert _facts(edit_flags=0).attribute_san2 is False  # read-negative -> decided-False
    assert _facts(edit_flags=0x4).attribute_san2 is False  # other bits only
    assert _facts(edit_flags=None).attribute_san2 is None  # unread -> undecidable


def test_esc11_polarity_vulnerable_when_bit_clear() -> None:
    # ESC11 is present when IF_ENFORCEENCRYPTICERTREQUEST (0x200) is CLEAR.
    cleared = _facts(interface_flags=0x0)
    assert cleared.enforce_encrypt_request is False
    assert cleared.esc11_vulnerable is True  # CLEAR bit => VULNERABLE
    enforced = _facts(interface_flags=IF_ENFORCEENCRYPTICERTREQUEST)
    assert enforced.enforce_encrypt_request is True
    assert enforced.esc11_vulnerable is False  # SET bit => NOT vulnerable
    assert _facts(interface_flags=None).esc11_vulnerable is None  # unread


def test_sid_ext_disabled_property() -> None:
    assert _facts(disable_extension_list=(OID_NTDS_CA_SECURITY_EXT,)).sid_ext_disabled is True
    assert _facts(disable_extension_list=("1.2.3",)).sid_ext_disabled is False
    assert _facts(disable_extension_list=()).sid_ext_disabled is False  # read-empty -> decided
    assert _facts(disable_extension_list=None).sid_ext_disabled is None  # unread


# =============================================================================
# LAYER 2 — reference/parity: ManageCA/ManageCertificates + ESC6a
# =============================================================================


def _ca_host_facts(**over: object) -> CaHostFacts:
    reg = _facts(**over)
    return CaHostFacts(provided=True, cas={normalize_ca_name(reg.ca_name): reg}, dcom=None)


def _esc6_store() -> object:
    """ESC6-candidate store: enrollable low-priv client-auth template on a trusted CA.

    Supplies-subject OFF, so NOT ESC1 — ESC6 is decided ONLY by the CA EditFlags.
    """
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_principal(con, "n-users", gx._SID_USERS, "Group")
    gx._trusted_ca(con, ["ESC6"])
    gx._add_adcs(
        con,
        "n-esc6",
        "CertTemplate",
        name="ESC6",
        pki_flags=gx._v2(
            certificate_name_flag="0",  # ENROLLEE_SUPPLIES_SUBJECT OFF -> not ESC1
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[gx._EKU_CLIENT_AUTH],
        ),
        raw_sd=gx._enroll_sd(gx._SID_USERS),
    )
    gx._run_m5(con)
    return con


def test_manage_ca_and_certificates_edges_confirmed_bh_parity() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_principal(con, "n-officer", _SID_OFFICER, "User")
    gx._add_principal(con, "n-manager", _SID_MANAGER, "Group")
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    facts = _ca_host_facts(
        manage_ca_sids=frozenset({_SID_OFFICER}),
        manage_cert_sids=frozenset({_SID_MANAGER}),
        interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,  # decided-safe (no esc11 noise)
        disable_extension_list=(),  # decided-empty (no esc16 noise)
    )
    buf, result = gx._esc(con, ca_host=facts)
    pairs = gx._pairs(buf)
    assert (KIND_MANAGE_CA, "n-officer", "n-entca") in pairs  # principal -> EnterpriseCA
    assert (KIND_MANAGE_CERTIFICATES, "n-manager", "n-entca") in pairs
    assert result.manage_ca == 1 and result.manage_certificates == 1
    # confirmed confidence + HIVE provenance (distinct from the ntds CA node).
    mca = next(e for e in buf.edges if e.kind == KIND_MANAGE_CA)
    assert mca.confidence == "confirmed"
    assert mca.provenance.image_sha256 == "c" * 64  # the hive anchor, not "b"*64
    assert mca.provenance.source_file == "CAHOST/SYSTEM"
    assert mca.access_mask is None and mca.object_type_guid is None
    # ESC7 decided -> NOT counted absent for this CA.
    assert result.ca_host_blocked.get("esc7", 0) == 0
    con.close()


def test_esc6a_emitted_like_esc1_when_san2_true() -> None:
    con = _esc6_store()
    buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            edit_flags=EDITF_ATTRIBUTESUBJECTALTNAME2,
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
            disable_extension_list=(),
        ),
    )
    assert (KIND_ESC6A, "n-users", "n-domain") in gx._pairs(buf)  # like ESC1, to Domain
    assert result.esc6a == 1
    esc6a = next(e for e in buf.edges if e.kind == KIND_ESC6A)
    assert esc6a.confidence == "inferred"  # composite, not confirmed
    assert esc6a.provenance.source_file == "CAHOST/SYSTEM"  # HIVE provenance
    assert result.ca_edit_flags_absent == 0  # decided, not a gap
    assert result.ca_host_blocked.get("esc6", 0) == 0
    con.close()


def test_esc6a_not_emitted_when_san2_false_and_no_gap() -> None:
    con = _esc6_store()
    buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            edit_flags=0,  # read-negative -> decided-safe
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
            disable_extension_list=(),
        ),
    )
    assert KIND_ESC6A not in gx._kinds(buf)  # negatively decided -> nothing
    assert result.esc6a == 0
    assert result.ca_edit_flags_absent == 0  # decided -> NO gap
    assert result.ca_host_blocked.get("esc6", 0) == 0
    con.close()


# =============================================================================
# LAYER 3 — counted gaps: every degraded branch fires its own token
# =============================================================================


def test_edit_flags_absent_counts_gap_and_blocks_esc6() -> None:
    con = _esc6_store()
    _buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            edit_flags=None,  # unread -> undecidable
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
            disable_extension_list=(),
        ),
    )
    assert result.ca_edit_flags_absent >= 1  # LOUD, counted on its own token
    assert result.ca_host_blocked.get("esc6", 0) >= 1  # still blocked
    assert result.esc6a == 0
    con.close()


def test_security_absent_forbids_manage_ca_edge() -> None:
    # FALSE-POSITIVE-FORBIDDEN: an unread Security descriptor yields NO ManageCA
    # edge, only a counted ca_security_absent gap.
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_principal(con, "n-officer", _SID_OFFICER, "User")
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            security_sd=None,  # undecidable
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
            disable_extension_list=(),
        ),
    )
    assert KIND_MANAGE_CA not in gx._kinds(buf)  # no edge from an absent SD
    assert result.manage_ca == 0
    assert result.ca_security_absent == 1  # counted on its own token
    con.close()


def test_interface_and_disable_ext_absent_count_gaps() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    _buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(interface_flags=None, disable_extension_list=None),
    )
    assert result.ca_interface_flags_absent == 1
    assert result.ca_disable_ext_absent == 1
    assert not result.ca_node_findings  # nothing decided positive -> no finding
    con.close()


def test_read_negative_and_read_empty_are_decided_no_gap_no_finding() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    _buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,  # enforced -> esc11 not vuln
            disable_extension_list=("1.2.3",),  # OID absent -> esc16 not present
        ),
    )
    assert result.ca_interface_flags_absent == 0  # read-negative => decided, no gap
    assert result.ca_disable_ext_absent == 0
    assert not result.ca_node_findings
    con.close()


def test_esc11_esc16_findings_emitted_when_positive() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    _buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            interface_flags=0x0,  # CLEAR -> ESC11 vulnerable
            disable_extension_list=(OID_NTDS_CA_SECURITY_EXT,),  # -> ESC16
        ),
    )
    props = {(f.node_id, f.prop) for f in result.ca_node_findings}
    assert ("n-entca", NODE_PROP_ESC11) in props
    assert ("n-entca", NODE_PROP_ESC16) in props
    for f in result.ca_node_findings:
        assert f.provenance.source_file == "CAHOST/SYSTEM"  # HIVE provenance on findings
    con.close()


def test_policy_module_unresolved_counts_gap() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._trusted_ca(con, [])
    gx._run_m5(con)
    _buf, result = gx._esc(
        con,
        ca_host=_ca_host_facts(
            policy_module_resolved=False,
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
            disable_extension_list=(),
        ),
    )
    assert result.ca_policy_module_unresolved == 1
    con.close()


def test_name_mismatch_is_loud_block_zero_edges() -> None:
    # A graph EnterpriseCA with NO matching hive stays a LOUD gap (never a false
    # negative): ca_host_name_mismatch + the esc6/7/11/16 blocks, and ZERO edges.
    con = _esc6_store()
    other = CaHostFacts(
        provided=True,
        cas={normalize_ca_name("some-other-ca"): _facts(ca_name="some-other-ca")},
        dcom=None,
    )
    buf, result = gx._esc(con, ca_host=other)
    assert result.ca_host_name_mismatch == 1
    assert result.ca_host_blocked.get("esc7", 0) == 1
    assert result.ca_host_blocked.get("esc11", 0) == 1
    assert result.ca_host_blocked.get("esc16", 0) == 1
    assert result.ca_host_blocked.get("esc6", 0) >= 1  # the ESC6 candidate on this CA
    assert KIND_MANAGE_CA not in gx._kinds(buf) and KIND_ESC6A not in gx._kinds(buf)
    con.close()


def test_correlation_ambiguous_flagged_name_match_still_wins() -> None:
    # The CA host whose computer node is HostsCAService-tied carries a label "ca"
    # (from _trusted_ca -> dns ca.corp.local -> but computer node label differs).
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_principal(con, "n-officer", _SID_OFFICER, "User")
    # A computer node that HOSTS the CA, with a label that does NOT match host_fqdn.
    gx._add_principal(con, "n-cahost", f"{gx._DOMAIN_SID}-2900", "Computer")
    gx._trusted_ca(con, [])
    # Seed a HostsCAService edge computer -> CA so the cross-check has a pair.
    con.execute(
        "INSERT INTO edge VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        _hosts_ca_row(),
    )
    gx._run_m5(con)
    facts = _ca_host_facts(
        host_fqdn="different-host.corp.local",  # label "different-host" != "n-cahost"
        manage_ca_sids=frozenset({_SID_OFFICER}),
        interface_flags=IF_ENFORCEENCRYPTICERTREQUEST,
        disable_extension_list=(),
    )
    buf, result = gx._esc(con, ca_host=facts)
    assert result.ca_host_correlation_ambiguous == 1  # surfaced, not silently picked
    # name match still wins -> the ManageCA edge is still emitted.
    assert (KIND_MANAGE_CA, "n-officer", "n-entca") in gx._pairs(buf)
    con.close()


def _hosts_ca_row() -> list[object]:
    from wraith.edges.models import EdgeRow

    row = EdgeRow(
        edge_id="hosts-ca-1",
        kind="HostsCAService",
        source_node_id="n-cahost",
        target_node_id="n-entca",
        is_inherited=False,
        derivation="topology",
        access_mask=None,
        object_type_guid=None,
        confidence="confirmed",
        forest_id=gx._FOREST,
        domain_id=gx._DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=gx._PROV,
    )
    return list(row.to_db_values())


def test_dcom_absent_vs_present_findings() -> None:
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_principal(con, "n-cahost", f"{gx._DOMAIN_SID}-2900", "Computer")
    gx._trusted_ca(con, [])
    con.execute("INSERT INTO edge VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", _hosts_ca_row())
    gx._run_m5(con)
    # absent DCOM -> counted gap.
    _b, absent = gx._esc(
        con,
        ca_host=_ca_host_facts(
            interface_flags=IF_ENFORCEENCRYPTICERTREQUEST, disable_extension_list=()
        ),
    )
    assert absent.dcom_restrictions_absent == 1
    # present DCOM, one unparseable SD -> finding + counted parse error.
    good_sd = _ca_security_sd([_ca_ace(CA_RIGHT_MANAGE_CA, _SID_OFFICER)])
    dcom = DcomRestrictions(
        enable_dcom="Y",
        machine_access_sd=good_sd,
        machine_launch_sd=b"not-a-descriptor",  # -> dcom_sd_parse_error
        default_access_sd=None,
        default_launch_sd=None,
        provenance=_HIVE_PROV,
    )
    reg = _facts(interface_flags=IF_ENFORCEENCRYPTICERTREQUEST, disable_extension_list=())
    facts = CaHostFacts(provided=True, cas={normalize_ca_name(reg.ca_name): reg}, dcom=dcom)
    _b2, present = gx._esc(con, ca_host=facts)
    assert present.dcom_restrictions_absent == 0
    assert present.dcom_sd_parse_error == 1
    dcom_props = [f for f in present.ca_node_findings if f.prop == NODE_PROP_DCOM]
    assert dcom_props and dcom_props[0].node_id == "n-cahost"
    assert dcom_props[0].value == "EnableDCOM=Y"  # redacted summary, no raw SD
    con.close()


# =============================================================================
# LAYER 3 — ca_security_parse_error fires on a present-but-unparseable SD
# =============================================================================


def test_ca_security_parse_error_fires_on_present_but_unparseable_sd() -> None:
    # Drive the REAL adapter read path with a present-but-unparseable Security value.
    base = "\\ControlSet001\\Services\\CertSvc\\Configuration"
    reader = _FakeReader(
        {
            "\\Select\\Current": (_REG_DWORD, 1),
            f"{base}\\Active": (_REG_SZ, "MyCA".encode("utf-16le") + b"\x00\x00"),
            f"{base}\\MyCA\\Security": (_REG_BINARY, b"garbage-not-an-SD"),
        }
    )
    reg = adapter._read_one_ca(reader, "ControlSet001", _HIVE_PROV)
    assert reg is not None
    # The adapter currently reports this as "absent" (security_sd None, empty grants);
    # the intended contract is a DISTINCT present-but-unparseable signal the composer
    # counts as ca_security_parse_error. Asserting the intended contract:
    con = gx._new_store()
    gx._add_domain(con)
    gx._add_adcs(con, "n-entca", "EnterpriseCA", name="MyCA", cert_ders=(gx._DER_CA,))
    gx._add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(gx._DER_CA,))
    gx._run_m5(con)
    facts = CaHostFacts(provided=True, cas={normalize_ca_name("MyCA"): reg}, dcom=None)
    _buf, result = gx._esc(con, ca_host=facts)
    con.close()
    assert result.ca_security_parse_error == 1  # EXPECTED-FAIL today
    assert result.ca_security_absent == 0


# =============================================================================
# LAYER 3 — regression: the all-absent path is byte-for-byte unchanged
# =============================================================================


def test_absent_ca_host_facts_identical_accounting() -> None:
    # ABSENT_CA_HOST_FACTS (provided=False) must account ESC6/7/11/16 exactly as
    # before this module: one esc7/esc11/esc16 block per CA + one esc6 per candidate.
    con = _esc6_store()
    _buf, result = gx._esc(con, ca_host=ABSENT_CA_HOST_FACTS)
    assert result.ca_host_blocked.get("esc7") == 1
    assert result.ca_host_blocked.get("esc11") == 1
    assert result.ca_host_blocked.get("esc16") == 1
    assert result.ca_host_blocked.get("esc6", 0) == 1  # the single ESC6 candidate
    # none of the NEW per-value gap tokens fire on the absent path.
    assert result.ca_security_absent == 0
    assert result.ca_edit_flags_absent == 0
    assert result.ca_interface_flags_absent == 0
    assert result.ca_disable_ext_absent == 0
    assert result.dcom_restrictions_absent == 0
    con.close()


def test_provided_but_matched_determinism_two_runs_identical() -> None:
    def snap() -> list[tuple[str, str, str, str]]:
        con = _esc6_store()
        gx._add_principal(con, "n-officer", _SID_OFFICER, "User")
        facts = _ca_host_facts(
            edit_flags=EDITF_ATTRIBUTESUBJECTALTNAME2,
            manage_ca_sids=frozenset({_SID_OFFICER}),
            interface_flags=0x0,
            disable_extension_list=(OID_NTDS_CA_SECURITY_EXT,),
        )
        buf, _r = gx._esc(con, ca_host=facts)
        out = sorted((e.edge_id, e.kind, e.source_node_id, e.target_node_id) for e in buf.edges)
        con.close()
        return out

    assert snap() == snap()


# =============================================================================
# LAYER 3 — the real-artifact anchor (DC SYSTEM+SOFTWARE; no CA, graceful)
# =============================================================================


@_needs_real
def test_real_hives_read_without_crash_and_degrade() -> None:
    facts, errors = adapter.build_ca_host_facts(
        system_hive_path=_REAL_SYSTEM,
        software_hive_path=_REAL_SOFTWARE,
        ingest_run_id=_RUN,
    )
    assert errors == 0  # both hives opened cleanly
    assert facts.provided is True
    assert facts.cas == {}  # the imaged DC runs no CertSvc CA -> graceful empty
    # the real SOFTWARE hive exercises the decoders on real bytes:
    assert facts.dcom is not None
    assert facts.dcom.enable_dcom == "Y"  # real inline-int REG_SZ decode
    assert facts.dcom.any_present is True
    assert facts.dcom.default_access_sd is None  # a genuinely-absent value -> None
    # real REG_BINARY descriptors round-trip through impacket ldaptypes:
    from wraith.analysis.adcs_esc import _sd_parses

    assert _sd_parses(facts.dcom.machine_access_sd)
    assert _sd_parses(facts.dcom.machine_launch_sd)


@_needs_real
def test_real_system_hive_path_rejection_counts_error() -> None:
    # A missing path is rejected by ensure_existing_file -> provided=False + error.
    facts, errors = adapter.build_ca_host_facts(
        system_hive_path=_REPO / "eviedence_test" / "Registry" / "DOES_NOT_EXIST",
        ingest_run_id=_RUN,
    )
    assert errors == 1 and facts.provided is False
