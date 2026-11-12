"""Coder-side sanity for the ADCS ESC composition pass (Phase 2) — not the gate.

The real test DC has no usable ADCS surface, so this drives the ESC composer with
SYNTHETIC forests crafted at the staging/builder seam: REAL ``nTSecurityDescriptor``
blobs (impacket ``ldaptypes`` — enroll ext-right ``0e10c968...``, GenericAll,
GenericWrite), REAL self-signed CA certs (``cryptography``), and known
``msPKI-*`` integers. Each test runs the FULL Module-5 edge pass (``compute_edges``)
to produce the confirmed base + Phase-1 topology edges, then runs
``compute_adcs_esc`` and asserts a KNOWN expected ESC output.

DC-config ESCs (ESC9/10) are driven with an injected :class:`DcConfigFlags`
(a real ``.regf`` fixture is deferred to the tester's real-DC parity gate); the
``read_dc_config_flags`` I/O seam is exercised for its graceful-degradation
accounting. The CRITICAL negative is the ESC6-shaped template with NO CA hive,
which MUST yield a counted ``ca_host_facts_absent`` and NO ``ADCSESC6`` edge.

The authoritative three-layer gate is the tester's; these are coder sanity.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import duckdb
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from wraith.analysis.adcs_esc import (
    ABSENT_CA_HOST_FACTS,
    KIND_ENROLL_ON_BEHALF_OF,
    KIND_ESC1,
    KIND_ESC3,
    KIND_ESC4,
    KIND_ESC9,
    KIND_ESC10A,
    KIND_ESC10B,
    KIND_ESC13,
    KIND_ESC15,
    KIND_GOLDEN_CERT,
    AdcsEscResult,
    CaHostFacts,
    DcConfigFlags,
    _EscGraph,
    _low_priv_enrollable,
    compute_adcs_esc,
    decode_template,
    effective_ekus,
    is_high_priv_sid,
    read_dc_config_flags,
)
from wraith.case.ingest_run import IngestRun
from wraith.edges import compute_edges
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import AdcsRow, ContainerRow, PrincipalRow, StagingObjectRow
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000e5c0")
_FOREST = "f"
_DOMAIN_SID = "S-1-5-21-9-9-9"
_SCOPING = (_FOREST, _DOMAIN_SID, "corp.local")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="a" * 64,
    source_object_id="src",
    directory_timestamp=datetime(2024, 1, 1, tzinfo=UTC),
    ingest_run_id=_RUN,
)

# EKU OIDs (public [MS-CRTD] facts).
_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_EKU_AGENT = "1.3.6.1.4.1.311.20.2.1"
_GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

# Well-known SIDs in the synthetic domain.
_SID_DOMAIN_USERS = f"{_DOMAIN_SID}-513"  # low-priv broad group
_SID_DOMAIN_ADMINS = f"{_DOMAIN_SID}-512"  # high-priv
_SID_ATTACKER = f"{_DOMAIN_SID}-1201"  # a low-priv attacker principal

# A reusable self-signed CA cert (generated once; ECDSA DER carries a nonce).
_K_CA = ec.generate_private_key(ec.SECP256R1())


def _ca_cert() -> bytes:
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corp-CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corp-CA")]))
        .public_key(_K_CA.public_key())
        .serial_number(7)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .sign(_K_CA, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


_DER_CA = _ca_cert()


# --- real-SD builders (impacket ldaptypes) -----------------------------------


def _object_ace(mask: int, sid: str, guid: str) -> object:
    from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACE, LDAP_SID

    ldap_sid = LDAP_SID()
    ldap_sid.fromCanonical(sid)
    body = ACCESS_ALLOWED_OBJECT_ACE()
    body["Mask"] = ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["ObjectTypeLen"] = 16
    body["InheritedObjectTypeLen"] = 0
    body["ObjectType"] = uuid.UUID(guid).bytes_le
    body["InheritedObjectType"] = b""
    body["Flags"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    body["Sid"] = ldap_sid
    ace = ACE()
    ace["AceType"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    ace["Ace"] = body
    return ace


def _plain_ace(mask: int, sid: str) -> object:
    from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, LDAP_SID

    ldap_sid = LDAP_SID()
    ldap_sid.fromCanonical(sid)
    body = ACCESS_ALLOWED_ACE()
    body["Mask"] = ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = ldap_sid
    ace = ACE()
    ace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    ace["Ace"] = body
    return ace


def _sd(aces: list[object], *, owner_sid: str = "S-1-5-18") -> bytes:
    """Build a self-relative SD with an explicit owner + a DACL.

    Default owner is Local System (``S-1-5-18``) -> M5 emits no ``Owns`` edge
    (noise). Pass a low-priv ``owner_sid`` to exercise the ``Owns`` takeover path.
    """
    from impacket.ldap.ldaptypes import ACL, LDAP_SID, SR_SECURITY_DESCRIPTOR

    owner = LDAP_SID()
    owner.fromCanonical(owner_sid)
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


def _enroll_sd(sid: str) -> bytes:
    """A DACL granting Certificate-Enrollment (control-access + enroll GUID) to ``sid``."""
    return _sd([_object_ace(0x100, sid, _GUID_ENROLL)])


_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000


# --- store + row helpers -----------------------------------------------------


def _pki_flags(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "certificate_name_flag": None,
        "enrollment_flag": None,
        "private_key_flag": None,
        "ra_signature": None,
        "template_schema_version": None,
        "extended_key_usage": [],
        "certificate_application_policy": [],
        "expiration_period": None,
        "overlap_period": None,
        "revision": None,
        "flags": None,
        "cn": None,
        "ca_certificate": [],
        "dns_host_name": None,
        "certificate_policy": [],
        "ra_application_policies": None,
        "oid_to_group_link": None,
        "oid": None,
    }
    base.update(over)
    return base


def _insert(con: duckdb.DuckDBPyConnection, table: str, values: tuple[object, ...]) -> None:
    placeholders = ",".join("?" * len(values))
    con.execute(f"INSERT INTO {table} VALUES ({placeholders})", list(values))  # noqa: S608


def _new_store() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con


def _add_adcs(
    con: duckdb.DuckDBPyConnection,
    node_id: str,
    adcs_type: str,
    *,
    name: str | None = None,
    pki_flags: dict[str, object] | None = None,
    published: list[str] | None = None,
    cert_ders: tuple[bytes, ...] = (),
    raw_sd: bytes | None = None,
) -> None:
    adcs = AdcsRow(
        node_id=node_id,
        object_guid=None,
        name=name or node_id,
        adcs_type=adcs_type,
        pki_flags=pki_flags or _pki_flags(),
        enrollment_rights=[],
        published_templates=published or [],
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=_PROV,
    )
    attrs = {"cACertificate": [{"__bytes_hex__": der.hex()} for der in cert_ders]}
    staging = StagingObjectRow(
        node_id=node_id,
        dnt=1,
        object_guid=None,
        object_sid=None,
        object_class=[adcs_type],
        raw_sd=raw_sd,
        attributes_json=json.dumps(attrs),
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=_PROV,
    )
    _insert(con, "adcs", adcs.to_db_values())
    _insert(con, "staging_object", staging.to_db_values())


def _add_domain(con: duckdb.DuckDBPyConnection) -> None:
    domain = ContainerRow(
        node_id="n-domain",
        object_guid=None,
        object_sid=_DOMAIN_SID,
        distinguished_name="DC=corp,DC=local",
        container_type="Domain",
        parent_node_id=None,
        gplinks=[],
        functional_level=None,
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=_PROV,
    )
    _insert(con, "container", domain.to_db_values())


def _add_principal(
    con: duckdb.DuckDBPyConnection,
    node_id: str,
    sid: str,
    ptype: str,
    *,
    dn: str | None = None,
    spns: list[str] | None = None,
    raw_sd: bytes | None = None,
) -> None:
    principal = PrincipalRow(
        node_id=node_id,
        object_sid=sid,
        object_guid=None,
        principal_type=ptype,
        samaccountname=node_id,
        upn=None,
        distinguished_name=dn,
        display_name=None,
        description=None,
        uac_flags=None,
        enabled=True,
        admincount=None,
        spns=spns or [],
        sid_history=[],
        primary_group_id=None,
        pwd_last_set=None,
        last_logon_timestamp=None,
        when_created=None,
        when_changed=None,
        secret_refs=[],
        behavior_summary_ref=None,
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        provenance=_PROV,
    )
    _insert(con, "principal", principal.to_db_values())
    if raw_sd is not None:
        staging = StagingObjectRow(
            node_id=node_id,
            dnt=1,
            object_guid=None,
            object_sid=sid,
            object_class=[ptype],
            raw_sd=raw_sd,
            attributes_json="{}",
            forest_id=_FOREST,
            domain_id=_DOMAIN_SID,
            domain_fqdn="corp.local",
            provenance=_PROV,
        )
        _insert(con, "staging_object", staging.to_db_values())


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


class _Buffer:
    def __init__(self) -> None:
        self.edges: list[object] = []

    def add(self, edge: object) -> None:
        self.edges.append(edge)


def _run_m5(con: duckdb.DuckDBPyConnection) -> None:
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    compute_edges(
        con,
        run,
        _empty_schema(),
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
    )


def _esc(
    con: duckdb.DuckDBPyConnection,
    *,
    dc_config: DcConfigFlags | None = None,
    ca_host: CaHostFacts = ABSENT_CA_HOST_FACTS,
) -> tuple[_Buffer, AdcsEscResult]:
    buf = _Buffer()
    result = compute_adcs_esc(
        con,
        buf,
        domain_node_id="n-domain",
        scoping=_SCOPING,
        dc_config=dc_config or DcConfigFlags(),
        ca_host_facts=ca_host,
    )
    return buf, result


def _pairs(buf: _Buffer) -> set[tuple[str, str, str]]:
    return {(e.kind, e.source_node_id, e.target_node_id) for e in buf.edges}  # type: ignore[attr-defined]


def _enrollable_template(**flags: object) -> dict[str, object]:
    """A V2 template published to the trusted CA, enrollable by Domain Users."""
    base = _pki_flags(template_schema_version="2", **flags)
    return base


def _vulnerable_ca_forest(con: duckdb.DuckDBPyConnection) -> None:
    """Common scaffolding: a trusted Enterprise CA + NTAuth + low-priv enroll group."""
    _add_domain(con)
    _add_principal(con, "n-grp513", _SID_DOMAIN_USERS, "Group")
    _add_adcs(
        con,
        "n-entca",
        "EnterpriseCA",
        pki_flags=_pki_flags(dns_host_name="ca.corp.local"),
        published=[
            "ESC1Tpl",
            "ESC4Tpl",
            "ESC9Tpl",
            "ESC13Tpl",
            "ESC15Tpl",
            "AgentTpl",
            "TargetTpl",
            "ESC6Tpl",
        ],
        cert_ders=(_DER_CA,),
    )
    _add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(_DER_CA,))


# =============================================================================
# Pure unit tests
# =============================================================================


def test_is_high_priv_sid() -> None:
    assert is_high_priv_sid(f"{_DOMAIN_SID}-512") is True  # Domain Admins
    assert is_high_priv_sid(f"{_DOMAIN_SID}-519") is True  # Enterprise Admins
    assert is_high_priv_sid("S-1-5-32-544") is True  # Administrators
    assert is_high_priv_sid(f"{_DOMAIN_SID}-513") is False  # Domain Users
    assert is_high_priv_sid(f"{_DOMAIN_SID}-1201") is False  # a normal user
    assert is_high_priv_sid(None) is False  # SID-less node is not an admin


def test_effective_ekus_v1_vs_v2() -> None:
    # V1: EKUs come ONLY from pKIExtendedKeyUsage (no application-policy attr).
    assert effective_ekus(1, ("A",), ("B",)) == ("A",)
    assert effective_ekus(None, ("A",), ("B",)) == ("A",)
    # V2+: application policy governs; falls back to pKIExtendedKeyUsage if empty.
    assert effective_ekus(2, ("A",), ("B",)) == ("B",)
    assert effective_ekus(4, ("A",), ()) == ("A",)


def test_decode_template_flag_parse_error_counted() -> None:
    tpl = decode_template("n", "n", _pki_flags(certificate_name_flag="not-an-int"), _PROV)
    assert tpl.flag_parse_error == 1  # unparseable flag counted, never a silent wrong answer
    assert tpl.name_flag is None


def test_decode_template_v1_ignores_enrollment_flag() -> None:
    # A V1 template has no msPKI-Enrollment-Flag/RA-Signature -> approval off, RA 0.
    tpl = decode_template(
        "n",
        "n",
        _pki_flags(template_schema_version="1", enrollment_flag="2", ra_signature="1"),
        _PROV,
    )
    assert tpl.is_v1 is True
    assert tpl.manager_approval is False and tpl.ra_signatures_required == 0


def test_low_priv_enrollable_uses_m4_closure() -> None:
    # Enroll granted ONLY to a high-priv group, but that group has a low-priv
    # effective member (via the M4 closure) -> still low-priv enrollable.
    graph = _EscGraph()
    graph.sid_of = {"g-admins": _SID_DOMAIN_ADMINS, "u-low": _SID_ATTACKER}
    graph.members_of = {"g-admins": {"u-low"}}
    assert _low_priv_enrollable(frozenset({"g-admins"}), graph) is True
    # With no low-priv member anywhere, an admins-only grant is NOT low-priv.
    graph.members_of = {"g-admins": set()}
    assert _low_priv_enrollable(frozenset({"g-admins"}), graph) is False


def test_dc_config_flag_properties() -> None:
    assert DcConfigFlags().weak_binding is None  # unread -> undecidable
    assert DcConfigFlags(strong_binding=2).weak_binding is False
    assert DcConfigFlags(strong_binding=1).weak_binding is True
    assert DcConfigFlags(strong_binding=0).strong_binding_disabled is True
    assert DcConfigFlags(cert_mapping_methods=0x4).upn_cert_mapping is True
    assert DcConfigFlags(cert_mapping_methods=0x18).upn_cert_mapping is False


def test_read_dc_config_flags_degrades_on_bad_hive(tmp_path: Path) -> None:
    # A non-hive file is not a crash: it is a counted read error with all-None flags.
    bad = tmp_path / "SYSTEM"
    bad.write_bytes(b"not a regf hive")
    flags, errors = read_dc_config_flags(bad)
    assert errors == 1 and flags.hive_read is False
    assert flags.strong_binding is None and flags.cert_mapping_methods is None


def test_read_dc_config_flags_rejects_missing_path(tmp_path: Path) -> None:
    flags, errors = read_dc_config_flags(tmp_path / "does-not-exist")
    assert errors == 1 and flags.hive_read is False


# =============================================================================
# ESC1 (fully offline)
# =============================================================================


def test_esc1_full_offline() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1Tpl",
        pki_flags=_enrollable_template(
            certificate_name_flag="1",  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag="0",  # no manager approval
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC1, "n-grp513", "n-domain") in _pairs(buf)
    assert result.esc1 == 1
    # Every ESC edge is an inferred, fully-provenanced §4 row.
    for e in buf.edges:
        assert e.confidence == "inferred"  # type: ignore[attr-defined]
        assert e.provenance.image_sha256 == "a" * 64  # type: ignore[attr-defined]
    con.close()


def test_esc1_not_emitted_from_high_priv_only() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-admins", _SID_DOMAIN_ADMINS, "Group")
    _add_adcs(con, "n-entca", "EnterpriseCA", published=["ESC1Tpl"], cert_ders=(_DER_CA,))
    _add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(_DER_CA,))
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1Tpl",
        pki_flags=_enrollable_template(
            certificate_name_flag="1",
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_ADMINS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc1 == 0  # admins-only enroll is not an escalation
    con.close()


def test_esc1_suppressed_when_manager_approval_on() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1Tpl",
        pki_flags=_enrollable_template(
            certificate_name_flag="1",
            enrollment_flag="2",  # CT_FLAG_PEND_ALL_REQUESTS -> approval required
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc1 == 0
    con.close()


# =============================================================================
# ESC4 (fully offline)
# =============================================================================


def test_esc4_template_write() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc4",
        "CertTemplate",
        name="ESC4Tpl",
        pki_flags=_enrollable_template(),
        raw_sd=_sd([_plain_ace(_GENERIC_ALL, _SID_DOMAIN_USERS)]),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC4, "n-grp513", "n-esc4") in _pairs(buf)
    assert result.esc4 == 1
    con.close()


def test_esc4_kind_is_wraith_native_not_bh_composite() -> None:
    # Our ESC4 is a control fact (holder -> CertTemplate); it MUST NOT be emitted
    # under BloodHound's composite "ADCSESC4" (principal -> Domain) kind string, or
    # the M6 export would conflate the two.
    assert KIND_ESC4 != "ADCSESC4"
    assert "ADCSESC4" not in KIND_ESC4  # no prefix collision either


def test_esc4_owns_takeover_path() -> None:
    # An object OWNER can rewrite the template DACL and reconfigure it, so an owner
    # takeover MUST qualify for ESC4 (M5 emits Owns ~3714 on the real DC; it was
    # previously missed). The template is owned by a low-priv group, no explicit
    # DACL grant.
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc4owns",
        "CertTemplate",
        name="ESC4OwnsTpl",
        pki_flags=_enrollable_template(),
        raw_sd=_sd([], owner_sid=_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC4, "n-grp513", "n-esc4owns") in _pairs(buf)
    assert result.esc4 == 1
    con.close()


# =============================================================================
# ESC13 (fully offline)
# =============================================================================


def test_esc13_issuance_policy_group_link() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_principal(
        con, "n-pkiadmins", f"{_DOMAIN_SID}-1105", "Group", dn="CN=PKI Admins,DC=corp,DC=local"
    )
    policy_oid = "1.3.6.1.4.1.311.21.8.1.1"
    _add_adcs(
        con,
        "n-policy",
        "IssuancePolicy",
        pki_flags=_pki_flags(oid=policy_oid, oid_to_group_link="CN=PKI Admins,DC=corp,DC=local"),
    )
    _add_adcs(
        con,
        "n-esc13",
        "CertTemplate",
        name="ESC13Tpl",
        pki_flags=_enrollable_template(certificate_policy=[policy_oid]),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC13, "n-grp513", "n-pkiadmins") in _pairs(buf)
    assert result.esc13 == 1
    esc13 = next(e for e in buf.edges if e.kind == KIND_ESC13)  # type: ignore[attr-defined]
    assert "client-auth" in esc13.derivation  # type: ignore[attr-defined]
    con.close()


def test_esc13_suppressed_when_not_client_auth_capable() -> None:
    # The OID-linked group is injected during PKINIT, so a template that cannot
    # authenticate (e.g. an EFS-only EKU) yields NO ESC13 (domain-expert fix).
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_principal(
        con, "n-pkiadmins", f"{_DOMAIN_SID}-1105", "Group", dn="CN=PKI Admins,DC=corp,DC=local"
    )
    policy_oid = "1.3.6.1.4.1.311.21.8.1.1"
    _add_adcs(
        con,
        "n-policy",
        "IssuancePolicy",
        pki_flags=_pki_flags(oid=policy_oid, oid_to_group_link="CN=PKI Admins,DC=corp,DC=local"),
    )
    _add_adcs(
        con,
        "n-esc13",
        "CertTemplate",
        name="ESC13Tpl",
        pki_flags=_enrollable_template(
            certificate_policy=[policy_oid],
            certificate_application_policy=["1.3.6.1.4.1.311.10.3.4"],  # EFS, not client-auth
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc13 == 0
    con.close()


# =============================================================================
# ESC15 (fully offline, informational/patched)
# =============================================================================


def test_esc15_schema_v1_supplies_subject() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc15",
        "CertTemplate",
        name="ESC15Tpl",
        pki_flags=_pki_flags(
            template_schema_version="1",  # V1
            certificate_name_flag="1",  # ENROLLEE_SUPPLIES_SUBJECT
            extended_key_usage=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC15, "n-grp513", "n-domain") in _pairs(buf)
    assert result.esc15 == 1
    con.close()


# =============================================================================
# ESC3 + EnrollOnBehalfOf (ntds-derivable; agent restriction undecidable)
# =============================================================================


def test_esc3_enroll_on_behalf_of() -> None:
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-agent",
        "CertTemplate",
        name="AgentTpl",
        pki_flags=_enrollable_template(
            enrollment_flag="0",  # approval OFF
            ra_signature="0",  # no authorized signature required
            certificate_application_policy=[_EKU_AGENT],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _add_adcs(
        con,
        "n-target",
        "CertTemplate",
        name="TargetTpl",
        pki_flags=_enrollable_template(certificate_application_policy=[_EKU_CLIENT_AUTH]),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    pairs = _pairs(buf)
    assert (KIND_ENROLL_ON_BEHALF_OF, "n-agent", "n-target") in pairs
    assert (KIND_ESC3, "n-grp513", "n-domain") in pairs
    assert result.enroll_on_behalf_of == 1 and result.esc3 == 1
    # Agent restrictions live on the CA host -> undecidable -> counted + noted.
    assert result.ca_host_blocked.get("esc3_agent", 0) >= 1
    esc3_edge = next(e for e in buf.edges if e.kind == KIND_ESC3)  # type: ignore[attr-defined]
    assert "undecidable[agent-restrictions:ca-host]" in esc3_edge.derivation  # type: ignore[attr-defined]
    con.close()


def test_esc3_suppressed_when_agent_requires_approval() -> None:
    # An agent template that still requires manager approval cannot be low-priv
    # obtained -> no EnrollOnBehalfOf and no ESC3 (domain-expert offline-flag fix).
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-agent",
        "CertTemplate",
        name="AgentTpl",
        pki_flags=_enrollable_template(
            enrollment_flag="2",  # CT_FLAG_PEND_ALL_REQUESTS -> manager approval ON
            ra_signature="0",
            certificate_application_policy=[_EKU_AGENT],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _add_adcs(
        con,
        "n-target",
        "CertTemplate",
        name="TargetTpl",
        pki_flags=_enrollable_template(certificate_application_policy=[_EKU_CLIENT_AUTH]),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.enroll_on_behalf_of == 0 and result.esc3 == 0
    con.close()


# =============================================================================
# ESC9 (DC-config: weak binding)
# =============================================================================


_SID_VICTIM = f"{_DOMAIN_SID}-1301"  # an enrollable victim account


def _esc9_store(*, victim_enrollable: bool = True) -> duckdb.DuckDBPyConnection:
    """A NO_SECURITY_EXTENSION client-auth template + an attacker who holds a
    GenericWrite (UPN/altSecurityIdentities control) over a victim USER.

    Corrected ESC9 (domain-expert review): the source is the WRITING principal, not
    an arbitrary enrollee, and the victim must itself be enrollable in the template.
    When ``victim_enrollable`` is False, the victim has no enroll right -> ESC9 must
    NOT fire (the write alone is not enough).
    """
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_principal(con, "n-attacker", _SID_ATTACKER, "Group")
    # The victim can be enrolled in the template (its SID holds Enroll on ESC9Tpl)
    # AND the attacker can rewrite the victim's UPN (GenericWrite on the victim).
    _add_principal(
        con,
        "n-victim",
        _SID_VICTIM,
        "User",
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_ATTACKER)]),
    )
    _add_adcs(
        con,
        "n-esc9",
        "CertTemplate",
        name="ESC9Tpl",
        pki_flags=_enrollable_template(
            enrollment_flag="524288",  # 0x80000 CT_FLAG_NO_SECURITY_EXTENSION
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        # Enroll granted to the victim (enrollable) or to Domain Users (victim NOT
        # enrollable -> negative case).
        raw_sd=_enroll_sd(_SID_VICTIM if victim_enrollable else _SID_DOMAIN_USERS),
    )
    _run_m5(con)
    return con


def test_esc9_requires_victim_write_and_enrollable_victim() -> None:
    con = _esc9_store()
    # Both DC flags read so ESC10 is DECIDED and does not pollute dc_config_absent;
    # 0x18 has no UPN bit, strong_binding=0 is weak (ESC9) but the user victim is
    # not a computer so ESC10b does not fire either.
    buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=0, cert_mapping_methods=0x18, hive_read=True)
    )
    # Source is the WRITING principal (n-attacker), NOT the enrollee.
    assert (KIND_ESC9, "n-attacker", "n-domain") in _pairs(buf)
    assert result.esc9 == 1 and result.dc_config_absent == 0
    esc9 = next(e for e in buf.edges if e.kind == KIND_ESC9)  # type: ignore[attr-defined]
    assert "victim-enrollable" in esc9.derivation  # type: ignore[attr-defined]
    con.close()


def test_esc9_not_fired_when_victim_not_enrollable() -> None:
    # Attacker can rewrite the victim's UPN, but the victim cannot enroll in the
    # NO_SEC_EXT template -> no cert request -> NO ESC9 (removes the old false path
    # that fired for every enrollee).
    con = _esc9_store(victim_enrollable=False)
    _buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=0, cert_mapping_methods=0x18, hive_read=True)
    )
    assert result.esc9 == 0
    con.close()


def test_esc9_undecidable_without_dc_hive() -> None:
    con = _esc9_store()
    buf, result = _esc(con)  # DC hive not read
    assert result.esc9 == 0
    assert result.dc_config_absent >= 1  # LOUD counted gap, no edge
    # Engine-plane honesty (doc 16 §C): with NO hive, the no-hive subset is counted in
    # lockstep with the superset, so hive_read=False is never read as "safe".
    assert result.dc_config_no_hive >= 1
    assert result.dc_config_no_hive == result.dc_config_absent
    assert KIND_ESC9 not in {e.kind for e in buf.edges}  # type: ignore[attr-defined]
    con.close()


def test_esc9_suppressed_when_binding_full() -> None:
    con = _esc9_store()
    _buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=2, cert_mapping_methods=0x18, hive_read=True)
    )
    assert result.esc9 == 0 and result.dc_config_absent == 0  # Full binding -> safe, decided
    con.close()


# =============================================================================
# ESC10a / ESC10b (DC-config: UPN mapping / disabled binding)
# =============================================================================


def _victim_store() -> duckdb.DuckDBPyConnection:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-attacker", _SID_ATTACKER, "Group")
    # A victim USER the attacker can GenericWrite (-> can set UPN) and a victim
    # COMPUTER the attacker can GenericWrite (-> can set dNSHostName).
    _add_principal(
        con,
        "n-victim-user",
        f"{_DOMAIN_SID}-1301",
        "User",
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_ATTACKER)]),
    )
    _add_principal(
        con,
        "n-victim-comp",
        f"{_DOMAIN_SID}-1302",
        "Computer",
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_ATTACKER)]),
    )
    _run_m5(con)
    return con


def test_esc10a_upn_mapping() -> None:
    con = _victim_store()
    buf, result = _esc(con, dc_config=DcConfigFlags(cert_mapping_methods=0x4, hive_read=True))
    pairs = _pairs(buf)
    assert (KIND_ESC10A, "n-attacker", "n-victim-user") in pairs
    assert (KIND_ESC10A, "n-attacker", "n-victim-comp") in pairs
    assert result.esc10a == 2
    con.close()


def test_esc10b_weak_binding_computer_only() -> None:
    con = _victim_store()
    buf, result = _esc(con, dc_config=DcConfigFlags(strong_binding=0, hive_read=True))
    pairs = _pairs(buf)
    # ESC10b targets only the COMPUTER victim (dNSHostName control).
    assert (KIND_ESC10B, "n-attacker", "n-victim-comp") in pairs
    assert (KIND_ESC10B, "n-attacker", "n-victim-user") not in pairs
    assert result.esc10b == 1
    con.close()


def test_esc10_undecidable_without_dc_hive() -> None:
    con = _victim_store()
    _buf, result = _esc(con)  # neither flag read
    assert result.esc10a == 0 and result.esc10b == 0
    assert result.dc_config_absent == 2  # one per undecidable branch (10a + 10b)
    # NO hive -> the no-hive subset equals the superset (both branches attributable
    # to the absent hive, not an unset value).
    assert result.dc_config_no_hive == 2
    con.close()


def test_esc10_hive_present_but_values_unset_is_distinct_from_no_hive() -> None:
    """THE two-plane distinctness assertion (doc 16 §C): a SYSTEM hive WAS read but
    both cert-mapping values are unset -> still undecidable, counted on the superset
    ``dc_config_absent`` but NOT on the ``dc_config_no_hive`` subset. This is what lets
    an operator tell "no hive supplied" from "hive read, value unset"."""
    con = _victim_store()
    _buf, result = _esc(con, dc_config=DcConfigFlags(hive_read=True))  # read, both None
    assert result.esc10a == 0 and result.esc10b == 0
    assert result.dc_config_absent == 2  # undecidable: value unset
    assert result.dc_config_no_hive == 0  # but NOT a no-hive gap (the hive was read)
    con.close()


# =============================================================================
# GoldenCert (fully offline)
# =============================================================================


def test_golden_cert() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-cahost", f"{_DOMAIN_SID}-1500", "Computer", spns=["HOST/ca.corp.local"])
    _add_adcs(
        con,
        "n-entca",
        "EnterpriseCA",
        pki_flags=_pki_flags(dns_host_name="ca.corp.local"),
        cert_ders=(_DER_CA,),
    )
    _add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(_DER_CA,))
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_GOLDEN_CERT, "n-cahost", "n-domain") in _pairs(buf)
    assert result.golden_cert == 1
    con.close()


# =============================================================================
# CRITICAL: ESC6-shaped template, NO CA hive -> counted gap, NO edge
# =============================================================================


def test_esc6_shaped_template_is_undecidable_negative() -> None:
    """An enrollable client-auth template (supplies-subject OFF, so NOT ESC1)
    published to a trusted CA: the ESC6 verdict needs the CA EditFlags
    (EDITF_ATTRIBUTESUBJECTALTNAME2) which lives ONLY in the CA host hive. With no
    CA hive this MUST be a counted ``ca_host_facts_absent`` gap and NO ADCSESC6
    edge (prove: no false positive AND no silent drop)."""
    con = _new_store()
    _vulnerable_ca_forest(con)
    _add_adcs(
        con,
        "n-esc6",
        "CertTemplate",
        name="ESC6Tpl",
        pki_flags=_enrollable_template(
            certificate_name_flag="0",  # ENROLLEE_SUPPLIES_SUBJECT OFF -> not ESC1
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    kinds = {e.kind for e in buf.edges}  # type: ignore[attr-defined]
    # No false ESC6 edge, and (because supplies-subject is off) no false ESC1.
    assert "ADCSESC6" not in kinds
    assert KIND_ESC1 not in kinds
    # The ESC6 undecidability is LOUD and counted (never a silent absence).
    assert result.ca_host_blocked.get("esc6", 0) >= 1
    assert result.ca_host_facts_absent >= 1
    # It is also recorded in the authoritative DuckDB edge table as absent (no row).
    rows = con.execute("SELECT count(*) FROM edge WHERE kind = 'ADCSESC6'").fetchone()
    assert rows is not None and rows[0] == 0
    con.close()


def test_esc7_11_16_counted_per_ca() -> None:
    con = _new_store()
    _add_domain(con)
    _add_adcs(con, "n-entca", "EnterpriseCA", cert_ders=(_DER_CA,))
    _add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(_DER_CA,))
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.ca_host_blocked.get("esc7") == 1
    assert result.ca_host_blocked.get("esc11") == 1
    assert result.ca_host_blocked.get("esc16") == 1
    con.close()


# =============================================================================
# Determinism + no-ADCS no-op
# =============================================================================


def test_determinism_two_passes_identical() -> None:
    def snapshot() -> list[tuple[str, str, str, str]]:
        con = _new_store()
        _vulnerable_ca_forest(con)
        _add_adcs(
            con,
            "n-esc1",
            "CertTemplate",
            name="ESC1Tpl",
            pki_flags=_enrollable_template(
                certificate_name_flag="1",
                enrollment_flag="0",
                ra_signature="0",
                certificate_application_policy=[_EKU_CLIENT_AUTH],
            ),
            raw_sd=_enroll_sd(_SID_DOMAIN_USERS),
        )
        _run_m5(con)
        buf, _result = _esc(con)
        snap = sorted(
            (e.edge_id, e.kind, e.source_node_id, e.target_node_id)  # type: ignore[attr-defined]
            for e in buf.edges
        )
        con.close()
        return snap

    assert snapshot() == snapshot()


def test_no_adcs_surface_is_noop() -> None:
    # A forest with no ADCS objects (the real test DC) yields ~0 ESC edges.
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-grp513", _SID_DOMAIN_USERS, "Group")
    _run_m5(con)
    buf, result = _esc(con)
    assert result.edges_total == 0
    assert result.ca_host_facts_absent == 0  # no CA -> nothing undecidable either
    assert len(buf.edges) == 0
    con.close()
