"""Tester GATE for Module 8 — ADCS ESC composition (``wraith/analysis/adcs_esc.py``).

This is the AUTHORITATIVE three-layer gate, written independently of the coder's
``tests/test_adcs_esc_sanity.py``. Fixtures are re-derived from the §2.3 ESC matrix
in ``docs/research/11-adcs-edges-decisions.md`` using REAL ``impacket`` security
descriptors (enroll ext-right ``0e10c968...`` / GenericAll / GenericWrite), REAL
self-signed CA certs (``cryptography``), and known ``msPKI-*`` integers. Every ESC
positive, every suppression, the ESC6/7/11/16 undecidable-negative accounting, the
V1-vs-V2 EKU sourcing split, the DC-hive reader against the REAL imaged DC SYSTEM
hive, determinism, and robustness are asserted against hand-derived expectations.

🧪 synthetic-validated: the real test DC (``eviedence_test``) has no usable ADCS, so
the ESC composition itself is driven by crafted forests; the ONE real-artifact
anchor is the imaged DC's own ``SYSTEM`` hive (ESC9/10 DC-config reader).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest
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
    run_adcs_esc,
)
from wraith.case.ingest_run import IngestRun
from wraith.edges import compute_edges
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import AdcsRow, ContainerRow, PrincipalRow, StagingObjectRow
from wraith.parsing.schema import NtdsSchema
from wraith.provenance.models import ProvenanceStruct

# --- scoping / provenance constants ------------------------------------------
_RUN = uuid.UUID("00000000-0000-0000-0000-0000000061ea")
_FOREST = "forest-gate"
_DOMAIN_SID = "S-1-5-21-7-7-7"
_SCOPING = (_FOREST, _DOMAIN_SID, "corp.local")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="b" * 64,
    source_object_id="src",
    directory_timestamp=datetime(2024, 6, 1, tzinfo=UTC),
    ingest_run_id=_RUN,
)

# --- public [MS-CRTD] EKU facts ----------------------------------------------
_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_EKU_SMARTCARD = "1.3.6.1.4.1.311.20.2.2"
_EKU_AGENT = "1.3.6.1.4.1.311.20.2.1"
_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"  # NOT an AD-client-auth EKU
_GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

# --- synthetic SIDs ----------------------------------------------------------
_SID_USERS = f"{_DOMAIN_SID}-513"  # Domain Users (low-priv broad group)
_SID_ADMINS = f"{_DOMAIN_SID}-512"  # Domain Admins (high-priv)
_SID_ATTACKER = f"{_DOMAIN_SID}-1337"  # a low-priv attacker principal

_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_CONTROL_ACCESS = 0x00000100

# --- the real imaged DC SYSTEM hive (the single real-artifact anchor) --------
_REPO = Path(__file__).resolve().parent.parent
_REAL_SYSTEM = _REPO / "eviedence_test" / "Registry" / "SYSTEM"
_real_system_present = _REAL_SYSTEM.is_file()
_needs_real_system = pytest.mark.skipif(
    not _real_system_present, reason="needs eviedence_test Registry SYSTEM hive present"
)

# A reusable self-signed CA cert (ECDSA DER carries a nonce so it is unique).
_K_CA = ec.generate_private_key(ec.SECP256R1())


def _ca_cert() -> bytes:
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gate-CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gate-CA")]))
        .public_key(_K_CA.public_key())
        .serial_number(42)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .sign(_K_CA, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


_DER_CA = _ca_cert()


# =============================================================================
# REAL-SD builders (impacket ldaptypes) — independent of the coder's helpers
# =============================================================================


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


def _sd(aces: list[object], owner_sid: str = "S-1-5-18") -> bytes:
    """Self-relative SD with ``owner_sid`` (default Local-System: no Owns noise) + DACL.

    M5 emits an ``Owns`` edge from a non-noise owner, so passing a real principal SID
    here lets the fixture exercise the owner-takeover (ESC4) path.
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
    return _sd([_object_ace(_CONTROL_ACCESS, sid, _GUID_ENROLL)])


# =============================================================================
# Store + row helpers (DB plumbing — NOT the logic under test)
# =============================================================================


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


def _v2(**flags: object) -> dict[str, object]:
    return _pki_flags(template_schema_version="2", **flags)


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


def _add_effective_membership(
    con: duckdb.DuckDBPyConnection, group_node_id: str, members: list[str]
) -> None:
    """Seed the M4 closure directly (group -> effective members), as M4 would."""
    for member in members:
        con.execute(
            "INSERT INTO effective_membership "
            "(group_node_id, member_node_id, forest_id, domain_id) VALUES (?, ?, ?, ?)",
            [group_node_id, member, _FOREST, _DOMAIN_SID],
        )


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
    domain_node_id: str | None = "n-domain",
) -> tuple[_Buffer, AdcsEscResult]:
    buf = _Buffer()
    result = compute_adcs_esc(
        con,
        buf,
        domain_node_id=domain_node_id,
        scoping=_SCOPING,
        dc_config=dc_config or DcConfigFlags(),
        ca_host_facts=ca_host,
    )
    return buf, result


def _pairs(buf: _Buffer) -> set[tuple[str, str, str]]:
    return {(e.kind, e.source_node_id, e.target_node_id) for e in buf.edges}  # type: ignore[attr-defined]


def _kinds(buf: _Buffer) -> set[str]:
    return {e.kind for e in buf.edges}  # type: ignore[attr-defined]


def _trusted_ca(con: duckdb.DuckDBPyConnection, published: list[str]) -> None:
    """A trusted EnterpriseCA (+ NTAuth anchor) publishing ``published`` templates."""
    _add_adcs(
        con,
        "n-entca",
        "EnterpriseCA",
        pki_flags=_pki_flags(dns_host_name="ca.corp.local"),
        published=published,
        cert_ders=(_DER_CA,),
    )
    _add_adcs(con, "n-ntauth", "NTAuthStore", cert_ders=(_DER_CA,))


# =============================================================================
# LAYER 1 — pure unit / golden (no DB): the ESC-matrix primitives
# =============================================================================


def test_is_high_priv_sid_classification() -> None:
    assert is_high_priv_sid(f"{_DOMAIN_SID}-512") is True  # Domain Admins
    assert is_high_priv_sid(f"{_DOMAIN_SID}-519") is True  # Enterprise Admins
    assert is_high_priv_sid(f"{_DOMAIN_SID}-516") is True  # Domain Controllers
    assert is_high_priv_sid(f"{_DOMAIN_SID}-500") is True  # Administrator
    assert is_high_priv_sid("S-1-5-32-544") is True  # Administrators (builtin)
    assert is_high_priv_sid(f"{_DOMAIN_SID}-513") is False  # Domain Users
    assert is_high_priv_sid(f"{_DOMAIN_SID}-1337") is False  # normal user
    assert is_high_priv_sid(None) is False  # SID-less node


def test_effective_ekus_v1_vs_v2_sourcing() -> None:
    # V1 (schema 1 or absent): EKUs ONLY from pKIExtendedKeyUsage — app-policy ignored.
    assert effective_ekus(1, (_EKU_CLIENT_AUTH,), (_EKU_AGENT,)) == (_EKU_CLIENT_AUTH,)
    assert effective_ekus(None, (_EKU_CLIENT_AUTH,), (_EKU_AGENT,)) == (_EKU_CLIENT_AUTH,)
    # V2+: application policy governs; falls back to pKIExtendedKeyUsage when empty.
    assert effective_ekus(2, (_EKU_CLIENT_AUTH,), (_EKU_AGENT,)) == (_EKU_AGENT,)
    assert effective_ekus(4, (_EKU_CLIENT_AUTH,), ()) == (_EKU_CLIENT_AUTH,)
    assert effective_ekus(2, (), ()) == ()


def test_decode_template_v1_ignores_v2_only_flags() -> None:
    # V1 has no enrollment flag / RA-signature: approval OFF, RA 0, no NO_SEC_EXT
    # EVEN when the integers are populated (the evaluator MUST branch on schema).
    tpl = decode_template(
        "n",
        "n",
        _pki_flags(
            template_schema_version="1",
            enrollment_flag=str(0x2 | 0x80000),  # approval + NO_SECURITY_EXTENSION bits
            ra_signature="3",
            extended_key_usage=[_EKU_CLIENT_AUTH],
            certificate_application_policy=[_EKU_AGENT],
        ),
        _PROV,
    )
    assert tpl.is_v1 is True
    assert tpl.manager_approval is False
    assert tpl.ra_signatures_required == 0
    assert tpl.no_security_extension is False
    # V1 EKU sourced from pKIExtendedKeyUsage only.
    assert tpl.ekus == (_EKU_CLIENT_AUTH,)
    assert tpl.client_auth_capable is True


def test_decode_template_v2_reads_v2_flags() -> None:
    tpl = decode_template(
        "n",
        "n",
        _v2(
            enrollment_flag=str(0x2 | 0x80000),
            ra_signature="1",
            certificate_name_flag="1",
            certificate_application_policy=[_EKU_AGENT],
            extended_key_usage=[_EKU_CLIENT_AUTH],
        ),
        _PROV,
    )
    assert tpl.is_v1 is False
    assert tpl.manager_approval is True
    assert tpl.ra_signatures_required == 1
    assert tpl.no_security_extension is True
    assert tpl.supplies_subject is True
    assert tpl.ekus == (_EKU_AGENT,)  # V2 sources from app-policy
    assert tpl.requires_enrollment_agent_eku is True


def test_decode_template_malformed_flag_counted() -> None:
    tpl = decode_template("n", "n", _v2(certificate_name_flag="0xZZ"), _PROV)
    assert tpl.flag_parse_error == 1  # counted, never silent
    assert tpl.name_flag is None
    assert tpl.supplies_subject is False


def test_decode_template_empty_eku_is_auth_capable() -> None:
    # No EKU == all purposes -> auth-capable (research §2.3 "no-eku" token).
    tpl = decode_template("n", "n", _v2(), _PROV)
    assert tpl.client_auth_capable is True
    # A server-auth-only EKU is NOT AD-client-auth capable.
    tpl2 = decode_template("n", "n", _v2(certificate_application_policy=[_EKU_SERVER_AUTH]), _PROV)
    assert tpl2.client_auth_capable is False


def test_dc_config_flag_undecidability() -> None:
    assert DcConfigFlags().weak_binding is None  # unread -> undecidable
    assert DcConfigFlags().strong_binding_disabled is None
    assert DcConfigFlags().upn_cert_mapping is None
    assert DcConfigFlags(strong_binding=2).weak_binding is False  # Full = safe
    assert DcConfigFlags(strong_binding=1).weak_binding is True  # Compat = weak
    assert DcConfigFlags(strong_binding=0).weak_binding is True
    assert DcConfigFlags(strong_binding=0).strong_binding_disabled is True
    assert DcConfigFlags(strong_binding=1).strong_binding_disabled is False
    assert DcConfigFlags(cert_mapping_methods=0x4).upn_cert_mapping is True
    assert DcConfigFlags(cert_mapping_methods=0x1F).upn_cert_mapping is True  # 0x4 bit set
    assert DcConfigFlags(cert_mapping_methods=0x18).upn_cert_mapping is False


def test_low_priv_enrollable_consults_m4_closure_not_reexpand() -> None:
    # Enroll granted ONLY to a high-priv group that has a low-priv effective member
    # (via the M4 closure) -> the SET is low-priv enrollable.
    graph = _EscGraph()
    graph.sid_of = {"g-admins": _SID_ADMINS, "u-low": _SID_ATTACKER}
    graph.members_of = {"g-admins": {"u-low"}}
    assert _low_priv_enrollable(frozenset({"g-admins"}), graph) is True
    # No low-priv member anywhere -> admins-only grant is NOT low-priv enrollable.
    graph.members_of = {"g-admins": set()}
    assert _low_priv_enrollable(frozenset({"g-admins"}), graph) is False


# =============================================================================
# LAYER 2 — golden full-pipeline fixtures (REAL SDs + REAL certs + known ints)
# Each ESC fires with correct direction + confidence=inferred.
# =============================================================================


def test_esc1_positive_holder_to_domain() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag="0",  # approval off
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC1, "n-users", "n-domain") in _pairs(buf)
    assert result.esc1 == 1
    esc1 = next(e for e in buf.edges if e.kind == KIND_ESC1)  # type: ignore[attr-defined]
    assert esc1.confidence == "inferred"  # type: ignore[attr-defined]
    assert esc1.provenance.image_sha256 == "b" * 64  # type: ignore[attr-defined]
    assert esc1.access_mask is None and esc1.object_type_guid is None  # type: ignore[attr-defined]
    con.close()


def test_esc1_suppressed_admin_only() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-admins", _SID_ADMINS, "Group")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_ADMINS),  # enroll granted ONLY to Domain Admins
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert result.esc1 == 0  # admin-only grant is not an escalation
    assert KIND_ESC1 not in _kinds(buf)
    con.close()


def test_esc1_suppressed_manager_approval_on() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",
            enrollment_flag="2",  # CT_FLAG_PEND_ALL_REQUESTS -> manager approval ON
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc1 == 0  # manager approval gates enrollment -> no ESC1
    con.close()


def test_esc1_suppressed_ra_signature_required() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",
            enrollment_flag="0",
            ra_signature="1",  # authorized-signature required -> not ESC1
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc1 == 0
    con.close()


def test_esc1_enrollability_via_low_priv_group_single_edge_no_reexpand() -> None:
    """Enroll granted to a low-priv GROUP that has three effective members: the
    path resolves through the M4 closure but emits exactly ONE edge from the group
    (members reach the target via MemberOf; the closure is read, NOT re-expanded)."""
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _add_principal(con, "n-u1", f"{_DOMAIN_SID}-2001", "User")
    _add_principal(con, "n-u2", f"{_DOMAIN_SID}-2002", "User")
    _add_principal(con, "n-u3", f"{_DOMAIN_SID}-2003", "User")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    _add_effective_membership(con, "n-users", ["n-u1", "n-u2", "n-u3"])
    buf, result = _esc(con)
    esc1_edges = [e for e in buf.edges if e.kind == KIND_ESC1]  # type: ignore[attr-defined]
    assert result.esc1 == 1  # exactly one, NOT one-per-member (no re-expansion)
    assert len(esc1_edges) == 1
    assert esc1_edges[0].source_node_id == "n-users"  # type: ignore[attr-defined]
    con.close()


def test_esc4_holder_to_template() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC4"])
    _add_adcs(
        con,
        "n-esc4",
        "CertTemplate",
        name="ESC4",
        pki_flags=_v2(),
        raw_sd=_sd([_plain_ace(_GENERIC_ALL, _SID_USERS)]),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC4, "n-users", "n-esc4") in _pairs(buf)  # holder -> template
    assert result.esc4 == 1
    con.close()


def test_esc4_from_generic_write() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC4"])
    _add_adcs(
        con,
        "n-esc4",
        "CertTemplate",
        name="ESC4",
        pki_flags=_v2(),
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_USERS)]),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc4 == 1
    con.close()


def test_esc4_kind_is_wraith_native_not_bh_composite() -> None:
    # The ESC4 control fact uses a WRAITH-native kind so the M6 BH export does not
    # mistake it for BloodHound's ADCSESC4 composite (principal -> Domain).
    assert KIND_ESC4 == "WraithESC4TemplateControl"
    assert KIND_ESC4 != "ADCSESC4"


def test_esc4_from_owns() -> None:
    # An object owner can rewrite the template DACL -> a takeover path. M5 emits Owns
    # from the SD owner; ESC4 MUST include it or an owner's path is silently missed.
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC4"])
    _add_adcs(
        con,
        "n-esc4",
        "CertTemplate",
        name="ESC4",
        pki_flags=_v2(),
        raw_sd=_sd([], owner_sid=_SID_USERS),  # n-users OWNS the template (empty DACL)
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC4, "n-users", "n-esc4") in _pairs(buf)
    assert result.esc4 == 1
    con.close()


def test_esc13_holder_to_group() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _add_principal(
        con, "n-pkiadmins", f"{_DOMAIN_SID}-1105", "Group", dn="CN=PKI Admins,DC=corp,DC=local"
    )
    _trusted_ca(con, ["ESC13"])
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
        name="ESC13",
        pki_flags=_v2(certificate_policy=[policy_oid]),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC13, "n-users", "n-pkiadmins") in _pairs(buf)  # holder -> Group
    assert result.esc13 == 1
    con.close()


def test_esc13_suppressed_for_non_client_auth_template() -> None:
    """ESC13 injects the OID-linked group membership during PKINIT, so the template
    MUST be able to authenticate. A Server-Auth / EFS / Doc-Signing-only template
    (no AD client-auth EKU) yields NO ESC13 even with the OIDGroupLink present."""
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _add_principal(
        con, "n-pkiadmins", f"{_DOMAIN_SID}-1105", "Group", dn="CN=PKI Admins,DC=corp,DC=local"
    )
    _trusted_ca(con, ["ESC13"])
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
        name="ESC13",
        # Explicit server-auth-only EKU -> NOT client_auth_capable.
        pki_flags=_v2(
            certificate_policy=[policy_oid],
            certificate_application_policy=[_EKU_SERVER_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.esc13 == 0  # non-client-auth template -> no group injection
    con.close()


def test_esc15_v1_supplies_subject_to_domain() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC15"])
    _add_adcs(
        con,
        "n-esc15",
        "CertTemplate",
        name="ESC15",
        pki_flags=_pki_flags(
            template_schema_version="1",  # V1 + ESS == EKUwu / CVE-2024-49019
            certificate_name_flag="1",
            extended_key_usage=[_EKU_CLIENT_AUTH],  # V1 EKU from pKIExtendedKeyUsage
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert (KIND_ESC15, "n-users", "n-domain") in _pairs(buf)
    assert result.esc15 == 1
    con.close()


def test_esc3_and_enroll_on_behalf_of() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["Agent", "Target"])
    _add_adcs(
        con,
        "n-agent",
        "CertTemplate",
        name="Agent",
        pki_flags=_v2(certificate_application_policy=[_EKU_AGENT]),  # Cert-Request-Agent EKU
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _add_adcs(
        con,
        "n-target",
        "CertTemplate",
        name="Target",
        pki_flags=_v2(certificate_application_policy=[_EKU_CLIENT_AUTH]),  # client-auth target
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    pairs = _pairs(buf)
    assert (KIND_ENROLL_ON_BEHALF_OF, "n-agent", "n-target") in pairs  # agent -> target
    assert (KIND_ESC3, "n-users", "n-domain") in pairs  # holder -> Domain
    assert result.enroll_on_behalf_of == 1 and result.esc3 == 1
    # agent restriction is a CA-host fact -> undecidable, counted + noted on the edge.
    assert result.ca_host_blocked.get("esc3_agent", 0) >= 1
    esc3 = next(e for e in buf.edges if e.kind == KIND_ESC3)  # type: ignore[attr-defined]
    assert "undecidable[agent-restrictions:ca-host]" in esc3.derivation  # type: ignore[attr-defined]
    con.close()


def test_esc3_suppressed_when_agent_requires_approval_or_ra_sig() -> None:
    """An agent template that still requires manager approval (or an authorized RA
    signature) cannot be low-priv obtained, so it does NOT qualify as an ESC3 agent:
    no EnrollOnBehalfOf and no ADCSESC3."""
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["Agent", "Target"])
    _add_adcs(
        con,
        "n-agent",
        "CertTemplate",
        name="Agent",
        pki_flags=_v2(
            enrollment_flag="2",  # CT_FLAG_PEND_ALL_REQUESTS -> manager approval ON
            certificate_application_policy=[_EKU_AGENT],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _add_adcs(
        con,
        "n-target",
        "CertTemplate",
        name="Target",
        pki_flags=_v2(certificate_application_policy=[_EKU_CLIENT_AUTH]),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    assert result.esc3 == 0 and result.enroll_on_behalf_of == 0
    assert KIND_ESC3 not in _kinds(buf)
    assert KIND_ENROLL_ON_BEHALF_OF not in _kinds(buf)
    con.close()


_SID_VICTIM = f"{_DOMAIN_SID}-1400"  # an account enrollable in the ESC9 template


def _esc9_store() -> duckdb.DuckDBPyConnection:
    """ESC9 (corrected §2.3): a NO_SECURITY_EXTENSION client-auth template that a
    VICTIM can enroll in, plus an ATTACKER who holds a UPN/altSecurityIdentities
    write over that victim. The issued cert carries no SID extension and maps by the
    rewritten UPN, so a bare enrollee cannot escalate — only the writing principal
    can. Escalation source = the ATTACKER (like ESC10a), target = the Domain.

    * ``n-victim`` (User) holds Enroll on the ESC9 template (so it is in the template's
      enrollable set) AND its own SD grants the attacker GenericWrite (-> a confirmed
      victim-write edge M5 emits).
    * ``n-attacker`` is the low-priv writing principal.
    """
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-attacker", _SID_ATTACKER, "Group")
    _add_principal(
        con,
        "n-victim",
        _SID_VICTIM,
        "User",
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_ATTACKER)]),
    )
    _trusted_ca(con, ["ESC9"])
    _add_adcs(
        con,
        "n-esc9",
        "CertTemplate",
        name="ESC9",
        pki_flags=_v2(
            enrollment_flag="524288",  # 0x80000 CT_FLAG_NO_SECURITY_EXTENSION
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_VICTIM),  # the VICTIM is the enroll holder
    )
    _run_m5(con)
    return con


def test_esc9_weak_binding_attacker_to_domain() -> None:
    # 0x18 has no UPN bit, so ESC10a does not fire and does not pollute the counters.
    con = _esc9_store()
    buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=1, cert_mapping_methods=0x18, hive_read=True)
    )
    # Source is the WRITING principal, NOT the bare enrollee.
    assert (KIND_ESC9, "n-attacker", "n-domain") in _pairs(buf)
    assert result.esc9 == 1 and result.dc_config_absent == 0
    esc9 = next(e for e in buf.edges if e.kind == KIND_ESC9)  # type: ignore[attr-defined]
    assert esc9.confidence == "inferred"  # type: ignore[attr-defined]
    assert "victim-enrollable" in esc9.derivation  # type: ignore[attr-defined]
    con.close()


def test_esc9_suppressed_at_full_binding() -> None:
    con = _esc9_store()
    _buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=2, cert_mapping_methods=0x18, hive_read=True)
    )
    assert result.esc9 == 0  # StrongCertificateBindingEnforcement == 2 (Full) -> safe
    assert result.dc_config_absent == 0  # decided, not undecidable
    con.close()


def test_esc9_undecidable_without_dc_hive() -> None:
    con = _esc9_store()
    buf, result = _esc(con)  # no DC hive
    assert result.esc9 == 0
    assert result.dc_config_absent >= 1  # LOUD counted gap, no guessed edge
    assert KIND_ESC9 not in _kinds(buf)
    con.close()


def test_esc9_negative_writable_victim_not_enrollable() -> None:
    """The attacker can write a victim, and a (different) victim is enrollable, but
    the WRITABLE victim is NOT enrollable in the NO_SECURITY_EXTENSION template -> no
    ESC9 (no UPN rewrite of an enrollable account is possible)."""
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-attacker", _SID_ATTACKER, "Group")
    _add_principal(con, "n-enrollee", _SID_VICTIM, "User")  # enrollable, NOT writable
    _add_principal(
        con,
        "n-other",
        f"{_DOMAIN_SID}-1401",
        "User",  # writable by attacker, NOT enrollable
        raw_sd=_sd([_plain_ace(_GENERIC_WRITE, _SID_ATTACKER)]),
    )
    _trusted_ca(con, ["ESC9"])
    _add_adcs(
        con,
        "n-esc9",
        "CertTemplate",
        name="ESC9",
        pki_flags=_v2(
            enrollment_flag="524288",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_VICTIM),  # enroll granted to n-enrollee only
    )
    _run_m5(con)
    buf, result = _esc(
        con, dc_config=DcConfigFlags(strong_binding=1, cert_mapping_methods=0x18, hive_read=True)
    )
    assert result.esc9 == 0  # writable victim is not enrollable -> no escalation
    assert KIND_ESC9 not in _kinds(buf)
    con.close()


def _victim_store() -> duckdb.DuckDBPyConnection:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-attacker", _SID_ATTACKER, "Group")
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


def test_esc10a_attacker_to_user_and_computer() -> None:
    con = _victim_store()
    buf, result = _esc(con, dc_config=DcConfigFlags(cert_mapping_methods=0x4, hive_read=True))
    pairs = _pairs(buf)
    assert (KIND_ESC10A, "n-attacker", "n-victim-user") in pairs
    assert (KIND_ESC10A, "n-attacker", "n-victim-comp") in pairs
    assert result.esc10a == 2
    con.close()


def test_esc10b_attacker_to_computer_only() -> None:
    con = _victim_store()
    buf, result = _esc(con, dc_config=DcConfigFlags(strong_binding=0, hive_read=True))
    pairs = _pairs(buf)
    assert (KIND_ESC10B, "n-attacker", "n-victim-comp") in pairs  # computer only
    assert (KIND_ESC10B, "n-attacker", "n-victim-user") not in pairs
    assert result.esc10b == 1
    con.close()


def test_esc10_undecidable_without_dc_hive() -> None:
    con = _victim_store()
    _buf, result = _esc(con)
    assert result.esc10a == 0 and result.esc10b == 0
    assert result.dc_config_absent == 2  # one per undecidable branch
    con.close()


def test_golden_cert_computer_to_domain() -> None:
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
# LAYER 2 — CRITICAL: ESC6/7/11/16 undecidable-negative accounting
# =============================================================================


def test_esc6_undecidable_negative_no_edge_no_false_esc1() -> None:
    """ESC6-shaped template (enrollable client-auth, supplies-subject OFF so NOT
    ESC1) published to a trusted CA, NO CA hive: the EDITF_ATTRIBUTESUBJECTALTNAME2
    verdict lives ONLY on the CA host. This MUST be a counted ca_host_facts_absent
    gap (esc6 breakdown), NO ADCSESC6 row in the edge table, and NO false ESC1."""
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC6"])
    _add_adcs(
        con,
        "n-esc6",
        "CertTemplate",
        name="ESC6",
        pki_flags=_v2(
            certificate_name_flag="0",  # ENROLLEE_SUPPLIES_SUBJECT OFF -> not ESC1
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    buf, result = _esc(con)
    kinds = _kinds(buf)
    assert "ADCSESC6" not in kinds  # no false positive
    assert KIND_ESC1 not in kinds  # no false ESC1 (supplies-subject is off)
    assert result.ca_host_blocked.get("esc6", 0) >= 1  # loud + counted, never silent
    assert result.ca_host_facts_absent >= 1
    con.close()


def test_esc6_undecidable_negative_no_row_in_edge_table() -> None:
    # The authoritative DuckDB edge table carries NO ADCSESC6 row (via run_adcs_esc).
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC6"])
    _add_adcs(
        con,
        "n-esc6",
        "CertTemplate",
        name="ESC6",
        pki_flags=_v2(
            certificate_name_flag="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    result = run_adcs_esc(
        con, run, forest_id=_FOREST, domain_id=_DOMAIN_SID, domain_fqdn="corp.local"
    )
    rows = con.execute("SELECT count(*) FROM edge WHERE kind = 'ADCSESC6'").fetchone()
    assert rows is not None and rows[0] == 0
    assert result.ca_host_blocked.get("esc6", 0) >= 1
    # The gap is surfaced on the run (loud), with the per-ESC breakdown.
    assert run.skip_counts.get("adcs.ca_host_facts_absent", 0) >= 1
    assert run.skip_counts.get("adcs.ca_host_facts_absent.esc6", 0) >= 1
    con.close()


def test_esc7_11_16_counted_per_ca() -> None:
    con = _new_store()
    _add_domain(con)
    _trusted_ca(con, [])
    _run_m5(con)
    _buf, result = _esc(con)
    assert result.ca_host_blocked.get("esc7") == 1
    assert result.ca_host_blocked.get("esc11") == 1
    assert result.ca_host_blocked.get("esc16") == 1
    con.close()


# =============================================================================
# LAYER 3 — robustness / property / real-artifact anchor
# =============================================================================


def test_malformed_flags_counted_no_crash() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["Bad"])
    _add_adcs(
        con,
        "n-bad",
        "CertTemplate",
        name="Bad",
        pki_flags=_v2(
            certificate_name_flag="not-an-int",
            enrollment_flag="garbage",
            ra_signature="??",
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    _buf, result = _esc(con)  # must not raise
    assert result.esc_flag_parse_error >= 3  # all three unparseable flags counted
    con.close()


def test_determinism_two_runs_identical() -> None:
    def snapshot() -> list[tuple[str, str, str, str]]:
        con = _new_store()
        _add_domain(con)
        _add_principal(con, "n-users", _SID_USERS, "Group")
        _trusted_ca(con, ["ESC1"])
        _add_adcs(
            con,
            "n-esc1",
            "CertTemplate",
            name="ESC1",
            pki_flags=_v2(
                certificate_name_flag="1",
                enrollment_flag="0",
                ra_signature="0",
                certificate_application_policy=[_EKU_CLIENT_AUTH],
            ),
            raw_sd=_enroll_sd(_SID_USERS),
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


def test_idempotent_rerun_writes_no_duplicates() -> None:
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _trusted_ca(con, ["ESC1"])
    _add_adcs(
        con,
        "n-esc1",
        "CertTemplate",
        name="ESC1",
        pki_flags=_v2(
            certificate_name_flag="1",
            enrollment_flag="0",
            ra_signature="0",
            certificate_application_policy=[_EKU_CLIENT_AUTH],
        ),
        raw_sd=_enroll_sd(_SID_USERS),
    )
    _run_m5(con)
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    run_adcs_esc(con, run, forest_id=_FOREST, domain_id=_DOMAIN_SID, domain_fqdn="corp.local")
    first = con.execute("SELECT count(*) FROM edge WHERE kind = 'ADCSESC1'").fetchone()
    run_adcs_esc(con, run, forest_id=_FOREST, domain_id=_DOMAIN_SID, domain_fqdn="corp.local")
    second = con.execute("SELECT count(*) FROM edge WHERE kind = 'ADCSESC1'").fetchone()
    assert first is not None and second is not None
    assert first[0] == 1 and second[0] == 1  # INSERT OR IGNORE -> idempotent
    con.close()


def test_no_adcs_forest_is_noop() -> None:
    # Models the real test DC: no ADCS objects -> ~0 ESC edges, nothing undecidable.
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _run_m5(con)
    buf, result = _esc(con)
    assert result.edges_total == 0
    assert result.ca_host_facts_absent == 0  # no CA -> nothing undecidable
    assert len(buf.edges) == 0
    con.close()


def test_read_dc_config_degrades_on_corrupt_hive(tmp_path: Path) -> None:
    bad = tmp_path / "SYSTEM"
    bad.write_bytes(b"this is not a regf hive")
    flags, errors = read_dc_config_flags(bad)
    assert errors == 1  # counted read error
    assert flags.hive_read is False
    assert flags.strong_binding is None and flags.cert_mapping_methods is None


def test_read_dc_config_rejects_missing_path(tmp_path: Path) -> None:
    flags, errors = read_dc_config_flags(tmp_path / "nope")
    assert errors == 1 and flags.hive_read is False


def test_run_surfaces_dc_hive_read_error(tmp_path: Path) -> None:
    con = _new_store()
    _add_domain(con)
    _run_m5(con)
    bad = tmp_path / "SYSTEM"
    bad.write_bytes(b"corrupt")
    run = IngestRun("case", "op", ingest_run_id=_RUN)
    run_adcs_esc(
        con,
        run,
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
        system_hive_path=bad,
    )
    assert run.skip_counts.get("adcs.dc_config_hive_read_error", 0) == 1
    con.close()


# --- the ONE real-artifact anchor: the imaged DC's own SYSTEM hive -----------


@_needs_real_system
def test_real_dc_system_hive_reads_without_crash() -> None:
    flags, errors = read_dc_config_flags(_REAL_SYSTEM)
    assert errors == 0  # \Select\Current resolved; hive opened cleanly
    assert flags.hive_read is True
    # The imaged DC has neither key set (older build) -> both undecidable (None),
    # never a guessed default.
    assert flags.weak_binding is None
    assert flags.upn_cert_mapping is None


@_needs_real_system
def test_real_dc_no_adcs_zero_esc_edges() -> None:
    # Feed the REAL DC-config flags into the composer over a no-ADCS forest:
    # ESC9/10 produce ~0 edges (no templates) and nothing is undecidably counted.
    flags, _errors = read_dc_config_flags(_REAL_SYSTEM)
    con = _new_store()
    _add_domain(con)
    _add_principal(con, "n-users", _SID_USERS, "Group")
    _run_m5(con)
    buf, result = _esc(con, dc_config=flags)
    assert result.edges_total == 0
    assert result.esc9 == 0 and result.esc10a == 0 and result.esc10b == 0
    assert result.ca_host_facts_absent == 0
    assert len(buf.edges) == 0
    con.close()
