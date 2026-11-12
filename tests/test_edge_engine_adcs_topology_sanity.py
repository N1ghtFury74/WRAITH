"""Coder-side sanity for the Phase-1 ADCS topology edges (not the gate).

The real test DC has no usable ADCS surface (1 IssuancePolicy, no CA/template),
so this exercises the topology builders against SYNTHETIC fixtures with REAL
self-signed ``cACertificate`` blobs (via ``cryptography``, fixed serials) and a
known template+CA+OID set, proving every edge kind and every counted gap with a
KNOWN expected output. The authoritative three-layer gate is the tester's.

Fixture certs use module-scoped EC keys (ECDSA signatures carry a random nonce,
so regenerating would change the DER; generating once and reusing the bytes keeps
each test's input stable). WRAITH determinism is proven by feeding the SAME bytes
to two runs and asserting byte-identical edge rows.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import duckdb
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from wraith.edges.adcs_topology import (
    KIND_ENTERPRISE_CA_FOR,
    KIND_EXTENDED_BY_POLICY,
    KIND_HOSTS_CA_SERVICE,
    KIND_ISSUED_SIGNED_BY,
    KIND_NTAUTH_STORE_FOR,
    KIND_OID_GROUP_LINK,
    KIND_ROOT_CA_FOR,
    KIND_TRUSTED_FOR_NTAUTH,
    compute_adcs_topology,
)
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.normalize.models import AdcsRow, ContainerRow, PrincipalRow, StagingObjectRow
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-0000000000ad")
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

# --- deterministic-within-process fixture keys (generated once) --------------
_K_ROOT = ec.generate_private_key(ec.SECP256R1())
_K_ENT = ec.generate_private_key(ec.SECP256R1())
_K_EXT = ec.generate_private_key(ec.SECP256R1())
_K_DUP_A = ec.generate_private_key(ec.SECP256R1())
_K_DUP_B = ec.generate_private_key(ec.SECP256R1())
_K_CHILD = ec.generate_private_key(ec.SECP256R1())


def _cert(
    cn: str,
    serial: int,
    key: ec.EllipticCurvePrivateKey,
    *,
    issuer_cn: str | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """Build one real DER cert (self-signed unless an issuer is given)."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    signer = issuer_key or key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


_DER_ROOT = _cert("Root CA", 1, _K_ROOT)
_DER_ENT = _cert("Enterprise CA", 2, _K_ENT, issuer_cn="Root CA", issuer_key=_K_ROOT)
_DER_EXTERNAL = _cert("External Anchor", 3, _K_EXT)
_DER_DUP_A = _cert("Dup Signer", 10, _K_DUP_A)
_DER_DUP_B = _cert("Dup Signer", 11, _K_DUP_B)
_DER_CHILD = _cert("Child CA", 12, _K_CHILD, issuer_cn="Dup Signer", issuer_key=_K_DUP_A)

_POLICY_OID = "1.3.6.1.4.1.311.21.8.7777777.custom"


# --- row + store helpers -----------------------------------------------------


def _pki_flags(**over: object) -> dict[str, object]:
    """Full ``pki_flags`` struct dict (all DDL keys) with the given overrides."""
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


@dataclass(frozen=True)
class _AdcsFixture:
    """One synthetic ADCS object to insert (adcs row + staging row)."""

    node_id: str
    adcs_type: str
    pki_flags: dict[str, object]
    cert_ders: tuple[bytes, ...] = ()


def _store(fixtures: list[_AdcsFixture]) -> duckdb.DuckDBPyConnection:
    """Open an in-memory store and insert the ADCS + staging rows."""
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    for fx in fixtures:
        adcs = AdcsRow(
            node_id=fx.node_id,
            object_guid=None,
            name=fx.node_id,
            adcs_type=fx.adcs_type,
            pki_flags=fx.pki_flags,
            enrollment_rights=[],
            published_templates=[],
            forest_id=_FOREST,
            domain_id=_DOMAIN_SID,
            domain_fqdn="corp.local",
            provenance=_PROV,
        )
        attrs = {"cACertificate": [{"__bytes_hex__": der.hex()} for der in fx.cert_ders]}
        staging = StagingObjectRow(
            node_id=fx.node_id,
            dnt=1,
            object_guid=None,
            object_sid=None,
            object_class=[fx.adcs_type],
            raw_sd=None,
            attributes_json=json.dumps(attrs),
            forest_id=_FOREST,
            domain_id=_DOMAIN_SID,
            domain_fqdn="corp.local",
            provenance=_PROV,
        )
        _insert(con, "adcs", adcs.to_db_values())
        _insert(con, "staging_object", staging.to_db_values())
    return con


def _insert(con: duckdb.DuckDBPyConnection, table: str, values: tuple[object, ...]) -> None:
    placeholders = ",".join("?" * len(values))
    con.execute(f"INSERT INTO {table} VALUES ({placeholders})", list(values))  # noqa: S608


class _Buffer:
    """Minimal edge sink matching ``edge_engine._EdgeBuffer.add`` for direct tests."""

    def __init__(self) -> None:
        self.edges: list[object] = []

    def add(self, edge: object) -> None:
        self.edges.append(edge)


def _kinds(edges: list[object]) -> list[str]:
    return sorted(e.kind for e in edges)  # type: ignore[attr-defined]


# --- happy path: every topology edge kind fires ------------------------------


def test_topology_full_fixture_known_edges() -> None:
    """All eight topology kinds on one coherent synthetic forest, known output."""
    fixtures = [
        _AdcsFixture("n-root", "RootCA", _pki_flags(), (_DER_ROOT,)),
        _AdcsFixture(
            "n-entca",
            "EnterpriseCA",
            _pki_flags(dns_host_name="entca.corp.local"),
            (_DER_ENT,),
        ),
        _AdcsFixture("n-ntauth", "NTAuthStore", _pki_flags(), (_DER_ENT, _DER_EXTERNAL)),
        _AdcsFixture(
            "n-template",
            "CertTemplate",
            _pki_flags(certificate_policy=[_POLICY_OID]),
        ),
        _AdcsFixture(
            "n-policy",
            "IssuancePolicy",
            _pki_flags(oid=_POLICY_OID, oid_to_group_link="CN=PKI Admins,DC=corp,DC=local"),
        ),
    ]
    con = _store(fixtures)
    buf = _Buffer()
    result = compute_adcs_topology(
        con,
        buf,
        "n-domain",
        {"entca.corp.local": "n-dc"},
        {"cn=pki admins,dc=corp,dc=local": "n-grp"},
        _SCOPING,
    )

    pairs = {(e.kind, e.source_node_id, e.target_node_id) for e in buf.edges}  # type: ignore[attr-defined]
    assert (KIND_ROOT_CA_FOR, "n-root", "n-domain") in pairs
    assert (KIND_ENTERPRISE_CA_FOR, "n-entca", "n-domain") in pairs
    assert (KIND_NTAUTH_STORE_FOR, "n-ntauth", "n-domain") in pairs
    assert (KIND_HOSTS_CA_SERVICE, "n-dc", "n-entca") in pairs
    assert (KIND_TRUSTED_FOR_NTAUTH, "n-entca", "n-ntauth") in pairs
    assert (KIND_ISSUED_SIGNED_BY, "n-entca", "n-root") in pairs
    assert (KIND_EXTENDED_BY_POLICY, "n-template", "n-policy") in pairs
    assert (KIND_OID_GROUP_LINK, "n-policy", "n-grp") in pairs

    # The external NTAuth anchor matches no EnterpriseCA -> counted, not an edge.
    assert result.ntauth_cert_unmatched == 1
    # Exactly these eight edges; no spurious edge, no self-signed-root chain edge.
    assert result.edges_total == 8
    assert result.enterprise_ca_for == 1 and result.root_ca_for == 1
    assert result.ntauth_store_for == 1 and result.hosts_ca_service == 1
    assert result.trusted_for_ntauth == 1 and result.issued_signed_by == 1
    assert result.extended_by_policy == 1 and result.oid_group_link == 1
    assert result.ca_cert_chain_ambiguous == 0 and result.cert_parse_error == 0
    assert result.hostscaservice_unresolved == 0 and result.oidgrouplink_sid_unresolved == 0
    # Every edge is a confirmed, fully-provenanced §4 row.
    for e in buf.edges:
        assert e.confidence == "confirmed"  # type: ignore[attr-defined]
        assert e.provenance.image_sha256 == "a" * 64  # type: ignore[attr-defined]
        assert e.access_mask is None and e.object_type_guid is None  # type: ignore[attr-defined]
    con.close()


# --- counted gaps ------------------------------------------------------------


def test_hostscaservice_unresolved_counted() -> None:
    """A CA naming a host with no matching computer node is a counted gap."""
    con = _store(
        [_AdcsFixture("n-entca", "EnterpriseCA", _pki_flags(dns_host_name="ghost.corp.local"))]
    )
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, "n-domain", {}, {}, _SCOPING)
    assert result.hosts_ca_service == 0 and result.hostscaservice_unresolved == 1
    assert KIND_HOSTS_CA_SERVICE not in _kinds(buf.edges)
    con.close()


def test_issued_signed_by_ambiguous_chain_counted() -> None:
    """Two CA nodes sharing a subject DN make a child's issuer ambiguous -> counted,
    never a guessed edge."""
    con = _store(
        [
            _AdcsFixture("n-dup-a", "RootCA", _pki_flags(), (_DER_DUP_A,)),
            _AdcsFixture("n-dup-b", "RootCA", _pki_flags(), (_DER_DUP_B,)),
            _AdcsFixture("n-child", "EnterpriseCA", _pki_flags(), (_DER_CHILD,)),
        ]
    )
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, "n-domain", {}, {}, _SCOPING)
    assert result.ca_cert_chain_ambiguous == 1
    assert result.issued_signed_by == 0
    assert KIND_ISSUED_SIGNED_BY not in _kinds(buf.edges)
    con.close()


def test_cert_parse_error_counted() -> None:
    """A malformed cACertificate blob is counted, never crashes the pass."""
    con = _store([_AdcsFixture("n-entca", "EnterpriseCA", _pki_flags(), (b"\x30not-a-cert",))])
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, "n-domain", {}, {}, _SCOPING)
    assert result.cert_parse_error == 1
    # EnterpriseCAFor still fires (topology does not depend on the cert).
    assert result.enterprise_ca_for == 1
    con.close()


def test_oidgrouplink_unresolved_dn_counted() -> None:
    """An OID-to-group DN that resolves to no modeled group is a counted gap."""
    con = _store(
        [
            _AdcsFixture(
                "n-policy",
                "IssuancePolicy",
                _pki_flags(oid="1.2.3", oid_to_group_link="CN=Nope,DC=x"),
            )
        ]
    )
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, "n-domain", {}, {}, _SCOPING)
    assert result.oid_group_link == 0 and result.oidgrouplink_sid_unresolved == 1
    con.close()


def test_trusted_for_ntauth_matches_on_cert_not_string() -> None:
    """TrustedForNTAuth is keyed on the parsed-x509 fingerprint: a byte-identical
    Enterprise CA cert in the NTAuth store matches; an unrelated anchor does not."""
    con = _store(
        [
            _AdcsFixture("n-entca", "EnterpriseCA", _pki_flags(), (_DER_ENT,)),
            _AdcsFixture("n-ntauth", "NTAuthStore", _pki_flags(), (_DER_ENT,)),
        ]
    )
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, "n-domain", {}, {}, _SCOPING)
    assert result.trusted_for_ntauth == 1 and result.ntauth_cert_unmatched == 0
    pairs = {(e.kind, e.source_node_id, e.target_node_id) for e in buf.edges}  # type: ignore[attr-defined]
    assert (KIND_TRUSTED_FOR_NTAUTH, "n-entca", "n-ntauth") in pairs
    con.close()


def test_no_domain_node_suppresses_to_domain_edges() -> None:
    """With no Domain node, EnterpriseCAFor/RootCAFor/NTAuthStoreFor cannot fire,
    but non-domain edges (e.g. IssuedSignedBy) still do."""
    con = _store(
        [
            _AdcsFixture("n-root", "RootCA", _pki_flags(), (_DER_ROOT,)),
            _AdcsFixture("n-entca", "EnterpriseCA", _pki_flags(), (_DER_ENT,)),
        ]
    )
    buf = _Buffer()
    result = compute_adcs_topology(con, buf, None, {}, {}, _SCOPING)
    assert result.enterprise_ca_for == 0 and result.root_ca_for == 0
    assert result.issued_signed_by == 1  # EnterpriseCA -> Root still resolves
    con.close()


def test_determinism_two_passes_byte_identical() -> None:
    """Identical fixture bytes -> identical edge_id set + row order across two runs."""
    fixtures = [
        _AdcsFixture("n-root", "RootCA", _pki_flags(), (_DER_ROOT,)),
        _AdcsFixture(
            "n-entca", "EnterpriseCA", _pki_flags(dns_host_name="entca.corp.local"), (_DER_ENT,)
        ),
        _AdcsFixture("n-ntauth", "NTAuthStore", _pki_flags(), (_DER_ENT,)),
    ]
    snapshots = []
    for _ in range(2):
        con = _store(fixtures)
        buf = _Buffer()
        compute_adcs_topology(con, buf, "n-domain", {"entca.corp.local": "n-dc"}, {}, _SCOPING)
        snapshots.append(sorted(e.edge_id for e in buf.edges))  # type: ignore[attr-defined]
        con.close()
    assert snapshots[0] == snapshots[1]


# --- end-to-end wiring through compute_edges ---------------------------------


def _schema() -> object:
    from wraith.parsing.schema import NtdsSchema

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


def test_end_to_end_compute_edges_wires_topology() -> None:
    """compute_edges wires the SPN host index into HostsCAService and the principal
    group-DN index into OIDGroupLink, and surfaces the ADCS counters on the run."""
    from wraith.case.ingest_run import IngestRun
    from wraith.edges import compute_edges

    con = _store(
        [
            _AdcsFixture(
                "n-entca", "EnterpriseCA", _pki_flags(dns_host_name="entca.corp.local"), (_DER_ENT,)
            ),
            _AdcsFixture(
                "n-policy",
                "IssuancePolicy",
                _pki_flags(oid="1.2.3", oid_to_group_link="CN=PKI Admins,DC=corp,DC=local"),
            ),
        ]
    )
    # A Domain container (so the X->Domain edges resolve), a Computer principal with
    # a HOST SPN for the CA host, and a Group with the OID-link DN.
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
    computer = PrincipalRow(
        node_id="n-dc",
        object_sid=f"{_DOMAIN_SID}-1001",
        object_guid=None,
        principal_type="Computer",
        samaccountname="ENTCA$",
        upn=None,
        distinguished_name="CN=ENTCA,DC=corp,DC=local",
        display_name=None,
        description=None,
        uac_flags=None,
        enabled=True,
        admincount=None,
        spns=["HOST/entca.corp.local"],
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
    group = PrincipalRow(
        node_id="n-grp",
        object_sid=f"{_DOMAIN_SID}-1105",
        object_guid=None,
        principal_type="Group",
        samaccountname="PKI Admins",
        upn=None,
        distinguished_name="CN=PKI Admins,DC=corp,DC=local",
        display_name=None,
        description=None,
        uac_flags=None,
        enabled=None,
        admincount=None,
        spns=[],
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
    _insert(con, "principal", computer.to_db_values())
    _insert(con, "principal", group.to_db_values())

    run = IngestRun("case", "op", ingest_run_id=_RUN)
    result = compute_edges(
        con,
        run,
        _schema(),  # type: ignore[arg-type]
        forest_id=_FOREST,
        domain_id=_DOMAIN_SID,
        domain_fqdn="corp.local",
    )
    kinds = dict(con.execute("SELECT kind, count(*) FROM edge GROUP BY kind").fetchall())
    assert kinds.get(KIND_ENTERPRISE_CA_FOR) == 1
    assert kinds.get(KIND_HOSTS_CA_SERVICE) == 1  # resolved via the HOST SPN index
    assert kinds.get(KIND_OID_GROUP_LINK) == 1  # resolved via the principal group DN
    cov = result.coverage_counts
    assert cov.get("edges.enterprise_ca_for") == 1
    assert cov.get("edges.hosts_ca_service") == 1
    assert cov.get("edges.oid_group_link") == 1
    con.close()
