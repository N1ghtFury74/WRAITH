"""Independent GATE suite — Module 7 Phase 1 (ADCS topology base edges).

Authored by ``wraith-tester`` (the gatekeeper). AUTHORITATIVE gate; does NOT trust
the coder's ``test_edge_engine_adcs_topology_sanity.py``. Every fixture and expected
value here is independently re-derived (independent certs/DNs/serials, independent
row construction) against ``wraith/edges/adcs_topology.py``.

This surface is SYNTHETIC-validated (the real DC c137.local has 1 IssuancePolicy
and no CA/template/NTAuth, so it emits ~0 real topology edges). The real-DC parity
and no-regression checks live in ``test_edge_engine_gate.py`` / ``test_gpo_gate.py``
and ``test_normalizer_gate.py`` (NOT touched here).

Layers:
  1. unit/golden — the 8 topology kinds with correct direction on one crafted forest.
  2. reference/robustness — every counted gap fires non-silently; malformed/partial
     input degrades to a counted gap, never a crash.
  3. property — determinism (identical bytes -> identical edge_id set).
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
from wraith.normalize.models import AdcsRow, StagingObjectRow
from wraith.provenance.models import ProvenanceStruct

_RUN = uuid.UUID("00000000-0000-0000-0000-00000000ca7e")
_FOREST = "gate-forest"
_DOMAIN_SID = "S-1-5-21-7-7-7"
_SCOPING = (_FOREST, _DOMAIN_SID, "gate.test")
_PROV = ProvenanceStruct(
    source_file="ntds.dit",
    image_sha256="b" * 64,
    source_object_id="gate-src",
    directory_timestamp=datetime(2023, 6, 1, tzinfo=UTC),
    ingest_run_id=_RUN,
)

# Independent fixture keys (generated once; ECDSA DER carries a random nonce, so a
# regenerate would change the bytes -> generate once, reuse the bytes).
_K_ROOT = ec.generate_private_key(ec.SECP256R1())
_K_SUB = ec.generate_private_key(ec.SECP256R1())
_K_EXT = ec.generate_private_key(ec.SECP256R1())
_K_TWINA = ec.generate_private_key(ec.SECP256R1())
_K_TWINB = ec.generate_private_key(ec.SECP256R1())
_K_ORPHAN = ec.generate_private_key(ec.SECP256R1())


def _der(
    cn: str,
    serial: int,
    key: ec.EllipticCurvePrivateKey,
    *,
    issuer: str,
    signer_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime(2021, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2031, 1, 1, tzinfo=UTC))
        .sign(signer_key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )


# Coherent chain: Sub CA issued by Root CA (self-signed).
_DER_ROOT = _der("gate-root", 100, _K_ROOT, issuer="gate-root", signer_key=_K_ROOT)
_DER_SUB = _der("gate-sub", 101, _K_SUB, issuer="gate-root", signer_key=_K_ROOT)
_DER_EXT = _der("gate-external", 102, _K_EXT, issuer="gate-external", signer_key=_K_EXT)
# Two self-signed roots sharing a subject DN -> ambiguous signer for a child.
_DER_TWIN_A = _der("gate-twin", 200, _K_TWINA, issuer="gate-twin", signer_key=_K_TWINA)
_DER_TWIN_B = _der("gate-twin", 201, _K_TWINB, issuer="gate-twin", signer_key=_K_TWINB)
_DER_ORPHAN = _der("gate-orphan", 202, _K_ORPHAN, issuer="gate-twin", signer_key=_K_TWINA)
# Same subject/issuer DN as the Sub CA cert but a DIFFERENT key -> different
# fingerprint (proves NTAuth match is on the x509 fingerprint, not the DN string).
_DER_SUB_IMPOSTER = _der(
    "gate-sub", 999, ec.generate_private_key(ec.SECP256R1()), issuer="gate-root", signer_key=_K_ROOT
)

_POLICY_OID = "1.3.6.1.4.1.311.21.8.424242.gate"


def _flags(**over: object) -> dict[str, object]:
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
class _Fx:
    node_id: str
    adcs_type: str
    flags: dict[str, object]
    ders: tuple[bytes, ...] = ()
    staging: bool = True


def _store(fx: list[_Fx]) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    for f in fx:
        adcs = AdcsRow(
            node_id=f.node_id,
            object_guid=None,
            name=f.node_id,
            adcs_type=f.adcs_type,
            pki_flags=f.flags,
            enrollment_rights=[],
            published_templates=[],
            forest_id=_FOREST,
            domain_id=_DOMAIN_SID,
            domain_fqdn="gate.test",
            provenance=_PROV,
        )
        _ins(con, "adcs", adcs.to_db_values())
        if f.staging:
            attrs = {"cACertificate": [{"__bytes_hex__": d.hex()} for d in f.ders]}
            staging = StagingObjectRow(
                node_id=f.node_id,
                dnt=1,
                object_guid=None,
                object_sid=None,
                object_class=[f.adcs_type],
                raw_sd=None,
                attributes_json=json.dumps(attrs),
                forest_id=_FOREST,
                domain_id=_DOMAIN_SID,
                domain_fqdn="gate.test",
                provenance=_PROV,
            )
            _ins(con, "staging_object", staging.to_db_values())
    return con


def _ins(con: duckdb.DuckDBPyConnection, table: str, values: tuple[object, ...]) -> None:
    sql = f"INSERT INTO {table} VALUES ({','.join('?' * len(values))})"  # noqa: S608
    con.execute(sql, list(values))


class _Buf:
    def __init__(self) -> None:
        self.edges: list[object] = []

    def add(self, edge: object) -> None:
        self.edges.append(edge)


def _pairs(buf: _Buf) -> set[tuple[str, str, str]]:
    return {(e.kind, e.source_node_id, e.target_node_id) for e in buf.edges}  # type: ignore[attr-defined]


# =============================================================================
# Layer 1 — unit/golden: the eight topology kinds + direction
# =============================================================================


def test_eight_kinds_correct_direction() -> None:
    """One coherent forest -> exactly the 8 topology edges with correct direction."""
    con = _store(
        [
            _Fx("root", "RootCA", _flags(), (_DER_ROOT,)),
            _Fx("sub", "EnterpriseCA", _flags(dns_host_name="ca.gate.test"), (_DER_SUB,)),
            _Fx("ntauth", "NTAuthStore", _flags(), (_DER_SUB, _DER_EXT)),
            _Fx("tmpl", "CertTemplate", _flags(certificate_policy=[_POLICY_OID])),
            _Fx(
                "pol",
                "IssuancePolicy",
                _flags(oid=_POLICY_OID, oid_to_group_link="CN=G,DC=gate,DC=test"),
            ),
        ]
    )
    buf = _Buf()
    r = compute_adcs_topology(
        con,
        buf,
        "dom",
        {"ca.gate.test": "host-ca"},
        {"cn=g,dc=gate,dc=test": "grp"},
        _SCOPING,
    )
    p = _pairs(buf)
    # direction asserted explicitly per the taxonomy (src -> tgt)
    assert (KIND_ROOT_CA_FOR, "root", "dom") in p
    assert (KIND_ENTERPRISE_CA_FOR, "sub", "dom") in p
    assert (KIND_NTAUTH_STORE_FOR, "ntauth", "dom") in p
    assert (KIND_HOSTS_CA_SERVICE, "host-ca", "sub") in p  # Computer -> CA
    assert (KIND_TRUSTED_FOR_NTAUTH, "sub", "ntauth") in p  # CA -> NTAuthStore
    assert (KIND_ISSUED_SIGNED_BY, "sub", "root") in p  # issued CA -> signer
    assert (KIND_EXTENDED_BY_POLICY, "tmpl", "pol") in p  # Template -> Policy
    assert (KIND_OID_GROUP_LINK, "pol", "grp") in p  # Policy -> Group
    assert r.edges_total == 8
    assert r.ntauth_cert_unmatched == 1  # the external anchor, counted not edged
    assert r.ca_cert_chain_ambiguous == 0 and r.cert_parse_error == 0
    # every edge is confirmed, NULL-mask, fully provenanced
    for e in buf.edges:
        assert e.confidence == "confirmed"  # type: ignore[attr-defined]
        assert e.access_mask is None and e.object_type_guid is None  # type: ignore[attr-defined]
        assert e.provenance.image_sha256 == "b" * 64  # type: ignore[attr-defined]
    # no PublishedTo synthesized here (slice 5B owns it; not duplicated)
    assert all(e.kind != "PublishedTo" for e in buf.edges)  # type: ignore[attr-defined]
    con.close()


def test_self_signed_root_emits_no_issued_signed_by() -> None:
    """A lone self-signed root (issuer == subject) emits no IssuedSignedBy self-edge."""
    con = _store([_Fx("root", "RootCA", _flags(), (_DER_ROOT,))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.issued_signed_by == 0
    assert all(e.kind != KIND_ISSUED_SIGNED_BY for e in buf.edges)  # type: ignore[attr-defined]
    con.close()


def test_trusted_for_ntauth_keyed_on_fingerprint_not_dn() -> None:
    """NTAuth match is on the x509 SHA-256 fingerprint: a same-DN/different-key
    imposter does NOT match (would match on a naive DN/string compare)."""
    con = _store(
        [
            _Fx("sub", "EnterpriseCA", _flags(), (_DER_SUB,)),
            _Fx("ntauth", "NTAuthStore", _flags(), (_DER_SUB_IMPOSTER,)),
        ]
    )
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.trusted_for_ntauth == 0  # fingerprints differ -> no match
    assert r.ntauth_cert_unmatched == 1
    con.close()


# =============================================================================
# Layer 2 — counted gaps (each fires, non-silently)
# =============================================================================


def test_gap_hostscaservice_unresolved() -> None:
    con = _store([_Fx("sub", "EnterpriseCA", _flags(dns_host_name="ghost.gate.test"))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.hosts_ca_service == 0 and r.hostscaservice_unresolved == 1
    assert all(e.kind != KIND_HOSTS_CA_SERVICE for e in buf.edges)  # type: ignore[attr-defined]
    con.close()


def test_gap_ca_cert_chain_ambiguous() -> None:
    """Two same-subject signers -> ambiguous -> counted, never a guessed edge."""
    con = _store(
        [
            _Fx("twin-a", "RootCA", _flags(), (_DER_TWIN_A,)),
            _Fx("twin-b", "RootCA", _flags(), (_DER_TWIN_B,)),
            _Fx("orphan", "EnterpriseCA", _flags(), (_DER_ORPHAN,)),
        ]
    )
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.ca_cert_chain_ambiguous == 1 and r.issued_signed_by == 0
    assert all(e.kind != KIND_ISSUED_SIGNED_BY for e in buf.edges)  # type: ignore[attr-defined]
    con.close()


def test_gap_ntauth_cert_unmatched() -> None:
    """An NTAuth anchor matching no EnterpriseCA cert is counted, not edged."""
    con = _store([_Fx("ntauth", "NTAuthStore", _flags(), (_DER_EXT,))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.ntauth_cert_unmatched == 1 and r.trusted_for_ntauth == 0
    con.close()


def test_gap_oidgrouplink_unresolved_mints_no_node() -> None:
    """An unresolvable OID-to-group DN is counted and mints NO bogus node/edge."""
    con = _store(
        [_Fx("pol", "IssuancePolicy", _flags(oid="1.2.3", oid_to_group_link="CN=Nope,DC=x"))]
    )
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.oid_group_link == 0 and r.oidgrouplink_sid_unresolved == 1
    assert buf.edges == []  # no edge, no minted target
    con.close()


def test_gap_cert_parse_error_on_ca_other_edges_still_fire() -> None:
    """A malformed CA cert blob is counted; the CA's topology edge still fires."""
    con = _store([_Fx("sub", "EnterpriseCA", _flags(), (b"\x30\x82garbage",))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.cert_parse_error == 1
    assert r.enterprise_ca_for == 1  # topology independent of the cert
    con.close()


def test_gap_cert_parse_error_on_ntauth_is_counted() -> None:
    """A malformed DER inside an NTAuthStore MUST be a counted cert_parse_error."""
    con = _store([_Fx("ntauth", "NTAuthStore", _flags(), (b"\x30\x82garbage",))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.cert_parse_error == 1
    con.close()


# =============================================================================
# Layer 2/3 — robustness: malformed/partial input degrades, never crashes
# =============================================================================


def test_truncated_der_counted_no_crash() -> None:
    """A valid-prefix-then-truncated DER is counted, never crashes the pass."""
    truncated = _DER_SUB[:40]  # valid SEQUENCE header, truncated body
    con = _store([_Fx("sub", "EnterpriseCA", _flags(), (truncated,))])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.cert_parse_error == 1 and r.enterprise_ca_for == 1
    con.close()


def test_empty_pki_flags_no_edges_no_crash() -> None:
    """An ADCS object with all-NULL pki_flags and no certs yields no edges."""
    con = _store([_Fx("sub", "EnterpriseCA", _flags())])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.enterprise_ca_for == 1  # the to-domain edge still fires
    assert r.issued_signed_by == 0 and r.trusted_for_ntauth == 0
    con.close()


def test_missing_staging_row_no_crash() -> None:
    """An adcs row with no staging_object (NULL join) is skipped cleanly, no crash."""
    con = _store([_Fx("sub", "EnterpriseCA", _flags(dns_host_name="ca.gate.test"), staging=False)])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {"ca.gate.test": "host"}, {}, _SCOPING)
    assert r.objects_scanned == 0  # no provenance -> skipped, nothing emitted
    assert buf.edges == []
    con.close()


def test_null_domain_node_suppresses_to_domain_only() -> None:
    """No Domain node -> X->Domain edges suppressed; non-domain edges still fire."""
    con = _store(
        [
            _Fx("root", "RootCA", _flags(), (_DER_ROOT,)),
            _Fx("sub", "EnterpriseCA", _flags(), (_DER_SUB,)),
        ]
    )
    buf = _Buf()
    r = compute_adcs_topology(con, buf, None, {}, {}, _SCOPING)
    assert r.enterprise_ca_for == 0 and r.root_ca_for == 0
    assert r.issued_signed_by == 1
    con.close()


def test_empty_store_returns_zero() -> None:
    con = _store([])
    buf = _Buf()
    r = compute_adcs_topology(con, buf, "dom", {}, {}, _SCOPING)
    assert r.edges_total == 0 and r.objects_scanned == 0
    con.close()


# =============================================================================
# Layer 3 — determinism
# =============================================================================


def test_determinism_identical_bytes_identical_edge_ids() -> None:
    fx = [
        _Fx("root", "RootCA", _flags(), (_DER_ROOT,)),
        _Fx("sub", "EnterpriseCA", _flags(dns_host_name="ca.gate.test"), (_DER_SUB,)),
        _Fx("ntauth", "NTAuthStore", _flags(), (_DER_SUB, _DER_EXT)),
        _Fx("tmpl", "CertTemplate", _flags(certificate_policy=[_POLICY_OID])),
        _Fx(
            "pol",
            "IssuancePolicy",
            _flags(oid=_POLICY_OID, oid_to_group_link="CN=G,DC=gate,DC=test"),
        ),
    ]
    snaps = []
    for _ in range(2):
        con = _store(fx)
        buf = _Buf()
        compute_adcs_topology(
            con, buf, "dom", {"ca.gate.test": "host-ca"}, {"cn=g,dc=gate,dc=test": "grp"}, _SCOPING
        )
        snaps.append(sorted(e.edge_id for e in buf.edges))  # type: ignore[attr-defined]
        con.close()
    assert snaps[0] == snaps[1]
    assert len(snaps[0]) == len(set(snaps[0]))  # edge_ids unique
