"""ADCS topology base edges (Phase 1) — ntds-derivable, confirmed confidence.

The attacker-lens PKI graph needs a backbone of *confirmed* topology edges that
later feed the ESC composites (Phase 2). These are all derivable offline from the
Configuration-NC ADCS objects already normalized into the ``adcs`` table (research
``docs/research/11-adcs-edges-decisions.md`` §2.2 / §2.7 "composition home"):

* **EnterpriseCAFor** — EnterpriseCA -> Domain.
* **RootCAFor** — RootCA -> Domain.
* **NTAuthStoreFor** — NTAuthStore -> Domain.
* **HostsCAService** — Computer -> EnterpriseCA (CA ``dNSHostName`` -> a computer).
* **TrustedForNTAuth** — EnterpriseCA -> NTAuthStore (the CA cert appears in the
  NTAuthStore's ``cACertificate`` set; compared as parsed x509, not as a string).
* **IssuedSignedBy** — CA -> CA (one cert's issuer == another cert's subject).
* **ExtendedByPolicy** — CertTemplate -> IssuancePolicy (template
  ``msPKI-Certificate-Policy`` OID matches the policy's ``msPKI-Cert-Template-OID``).
* **OIDGroupLink** — IssuancePolicy -> Group (``msDS-OIDToGroupLink`` DN).

``PublishedTo`` (Template -> EnterpriseCA) is already emitted by slice 5B
(:func:`wraith.edges.derivations.build_published_to_edges`) and is intentionally
left there (verified, not duplicated).

Design rules (CLAUDE.md quality bar):

* Cert blobs are parsed with ``cryptography`` x509 (the pinned dep) — never a
  hand-rolled ASN.1 reader, never string comparison of DER.
* Small pure builders; one I/O orchestrator (:func:`compute_adcs_topology`).
* Everything that cannot be resolved is a COUNTED gap (never a silent drop, never
  a guessed edge): unparseable cert, unresolved CA host, ambiguous issuer chain,
  unmatched NTAuth anchor, unresolvable OID-to-group DN.
* Deterministic: objects streamed ``ORDER BY node_id``; candidate sets sorted;
  edges deduped + sorted by ``edge_id`` in the shared buffer.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

import duckdb
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from wraith.common.determinism import stable_id
from wraith.edges.models import EdgeRow
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)


class _EdgeSink(Protocol):
    """The minimal edge-buffer contract this pass needs (``edge_engine._EdgeBuffer``)."""

    def add(self, edge: EdgeRow) -> None:
        """Add a non-ACL (NULL-mask) edge to the shared dedup buffer."""
        ...


CONFIDENCE_CONFIRMED: str = "confirmed"

# --- §4 edge kinds (additive free-VARCHAR values) ----------------------------
KIND_ENTERPRISE_CA_FOR: str = "EnterpriseCAFor"
KIND_ROOT_CA_FOR: str = "RootCAFor"
KIND_NTAUTH_STORE_FOR: str = "NTAuthStoreFor"
KIND_HOSTS_CA_SERVICE: str = "HostsCAService"
KIND_TRUSTED_FOR_NTAUTH: str = "TrustedForNTAuth"
KIND_ISSUED_SIGNED_BY: str = "IssuedSignedBy"
KIND_EXTENDED_BY_POLICY: str = "ExtendedByPolicy"
KIND_OID_GROUP_LINK: str = "OIDGroupLink"

# --- derivation tags ---------------------------------------------------------
DERIVATION_ENTERPRISE_CA_FOR: str = "ADCS:EnterpriseCAFor"
DERIVATION_ROOT_CA_FOR: str = "ADCS:RootCAFor"
DERIVATION_NTAUTH_STORE_FOR: str = "ADCS:NTAuthStoreFor"
DERIVATION_HOSTS_CA_SERVICE: str = "ADCS:HostsCAService"
DERIVATION_TRUSTED_FOR_NTAUTH: str = "ADCS:TrustedForNTAuth"
DERIVATION_ISSUED_SIGNED_BY: str = "ADCS:IssuedSignedBy"
DERIVATION_EXTENDED_BY_POLICY: str = "ADCS:ExtendedByPolicy"
DERIVATION_OID_GROUP_LINK: str = "ADCS:OIDGroupLink"

# --- adcs_type discriminants (from M3 classify) ------------------------------
_TYPE_TEMPLATE: str = "CertTemplate"
_TYPE_ENTERPRISE_CA: str = "EnterpriseCA"
_TYPE_ROOT_CA: str = "RootCA"
_TYPE_AIACA: str = "AIACA"
_TYPE_NTAUTH: str = "NTAuthStore"
_TYPE_ISSUANCE_POLICY: str = "IssuancePolicy"

#: adcs_types whose ``cACertificate`` blobs participate in the IssuedSignedBy
#: issuer/subject chain (every CA-bearing object).
_CA_CERT_TYPES: frozenset[str] = frozenset({_TYPE_ENTERPRISE_CA, _TYPE_ROOT_CA, _TYPE_AIACA})


# =============================================================================
# Decoded ADCS object (what the builders read) + cert helpers
# =============================================================================


@dataclass(frozen=True)
class AdcsObject:
    """One ADCS object as the topology pass reads it (decoded, typed).

    Attributes:
        node_id: the object's canonical node id.
        adcs_type: the §3.5 discriminant (``CertTemplate``/``EnterpriseCA``/...).
        name: the object's display/cn name (for logs; not load-bearing).
        dns_host_name: EnterpriseCA ``dNSHostName`` (for HostsCAService), else ``None``.
        certificate_policy: template ``msPKI-Certificate-Policy`` OIDs (ExtendedByPolicy).
        oid: IssuancePolicy ``msPKI-Cert-Template-OID`` (ExtendedByPolicy target key).
        oid_to_group_link: IssuancePolicy ``msDS-OIDToGroupLink`` group DN (OIDGroupLink).
        cert_ders: the raw ``cACertificate`` DER blobs (lossless, from staging).
        provenance: the object's provenance (re-stamped per emitted edge).
    """

    node_id: str
    adcs_type: str
    name: str | None
    dns_host_name: str | None
    certificate_policy: tuple[str, ...]
    oid: str | None
    oid_to_group_link: str | None
    cert_ders: tuple[bytes, ...]
    provenance: ProvenanceStruct


@dataclass(frozen=True)
class _CertInfo:
    """The three cert-identity facts the topology joins need (all strings).

    Attributes:
        fingerprint: the SHA-256 fingerprint hex (cert identity, not a DER string).
        subject_dn: the subject as a stable RFC 4514 string (chain join key).
        issuer_dn: the issuer as a stable RFC 4514 string (chain join key).
    """

    fingerprint: str
    subject_dn: str
    issuer_dn: str


def _cert_info(der: bytes) -> _CertInfo | None:
    """Parse a DER ``cACertificate`` blob and extract its three join facts.

    Delegates the parse to ``cryptography`` (never a hand-rolled ASN.1 reader) and
    extracts the fingerprint + subject + issuer under ONE guard, so the "no x509
    exception ever leaks" guarantee is structural (Phase-1 carry-forward): a
    malformed blob — or a cert whose name/fingerprint cannot be rendered — returns
    ``None`` so the caller counts one ``adcs.cert_parse_error`` gap, never crashes.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
        return _CertInfo(
            fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            subject_dn=cert.subject.rfc4514_string(),
            issuer_dn=cert.issuer.rfc4514_string(),
        )
    except Exception as exc:  # malformed cert blob -> counted gap, never a crash
        _log.debug("adcs: unparseable cACertificate blob: %s", type(exc).__name__)
        return None


# =============================================================================
# Edge builders (pure)
# =============================================================================


def _topo_edge(
    kind: str,
    derivation: str,
    source_node_id: str,
    target_node_id: str,
    source_object_id: str,
    obj_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow:
    """Build one ADCS topology §4 edge (NULL mask/GUID, confidence confirmed)."""
    forest_id, domain_id, domain_fqdn = scoping
    prov = ProvenanceStruct(
        source_file=obj_prov.source_file,
        image_sha256=obj_prov.image_sha256,
        source_object_id=source_object_id,
        directory_timestamp=obj_prov.directory_timestamp,
        ingest_run_id=obj_prov.ingest_run_id,
    )
    return EdgeRow(
        edge_id=stable_id(kind, source_node_id, target_node_id, derivation),
        kind=kind,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        is_inherited=False,
        derivation=derivation,
        access_mask=None,
        object_type_guid=None,
        confidence=CONFIDENCE_CONFIRMED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=prov,
    )


def build_to_domain_edge(
    kind: str,
    derivation: str,
    ca: AdcsObject,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow | None:
    """Build an ``X -> Domain`` topology edge (EnterpriseCAFor/RootCAFor/NTAuthStoreFor).

    Source = the ADCS object; target = the domain node. Returns ``None`` when
    there is no domain node or the object resolves to the domain itself (a
    defensive reflexive guard, silently skipped — not an expected gap).
    """
    if domain_node_id is None or ca.node_id == domain_node_id:
        return None
    return _topo_edge(
        kind, derivation, ca.node_id, domain_node_id, f"{ca.node_id}:adcs", ca.provenance, scoping
    )


def build_hosts_ca_service_edge(
    ca: AdcsObject,
    host_to_node: Mapping[str, str],
    scoping: tuple[str, str | None, str | None],
) -> tuple[EdgeRow | None, bool]:
    """Build the ``Computer -> EnterpriseCA`` HostsCAService edge.

    Resolves the CA ``dNSHostName`` (case-insensitive) against the host -> node
    index (the M5 SPN host index: every computer advertises ``HOST/<fqdn>``).
    Returns ``(edge, unresolved)`` — ``unresolved`` is ``True`` when the CA names
    a host that resolves to no computer node (a counted
    ``adcs.hostscaservice_unresolved`` gap). A CA with no ``dNSHostName`` at all
    is not counted (nothing to resolve).
    """
    if not ca.dns_host_name:
        return None, False
    host_node = host_to_node.get(ca.dns_host_name.lower())
    if host_node is None:
        return None, True
    if host_node == ca.node_id:
        return None, False
    edge = _topo_edge(
        KIND_HOSTS_CA_SERVICE,
        DERIVATION_HOSTS_CA_SERVICE,
        host_node,
        ca.node_id,
        f"{ca.node_id}:dNSHostName",
        ca.provenance,
        scoping,
    )
    return edge, False


def build_trusted_for_ntauth_edges(
    ntauth: AdcsObject,
    ntauth_cert_fps: Sequence[str],
    enterprise_fp_to_nodes: Mapping[str, frozenset[str]],
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], int]:
    """Build ``EnterpriseCA -> NTAuthStore`` TrustedForNTAuth edges for one store.

    For each cert fingerprint published in the NTAuthStore, emit one edge from
    every EnterpriseCA node whose own cert matches that fingerprint (matched on
    parsed x509 identity, not on a DER string). An NTAuth anchor that matches no
    known EnterpriseCA is a counted ``adcs.ntauth_cert_unmatched`` gap (surfaced,
    not an edge — e.g. an external/offline-root anchor).

    Returns:
        ``(edges, unmatched)``.
    """
    edges: list[EdgeRow] = []
    unmatched = 0
    seen: set[str] = set()
    for fp in ntauth_cert_fps:
        ca_nodes = enterprise_fp_to_nodes.get(fp)
        if not ca_nodes:
            unmatched += 1
            continue
        for ca_node in sorted(ca_nodes):
            if ca_node == ntauth.node_id or ca_node in seen:
                continue
            seen.add(ca_node)
            edges.append(
                _topo_edge(
                    KIND_TRUSTED_FOR_NTAUTH,
                    DERIVATION_TRUSTED_FOR_NTAUTH,
                    ca_node,
                    ntauth.node_id,
                    f"{ntauth.node_id}:NTAuthCertificates",
                    ntauth.provenance,
                    scoping,
                )
            )
    return edges, unmatched


def build_issued_signed_by_edges(
    ca: AdcsObject,
    certs: Sequence[_CertInfo],
    subject_dn_to_nodes: Mapping[str, frozenset[str]],
    scoping: tuple[str, str | None, str | None],
) -> tuple[list[EdgeRow], int]:
    """Build ``CA -> CA`` IssuedSignedBy edges from one CA object's certs.

    For each cert, look up its issuer DN in the subject-DN index (built over every
    CA object's certs). A self-signed root (issuer == subject) emits no edge. A
    unique signing CA node (other than self) emits one IssuedSignedBy edge
    (this CA -> the signing CA). Multiple DISTINCT candidate signer nodes is
    genuinely ambiguous offline -> counted ``adcs.ca_cert_chain_ambiguous``, never
    guessed. Zero candidates (external root) is simply no edge (not a gap).

    Returns:
        ``(edges, ambiguous)``.
    """
    edges: list[EdgeRow] = []
    ambiguous = 0
    seen: set[str] = set()
    for cert in certs:
        issuer = cert.issuer_dn
        if issuer == cert.subject_dn:
            continue  # self-signed root -> no IssuedSignedBy to itself
        candidates = {n for n in subject_dn_to_nodes.get(issuer, frozenset()) if n != ca.node_id}
        if not candidates:
            continue
        if len(candidates) > 1:
            ambiguous += 1
            continue
        signer = next(iter(candidates))
        if signer in seen:
            continue
        seen.add(signer)
        edges.append(
            _topo_edge(
                KIND_ISSUED_SIGNED_BY,
                DERIVATION_ISSUED_SIGNED_BY,
                ca.node_id,
                signer,
                f"{ca.node_id}:cACertificate",
                ca.provenance,
                scoping,
            )
        )
    return edges, ambiguous


def build_extended_by_policy_edges(
    template: AdcsObject,
    oid_to_policy_node: Mapping[str, str],
    scoping: tuple[str, str | None, str | None],
) -> list[EdgeRow]:
    """Build ``CertTemplate -> IssuancePolicy`` ExtendedByPolicy edges.

    Each ``msPKI-Certificate-Policy`` OID on the template that matches a known
    IssuancePolicy's ``msPKI-Cert-Template-OID`` yields one edge. A policy OID
    that matches no modeled IssuancePolicy object (e.g. a standard/well-known
    issuance OID) is simply not an edge — matching BloodHound, which only draws
    ExtendedByPolicy to a real issuance-policy node (not a counted gap).
    """
    edges: list[EdgeRow] = []
    seen: set[str] = set()
    for policy_oid in template.certificate_policy:
        policy_node = oid_to_policy_node.get(policy_oid)
        if policy_node is None or policy_node in seen or policy_node == template.node_id:
            continue
        seen.add(policy_node)
        edges.append(
            _topo_edge(
                KIND_EXTENDED_BY_POLICY,
                DERIVATION_EXTENDED_BY_POLICY,
                template.node_id,
                policy_node,
                f"{template.node_id}:msPKI-Certificate-Policy",
                template.provenance,
                scoping,
            )
        )
    return edges


def build_oid_group_link_edge(
    policy: AdcsObject,
    group_dn_to_node: Mapping[str, str],
    scoping: tuple[str, str | None, str | None],
) -> tuple[EdgeRow | None, bool]:
    """Build the ``IssuancePolicy -> Group`` OIDGroupLink edge.

    ``msDS-OIDToGroupLink`` holds the *distinguished name* of a universal group
    ([MS-ADTS] / ADCS), so it is resolved against the group-DN index built from
    the ``principal`` table (NOT a SID — the research "foreign-SID mint" note does
    not apply, there is no SID to mint from). A DN present but matching no modeled
    group is a counted ``adcs.oidgrouplink_sid_unresolved`` gap (never a guessed /
    minted bogus node). A policy with no link is not counted.

    Returns:
        ``(edge, unresolved)``.
    """
    dn = policy.oid_to_group_link
    if not dn:
        return None, False
    group_node = group_dn_to_node.get(dn.lower())
    if group_node is None:
        return None, True
    if group_node == policy.node_id:
        return None, False
    edge = _topo_edge(
        KIND_OID_GROUP_LINK,
        DERIVATION_OID_GROUP_LINK,
        policy.node_id,
        group_node,
        f"{policy.node_id}:msDS-OIDToGroupLink",
        policy.provenance,
        scoping,
    )
    return edge, False


# =============================================================================
# Result + orchestration (I/O)
# =============================================================================


@dataclass
class AdcsTopologyResult:
    """Counts from the ADCS topology pass (coverage + counted gaps; no secrets)."""

    enterprise_ca_for: int = 0
    root_ca_for: int = 0
    ntauth_store_for: int = 0
    hosts_ca_service: int = 0
    trusted_for_ntauth: int = 0
    issued_signed_by: int = 0
    extended_by_policy: int = 0
    oid_group_link: int = 0
    # counted gaps (never silent)
    hostscaservice_unresolved: int = 0
    ca_cert_chain_ambiguous: int = 0
    ntauth_cert_unmatched: int = 0
    oidgrouplink_sid_unresolved: int = 0
    cert_parse_error: int = 0
    objects_scanned: int = 0

    @property
    def edges_total(self) -> int:
        """Total topology edges emitted this pass (for logs/report)."""
        return (
            self.enterprise_ca_for
            + self.root_ca_for
            + self.ntauth_store_for
            + self.hosts_ca_service
            + self.trusted_for_ntauth
            + self.issued_signed_by
            + self.extended_by_policy
            + self.oid_group_link
        )


def _str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a struct list/scalar value to a tuple of non-empty strings."""
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        return tuple(v for v in value if isinstance(v, str) and v)
    return ()


def _opt_str(value: object) -> str | None:
    """Coerce a struct scalar to a non-empty ``str``, else ``None``."""
    return value if isinstance(value, str) and value else None


def _ci_get(attrs: Mapping[str, object], name: str) -> object:
    """Case-insensitive attribute lookup in a staging attributes dict."""
    target = name.lower()
    for key, value in attrs.items():
        if key.lower() == target:
            return value
    return None


def _collect_cert_ders(value: object) -> list[bytes]:
    """Collect every ``{"__bytes_hex__": hex}`` blob under a staging attr value.

    ``cACertificate`` is multi-valued; each value is a lossless hex-tagged DER
    blob in ``staging_object.attributes`` (not secret-denylisted). Returns every
    decoded DER (order-stable); a non-hex/garbled tag is skipped.
    """
    out: list[bytes] = []
    if isinstance(value, dict) and "__bytes_hex__" in value:
        raw = value["__bytes_hex__"]
        if isinstance(raw, str):
            try:
                out.append(bytes.fromhex(raw))
            except ValueError:
                _log.debug("adcs: non-hex cACertificate tag skipped")
    elif isinstance(value, list):
        for item in value:
            out.extend(_collect_cert_ders(item))
    return out


def _load_adcs_objects(
    con: duckdb.DuckDBPyConnection,
) -> list[AdcsObject]:
    """Load decoded :class:`AdcsObject` rows (``ORDER BY node_id``, deterministic).

    Reads the typed ``pki_flags`` facts from the ``adcs`` table and the lossless
    ``cACertificate`` DER blobs from ``staging_object.attributes`` (pki_flags
    stores a lossy ``str()`` view of the cert bytes, so the x509 chain logic uses
    the staging source).
    """
    rows = con.execute(
        "SELECT a.node_id, a.adcs_type, a.name, a.pki_flags, s.attributes, s.provenance "
        "FROM adcs a LEFT JOIN staging_object s ON s.node_id = a.node_id "
        "ORDER BY a.node_id"
    ).fetchall()
    objects: list[AdcsObject] = []
    for node_id, adcs_type, name, pki_flags, attributes_json, provenance in rows:
        if provenance is None:
            continue
        flags: Mapping[str, object] = pki_flags if isinstance(pki_flags, dict) else {}
        cert_ders: list[bytes] = []
        if attributes_json:
            try:
                attrs = json.loads(attributes_json)
            except (ValueError, TypeError):
                attrs = None
            if isinstance(attrs, dict):
                cert_ders = _collect_cert_ders(_ci_get(attrs, "cACertificate"))
        objects.append(
            AdcsObject(
                node_id=node_id,
                adcs_type=adcs_type,
                name=name,
                dns_host_name=_opt_str(flags.get("dns_host_name")),
                certificate_policy=_str_tuple(flags.get("certificate_policy")),
                oid=_opt_str(flags.get("oid")),
                oid_to_group_link=_opt_str(flags.get("oid_to_group_link")),
                cert_ders=tuple(cert_ders),
                provenance=ProvenanceStruct.model_validate(provenance),
            )
        )
    return objects


@dataclass
class _CertIndexes:
    """Parsed-cert indexes shared across the CA-cert topology edges."""

    #: subject-DN -> node ids of CA objects whose cert has that subject.
    subject_dn_to_nodes: dict[str, set[str]] = field(default_factory=dict)
    #: fingerprint -> EnterpriseCA node ids with that cert (TrustedForNTAuth).
    enterprise_fp_to_nodes: dict[str, set[str]] = field(default_factory=dict)
    #: node_id -> its parsed cert-identity facts (IssuedSignedBy, per object).
    certs_by_node: dict[str, list[_CertInfo]] = field(default_factory=dict)


def _build_cert_indexes(objects: Sequence[AdcsObject]) -> tuple[_CertIndexes, int]:
    """Parse every CA-bearing object's certs once; build the shared indexes.

    Returns ``(_CertIndexes, cert_parse_error)`` — unparseable blobs are counted,
    never silently dropped.
    """
    idx = _CertIndexes()
    parse_errors = 0
    for obj in objects:
        if obj.adcs_type not in _CA_CERT_TYPES:
            continue
        parsed: list[_CertInfo] = []
        for der in obj.cert_ders:
            info = _cert_info(der)
            if info is None:
                parse_errors += 1
                continue
            parsed.append(info)
            idx.subject_dn_to_nodes.setdefault(info.subject_dn, set()).add(obj.node_id)
            if obj.adcs_type == _TYPE_ENTERPRISE_CA:
                idx.enterprise_fp_to_nodes.setdefault(info.fingerprint, set()).add(obj.node_id)
        if parsed:
            idx.certs_by_node[obj.node_id] = parsed
    return idx, parse_errors


def _ntauth_fingerprints(objects: Sequence[AdcsObject]) -> dict[str, tuple[list[str], int]]:
    """Fingerprint every NTAuthStore's anchors; return ``node -> (fps, parse_err)``."""
    out: dict[str, tuple[list[str], int]] = {}
    for obj in objects:
        if obj.adcs_type != _TYPE_NTAUTH:
            continue
        fps: list[str] = []
        errors = 0
        for der in obj.cert_ders:
            info = _cert_info(der)
            if info is None:
                errors += 1
                continue
            fps.append(info.fingerprint)
        out[obj.node_id] = (fps, errors)
    return out


def compute_adcs_topology(
    con: duckdb.DuckDBPyConnection,
    buffer: _EdgeSink,
    domain_node_id: str | None,
    host_to_node: Mapping[str, str],
    group_dn_to_node: Mapping[str, str],
    scoping: tuple[str, str | None, str | None],
) -> AdcsTopologyResult:
    """Compute and buffer the Phase-1 ADCS topology edges; return the counts.

    Pure of the :class:`~wraith.case.ingest_run.IngestRun` (the caller bumps
    counters from the returned :class:`AdcsTopologyResult`); every edge is added
    to the shared ``buffer`` (deduped + sorted there). ``PublishedTo`` is NOT
    emitted here (slice 5B owns it). All resolution failures are counted.

    Inputs:
        con: an open canonical-store connection (``adcs`` + ``staging_object``).
        buffer: the shared ``_EdgeBuffer`` (``.add(edge)``).
        domain_node_id: the Domain object's node id (EnterpriseCAFor/RootCAFor/
            NTAuthStoreFor target), or ``None`` (those edges are then skipped).
        host_to_node: lowercased host -> computer node (the M5 SPN host index) for
            HostsCAService.
        group_dn_to_node: lowercased group DN -> node for OIDGroupLink.
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        An :class:`AdcsTopologyResult`.

    Failure modes:
        ``duckdb.Error`` on a store failure. Per-object/per-cert malformed data
        degrades to counted gaps; never a crash, never a guessed/dangling edge.
    """
    result = AdcsTopologyResult()
    objects = _load_adcs_objects(con)
    result.objects_scanned = len(objects)
    if not objects:
        return result

    cert_idx, cert_errors = _build_cert_indexes(objects)
    result.cert_parse_error += cert_errors
    ntauth_fps = _ntauth_fingerprints(objects)
    subject_index: Mapping[str, frozenset[str]] = {
        dn: frozenset(nodes) for dn, nodes in cert_idx.subject_dn_to_nodes.items()
    }
    enterprise_index: Mapping[str, frozenset[str]] = {
        fp: frozenset(nodes) for fp, nodes in cert_idx.enterprise_fp_to_nodes.items()
    }
    # First-wins on an OID collision (``node_id``-ordered stream -> deterministic),
    # matching the WRAITH setdefault convention (Phase-1 carry-forward).
    oid_to_policy_node: dict[str, str] = {}
    for obj in objects:
        if obj.adcs_type == _TYPE_ISSUANCE_POLICY and obj.oid:
            oid_to_policy_node.setdefault(obj.oid, obj.node_id)

    add = buffer.add
    for obj in objects:
        if obj.adcs_type == _TYPE_ENTERPRISE_CA:
            edge = build_to_domain_edge(
                KIND_ENTERPRISE_CA_FOR, DERIVATION_ENTERPRISE_CA_FOR, obj, domain_node_id, scoping
            )
            if edge is not None:
                add(edge)
                result.enterprise_ca_for += 1
            host_edge, unresolved = build_hosts_ca_service_edge(obj, host_to_node, scoping)
            if host_edge is not None:
                add(host_edge)
                result.hosts_ca_service += 1
            result.hostscaservice_unresolved += int(unresolved)
        elif obj.adcs_type == _TYPE_ROOT_CA:
            edge = build_to_domain_edge(
                KIND_ROOT_CA_FOR, DERIVATION_ROOT_CA_FOR, obj, domain_node_id, scoping
            )
            if edge is not None:
                add(edge)
                result.root_ca_for += 1
        elif obj.adcs_type == _TYPE_NTAUTH:
            edge = build_to_domain_edge(
                KIND_NTAUTH_STORE_FOR, DERIVATION_NTAUTH_STORE_FOR, obj, domain_node_id, scoping
            )
            if edge is not None:
                add(edge)
                result.ntauth_store_for += 1
            fps, err = ntauth_fps.get(obj.node_id, ([], 0))
            # Count malformed-DER errors from NTAuth anchors (NTAuthStore is not in
            # _CA_CERT_TYPES, so _build_cert_indexes never sees these) — otherwise a
            # bad anchor is a silent drop (§5: malformed input is a COUNTED gap).
            result.cert_parse_error += err
            nt_edges, unmatched = build_trusted_for_ntauth_edges(
                obj, fps, enterprise_index, scoping
            )
            for nt_edge in nt_edges:
                add(nt_edge)
                result.trusted_for_ntauth += 1
            result.ntauth_cert_unmatched += unmatched
        elif obj.adcs_type == _TYPE_TEMPLATE:
            for pol_edge in build_extended_by_policy_edges(obj, oid_to_policy_node, scoping):
                add(pol_edge)
                result.extended_by_policy += 1
        elif obj.adcs_type == _TYPE_ISSUANCE_POLICY:
            oid_edge, unresolved = build_oid_group_link_edge(obj, group_dn_to_node, scoping)
            if oid_edge is not None:
                add(oid_edge)
                result.oid_group_link += 1
            result.oidgrouplink_sid_unresolved += int(unresolved)

        # IssuedSignedBy spans every CA-bearing object's parsed certs.
        certs = cert_idx.certs_by_node.get(obj.node_id)
        if certs:
            chain_edges, ambiguous = build_issued_signed_by_edges(
                obj, certs, subject_index, scoping
            )
            for chain_edge in chain_edges:
                add(chain_edge)
                result.issued_signed_by += 1
            result.ca_cert_chain_ambiguous += ambiguous

    return result
