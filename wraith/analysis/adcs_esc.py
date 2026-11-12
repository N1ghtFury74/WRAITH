"""ADCS ESC attack-path composition (Phase 2) — inferred cross-object edges.

This is the dedicated ADCS *composition / analysis* pass (research
``docs/research/11-adcs-edges-decisions.md`` item 4 "composition home"): it runs
AFTER Module 5 and reads only already-confirmed facts —

* the Module-5 base edges (``Enroll`` / ``AutoEnroll`` / ``AllExtendedRights`` /
  ``GenericAll`` / ``WriteDacl`` / ``WriteOwner`` / ``GenericWrite`` /
  ``WritePKI*Flag`` / write-property edges on victims),
* the Phase-1 ADCS topology edges (``PublishedTo`` / ``TrustedForNTAuth`` /
  ``HostsCAService`` / ``ExtendedByPolicy`` / ``OIDGroupLink``),
* the Module-4 ``effective_membership`` closure (reused, NEVER re-expanded here),
* the template ``pki_flags`` (raw ``msPKI-*`` facts from Module 3), and
* the imaged DC's ``SYSTEM``-hive config flags (``StrongCertificateBinding
  Enforcement`` / ``CertificateMappingMethods``),

and composes them into the ESC attack-path edges. Every emitted edge is
``confidence="inferred"`` with a ``derivation`` id that records WHICH conditions
were satisfied (and, for ESC3, which are undecidable offline).

Verdict tiers (research item 2.2):

* **Fully offline from ntds:** ESC1, ESC4, ESC13, ESC15, EnrollOnBehalfOf,
  GoldenCert.
* **Offline given the DC SYSTEM hive (+ntds):** ESC9, ESC10a, ESC10b.
* **ntds-derivable but CA-restriction over-approximate (flagged):** ESC3.
* **CA-host-only → UNDECIDABLE offline → a LOUD counted ``ca_host_facts_absent``
  gap, NEVER a false edge:** ESC6, ESC7, ESC11, ESC16, DelegatedEnrollmentAgent.
* **Out of scope (document, emit nothing):** ESC8, ESC11-relay, ESC12,
  CoerceAndRelayNTLMToADCS.

Design rules (CLAUDE.md quality bar): no schema change (``edge.kind`` is free
VARCHAR, ``confidence`` is ``inferred``); no new third-party deps (the DC SYSTEM
hive is read through Impacket's ``winregistry`` — the SAME library already used
for the boot key — never ``regipy``); small pure builders + one I/O orchestrator;
determinism (objects streamed/sorted by id); provenance on every edge; and EVERY
parse/resolve/undecidable branch is a counted gap — never a silent drop, never a
guessed edge.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import duckdb

from wraith.common.determinism import stable_id
from wraith.edges.models import EdgeRow
from wraith.model.store import create_edge_tables
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

CONFIDENCE_INFERRED: str = "inferred"
#: Direct-from-ACE / direct-from-registry CA-host facts (ManageCA /
#: ManageCertificates) are CONFIRMED, not composites: the bit is literally present
#: in the CA ``Security`` descriptor. They carry this confidence (parity with the
#: M5 base ACL edges), distinct from the ``inferred`` ESC composites (ESC6a).
CONFIDENCE_CONFIRMED: str = "confirmed"


class _EdgeSink(Protocol):
    """The minimal edge-buffer contract this pass needs (``.add(edge)``)."""

    def add(self, edge: EdgeRow) -> None:
        """Buffer one inferred ESC edge (dedup by ``edge_id`` happens in the sink)."""
        ...


# =============================================================================
# §2.3 ESC condition-matrix constants (public [MS-CRTD]/[MS-WCCE] facts)
# =============================================================================

#: ``msPKI-Certificate-Name-Flag`` bit: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: int = 0x0000_0001
#: ``msPKI-Enrollment-Flag`` bit: CT_FLAG_PEND_ALL_REQUESTS (manager approval).
CT_FLAG_PEND_ALL_REQUESTS: int = 0x0000_0002
#: ``msPKI-Enrollment-Flag`` bit: CT_FLAG_NO_SECURITY_EXTENSION (ESC9).
CT_FLAG_NO_SECURITY_EXTENSION: int = 0x0008_0000
#: ``CertificateMappingMethods`` Schannel UPN bit (ESC10a).
CERT_MAPPING_UPN_BIT: int = 0x0000_0004

# --- EKU OIDs (client-auth-capable + enrollment-agent) -----------------------
EKU_CLIENT_AUTH: str = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON: str = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT_AUTH: str = "1.3.6.1.5.2.3.4"
EKU_ANY_PURPOSE: str = "2.5.29.37.0"
EKU_CERTIFICATE_REQUEST_AGENT: str = "1.3.6.1.4.1.311.20.2.1"

#: EKUs that make an issued cert usable for AD client authentication (research
#: §2.3 "auth EKU"). An EMPTY effective-EKU set is ALSO auth-capable (no EKU ==
#: all purposes) and is recorded with the ``no-eku`` derivation token.
_AUTH_EKUS: frozenset[str] = frozenset(
    {EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON, EKU_PKINIT_CLIENT_AUTH, EKU_ANY_PURPOSE}
)

# --- §4 edge kinds (additive free-VARCHAR values) ----------------------------
KIND_ESC1: str = "ADCSESC1"
KIND_ESC3: str = "ADCSESC3"
#: ESC4 is a WRAITH-NATIVE control fact (``holder -> CertTemplate``): "a non-admin
#: can reconfigure this template". It is DELIBERATELY NOT ``ADCSESC4`` — BloodHound's
#: ``ADCSESC4`` is the composite ``principal -> Domain`` (which additionally requires
#: the reconfigured template to be published to an NTAuth-trusted CA). Using a
#: distinct kind string prevents the M6 BloodHound export from mistaking this
#: control fact for BH's composite; M6 composes BH's ``ADCSESC4`` principal->Domain
#: FROM this fact + the NTAuth-trusted-publication facts.
KIND_ESC4: str = "WraithESC4TemplateControl"
KIND_ESC9: str = "ADCSESC9"
KIND_ESC10A: str = "ADCSESC10a"
KIND_ESC10B: str = "ADCSESC10b"
KIND_ESC13: str = "ADCSESC13"
KIND_ESC15: str = "ADCSESC15"
KIND_ENROLL_ON_BEHALF_OF: str = "EnrollOnBehalfOf"
KIND_GOLDEN_CERT: str = "GoldenCert"

# --- CA-host ESC edge kinds (ESC6/ESC7; names BH-CE parity confirmed) ---------
#: ESC7 direct SD grants (principal -> EnterpriseCA), CONFIRMED confidence. BH CE
#: has edges named exactly ``ManageCA`` / ``ManageCertificates`` (Source ∈
#: {User,Group,Computer}, Destination = EnterpriseCA), so M10 needs no translation.
KIND_MANAGE_CA: str = "ManageCA"
KIND_MANAGE_CERTIFICATES: str = "ManageCertificates"
#: ESC6a (principal -> Domain): a client-auth, enrollable template on a CA whose
#: ``EDITF_ATTRIBUTESUBJECTALTNAME2`` is set becomes ESC1-equivalent CA-wide.
#: Composed like ESC1 but gated on ``attribute_san2 is True``; ``inferred``.
KIND_ESC6A: str = "ADCSESC6a"
#: Reserved (strong-mapping-also-disabled variant); composed LATER from the per-DC
#: ``DcConfigFlags`` already read — no new collection. Not emitted in this module.
KIND_ESC6B: str = "ADCSESC6b"

# --- CA ``Security`` ACCESS_MASK role bits ([MS-CSRA] §3.1.1.7, public) --------
CA_RIGHT_MANAGE_CA: int = 0x0000_0001  # Administrator
CA_RIGHT_MANAGE_CERTIFICATES: int = 0x0000_0002  # Officer
CA_RIGHT_AUDITOR: int = 0x0000_0004
CA_RIGHT_OPERATOR: int = 0x0000_0008
CA_RIGHT_READ: int = 0x0000_0100
CA_RIGHT_ENROLL: int = 0x0000_0200
#: ``PolicyModules\<active>\EditFlags`` bit: any requester may supply an arbitrary
#: SAN (ESC6). Set => every client-auth template on the CA is ESC1-equivalent.
EDITF_ATTRIBUTESUBJECTALTNAME2: int = 0x0004_0000
#: ``InterfaceFlags`` bit: enforce packet-privacy on the ICertRequest RPC. ESC11 is
#: present when this bit is CLEAR (relay-to-ICPR possible).
IF_ENFORCEENCRYPTICERTREQUEST: int = 0x0000_0200
#: ``DisableExtensionList`` member OID (``szOID_NTDS_CA_SECURITY_EXT``) whose
#: presence disables the SID security extension CA-wide (ESC16).
OID_NTDS_CA_SECURITY_EXT: str = "1.3.6.1.4.1.311.25.2"

#: CA-node finding property names (ESC11/ESC16 are modeled as node properties /
#: findings, NOT traversable edges in v1 — BH-image ingest for those is version
#: dependent, so WRAITH does not invent non-BH edges).
NODE_PROP_ESC11: str = "esc11_no_encrypt_enforcement"
NODE_PROP_ESC16: str = "esc16_sid_ext_disabled"
#: Machine-wide DCOM-restriction host finding (separate plane from CA Security).
NODE_PROP_DCOM: str = "dcom_restrictions"

#: Prefix for every ESC-composite ``derivation`` tag.
_ESC_PREFIX: str = "ESC"

# --- confirmed base-edge kinds this pass composes ON (read from ``edge``) -----
_KIND_ENROLL: str = "Enroll"
_KIND_AUTO_ENROLL: str = "AutoEnroll"
_KIND_ALL_EXTENDED_RIGHTS: str = "AllExtendedRights"
_KIND_GENERIC_ALL: str = "GenericAll"
_KIND_GENERIC_WRITE: str = "GenericWrite"
_KIND_WRITE_DACL: str = "WriteDacl"
_KIND_WRITE_OWNER: str = "WriteOwner"
_KIND_WRITE_PKI_ENROLLMENT_FLAG: str = "WritePKIEnrollmentFlag"
_KIND_WRITE_PKI_NAME_FLAG: str = "WritePKINameFlag"
_KIND_WRITE_ALT_SECURITY_IDENTITIES: str = "WriteAltSecurityIdentities"
#: The granular DNS-Host-Name-Attributes write kind M5 WOULD emit for a scoped
#: WRITE_PROP on GUID ``72e39547-7b18-11d1-adef-00c04fd8d5cd`` (the attribute set
#: that actually grants ``dNSHostName``). The M5 ACL engine does NOT currently map
#: this GUID (it is surfaced as a counted ``unmapped_objecttype`` gap there), so
#: this kind is never produced upstream TODAY; it is listed for forward-compat and
#: ESC10b falls back to the generic-write kinds (see ``_ESC10B_KINDS`` + module doc).
_KIND_WRITE_DNS_HOST_NAME: str = "WriteDnsHostName"
_KIND_OWNS: str = "Owns"
_KIND_PUBLISHED_TO: str = "PublishedTo"
_KIND_TRUSTED_FOR_NTAUTH: str = "TrustedForNTAuth"
_KIND_HOSTS_CA_SERVICE: str = "HostsCAService"
_KIND_EXTENDED_BY_POLICY: str = "ExtendedByPolicy"
_KIND_OID_GROUP_LINK: str = "OIDGroupLink"

#: Confirmed edge kinds that grant template enrollment (research enrollability
#: core). ``GenericAll`` / ``AllExtendedRights`` subsume ``Enroll``.
_ENROLL_KINDS: frozenset[str] = frozenset(
    {_KIND_ENROLL, _KIND_AUTO_ENROLL, _KIND_ALL_EXTENDED_RIGHTS, _KIND_GENERIC_ALL}
)
#: Confirmed edge kinds that let a non-admin take over / reconfigure a template
#: (ESC4 = full control: GenericAll / WriteDacl / WriteOwner / Owns / GenericWrite /
#: the PKI-flag WriteProperty edges). ``Owns`` IS emitted by M5 (owner_edges ~3714):
#: an object owner can rewrite its DACL and so reconfigure the template, so an
#: owner's takeover path MUST qualify here or it is silently missed.
_ESC4_KINDS: frozenset[str] = frozenset(
    {
        _KIND_GENERIC_ALL,
        _KIND_GENERIC_WRITE,
        _KIND_WRITE_DACL,
        _KIND_WRITE_OWNER,
        _KIND_OWNS,
        _KIND_WRITE_PKI_ENROLLMENT_FLAG,
        _KIND_WRITE_PKI_NAME_FLAG,
    }
)
#: Confirmed edge kinds that let an attacker write a victim's userPrincipalName /
#: altSecurityIdentities (the ESC9 + ESC10a enabling control). WriteAccountRestrictions
#: is EXCLUDED — the User-Account-Restrictions property set (``4c164200-…``) does NOT
#: contain userPrincipalName/altSecurityIdentities. WritePublicInformation is EXCLUDED
#: too: userPrincipalName membership in the Public-Information property set
#: (``e48d0154-…``) could not be confirmed from [MS-ADSC], so (per the locked
#: decision) it is DROPPED rather than risk a false path. altSecurityIdentities is
#: covered by its own scoped kind (``WriteAltSecurityIdentities``).
_VICTIM_WRITE_KINDS: frozenset[str] = frozenset(
    {
        _KIND_GENERIC_ALL,
        _KIND_GENERIC_WRITE,
        _KIND_WRITE_DACL,
        _KIND_WRITE_OWNER,
        _KIND_WRITE_ALT_SECURITY_IDENTITIES,
    }
)
#: ESC10b victim control is specifically over a COMPUTER's dNSHostName, so only
#: kinds that can set dNSHostName qualify: GenericAll / GenericWrite (full/all-prop
#: write) and the granular DNS-Host-Name-Attributes write. WriteAccountRestrictions
#: is EXCLUDED — it does NOT grant dNSHostName. The granular ``WriteDnsHostName`` kind
#: is not produced by M5 today (its GUID is unmapped there), so in practice ESC10b
#: falls back to the generic-write kinds; the granular kind is kept for forward-compat.
_ESC10B_KINDS: frozenset[str] = frozenset(
    {_KIND_GENERIC_ALL, _KIND_GENERIC_WRITE, _KIND_WRITE_DNS_HOST_NAME}
)

# --- well-known SID classification (public [MS-DTYP] facts) -------------------
#: Builtin privileged group SIDs (absolute).
_HIGH_PRIV_ABSOLUTE_SIDS: frozenset[str] = frozenset(
    {
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    }
)
#: Domain-relative RIDs of privileged principals (``<domain>-<rid>``).
_HIGH_PRIV_RIDS: frozenset[int] = frozenset(
    {
        500,  # Administrator
        502,  # krbtgt
        512,  # Domain Admins
        516,  # Domain Controllers
        517,  # Cert Publishers
        518,  # Schema Admins
        519,  # Enterprise Admins
        520,  # Group Policy Creator Owners
        521,  # Read-only Domain Controllers
        498,  # Enterprise Read-only Domain Controllers
    }
)


def _trailing_rid(sid: str | None) -> int | None:
    """Return the trailing RID integer of a SID, or ``None`` if not parseable."""
    if not sid:
        return None
    tail = sid.rsplit("-", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return None


def is_high_priv_sid(sid: str | None) -> bool:
    """Return whether ``sid`` is a well-known privileged principal.

    A high-priv grantee does not make a template "low-priv enrollable" (research
    §2.3), so ESC edges are NOT emitted from these identities. ``None`` (a node
    with no SID — e.g. a container) is treated as NOT high-priv (it cannot be an
    admin group). Public [MS-DTYP] fact; never raises.
    """
    if sid is None:
        return False
    if sid in _HIGH_PRIV_ABSOLUTE_SIDS:
        return True
    rid = _trailing_rid(sid)
    return rid in _HIGH_PRIV_RIDS


# =============================================================================
# DC-config flags (read offline from the imaged DC's own SYSTEM hive)
# =============================================================================


@dataclass(frozen=True)
class DcConfigFlags:
    """The DC-config certificate-binding flags read from the imaged DC SYSTEM hive.

    Per-DC facts (research item 2.1 / open-risk "multi-DC"): these verdicts hold
    for the IMAGED DC only. ``hive_read`` distinguishes "the SYSTEM hive was not
    provided to this pass" (ESC9/10 then undecidable -> counted ``dc_config_absent``)
    from "the hive was read but the specific value is unset" (also undecidable,
    because the OS default varies by patch level and WRAITH must not guess).

    Attributes:
        strong_binding: raw ``Kdc\\StrongCertificateBindingEnforcement`` DWORD
            (0=Disabled, 1=Compatibility, 2=Full), or ``None`` if unset/unread.
        cert_mapping_methods: raw Schannel ``CertificateMappingMethods`` DWORD
            bitmask, or ``None`` if unset/unread.
        hive_read: whether a DC SYSTEM hive was actually read this run.
    """

    strong_binding: int | None = None
    cert_mapping_methods: int | None = None
    hive_read: bool = False

    @property
    def weak_binding(self) -> bool | None:
        """Whether cert binding is weak (ESC9): ``True`` if enforcement != Full(2).

        ``None`` means undecidable (the value was not read) — the composer then
        counts a ``dc_config_absent`` gap rather than guessing.
        """
        if self.strong_binding is None:
            return None
        return self.strong_binding != 2

    @property
    def strong_binding_disabled(self) -> bool | None:
        """Whether strong binding is fully Disabled (ESC10b): ``True`` iff == 0."""
        if self.strong_binding is None:
            return None
        return self.strong_binding == 0

    @property
    def upn_cert_mapping(self) -> bool | None:
        """Whether Schannel UPN cert-mapping is enabled (ESC10a): the 0x4 bit."""
        if self.cert_mapping_methods is None:
            return None
        return bool(self.cert_mapping_methods & CERT_MAPPING_UPN_BIT)


#: The "no DC SYSTEM hive read" singleton (module-level, so it is a safe default
#: argument): ESC9/10 are then undecidable -> a counted ``dc_config_absent`` gap.
DC_CONFIG_UNKNOWN: DcConfigFlags = DcConfigFlags()


def _open_system_hive(path: Path) -> object:
    """Open a SYSTEM hive via Impacket ``winregistry`` (the boot-key reader lib).

    Lazily imports Impacket (offline-cheap import; the SAME dependency used by the
    2b boot-key path — NOT ``regipy``). Prefers the version-current
    ``get_registry_parser`` factory, falling back to the classic ``Registry``
    constructor. Raises on an unreadable/invalid hive (the caller counts it).
    """
    from impacket import winregistry

    factory = getattr(winregistry, "get_registry_parser", None)
    if factory is not None:
        return factory(str(path), False)
    return winregistry.Registry(str(path), False)  # pragma: no cover - older impacket


def _read_dword(reader: object, key_path: str) -> int | None:
    """Read one REG_DWORD value by full path, or ``None`` if absent/unreadable.

    Guarded end-to-end: a missing key, a non-DWORD payload, or any Impacket
    exception degrades to ``None`` (an undecidable value, counted by the caller),
    never a crash and never a guessed default.
    """
    try:
        result = reader.getValue(key_path)  # type: ignore[attr-defined]
    except Exception as exc:  # absent key / malformed hive node -> None
        _log.debug("adcs-esc: SYSTEM value %s unreadable: %s", key_path, type(exc).__name__)
        return None
    if not result:
        return None
    data = result[1]
    if isinstance(data, bool):  # bool is an int subclass; not a DWORD payload
        return None
    if isinstance(data, int):
        return data
    if isinstance(data, (bytes, bytearray)) and len(data) >= 4:
        return int.from_bytes(bytes(data[:4]), "little")
    return None


def read_dc_config_flags(
    system_hive_path: Path | str,
) -> tuple[DcConfigFlags, int]:
    """Read the ESC9/10 DC-config flags from the imaged DC's ``SYSTEM`` hive.

    Reads, fully offline via Impacket ``winregistry`` (NO new dependency, NO
    network):

    * ``<ControlSet>\\Services\\Kdc\\StrongCertificateBindingEnforcement`` and
    * ``<ControlSet>\\Control\\SecurityProviders\\Schannel\\CertificateMappingMethods``.

    Inputs:
        system_hive_path: path to the imaged DC's ``SYSTEM`` hive (untrusted;
            validated before open).

    Returns:
        ``(DcConfigFlags, errors)`` — the flags (with ``hive_read=True`` when the
        hive opened) and the count of read failures (an unopenable hive, or an
        unreadable ``\\Select\\Current`` selector). A value simply being UNSET is
        NOT an error (it is a legitimate "undecidable" state -> ``None``), so the
        two concerns stay distinct.

    Failure modes:
        Never raises; an unopenable hive degrades to an all-``None`` flags set
        (``hive_read=False``) with ``errors == 1``.
    """
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        resolved = ensure_existing_file(system_hive_path)
    except PathSafetyError as exc:
        _log.warning("adcs-esc: SYSTEM hive path rejected: %s", exc)
        return DcConfigFlags(), 1

    try:
        reader = _open_system_hive(resolved)
    except Exception as exc:
        _log.warning(
            "adcs-esc: SYSTEM hive unreadable (%s); ESC9/10 undecidable", type(exc).__name__
        )
        return DcConfigFlags(), 1

    errors = 0
    try:
        current = _read_dword(reader, "\\Select\\Current")
        if current is None:
            errors += 1
        control_set = f"ControlSet{current:03d}" if current is not None else "ControlSet001"
        strong = _read_dword(
            reader, f"\\{control_set}\\Services\\Kdc\\StrongCertificateBindingEnforcement"
        )
        mapping = _read_dword(
            reader,
            f"\\{control_set}\\Control\\SecurityProviders\\Schannel\\CertificateMappingMethods",
        )
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # pragma: no cover - best-effort cleanup
                _log.debug("adcs-esc: SYSTEM hive close raised", exc_info=True)

    return (
        DcConfigFlags(strong_binding=strong, cert_mapping_methods=mapping, hive_read=True),
        errors,
    )


# =============================================================================
# CA-host facts — the swappable adapter SEAM (undecidable while absent)
# =============================================================================


@dataclass(frozen=True)
class CaRegistryFacts:
    """One Enterprise CA's registry facts, read from one CA host ``SYSTEM`` hive.

    Mirrors :class:`DcConfigFlags`: a raw value of ``None`` means "unread /
    undecidable" (the composer counts a gap), while a CONCRETE value — including a
    read-empty ``()`` ``disable_extension_list`` or an empty grant set — means
    "decided" (no gap). Decision ``@property``s return ``None`` only when the
    governing raw value was not read.

    Attributes:
        ca_name: the CA common name from ``Configuration\\Active`` (the correlation
            key; stored as read, normalized by :func:`normalize_ca_name` at match).
        host_fqdn: the CA host FQDN, when known (for the ``hosts_ca`` cross-check).
        security_sd: the ``Security`` REG_BINARY descriptor bytes (``None`` =>
            unread => ESC7 undecidable).
        manage_ca_sids: grantee SIDs effectively holding ManageCA (bit ``0x1``),
            SID-level deny-before-allow applied (empty = decided-none, no gap).
        manage_cert_sids: grantee SIDs effectively holding ManageCertificates
            (bit ``0x2``).
        edit_flags: ``PolicyModules\\<active>\\EditFlags`` DWORD (``None`` => unread).
        interface_flags: ``InterfaceFlags`` DWORD (``None`` => unread).
        disable_extension_list: ``DisableExtensionList`` tuple (``None`` => unread;
            ``()`` => read-empty, DECIDED, no gap).
        policy_module_resolved: whether the active policy-module subkey resolved.
        provenance: the SYSTEM-hive provenance anchor (distinct from the
            ntds.dit-sourced CA node provenance); the registry value path becomes
            each emitted edge's ``source_object_id``.
        security_parse_error: the ``Security`` value was PRESENT but ``ldaptypes``
            could not parse it. Distinct from ``security_sd is None`` (absent):
            ``True`` keeps ``security_sd=None`` (so NO ManageCA/ManageCertificates
            edge is ever emitted from grants we could not compute — the
            false-positive-forbidden rule) while letting the composer count the
            DISTINCT ``ca_security_parse_error`` gap instead of ``ca_security_absent``.
        security_ace_skipped: count of individual ``Security`` DACL ACEs that could
            not be decoded (a per-ACE degrade during an otherwise-successful parse);
            surfaced as the coverage-class ``ca_security_ace_skipped`` so a dropped,
            potentially grant-bearing ACE is never silent.
    """

    ca_name: str
    host_fqdn: str | None
    security_sd: bytes | None
    manage_ca_sids: frozenset[str]
    manage_cert_sids: frozenset[str]
    edit_flags: int | None
    interface_flags: int | None
    disable_extension_list: tuple[str, ...] | None
    policy_module_resolved: bool
    provenance: ProvenanceStruct
    security_parse_error: bool = False
    security_ace_skipped: int = 0

    @property
    def attribute_san2(self) -> bool | None:
        """ESC6: ``EDITF_ATTRIBUTESUBJECTALTNAME2`` (``None`` if EditFlags unread)."""
        if self.edit_flags is None:
            return None
        return bool(self.edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2)

    @property
    def enforce_encrypt_request(self) -> bool | None:
        """ESC11 helper: ``IF_ENFORCEENCRYPTICERTREQUEST`` set (``None`` if unread)."""
        if self.interface_flags is None:
            return None
        return bool(self.interface_flags & IF_ENFORCEENCRYPTICERTREQUEST)

    @property
    def esc11_vulnerable(self) -> bool | None:
        """ESC11 present when encryption enforcement is CLEAR (``None`` if unread)."""
        enforced = self.enforce_encrypt_request
        if enforced is None:
            return None
        return not enforced

    @property
    def sid_ext_disabled(self) -> bool | None:
        """ESC16: SID-extension OID in ``DisableExtensionList`` (``None`` if unread)."""
        disable = self.disable_extension_list
        if disable is None:
            return None
        return OID_NTDS_CA_SECURITY_EXT in disable


@dataclass(frozen=True)
class DcomRestrictions:
    """Machine-wide DCOM restrictions from the CA host ``SOFTWARE`` hive.

    A SEPARATE finding plane from the CA ``Security`` descriptor (research §4):
    DCOM governs who can reach/activate COM on the machine at all, which remote
    ESC7 abuse (``ICertAdminD2``) additionally needs. WRAITH records it but never
    merges it with — nor infers it from — the CA authorization facts.

    Attributes:
        enable_dcom: ``Microsoft\\Ole\\EnableDCOM`` (``"Y"``/``"N"``), or ``None``.
        machine_access_sd/machine_launch_sd: machine-wide access/launch limit SDs.
        default_access_sd/default_launch_sd: the default access/launch ACLs.
        provenance: the SOFTWARE-hive provenance anchor.
    """

    enable_dcom: str | None
    machine_access_sd: bytes | None
    machine_launch_sd: bytes | None
    default_access_sd: bytes | None
    default_launch_sd: bytes | None
    provenance: ProvenanceStruct

    @property
    def any_present(self) -> bool:
        """Whether any DCOM value was read (else the composer counts an absent gap)."""
        return any(
            v is not None
            for v in (
                self.enable_dcom,
                self.machine_access_sd,
                self.machine_launch_sd,
                self.default_access_sd,
                self.default_launch_sd,
            )
        )


@dataclass(frozen=True)
class CaHostFacts:
    """CA-host registry facts (ESC6/7/11/16) — the swappable adapter seam.

    These facts live ONLY in the CA host's ``SYSTEM`` + ``SOFTWARE`` registry and
    are populated by :mod:`wraith.analysis.ca_host_facts`. While ``provided`` is
    ``False`` (the default :data:`ABSENT_CA_HOST_FACTS`), every CA-host-only ESC is
    UNDECIDABLE and the composer emits a LOUD counted ``adcs.ca_host_facts_absent``
    gap instead of a (possibly false) edge. When ``provided`` is ``True`` the
    composer correlates each ``CaRegistryFacts`` to an EnterpriseCA node and emits
    the decided edges/findings (a value of ``None`` still degrades to the matching
    counted gap — never a false edge).

    Attributes:
        provided: whether a CA-host artifact was parsed into these facts.
        cas: normalized-CA-name -> :class:`CaRegistryFacts` (per Enterprise CA).
        dcom: the machine-wide :class:`DcomRestrictions`, or ``None`` if the
            ``SOFTWARE`` hive was not provided / had no OLE values.
    """

    provided: bool = False
    cas: Mapping[str, CaRegistryFacts] = field(default_factory=dict)
    dcom: DcomRestrictions | None = None


#: The default stub: NO CA-host artifact -> ESC6/7/11/16 undecidable (counted).
#: ``provided=False`` keeps the whole absent-accounting path byte-for-byte
#: unchanged for every existing call site.
ABSENT_CA_HOST_FACTS: CaHostFacts = CaHostFacts()


def normalize_ca_name(name: str | None) -> str:
    """Return the correlation-normalized CA name (casefold + strip), or ``""``.

    Deterministic, pure; used both to key :attr:`CaHostFacts.cas` and to match an
    EnterpriseCA node's ``name``. ``None``/blank collapses to ``""`` (which never
    matches a real CA, so it falls through to a loud counted gap).
    """
    if name is None:
        return ""
    return name.strip().casefold()


# =============================================================================
# Decoded template (parsed msPKI-* facts with schema-version branching)
# =============================================================================


def _opt_int(value: object) -> tuple[int | None, bool]:
    """Coerce a raw ``pki_flags`` string/int to ``(int, had_parse_error)``.

    ``pki_flags`` stores every integer ``msPKI-*`` flag as a DECIMAL string
    (``str(int)`` in the normalizer). Returns ``(None, False)`` for a genuinely
    absent value (not an error) and ``(None, True)`` for a present-but-unparseable
    value (a counted ``esc_flag_parse_error`` gap — never a silent wrong answer).
    """
    if value is None:
        return None, False
    if isinstance(value, bool):
        return None, True
    if isinstance(value, int):
        return value, False
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, False
        try:
            return int(text, 0) if text.lower().startswith("0x") else int(text), False
        except ValueError:
            return None, True
    return None, True


def _str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a struct list/scalar to a tuple of non-empty strings (order-stable)."""
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        return tuple(v for v in value if isinstance(v, str) and v)
    return ()


@dataclass(frozen=True)
class EscTemplate:
    """One ``pKICertificateTemplate`` decoded for ESC evaluation (typed).

    Attributes:
        node_id: the template's canonical node id.
        name: the template cn/name (diagnostics; not load-bearing).
        schema_version: ``msPKI-Template-Schema-Version`` (1 = V1; >=2 = V2+).
        name_flag: ``msPKI-Certificate-Name-Flag`` int, or ``None``.
        enrollment_flag: ``msPKI-Enrollment-Flag`` int, or ``None`` (absent on V1).
        ra_signature: ``msPKI-RA-Signature`` int (authorized-signature count), or
            ``None`` (absent on V1 -> treated as 0).
        ekus: the EFFECTIVE EKU OID set (schema-version branched; see
            :func:`effective_ekus`).
        provenance: the template object's provenance (re-stamped per edge).
        flag_parse_error: count of this template's unparseable integer flags.
    """

    node_id: str
    name: str | None
    schema_version: int | None
    name_flag: int | None
    enrollment_flag: int | None
    ra_signature: int | None
    ekus: tuple[str, ...]
    provenance: ProvenanceStruct
    flag_parse_error: int

    @property
    def is_v1(self) -> bool:
        """Whether this is a schema V1 template (``msPKI-Template-Schema-Version``=1).

        V1 lacks ``msPKI-Enrollment-Flag`` / ``msPKI-RA-Signature`` / application
        -policy EKUs, so the evaluator MUST branch here or it mis-reads ESC1/ESC15
        (research open-risk). A missing schema version is treated as V1 (the most
        permissive interpretation: no enrollment flag / no RA signature).
        """
        return self.schema_version is None or self.schema_version <= 1

    @property
    def supplies_subject(self) -> bool:
        """CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) set on the name flag."""
        return bool((self.name_flag or 0) & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    @property
    def manager_approval(self) -> bool:
        """Whether manager approval is required (CT_FLAG_PEND_ALL_REQUESTS 0x2).

        V1 has no ``msPKI-Enrollment-Flag`` -> no manager-approval gate -> ``False``.
        """
        if self.is_v1 or self.enrollment_flag is None:
            return False
        return bool(self.enrollment_flag & CT_FLAG_PEND_ALL_REQUESTS)

    @property
    def ra_signatures_required(self) -> int:
        """Authorized-signature count (``msPKI-RA-Signature``); 0 on V1/absent."""
        if self.is_v1 or self.ra_signature is None:
            return 0
        return self.ra_signature

    @property
    def no_security_extension(self) -> bool:
        """CT_FLAG_NO_SECURITY_EXTENSION (0x80000) set on the enrollment flag (ESC9)."""
        if self.is_v1 or self.enrollment_flag is None:
            return False
        return bool(self.enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION)

    @property
    def client_auth_capable(self) -> bool:
        """Whether the template can issue an AD-client-authentication cert.

        An auth EKU (Client Auth / Smartcard Logon / PKINIT / Any Purpose) OR an
        EMPTY effective-EKU set (no EKU == all purposes) makes it auth-capable.
        """
        if not self.ekus:
            return True
        return any(eku in _AUTH_EKUS for eku in self.ekus)

    @property
    def requires_enrollment_agent_eku(self) -> bool:
        """Whether the template carries the Certificate-Request-Agent EKU (ESC3)."""
        return EKU_CERTIFICATE_REQUEST_AGENT in self.ekus


def effective_ekus(
    schema_version: int | None,
    pki_extended_key_usage: tuple[str, ...],
    certificate_application_policy: tuple[str, ...],
) -> tuple[str, ...]:
    """Return the EFFECTIVE EKU set, schema-version branched (research open-risk).

    * **V1** (``msPKI-Template-Schema-Version`` = 1 or absent): EKUs come ONLY
      from ``pKIExtendedKeyUsage`` — V1 has no application-policy attribute.
    * **V2+**: the enrollment-governing EKUs are the application policies
      (``msPKI-Certificate-Application-Policy``) when present, else the
      ``pKIExtendedKeyUsage`` fallback.

    Pure/deterministic; input order is preserved.
    """
    is_v1 = schema_version is None or schema_version <= 1
    if is_v1:
        return pki_extended_key_usage
    return certificate_application_policy or pki_extended_key_usage


def decode_template(
    node_id: str,
    name: str | None,
    pki_flags: Mapping[str, object],
    provenance: ProvenanceStruct,
) -> EscTemplate:
    """Decode an ``adcs`` template row's ``pki_flags`` into an :class:`EscTemplate`.

    Parses the integer ``msPKI-*`` flags (counting any unparseable value as a
    ``flag_parse_error``) and computes the effective EKU set with V1/V2 branching.
    Never raises.
    """
    schema_version, e_sv = _opt_int(pki_flags.get("template_schema_version"))
    name_flag, e_nf = _opt_int(pki_flags.get("certificate_name_flag"))
    enrollment_flag, e_ef = _opt_int(pki_flags.get("enrollment_flag"))
    ra_signature, e_ra = _opt_int(pki_flags.get("ra_signature"))
    ekus = effective_ekus(
        schema_version,
        _str_tuple(pki_flags.get("extended_key_usage")),
        _str_tuple(pki_flags.get("certificate_application_policy")),
    )
    return EscTemplate(
        node_id=node_id,
        name=name,
        schema_version=schema_version,
        name_flag=name_flag,
        enrollment_flag=enrollment_flag,
        ra_signature=ra_signature,
        ekus=ekus,
        provenance=provenance,
        flag_parse_error=int(e_sv) + int(e_nf) + int(e_ef) + int(e_ra),
    )


# =============================================================================
# Loaded graph indexes (read once, deterministic)
# =============================================================================


@dataclass
class _EscGraph:
    """Everything the ESC composer reads, loaded once from the gated stores."""

    templates: list[EscTemplate] = field(default_factory=list)
    enterprise_ca_nodes: list[str] = field(default_factory=list)
    ca_provenance: dict[str, ProvenanceStruct] = field(default_factory=dict)
    #: EnterpriseCA node_id -> its ``name`` column (the CA cn; host<->CA key).
    ca_name_of: dict[str, str] = field(default_factory=dict)
    sid_of: dict[str, str | None] = field(default_factory=dict)
    #: node_id -> the SID it maps to, reversed (for CA ``Security`` grantees).
    node_of_sid: dict[str, str] = field(default_factory=dict)
    principal_type_of: dict[str, str] = field(default_factory=dict)
    #: node_id -> lowercased name labels (samaccountname sans ``$`` + DN cn), for
    #: the secondary ``hosts_ca`` host-FQDN correlation cross-check.
    principal_labels: dict[str, frozenset[str]] = field(default_factory=dict)
    #: template -> enroll-right holder node ids (Enroll/AutoEnroll/AllExt/GenericAll).
    enroll_holders: dict[str, set[str]] = field(default_factory=dict)
    #: template -> ESC4 write holder node ids.
    esc4_holders: dict[str, set[str]] = field(default_factory=dict)
    #: template -> CA node ids it is PublishedTo.
    published_cas: dict[str, set[str]] = field(default_factory=dict)
    #: CA node ids that are TrustedForNTAuth.
    ntauth_trusted_cas: set[str] = field(default_factory=set)
    #: template -> IssuancePolicy node ids (ExtendedByPolicy).
    template_policies: dict[str, set[str]] = field(default_factory=dict)
    #: IssuancePolicy -> linked Group node ids (OIDGroupLink).
    policy_groups: dict[str, set[str]] = field(default_factory=dict)
    #: (computer, CA) HostsCAService pairs, with the edge provenance.
    hosts_ca: list[tuple[str, str, ProvenanceStruct]] = field(default_factory=list)
    #: (attacker, victim, kind, provenance) victim-write edges (ESC10).
    victim_writes: list[tuple[str, str, str, ProvenanceStruct]] = field(default_factory=list)
    #: effective-membership closure: group -> its effective member node ids.
    members_of: dict[str, set[str]] = field(default_factory=dict)


def _safe_provenance(raw: object) -> ProvenanceStruct | None:
    """Validate a raw provenance payload, or ``None`` on a NULL/malformed value.

    Inputs:
        raw: the ``provenance`` column value from a store row (duck-typed).

    Returns:
        The parsed :class:`ProvenanceStruct`, or ``None`` when the payload is
        missing (SQL NULL) or does not validate. A ``None`` return is the caller's
        signal to SKIP the row AND increment a counted gap — never a mid-run crash
        and never a fact without provenance (CLAUDE.md provenance non-negotiable).

    Failure modes:
        Never raises (a pydantic validation error degrades to a counted ``None``).
    """
    if raw is None:
        return None
    try:
        return ProvenanceStruct.model_validate(raw)
    except Exception as exc:  # malformed provenance payload -> counted drop, not a crash
        _log.debug("adcs-esc: provenance payload unresolved: %s", type(exc).__name__)
        return None


def _load_principals(con: duckdb.DuckDBPyConnection, graph: _EscGraph) -> None:
    """Load principal SID/type (+ a reverse SID map and name labels).

    The extra ``samaccountname``/``distinguished_name`` columns feed two CA-host
    needs: ``node_of_sid`` resolves a CA ``Security`` grantee SID to a graph node,
    and ``principal_labels`` lets the secondary ``hosts_ca`` host-FQDN cross-check
    recognise the CA host computer. Both are additive and leave the existing
    ESC1/3/9/10 reads untouched.
    """
    rows = con.execute(
        "SELECT node_id, object_sid, principal_type, samaccountname, distinguished_name "
        "FROM principal ORDER BY node_id"
    ).fetchall()
    for node_id, object_sid, principal_type, samaccountname, distinguished_name in rows:
        graph.sid_of[node_id] = object_sid
        graph.principal_type_of[node_id] = principal_type
        if object_sid is not None and object_sid not in graph.node_of_sid:
            graph.node_of_sid[object_sid] = node_id
        labels = _principal_labels(samaccountname, distinguished_name)
        if labels:
            graph.principal_labels[node_id] = labels


def _principal_labels(samaccountname: object, distinguished_name: object) -> frozenset[str]:
    """Return lowercased host-name labels for a principal (``$`` and DN cn stripped).

    Pure; used only for the soft ``hosts_ca`` host-FQDN cross-check. Never raises.
    """
    labels: set[str] = set()
    if isinstance(samaccountname, str) and samaccountname:
        labels.add(samaccountname.rstrip("$").casefold())
    if isinstance(distinguished_name, str) and distinguished_name.upper().startswith("CN="):
        cn = distinguished_name[3:].split(",", 1)[0]
        if cn:
            labels.add(cn.casefold())
    return frozenset(label for label in labels if label)


def _load_templates_and_cas(
    con: duckdb.DuckDBPyConnection, graph: _EscGraph, result: AdcsEscResult
) -> int:
    """Load decoded templates + EnterpriseCA nodes; return total flag-parse errors.

    An ADCS row with NULL/malformed provenance is SKIPPED and counted on
    ``result.esc_template_unresolved`` (never a silent drop: a provenance-less fact
    is forbidden, so the row cannot become a template/CA, and the loss is surfaced).
    """
    rows = con.execute(
        "SELECT node_id, name, adcs_type, pki_flags, provenance FROM adcs ORDER BY node_id"
    ).fetchall()
    flag_errors = 0
    for node_id, name, adcs_type, pki_flags, provenance in rows:
        prov = _safe_provenance(provenance)
        if prov is None:
            result.esc_template_unresolved += 1
            _log.debug("adcs-esc: ADCS row %s skipped: provenance NULL/malformed", node_id)
            continue
        if adcs_type == "CertTemplate":
            flags: Mapping[str, object] = pki_flags if isinstance(pki_flags, dict) else {}
            template = decode_template(node_id, name, flags, prov)
            graph.templates.append(template)
            flag_errors += template.flag_parse_error
        elif adcs_type == "EnterpriseCA":
            graph.enterprise_ca_nodes.append(node_id)
            graph.ca_provenance[node_id] = prov
            graph.ca_name_of[node_id] = name if isinstance(name, str) else ""
    return flag_errors


def _load_edges(con: duckdb.DuckDBPyConnection, graph: _EscGraph, result: AdcsEscResult) -> None:
    """Load the confirmed base + topology edges the composer reasons over.

    All queries are ``ORDER BY edge_id`` so the in-memory buckets are built
    deterministically. The template node set gates which enroll/write edges are
    kept (an enroll ACE on a non-template object is irrelevant here). A base /
    topology edge with NULL/malformed provenance is SKIPPED and counted on
    ``result.esc_template_unresolved`` (same accounting as the ADCS loader) rather
    than raised mid-run.
    """
    template_nodes = {t.node_id for t in graph.templates}

    acl_rows = con.execute(
        "SELECT source_node_id, target_node_id, kind FROM edge "
        "WHERE kind IN "
        "('Enroll','AutoEnroll','AllExtendedRights','GenericAll','GenericWrite',"
        "'WriteDacl','WriteOwner','Owns','WritePKIEnrollmentFlag','WritePKINameFlag') "
        "ORDER BY edge_id"
    ).fetchall()
    for source, target, kind in acl_rows:
        if target not in template_nodes:
            continue
        if kind in _ENROLL_KINDS:
            graph.enroll_holders.setdefault(target, set()).add(source)
        if kind in _ESC4_KINDS:
            graph.esc4_holders.setdefault(target, set()).add(source)

    for source, target in con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = ? ORDER BY edge_id",
        [_KIND_PUBLISHED_TO],
    ).fetchall():
        graph.published_cas.setdefault(source, set()).add(target)

    for source, _target in con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = ? ORDER BY edge_id",
        [_KIND_TRUSTED_FOR_NTAUTH],
    ).fetchall():
        graph.ntauth_trusted_cas.add(source)

    for source, target in con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = ? ORDER BY edge_id",
        [_KIND_EXTENDED_BY_POLICY],
    ).fetchall():
        graph.template_policies.setdefault(source, set()).add(target)

    for source, target in con.execute(
        "SELECT source_node_id, target_node_id FROM edge WHERE kind = ? ORDER BY edge_id",
        [_KIND_OID_GROUP_LINK],
    ).fetchall():
        graph.policy_groups.setdefault(source, set()).add(target)

    for source, target, provenance in con.execute(
        "SELECT source_node_id, target_node_id, provenance FROM edge "
        "WHERE kind = ? ORDER BY edge_id",
        [_KIND_HOSTS_CA_SERVICE],
    ).fetchall():
        prov = _safe_provenance(provenance)
        if prov is None:
            result.esc_template_unresolved += 1
            continue
        graph.hosts_ca.append((source, target, prov))

    # The union of the kinds ESC9/ESC10a (``_VICTIM_WRITE_KINDS``) and ESC10b
    # (``_ESC10B_KINDS``) reason over; filtered per-ESC in the composers below.
    victim_write_kinds = sorted(_VICTIM_WRITE_KINDS | _ESC10B_KINDS)
    placeholders = ",".join("?" * len(victim_write_kinds))
    victim_sql = (
        "SELECT source_node_id, target_node_id, kind, provenance FROM edge "  # noqa: S608
        f"WHERE kind IN ({placeholders}) ORDER BY edge_id"  # kinds are bound as params
    )
    for source, target, kind, provenance in con.execute(victim_sql, victim_write_kinds).fetchall():
        prov = _safe_provenance(provenance)
        if prov is None:
            result.esc_template_unresolved += 1
            continue
        graph.victim_writes.append((source, target, kind, prov))


def _load_effective_membership(con: duckdb.DuckDBPyConnection, graph: _EscGraph) -> None:
    """Load the M4 closure as ``group -> effective members`` (reused, not rebuilt)."""
    rows = con.execute(
        "SELECT group_node_id, member_node_id FROM effective_membership "
        "ORDER BY group_node_id, member_node_id"
    ).fetchall()
    for group_node_id, member_node_id in rows:
        graph.members_of.setdefault(group_node_id, set()).add(member_node_id)


# =============================================================================
# Enrollability core + edge builder helper (pure)
# =============================================================================


def _enrollable(template: EscTemplate, graph: _EscGraph) -> tuple[frozenset[str], bool]:
    """Resolve "who can enroll in ``template``" and whether it is NTAuth-trusted.

    Returns ``(holders, published_to_trusted)`` where ``holders`` is the set of
    principals directly granted an enroll-class right on the template (research
    enrollability core; members reach the template via ``MemberOf`` traversal, so
    they are NOT re-expanded here) and ``published_to_trusted`` is ``True`` iff the
    template is published to at least one NTAuth-trusted EnterpriseCA.
    """
    holders = frozenset(graph.enroll_holders.get(template.node_id, frozenset()))
    cas = graph.published_cas.get(template.node_id, set())
    published_to_trusted = bool(cas & graph.ntauth_trusted_cas)
    return holders, published_to_trusted


def _enrollable_principals(holders: frozenset[str], graph: _EscGraph) -> frozenset[str]:
    """Return the full enrollable principal set: holders + their effective members.

    The enroll-right holders PLUS their effective members (via the M4
    ``effective_membership`` closure — READ, never re-expanded). This is the single
    source of truth for "who can actually enroll in this template", used both by
    :func:`_low_priv_enrollable` (the escalation gate) and by ESC9 (to test whether
    the victim whose UPN the attacker rewrites is itself enrollable). Pure.
    """
    enrollable: set[str] = set(holders)
    for holder in holders:
        enrollable |= graph.members_of.get(holder, set())
    return frozenset(enrollable)


def _low_priv_enrollable(holders: frozenset[str], graph: _EscGraph) -> bool:
    """Whether a NON-privileged principal can enroll (reusing the M4 closure).

    The template is "low-priv enrollable" iff any member of the enrollable set
    (:func:`_enrollable_principals`) is not a well-known privileged identity
    (research §2.3). A holder with no SID (e.g. a minted stub for a foreign/unknown
    trustee) counts as non-privileged.

    NOTE (intended behavior, not a bug): a template whose ONLY direct holder is a
    high-priv group that merely CONTAINS a low-priv member passes this gate, yet
    :func:`_emit_from_holders` emits no edge FROM that high-priv group (it skips
    high-priv sources). That is correct: the low-priv member reaches the template
    via its own ``MemberOf`` traversal in the graph, so the escalation path is
    represented without a redundant edge from the group node.
    """
    return any(
        not is_high_priv_sid(graph.sid_of.get(node))
        for node in _enrollable_principals(holders, graph)
    )


def _esc_edge(
    kind: str,
    derivation: str,
    source_node_id: str,
    target_node_id: str,
    source_object_id: str,
    anchor_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
    confidence: str = CONFIDENCE_INFERRED,
) -> EdgeRow:
    """Build one ESC §4 edge (NULL mask/GUID).

    ``confidence`` defaults to ``"inferred"`` (the ESC composites), so every
    existing call site is byte-for-byte unchanged; direct-from-registry CA-host
    facts (ManageCA/ManageCertificates) pass ``CONFIDENCE_CONFIRMED``.
    """
    forest_id, domain_id, domain_fqdn = scoping
    prov = ProvenanceStruct(
        source_file=anchor_prov.source_file,
        image_sha256=anchor_prov.image_sha256,
        source_object_id=source_object_id,
        directory_timestamp=anchor_prov.directory_timestamp,
        ingest_run_id=anchor_prov.ingest_run_id,
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
        confidence=confidence,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=prov,
    )


def _derivation(
    esc: str, satisfied: Sequence[str], anchor: str, undecidable: Sequence[str] = ()
) -> str:
    """Compose a deterministic derivation id recording satisfied/undecidable conds.

    Form: ``ESC:<edge>[cond,cond,...]:<anchor>`` with an optional
    ``~undecidable[...]`` segment (research item 4: the derivation records WHICH
    conditions held and WHICH were undecidable). Tokens are emitted in the caller's
    fixed order, so the id is byte-stable.
    """
    sat = ",".join(satisfied)
    base = f"{_ESC_PREFIX}:{esc}[{sat}]"
    if undecidable:
        base += f"~undecidable[{','.join(undecidable)}]"
    return f"{base}:{anchor}"


def _emit_from_holders(
    *,
    kind: str,
    esc: str,
    satisfied: Sequence[str],
    anchor_node: str,
    holders: frozenset[str],
    target_node: str,
    anchor_prov: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
    graph: _EscGraph,
    undecidable: Sequence[str] = (),
) -> list[EdgeRow]:
    """Emit one ESC edge per NON-privileged holder (``holder -> target``).

    High-priv holders are skipped (a grant only to admins is not an escalation —
    the "low-priv enrollable" condition). Deterministic: holders sorted.

    NOTE (intended behavior, not a bug): if a template's only holder is a high-priv
    group that CONTAINS a low-priv member, :func:`_low_priv_enrollable` still passes
    (the member can enroll) but NO edge is emitted here (the high-priv group source
    is skipped). The low-priv member still reaches the target via its own
    ``MemberOf`` traversal, so this is correct — not a missed path.
    """
    derivation = _derivation(esc, satisfied, anchor_node, undecidable)
    edges: list[EdgeRow] = []
    for holder in sorted(holders):
        if is_high_priv_sid(graph.sid_of.get(holder)):
            continue
        if holder == target_node:
            continue
        edges.append(
            _esc_edge(
                kind,
                derivation,
                holder,
                target_node,
                f"{anchor_node}:{esc}",
                anchor_prov,
                scoping,
            )
        )
    return edges


# =============================================================================
# Result + orchestration
# =============================================================================


@dataclass(frozen=True)
class CaNodeFinding:
    """A CA-host node-level finding (ESC11/ESC16/DCOM) — NOT a traversable edge.

    ESC11/ESC16 and the machine-wide DCOM restrictions have no v1 BloodHound edge
    (their BH-image ingest is version-dependent), so WRAITH records them as node
    properties/findings on the EnterpriseCA / Computer-host node, carried on the
    result for a later surfacing module. Every finding carries its HIVE provenance
    and the registry value path, so it is a fact with provenance, never a loose
    flag.

    Attributes:
        node_id: the EnterpriseCA (ESC11/ESC16) or Computer-host (DCOM) node id.
        prop: the property name (:data:`NODE_PROP_ESC11` / :data:`NODE_PROP_ESC16`
            / :data:`NODE_PROP_DCOM`).
        value: the decided value (``True`` for ESC11/ESC16; a redacted DCOM summary
            string for DCOM — never raw secret material).
        source_object_id: the registry value path the finding was decided from.
        provenance: the CA-host hive provenance anchor.
    """

    node_id: str
    prop: str
    value: bool | str
    source_object_id: str
    provenance: ProvenanceStruct


@dataclass
class AdcsEscResult:
    """Counts from the ESC composition pass (coverage + counted gaps; no secrets)."""

    esc1: int = 0
    esc3: int = 0
    esc4: int = 0
    esc9: int = 0
    esc10a: int = 0
    esc10b: int = 0
    esc13: int = 0
    esc15: int = 0
    enroll_on_behalf_of: int = 0
    golden_cert: int = 0
    # CA-host facts (emitted when a CA host hive is provided + correlated)
    manage_ca: int = 0
    manage_certificates: int = 0
    esc6a: int = 0
    #: ESC11/ESC16/DCOM node-level findings (deterministic; surfaced downstream).
    ca_node_findings: list[CaNodeFinding] = field(default_factory=list)
    # counted gaps (never silent)
    ca_host_facts_absent: int = 0
    ca_host_blocked: dict[str, int] = field(default_factory=dict)
    # --- CA-host adapter counted gaps (research 28 §5.5; every degraded branch) --
    ca_host_hive_read_error: int = 0
    ca_host_name_mismatch: int = 0
    ca_host_correlation_ambiguous: int = 0
    ca_security_absent: int = 0
    ca_security_parse_error: int = 0
    #: Coverage-class (NOT a hard gap): individual CA ``Security`` DACL ACEs that
    #: could not be decoded during an otherwise-successful parse (counted, never
    #: silent — a dropped ACE could have carried a ManageCA/Officer grant).
    ca_security_ace_skipped: int = 0
    #: Coverage-class: a ManageCA/ManageCertificates grantee SID that has no
    #: principal node in the graph (well-known/foreign SIDs legitimately have none);
    #: counted so the skipped edge is never silent.
    ca_grantee_unresolved: int = 0
    ca_edit_flags_absent: int = 0
    ca_interface_flags_absent: int = 0
    ca_disable_ext_absent: int = 0
    ca_policy_module_unresolved: int = 0
    dcom_restrictions_absent: int = 0
    dcom_sd_parse_error: int = 0
    #: ESC9/10 undecidable because a DC-config value was not available. Counted
    #: once per undecidable ESC9/10 branch. This is the SUPERSET gap (fires whether
    #: or not a hive was read); :attr:`dc_config_no_hive` is the "no hive at all"
    #: SUBSET of it, so an operator can tell "no SYSTEM hive supplied" (both > 0)
    #: from "hive read but the registry value is unset" (``dc_config_absent`` > 0
    #: while ``dc_config_no_hive`` == 0). ``hive_read=False`` is therefore NEVER
    #: rendered as "safe" — it is always a named counted gap.
    dc_config_absent: int = 0
    #: The subset of :attr:`dc_config_absent` attributable to NO DC SYSTEM hive being
    #: read this pass (``DcConfigFlags.hive_read is False``). Counted once per
    #: undecidable ESC9/10 branch, in lockstep with ``dc_config_absent`` but only when
    #: the hive was absent — the engine-plane twin of the catalog-plane
    #: ``esc_dc_config_undecidable_no_system_hive`` gap (research 16 §C).
    dc_config_no_hive: int = 0
    esc_template_unresolved: int = 0
    esc_flag_parse_error: int = 0
    # coverage context
    templates_scanned: int = 0
    enterprise_cas_scanned: int = 0

    @property
    def edges_total(self) -> int:
        """Total ESC/CA-host edges emitted this pass (for logs/report)."""
        return (
            self.esc1
            + self.esc3
            + self.esc4
            + self.esc9
            + self.esc10a
            + self.esc10b
            + self.esc13
            + self.esc15
            + self.enroll_on_behalf_of
            + self.golden_cert
            + self.manage_ca
            + self.manage_certificates
            + self.esc6a
        )

    def _block_ca_host(self, esc: str, count: int = 1) -> None:
        """Record a CA-host-undecidable blocker (per-ESC breakdown + total).

        Used by the uncovered-CA fall-through (no hive / no-match): both the
        per-ESC breakdown (:attr:`ca_host_blocked`) and the generic
        :attr:`ca_host_facts_absent` roll-up are bumped.
        """
        if count <= 0:
            return
        self.ca_host_blocked[esc] = self.ca_host_blocked.get(esc, 0) + count
        self.ca_host_facts_absent += count

    def _block_ca_host_detail(self, esc: str, count: int = 1) -> None:
        """Record a per-ESC blocker on a MATCHED CA WITHOUT the generic roll-up.

        A matched CA whose per-value fact is undecidable bumps ONLY its specific
        token (e.g. :attr:`ca_edit_flags_absent`) plus this per-ESC breakdown; the
        generic :attr:`ca_host_facts_absent` stays RESERVED for the no-hive /
        no-match uncovered-CA fall-through (research 28 §5.5), keeping ESC6
        consistent with the matched-path ESC7/ESC11/ESC16 accounting.
        """
        if count <= 0:
            return
        self.ca_host_blocked[esc] = self.ca_host_blocked.get(esc, 0) + count


def compute_adcs_esc(
    con: duckdb.DuckDBPyConnection,
    sink: _EdgeSink,
    *,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
    dc_config: DcConfigFlags = DC_CONFIG_UNKNOWN,
    ca_host_facts: CaHostFacts = ABSENT_CA_HOST_FACTS,
) -> AdcsEscResult:
    """Compose the inferred ESC edges into ``sink``; return the counts.

    Reads the confirmed M5 base edges + Phase-1 topology edges + the M4
    ``effective_membership`` closure + template ``pki_flags`` + the imaged DC's
    SYSTEM-hive flags, and emits the ESC composites (research §2.3 matrix). The
    forest-root-domain target for domain-escalation ESCs is ``domain_node_id``
    (single-forest v1). Every undecidable CA-host / DC-config condition is a LOUD
    counted gap; no false edge is ever emitted.

    Inputs:
        con: an open canonical store with the gated M3/M4/M5 tables.
        sink: the shared edge buffer (``.add(edge)``; dedup there).
        domain_node_id: the (forest-root) Domain node id, or ``None`` (the
            domain-targeted ESCs — 1/3/9/15/GoldenCert — are then skipped).
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.
        dc_config: the DC-config flags (default: not read -> ESC9/10 undecidable).
        ca_host_facts: the CA-host facts (default: absent -> ESC6/7/11/16 gaps).

    Returns:
        An :class:`AdcsEscResult`.

    Failure modes:
        ``duckdb.Error`` on a store failure. Per-template/per-flag malformed data
        and every undecidable condition degrade to counted gaps; never a crash,
        never a guessed/false edge.
    """
    graph = _EscGraph()
    result = AdcsEscResult()
    _load_principals(con, graph)
    result.esc_flag_parse_error = _load_templates_and_cas(con, graph, result)
    _load_edges(con, graph, result)
    _load_effective_membership(con, graph)
    result.templates_scanned = len(graph.templates)
    result.enterprise_cas_scanned = len(graph.enterprise_ca_nodes)

    for template in sorted(graph.templates, key=lambda t: t.node_id):
        _compose_template_escs(template, graph, sink, result, domain_node_id, scoping, dc_config)

    _compose_esc3(graph, sink, result, domain_node_id, scoping)
    _compose_esc10(graph, sink, result, scoping, dc_config)
    _compose_golden_cert(graph, sink, result, domain_node_id, scoping)
    _account_ca_host_gaps(graph, sink, result, domain_node_id, scoping, ca_host_facts)

    return result


def _compose_template_escs(
    template: EscTemplate,
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
    dc_config: DcConfigFlags,
) -> None:
    """Compose the per-template ESCs (1/4/9/13/15) for one template."""
    holders, published_to_trusted = _enrollable(template, graph)
    enrollable = bool(holders) and published_to_trusted
    low_priv = enrollable and _low_priv_enrollable(holders, graph)

    # ESC4 — a non-admin can reconfigure the template itself (no enrollability
    # precondition; the DACL write IS the escalation). Target = the template.
    esc4_holders = frozenset(graph.esc4_holders.get(template.node_id, frozenset()))
    for edge in _emit_from_holders(
        kind=KIND_ESC4,
        esc=KIND_ESC4,
        satisfied=("template-write",),
        anchor_node=template.node_id,
        holders=esc4_holders,
        target_node=template.node_id,
        anchor_prov=template.provenance,
        scoping=scoping,
        graph=graph,
    ):
        sink.add(edge)
        result.esc4 += 1

    if not enrollable:
        return

    eku_token = "no-eku" if not template.ekus else "auth-eku"

    # ESC1 — supplies-subject + auth EKU + approval off + RA-Sig 0 + low-priv
    # enrollable + NTAuth-trusted publication. Target = the forest-root Domain.
    if (
        domain_node_id is not None
        and low_priv
        and template.supplies_subject
        and template.client_auth_capable
        and not template.manager_approval
        and template.ra_signatures_required == 0
    ):
        for edge in _emit_from_holders(
            kind=KIND_ESC1,
            esc=KIND_ESC1,
            satisfied=("ess", eku_token, "no-approval", "ra0", "lowpriv", "ntauth"),
            anchor_node=template.node_id,
            holders=holders,
            target_node=domain_node_id,
            anchor_prov=template.provenance,
            scoping=scoping,
            graph=graph,
        ):
            sink.add(edge)
            result.esc1 += 1

    # ESC9 — NO_SECURITY_EXTENSION client-auth template + weak DC binding + the
    # attacker holds a UPN/altSecurityIdentities write over a VICTIM that is itself
    # enrollable in THIS template. Source = the WRITING principal (exactly like
    # ESC10a — NOT an arbitrary enrollee): the issued cert carries no SID extension
    # and maps by the rewritten UPN, so a bare enrollee cannot escalate; only a
    # principal who can rewrite an enrollable victim's UPN can. Target = the Domain.
    if (
        domain_node_id is not None
        and template.no_security_extension
        and template.client_auth_capable
    ):
        weak = dc_config.weak_binding
        if weak is None:
            # Undecidable: count the superset gap always, and the no-hive subset when
            # no SYSTEM hive was read (so "no hive" is distinct from "hive value unset").
            result.dc_config_absent += 1
            if not dc_config.hive_read:
                result.dc_config_no_hive += 1
        elif weak:
            enrollable_victims = _enrollable_principals(holders, graph)
            for attacker, victim, kind, prov in graph.victim_writes:
                if kind not in _VICTIM_WRITE_KINDS:
                    continue  # e.g. a dNSHostName-only write cannot set the UPN
                if attacker == victim or victim not in enrollable_victims:
                    continue
                derivation = _derivation(
                    KIND_ESC9,
                    ("no-sec-ext", eku_token, "weak-binding", "victim-enrollable", f"write:{kind}"),
                    f"{template.node_id}:{victim}",
                )
                sink.add(
                    _esc_edge(
                        KIND_ESC9,
                        derivation,
                        attacker,
                        domain_node_id,
                        f"{template.node_id}:{victim}:ESC9",
                        prov,
                        scoping,
                    )
                )
                result.esc9 += 1

    # ESC13 — enrollable, CLIENT-AUTH-CAPABLE template whose issuance policy links a
    # group. The OID-linked group membership is injected during PKINIT, so the cert
    # MUST be able to authenticate (a Document-Signing / EFS-only template yields no
    # group and no escalation). Target = each linked group (research: principal ->
    # Group).
    if template.client_auth_capable:
        for policy in sorted(graph.template_policies.get(template.node_id, set())):
            for group in sorted(graph.policy_groups.get(policy, set())):
                for edge in _emit_from_holders(
                    kind=KIND_ESC13,
                    esc=KIND_ESC13,
                    satisfied=("enrollable", "client-auth", "oid-group-link"),
                    anchor_node=f"{template.node_id}:{policy}",
                    holders=holders,
                    target_node=group,
                    anchor_prov=template.provenance,
                    scoping=scoping,
                    graph=graph,
                ):
                    sink.add(edge)
                    result.esc13 += 1

    # ESC15 / EKUwu (CVE-2024-49019) — V1 template + supplies-subject. Informational
    # / patched, emitted as a flagged finding edge to the forest-root Domain.
    if domain_node_id is not None and template.is_v1 and template.supplies_subject:
        for edge in _emit_from_holders(
            kind=KIND_ESC15,
            esc=KIND_ESC15,
            satisfied=("schema-v1", "ess", "enrollable", "informational-patched"),
            anchor_node=template.node_id,
            holders=holders,
            target_node=domain_node_id,
            anchor_prov=template.provenance,
            scoping=scoping,
            graph=graph,
        ):
            sink.add(edge)
            result.esc15 += 1


def _compose_esc3(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
) -> None:
    """Compose ESC3 + EnrollOnBehalfOf (enrollment-agent escalation).

    An *agent* template (enrollable, Certificate-Request-Agent EKU, **manager
    approval OFF and RA-Sig 0** — both offline template flags) plus a *target*
    template (enrollable, client-auth) yields ``EnrollOnBehalfOf`` edges (agent
    template -> each target template) and ``ADCSESC3`` edges (each non-admin holder
    of the agent template -> the forest-root Domain). An agent template that still
    requires approval or an authorized signature cannot be low-priv obtained, so it
    does NOT qualify. The agent RESTRICTIONS that would scope this live on the CA
    host (absent offline), so every edge carries a
    ``~undecidable[agent-restrictions:ca-host]`` note AND a counted
    ``ca_host_facts_absent`` gap is recorded per agent template.
    """
    agents: list[tuple[EscTemplate, frozenset[str]]] = []
    targets: list[EscTemplate] = []
    for template in sorted(graph.templates, key=lambda t: t.node_id):
        holders, published_to_trusted = _enrollable(template, graph)
        if not (holders and published_to_trusted):
            continue
        if (
            template.requires_enrollment_agent_eku
            and not template.manager_approval
            and template.ra_signatures_required == 0
        ):
            agents.append((template, holders))
        if template.client_auth_capable:
            targets.append(template)

    for agent, holders in agents:
        result._block_ca_host("esc3_agent")  # agent restriction is a CA-host fact
        undecidable = ("agent-restrictions:ca-host",)
        for target in targets:
            if target.node_id == agent.node_id:
                continue
            derivation = _derivation(
                KIND_ENROLL_ON_BEHALF_OF,
                ("agent-eku", "clientauth-target"),
                agent.node_id,
                undecidable,
            )
            sink.add(
                _esc_edge(
                    KIND_ENROLL_ON_BEHALF_OF,
                    derivation,
                    agent.node_id,
                    target.node_id,
                    f"{agent.node_id}:EnrollOnBehalfOf",
                    agent.provenance,
                    scoping,
                )
            )
            result.enroll_on_behalf_of += 1
        if domain_node_id is not None and targets:
            for edge in _emit_from_holders(
                kind=KIND_ESC3,
                esc=KIND_ESC3,
                satisfied=("agent-eku", "clientauth-target", "enrollable"),
                anchor_node=agent.node_id,
                holders=holders,
                target_node=domain_node_id,
                anchor_prov=agent.provenance,
                scoping=scoping,
                graph=graph,
                undecidable=undecidable,
            ):
                sink.add(edge)
                result.esc3 += 1


def _compose_esc10(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    scoping: tuple[str, str | None, str | None],
    dc_config: DcConfigFlags,
) -> None:
    """Compose ESC10a (UPN cert-mapping) and ESC10b (weak binding + computer).

    * **ESC10a** = Schannel ``CertificateMappingMethods`` UPN bit (0x4) + attacker
      can write the victim's UPN / altSecurityIdentities (a confirmed victim-write
      edge) -> ``ADCSESC10a`` (attacker -> victim).
    * **ESC10b** = ``StrongCertificateBindingEnforcement`` == 0 + attacker controls
      a victim COMPUTER's dNSHostName -> ``ADCSESC10b`` (attacker -> victim).

    When the DC SYSTEM hive was not read, the enabling flag is ``None`` ->
    undecidable -> a counted ``dc_config_absent`` gap (once per branch), plus the
    ``dc_config_no_hive`` subset when no hive was supplied at all, never an edge.
    Determinism: victim writes are already ``edge_id``-ordered.
    """
    upn = dc_config.upn_cert_mapping
    disabled = dc_config.strong_binding_disabled

    # Undecidable branches: count the superset gap always; count the no-hive subset
    # when no SYSTEM hive was read (keeps "no hive" distinct from "hive value unset").
    if upn is None:
        result.dc_config_absent += 1
        if not dc_config.hive_read:
            result.dc_config_no_hive += 1
    if disabled is None:
        result.dc_config_absent += 1
        if not dc_config.hive_read:
            result.dc_config_no_hive += 1

    for attacker, victim, kind, prov in graph.victim_writes:
        if attacker == victim:
            continue
        victim_is_computer = graph.principal_type_of.get(victim) == "Computer"
        # ESC10a (UPN mapping) — victim may be a user or a computer, but the write
        # must be one that can set userPrincipalName/altSecurityIdentities (a
        # dNSHostName-only write loaded for ESC10b does NOT qualify here).
        if upn and kind in _VICTIM_WRITE_KINDS:
            derivation = _derivation(KIND_ESC10A, ("upn-mapping", f"write:{kind}"), victim)
            sink.add(
                _esc_edge(
                    KIND_ESC10A,
                    derivation,
                    attacker,
                    victim,
                    f"{victim}:ADCSESC10a",
                    prov,
                    scoping,
                )
            )
            result.esc10a += 1
        # ESC10b (weak binding) — victim must be a computer and the write must be
        # able to set dNSHostName.
        if disabled and victim_is_computer and kind in _ESC10B_KINDS:
            derivation = _derivation(
                KIND_ESC10B, ("strong-binding-disabled", f"write:{kind}"), victim
            )
            sink.add(
                _esc_edge(
                    KIND_ESC10B,
                    derivation,
                    attacker,
                    victim,
                    f"{victim}:ADCSESC10b",
                    prov,
                    scoping,
                )
            )
            result.esc10b += 1


def _compose_golden_cert(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
) -> None:
    """Compose GoldenCert (CA-host compromise -> forge any cert -> Domain).

    For each ``HostsCAService`` (Computer -> EnterpriseCA) whose CA is
    ``TrustedForNTAuth`` (its cert anchors domain auth), emit ``GoldenCert``
    (the CA-host Computer -> the forest-root Domain): owning the CA key lets the
    holder forge a cert for any principal. Deterministic: pairs sorted.
    """
    if domain_node_id is None:
        return
    seen: set[tuple[str, str]] = set()
    for computer, ca_node, prov in sorted(graph.hosts_ca, key=lambda h: (h[0], h[1])):
        if ca_node not in graph.ntauth_trusted_cas:
            continue
        if computer == domain_node_id or (computer, ca_node) in seen:
            continue
        seen.add((computer, ca_node))
        derivation = _derivation(KIND_GOLDEN_CERT, ("hosts-ca", "ntauth-trusted"), ca_node)
        sink.add(
            _esc_edge(
                KIND_GOLDEN_CERT,
                derivation,
                computer,
                domain_node_id,
                f"{ca_node}:GoldenCert",
                prov,
                scoping,
            )
        )
        result.golden_cert += 1


def _account_ca_host_gaps(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
    ca_host_facts: CaHostFacts,
) -> None:
    """Dispatch: compose CA-host edges when provided, else account absent gaps.

    When ``ca_host_facts`` is absent (the default ``ABSENT_CA_HOST_FACTS``) this
    runs the ORIGINAL absent-accounting (byte-for-byte unchanged): ESC6 (per
    enrollable+client-auth template published to a trusted CA), ESC7/ESC11/ESC16
    (per EnterpriseCA) each become a LOUD counted ``adcs.ca_host_facts_absent``
    gap and NO edge is emitted. When it is provided, the dormant seam lights up:
    :func:`_compose_ca_host_edges` correlates each CA and emits the decided edges /
    findings (a still-``None`` value degrades to its specific counted gap, never a
    false edge).
    """
    if ca_host_facts.provided:
        _compose_ca_host_edges(graph, sink, result, domain_node_id, scoping, ca_host_facts)
        return

    esc6_blocked = 0
    for template in graph.templates:
        _holders, published_to_trusted = _enrollable(template, graph)
        if published_to_trusted and template.client_auth_capable and _holders:
            esc6_blocked += 1
    if esc6_blocked:
        result._block_ca_host("esc6", esc6_blocked)
        _log.warning(
            "adcs-esc: ESC6 could not be evaluated for %d template(s): CA EditFlags "
            "(EDITF_ATTRIBUTESUBJECTALTNAME2) unknown — CA host hive not provided",
            esc6_blocked,
        )

    n_cas = len(graph.enterprise_ca_nodes)
    if n_cas:
        for esc in ("esc7", "esc11", "esc16"):
            result._block_ca_host(esc, n_cas)
        _log.warning(
            "adcs-esc: ESC7/ESC11/ESC16 could not be evaluated for %d CA(s): "
            "ManageCA/ManageCertificates (Security), InterfaceFlags and "
            "DisableExtensionList live in the CA host hive — not provided",
            n_cas,
        )


# =============================================================================
# CA-host edge composition (the lit seam; research 28 §5.2-§5.5)
# =============================================================================


def _esc6_templates_for_ca(graph: _EscGraph, ca_node: str) -> list[EscTemplate]:
    """Return the ESC6-candidate templates published to ``ca_node`` (predicate reuse).

    Uses the EXACT absent-accounting predicate (``_enrollable`` holders +
    ``client_auth_capable``) restricted to templates whose ``PublishedTo`` set
    includes ``ca_node``. Deterministic (sorted by node id). Pure.
    """
    out: list[EscTemplate] = []
    for template in sorted(graph.templates, key=lambda t: t.node_id):
        holders, published_to_trusted = _enrollable(template, graph)
        if not (holders and published_to_trusted and template.client_auth_capable):
            continue
        if ca_node in graph.published_cas.get(template.node_id, set()):
            out.append(template)
    return out


def _correlate_ca(
    graph: _EscGraph, ca_node: str, ca_host_facts: CaHostFacts
) -> tuple[CaRegistryFacts | None, bool]:
    """Correlate an EnterpriseCA node to a :class:`CaRegistryFacts` (research §5.4).

    Primary key: the normalized CA common name (the node ``name`` vs the hive's
    ``Configuration\\Active`` name). Secondary cross-check: if the matched facts
    carry a ``host_fqdn`` and the ``hosts_ca`` seam ties this CA to computer
    node(s) whose labels do NOT include that FQDN's host label, a soft
    ``ca_host_correlation_ambiguous`` is flagged (the name match still wins).

    Returns ``(facts_or_None, ambiguous)``. Pure; never raises.
    """
    key = normalize_ca_name(graph.ca_name_of.get(ca_node))
    facts = ca_host_facts.cas.get(key) if key else None
    if facts is None:
        return None, False
    ambiguous = False
    if facts.host_fqdn:
        host_label = facts.host_fqdn.split(".", 1)[0].strip().casefold()
        computers = {c for c, ca, _ in graph.hosts_ca if ca == ca_node}
        if (
            host_label
            and computers
            and not any(host_label in graph.principal_labels.get(c, frozenset()) for c in computers)
        ):
            ambiguous = True
    return facts, ambiguous


def _compose_ca_host_edges(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
    ca_host_facts: CaHostFacts,
) -> None:
    """Emit CA-host edges/findings per EnterpriseCA node (the lit dormant seam).

    Per CA (sorted): correlate to a :class:`CaRegistryFacts`. NO match => fall
    through to the per-CA absent accounting (``ca_host_name_mismatch`` + the
    original ``_block_ca_host`` blockers) so an uncovered CA stays a LOUD gap
    (never a false negative). A matched CA emits ManageCA/ManageCertificates
    (ESC7, CONFIRMED), ESC6a (``inferred``, gated on ``attribute_san2 is True``),
    and ESC11/ESC16 node findings — emitting NOTHING when a value is negatively
    decided and counting the specific gap when the needed value was ``None``.
    The machine-wide DCOM plane is accounted once, after the CA loop.

    ESC1/3/9/10 composition is never referenced here, so it cannot regress.
    """
    for ca_node in sorted(graph.enterprise_ca_nodes):
        facts, ambiguous = _correlate_ca(graph, ca_node, ca_host_facts)
        if ambiguous:
            result.ca_host_correlation_ambiguous += 1
        if facts is None:
            _block_ca_no_match(graph, result, ca_node)
            continue
        anchor = facts.provenance
        _compose_ca_esc7(graph, sink, result, scoping, ca_node, facts, anchor)
        _compose_ca_esc6a(graph, sink, result, domain_node_id, scoping, ca_node, facts, anchor)
        _compose_ca_esc11_esc16(result, ca_node, facts, anchor)

    _account_dcom(result, graph, ca_host_facts)


def _block_ca_no_match(graph: _EscGraph, result: AdcsEscResult, ca_node: str) -> None:
    """Account an uncorrelated CA as a LOUD gap (``ca_host_name_mismatch`` + blocks).

    A graph EnterpriseCA with no matching hive is NOT a silent success: it is
    counted on ``ca_host_name_mismatch`` and each of its ESC6/7/11/16 stays a
    counted ``ca_host_facts_absent`` blocker (ESC6 per candidate template on THIS
    CA, ESC7/11/16 once for this CA), exactly as the fully-absent path would.
    """
    result.ca_host_name_mismatch += 1
    esc6_blocked = len(_esc6_templates_for_ca(graph, ca_node))
    if esc6_blocked:
        result._block_ca_host("esc6", esc6_blocked)
    for esc in ("esc7", "esc11", "esc16"):
        result._block_ca_host(esc, 1)
    _log.warning(
        "adcs-esc: CA %s has no matching CA-host hive (name mismatch): "
        "ESC6/7/11/16 remain counted gaps for this CA",
        ca_node,
    )


def _compose_ca_esc7(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    scoping: tuple[str, str | None, str | None],
    ca_node: str,
    facts: CaRegistryFacts,
    anchor: ProvenanceStruct,
) -> None:
    """Emit ManageCA / ManageCertificates (ESC7) from the CA ``Security`` grants.

    Direct-from-ACE CONFIRMED facts (parity with the M5 base ACL edges), one edge
    per grantee principal node -> this EnterpriseCA; member principals reach the CA
    via their own ``MemberOf`` traversal, so grantees are NOT expanded and high-priv
    grantees are NOT skipped (BH ManageCA/ManageCertificates parity).

    Two MUTUALLY-EXCLUSIVE undecidable branches, kept distinct (research 28 §5.5):
    a PRESENT-but-unparseable ``Security`` descriptor (``facts.security_parse_error``)
    counts ``ca_security_parse_error`` — NOT "no grant" — while a genuinely ABSENT
    descriptor (``security_sd is None`` and no parse error) counts
    ``ca_security_absent``. Both emit NO edge (false-positive-forbidden): the adapter
    keeps ``security_sd=None`` on a parse failure so an edge can never be minted from
    grants it could not compute. Any per-ACE decode drops during an otherwise-
    successful parse are surfaced as the coverage-class ``ca_security_ace_skipped``
    (never silent). The SID-level deny-before-allow was applied by the adapter.
    """
    result.ca_security_ace_skipped += facts.security_ace_skipped
    if facts.security_parse_error:
        result.ca_security_parse_error += 1
        _log.warning(
            "adcs-esc: CA %s Security descriptor present but unparseable -> ESC7 undecidable",
            ca_node,
        )
        return
    if facts.security_sd is None:
        result.ca_security_absent += 1
        _log.warning("adcs-esc: CA %s Security descriptor unread -> ESC7 undecidable", ca_node)
        return
    _emit_ca_role_edges(
        graph,
        sink,
        result,
        scoping,
        ca_node,
        facts,
        anchor,
        role_sids=facts.manage_ca_sids,
        kind=KIND_MANAGE_CA,
        value_name="Security",
    )
    _emit_ca_role_edges(
        graph,
        sink,
        result,
        scoping,
        ca_node,
        facts,
        anchor,
        role_sids=facts.manage_cert_sids,
        kind=KIND_MANAGE_CERTIFICATES,
        value_name="Security",
    )


def _emit_ca_role_edges(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    scoping: tuple[str, str | None, str | None],
    ca_node: str,
    facts: CaRegistryFacts,
    anchor: ProvenanceStruct,
    *,
    role_sids: frozenset[str],
    kind: str,
    value_name: str,
) -> None:
    """Emit one CONFIRMED ``kind`` edge per grantee node (deterministic; sorted)."""
    source_object_id = f"CertSvc\\Configuration\\{facts.ca_name}\\{value_name}"
    for sid in sorted(role_sids):
        node = graph.node_of_sid.get(sid)
        if node is None:
            # A grant to a SID absent from the graph has no principal node to
            # anchor; well-known/foreign SIDs legitimately have no node. Counted
            # (coverage-class, never silent) and logged, not a false edge.
            result.ca_grantee_unresolved += 1
            _log.debug("adcs-esc: CA %s %s grantee SID %s has no graph node", ca_node, kind, sid)
            continue
        if node == ca_node:
            continue
        derivation = _derivation(kind, ("ca-security",), ca_node)
        sink.add(
            _esc_edge(
                kind,
                derivation,
                node,
                ca_node,
                source_object_id,
                anchor,
                scoping,
                confidence=CONFIDENCE_CONFIRMED,
            )
        )
        if kind == KIND_MANAGE_CA:
            result.manage_ca += 1
        else:
            result.manage_certificates += 1


def _compose_ca_esc6a(
    graph: _EscGraph,
    sink: _EdgeSink,
    result: AdcsEscResult,
    domain_node_id: str | None,
    scoping: tuple[str, str | None, str | None],
    ca_node: str,
    facts: CaRegistryFacts,
    anchor: ProvenanceStruct,
) -> None:
    """Emit ESC6a (principal -> Domain) for templates on a SAN2-enabled CA.

    Reuses the EXACT ESC6 template predicate (:func:`_esc6_templates_for_ca`);
    only the final gate flips from "always block" to "block unless
    ``attribute_san2`` is decided". On a MATCHED CA, ``attribute_san2 is None``
    bumps ONLY its specific token ``ca_edit_flags_absent`` (once per candidate
    template, matching the absent-path ESC6 granularity) plus the per-ESC
    ``ca_host_blocked["esc6"]`` breakdown via :meth:`_block_ca_host_detail` — it does
    NOT roll into the generic ``ca_host_facts_absent``, which stays reserved for the
    no-hive / no-match uncovered-CA fall-through. This keeps ESC6 consistent with the
    matched-path ESC7/ESC11/ESC16 accounting (research 28 §5.5). ``False`` emits
    nothing; ``True`` emits ESC6a like ESC1 (``inferred``, high-priv holders skipped
    by :func:`_emit_from_holders`). The edge carries the HIVE provenance (``anchor``),
    not the ntds template provenance.
    """
    candidates = _esc6_templates_for_ca(graph, ca_node)
    if not candidates:
        return
    san2 = facts.attribute_san2
    if san2 is None:
        result.ca_edit_flags_absent += len(candidates)
        result._block_ca_host_detail("esc6", len(candidates))
        _log.warning(
            "adcs-esc: CA %s EditFlags unread -> ESC6 undecidable for %d template(s)",
            ca_node,
            len(candidates),
        )
        return
    if not san2 or domain_node_id is None:
        return
    for template in candidates:
        holders, _published = _enrollable(template, graph)
        eku_token = "no-eku" if not template.ekus else "auth-eku"
        for edge in _emit_from_holders(
            kind=KIND_ESC6A,
            esc=KIND_ESC6A,
            satisfied=("san2", eku_token, "enrollable", "ntauth"),
            anchor_node=f"{template.node_id}:{ca_node}",
            holders=holders,
            target_node=domain_node_id,
            anchor_prov=anchor,
            scoping=scoping,
            graph=graph,
        ):
            sink.add(edge)
            result.esc6a += 1


def _compose_ca_esc11_esc16(
    result: AdcsEscResult,
    ca_node: str,
    facts: CaRegistryFacts,
    anchor: ProvenanceStruct,
) -> None:
    """Record ESC11/ESC16 as EnterpriseCA node findings (NOT traversable edges).

    ESC11 (``InterfaceFlags`` bit CLEAR) and ESC16 (SID-ext OID in
    ``DisableExtensionList``) are modeled as node properties; an undecidable value
    (``None``) counts its specific gap (``ca_interface_flags_absent`` /
    ``ca_disable_ext_absent``), a negatively-decided value records nothing (no
    gap), and a positively-decided value appends a provenance-carrying finding.
    An unresolved policy module is a distinct ``ca_policy_module_unresolved`` gap.
    """
    if not facts.policy_module_resolved:
        result.ca_policy_module_unresolved += 1
        _log.warning("adcs-esc: CA %s active policy module unresolved", ca_node)

    esc11 = facts.esc11_vulnerable
    if esc11 is None:
        result.ca_interface_flags_absent += 1
    elif esc11:
        result.ca_node_findings.append(
            CaNodeFinding(
                node_id=ca_node,
                prop=NODE_PROP_ESC11,
                value=True,
                source_object_id=f"CertSvc\\Configuration\\{facts.ca_name}\\InterfaceFlags",
                provenance=anchor,
            )
        )

    esc16 = facts.sid_ext_disabled
    if esc16 is None:
        result.ca_disable_ext_absent += 1
    elif esc16:
        result.ca_node_findings.append(
            CaNodeFinding(
                node_id=ca_node,
                prop=NODE_PROP_ESC16,
                value=True,
                source_object_id=(
                    f"CertSvc\\Configuration\\{facts.ca_name}"
                    "\\PolicyModules\\<active>\\DisableExtensionList"
                ),
                provenance=anchor,
            )
        )


def _account_dcom(result: AdcsEscResult, graph: _EscGraph, ca_host_facts: CaHostFacts) -> None:
    """Record the machine-wide DCOM restrictions as host findings (separate plane).

    DCOM is machine-wide (one plane per host), NEVER merged with the per-CA
    ``Security`` authorization. Absent (no ``SOFTWARE`` hive, or no OLE values) =>
    ``dcom_restrictions_absent``. Present => a redacted ``EnableDCOM`` summary
    finding attached to each CA host Computer node (via ``hosts_ca``), plus one
    ``dcom_sd_parse_error`` per present-but-unparseable restriction SD. The raw SDs
    are retained only on :class:`DcomRestrictions` for a future remote-ESC7
    reachability composite; no COM-rights edge is minted in v1.
    """
    dcom = ca_host_facts.dcom
    if dcom is None or not dcom.any_present:
        result.dcom_restrictions_absent += 1
        return
    for sd in (
        dcom.machine_access_sd,
        dcom.machine_launch_sd,
        dcom.default_access_sd,
        dcom.default_launch_sd,
    ):
        if sd is not None and not _sd_parses(sd):
            result.dcom_sd_parse_error += 1
    host_nodes = sorted({c for c, _ca, _p in graph.hosts_ca})
    summary = f"EnableDCOM={dcom.enable_dcom}" if dcom.enable_dcom is not None else "EnableDCOM=?"
    for node in host_nodes:
        result.ca_node_findings.append(
            CaNodeFinding(
                node_id=node,
                prop=NODE_PROP_DCOM,
                value=summary,
                source_object_id="Microsoft\\Ole",
                provenance=dcom.provenance,
            )
        )


def _sd_parses(sd_bytes: bytes) -> bool:
    """Return whether ``sd_bytes`` parses as a self-relative SD (via impacket).

    Pure boolean probe (the parsed SD is retained on :class:`DcomRestrictions` for
    a future composite); a parse failure degrades to ``False`` -> counted
    ``dcom_sd_parse_error``. Never raises.
    """
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    try:
        SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception as exc:  # malformed DCOM SD -> counted gap, never a crash
        _log.debug("adcs-esc: DCOM SD unparseable: %s", type(exc).__name__)
        return False
    return True


# =============================================================================
# Run orchestrator (I/O: resolves the domain node, reads the DC hive, writes)
# =============================================================================

# --- coverage + skip counter keys (surfaced on the IngestRun; never silent) ---
_COV_ESC1 = "edges.adcs_esc1"
_COV_ESC3 = "edges.adcs_esc3"
_COV_ESC4 = "edges.adcs_esc4"
_COV_ESC9 = "edges.adcs_esc9"
_COV_ESC10A = "edges.adcs_esc10a"
_COV_ESC10B = "edges.adcs_esc10b"
_COV_ESC13 = "edges.adcs_esc13"
_COV_ESC15 = "edges.adcs_esc15"
_COV_ENROLL_ON_BEHALF = "edges.enroll_on_behalf_of"
_COV_GOLDEN_CERT = "edges.golden_cert"
_COV_MANAGE_CA = "edges.manage_ca"
_COV_MANAGE_CERTIFICATES = "edges.manage_certificates"
_COV_ESC6A = "edges.adcs_esc6a"
_COV_CA_NODE_FINDINGS = "adcs.ca_node_findings"
_SKIP_CA_HOST_ABSENT = "adcs.ca_host_facts_absent"
# --- CA-host adapter counted-gap skip keys (research 28 §5.5) -----------------
_SKIP_CA_HOST_HIVE_READ = "adcs.ca_host_hive_read_error"
_SKIP_CA_HOST_NAME_MISMATCH = "adcs.ca_host_name_mismatch"
_SKIP_CA_HOST_CORRELATION_AMBIGUOUS = "adcs.ca_host_correlation_ambiguous"
_SKIP_CA_SECURITY_ABSENT = "adcs.ca_security_absent"
_SKIP_CA_SECURITY_PARSE = "adcs.ca_security_parse_error"
#: Coverage-class (not a hard gap): a per-ACE decode drop / an unresolved grantee
#: SID — counted so no degraded branch is silent (research 28 §5.5).
_SKIP_CA_SECURITY_ACE_SKIPPED = "adcs.ca_security_ace_skipped"
_SKIP_CA_GRANTEE_UNRESOLVED = "adcs.ca_grantee_unresolved"
_SKIP_CA_EDIT_FLAGS_ABSENT = "adcs.ca_edit_flags_absent"
_SKIP_CA_INTERFACE_FLAGS_ABSENT = "adcs.ca_interface_flags_absent"
_SKIP_CA_DISABLE_EXT_ABSENT = "adcs.ca_disable_ext_absent"
_SKIP_CA_POLICY_MODULE_UNRESOLVED = "adcs.ca_policy_module_unresolved"
_SKIP_DCOM_ABSENT = "adcs.dcom_restrictions_absent"
_SKIP_DCOM_SD_PARSE = "adcs.dcom_sd_parse_error"
_SKIP_DC_CONFIG_ABSENT = "adcs.dc_config_absent"
#: Engine-plane twin of the catalog-plane ``esc_dc_config_undecidable_no_system_hive``
#: gap: ESC9/10 undecidable specifically because NO DC SYSTEM hive was read (a subset
#: of ``adcs.dc_config_absent``). Lets a reader of the ESC pass's own skip ledger tell
#: "no hive supplied" from "hive read but value unset" without the catalog layer.
_SKIP_DC_CONFIG_NO_HIVE = "adcs.dc_config_undecidable_no_hive"
_SKIP_TEMPLATE_UNRESOLVED = "adcs.esc_template_unresolved"
_SKIP_FLAG_PARSE = "adcs.esc_flag_parse_error"
_SKIP_DC_HIVE_READ = "adcs.dc_config_hive_read_error"


@dataclass
class _EscBuffer:
    """Local dedup buffer keyed by ``edge_id`` (first writer wins)."""

    by_id: dict[str, EdgeRow] = field(default_factory=dict)

    def add(self, edge: EdgeRow) -> None:
        """Buffer one inferred edge; first writer wins on an ``edge_id`` collision."""
        self.by_id.setdefault(edge.edge_id, edge)

    def ordered(self) -> list[EdgeRow]:
        """Return the buffered edges sorted by ``edge_id`` (byte-reproducible)."""
        return sorted(self.by_id.values(), key=lambda e: e.edge_id)


def _resolve_domain_node(con: duckdb.DuckDBPyConnection, domain_id: str | None) -> str | None:
    """Return the (forest-root) Domain node id, or ``None`` (edges then skipped)."""
    if domain_id is not None:
        row = con.execute(
            "SELECT node_id FROM container WHERE container_type = 'Domain' "
            "AND object_sid = ? ORDER BY node_id LIMIT 1",
            [domain_id],
        ).fetchone()
        if row is not None:
            return str(row[0])
    row = con.execute(
        "SELECT node_id FROM container WHERE container_type = 'Domain' ORDER BY node_id LIMIT 1"
    ).fetchone()
    return str(row[0]) if row is not None else None


def _write_new_edges(con: duckdb.DuckDBPyConnection, edges: Sequence[EdgeRow]) -> int:
    """Append new inferred edges, skipping any ``edge_id`` already present.

    The ESC pass runs AFTER M5 has written the base edges, so it APPENDS to a
    populated ``edge`` table. ``INSERT OR IGNORE`` makes re-running idempotent and
    never clobbers a confirmed base edge that happens to share an id. Returns the
    number of rows actually inserted (deterministic: edges pre-sorted by id).
    """
    if not edges:
        return 0
    before = con.execute("SELECT count(*) FROM edge").fetchone()
    placeholders = ",".join("?" * len(edges[0].to_db_values()))
    sql = f"INSERT OR IGNORE INTO edge VALUES ({placeholders})"  # noqa: S608 - fixed literal
    con.executemany(sql, [e.to_db_values() for e in edges])
    after = con.execute("SELECT count(*) FROM edge").fetchone()
    return int(after[0]) - int(before[0]) if before and after else 0


def _bump(run_coverage: dict[str, int], run_skip: dict[str, int], result: AdcsEscResult) -> None:
    """Fill the coverage/skip dicts from the result (then surfaced on the run)."""
    run_coverage[_COV_ESC1] = result.esc1
    run_coverage[_COV_ESC3] = result.esc3
    run_coverage[_COV_ESC4] = result.esc4
    run_coverage[_COV_ESC9] = result.esc9
    run_coverage[_COV_ESC10A] = result.esc10a
    run_coverage[_COV_ESC10B] = result.esc10b
    run_coverage[_COV_ESC13] = result.esc13
    run_coverage[_COV_ESC15] = result.esc15
    run_coverage[_COV_ENROLL_ON_BEHALF] = result.enroll_on_behalf_of
    run_coverage[_COV_GOLDEN_CERT] = result.golden_cert
    run_coverage[_COV_MANAGE_CA] = result.manage_ca
    run_coverage[_COV_MANAGE_CERTIFICATES] = result.manage_certificates
    run_coverage[_COV_ESC6A] = result.esc6a
    run_coverage[_COV_CA_NODE_FINDINGS] = len(result.ca_node_findings)
    run_skip[_SKIP_CA_HOST_ABSENT] = result.ca_host_facts_absent
    run_skip[_SKIP_DC_CONFIG_ABSENT] = result.dc_config_absent
    run_skip[_SKIP_DC_CONFIG_NO_HIVE] = result.dc_config_no_hive
    run_skip[_SKIP_TEMPLATE_UNRESOLVED] = result.esc_template_unresolved
    run_skip[_SKIP_FLAG_PARSE] = result.esc_flag_parse_error
    # CA-host adapter counted gaps (research 28 §5.5; every degraded branch)
    run_skip[_SKIP_CA_HOST_HIVE_READ] = result.ca_host_hive_read_error
    run_skip[_SKIP_CA_HOST_NAME_MISMATCH] = result.ca_host_name_mismatch
    run_skip[_SKIP_CA_HOST_CORRELATION_AMBIGUOUS] = result.ca_host_correlation_ambiguous
    run_skip[_SKIP_CA_SECURITY_ABSENT] = result.ca_security_absent
    run_skip[_SKIP_CA_SECURITY_PARSE] = result.ca_security_parse_error
    run_skip[_SKIP_CA_SECURITY_ACE_SKIPPED] = result.ca_security_ace_skipped
    run_skip[_SKIP_CA_GRANTEE_UNRESOLVED] = result.ca_grantee_unresolved
    run_skip[_SKIP_CA_EDIT_FLAGS_ABSENT] = result.ca_edit_flags_absent
    run_skip[_SKIP_CA_INTERFACE_FLAGS_ABSENT] = result.ca_interface_flags_absent
    run_skip[_SKIP_CA_DISABLE_EXT_ABSENT] = result.ca_disable_ext_absent
    run_skip[_SKIP_CA_POLICY_MODULE_UNRESOLVED] = result.ca_policy_module_unresolved
    run_skip[_SKIP_DCOM_ABSENT] = result.dcom_restrictions_absent
    run_skip[_SKIP_DCOM_SD_PARSE] = result.dcom_sd_parse_error


def run_adcs_esc(
    con: duckdb.DuckDBPyConnection,
    run: object,
    *,
    forest_id: str,
    domain_id: str | None,
    domain_fqdn: str | None,
    system_hive_path: Path | str | None = None,
    ca_host_facts: CaHostFacts = ABSENT_CA_HOST_FACTS,
    ca_host_hive_errors: int = 0,
) -> AdcsEscResult:
    """Run the full ESC composition pass and append the inferred edges.

    Resolves the forest-root Domain node, reads the DC-config flags from the
    imaged DC's ``SYSTEM`` hive (when a path is given; otherwise ESC9/10 are
    undecidable), composes the ESC edges, appends them idempotently to the ``edge``
    table, and surfaces every coverage/gap counter on ``run``.

    Inputs:
        con: an open canonical store with the gated M3/M4/M5 tables.
        run: the ``IngestRun`` (duck-typed: ``bump_coverage`` / ``bump_skip``).
        forest_id/domain_id/domain_fqdn: the scoping block (MUST match M3/M4/M5).
        system_hive_path: the imaged DC ``SYSTEM`` hive (for ESC9/10), or ``None``.
        ca_host_facts: the CA-host facts (default absent -> ESC6/7/11/16 gaps).
            Build these from the CA host's SYSTEM+SOFTWARE hives via
            :func:`wraith.analysis.ca_host_facts.build_ca_host_facts`.
        ca_host_hive_errors: the count of CA-host hive read errors the adapter
            reported (surfaced as ``adcs.ca_host_hive_read_error``), so a rejected
            /unopenable CA hive is a LOUD counted gap, never silent.

    Returns:
        An :class:`AdcsEscResult`.

    Failure modes:
        ``duckdb.Error`` on a store failure. A missing/invalid SYSTEM hive degrades
        to undecidable ESC9/10 (counted), never a crash.
    """
    create_edge_tables(con)
    scoping = (forest_id, domain_id, domain_fqdn)
    domain_node_id = _resolve_domain_node(con, domain_id)

    dc_config = DC_CONFIG_UNKNOWN
    hive_errors = 0
    if system_hive_path is not None:
        dc_config, hive_errors = read_dc_config_flags(system_hive_path)

    buffer = _EscBuffer()
    result = compute_adcs_esc(
        con,
        buffer,
        domain_node_id=domain_node_id,
        scoping=scoping,
        dc_config=dc_config,
        ca_host_facts=ca_host_facts,
    )
    if ca_host_hive_errors:
        result.ca_host_hive_read_error += ca_host_hive_errors
    _write_new_edges(con, buffer.ordered())

    coverage: dict[str, int] = {}
    skips: dict[str, int] = {}
    _bump(coverage, skips, result)
    if hive_errors:
        skips[_SKIP_DC_HIVE_READ] = hive_errors
    bump_coverage = getattr(run, "bump_coverage", None)
    bump_skip = getattr(run, "bump_skip", None)
    if callable(bump_coverage):
        for key, count in sorted(coverage.items()):
            if count:
                bump_coverage(key, count)
    if callable(bump_skip):
        for key, count in sorted(skips.items()):
            if count:
                bump_skip(key, count)
        for esc, count in sorted(result.ca_host_blocked.items()):
            if count:
                bump_skip(f"{_SKIP_CA_HOST_ABSENT}.{esc}", count)
    return result
