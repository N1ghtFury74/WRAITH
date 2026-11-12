"""Pure entity builders: ``ParsedObject`` -> canonical row (Module 3).

Each builder is a small pure function taking the 2a :class:`ParsedObject`, its
already-minted ``node_id``, the classification verdict, and a
:class:`BuildContext` (scoping + the first-pass index + the secret-ref and
GPC-cn maps). No I/O, no counting side effects (the pipeline owns counters), so
every builder is independently unit-testable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from wraith.model.store import DEFAULT_SOURCE_ID
from wraith.normalize.classify import ClassifiedKind
from wraith.normalize.decoders import (
    GpLinkEntry,
    decode_filetime,
    decode_trust_direction,
    decode_trust_sid_filtering,
    decode_trust_transitive,
    decode_trust_type,
    decode_uac_enabled,
)
from wraith.normalize.identity import WELL_KNOWN_SIDS, DirectoryIndex
from wraith.normalize.models import (
    AdcsRow,
    ContainerRow,
    GpoRow,
    PrincipalRow,
    StagingObjectRow,
    StructValue,
    TrustRow,
    encode_raw_attributes,
)
from wraith.parsing.ntds import ParsedObject
from wraith.parsing.ntds_secrets import StoredSecretRef
from wraith.parsing.ntds_values import as_list, as_scalar, decode_ntds_sid
from wraith.provenance.models import ProvenanceStruct

#: Attribute lDAPDisplayNames whose VALUES are (or embed) recoverable secret
#: material and therefore MUST NOT be persisted to the unencrypted canonical
#: store (NFR-05 / schema §1.5 — secrets by reference only). These are stripped
#: from ``staging_object.attributes`` before serialization; the recovered values
#: live only in the encrypted ``SecretStore`` (via 2b), referenced by
#: ``secret_refs``. Matched case-insensitively (NTDS lDAPDisplayNames vary in
#: case across forests). Covers PEK-encrypted hash/credential attributes,
#: LAPS v1/v2 cleartext+ciphertext, gMSA/KDS managed-password blobs, trust-auth
#: blobs, and the LSA secret value columns.
SECRET_ATTRIBUTE_DENYLIST: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "ms-Mcs-AdmPwd",  # LAPS v1 cleartext
        "msLAPS-Password",  # LAPS v2 cleartext
        "msLAPS-EncryptedPassword",  # LAPS v2 ciphertext
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "unicodePwd",  # NT credential (PEK-encrypted)
        "dBCSPwd",  # LM credential (PEK-encrypted)
        "ntPwdHistory",
        "lmPwdHistory",
        "supplementalCredentials",  # Kerberos keys / cleartext
        "msDS-ManagedPassword",  # gMSA managed password blob
        "msKds-RootKeyData",  # KDS root key
        "trustAuthIncoming",  # TDO trust-auth blobs
        "trustAuthOutgoing",
        "pekList",  # the PEK itself
        "priorValue",  # LSA secret value columns
        "currentValue",
    )
)

#: Non-secret attributes that superficially resemble credential attributes but
#: are REQUIRED by M5 (delegation/RBCD/key-trust/LAPS-expiry) and therefore are
#: explicitly NOT denylisted. Documented here so the two lists cannot drift.
#: (``msDS-AllowedToActOnBehalfOfOtherIdentity``, ``msDS-AllowedToDelegateTo``,
#: ``msDS-KeyCredentialLink``, ``msDS-GroupMSAMembership``,
#: ``ms-Mcs-AdmPwdExpirationTime``; the raw SD stays in ``staging_object.raw_sd``.)
_M5_REQUIRED_NON_SECRET: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-AllowedToDelegateTo",
        "msDS-KeyCredentialLink",
        "msDS-GroupMSAMembership",
        "ms-Mcs-AdmPwdExpirationTime",
    )
)


def strip_secret_attributes(attributes: Mapping[str, object]) -> dict[str, object]:
    """Return a copy of ``attributes`` with denylisted secret keys removed.

    Case-insensitive against :data:`SECRET_ATTRIBUTE_DENYLIST`. Pure; never
    raises. The removed values are recoverable only from the encrypted
    ``SecretStore`` (2b), never from the canonical store.

    Inputs:
        attributes: the object's attributes keyed by ``lDAPDisplayName``.

    Returns:
        A new dict with every denylisted key dropped (all others preserved).
    """
    return {
        name: value
        for name, value in attributes.items()
        if name.lower() not in SECRET_ATTRIBUTE_DENYLIST
    }


@dataclass(frozen=True)
class BuildContext:
    """Shared, immutable inputs threaded into every builder.

    Attributes:
        forest_id/domain_id/domain_fqdn: the §2.2 scoping block for this run.
        index: the first-pass :class:`DirectoryIndex` for DN/parent resolution.
        node_secret_refs: 2b's ``node_id -> (StoredSecretRef, ...)`` map.
        gpc_cn_to_node: lowercased GPC ``cn`` GUID -> GPO ``node_id`` (for gPLink).
    """

    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    index: DirectoryIndex
    node_secret_refs: Mapping[str, tuple[StoredSecretRef, ...]]
    gpc_cn_to_node: Mapping[str, str]
    #: Multi-source attribution stamped on staging rows (contract §2.2b, schema
    #: v1.2). Defaulted so legacy single-source callers that construct a context
    #: without a minted source_id still work (the real ingest path supplies one).
    source_id: str = DEFAULT_SOURCE_ID


def _as_int(value: object) -> int | None:
    """Coerce an attribute value to a non-boolean ``int`` (scalar), else ``None``."""
    scalar = as_scalar(value)
    if isinstance(scalar, bool):
        return None
    return scalar if isinstance(scalar, int) else None


def _as_str(value: object) -> str | None:
    """Coerce an attribute value to a non-empty ``str`` (scalar), else ``None``."""
    scalar = as_scalar(value)
    if isinstance(scalar, str) and scalar:
        return scalar
    return None


def _join_multi(value: object) -> str | None:
    """Join a (possibly multi-valued) text attribute into one string, or ``None``."""
    parts = [str(v) for v in as_list(value) if v is not None and str(v) != ""]
    return "; ".join(parts) if parts else None


def _str_list(value: object) -> list[str]:
    """Return a deduped-order-preserving list of string values (e.g. SPNs)."""
    out: list[str] = []
    for item in as_list(value):
        if item is None:
            continue
        text = str(item)
        if text and text not in out:
            out.append(text)
    return out


def _sid_history(value: object) -> list[str]:
    """Decode a multi-valued ``sIDHistory`` (raw SID bytes) to SID strings."""
    out: list[str] = []
    for item in as_list(value):
        if isinstance(item, (bytes, bytearray, memoryview)):
            decoded = decode_ntds_sid(bytes(item))
            if decoded is not None:
                out.append(decoded)
    return out


def _secret_refs(node_id: str, ctx: BuildContext) -> list[StructValue]:
    """Build the ``secret_refs`` STRUCT list from 2b's map (references only).

    Carries both 2b flags: ``decrypted`` (the stored payload is recovered
    plaintext/hash vs raw deferred ciphertext) and ``decryptable_offline``
    (whether offline decryption is even in scope) — the recovered-vs-deferred
    distinction. Still references only; never a secret value.
    """
    refs = ctx.node_secret_refs.get(node_id, ())
    return [
        {
            "secret_id": ref.secret_id,
            "secret_type": str(ref.secret_type),
            "label": ref.label,
            "decrypted": ref.decrypted,
            "decryptable_offline": ref.decryptable_offline,
        }
        for ref in refs
    ]


def build_principal(
    obj: ParsedObject,
    node_id: str,
    classified: ClassifiedKind,
    ctx: BuildContext,
) -> PrincipalRow:
    """Build a §3.1 Principal row from a security-principal object.

    Inputs:
        obj: the 2a object.
        node_id: the minted ``node_id`` (GUID-preferred, SID-fallback).
        classified: the classifier verdict (``principal_type``, ``is_fsp``).
        ctx: shared scoping/index/secret-ref context.

    Returns:
        A fully-populated :class:`PrincipalRow`.

    Failure modes:
        Never raises; absent attributes decode to ``None``/empty.
    """
    uac = _as_int(obj.attribute("userAccountControl"))
    principal_type = classified.principal_type or "User"
    display_name = _as_str(obj.attribute("displayName"))
    if classified.is_fsp:
        # Prefer the well-known canonical name; fall back to RDN / SID.
        sid = obj.object_sid
        if sid and sid in WELL_KNOWN_SIDS:
            name, wk_type = WELL_KNOWN_SIDS[sid]
            display_name = display_name or name
            principal_type = wk_type
        else:
            display_name = display_name or _as_str(obj.attribute("name")) or sid

    return PrincipalRow(
        node_id=node_id,
        object_sid=obj.object_sid,
        object_guid=obj.object_guid,
        principal_type=principal_type,
        samaccountname=obj.sam_account_name,
        upn=_as_str(obj.attribute("userPrincipalName")),
        distinguished_name=ctx.index.reconstruct_dn(obj.dnt),
        display_name=display_name,
        description=_join_multi(obj.attribute("description", scalar=False)),
        uac_flags=uac,
        enabled=decode_uac_enabled(uac),
        admincount=_as_int(obj.attribute("adminCount")),
        spns=_str_list(obj.attribute("servicePrincipalName", scalar=False)),
        sid_history=_sid_history(obj.attribute("sIDHistory", scalar=False)),
        primary_group_id=_as_int(obj.attribute("primaryGroupID")),
        pwd_last_set=decode_filetime(_as_int(obj.attribute("pwdLastSet"))),
        last_logon_timestamp=decode_filetime(_as_int(obj.attribute("lastLogonTimestamp"))),
        when_created=obj.when_created,
        when_changed=obj.when_changed,
        secret_refs=_secret_refs(node_id, ctx),
        behavior_summary_ref=None,
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
    )


def build_stub_principal(
    sid: str,
    node_id: str,
    provenance: ProvenanceStruct,
    ctx: BuildContext,
) -> PrincipalRow:
    """Build a synthetic stub Principal for an objectless referenced SID.

    Used for well-known/BUILTIN SIDs (and referenced primaryGroup/sidHistory
    SIDs) that have no backing object in the DIT. ``display_name`` is the
    canonical name when known; ``principal_type`` follows
    :data:`~wraith.normalize.identity.WELL_KNOWN_SIDS` (default ``Group``).

    Inputs:
        sid: the SID with no backing object.
        node_id: its :func:`~wraith.normalize.identity.node_id_for_sid` id.
        provenance: the synthetic provenance struct minted by the pipeline.
        ctx: shared scoping context.

    Returns:
        A stub :class:`PrincipalRow` (secret_refs empty; it is objectless).

    Failure modes:
        Never raises.
    """
    name, principal_type = WELL_KNOWN_SIDS.get(sid, (sid, "Group"))
    return PrincipalRow(
        node_id=node_id,
        object_sid=sid,
        object_guid=None,
        principal_type=principal_type,
        samaccountname=None,
        upn=None,
        distinguished_name=None,
        display_name=name,
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
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=provenance,
    )


def build_container(
    obj: ParsedObject,
    node_id: str,
    classified: ClassifiedKind,
    gplinks: Sequence[StructValue],
    ctx: BuildContext,
) -> ContainerRow:
    """Build a §3.2 OU/Container/Domain row.

    Inputs:
        obj: the 2a object.
        node_id: the minted ``node_id``.
        classified: the classifier verdict (``container_type``).
        gplinks: the resolved ``gplinks`` STRUCT list (pipeline-resolved so the
            disabled/unresolved counters can be bumped there).
        ctx: shared scoping/index context.

    Returns:
        A :class:`ContainerRow`.

    Failure modes:
        Never raises.
    """
    functional_level = _as_int(obj.attribute("msDS-Behavior-Version"))
    return ContainerRow(
        node_id=node_id,
        object_guid=obj.object_guid,
        object_sid=obj.object_sid,
        distinguished_name=ctx.index.reconstruct_dn(obj.dnt),
        container_type=classified.container_type or "Container",
        parent_node_id=ctx.index.parent_node_id(obj.dnt),
        gplinks=list(gplinks),
        functional_level=functional_level,
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
    )


@dataclass(frozen=True)
class GpLinkResolution:
    """Resolved ``gplinks`` + the per-reason skip counts for the pipeline."""

    gplinks: list[StructValue]
    disabled: int
    unresolved: int


def resolve_gplinks(
    entries: Sequence[GpLinkEntry], gpc_cn_to_node: Mapping[str, str]
) -> GpLinkResolution:
    """Resolve parsed ``gPLink`` entries to ``gplinks`` STRUCTs via the cn map.

    Disabled links (flag 0x1) are dropped and counted; an entry whose GPC cn GUID
    resolves to no GPO node is dropped and counted (so the pipeline surfaces both
    as ``normalizer.gplink_disabled`` / ``normalizer.gplink_unresolved``).

    Inputs:
        entries: parsed :class:`GpLinkEntry` list (link order preserved).
        gpc_cn_to_node: lowercased GPC cn GUID -> GPO ``node_id``.

    Returns:
        A :class:`GpLinkResolution`.

    Failure modes:
        Never raises.
    """
    gplinks: list[StructValue] = []
    disabled = 0
    unresolved = 0
    for entry in entries:
        if entry.disabled:
            disabled += 1
            continue
        gpo_node = gpc_cn_to_node.get(entry.gpo_cn_guid)
        if gpo_node is None:
            unresolved += 1
            continue
        gplinks.append(
            {
                "gpo_node_id": gpo_node,
                "enforced": entry.enforced,
                "link_order": entry.link_order,
            }
        )
    return GpLinkResolution(gplinks=gplinks, disabled=disabled, unresolved=unresolved)


def build_gpo(obj: ParsedObject, node_id: str, ctx: BuildContext) -> GpoRow:
    """Build a §3.3 GPO row (``derived_rights`` empty — SYSVOL module fills it)."""
    return GpoRow(
        node_id=node_id,
        object_guid=obj.object_guid,
        display_name=_as_str(obj.attribute("displayName")),
        gpc_file_sys_path=_as_str(obj.attribute("gPCFileSysPath")),
        derived_rights=[],
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
    )


def build_trust(obj: ParsedObject, node_id: str, ctx: BuildContext) -> TrustRow:
    """Build a §3.4 Trust row from a ``trustedDomain`` object."""
    attr = _as_int(obj.attribute("trustAttributes"))
    trust_type = _as_int(obj.attribute("trustType"))
    direction = _as_int(obj.attribute("trustDirection"))
    target_sid = None
    sec_id = as_scalar(obj.attribute("securityIdentifier", scalar=False))
    if isinstance(sec_id, (bytes, bytearray, memoryview)):
        target_sid = decode_ntds_sid(bytes(sec_id))
    return TrustRow(
        node_id=node_id,
        source_domain_id=ctx.domain_id,
        target_domain_id=target_sid,
        direction=decode_trust_direction(direction),
        trust_type=decode_trust_type(trust_type, attr),
        trust_attributes=attr,
        transitive=decode_trust_transitive(attr),
        sid_filtering=decode_trust_sid_filtering(attr),
        trust_key_ref=None,
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
    )


def _pki_flags(obj: ParsedObject) -> StructValue:
    """Capture the RAW [MS-CRTD] msPKI-* base facts as the ``pki_flags`` struct."""

    def s(ldap: str) -> str | None:
        return _as_str(obj.attribute(ldap)) or (
            str(_as_int(obj.attribute(ldap))) if _as_int(obj.attribute(ldap)) is not None else None
        )

    return {
        "certificate_name_flag": s("msPKI-Certificate-Name-Flag"),
        "enrollment_flag": s("msPKI-Enrollment-Flag"),
        "private_key_flag": s("msPKI-Private-Key-Flag"),
        "ra_signature": s("msPKI-RA-Signature"),
        "template_schema_version": s("msPKI-Template-Schema-Version"),
        "extended_key_usage": _str_list(obj.attribute("pKIExtendedKeyUsage", scalar=False)),
        "certificate_application_policy": _str_list(
            obj.attribute("msPKI-Certificate-Application-Policy", scalar=False)
        ),
        "expiration_period": s("pKIExpirationPeriod"),
        "overlap_period": s("pKIOverlapPeriod"),
        "revision": s("revision"),
        "flags": s("flags"),
        "cn": _as_str(obj.attribute("cn")) or _as_str(obj.attribute("name")),
        "ca_certificate": _str_list(obj.attribute("cACertificate", scalar=False)),
        "dns_host_name": _as_str(obj.attribute("dNSHostName")),
        # Additive raw facts for Phase-2 ADCS composition (ESC13/ESC3/OIDGroupLink)
        # and the Phase-1 ExtendedByPolicy/OIDGroupLink topology edges. Still raw,
        # within the same "raw msPKI-* facts" §3.5 struct — no contract-shape change.
        "certificate_policy": _str_list(obj.attribute("msPKI-Certificate-Policy", scalar=False)),
        "ra_application_policies": _join_multi(
            obj.attribute("msPKI-RA-Application-Policies", scalar=False)
        ),
        "oid_to_group_link": _as_str(obj.attribute("msDS-OIDToGroupLink")),
        "oid": _as_str(obj.attribute("msPKI-Cert-Template-OID")),
    }


def build_adcs(
    obj: ParsedObject, node_id: str, classified: ClassifiedKind, ctx: BuildContext
) -> AdcsRow:
    """Build a §3.5 ADCS row (raw base facts only; ``enrollment_rights`` empty)."""
    return AdcsRow(
        node_id=node_id,
        object_guid=obj.object_guid,
        name=_as_str(obj.attribute("name")) or _as_str(obj.attribute("cn")),
        adcs_type=classified.adcs_type or "CertTemplate",
        pki_flags=_pki_flags(obj),
        enrollment_rights=[],
        published_templates=_str_list(obj.attribute("certificateTemplates", scalar=False)),
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
    )


def build_staging_object(
    obj: ParsedObject,
    node_id: str,
    class_names: Sequence[str],
    ctx: BuildContext,
) -> StagingObjectRow:
    """Build the ``staging_object`` row — raw attrs + SD for M4/M5 (outside §3).

    Denylisted secret attributes (:data:`SECRET_ATTRIBUTE_DENYLIST`) are stripped
    BEFORE serialization so no recovered secret material ever lands in the
    unencrypted canonical store (NFR-05); the raw SD and the M5-required
    non-secret delegation/key-trust attributes are retained.
    """
    return StagingObjectRow(
        node_id=node_id,
        dnt=obj.dnt,
        object_guid=obj.object_guid,
        object_sid=obj.object_sid,
        object_class=list(class_names),
        raw_sd=obj.raw_sd_bytes,
        attributes_json=encode_raw_attributes(strip_secret_attributes(obj.attributes)),
        forest_id=ctx.forest_id,
        domain_id=ctx.domain_id,
        domain_fqdn=ctx.domain_fqdn,
        provenance=obj.provenance,
        source_id=ctx.source_id,
    )
