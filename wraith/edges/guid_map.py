"""The (AccessMask, ObjectType GUID) -> edge-kind fact map — the core ACL IP.

This module is a reviewed, WRAITH-native fact constant (research report item 2,
frozen by the orchestrator against spec Appendix B). The rights-GUIDs and
access-mask bits are *public facts* ([MS-DTYP] 2.4.3 / [MS-ADTS] 5.1.3.2 / MS
``adschema``); the classification logic below is re-expressed originally and does
NOT transcribe any foreign (GPL) source.

Three concerns, all pure/deterministic:

* :class:`AccessMask` — the DS-specific access-mask bits as an ``IntFlag`` (so the
  classifier reads bit names, not scattered library constants).
* the GUID -> ``(edge kind, derivation)`` fact maps (whole-object + scoped
  write / self / control-access + LAPS read).
* :func:`classify_ace` — the precedence logic (GENERIC_ALL dominates; object-type
  gating; unknown scoped-write/control GUID -> surfaced as unmapped) that turns a
  ``(mask, object_type_guid)`` pair into the list of edge facts to emit.

Scope note (slice 5A): this map intentionally covers only the SD/ACE-derived
edges of the object DACL. ADCS enrollment rights (``Enroll``/``AutoEnroll``) and
the PKI-flag write attributes are slice 5B / ADCS-base-facts and are NOT included
here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag

from wraith.parsing.schema import NtdsSchema

# --- §4 edge kinds (the ``kind`` enum values this module can produce) ---------
KIND_GENERIC_ALL: str = "GenericAll"
KIND_GENERIC_WRITE: str = "GenericWrite"
KIND_WRITE_DACL: str = "WriteDacl"
KIND_WRITE_OWNER: str = "WriteOwner"
KIND_ALL_EXTENDED_RIGHTS: str = "AllExtendedRights"
KIND_ADD_MEMBER: str = "AddMember"
KIND_ADD_SELF: str = "AddSelf"
KIND_WRITE_SPN: str = "WriteSPN"
KIND_ADD_KEY_CREDENTIAL_LINK: str = "AddKeyCredentialLink"
KIND_WRITE_ACCOUNT_RESTRICTIONS: str = "WriteAccountRestrictions"
KIND_WRITE_ALT_SECURITY_IDENTITIES: str = "WriteAltSecurityIdentities"
KIND_ADD_ALLOWED_TO_ACT: str = "AddAllowedToAct"
KIND_WRITE_GPLINK: str = "WriteGPLink"
KIND_WRITE_PUBLIC_INFORMATION: str = "WritePublicInformation"
KIND_FORCE_CHANGE_PASSWORD: str = "ForceChangePassword"  # noqa: S105 - edge-kind name, not a secret
KIND_GET_CHANGES: str = "GetChanges"
KIND_GET_CHANGES_ALL: str = "GetChangesAll"
KIND_GET_CHANGES_IN_FILTERED_SET: str = "GetChangesInFilteredSet"
KIND_READ_LAPS_PASSWORD: str = "ReadLAPSPassword"  # noqa: S105 - edge-kind name, not a secret

#: Prefix for every ACE-derived edge's ``derivation`` tag (``ACE:<kind>``).
_ACE_PREFIX: str = "ACE:"


def _derivation(kind: str) -> str:
    """Return the ``ACE:<kind>`` derivation tag for an ACL-derived edge kind."""
    return f"{_ACE_PREFIX}{kind}"


class AccessMask(IntFlag):
    """DS-specific access-mask bits ([MS-DTYP] 2.4.3 / [MS-ADTS] 5.1.3.2).

    Re-expressed as public facts (confirmed against Impacket's ``ACCESS_MASK`` /
    ``ACCESS_ALLOWED_OBJECT_ACE`` bit values) so the classifier reads named bits
    rather than importing scattered library constants. Values are the raw 32-bit
    access-mask bit positions.
    """

    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_SELF = 0x00000008
    DS_READ_PROP = 0x00000010
    DS_WRITE_PROP = 0x00000020
    DS_CONTROL_ACCESS = 0x00000100
    WRITE_DACL = 0x00040000
    WRITE_OWNER = 0x00080000
    GENERIC_ALL = 0x10000000
    GENERIC_WRITE = 0x40000000


@dataclass(frozen=True)
class AceEdgeFact:
    """One edge fact classified from an ACE: its kind, derivation, and scope.

    Attributes:
        kind: the §4 ``edge.kind`` value.
        derivation: the ``ACE:<kind>`` derivation tag.
        scoped: ``True`` when the fact was triggered by a specific ObjectType
            GUID (the edge carries that GUID in ``object_type_guid``); ``False``
            for whole-object rights (``object_type_guid`` is NULL).
    """

    kind: str
    derivation: str
    scoped: bool


def _whole(kind: str) -> AceEdgeFact:
    """Build a whole-object (``scoped=False``) fact for ``kind``."""
    return AceEdgeFact(kind=kind, derivation=_derivation(kind), scoped=False)


def _scoped(kind: str) -> AceEdgeFact:
    """Build a scoped (``scoped=True``) fact for ``kind``."""
    return AceEdgeFact(kind=kind, derivation=_derivation(kind), scoped=True)


# --- whole-object facts (ObjectType absent, or the dominating GENERIC_ALL) ----
_FACT_GENERIC_ALL: AceEdgeFact = _whole(KIND_GENERIC_ALL)
_FACT_GENERIC_WRITE: AceEdgeFact = _whole(KIND_GENERIC_WRITE)
_FACT_WRITE_DACL: AceEdgeFact = _whole(KIND_WRITE_DACL)
_FACT_WRITE_OWNER: AceEdgeFact = _whole(KIND_WRITE_OWNER)
_FACT_ALL_EXTENDED_RIGHTS: AceEdgeFact = _whole(KIND_ALL_EXTENDED_RIGHTS)

# --- base-schema attribute GUIDs (fixed, public MS adschema facts, lowercase) -
GUID_MEMBER: str = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_SERVICE_PRINCIPAL_NAME: str = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_KEY_CREDENTIAL_LINK: str = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
GUID_USER_ACCOUNT_RESTRICTIONS: str = "4c164200-20c0-11d0-a768-00aa006e0529"
GUID_ALT_SECURITY_IDENTITIES: str = "00fbf30c-91fe-11d1-aebc-0000f80367c1"
GUID_ALLOWED_TO_ACT: str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
#: ``gP-Link`` attribute ``schemaIDGUID`` — WRITE_PROP here lets an attacker link
#: a malicious GPO to the OU/Domain (WriteGPLink); public MS ``adschema`` fact.
GUID_GPLINK: str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
#: ``Public-Information`` property-set ``rightsGUID`` — WRITE_PROP on the set
#: (which contains ``servicePrincipalName`` + ``altSecurityIdentities``) enables
#: targeted Kerberoast / cert-mapping spoofing; public MS ``adschema`` fact.
GUID_PUBLIC_INFORMATION: str = "e48d0154-bcf8-11d1-8702-00c04fb96050"

# --- control-access (extended-right) GUIDs (fixed, public MS adschema facts) --
GUID_FORCE_CHANGE_PASSWORD: str = "00299570-246d-11d0-a768-00aa006e0529"  # noqa: S105 - rights-GUID
GUID_GET_CHANGES: str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL: str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_IN_FILTERED_SET: str = "89e95b76-444d-4c62-991a-0facbeda640c"

#: Scoped ``WRITE_PROP`` facts by ObjectType GUID (lowercase).
_WRITE_PROP_MAP: dict[str, AceEdgeFact] = {
    GUID_MEMBER: _scoped(KIND_ADD_MEMBER),
    GUID_SERVICE_PRINCIPAL_NAME: _scoped(KIND_WRITE_SPN),
    GUID_KEY_CREDENTIAL_LINK: _scoped(KIND_ADD_KEY_CREDENTIAL_LINK),
    GUID_USER_ACCOUNT_RESTRICTIONS: _scoped(KIND_WRITE_ACCOUNT_RESTRICTIONS),
    GUID_ALT_SECURITY_IDENTITIES: _scoped(KIND_WRITE_ALT_SECURITY_IDENTITIES),
    GUID_ALLOWED_TO_ACT: _scoped(KIND_ADD_ALLOWED_TO_ACT),
    GUID_GPLINK: _scoped(KIND_WRITE_GPLINK),
    GUID_PUBLIC_INFORMATION: _scoped(KIND_WRITE_PUBLIC_INFORMATION),
}

#: Scoped ``DS_SELF`` (validated-write) facts by ObjectType GUID (lowercase).
_SELF_MAP: dict[str, AceEdgeFact] = {
    GUID_MEMBER: _scoped(KIND_ADD_SELF),
    GUID_SERVICE_PRINCIPAL_NAME: _scoped(KIND_WRITE_SPN),
}

#: Scoped ``CONTROL_ACCESS`` facts by extended-right GUID (lowercase).
_CONTROL_ACCESS_MAP: dict[str, AceEdgeFact] = {
    GUID_FORCE_CHANGE_PASSWORD: _scoped(KIND_FORCE_CHANGE_PASSWORD),
    GUID_GET_CHANGES: _scoped(KIND_GET_CHANGES),
    GUID_GET_CHANGES_ALL: _scoped(KIND_GET_CHANGES_ALL),
    GUID_GET_CHANGES_IN_FILTERED_SET: _scoped(KIND_GET_CHANGES_IN_FILTERED_SET),
}

#: LDAP display names of the LAPS password attributes whose per-forest
#: ``schemaIDGUID`` keys ``ReadLAPSPassword`` (legacy LAPS v1 + Windows LAPS v2).
LAPS_ATTRIBUTE_NAMES: tuple[str, ...] = (
    "ms-Mcs-AdmPwd",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
)

#: The fact emitted for a ``READ_PROP`` ACE on a resolved LAPS attribute GUID.
_FACT_READ_LAPS: AceEdgeFact = _scoped(KIND_READ_LAPS_PASSWORD)

#: Edge kinds whose synthesis is not an ObjectType-scoped ACL grant (no
#: ``object_type_guid``): used by the orchestrator to NULL the column.
WHOLE_OBJECT_KINDS: frozenset[str] = frozenset(
    {
        KIND_GENERIC_ALL,
        KIND_GENERIC_WRITE,
        KIND_WRITE_DACL,
        KIND_WRITE_OWNER,
        KIND_ALL_EXTENDED_RIGHTS,
    }
)


@dataclass(frozen=True)
class ClassifyResult:
    """The outcome of classifying one ACE.

    Attributes:
        facts: the edge facts to emit (de-duplicated, order-stable).
        unmapped_objecttype: ``True`` when the ACE carried a WRITE_PROP / SELF /
            CONTROL_ACCESS bit **and** a specific ObjectType GUID that is not in
            any fact map (skipped, surfaced as a counted gap — never a generic
            fallback, which would be a false positive). Plain READ_PROP on an
            unknown GUID is NOT flagged (it is not attacker-relevant control).
    """

    facts: tuple[AceEdgeFact, ...]
    unmapped_objecttype: bool


def resolve_laps_guids(schema: NtdsSchema) -> tuple[frozenset[str], int]:
    """Resolve the LAPS attributes' per-forest ``schemaIDGUID``s from the schema.

    LAPS attributes are schema extensions with a per-forest ``schemaIDGUID``, so
    ``ReadLAPSPassword`` can only be keyed when the DIT schema surfaces that GUID
    (research Open Risk 7). The 2a :class:`NtdsSchema` exposes it as
    ``AttributeDef.schema_id_guid`` (a lowercase dashed GUID), which this reads.

    Inputs:
        schema: the gated 2a :class:`NtdsSchema`.

    Returns:
        ``(guids, unresolvable)`` — the set of resolvable LAPS ``schemaIDGUID``s
        (lowercase) and the count of LAPS attributes present in the schema whose
        ``schemaIDGUID`` could not be read (a surfaced gap). An empty set with
        ``unresolvable == 0`` means the forest simply has no LAPS schema
        extension (no LAPS deployed) — not an error.

    Failure modes:
        Never raises.
    """
    guids: set[str] = set()
    unresolvable = 0
    for ldap in LAPS_ATTRIBUTE_NAMES:
        attr = schema.attributes_by_ldap.get(ldap)
        if attr is None:
            continue
        if attr.schema_id_guid:
            guids.add(attr.schema_id_guid.lower())
        else:
            unresolvable += 1
    return frozenset(guids), unresolvable


def _dedup(facts: list[AceEdgeFact]) -> tuple[AceEdgeFact, ...]:
    """Return ``facts`` with (kind, derivation) duplicates removed, order-stable."""
    seen: set[tuple[str, str]] = set()
    out: list[AceEdgeFact] = []
    for fact in facts:
        key = (fact.kind, fact.derivation)
        if key not in seen:
            seen.add(key)
            out.append(fact)
    return tuple(out)


def classify_ace(
    mask: int,
    object_type_guid: str | None,
    laps_guids: frozenset[str],
    handled_elsewhere: frozenset[str] = frozenset(),
) -> ClassifyResult:
    """Classify one ALLOW ACE into the edge facts it grants (the core logic).

    Precedence / gating rules (research item 2.5, re-expressed):

    1. **GENERIC_ALL dominates.** If the mask has ``GENERIC_ALL``, emit only
       ``GenericAll`` (not the sub-rights it subsumes).
    2. **Whole-object write bits are object-type-independent.** ``WRITE_DACL`` /
       ``WRITE_OWNER`` / ``GENERIC_WRITE`` emit their edge whenever their bit is
       set, regardless of ObjectType.
    3. **Object-type gating for property / control rights.** ``WRITE_PROP`` /
       ``SELF`` / ``CONTROL_ACCESS`` with **no** ObjectType grant the whole-object
       variant (``GenericWrite`` / ``AllExtendedRights``); **with** an ObjectType
       they grant only the specific scoped right if the GUID is mapped, else the
       ACE is flagged ``unmapped_objecttype`` (skipped — no generic fallback).
    4. **LAPS read.** ``READ_PROP`` with a resolved LAPS ``schemaIDGUID`` grants
       ``ReadLAPSPassword``; any other read grants nothing (not flagged).

    Inputs:
        mask: the raw integer access mask from the ACE.
        object_type_guid: the ACE's ObjectType GUID (lowercase dashed string), or
            ``None`` when the ACE carries no ObjectType.
        laps_guids: the resolved LAPS ``schemaIDGUID`` set (see
            :func:`resolve_laps_guids`); empty when the forest has no LAPS schema.
        handled_elsewhere: scoped GUIDs that another pass maps (the 5B ADCS
            enrollment / PKI-flag GUIDs). A scoped ACE on one of these is NOT
            flagged ``unmapped_objecttype`` here — it is not a gap, just mapped by
            a different builder (M-1: keeps the counter honest on the ADCS surface).

    Returns:
        A :class:`ClassifyResult`.

    Failure modes:
        Never raises; an unrecognized scoped write/control GUID becomes
        ``unmapped_objecttype=True`` (a counted gap), never a wrong edge.
    """
    bits = int(mask)

    # Rule 1: GENERIC_ALL dominates — emit only GenericAll.
    if bits & AccessMask.GENERIC_ALL:
        return ClassifyResult((_FACT_GENERIC_ALL,), False)

    facts: list[AceEdgeFact] = []

    # Rule 2: whole-object write rights (independent of ObjectType).
    if bits & AccessMask.WRITE_DACL:
        facts.append(_FACT_WRITE_DACL)
    if bits & AccessMask.WRITE_OWNER:
        facts.append(_FACT_WRITE_OWNER)
    if bits & AccessMask.GENERIC_WRITE:
        facts.append(_FACT_GENERIC_WRITE)

    unmapped = False

    if object_type_guid is None:
        # Rule 3 (whole-object variants): all-property write ~ GenericWrite;
        # all-extended-rights control ~ AllExtendedRights.
        if bits & AccessMask.DS_WRITE_PROP:
            facts.append(_FACT_GENERIC_WRITE)
        if bits & AccessMask.DS_CONTROL_ACCESS:
            facts.append(_FACT_ALL_EXTENDED_RIGHTS)
    else:
        guid = object_type_guid.lower()
        matched = False
        if bits & AccessMask.DS_WRITE_PROP:
            fact = _WRITE_PROP_MAP.get(guid)
            if fact is not None:
                facts.append(fact)
                matched = True
        if bits & AccessMask.DS_SELF:
            fact = _SELF_MAP.get(guid)
            if fact is not None:
                facts.append(fact)
                matched = True
        if bits & AccessMask.DS_CONTROL_ACCESS:
            fact = _CONTROL_ACCESS_MAP.get(guid)
            if fact is not None:
                facts.append(fact)
                matched = True
        if bits & AccessMask.DS_READ_PROP and guid in laps_guids:
            facts.append(_FACT_READ_LAPS)
            matched = True
        # A scoped write/self/control ACE with an unmapped GUID is a surfaced gap
        # (rule 2 of item 2.5): never fall back to a generic edge. READ_PROP alone
        # is not attacker-relevant control, so it is not flagged. A GUID the 5B
        # ADCS pass maps is "handled elsewhere" -> not a gap either (M-1).
        control_bits = AccessMask.DS_WRITE_PROP | AccessMask.DS_SELF | AccessMask.DS_CONTROL_ACCESS
        if not matched and (bits & control_bits) and guid not in handled_elsewhere:
            unmapped = True

    return ClassifyResult(_dedup(facts), unmapped)


# =============================================================================
# Slice 5B — ADCS base-fact classification (ADDITIVE; the 5A table above is
# untouched). ADCS objects (CertTemplate / EnterpriseCA) carry enrollment and
# PKI-flag rights the 5A DACL pass intentionally leaves unmapped; this block maps
# them. ESC composition stays BloodHound's (research item 6). The whole-object
# control edges (GenericAll/Write/WriteDacl/WriteOwner/Owns) on an ADCS object are
# already produced by the 5A generic DACL pass — this classifier adds ONLY the
# ADCS-scoped facts (Enroll / AutoEnroll / WritePKI*Flag).
# =============================================================================

KIND_ENROLL: str = "Enroll"
KIND_AUTO_ENROLL: str = "AutoEnroll"
KIND_WRITE_PKI_ENROLLMENT_FLAG: str = "WritePKIEnrollmentFlag"
KIND_WRITE_PKI_NAME_FLAG: str = "WritePKINameFlag"
KIND_PUBLISHED_TO: str = "PublishedTo"

#: Certificate-Enrollment / Certificate-AutoEnrollment extended-right GUIDs
#: (fixed, public MS adschema / [MS-CRTD] facts, lowercase).
GUID_CERTIFICATE_ENROLLMENT: str = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_CERTIFICATE_AUTOENROLLMENT: str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

#: LDAP display names of the PKI-flag attributes whose per-forest ``schemaIDGUID``
#: keys ``WritePKIEnrollmentFlag`` / ``WritePKINameFlag`` (resolved from the DIT
#: schema exactly like LAPS — they are schema-extension attributes).
PKI_ENROLLMENT_FLAG_ATTR: str = "msPKI-Enrollment-Flag"
PKI_NAME_FLAG_ATTR: str = "msPKI-Certificate-Name-Flag"

_FACT_ENROLL: AceEdgeFact = _scoped(KIND_ENROLL)
_FACT_AUTO_ENROLL: AceEdgeFact = _scoped(KIND_AUTO_ENROLL)
_FACT_WRITE_PKI_ENROLLMENT_FLAG: AceEdgeFact = _scoped(KIND_WRITE_PKI_ENROLLMENT_FLAG)
_FACT_WRITE_PKI_NAME_FLAG: AceEdgeFact = _scoped(KIND_WRITE_PKI_NAME_FLAG)


@dataclass(frozen=True)
class PkiFlagGuids:
    """The resolved per-forest ``schemaIDGUID``s of the two PKI-flag attributes.

    Attributes:
        enrollment_flag: ``msPKI-Enrollment-Flag`` schemaIDGUID (lowercase), or
            ``None`` if the schema did not surface it.
        name_flag: ``msPKI-Certificate-Name-Flag`` schemaIDGUID (lowercase), or
            ``None``.
    """

    enrollment_flag: str | None
    name_flag: str | None


def resolve_pki_flag_guids(schema: NtdsSchema) -> tuple[PkiFlagGuids, int]:
    """Resolve the two PKI-flag attributes' ``schemaIDGUID``s from the DIT schema.

    Like :func:`resolve_laps_guids`, these are schema-extension attributes with a
    per-forest ``schemaIDGUID`` (research item 6). ``WritePKIEnrollmentFlag`` /
    ``WritePKINameFlag`` can only be keyed when the schema surfaces the GUID.

    Inputs:
        schema: the gated 2a :class:`NtdsSchema`.

    Returns:
        ``(PkiFlagGuids, unresolvable)`` — the resolved GUIDs and the count of the
        two attributes that are present in the schema but whose ``schemaIDGUID``
        could not be read (a surfaced gap). An attribute simply absent from the
        schema (no ADCS) is not counted (the edge just never fires).

    Failure modes:
        Never raises.
    """
    unresolvable = 0
    resolved: dict[str, str | None] = {}
    for attr_name in (PKI_ENROLLMENT_FLAG_ATTR, PKI_NAME_FLAG_ATTR):
        attr = schema.attributes_by_ldap.get(attr_name)
        if attr is None:
            resolved[attr_name] = None
            continue
        if attr.schema_id_guid:
            resolved[attr_name] = attr.schema_id_guid.lower()
        else:
            resolved[attr_name] = None
            unresolvable += 1
    return (
        PkiFlagGuids(
            enrollment_flag=resolved[PKI_ENROLLMENT_FLAG_ATTR],
            name_flag=resolved[PKI_NAME_FLAG_ATTR],
        ),
        unresolvable,
    )


def classify_adcs_ace(
    mask: int,
    object_type_guid: str | None,
    pki_flag_guids: PkiFlagGuids,
) -> ClassifyResult:
    """Classify one ALLOW ACE on an ADCS object into its ADCS-scoped facts.

    Returns ONLY the ADCS-specific scoped facts (``Enroll`` / ``AutoEnroll`` /
    ``WritePKIEnrollmentFlag`` / ``WritePKINameFlag``). Whole-object control
    (GenericAll/GenericWrite/WriteDacl/WriteOwner/AllExtendedRights/Owns) on the
    ADCS object is produced by the 5A generic DACL pass and is NOT re-emitted
    here. ``GENERIC_ALL`` therefore yields no ADCS-scoped fact (the 5A pass emits
    ``GenericAll`` which subsumes enrollment for ESC composition downstream).

    Inputs:
        mask: the raw integer access mask.
        object_type_guid: the ACE ObjectType GUID (lowercase), or ``None``.
        pki_flag_guids: the resolved PKI-flag ``schemaIDGUID``s.

    Returns:
        A :class:`ClassifyResult`. ``unmapped_objecttype`` is never set here
        (unmapped scoped GUIDs on ADCS objects are already counted by the 5A pass).

    Failure modes:
        Never raises.
    """
    if object_type_guid is None:
        return ClassifyResult((), False)
    bits = int(mask)
    guid = object_type_guid.lower()
    facts: list[AceEdgeFact] = []
    if bits & AccessMask.DS_CONTROL_ACCESS:
        if guid == GUID_CERTIFICATE_ENROLLMENT:
            facts.append(_FACT_ENROLL)
        elif guid == GUID_CERTIFICATE_AUTOENROLLMENT:
            facts.append(_FACT_AUTO_ENROLL)
    if bits & AccessMask.DS_WRITE_PROP:
        if pki_flag_guids.enrollment_flag is not None and guid == pki_flag_guids.enrollment_flag:
            facts.append(_FACT_WRITE_PKI_ENROLLMENT_FLAG)
        elif pki_flag_guids.name_flag is not None and guid == pki_flag_guids.name_flag:
            facts.append(_FACT_WRITE_PKI_NAME_FLAG)
    return ClassifyResult(_dedup(facts), False)
