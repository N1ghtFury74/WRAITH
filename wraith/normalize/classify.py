"""Object classification for Module 3 (research item 1).

Decides which canonical table an NTDS object maps to from its ``objectClass``
chain, confirmed/tie-broken by ``sAMAccountType`` and (last) the container DN.
The rule is a small, pure, table-driven function so it is trivially testable and
deterministic.

Key facts confirmed against real evidence (``docs/research/04``):

* ``objectClass`` is the full class chain stored as ``governsID`` ints; the
  resolver hands M3 the decoded class names **most-derived first**. The
  classifier works off the class-name *set* plus the most-derived hint, so it is
  robust to ordering differences.
* ``computer`` is a subclass of ``user`` -> it MUST be tested before ``user``
  (via ``sAMAccountType`` machine-account, then class membership), or every
  computer misfiles as a user ([MS-ADSC]).
* ``certificationAuthority`` objects all share one class and are discriminated
  by their container DN (``CN=Certification Authorities`` -> RootCA,
  ``CN=NTAuthCertificates`` -> NTAuthStore, ``CN=AIA`` -> AIACA).
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum

from wraith.normalize.decoders import (
    SAM_ALIAS_OBJECT,
    SAM_GROUP_OBJECT,
    SAM_MACHINE_ACCOUNT,
    SAM_NON_SECURITY_ALIAS_OBJECT,
    SAM_NON_SECURITY_GROUP_OBJECT,
    SAM_NORMAL_USER_ACCOUNT,
    SAM_TRUST_ACCOUNT,
)


class EntityKind(StrEnum):
    """Which canonical table an object maps to (or that it is skipped)."""

    PRINCIPAL = "principal"
    CONTAINER = "container"
    GPO = "gpo"
    TRUST = "trust"
    ADCS = "adcs"
    SKIP = "skip"


#: Reasons a SKIP classification is counted (surfaced on the IngestRun).
SKIP_UNCLASSIFIED = "unclassified"  # looked like a principal but could not type
SKIP_NOT_MODELED = "not_modeled"  # a recognized infra class M3 does not model
# NOTE: deletion (isDeleted/isRecycled) is detected in the pipeline BEFORE
# classify() runs, so the classifier never returns a "deleted" skip reason.


@dataclass(frozen=True)
class ClassifiedKind:
    """The classification verdict for one object.

    Attributes:
        entity: the target :class:`EntityKind` (``SKIP`` if not emitted).
        principal_type: ``User``/``Computer``/``Group`` for a Principal, else ``None``.
        container_type: ``OU``/``Container``/``Domain`` for a Container, else ``None``.
        adcs_type: the §3.5 ADCS discriminant, else ``None``.
        is_fsp: ``True`` if this is a ``foreignSecurityPrincipal`` stub Principal.
        skip_reason: :data:`SKIP_UNCLASSIFIED` or :data:`SKIP_NOT_MODELED` when
            ``entity is SKIP``, else ``None`` (deletion is handled upstream).
    """

    entity: EntityKind
    principal_type: str | None = None
    container_type: str | None = None
    adcs_type: str | None = None
    is_fsp: bool = False
    skip_reason: str | None = None


# --- decisive structural / container classes ---------------------------------
_ADCS_TEMPLATE = "pKICertificateTemplate"
_ADCS_ENROLL = "pKIEnrollmentService"
_ADCS_CA = "certificationAuthority"
_ADCS_OID = "msPKI-Enterprise-Oid"
_GPO_CLASS = "groupPolicyContainer"
_TRUST_CLASS = "trustedDomain"
_DOMAIN_CLASS = "domainDNS"
_OU_CLASS = "organizationalUnit"
_FSP_CLASS = "foreignSecurityPrincipal"
_BUILTIN_DOMAIN_CLASS = "builtinDomain"
_CONTAINER_CLASS = "container"

#: gMSA/MSA classes -> ``Computer`` principal_type (the enum has no MSA value;
#: raw objectClass is retained in ``staging_object`` so this is recoverable).
_MSA_CLASSES = frozenset({"msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount"})
_COMPUTER_CLASS = "computer"
_USER_CLASS = "user"
_GROUP_CLASS = "group"

#: Recognized infrastructure classes M3 intentionally does not model as entities
#: (schema/config/DNS/display objects). Matched as the most-derived class so the
#: skip is a counted ``not_modeled`` gap, distinct from a surprising
#: ``unclassified`` (research item 9, additive refinement — documented).
_NOT_MODELED_MOST_DERIVED = frozenset(
    {
        "attributeSchema",
        "classSchema",
        "subSchema",
        "controlAccessRight",
        "displaySpecifier",
        "dnsNode",
        "dnsZone",
        "dSUISettings",
        "crossRef",
        "crossRefContainer",
        "lostAndFound",
        "rpcContainer",
        "secret",
        "nTFRSSettings",
        "nTFRSReplicaSet",
        "nTFRSSubscriptions",
        "nTFRSSubscriber",
        "nTFRSMember",
        "fileLinkTracking",
        "linkTrackObjectMoveTable",
        "linkTrackVolumeTable",
        "linkTrackOMTEntry",
        "linkTrackVolEntry",
        "serviceConnectionPoint",
        "rIDSet",
        "rIDManager",
        "msDS-QuotaContainer",
        "msDS-QuotaControl",
        "msDS-ResourceProperty",
        "msDS-ResourcePropertyList",
        "msDS-ValueType",
        "msDS-ClaimType",
        "msDS-ClaimsTransformationPolicyType",
        "msDS-PasswordSettings",
        "msDS-PasswordSettingsContainer",
        "ipsecPolicy",
        "ipsecNFA",
        "ipsecNegotiationPolicy",
        "ipsecFilter",
        "ipsecISAKMPPolicy",
        "msExchConfigurationContainer",
        "msPKI-Key-Recovery-Agent",
        "packageRegistration",
        "classStore",
        "sitesContainer",
        "site",
        "server",
        "serversContainer",
        "siteLink",
        "subnet",
        "subnetContainer",
        "nTDSDSA",
        "nTDSSettings",
        "nTDSConnection",
        "applicationVersion",
        "samServer",
    }
)


def classify(
    class_names: Collection[str],
    most_derived: str | None,
    sam_account_type: int | None,
    container_dn: str | None,
) -> ClassifiedKind:
    """Classify one object into a canonical :class:`EntityKind`.

    Precedence (research item 1): (1) exact-match the ADCS/structural/container
    classes; (2) GPO/Trust/Domain/OU/FSP/Container; (3) otherwise a security
    principal typed Computer -> User -> Group by ``sAMAccountType``, falling back
    to class membership when ``sAMAccountType`` is absent (e.g. gMSA, FSP).

    Inputs:
        class_names: the decoded ``objectClass`` names present on the object.
        most_derived: the most-derived (first) class name, or ``None``.
        sam_account_type: raw ``sAMAccountType`` int, or ``None``.
        container_dn: the object's reconstructed parent/own DN (for CA
            discrimination), or ``None``.

    Returns:
        A :class:`ClassifiedKind`. Unmatched objects return ``EntityKind.SKIP``
        with a :data:`SKIP_NOT_MODELED` or :data:`SKIP_UNCLASSIFIED` reason.

    Failure modes:
        Never raises (deleted/tombstone detection is the caller's; this function
        does not see ``isDeleted``).
    """
    classes = frozenset(class_names)

    # (1) ADCS classes (exact match; most specific first).
    if _ADCS_TEMPLATE in classes:
        return ClassifiedKind(EntityKind.ADCS, adcs_type="CertTemplate")
    if _ADCS_ENROLL in classes:
        return ClassifiedKind(EntityKind.ADCS, adcs_type="EnterpriseCA")
    if _ADCS_OID in classes:
        return ClassifiedKind(EntityKind.ADCS, adcs_type="IssuancePolicy")
    if _ADCS_CA in classes:
        return ClassifiedKind(EntityKind.ADCS, adcs_type=_ca_subtype(container_dn))

    # (2) GPO / Trust / Domain / OU / FSP / Container.
    if _GPO_CLASS in classes:
        return ClassifiedKind(EntityKind.GPO)
    if _TRUST_CLASS in classes:
        return ClassifiedKind(EntityKind.TRUST)
    if _DOMAIN_CLASS in classes:
        return ClassifiedKind(EntityKind.CONTAINER, container_type="Domain")
    if _OU_CLASS in classes:
        return ClassifiedKind(EntityKind.CONTAINER, container_type="OU")
    if _FSP_CLASS in classes:
        return ClassifiedKind(EntityKind.PRINCIPAL, principal_type="Group", is_fsp=True)

    # (3) security principals (computer before user; sAMAccountType authoritative).
    principal_type = _principal_type(classes, sam_account_type)
    if principal_type is not None:
        return ClassifiedKind(EntityKind.PRINCIPAL, principal_type=principal_type)

    # builtinDomain / container (tested after security principals so a SID-bearing
    # builtinDomain is not mistaken; neither class overlaps a principal class).
    if _BUILTIN_DOMAIN_CLASS in classes or _CONTAINER_CLASS in classes:
        return ClassifiedKind(EntityKind.CONTAINER, container_type="Container")

    # Not emitted: recognized infra class -> not_modeled; else unclassified.
    reason = SKIP_NOT_MODELED if most_derived in _NOT_MODELED_MOST_DERIVED else SKIP_UNCLASSIFIED
    return ClassifiedKind(EntityKind.SKIP, skip_reason=reason)


def _principal_type(classes: frozenset[str], sam_account_type: int | None) -> str | None:
    """Return ``Computer``/``User``/``Group`` for a security principal, else ``None``."""
    # sAMAccountType is authoritative when present.
    if sam_account_type == SAM_MACHINE_ACCOUNT:
        return "Computer"
    if sam_account_type in (SAM_NORMAL_USER_ACCOUNT, SAM_TRUST_ACCOUNT):
        return "User"
    if sam_account_type in (
        SAM_GROUP_OBJECT,
        SAM_NON_SECURITY_GROUP_OBJECT,
        SAM_ALIAS_OBJECT,
        SAM_NON_SECURITY_ALIAS_OBJECT,
    ):
        return "Group"
    # Fallback to class membership (gMSA/MSA have no distinct sAMAccountType here,
    # and some objects omit it). Computer/MSA before user (subclass ordering).
    if _COMPUTER_CLASS in classes or classes & _MSA_CLASSES:
        return "Computer"
    if _GROUP_CLASS in classes:
        return "Group"
    if _USER_CLASS in classes:
        return "User"
    return None


def _ca_subtype(container_dn: str | None) -> str:
    """Discriminate a ``certificationAuthority`` object by its container DN."""
    dn = (container_dn or "").upper()
    if "CN=NTAUTHCERTIFICATES" in dn:
        return "NTAuthStore"
    if "CN=AIA" in dn:
        return "AIACA"
    # Default: CN=Certification Authorities (root CA store).
    return "RootCA"
