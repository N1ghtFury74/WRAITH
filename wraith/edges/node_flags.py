"""Node-flag derivations (NOT edges, NO new schema columns) — slice 5B.

BloodHound models unconstrained-delegation / kerberoastable / AS-REP-roastable as
node *properties*, not traversable edges (research item 4). WRAITH keeps that
parity: these are pure, deterministic predicates over the FROZEN §3 ``principal``
columns (``uac_flags`` / ``enabled`` / ``spns`` / ``samaccountname``). They are
exposed as functions for the export adapter (M6) and the dossier layer (M7) to
consume — this module writes nothing and adds no column.

Public facts reused (public [MS-ADTS] ``userAccountControl`` bits, already named
in :mod:`wraith.normalize.decoders`): ``TRUSTED_FOR_DELEGATION`` (``0x80000``)
and ``DONT_REQ_PREAUTH`` (``0x400000``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from wraith.normalize.decoders import (
    UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH,
    UAC_ENCRYPTED_TEXT_PWD_ALLOWED,
    UAC_PASSWD_NOTREQD,
    UAC_SERVER_TRUST_ACCOUNT,
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
)

#: ``sAMAccountName`` of the KDC service account, excluded from kerberoastable
#: (it always carries an SPN but is not a roast target — BloodHound parity).
_KRBTGT: str = "krbtgt"


@dataclass(frozen=True)
class NodeFlags:
    """The attacker-relevant boolean flags derived for one principal.

    Attributes:
        unconstrained_delegation: the account is trusted for (unconstrained)
            Kerberos delegation (``UAC & TRUSTED_FOR_DELEGATION``).
        kerberoastable: an enabled User (not ``krbtgt``) carrying at least one
            SPN — its service ticket can be requested and offline-cracked.
        asrep_roastable: an enabled ``User`` that does not require Kerberos
            pre-authentication (``UAC & DONT_REQ_PREAUTH``) — an AS-REP can be
            requested and offline-cracked. Enabled-User-filtered for symmetry with
            ``kerberoastable`` (DE hunt-audit defect #3).
    """

    unconstrained_delegation: bool
    kerberoastable: bool
    asrep_roastable: bool


def is_unconstrained_delegation(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``TRUSTED_FOR_DELEGATION`` (``0x80000``).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the unconstrained-delegation bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_TRUSTED_FOR_DELEGATION)


def is_domain_controller(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``SERVER_TRUST_ACCOUNT`` (``0x2000``).

    A Domain Controller's computer account carries ``SERVER_TRUST_ACCOUNT``; this
    is how a DC is told apart from an ordinary computer offline (public [MS-ADTS]
    ``userAccountControl`` fact). Used to suppress the DC-self case for the
    ``CoerceToTGT`` edge (DCs legitimately carry ``TRUSTED_FOR_DELEGATION`` and are
    already Tier-0, so they are not a coercion finding).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the server-trust-account bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_SERVER_TRUST_ACCOUNT)


def is_coercible_unconstrained(uac_flags: int | None) -> bool:
    """Return whether a principal is a coercible (non-DC) unconstrained-delegation host.

    ``True`` when the account is trusted for unconstrained Kerberos delegation
    (``TRUSTED_FOR_DELEGATION``) **and** is NOT a Domain Controller
    (``SERVER_TRUST_ACCOUNT``). This is the predicate for synthesizing a
    ``CoerceToTGT`` edge: a non-DC unconstrained host can coerce a DC to
    authenticate to it and capture the DC's TGT, whereas a DC carrying the flag is
    expected and not a finding (BloodHound CE parity — the flag was promoted to a
    traversable edge only for the non-DC case).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff unconstrained-delegation is set and the server-trust (DC) bit
        is not.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return is_unconstrained_delegation(uac_flags) and not is_domain_controller(uac_flags)


def is_asrep_roastable(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``DONT_REQ_PREAUTH`` (``0x400000``).

    This is the RAW directory-attribute predicate (parity with BloodHound's
    ``dontreqpreauth`` node property). The AS-REP-roast *hunt* / risk factor apply
    the enabled-User filter on top via :func:`is_asrep_roastable_account`.

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the don't-require-preauth bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_DONT_REQ_PREAUTH)


def _is_enabled_user(principal_type: str, enabled: bool | None) -> bool:
    """Return whether a principal is an enabled ``User`` (the shared roast filter).

    THE single enabled-User predicate reused by BOTH roast hunts
    (:func:`is_kerberoastable` and :func:`is_asrep_roastable_account`) so the
    Kerberoast and AS-REP-roast populations are filtered symmetrically (DE hunt-audit
    defect #3). ``None`` enabled is treated as not enabled.

    Failure modes:
        Never raises.
    """
    return principal_type == "User" and bool(enabled)


def is_asrep_roastable_account(
    principal_type: str, enabled: bool | None, uac_flags: int | None
) -> bool:
    """Return whether a principal is an AS-REP-roastable account (enabled User, no preauth).

    The gated AS-REP-roast predicate: the EXACT enabled-User filter the Kerberoast
    hunt uses (:func:`_is_enabled_user`) plus the raw ``DONT_REQ_PREAUTH`` bit
    (:func:`is_asrep_roastable`). Keeps ``set-asrep`` / ``paths-from-asrep`` symmetric
    with ``set-kerberoastable`` — a disabled or non-User account carrying the bit is no
    longer surfaced as a live roast target (DE hunt-audit defect #3).

    Inputs:
        principal_type: the §3 ``principal_type`` (``User``/``Computer``/``Group``).
        enabled: the derived ``enabled`` flag (``None`` treated as not enabled).
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the account is an enabled ``User`` with ``DONT_REQ_PREAUTH`` set.

    Failure modes:
        Never raises.
    """
    if not _is_enabled_user(principal_type, enabled):
        return False
    return is_asrep_roastable(uac_flags)


def is_password_not_required(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``PASSWD_NOTREQD`` (``0x20``).

    A set bit means the account may have an empty / not-required password — it can
    be authenticated with no credential, a credential-exposure finding (T1078).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the password-not-required bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_PASSWD_NOTREQD)


def is_password_never_expires(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``DONT_EXPIRE_PASSWORD`` (``0x10000``).

    The account's password never expires — a stale, long-lived credential that
    widens the window for offline cracking / reuse (hygiene / T1078).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the don't-expire-password bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_DONT_EXPIRE_PASSWORD)


def is_reversible_password(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``ENCRYPTED_TEXT_PWD_ALLOWED`` (``0x80``).

    The account's password is stored with reversible encryption, so it can be
    recovered to plaintext from the directory (T1555) — a severe exposure.

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the reversible-encryption bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_ENCRYPTED_TEXT_PWD_ALLOWED)


def is_protocol_transition(uac_flags: int | None) -> bool:
    """Return whether ``uac_flags`` sets ``TRUSTED_TO_AUTH_FOR_DELEGATION`` (``0x1000000``).

    The account can perform S4U2Self protocol transition — the flag that upgrades
    constrained delegation to "any protocol" and makes it abusable without the
    victim ever authenticating (T1134.005 companion to constrained delegation).

    Inputs:
        uac_flags: the raw ``userAccountControl`` value, or ``None``.

    Returns:
        ``True`` iff the trusted-to-auth-for-delegation bit is set.

    Failure modes:
        Never raises; ``None`` -> ``False``.
    """
    return uac_flags is not None and bool(uac_flags & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)


def is_kerberoastable(
    principal_type: str,
    enabled: bool | None,
    spns: Sequence[str] | None,
    samaccountname: str | None,
) -> bool:
    """Return whether a principal is kerberoastable (enabled User with an SPN).

    An account is kerberoastable when it is a ``User`` (not the ``krbtgt`` KDC
    account), is enabled, and advertises at least one ``servicePrincipalName``
    (so a TGS can be requested and the service key cracked offline).

    Inputs:
        principal_type: the §3 ``principal_type`` (``User``/``Computer``/``Group``).
        enabled: the derived ``enabled`` flag (``None`` treated as not enabled).
        spns: the account's ``servicePrincipalName`` list (may be empty/``None``).
        samaccountname: the account's ``sAMAccountName`` (``krbtgt`` is excluded).

    Returns:
        ``True`` iff the account is a roast target.

    Failure modes:
        Never raises.
    """
    if not _is_enabled_user(principal_type, enabled):
        return False
    if samaccountname is not None and samaccountname.lower() == _KRBTGT:
        return False
    return bool(spns)


def compute_node_flags(
    principal_type: str,
    uac_flags: int | None,
    enabled: bool | None,
    spns: Sequence[str] | None,
    samaccountname: str | None,
) -> NodeFlags:
    """Compute all node flags for one principal (the M6/M7 entry point).

    Inputs:
        principal_type: the §3 ``principal_type``.
        uac_flags: the raw ``userAccountControl``.
        enabled: the derived ``enabled`` flag.
        spns: the ``servicePrincipalName`` list.
        samaccountname: the ``sAMAccountName``.

    Returns:
        A :class:`NodeFlags` with the three booleans.

    Failure modes:
        Never raises.
    """
    return NodeFlags(
        unconstrained_delegation=is_unconstrained_delegation(uac_flags),
        kerberoastable=is_kerberoastable(principal_type, enabled, spns, samaccountname),
        # Symmetric with ``kerberoastable``: the enabled-User-filtered AS-REP predicate
        # (DE hunt-audit defect #3), not the raw bit — a disabled/non-User account
        # carrying DONT_REQ_PREAUTH is not a live roast target.
        asrep_roastable=is_asrep_roastable_account(principal_type, enabled, uac_flags),
    )
