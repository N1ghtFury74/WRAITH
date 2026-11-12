"""Pure semantic decoders for Module 3 (the Object Normalizer).

These turn 2a's structural values into the canonical *semantic* facts the
frozen schema (§3) wants: account state from ``userAccountControl``, FILETIME
timestamps, ``gPLink`` precedence, and trust bit/enum decodes. Every function
is pure (no I/O, no global state), so the edge/normalizer logic stays trivially
unit-testable and deterministic.

Public-fact constants only (reusable per CLAUDE.md): UAC flags, ``sAMAccountType``
values, trust direction/type/attribute bits, well-known SID names. Foreign
source code is NOT copied — the constants are reimplemented from [MS-ADTS],
[MS-SAMR], [MS-DTYP], [MS-LSAD] and the public KB docs cited in
``docs/research/04-module3-normalizer-decisions.md``.

Timestamp distinction (load-bearing, research item 2): 2a's
``decode_ntds_timestamp`` is **seconds** since 1601 for ``whenChanged``/
``whenCreated`` only. ``pwdLastSet``/``lastLogonTimestamp`` are FILETIME
**100-nanosecond ticks** since 1601 and MUST use :func:`decode_filetime` here;
cross-applying the 2a decoder would be wrong by centuries.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

# --- userAccountControl bit flags (public [MS-ADTS]/KB305144) -----------------
UAC_ACCOUNTDISABLE: int = 0x0002
UAC_PASSWD_NOTREQD: int = 0x0020
#: ``ENCRYPTED_TEXT_PASSWORD_ALLOWED`` — the account's password is stored with
#: reversible encryption (recoverable to plaintext). Public [MS-ADTS]/KB305144.
UAC_ENCRYPTED_TEXT_PWD_ALLOWED: int = 0x0080
UAC_NORMAL_ACCOUNT: int = 0x0200
UAC_INTERDOMAIN_TRUST_ACCOUNT: int = 0x0800
UAC_WORKSTATION_TRUST_ACCOUNT: int = 0x1000
UAC_SERVER_TRUST_ACCOUNT: int = 0x2000
UAC_DONT_EXPIRE_PASSWORD: int = 0x10000
UAC_TRUSTED_FOR_DELEGATION: int = 0x80000
UAC_NOT_DELEGATED: int = 0x100000
UAC_DONT_REQ_PREAUTH: int = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: int = 0x1000000
UAC_PARTIAL_SECRETS_ACCOUNT: int = 0x4000000

# --- sAMAccountType values (public AD a-samaccounttype / MS-SAMR 2.2.1.9) ------
SAM_GROUP_OBJECT: int = 0x10000000
SAM_NON_SECURITY_GROUP_OBJECT: int = 0x10000001
SAM_ALIAS_OBJECT: int = 0x20000000
SAM_NON_SECURITY_ALIAS_OBJECT: int = 0x20000001
SAM_NORMAL_USER_ACCOUNT: int = 0x30000000
SAM_MACHINE_ACCOUNT: int = 0x30000001
SAM_TRUST_ACCOUNT: int = 0x30000002

# --- trust bits/values (public [MS-ADTS]/[MS-LSAD]) ---------------------------
TRUST_DIRECTION_DISABLED: int = 0
TRUST_DIRECTION_INBOUND: int = 1
TRUST_DIRECTION_OUTBOUND: int = 2
TRUST_DIRECTION_BIDIRECTIONAL: int = 3

TRUST_TYPE_DOWNLEVEL: int = 1  # NT4
TRUST_TYPE_UPLEVEL: int = 2  # AD
TRUST_TYPE_MIT: int = 3  # Kerberos realm
TRUST_TYPE_DCE: int = 4

TRUST_ATTR_NON_TRANSITIVE: int = 0x1
TRUST_ATTR_UPLEVEL_ONLY: int = 0x2
TRUST_ATTR_QUARANTINED_DOMAIN: int = 0x4  # == SID filtering (external trusts)
TRUST_ATTR_FOREST_TRANSITIVE: int = 0x8
TRUST_ATTR_CROSS_ORGANIZATION: int = 0x10
TRUST_ATTR_WITHIN_FOREST: int = 0x20
TRUST_ATTR_TREAT_AS_EXTERNAL: int = 0x40
TRUST_ATTR_NO_TGT_DELEGATION: int = 0x200
TRUST_ATTR_PIM_TRUST: int = 0x400

#: FILETIME "never"/"never expires" sentinel (max signed 64-bit).
_FILETIME_NEVER: int = 0x7FFFFFFFFFFFFFFF
#: 100-ns ticks per microsecond (FILETIME granularity -> datetime microseconds).
_TICKS_PER_MICROSECOND: int = 10
#: Epoch for FILETIME (naive UTC; canonical rows are naive-UTC, see store DDL).
_EPOCH_1601_NAIVE: datetime = datetime(1601, 1, 1)


def decode_filetime(value: int | None) -> datetime | None:
    """Decode a Windows FILETIME integer to a naive-UTC :class:`datetime`.

    FILETIME is the number of 100-nanosecond ticks since 1601-01-01 UTC — the
    encoding of ``pwdLastSet``/``lastLogonTimestamp``/``accountExpires`` (NOT the
    seconds-since-1601 encoding 2a's ``decode_ntds_timestamp`` handles).

    Inputs:
        value: the FILETIME ticks, or ``None``.

    Returns:
        A naive-UTC :class:`datetime`, or ``None`` for an unset value (``<= 0``),
        the ``0x7FFFFFFFFFFFFFFF`` never/never-expires sentinel, or a value so
        large it would overflow the calendar.

    Failure modes:
        Never raises; an out-of-range value degrades to ``None``.
    """
    if value is None or value <= 0 or value == _FILETIME_NEVER:
        return None
    try:
        return _EPOCH_1601_NAIVE + timedelta(microseconds=int(value) // _TICKS_PER_MICROSECOND)
    except (OverflowError, ValueError, OSError):
        return None


def to_naive_utc(value: datetime | None) -> datetime | None:
    """Normalize a datetime to naive UTC for deterministic canonical storage.

    2a yields tz-aware UTC datetimes; the canonical ``TIMESTAMP`` columns are
    naive-UTC (see ``wraith/model/store.py``). This converts a tz-aware value to
    UTC then drops the tzinfo; a naive value is returned unchanged.

    Inputs:
        value: a tz-aware or naive datetime, or ``None``.

    Returns:
        The naive-UTC datetime, or ``None``.

    Failure modes:
        Never raises.
    """
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def decode_uac_enabled(uac_flags: int | None) -> bool | None:
    """Return whether an account is enabled from ``userAccountControl``.

    Inputs:
        uac_flags: the raw ``userAccountControl`` integer, or ``None``.

    Returns:
        ``True`` if the ``ACCOUNTDISABLE`` bit is clear, ``False`` if set, or
        ``None`` if ``uac_flags`` is absent (unknown, not asserted as enabled).

    Failure modes:
        Never raises.
    """
    if uac_flags is None:
        return None
    return not (uac_flags & UAC_ACCOUNTDISABLE)


_GPLINK_ENTRY_RE = re.compile(r"\[LDAP://(?P<dn>[^;]+);(?P<flags>\d+)\]")
_GPLINK_CN_GUID_RE = re.compile(r"CN=\{?(?P<guid>[0-9A-Fa-f-]{36})\}?", re.IGNORECASE)

#: ``gPLink`` per-entry flag bits ([MS-ADTS] ``gPLink``).
GPLINK_FLAG_DISABLED: int = 0x1
GPLINK_FLAG_ENFORCED: int = 0x2


class GpLinkEntry:
    """One parsed ``gPLink`` entry (left-to-right precedence).

    Attributes:
        gpo_cn_guid: the GPC ``cn`` GUID the link references, lowercased and
            brace-stripped. NOTE this is the GPC's ``cn`` (= the policy GUID in
            ``CN={...}``), which is NOT the GPC's ``objectGUID`` — the normalizer
            resolves it to the GPO ``node_id`` via a cn-GUID -> node_id map built
            from each GPC's ``name``/``cn`` (confirmed against real evidence).
        enforced: ``True`` when the ``LDAP_GPLINK_FLAG_ENFORCED`` (0x2) bit is set.
        disabled: ``True`` when the ``disabled`` (0x1) bit is set (link ignored).
        link_order: positional index (0-based; lower = higher precedence).
    """

    __slots__ = ("gpo_cn_guid", "enforced", "disabled", "link_order")

    def __init__(self, gpo_cn_guid: str, enforced: bool, disabled: bool, link_order: int) -> None:
        self.gpo_cn_guid = gpo_cn_guid
        self.enforced = enforced
        self.disabled = disabled
        self.link_order = link_order

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GpLinkEntry):
            return NotImplemented
        return (
            self.gpo_cn_guid == other.gpo_cn_guid
            and self.enforced == other.enforced
            and self.disabled == other.disabled
            and self.link_order == other.link_order
        )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"GpLinkEntry(gpo_cn_guid={self.gpo_cn_guid!r}, enforced={self.enforced}, "
            f"disabled={self.disabled}, link_order={self.link_order})"
        )


def parse_gplink(value: str | None) -> list[GpLinkEntry]:
    """Parse a ``gPLink`` string into ordered :class:`GpLinkEntry` entries.

    The format is a concatenation of ``[LDAP://<gpo-dn>;<flags>]`` entries in
    precedence order (lower index = higher precedence). The GPC ``cn`` GUID is
    extracted from the ``CN={...}`` component of each entry's DN.

    Inputs:
        value: the raw ``gPLink`` attribute value, or ``None``.

    Returns:
        A list of :class:`GpLinkEntry` in link order. An entry whose DN has no
        parseable ``CN={GUID}`` is skipped (the caller counts it). ``[]`` for a
        missing/blank value.

    Failure modes:
        Never raises; malformed entries are skipped.
    """
    if not value:
        return []
    out: list[GpLinkEntry] = []
    for order, match in enumerate(_GPLINK_ENTRY_RE.finditer(value)):
        dn = match.group("dn")
        flags = int(match.group("flags"))
        guid_match = _GPLINK_CN_GUID_RE.search(dn)
        if guid_match is None:
            continue
        out.append(
            GpLinkEntry(
                gpo_cn_guid=guid_match.group("guid").lower(),
                enforced=bool(flags & GPLINK_FLAG_ENFORCED),
                disabled=bool(flags & GPLINK_FLAG_DISABLED),
                link_order=order,
            )
        )
    return out


def decode_trust_direction(value: int | None) -> str | None:
    """Map ``trustDirection`` to the §3.4 ``direction`` enum string.

    Inputs:
        value: the raw ``trustDirection`` int (0 disabled, 1 inbound, 2 outbound,
            3 bidirectional), or ``None``.

    Returns:
        ``"inbound"``/``"outbound"``/``"bidirectional"``/``"disabled"``, or
        ``None`` for an unknown/absent value.

    Failure modes:
        Never raises.
    """
    return (
        {
            TRUST_DIRECTION_DISABLED: "disabled",
            TRUST_DIRECTION_INBOUND: "inbound",
            TRUST_DIRECTION_OUTBOUND: "outbound",
            TRUST_DIRECTION_BIDIRECTIONAL: "bidirectional",
        }.get(value)
        if value is not None
        else None
    )


def decode_trust_type(trust_type: int | None, trust_attributes: int | None) -> str | None:
    """Derive the §3.4 ``trust_type`` enum from ``trustType`` + ``trustAttributes``.

    Precedence (research item 3): ``trustType==MIT`` -> ``realm``;
    ``FOREST_TRANSITIVE`` -> ``forest``; ``WITHIN_FOREST`` -> ``parent-child``
    (tree-root is not distinguishable from attributes alone, deferred); else
    ``external``.

    Inputs:
        trust_type: raw ``trustType`` (1 downlevel, 2 uplevel, 3 MIT, 4 DCE).
        trust_attributes: raw ``trustAttributes`` bitmask.

    Returns:
        One of ``realm``/``forest``/``parent-child``/``external``, or ``None`` if
        neither input is present.

    Failure modes:
        Never raises.
    """
    if trust_type is None and trust_attributes is None:
        return None
    if trust_type == TRUST_TYPE_MIT:
        return "realm"
    attr = trust_attributes or 0
    if attr & TRUST_ATTR_FOREST_TRANSITIVE:
        return "forest"
    if attr & TRUST_ATTR_WITHIN_FOREST:
        return "parent-child"
    return "external"


def decode_trust_transitive(trust_attributes: int | None) -> bool | None:
    """Return trust transitivity from ``trustAttributes`` (``not NON_TRANSITIVE``).

    Inputs:
        trust_attributes: raw ``trustAttributes`` bitmask, or ``None``.

    Returns:
        ``True``/``False``, or ``None`` if the bitmask is absent.

    Failure modes:
        Never raises.
    """
    if trust_attributes is None:
        return None
    return not (trust_attributes & TRUST_ATTR_NON_TRANSITIVE)


def decode_trust_sid_filtering(trust_attributes: int | None) -> bool | None:
    """Return a best-effort SID-filtering bool from ``trustAttributes``.

    ``QUARANTINED_DOMAIN (0x4)`` reliably means SID filtering for *external*
    trusts; intra-forest/forest-transitive trusts apply it under different rules
    (research risk). M3 records the raw bitmask too; precise semantics are M5's.

    Inputs:
        trust_attributes: raw ``trustAttributes`` bitmask, or ``None``.

    Returns:
        ``True``/``False`` best-effort, or ``None`` if the bitmask is absent.

    Failure modes:
        Never raises.
    """
    if trust_attributes is None:
        return None
    return bool(trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN)
