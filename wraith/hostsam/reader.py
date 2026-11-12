"""Registry-hive I/O seam for the Tier-C host-SAM ``AdminTo`` module.

Reads a member host's ``SAM`` hive (alias membership + local machine SID) and,
optionally, its ``SYSTEM`` hive (the host's ComputerName, for the computer-node
join) — entirely offline. The hive reader is Impacket ``winregistry`` (PM
decision overriding doc-09's regipy recommendation): the SAME dependency already
used for the boot key in :mod:`wraith.parsing.ntds_secrets` and for the ADCS
DC-config in :mod:`wraith.analysis.adcs_esc`. No new third-party dependency, no
``regipy``.

Alias membership is PLAINTEXT in the SAM hive, so NO SYSTEM boot key / syskey /
PEK is needed here (research §2.6). The crypto path is never touched.

This is the impure boundary: every open/read is guarded so an unreadable or
malformed hive degrades to a counted gap on the returned result (``read_error``
/ ``cblob_errors``), never a crash. The C-blob struct parsing itself is the pure
:mod:`wraith.hostsam.cblob`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wraith.hostsam.cblob import (
    DOMAIN_ALIAS_RID_ADMINS,
    DOMAIN_ALIAS_RID_DCOM_USERS,
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
    DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    parse_binary_sid,
    parse_c_blob,
)

_log = logging.getLogger(__name__)

#: Registry-path template of any alias ``C`` value: the 8-upper-hex RID subkey.
_ALIAS_KEY_TEMPLATE: str = "\\SAM\\Domains\\Builtin\\Aliases\\{subkey}"
#: Registry path of the Administrators alias ``C`` value (RID 0x220).
_ADMINS_C_PATH: str = "\\SAM\\Domains\\Builtin\\Aliases\\00000220\\C"
#: The alias subtree key (for its last-written timestamp + the Members cross-check).
_ADMINS_KEY_PATH: str = "\\SAM\\Domains\\Builtin\\Aliases\\00000220"
_MEMBERS_KEY_PATH: str = "\\SAM\\Domains\\Builtin\\Aliases\\Members"

#: The three ADDITIONAL built-in local aliases read from the SAME hive alongside
#: Administrators, driving the ``CanRDP`` / ``ExecuteDCOM`` / ``CanPSRemote`` lanes
#: (research 27 §2.3). Each is ``(RID, 8-upper-hex subkey)``; the C-blob layout is
#: byte-for-byte identical to Administrators, so :func:`parse_c_blob` applies
#: unchanged — the subkey name is the only per-alias variable. Administrators is
#: NOT in this table: it keeps its own top-level fields + hive-level gap tokens
#: (it is always present, unlike these three which are frequently absent).
_EXTRA_ALIAS_SUBKEYS: tuple[tuple[int, str], ...] = (
    (DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS, "0000022B"),
    (DOMAIN_ALIAS_RID_DCOM_USERS, "00000232"),
    (DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS, "00000244"),
)
#: The local account-domain ``V`` value; its trailing bytes carry the machine SID.
_ACCOUNT_V_PATH: str = "\\SAM\\Domains\\Account\\V"
#: The host's NetBIOS ComputerName (SYSTEM hive; value under the current ControlSet).
_COMPUTERNAME_SUFFIX: str = "\\Control\\ComputerName\\ComputerName\\ComputerName"
_SELECT_CURRENT_PATH: str = "\\Select\\Current"

#: Windows FILETIME epoch (1601-01-01 UTC); REG_NK ``lastChange`` is 100ns ticks.
_FILETIME_EPOCH: datetime = datetime(1601, 1, 1, tzinfo=UTC)
#: A machine/domain SID (``S-1-5-21-a-b-c``) is 24 bytes: rev+count+auth(8) + 3*u32.
_MACHINE_SID_LEN: int = 24

#: ``HostSamRead.read_error_reason`` tokens (distinct causes of a read gap). The
#: orchestrator maps these to the two counted-gap keys so an operator can tell a
#: missing/unopenable hive from a present hive whose Administrators alias is absent.
READ_ERROR_HIVE_UNREADABLE: str = "hive_unreadable"
READ_ERROR_ALIAS_ABSENT: str = "alias_absent"


@dataclass(frozen=True)
class AliasRead:
    """One built-in local alias's ``C``-blob read (per-alias status + membership).

    Covers the three ADDITIONAL aliases (Remote Desktop Users / Distributed COM
    Users / Remote Management Users) read alongside Administrators from the same
    hive. Unlike Administrators, these are frequently absent on a host — absence
    is a benign, separately-counted state (``found=False``), NOT a read error.

    Attributes:
        rid: the alias RID (``0x22B`` / ``0x232`` / ``0x244``), used to map the
            lane to its edge kind downstream.
        subkey: the 8-upper-hex alias subkey name (e.g. ``0000022B``) — the
            provenance anchor for this lane's edges.
        member_sids: the alias member SIDs (authoritative), in on-disk order;
            empty when the alias was absent OR present-but-empty.
        last_change: the alias key's last-written REGF timestamp (UTC), for the
            edge provenance ``directory_timestamp``; ``None`` if unavailable.
        found: whether the alias ``C`` value was located (``False`` = absent,
            benign). A present-but-empty alias is ``found=True`` with
            ``member_sids == ()``.
        cblob_errors: count of malformed-field conditions from this alias's
            C-blob parse (a real gap the caller counts per lane).
    """

    rid: int
    subkey: str
    member_sids: tuple[str, ...]
    last_change: datetime | None
    found: bool
    cblob_errors: int


@dataclass(frozen=True)
class HostSamRead:
    """What one member host's ``SAM`` hive yielded (counts + facts, no secrets).

    Attributes:
        member_sids: the Administrators-alias member SIDs (authoritative), in
            on-disk order; empty when the alias/C value was absent or unreadable.
        machine_sid: the host's local account-domain SID (``S-1-5-21-a-b-c``, no
            RID), used to split LOCAL from DOMAIN members; ``None`` if unreadable.
        last_change: the alias key's last-written REGF timestamp (UTC), for the
            edge provenance ``directory_timestamp``; ``None`` if unavailable.
        members_crosscheck_domains: the domain SIDs listed under the ``Members``
            reverse-index subkey — a corroboration set, NOT the source of truth.
        found_alias: whether the Administrators alias ``C`` value was located.
        read_error: whether the hive (or the alias C value) could not be read at
            all — a counted gap for the caller.
        read_error_reason: when ``read_error`` is set, WHICH cause —
            :data:`READ_ERROR_HIVE_UNREADABLE` (hive missing / path rejected /
            unopenable) or :data:`READ_ERROR_ALIAS_ABSENT` (hive opened but the
            Administrators alias ``C`` value was not present). ``None`` otherwise.
        cblob_errors: count of malformed-field conditions from the C-blob parse.
        aliases: the three ADDITIONAL built-in aliases (Remote Desktop Users /
            Distributed COM Users / Remote Management Users), in fixed order, each
            as an :class:`AliasRead` (per-alias membership + status). Empty when
            the hive was unreadable (the read returned early) — so a caller built
            against the legacy Administrators-only shape sees ``()`` and is
            unaffected. Administrators is NOT duplicated here: it stays in the
            top-level fields above.
    """

    member_sids: tuple[str, ...]
    machine_sid: str | None
    last_change: datetime | None
    members_crosscheck_domains: tuple[str, ...]
    found_alias: bool
    read_error: bool
    read_error_reason: str | None = field(default=None)
    cblob_errors: int = field(default=0)
    aliases: tuple[AliasRead, ...] = field(default=())


def _open_hive(path: Path) -> object:
    """Open a registry hive via Impacket ``winregistry`` (NOT regipy).

    Prefers the version-current ``get_registry_parser`` factory (impacket 0.13.x
    makes ``Registry`` abstract), falling back to the classic ``Registry``
    constructor on older impacket. Lazily imported (offline-cheap). Raises on an
    unreadable/invalid hive — the caller turns that into a counted gap.
    """
    from impacket import winregistry

    factory = getattr(winregistry, "get_registry_parser", None)
    if factory is not None:
        return factory(str(path), False)
    return winregistry.Registry(str(path), False)  # pragma: no cover - older impacket


def _get_binary(reader: object, path: str) -> bytes | None:
    """Return a value's raw bytes by full path, or ``None`` if absent/unreadable."""
    try:
        result = reader.getValue(path)  # type: ignore[attr-defined]
    except Exception as exc:  # absent key / malformed node -> None
        _log.debug("hostsam: value %s unreadable: %s", path, type(exc).__name__)
        return None
    if not result:
        return None
    data = result[1]
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return None


def _filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert a Windows FILETIME (100ns ticks since 1601) to a UTC datetime.

    Returns ``None`` for a non-positive / absurd value (a malformed node), never
    raising — the timestamp is diagnostic provenance, not load-bearing.
    """
    if filetime <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (OverflowError, OSError, ValueError):
        return None


def _read_last_change(reader: object, key_path: str) -> datetime | None:
    """Read a key's ``lastChange`` FILETIME (REG_NK), or ``None`` if unavailable."""
    try:
        node = reader.findKey(key_path)  # type: ignore[attr-defined]
        if node is None:
            return None
        raw = node["lastChange"]
    except Exception as exc:  # node missing / field absent -> None
        _log.debug("hostsam: lastChange for %s unavailable: %s", key_path, type(exc).__name__)
        return None
    if not isinstance(raw, int):
        return None
    return _filetime_to_datetime(raw)


def _parse_machine_sid(v_value: bytes) -> str | None:
    """Extract the local account-domain SID from the ``Account\\V`` value tail.

    The machine SID is serialised as the final 24 bytes of ``V``: a canonical
    ``S-1-5-21-a-b-c`` SID whose binary form has FOUR sub-authorities (the literal
    ``21`` plus the three domain identifiers), i.e. ``8 + 4*4 = 24`` bytes. The
    tail is parsed with the shared bounds-checked :func:`parse_binary_sid`;
    anything that is not a well-formed domain-specific (``S-1-5-21-...``) SID
    returns ``None`` (a short/malformed value), never raising.
    """
    if len(v_value) < _MACHINE_SID_LEN:
        return None
    tail = v_value[-_MACHINE_SID_LEN:]
    parsed = parse_binary_sid(tail, 0)
    if parsed is None:
        return None
    sid, _consumed = parsed
    parts = sid.split("-")
    if len(parts) != 7 or parts[:4] != ["S", "1", "5", "21"]:
        return None
    return sid


def _read_members_crosscheck(reader: object) -> tuple[str, ...]:
    """Enumerate the ``Members`` reverse-index domain SIDs (corroboration only).

    The ``Builtin\\Aliases\\Members\\<domain-SID>`` subkeys are SAM's SID->alias
    reverse index; their names are the domain SIDs that contribute at least one
    alias member. This is a cross-check against the C-array's member domains, NOT
    the membership source of truth (research §2.1). Returns an empty tuple on any
    read failure (the cross-check is optional).
    """
    try:
        node = reader.findKey(_MEMBERS_KEY_PATH)  # type: ignore[attr-defined]
        if node is None:
            return ()
        names = reader.enumKey(node)  # type: ignore[attr-defined]
    except Exception as exc:
        _log.debug("hostsam: Members cross-check unavailable: %s", type(exc).__name__)
        return ()
    return tuple(sorted(str(name) for name in names))


def _read_alias(reader: object, rid: int, subkey: str) -> AliasRead:
    """Read one additional built-in alias's ``C`` blob (per-alias, bounds-safe).

    Locates ``\\SAM\\Domains\\Builtin\\Aliases\\<subkey>\\C``, parses it with the
    SAME pure :func:`~wraith.hostsam.cblob.parse_c_blob` used for Administrators
    (the layout is alias-agnostic), and reads the alias key's last-written time.

    Inputs:
        reader: an already-opened Impacket ``winregistry`` hive reader.
        rid: the alias RID (for the returned :class:`AliasRead`).
        subkey: the 8-upper-hex alias subkey name.

    Returns:
        An :class:`AliasRead`. An absent ``C`` value yields ``found=False`` with
        empty membership (benign — these aliases are frequently absent); a present
        value yields the parsed members plus its ``cblob_errors`` count.

    Failure modes:
        Never raises; an unreadable value degrades to ``found=False`` (the caller
        distinguishes absent from a hive-level read error, which it handles first).
    """
    c_path = f"{_ALIAS_KEY_TEMPLATE.format(subkey=subkey)}\\C"
    blob = _get_binary(reader, c_path)
    if blob is None:
        return AliasRead(
            rid=rid, subkey=subkey, member_sids=(), last_change=None, found=False, cblob_errors=0
        )
    parsed = parse_c_blob(blob)
    last_change = _read_last_change(reader, _ALIAS_KEY_TEMPLATE.format(subkey=subkey))
    return AliasRead(
        rid=rid,
        subkey=subkey,
        member_sids=parsed.member_sids,
        last_change=last_change,
        found=True,
        cblob_errors=parsed.errors,
    )


def read_host_sam(sam_hive_path: Path | str) -> HostSamRead:
    """Read the Administrators-alias membership from a host ``SAM`` hive (offline).

    Opens the hive via Impacket ``winregistry``, reads the Administrators alias
    (RID ``0x220``) ``C`` value, parses its inline member SID array with the pure
    :func:`~wraith.hostsam.cblob.parse_c_blob`, reads the local machine SID
    (``Account\\V`` tail), the alias key's last-written timestamp, and the
    ``Members`` reverse-index cross-check. It ALSO reads the three additional
    built-in aliases (Remote Desktop Users / Distributed COM Users / Remote
    Management Users, RIDs ``0x22B`` / ``0x232`` / ``0x244``) from the same hive
    into :attr:`HostSamRead.aliases`, each with the same parser (their absence is
    benign — recorded as ``found=False``, not a read error).

    Inputs:
        sam_hive_path: path to the host's ``SAM`` hive (untrusted; validated and
            resolved before opening — never executed, read-only).

    Returns:
        A :class:`HostSamRead`. An unopenable hive, a path-safety rejection, or a
        missing alias ``C`` value sets ``read_error`` / ``found_alias`` and leaves
        ``member_sids`` empty — a counted gap for the caller, never a crash.

    Failure modes:
        Never raises; every failure is reflected on the returned struct.
    """
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        resolved = ensure_existing_file(sam_hive_path)
    except PathSafetyError as exc:
        _log.warning("hostsam: SAM hive path rejected: %s", exc)
        return HostSamRead(
            (),
            None,
            None,
            (),
            found_alias=False,
            read_error=True,
            read_error_reason=READ_ERROR_HIVE_UNREADABLE,
        )

    try:
        reader = _open_hive(resolved)
    except Exception as exc:
        _log.warning("hostsam: SAM hive unreadable (%s)", type(exc).__name__)
        return HostSamRead(
            (),
            None,
            None,
            (),
            found_alias=False,
            read_error=True,
            read_error_reason=READ_ERROR_HIVE_UNREADABLE,
        )

    try:
        blob = _get_binary(reader, _ADMINS_C_PATH)
        if blob is None:
            _log.warning(
                "hostsam: Administrators alias (RID 0x%x) C value absent", DOMAIN_ALIAS_RID_ADMINS
            )
            return HostSamRead(
                (),
                None,
                None,
                (),
                found_alias=False,
                read_error=True,
                read_error_reason=READ_ERROR_ALIAS_ABSENT,
            )
        parsed = parse_c_blob(blob)
        machine_sid = None
        v_value = _get_binary(reader, _ACCOUNT_V_PATH)
        if v_value is not None:
            machine_sid = _parse_machine_sid(v_value)
        last_change = _read_last_change(reader, _ADMINS_KEY_PATH)
        crosscheck = _read_members_crosscheck(reader)
        # The three additional local aliases (RDP / DCOM / PSRemote), read from the
        # SAME hive with the SAME parser; absence is benign (not a hive read error).
        aliases = tuple(_read_alias(reader, rid, subkey) for rid, subkey in _EXTRA_ALIAS_SUBKEYS)
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # pragma: no cover - best-effort cleanup
                _log.debug("hostsam: SAM hive close raised", exc_info=True)

    return HostSamRead(
        member_sids=parsed.member_sids,
        machine_sid=machine_sid,
        last_change=last_change,
        members_crosscheck_domains=crosscheck,
        found_alias=True,
        read_error=False,
        cblob_errors=parsed.errors,
        aliases=aliases,
    )


def read_computer_name(system_hive_path: Path | str) -> tuple[str | None, int]:
    """Read the host's NetBIOS ComputerName from its ``SYSTEM`` hive (offline).

    Resolves the current ``ControlSet`` via ``\\Select\\Current``, then reads
    ``<ControlSet>\\Control\\ComputerName\\ComputerName\\ComputerName`` (a
    UTF-16LE REG_SZ). Used ONLY for the computer-node join (research §2.6) — not
    for membership.

    Inputs:
        system_hive_path: path to the host's ``SYSTEM`` hive (untrusted;
            validated before open).

    Returns:
        ``(computer_name, errors)``. ``computer_name`` is the decoded NetBIOS
        name (upper-case as stored is NOT forced here), or ``None`` when the hive
        or the value is unreadable; ``errors`` is ``1`` on any read failure, else
        ``0``.

    Failure modes:
        Never raises; an unreadable hive degrades to ``(None, 1)``.
    """
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        resolved = ensure_existing_file(system_hive_path)
    except PathSafetyError as exc:
        _log.warning("hostsam: SYSTEM hive path rejected: %s", exc)
        return None, 1

    try:
        reader = _open_hive(resolved)
    except Exception as exc:
        _log.warning("hostsam: SYSTEM hive unreadable (%s)", type(exc).__name__)
        return None, 1

    try:
        current = _read_select_current(reader)
        control_set = f"ControlSet{current:03d}" if current is not None else "ControlSet001"
        name = _read_computername_value(reader, f"\\{control_set}{_COMPUTERNAME_SUFFIX}")
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # pragma: no cover - best-effort cleanup
                _log.debug("hostsam: SYSTEM hive close raised", exc_info=True)

    return (name, 0) if name is not None else (None, 1)


def _read_select_current(reader: object) -> int | None:
    """Read ``\\Select\\Current`` (the active ControlSet index), or ``None``."""
    try:
        result = reader.getValue(_SELECT_CURRENT_PATH)  # type: ignore[attr-defined]
    except Exception as exc:
        _log.debug("hostsam: Select\\Current unreadable: %s", type(exc).__name__)
        return None
    if not result:
        return None
    value = result[1]
    if isinstance(value, bool):  # bool is an int subclass; not a ControlSet index
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and len(value) >= 4:
        return int.from_bytes(bytes(value[:4]), "little")
    return None


def _read_computername_value(reader: object, path: str) -> str | None:
    """Read a UTF-16LE REG_SZ ComputerName value, or ``None`` if absent/malformed."""
    try:
        result = reader.getValue(path)  # type: ignore[attr-defined]
    except Exception as exc:
        _log.debug("hostsam: ComputerName value unreadable: %s", type(exc).__name__)
        return None
    if not result:
        return None
    value = result[1]
    if isinstance(value, str):
        return value.rstrip("\x00") or None
    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = bytes(value).decode("utf-16-le")
        except (UnicodeDecodeError, ValueError):
            return None
        return decoded.rstrip("\x00") or None
    return None
