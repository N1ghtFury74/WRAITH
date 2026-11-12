"""SAM alias ``C``-blob + binary-SID parser (Tier-C host-SAM, pure/no-I/O).

The ``C`` REG_BINARY value on each ``SAM\\Domains\\Builtin\\Aliases\\<RID>`` subkey
serialises a domain-local group (alias): a 52-byte header followed by the NT
security descriptor, the name, the description, and the inline **member SID
array**. For the local-``AdminTo`` derivation we need exactly the SID array of the
Administrators alias (RID ``0x220`` = ``DOMAIN_ALIAS_RID_ADMINS``). That array
*is* the authoritative membership (the same set a live ``SamrGetMembersInAlias``
returns) — see ``docs/research/09-host-sam-adminto-reference.md`` §2.1/§2.2.

This module is a **WRAITH-original** struct reader for the libyal winreg-kb
public layout (format reused, no foreign code). It is a pure function over
``bytes``; the untrusted-input rule governs every slice: EVERY offset/size is
bounds-checked against the buffer length BEFORE it is used, and a malformed
field degrades to a counted parse error (surfaced on :attr:`CBlobParse.errors`),
never an out-of-bounds read, never a crash, never a silently-wrong member list.
Determinism: identical bytes -> identical :class:`CBlobParse`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

#: Well-known predefined RID of the built-in Administrators alias ([MS-SAMR]
#: §2.4.5): ``0x220`` = 544 = ``DOMAIN_ALIAS_RID_ADMINS``. The alias subkey name
#: is this value as 8 upper-hex digits (``00000220``).
DOMAIN_ALIAS_RID_ADMINS: int = 0x220

#: Sibling built-in alias RIDs that back the other three BloodHound local-group
#: edges (research 27 §2.1, SID-anchored: Microsoft well-known SIDs / [MS-DTYP]
#: §2.4.2.4). They parse with the SAME struct reader as Administrators — the only
#: per-alias variable is the 8-upper-hex subkey name — and map:
#: ``0x22B`` (555) -> ``CanRDP`` (Remote Desktop Users),
#: ``0x232`` (562) -> ``ExecuteDCOM`` (Distributed COM Users),
#: ``0x244`` (580) -> ``CanPSRemote`` (Remote Management Users).
DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS: int = 0x22B
DOMAIN_ALIAS_RID_DCOM_USERS: int = 0x232
DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS: int = 0x244

# --- public libyal winreg-kb header layout (relative to the blob start) -------
_OFF_RID: int = 0
_OFF_SID_ARRAY_OFFSET: int = 40  # SID-array start, RELATIVE to the 52-byte header
_OFF_SID_ARRAY_SIZE: int = 44  # SID-array size in bytes
_OFF_SID_ARRAY_COUNT: int = 48  # member count
_HEADER_SIZE: int = 52  # fixed header; data region (SD/name/desc/SIDs) follows

#: A binary SID is at least ``revision(1) + sub_count(1) + authority(6)`` = 8 bytes.
_SID_MIN_SIZE: int = 8
#: [MS-DTYP] caps a SID at 15 sub-authorities; a larger count is malformed input.
_SID_MAX_SUBAUTH: int = 15


def parse_binary_sid(buf: bytes, offset: int) -> tuple[str, int] | None:
    """Parse one binary SID at ``buf[offset:]`` (bounds-checked, pure).

    A binary SID is ``[revision u8][sub_count u8][authority u48 big-endian]
    [sub_authorities u32-le * sub_count]``, rendered canonically as
    ``S-<rev>-<authority>[-<sub>]*``.

    Inputs:
        buf: the containing buffer (untrusted).
        offset: the byte offset of the SID within ``buf``.

    Returns:
        ``(sid_string, consumed_bytes)`` on success, or ``None`` when ``offset``
        is negative, the header/sub-authorities would read past the end of
        ``buf``, or ``sub_count`` exceeds the [MS-DTYP] maximum (all malformed
        input — the caller counts it as a parse error).

    Failure modes:
        Never raises; every out-of-range condition returns ``None``.
    """
    if offset < 0 or offset + _SID_MIN_SIZE > len(buf):
        return None
    revision = buf[offset]
    sub_count = buf[offset + 1]
    if sub_count > _SID_MAX_SUBAUTH:
        return None
    end = offset + _SID_MIN_SIZE + 4 * sub_count
    if end > len(buf):
        return None
    authority = int.from_bytes(buf[offset + 2 : offset + 8], "big")
    subs = [
        struct.unpack_from("<I", buf, offset + _SID_MIN_SIZE + 4 * i)[0] for i in range(sub_count)
    ]
    sid = f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)
    return sid, end - offset


@dataclass(frozen=True)
class CBlobParse:
    """The result of parsing one alias ``C`` blob (counts, never raises).

    Attributes:
        rid: the alias RID from the header (``None`` if the header is truncated).
        member_sids: the inline member SIDs successfully parsed, in on-disk order
            (deduped is NOT done here — that is the edge builder's concern).
        declared_count: the member count the header advertises (offset 48), or
            ``None`` if the header is truncated. A mismatch with
            ``len(member_sids)`` is recorded as one ``errors`` increment so the
            gap is never silent.
        errors: count of malformed-field conditions encountered (truncated
            header, out-of-range SID-array offset/size, a SID that overruns the
            declared array, or a count mismatch). ``0`` means a fully clean parse.
        ok: ``True`` iff ``errors == 0`` (a convenience for the caller's gate).
    """

    rid: int | None
    member_sids: tuple[str, ...]
    declared_count: int | None
    errors: int
    ok: bool


def _u32(buf: bytes, offset: int) -> int:
    """Read a little-endian u32 at ``offset`` (caller has bounds-checked)."""
    return int(struct.unpack_from("<I", buf, offset)[0])


def parse_c_blob(blob: bytes) -> CBlobParse:
    """Parse an alias ``C`` REG_BINARY blob into its member SID array (pure).

    Reads the libyal winreg-kb header (RID + SID-array offset/size/count) and
    walks the inline SID array, bounds-checking every slice against ``len(blob)``
    and against the array's own declared extent before reading. The member SIDs
    are the authoritative alias membership (research §2.1).

    Inputs:
        blob: the raw ``C`` value bytes (untrusted forensic input).

    Returns:
        A :class:`CBlobParse`. A truncated header yields ``rid=None``,
        ``member_sids=()`` and ``errors>=1``; a well-formed header with a
        malformed SID array yields the SIDs parsed up to the fault plus a counted
        error. The function NEVER raises and NEVER reads out of bounds.

    Failure modes:
        None (every malformed condition becomes a counted ``errors`` increment).
    """
    if len(blob) < _HEADER_SIZE:
        return CBlobParse(rid=None, member_sids=(), declared_count=None, errors=1, ok=False)

    rid = _u32(blob, _OFF_RID)
    sid_offset = _u32(blob, _OFF_SID_ARRAY_OFFSET)
    sid_size = _u32(blob, _OFF_SID_ARRAY_SIZE)
    declared_count = _u32(blob, _OFF_SID_ARRAY_COUNT)

    # ``sid_offset`` / ``sid_size`` are unsigned u32 reads, so ``array_start >=
    # _HEADER_SIZE`` and ``sid_size >= 0`` hold by construction (no dead guards):
    # the only way the extent can be malformed is overrunning the buffer end.
    array_start = _HEADER_SIZE + sid_offset
    array_end = array_start + sid_size

    # Bounds-check the whole array extent BEFORE any slice (untrusted input).
    if array_end > len(blob):
        return CBlobParse(
            rid=rid, member_sids=(), declared_count=declared_count, errors=1, ok=False
        )

    sids: list[str] = []
    errors = 0
    cursor = array_start
    while cursor < array_end and len(sids) < declared_count:
        parsed = parse_binary_sid(blob, cursor)
        if parsed is None:
            errors += 1
            break
        sid, consumed = parsed
        if consumed <= 0 or cursor + consumed > array_end:
            # A SID whose encoding overruns the declared array is malformed.
            errors += 1
            break
        sids.append(sid)
        cursor += consumed

    if len(sids) != declared_count:
        # Fewer (or, via a malformed walk, different) SIDs than advertised: a
        # counted gap, but the SIDs we DID recover are still returned.
        errors += 1

    return CBlobParse(
        rid=rid,
        member_sids=tuple(sids),
        declared_count=declared_count,
        errors=errors,
        ok=errors == 0,
    )
