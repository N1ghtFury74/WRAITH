"""Pure structural decoders for NTDS on-disk value encodings.

These functions turn the raw/parsed values ``dissect`` yields for NTDS columns
into lossless, canonical structural representations (SID string, GUID string,
timestamp). They are deliberately *structural only* — they do not interpret
semantics (principal type, UAC bits, ACE contents). Every function is pure
(no I/O, no global state) so it is trivially unit-testable and deterministic.

Encodings handled (public [MS-DTYP]/[MS-ADTS] facts, reimplemented originally):

* **objectSid** — NTDS stores ``objectSid`` as a ``SID`` blob whose
  sub-authorities are little-endian **except the final one, which is stored
  big-endian** (the classic NTDS quirk; verified against BUILTIN ``S-1-5-32``,
  the domain object, and ``Administrator``/``krbtgt`` RIDs). Hence
  :func:`decode_ntds_sid` — distinct from a generic Windows SID decode.
* **objectGUID / schemaIDGUID** — a 16-byte GUID: first three fields
  little-endian, the trailing 8 bytes big-endian (registry/.NET string form).
* **whenChanged / whenCreated** — stored as an integer number of **seconds
  since 1601-01-01 UTC** (NTDS replication-time granularity), not 100-ns
  FILETIME ticks.

The ``dissect`` backend wraps many single-valued NTDS attributes in a one-element
list (tagged columns); :func:`as_scalar` / :func:`as_list` normalise that so
callers never have to special-case it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

#: Epoch for NTDS ``whenChanged``/``whenCreated`` (seconds since 1601-01-01 UTC).
_EPOCH_1601: datetime = datetime(1601, 1, 1, tzinfo=UTC)

#: Minimum length of a well-formed SID header (revision + count + 6-byte authority).
_SID_HEADER_LEN: int = 8


def as_scalar(value: Any) -> Any:  # noqa: ANN401 - backend values are untyped unions
    """Return a single value for a possibly list-wrapped backend value.

    ``dissect`` yields single-valued NTDS attributes as a one-element list for
    tagged columns and as a bare value for fixed columns. This collapses the
    former to the element and leaves the latter unchanged.

    Inputs:
        value: a backend-parsed value (scalar, list, or ``None``).

    Returns:
        ``None`` for ``None`` or an empty list; the sole element for a
        one-element list; the first element for a multi-element list; otherwise
        ``value`` unchanged.

    Failure modes:
        Never raises.
    """
    if isinstance(value, list):
        return value[0] if value else None
    return value


def as_list(value: Any) -> list[Any]:  # noqa: ANN401 - backend values are untyped
    """Return a list for a possibly scalar backend value (multi-valued view).

    Inputs:
        value: a backend-parsed value (scalar, list, or ``None``).

    Returns:
        ``[]`` for ``None``, the list itself for a list, else ``[value]``.

    Failure modes:
        Never raises.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def decode_ntds_sid(raw: bytes | None) -> str | None:
    """Decode NTDS ``objectSid`` raw bytes to the canonical ``S-1-...`` string.

    The final sub-authority is read big-endian and all preceding ones
    little-endian, matching NTDS on-disk storage (a lossless structural decode;
    not semantic interpretation).

    Inputs:
        raw: the raw ``objectSid`` bytes, or ``None``.

    Returns:
        The SID string (e.g. ``S-1-5-21-...-500``), or ``None`` if ``raw`` is
        ``None`` / too short / internally inconsistent (truncated blob). A
        malformed blob degrades to ``None`` rather than raising, so a torn
        record cannot crash a run.

    Failure modes:
        Never raises; a malformed/short blob returns ``None``.
    """
    if raw is None or len(raw) < _SID_HEADER_LEN:
        return None
    revision = raw[0]
    sub_count = raw[1]
    if len(raw) < _SID_HEADER_LEN + 4 * sub_count:
        return None
    authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    for index in range(sub_count):
        chunk = raw[8 + 4 * index : 12 + 4 * index]
        # Final sub-authority (the RID for principal SIDs) is stored big-endian.
        if index == sub_count - 1:
            sub = int.from_bytes(chunk, "big")
        else:
            sub = int.from_bytes(chunk, "little")
        parts.append(str(sub))
    return "-".join(parts)


def decode_guid(raw: bytes | None) -> str | None:
    """Decode a 16-byte GUID blob to the canonical dashed string form.

    Inputs:
        raw: the 16-byte GUID bytes (``objectGUID``/``schemaIDGUID``), or ``None``.

    Returns:
        The lowercase dashed GUID string, or ``None`` if ``raw`` is ``None`` or
        not exactly 16 bytes (counted/handled by the caller, never raised here).

    Failure modes:
        Never raises; a wrong-length blob returns ``None``.
    """
    if raw is None or len(raw) != 16:
        return None
    data1 = int.from_bytes(raw[0:4], "little")
    data2 = int.from_bytes(raw[4:6], "little")
    data3 = int.from_bytes(raw[6:8], "little")
    data4 = raw[8:10].hex()
    data5 = raw[10:16].hex()
    return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4}-{data5}"


def decode_ntds_timestamp(value: int | None) -> datetime | None:
    """Decode an NTDS ``whenChanged``/``whenCreated`` integer to a UTC datetime.

    The value is the number of seconds since 1601-01-01 UTC. ``0`` (and any
    non-positive value) denotes "unset" and decodes to ``None``.

    Inputs:
        value: seconds since 1601-01-01 UTC, or ``None``.

    Returns:
        A timezone-aware UTC :class:`datetime`, or ``None`` for an unset/invalid
        value (including a sentinel so large it would overflow the calendar).

    Failure modes:
        Never raises; an out-of-range value degrades to ``None``.
    """
    if value is None or value <= 0:
        return None
    try:
        return _EPOCH_1601 + timedelta(seconds=int(value))
    except (OverflowError, ValueError, OSError):
        return None
