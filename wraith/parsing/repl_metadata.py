"""Offline decoder for the NTDS ``replPropertyMetaData`` BLOB.

``replPropertyMetaData`` is a single, system-only octet column present on every
object in the ``datatable`` (Attribute-Id OID ``1.2.840.113556.1.4.3``, datatable
column ``ATTk589827``). It stores, **per replicated attribute of that object**, a
replication "stamp": the originating-update version, the originating wall-clock
time, the invocationId of the originating DC, and that DC's originating USN.
Those stamps are what lets a multi-DC merge pick a *per-attribute* "newest-wins"
winner — a thing object-level ``whenChanged`` cannot do (it cannot say *which*
attribute diverged).

This module is **pure and standalone**: it takes the RAW column bytes already
surfaced by ``dissect.esedb``/``ntdissector`` (see :mod:`wraith.parsing.ntds`)
and returns a typed, fully-decoded result. It does NOT open the ``ntds.dit`` and
is **not** wired into the ingest pipeline — M-MS4 (the multi-source merge) is the
intended and only consumer; M-MS4 attaches file/image/object provenance around
the decoded stamps (this decoder sees only the column bytes, so it cannot and
does not fabricate those provenance fields here).

On-disk layout — ``PROPERTY_META_DATA_EXT_VECTOR`` (little-endian throughout),
written from the [MS-DRSR] primary source (5.155 ``PROPERTY_META_DATA_EXT`` and
4.1.10.2.23 ``PROPERTY_META_DATA``):

* 12-byte header: ``dwVersion`` (uint32, == 1), ``dwReserved`` (uint32, == 0),
  ``cNumProps`` (uint32, number of entries that follow).
* ``cNumProps`` x 40-byte entries, each:
  ``attid`` (uint32) ``+`` ``version`` (uint32) ``+`` ``timeChanged``
  (``DSTIME`` = int64 **seconds** since 1601-01-01 UTC, NOT a 100-ns FILETIME)
  ``+`` ``uuidDsaOriginating`` (16-byte UUID, ``bytes_le`` form, the originating
  DC invocationId) ``+`` ``usnOriginating`` (int64).

**Scope boundary (documented fast-follow):** the *linked-value* metadata
(``DS_REPL_VALUE_META_DATA`` / ``msDS-ReplValueMetaData``, stored per-row in the
``link_table``, carrying membership add/remove recency via ``ftimeCreated`` /
``ftimeDeleted``) is a SEPARATE parse with its own byte layout ([MS-ADTS] 2.2.8).
It is the documented next decoder and is intentionally **NOT** built here — this
module stays scoped to ``replPropertyMetaData`` only.

**Licensing / provenance of the format knowledge.** The per-entry struct is fully
specified by Microsoft's public [MS-DRSR] 5.155 and cross-checked against the
Win32 ``DS_REPL_ATTR_META_DATA_2`` field semantics (ntdsapi.h). The one field
group reverse-engineered by others is the 12-byte vector header; **DSInternals
(MIT) was used ONLY as a format study reference for that header — no DSInternals
code is copied**; all code here is original, written from the spec. Byte-for-byte
parity against a REAL captured blob (``repadmin /showmeta`` on a lab DC / GOAD /
Samba) is PENDING a real capture (spike doc 26 §5.3): treat this decoder as
**synthetic-tested, untested-on-real** until that parity fixture lands.

Honest offline limits (counted-gap framing, surfaced by the helpers, never
silent): the blob carries the ATTID (not the attribute name) and the originating
invocationId GUID (not the DC DN / name). :func:`resolve_attid` and
:func:`resolve_dsa` turn those into names via caller-supplied maps and COUNT an
unresolved id as a gap while keeping the raw id. ``timeChanged`` has 1-second
resolution and is the originating DC's (possibly skewed) wall clock, so
:func:`compare_recency` uses ``version`` as the skew-immune PRIMARY comparator,
``timeChanged`` secondary, ``usnOriginating`` tertiary, and returns an explicit
``TIED`` on a true tie rather than ever guessing.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

#: Epoch for ``DSTIME`` / NTDS replication time (seconds since 1601-01-01 UTC).
_EPOCH_1601: datetime = datetime(1601, 1, 1, tzinfo=UTC)

#: Fixed sizes of the ``PROPERTY_META_DATA_EXT_VECTOR`` (little-endian).
HEADER_LEN: int = 12
ENTRY_LEN: int = 40

#: Required header constants per [MS-DRSR]; any deviation is a malformed blob.
EXPECTED_VERSION: int = 1
EXPECTED_RESERVED: int = 0

#: ``struct`` formats (little-endian). Header = 3 x uint32. Entry prefix =
#: attid(uint32) + version(uint32) + timeChanged(int64). Entry suffix = usn(int64).
_HEADER_FMT: str = "<III"
_ENTRY_PREFIX_FMT: str = "<IIq"  # attid, version, DSTIME seconds (signed int64)
_ENTRY_USN_FMT: str = "<q"  # originating USN (signed int64)


class ReplMetadataParseError(ValueError):
    """Raised when a ``replPropertyMetaData`` blob cannot be fully decoded.

    Carries a machine-usable ``reason`` so the caller (M-MS4) can COUNT the gap
    with a specific cause instead of a bare exception. The decoder NEVER returns
    partial/best-effort data: either the whole vector decodes or this is raised.
    """

    def __init__(self, reason: str) -> None:
        """Build the error.

        Inputs:
            reason: a short, stable machine/human cause string (e.g.
                ``"length-mismatch"``). Stored on ``self.reason``.
        """
        self.reason: str = reason
        super().__init__(reason)


class ReplAttributeStamp(BaseModel):
    """One per-attribute replication stamp decoded from the blob.

    Fields:
        attid: the internal ATTID of the attribute this stamp describes. Kept
            raw; resolve to an ``lDAPDisplayName`` via :func:`resolve_attid`.
        version: the originating-update version (starts at 1, +1 per originating
            change). The skew-immune PRIMARY recency comparator.
        time_changed: the originating wall-clock time of the last change, UTC,
            1-second resolution (decoded from ``DSTIME`` seconds-since-1601).
        originating_dsa: the invocationId GUID of the originating DC, as a
            lowercase dashed string. Kept raw; resolve to a DC name via
            :func:`resolve_dsa`. Cross-DC meaningful.
        originating_usn: the originating DC's USN for this change. Cross-DC
            meaningful; the tertiary recency comparator.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attid: int
    version: int
    time_changed: datetime
    originating_dsa: str
    originating_usn: int


class ReplMetadata(BaseModel):
    """The fully-decoded ``PROPERTY_META_DATA_EXT_VECTOR``.

    A successful decode is always complete and consistent: ``len(stamps)`` equals
    the header's ``cNumProps`` and every 40-byte entry was consumed with no
    trailing bytes. A malformed blob never produces a partial instance of this —
    it raises :class:`ReplMetadataParseError` instead.

    Fields:
        version: the vector header ``dwVersion`` (always ``1`` on success).
        num_props: the header ``cNumProps`` (== ``len(stamps)``).
        stamps: the decoded per-attribute stamps, in on-disk order.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int
    num_props: int
    stamps: tuple[ReplAttributeStamp, ...]


def parse_repl_property_metadata(blob: bytes) -> ReplMetadata:
    """Decode a raw ``replPropertyMetaData`` BLOB to a typed :class:`ReplMetadata`.

    Pure, deterministic, offline: identical bytes always give an identical result.
    The entry count is bounded against the blob length BEFORE iterating, and the
    total length must match the header exactly, so neither truncation nor trailing
    bytes can yield silent partial data.

    Inputs:
        blob: the raw column bytes of ``replPropertyMetaData`` (``ATTk589827``) for
            one object, exactly as surfaced by the ESE backend. Must be ``bytes``
            (or ``bytearray``/``memoryview``, which are accepted and normalised).

    Returns:
        A :class:`ReplMetadata` with one :class:`ReplAttributeStamp` per attribute,
        in on-disk order (may be empty for a zero-count vector).

    Failure modes (ALL raise :class:`ReplMetadataParseError`, never partial data):
        * ``not-bytes`` — input is not a bytes-like object.
        * ``header-too-short`` — fewer than 12 bytes.
        * ``bad-version`` — header ``dwVersion`` != 1.
        * ``bad-reserved`` — header ``dwReserved`` != 0.
        * ``length-mismatch`` — ``12 + cNumProps * 40`` != ``len(blob)`` (covers
          truncation AND unexpected trailing bytes).
        * ``time-overflow`` — a ``DSTIME`` that overflows the datetime calendar
          (a corrupt/implausible stamp, never a valid one).
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise ReplMetadataParseError("not-bytes")
    data = bytes(blob)

    if len(data) < HEADER_LEN:
        raise ReplMetadataParseError("header-too-short")

    dw_version, dw_reserved, num_props = struct.unpack_from(_HEADER_FMT, data, 0)
    if dw_version != EXPECTED_VERSION:
        raise ReplMetadataParseError("bad-version")
    if dw_reserved != EXPECTED_RESERVED:
        raise ReplMetadataParseError("bad-reserved")

    # Bound the count against the actual length BEFORE iterating; require an exact
    # match so truncation (too short) and trailing bytes (too long) both fail.
    if HEADER_LEN + num_props * ENTRY_LEN != len(data):
        raise ReplMetadataParseError("length-mismatch")

    stamps: list[ReplAttributeStamp] = []
    offset = HEADER_LEN
    for _ in range(num_props):
        attid, version, dstime_secs = struct.unpack_from(_ENTRY_PREFIX_FMT, data, offset)
        dsa = uuid.UUID(bytes_le=data[offset + 16 : offset + 32])
        (usn,) = struct.unpack_from(_ENTRY_USN_FMT, data, offset + 32)
        try:
            time_changed = _EPOCH_1601 + timedelta(seconds=int(dstime_secs))
        except (OverflowError, ValueError, OSError) as exc:
            raise ReplMetadataParseError("time-overflow") from exc
        stamps.append(
            ReplAttributeStamp(
                attid=attid,
                version=version,
                time_changed=time_changed,
                originating_dsa=str(dsa),
                originating_usn=usn,
            )
        )
        offset += ENTRY_LEN

    return ReplMetadata(version=dw_version, num_props=num_props, stamps=tuple(stamps))


# =============================================================================
# Optional resolution helpers — pure, caller-supplied maps, counted-gap on miss.
# The decoder itself never fails on an unresolved id; it degrades and COUNTS.
# =============================================================================


class AttidResolution(BaseModel):
    """Result of resolving an ATTID to an attribute ``lDAPDisplayName``.

    Fields:
        attid: the raw ATTID, ALWAYS kept (even when unresolved).
        ldap_display_name: the resolved name, or ``None`` if the map had no entry.
        unresolved: ``True`` when the ATTID was not in the map — this is the
            COUNTED GAP flag the caller tallies (``attid_unresolved``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attid: int
    ldap_display_name: str | None
    unresolved: bool


class DsaResolution(BaseModel):
    """Result of resolving an originating invocationId to a DC name.

    Fields:
        invocation_id: the raw invocationId GUID string, ALWAYS kept.
        dc_name: the resolved DC name, or ``None`` if the map had no entry.
        unresolved: ``True`` when the GUID was not in the map — the COUNTED GAP
            flag the caller tallies (``dsa_unresolved``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    invocation_id: str
    dc_name: str | None
    unresolved: bool


def resolve_attid(attid: int, schema_map: Mapping[int, str]) -> AttidResolution:
    """Resolve an ATTID to an ``lDAPDisplayName`` via a caller-supplied map.

    Pure; never raises, never fails the decode. A miss keeps the raw ATTID and
    flags a counted ``attid_unresolved`` gap for the caller to tally.

    Inputs:
        attid: the raw internal ATTID from a :class:`ReplAttributeStamp`.
        schema_map: ATTID -> ``lDAPDisplayName`` (built by the schema layer).

    Returns:
        An :class:`AttidResolution`; ``unresolved=True`` when ``attid`` is absent
        from ``schema_map`` (``ldap_display_name`` then ``None``, ``attid`` kept).

    Failure modes:
        Never raises.
    """
    name = schema_map.get(attid)
    return AttidResolution(attid=attid, ldap_display_name=name, unresolved=name is None)


def resolve_dsa(invocation_id: str, ntds_settings_map: Mapping[str, str]) -> DsaResolution:
    """Resolve an originating invocationId GUID to a DC name via a supplied map.

    Pure; never raises, never fails the decode. A miss keeps the raw GUID and
    flags a counted ``dsa_unresolved`` gap for the caller to tally. The lookup is
    case-insensitive on the GUID string so ``bytes_le`` formatting differences do
    not cause a spurious miss.

    Inputs:
        invocation_id: the raw invocationId GUID string from a stamp
            (:attr:`ReplAttributeStamp.originating_dsa`).
        ntds_settings_map: invocationId GUID string -> DC name (from the NTDS
            Settings objects). May be absent/empty if that capture is missing.

    Returns:
        A :class:`DsaResolution`; ``unresolved=True`` when ``invocation_id`` is
        absent from the map (``dc_name`` then ``None``, raw GUID kept).

    Failure modes:
        Never raises.
    """
    # Normalise keys once so a mixed-case map still matches deterministically.
    lowered = {key.lower(): value for key, value in ntds_settings_map.items()}
    name = lowered.get(invocation_id.lower())
    return DsaResolution(invocation_id=invocation_id, dc_name=name, unresolved=name is None)


# =============================================================================
# Recency comparator — the "which stamp is newest" primitive M-MS4 consumes.
# =============================================================================


class Recency(StrEnum):
    """Verdict of comparing two stamps for recency.

    ``FIRST``/``SECOND`` name which argument of :func:`compare_recency` is newer;
    ``TIED`` is an EXPLICIT true-tie signal so the merge can leave the attribute
    un-chosen (the owner's contract decision) rather than ever picking arbitrarily.
    """

    FIRST = "first"
    SECOND = "second"
    TIED = "tied"


def compare_recency(first: ReplAttributeStamp, second: ReplAttributeStamp) -> Recency:
    """Decide which of two per-attribute stamps is newer (skew-immune ordering).

    Comparison ladder, in order:

    1. ``version`` — the PRIMARY, skew-immune comparator (originating-update
       count; immune to DC clock skew).
    2. ``time_changed`` — secondary tiebreak (1-second wall-clock resolution).
    3. ``originating_usn`` — tertiary tiebreak.
    4. A true tie on all three -> :attr:`Recency.TIED` (NEVER an arbitrary pick;
       the caller records a counted divergence per the merge contract).

    Note the ladder does NOT consider ``originating_dsa``: a USN is only globally
    comparable within one originating DC, but it is used solely as a last-resort
    tiebreak after version and time already failed to separate the two, and a
    genuine tie there is surfaced as ``TIED`` rather than resolved by DC identity.

    Inputs:
        first: one stamp (e.g. the current winner for an attribute).
        second: the other stamp (e.g. a candidate from another source).

    Returns:
        :attr:`Recency.FIRST` if ``first`` is newer, :attr:`Recency.SECOND` if
        ``second`` is newer, :attr:`Recency.TIED` if indistinguishable.

    Failure modes:
        Never raises (pure comparison of already-decoded fields).
    """
    if first.version != second.version:
        return Recency.FIRST if first.version > second.version else Recency.SECOND
    if first.time_changed != second.time_changed:
        return Recency.FIRST if first.time_changed > second.time_changed else Recency.SECOND
    if first.originating_usn != second.originating_usn:
        return Recency.FIRST if first.originating_usn > second.originating_usn else Recency.SECOND
    return Recency.TIED
