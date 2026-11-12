"""Golden gate suite — the ``replPropertyMetaData`` offline decoder (M-MS pre-4).

Every fixture is hand-built bytes with KNOWN values; every expected value is
derived independently via the stdlib (``struct`` / ``uuid`` / ``datetime``), NOT
copied from the implementation. A wrong decoded ATTID, version, UTC time,
invocationId, or USN is a GATE FAIL — M-MS4's per-attribute newest-wins stands
on these bytes.

CAVEAT (per spike doc 26 §5.3): these are SYNTHETIC golden vectors. Byte-for-byte
parity against a REAL captured blob (``repadmin /showmeta`` on a lab DC / GOAD /
Samba) is PENDING a real capture; the decoder is "synthetic-tested,
untested-on-real" until that fixture lands.
"""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from wraith.parsing.repl_metadata import (
    ENTRY_LEN,
    HEADER_LEN,
    Recency,
    ReplAttributeStamp,
    ReplMetadataParseError,
    compare_recency,
    parse_repl_property_metadata,
    resolve_attid,
    resolve_dsa,
)

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


# --- independent reference encoders (built from [MS-DRSR] 5.155, not the SUT) --


def _encode_entry(
    attid: int, version: int, dstime_secs: int, invocation_id: uuid.UUID, usn: int
) -> bytes:
    """Independently assemble one 40-byte PROPERTY_META_DATA_EXT entry (LE)."""
    out = struct.pack("<IIq", attid, version, dstime_secs)
    out += invocation_id.bytes_le
    out += struct.pack("<q", usn)
    assert len(out) == ENTRY_LEN
    return out


def _encode_vector(entries: list[bytes], *, reserved: int = 0, version: int = 1) -> bytes:
    """Independently assemble a PROPERTY_META_DATA_EXT_VECTOR blob (LE header)."""
    header = struct.pack("<III", version, reserved, len(entries))
    assert len(header) == HEADER_LEN
    return header + b"".join(entries)


def _stamp(
    *,
    attid: int = 10,
    version: int = 1,
    secs: int = 0,
    dsa: str = "00000000-0000-0000-0000-000000000000",
    usn: int = 1,
) -> ReplAttributeStamp:
    """Build a stamp directly for the comparator tests."""
    return ReplAttributeStamp(
        attid=attid,
        version=version,
        time_changed=_EPOCH_1601 + timedelta(seconds=secs),
        originating_dsa=dsa,
        originating_usn=usn,
    )


# =============================================================================
# Clean multi-entry vector
# =============================================================================


def test_clean_three_entry_vector_decodes_exactly() -> None:
    dsa_a = uuid.UUID("1b9705a0-1111-2222-3333-444455556666")
    dsa_b = uuid.UUID("deadbeef-0000-1111-2222-333344445555")
    dsa_c = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    # whenChanged = 2021-06-01T12:00:00Z expressed as DSTIME seconds-since-1601.
    secs_b = int((datetime(2021, 6, 1, 12, 0, 0, tzinfo=UTC) - _EPOCH_1601).total_seconds())

    blob = _encode_vector(
        [
            _encode_entry(589827, 1, 0, dsa_a, 0),
            _encode_entry(90001, 42, secs_b, dsa_b, 123456789),
            _encode_entry(131074, 7, 13_000_000_000, dsa_c, -1),  # signed USN round-trips
        ]
    )

    result = parse_repl_property_metadata(blob)

    assert result.version == 1
    assert result.num_props == 3
    assert len(result.stamps) == 3

    s0, s1, s2 = result.stamps

    assert s0.attid == 589827
    assert s0.version == 1
    assert s0.time_changed == _EPOCH_1601
    assert s0.originating_dsa == str(dsa_a)
    assert s0.originating_usn == 0

    assert s1.attid == 90001
    assert s1.version == 42
    assert s1.time_changed == datetime(2021, 6, 1, 12, 0, 0, tzinfo=UTC)
    assert s1.originating_dsa == str(dsa_b)
    assert s1.originating_usn == 123456789

    assert s2.attid == 131074
    assert s2.version == 7
    assert s2.time_changed == _EPOCH_1601 + timedelta(seconds=13_000_000_000)
    assert s2.originating_dsa == str(dsa_c)
    assert s2.originating_usn == -1


def test_time_changed_is_seconds_not_filetime() -> None:
    # 1 second of DSTIME must advance exactly 1 second (not 100ns-tick semantics).
    blob = _encode_vector([_encode_entry(1, 1, 1, uuid.UUID(int=0), 1)])
    (stamp,) = parse_repl_property_metadata(blob).stamps
    assert stamp.time_changed == _EPOCH_1601 + timedelta(seconds=1)
    assert stamp.time_changed.tzinfo is UTC


def test_invocation_id_uses_bytes_le_form() -> None:
    dsa = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    blob = _encode_vector([_encode_entry(5, 2, 10, dsa, 99)])
    (stamp,) = parse_repl_property_metadata(blob).stamps
    # bytes_le round-trips to the same canonical string; a big-endian misread would not.
    assert stamp.originating_dsa == "00112233-4455-6677-8899-aabbccddeeff"
    assert uuid.UUID(stamp.originating_dsa).bytes_le == dsa.bytes_le


# =============================================================================
# Zero-count vector
# =============================================================================


def test_zero_count_vector_is_empty_not_error() -> None:
    blob = _encode_vector([])
    result = parse_repl_property_metadata(blob)
    assert result.num_props == 0
    assert result.stamps == ()


# =============================================================================
# Malformed / truncated -> counted parse gap (never partial)
# =============================================================================


def test_header_too_short_raises() -> None:
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(b"\x01\x00\x00")
    assert exc.value.reason == "header-too-short"


def test_bad_version_raises() -> None:
    blob = _encode_vector([_encode_entry(1, 1, 0, uuid.UUID(int=0), 0)], version=2)
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(blob)
    assert exc.value.reason == "bad-version"


def test_nonzero_reserved_raises() -> None:
    blob = _encode_vector([_encode_entry(1, 1, 0, uuid.UUID(int=0), 0)], reserved=1)
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(blob)
    assert exc.value.reason == "bad-reserved"


def test_truncated_entry_raises_no_partial() -> None:
    # Header claims 2 entries, only 1.5 present -> length mismatch, NOT a 1-entry result.
    good = _encode_vector(
        [
            _encode_entry(1, 1, 0, uuid.UUID(int=0), 0),
            _encode_entry(2, 2, 0, uuid.UUID(int=1), 0),
        ]
    )
    truncated = good[: HEADER_LEN + ENTRY_LEN + 10]
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(truncated)
    assert exc.value.reason == "length-mismatch"


def test_trailing_bytes_raises() -> None:
    blob = _encode_vector([_encode_entry(1, 1, 0, uuid.UUID(int=0), 0)]) + b"\xff\xff"
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(blob)
    assert exc.value.reason == "length-mismatch"


def test_count_overrun_is_bounded_before_iterating() -> None:
    # Header claims a huge count but the blob is tiny -> must fail on the bound,
    # not attempt to read past the buffer.
    blob = struct.pack("<III", 1, 0, 1_000_000)
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(blob)
    assert exc.value.reason == "length-mismatch"


def test_implausible_dstime_overflow_raises() -> None:
    # A DSTIME so large it overflows the datetime calendar is corrupt, never valid.
    blob = _encode_vector([_encode_entry(1, 1, 0x7FFFFFFFFFFFFFFF, uuid.UUID(int=0), 0)])
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(blob)
    assert exc.value.reason == "time-overflow"


def test_non_bytes_input_raises() -> None:
    with pytest.raises(ReplMetadataParseError) as exc:
        parse_repl_property_metadata(None)  # type: ignore[arg-type]
    assert exc.value.reason == "not-bytes"


def test_bytearray_and_memoryview_accepted() -> None:
    blob = _encode_vector([_encode_entry(9, 3, 5, uuid.UUID(int=7), 11)])
    from_ba = parse_repl_property_metadata(bytearray(blob))
    from_mv = parse_repl_property_metadata(memoryview(blob))
    assert from_ba == from_mv == parse_repl_property_metadata(blob)


# =============================================================================
# Comparator — version primary, time secondary, usn tertiary, true-tie -> TIED
# =============================================================================


def test_comparator_version_wins_even_against_newer_time() -> None:
    # second has a LATER wall-clock but LOWER version; version is skew-immune primary.
    first = _stamp(version=5, secs=0, usn=1)
    second = _stamp(version=4, secs=10_000_000, usn=999)
    assert compare_recency(first, second) is Recency.FIRST


def test_comparator_time_breaks_equal_version() -> None:
    first = _stamp(version=3, secs=100, usn=50)
    second = _stamp(version=3, secs=200, usn=1)
    assert compare_recency(first, second) is Recency.SECOND


def test_comparator_usn_breaks_equal_version_and_time() -> None:
    first = _stamp(version=3, secs=100, usn=50)
    second = _stamp(version=3, secs=100, usn=51)
    assert compare_recency(first, second) is Recency.SECOND


def test_comparator_true_tie_is_explicit() -> None:
    first = _stamp(version=3, secs=100, usn=50, dsa="aaaa-...")
    second = _stamp(version=3, secs=100, usn=50, dsa="bbbb-...")
    # Identical on all three ladder fields, even with different DSAs -> TIED, never a pick.
    assert compare_recency(first, second) is Recency.TIED


# =============================================================================
# Resolution helpers — resolve or counted gap with raw id kept
# =============================================================================


def test_resolve_attid_hit() -> None:
    res = resolve_attid(590045, {590045: "sAMAccountName"})
    assert res.attid == 590045
    assert res.ldap_display_name == "sAMAccountName"
    assert res.unresolved is False


def test_resolve_attid_miss_keeps_raw_and_counts() -> None:
    res = resolve_attid(999999, {590045: "sAMAccountName"})
    assert res.attid == 999999  # raw id KEPT
    assert res.ldap_display_name is None
    assert res.unresolved is True  # counted gap


def test_resolve_dsa_hit_case_insensitive() -> None:
    guid = "1B9705A0-1111-2222-3333-444455556666"
    res = resolve_dsa(guid.lower(), {guid: "DC01"})
    assert res.dc_name == "DC01"
    assert res.unresolved is False
    assert res.invocation_id == guid.lower()


def test_resolve_dsa_miss_keeps_raw_and_counts() -> None:
    res = resolve_dsa("ffffffff-0000-0000-0000-000000000000", {})
    assert res.invocation_id == "ffffffff-0000-0000-0000-000000000000"  # raw GUID KEPT
    assert res.dc_name is None
    assert res.unresolved is True  # counted gap
