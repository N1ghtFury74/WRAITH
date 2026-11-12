"""Independent gate suite — pure NTDS structural decoders (Module 2a).

Authored by ``wraith-tester`` (the gatekeeper), independently of the coder's
sanity file (``tests/test_ntds_structural_sanity.py``). These tests need NO
evidence: every fixture is hand-crafted bytes and every expected value is
derived independently via the stdlib (``struct`` / ``uuid`` / ``datetime``),
NOT copied from the implementation.

Correctness core under test: ``decode_ntds_sid`` (the big-endian last
sub-authority quirk), ``decode_guid`` (mixed-endian ``bytes_le`` form), and
``decode_ntds_timestamp`` (seconds-since-1601). A wrong decoded SID, GUID, or
timestamp is a GATE FAIL — these are the structural foundation Module 3 builds on.
"""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from wraith.parsing.ntds_values import (
    as_list,
    as_scalar,
    decode_guid,
    decode_ntds_sid,
    decode_ntds_timestamp,
)
from wraith.parsing.schema import _parse_internal_id_from_column

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


def _build_ntds_sid(authority: int, subs: list[int]) -> bytes:
    """Independently assemble an NTDS objectSid blob (reference encoder).

    NTDS stores sub-authorities little-endian EXCEPT the final one, which is
    big-endian. Built here from first principles so the decoder is checked
    against a layout this test controls, not against itself.
    """
    out = bytes([1, len(subs)]) + struct.pack(">Q", authority)[2:]  # 6-byte BE authority
    for index, value in enumerate(subs):
        last = index == len(subs) - 1
        out += value.to_bytes(4, "big" if last else "little")
    return out


# =============================================================================
# decode_ntds_sid — the big-endian last-sub-authority quirk
# =============================================================================


def test_sid_principal_rid_round_trips_from_crafted_layout() -> None:
    """Proves: a crafted S-1-5-21-a-b-c-500 decodes to exactly that string."""
    raw = _build_ntds_sid(5, [21, 111, 222, 333, 500])
    assert decode_ntds_sid(raw) == "S-1-5-21-111-222-333-500"


def test_sid_last_subauthority_is_read_big_endian() -> None:
    """Proves: the FINAL sub-authority is big-endian — the NTDS quirk.

    RID 500 == 0x000001F4. Stored big-endian the four bytes are 00 00 01 F4.
    A naive little-endian reader would turn those same bytes into 0xF4010000
    (4093706496). Asserting 500 comes out proves the big-endian rule is applied
    to the last sub-authority (and only there).
    """
    # header: rev=1, count=2, authority=5 ; sub0=5 (LE) ; sub1=500 (BE bytes 00 00 01 f4)
    last_be = b"\x00\x00\x01\xf4"
    raw = bytes([1, 2]) + struct.pack(">Q", 5)[2:] + (5).to_bytes(4, "little") + last_be
    assert decode_ntds_sid(raw) == "S-1-5-5-500"
    # Control: the SAME trailing bytes read little-endian would be a large int,
    # which is NOT what a correct decoder must produce (derived, not hardcoded).
    wrong_if_le = int.from_bytes(last_be, "little")
    assert wrong_if_le != 500
    assert not decode_ntds_sid(raw).endswith(str(wrong_if_le))


def test_sid_builtin_administrators_s_1_5_32_544() -> None:
    """Proves: BUILTIN\\Administrators S-1-5-32-544 decodes correctly (544 BE)."""
    raw = _build_ntds_sid(5, [32, 544])
    assert decode_ntds_sid(raw) == "S-1-5-32-544"
    # Independent confirmation the final sub (544 == 0x220) was stored big-endian.
    assert raw[-4:] == b"\x00\x00\x02\x20"


def test_sid_domain_identifier_has_no_rid() -> None:
    """Proves: a domain SID (4 sub-authorities, no RID) decodes losslessly."""
    raw = _build_ntds_sid(5, [21, 2232410529, 1445159330, 2725690660])
    assert decode_ntds_sid(raw) == "S-1-5-21-2232410529-1445159330-2725690660"


def test_sid_malformed_degrades_to_none_never_raises() -> None:
    """Proves: None/short-header/truncated-subs blobs -> None (counted gap)."""
    assert decode_ntds_sid(None) is None
    assert decode_ntds_sid(b"") is None
    assert decode_ntds_sid(b"\x01\x05\x00") is None  # header < 8 bytes
    # Header claims 5 sub-authorities but only one is present -> too short -> None.
    truncated = bytes([1, 5]) + struct.pack(">Q", 5)[2:] + (21).to_bytes(4, "little")
    assert decode_ntds_sid(truncated) is None


# =============================================================================
# decode_guid — mixed-endian bytes_le form
# =============================================================================


def test_guid_matches_independent_uuid_bytes_le_decode() -> None:
    """Proves: decode_guid == stdlib uuid.UUID(bytes_le=...) for crafted bytes."""
    raw = bytes(range(16))  # 00 01 02 ... 0f
    expected = str(uuid.UUID(bytes_le=raw))
    assert decode_guid(raw) == expected
    # Spot-check the first field really is little-endian (03020100...).
    assert decode_guid(raw) == "03020100-0504-0706-0809-0a0b0c0d0e0f"


def test_guid_second_crafted_vector() -> None:
    """Proves: a second, unrelated 16-byte GUID also matches the stdlib decode."""
    raw = bytes.fromhex("fc7a25c0f00eac4f80627471f65ede91")
    assert decode_guid(raw) == str(uuid.UUID(bytes_le=raw))
    assert decode_guid(raw) == "c0257afc-0ef0-4fac-8062-7471f65ede91"


def test_guid_wrong_length_or_none_returns_none() -> None:
    """Proves: a non-16-byte or None blob -> None, never raises."""
    assert decode_guid(None) is None
    assert decode_guid(b"\x00" * 15) is None
    assert decode_guid(b"\x00" * 17) is None
    assert decode_guid(b"") is None


# =============================================================================
# decode_ntds_timestamp — integer seconds since 1601-01-01 UTC
# =============================================================================


def test_timestamp_decodes_known_utc_instant_derived_independently() -> None:
    """Proves: seconds-since-1601 -> the correct UTC datetime.

    The expected seconds count is computed independently from the stdlib epoch
    delta, not taken from the implementation, then fed back through the decoder.
    """
    target = datetime(2020, 9, 18, 0, 24, 4, tzinfo=UTC)
    seconds = int((target - _EPOCH_1601).total_seconds())
    assert seconds == 13244862244  # independent cross-check of the Admin whenChanged
    assert decode_ntds_timestamp(seconds) == target


def test_timestamp_epoch_boundary() -> None:
    """Proves: a 1-second offset decodes to 1601-01-01T00:00:01Z."""
    assert decode_ntds_timestamp(1) == datetime(1601, 1, 1, 0, 0, 1, tzinfo=UTC)
    assert decode_ntds_timestamp(1) == _EPOCH_1601 + timedelta(seconds=1)


def test_timestamp_unset_and_invalid_return_none() -> None:
    """Proves: 0/None/negative -> None (unset sentinel), never raises."""
    assert decode_ntds_timestamp(0) is None
    assert decode_ntds_timestamp(None) is None
    assert decode_ntds_timestamp(-1) is None


def test_timestamp_overflow_degrades_to_none() -> None:
    """Proves: a value too large for the calendar degrades to None, not a crash."""
    assert decode_ntds_timestamp(10**30) is None


# =============================================================================
# as_scalar / as_list — tagged-column normalisation
# =============================================================================


def test_as_scalar_normalisation() -> None:
    """Proves: list-wrapped single values collapse; scalars pass through."""
    assert as_scalar([42]) == 42
    assert as_scalar([]) is None
    assert as_scalar(None) is None
    assert as_scalar("x") == "x"
    assert as_scalar([1, 2, 3]) == 1  # first element of a multi-valued list


def test_as_list_normalisation() -> None:
    """Proves: scalars wrap to one-element lists; None -> []; lists copy."""
    assert as_list(None) == []
    assert as_list(5) == [5]
    src = [1, 2]
    out = as_list(src)
    assert out == [1, 2]
    assert out is not src  # returns a copy, not the same object


# =============================================================================
# _parse_internal_id_from_column — the ATT<type><id> id extractor
# =============================================================================


@pytest.mark.parametrize(
    ("column", "expected"),
    [
        ("ATTm590045", 590045),
        ("ATTr589970", 589970),
        ("ATTp131353", 131353),
        ("ATTc131102", 131102),
        ("DNT_col", None),
        ("PDNT_col", None),
        ("ATT", None),
        ("ATTm", None),
        ("ATTmabcde", None),
    ],
)
def test_parse_internal_id_from_column(column: str, expected: int | None) -> None:
    """Proves: the trailing internal id is parsed; non-ATT/malformed -> None."""
    assert _parse_internal_id_from_column(column) == expected
