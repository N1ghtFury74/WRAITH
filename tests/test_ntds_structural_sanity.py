"""Minimal sanity checks for Module 2a structural decoders (pure functions).

Scope: just the pure, fixture-free decoders. The full three-layer gate
(golden/parity/property against the real ``ntds.dit``) is owned by
``wraith-tester`` — this file only guards the structural value decoders so an
obvious regression is caught immediately.
"""

from __future__ import annotations

from datetime import UTC, datetime

from wraith.parsing.ntds_values import (
    as_list,
    as_scalar,
    decode_guid,
    decode_ntds_sid,
    decode_ntds_timestamp,
)
from wraith.parsing.schema import _parse_internal_id_from_column


def test_decode_ntds_sid_principal_rid_is_big_endian() -> None:
    # Administrator objectSid from the GOAD ntds.dit (RID 500, stored big-endian).
    raw = bytes.fromhex("010500000000000515000000a1e10f85a261235624bd76a2000001f4")
    assert decode_ntds_sid(raw) == "S-1-5-21-2232410529-1445159330-2725690660-500"


def test_decode_ntds_sid_domain_and_builtin() -> None:
    domain = bytes.fromhex("010400000000000515000000a1e10f85a2612356a276bd24")
    assert decode_ntds_sid(domain) == "S-1-5-21-2232410529-1445159330-2725690660"
    builtin_admins = bytes.fromhex("01020000000000052000000000000220")
    assert decode_ntds_sid(builtin_admins) == "S-1-5-32-544"


def test_decode_ntds_sid_malformed_returns_none() -> None:
    assert decode_ntds_sid(None) is None
    assert decode_ntds_sid(b"\x01\x05") is None  # truncated header
    assert decode_ntds_sid(bytes.fromhex("010500000000000515000000")) is None  # too short


def test_decode_guid_roundtrip_form() -> None:
    raw = bytes.fromhex("fc7a25c0f00eac4f80627471f65ede91")
    assert decode_guid(raw) == "c0257afc-0ef0-4fac-8062-7471f65ede91"
    assert decode_guid(None) is None
    assert decode_guid(b"\x00" * 15) is None


def test_decode_ntds_timestamp_seconds_since_1601() -> None:
    assert decode_ntds_timestamp(13244862244) == datetime(2020, 9, 18, 0, 24, 4, tzinfo=UTC)
    assert decode_ntds_timestamp(0) is None
    assert decode_ntds_timestamp(None) is None
    assert decode_ntds_timestamp(-1) is None


def test_scalar_list_helpers() -> None:
    assert as_scalar([42]) == 42
    assert as_scalar([]) is None
    assert as_scalar(7) == 7
    assert as_scalar(None) is None
    assert as_list(None) == []
    assert as_list(5) == [5]
    assert as_list([1, 2]) == [1, 2]


def test_parse_internal_id_from_column() -> None:
    assert _parse_internal_id_from_column("ATTm590045") == 590045
    assert _parse_internal_id_from_column("ATTp131353") == 131353
    assert _parse_internal_id_from_column("DNT_col") is None
    assert _parse_internal_id_from_column("ATT") is None
