"""Foundation gate — Layer 1 (unit/golden): determinism + integrity primitives.

Hand-computed expected outputs for the canonical serialization, the hash
helpers, the shared validator, and the streaming hashers. These are the bedrock
of schema principle 6 (identical inputs -> identical ids/rows), so every
assertion here is an exact, pre-computed constant rather than a self-referential
round-trip.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from wraith.acquisition.hashing import sha256_bytes, sha256_file, sha256_stream
from wraith.common.determinism import canonical_json, sha256_hex, stable_id
from wraith.common.validators import validate_sha256_hex

# Known SHA-256 vectors (FIPS 180-4 / RFC examples).
_SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --------------------------- canonical_json --------------------------------


def test_canonical_json_sorts_keys_and_strips_whitespace() -> None:
    """Keys sorted, no insignificant whitespace (exact byte expectation)."""
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_nested_keys_sorted_lists_preserved() -> None:
    """Nested dict keys sort; list element order is preserved verbatim."""
    obj = {"z": [3, 2, 1], "a": {"y": 1, "x": 2}}
    assert canonical_json(obj) == '{"a":{"x":2,"y":1},"z":[3,2,1]}'


def test_canonical_json_is_not_ascii_escaped() -> None:
    """ensure_ascii=False: non-ASCII content is emitted literally (byte-stable)."""
    assert canonical_json({"k": "café ☃"}) == '{"k":"café ☃"}'


def test_canonical_json_byte_stable_across_calls() -> None:
    """Same input twice -> identical bytes (determinism guarantee)."""
    obj = {"forest": "F1", "n": 3, "flags": ["b", "a"]}
    assert canonical_json(obj) == canonical_json(dict(reversed(list(obj.items()))))


def test_canonical_json_raises_on_nonserializable() -> None:
    with pytest.raises(TypeError):
        canonical_json({"k": b"bytes-are-not-json"})


# --------------------------- sha256 helpers --------------------------------


def test_sha256_hex_known_vectors() -> None:
    assert sha256_hex(b"") == _SHA256_EMPTY
    assert sha256_hex(b"abc") == _SHA256_ABC


def test_sha256_bytes_matches_sha256_hex() -> None:
    assert sha256_bytes(b"abc") == sha256_hex(b"abc") == _SHA256_ABC


def test_sha256_hex_is_lowercase_64() -> None:
    digest = sha256_hex(b"anything")
    assert len(digest) == 64
    assert digest == digest.lower()


# --------------------------- stable_id -------------------------------------


def test_stable_id_deterministic() -> None:
    assert stable_id("a", "b", "c") == stable_id("a", "b", "c")


def test_stable_id_order_sensitive() -> None:
    assert stable_id("a", "b") != stable_id("b", "a")


def test_stable_id_separator_prevents_concatenation_collision() -> None:
    """('a','b') must not collide with ('ab',) — the unit-separator guarantees it."""
    assert stable_id("a", "b") != stable_id("ab")
    assert stable_id("a", "b") != stable_id("ab", "")


def test_stable_id_matches_manual_sha256_of_unit_separated_parts() -> None:
    """Golden: stable_id is sha256 of parts joined by \\x1f, UTF-8 encoded."""
    expected = hashlib.sha256(b"x\x1fy").hexdigest()
    assert stable_id("x", "y") == expected


def test_stable_id_rejects_non_str() -> None:
    with pytest.raises(TypeError):
        stable_id("ok", 5)  # type: ignore[arg-type]


# --------------------------- validate_sha256_hex ---------------------------


def test_validate_sha256_hex_accepts_lowercase_64() -> None:
    good = "0123456789abcdef" * 4
    assert validate_sha256_hex(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "A" * 64,  # uppercase rejected
        "a" * 63,  # too short
        "a" * 65,  # too long
        "g" * 64,  # non-hex
        "",  # empty
        "0123456789ABCDEF" * 4,  # mixed/upper
    ],
)
def test_validate_sha256_hex_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_sha256_hex(bad)


# --------------------------- streaming hashers -----------------------------


def test_sha256_file_stream_bytes_agree_small(tmp_path: Path) -> None:
    content = b"the quick brown fox"
    p = tmp_path / "small.bin"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected
    assert sha256_stream(p) == expected
    assert sha256_bytes(content) == expected


def test_sha256_bounded_memory_multichunk(tmp_path: Path) -> None:
    """A >1 MiB file forces multiple read iterations; all three agree.

    This exercises the bounded-memory chunked path without loading GBs. True
    multi-GB performance is deferred (no large artifact offline).
    """
    content = os.urandom(3 * 1024 * 1024 + 123)
    p = tmp_path / "big.bin"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected
    assert sha256_stream(p) == expected
    assert sha256_stream(p, chunk_size=1) == expected  # degenerate tiny chunk still correct


def test_sha256_stream_rejects_nonpositive_chunk(tmp_path: Path) -> None:
    p = tmp_path / "f.bin"
    p.write_bytes(b"x")
    with pytest.raises(ValueError):
        sha256_stream(p, chunk_size=0)


def test_sha256_file_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sha256_file(tmp_path / "nope.bin")
