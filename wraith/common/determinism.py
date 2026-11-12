"""Deterministic serialization and hash-derived identifiers.

WRAITH's determinism guarantee (CLAUDE.md; schema principle 6) applies to
analytical outputs: identical inputs must produce byte-identical canonical rows
and identical hash-derived ids. This module centralizes the one canonical
serialization used everywhere ids or stable bytes are produced, so no two call
sites can diverge.

Note: secret-store ciphertext, run UUIDs and wall-clock timings legitimately
vary and must NOT be fed through these helpers as if they were canonical.
"""

from __future__ import annotations

import hashlib
import json

#: Field separator used when composing hash-input tuples. Chosen as an ASCII
#: unit-separator so it cannot collide with realistic SID/GUID/DN content.
_FIELD_SEP: str = "\x1f"


def canonical_json(obj: object) -> str:
    """Serialize ``obj`` to WRAITH's single canonical JSON form.

    Inputs:
        obj: any JSON-serializable value (dict/list/str/int/float/bool/None).

    Returns:
        A ``str`` with sorted keys, no ASCII-escaping, no insignificant
        whitespace, and LF-only newlines — byte-stable across runs and hosts.

    Failure modes:
        Raises ``TypeError`` if ``obj`` contains a non-JSON-serializable value
        (callers must convert ``bytes``/``datetime``/``UUID`` first).
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``.

    Inputs:
        data: the bytes to hash.

    Returns:
        A 64-character lowercase hex string.

    Failure modes:
        Raises ``TypeError`` if ``data`` is not ``bytes``-like.
    """
    return hashlib.sha256(data).hexdigest()


def stable_id(*parts: str) -> str:
    """Compute a deterministic id from ordered string ``parts``.

    The parts are joined with a fixed unit-separator and UTF-8 encoded before
    hashing, so identical inputs always yield the identical id (schema
    principle 6; used for ``node_id``/``edge_id``/``secret_id`` derivations).

    Inputs:
        *parts: the ordered, already-normalized string components.

    Returns:
        A 64-character lowercase hex SHA-256 string.

    Failure modes:
        Raises ``TypeError`` if any part is not a ``str``.
    """
    for part in parts:
        if not isinstance(part, str):  # defensive: ids must be built from text
            raise TypeError(f"stable_id parts must be str, got {type(part).__name__}")
    return sha256_hex(_FIELD_SEP.join(parts).encode("utf-8"))
