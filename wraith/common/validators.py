"""Shared pydantic field-validators reused across data models.

Centralizing these keeps one definition of "well-formed" for values that appear
on several models — notably the SHA-256 artifact hash that every provenance fact
carries (schema §2.3/§2.4 + the manifest). One validator, applied everywhere,
means a malformed hash is rejected at the point of creation on every model.
"""

from __future__ import annotations

import re

#: A lowercase, 64-character hex SHA-256 digest (the canonical artifact hash).
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def validate_sha256_hex(value: str, *, field: str = "image_sha256") -> str:
    """Validate that ``value`` is a lowercase 64-char hex SHA-256 string.

    Inputs:
        value: the candidate digest string.
        field: the field name, used only to make the error message precise.

    Returns:
        ``value`` unchanged when it is well-formed.

    Failure modes:
        Raises ``ValueError`` if ``value`` is not exactly 64 lowercase hex
        characters (pydantic surfaces this as a ``ValidationError``).
    """
    if not _SHA256_HEX.match(value):
        raise ValueError(f"{field} must be a lowercase 64-char hex SHA-256")
    return value
