"""Envelope key management: per-case DEK wrapped by a passphrase-derived KEK.

The keyring (``secrets/keyring.json``) holds the wrapped DEK plus everything
needed to unwrap it given the operator passphrase: the KDF algorithm/params/salt
and the wrap nonce. Key recovery is PASSPHRASE-ONLY (no escrow): a lost
passphrase is unrecoverable by design. The keyring stores a *list* of
wrap-entries so a second unwrap path could be added later without a format
change; v1 writes exactly one passphrase entry.

The wrapped-DEK blob is intentionally non-deterministic (random DEK, salt,
nonce) — this is outside WRAITH's determinism guarantee (research Item 6).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

from wraith.common.determinism import canonical_json
from wraith.secrets.kdf import KdfAlgorithm, KdfParams, default_params, derive_kek
from wraith.secrets.records import NONCE_LENGTH

#: Keyring format version tag.
KEYRING_VERSION: int = 1

#: DEK size in bytes (AES-256).
DEK_LENGTH: int = 32

#: KDF salt size in bytes.
SALT_LENGTH: int = 16

#: Wrap-entry type for the single passphrase path implemented in v1.
ENTRY_TYPE_PASSPHRASE: str = "passphrase"  # noqa: S105 (entry-type label, not a secret)


class KeyUnwrapError(Exception):
    """Raised when no wrap-entry can unwrap the DEK with the given passphrase.

    Means the passphrase is wrong or the keyring was tampered with. Because
    recovery is passphrase-only with no escrow, this is terminal for the case's
    secrets by design.
    """


class WrapEntry(BaseModel):
    """One way to unwrap the case DEK (v1: a single passphrase entry).

    Fields:
        entry_type: currently always ``"passphrase"``.
        kdf: the KDF configuration used to derive this entry's KEK.
        wrap_nonce_hex: the AES-GCM nonce used to wrap the DEK.
        wrapped_dek_hex: the AES-256-GCM-wrapped DEK (ciphertext + tag).

    Note:
        Hex well-formedness is not enforced at construction; a tampered/malformed
        hex field surfaces as ``KeyUnwrapError`` at :func:`unwrap_dek` time (that
        is the intended, typed tamper signal), never as an uncaught exception.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_type: str
    kdf: KdfParams
    wrap_nonce_hex: str
    wrapped_dek_hex: str


class Keyring(BaseModel):
    """The on-disk keyring: wrapped DEK plus unwrap metadata.

    Fields:
        version: format version tag.
        case_id: the owning case (also the AAD for DEK wrapping).
        wrap_entries: one-or-more unwrap paths; v1 writes exactly one.

    Failure modes:
        Raises ``pydantic.ValidationError`` if required fields are missing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int
    case_id: str
    wrap_entries: list[WrapEntry]


def create_keyring(
    case_id: str,
    passphrase: bytes,
    algorithm: KdfAlgorithm = KdfAlgorithm.ARGON2ID,
) -> tuple[Keyring, bytes]:
    """Generate a fresh case DEK and wrap it under a passphrase-derived KEK.

    Inputs:
        case_id: the owning case id (bound as AAD on the DEK wrap).
        passphrase: operator passphrase as UTF-8 bytes (transient; dropped by
            the caller after this call).
        algorithm: KDF for the KEK (argon2id default, scrypt fallback).

    Returns:
        ``(keyring, dek)`` — the keyring to persist and the raw 32-byte DEK for
        in-memory use during this run.

    Failure modes:
        Propagates KDF errors for invalid cost params.
    """
    dek = os.urandom(DEK_LENGTH)
    salt = os.urandom(SALT_LENGTH)
    kdf = default_params(algorithm, salt)
    kek = derive_kek(passphrase, kdf)
    wrap_nonce = os.urandom(NONCE_LENGTH)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, dek, case_id.encode("utf-8"))
    entry = WrapEntry(
        entry_type=ENTRY_TYPE_PASSPHRASE,
        kdf=kdf,
        wrap_nonce_hex=wrap_nonce.hex(),
        wrapped_dek_hex=wrapped.hex(),
    )
    keyring = Keyring(version=KEYRING_VERSION, case_id=case_id, wrap_entries=[entry])
    return keyring, dek


def unwrap_dek(keyring: Keyring, passphrase: bytes) -> bytes:
    """Recover the case DEK from the keyring using the operator passphrase.

    Tries each wrap-entry in order (v1 has one). The passphrase is used only to
    derive the KEK and is never stored.

    Inputs:
        keyring: the loaded keyring.
        passphrase: operator passphrase as UTF-8 bytes.

    Returns:
        The raw 32-byte DEK.

    Failure modes:
        Raises ``KeyUnwrapError`` if no entry unwraps — this covers a wrong
        passphrase, a bad AEAD tag, AND a tampered keyring with malformed hex or
        salt/cost params (``ValueError`` from ``bytes.fromhex``/the KDF is
        treated as a failed entry, not surfaced as an uncaught exception).
    """
    for entry in keyring.wrap_entries:
        try:
            kek = derive_kek(passphrase, entry.kdf)
            dek = AESGCM(kek).decrypt(
                bytes.fromhex(entry.wrap_nonce_hex),
                bytes.fromhex(entry.wrapped_dek_hex),
                keyring.case_id.encode("utf-8"),
            )
        except (InvalidTag, ValueError):
            continue
        return dek
    raise KeyUnwrapError(
        "could not unwrap DEK: wrong passphrase or tampered keyring "
        "(no escrow — this is terminal by design)"
    )


def write_keyring(path: Path | str, keyring: Keyring) -> None:
    """Persist the keyring to ``keyring.json`` (canonical JSON, LF).

    Inputs:
        path: destination file path (under the case ``secrets/`` dir).
        keyring: the keyring to write.

    Returns:
        None.

    Failure modes:
        Raises ``OSError`` if the file cannot be written.
    """
    text = canonical_json(keyring.model_dump(mode="json"))
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def load_keyring(path: Path | str) -> Keyring:
    """Load and validate a keyring from ``keyring.json``.

    Inputs:
        path: the keyring file path.

    Returns:
        A validated ``Keyring``.

    Failure modes:
        Raises ``FileNotFoundError`` if absent; ``pydantic.ValidationError`` or
        ``json.JSONDecodeError`` if the file is corrupt.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Keyring.model_validate(data)
