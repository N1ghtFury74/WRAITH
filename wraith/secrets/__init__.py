"""Encrypted-secret-at-rest store (NFR-05; research Item 1).

Design (owner-locked):
  * Record cipher: AES-256-GCM AEAD, fresh 96-bit nonce per record, with AAD
    binding each ciphertext to ``case_id || secret_id || secret_type || node_id``.
  * Envelope keys: one per-case random 256-bit DEK, wrapped by a KEK derived
    from the operator passphrase via argon2id (default) or scrypt (fallback).
  * Key recovery: PASSPHRASE-ONLY, NO ESCROW. A lost passphrase is
    unrecoverable by design. The keyring stores a *list* of wrap-entries so a
    second unwrap path could be added later; v1 implements exactly one.
  * Redaction: every in-memory secret is a pydantic ``SecretStr``/``SecretBytes``;
    canonical tables hold only ``secret_refs`` (→ secret_id). ``reveal`` is the
    only path to plaintext.

NOTE: this package is ``wraith.secrets`` and never shadows the stdlib
``secrets`` module (absolute imports). It deliberately uses ``os.urandom`` for
all key/nonce material.
"""

from __future__ import annotations

from wraith.secrets.kdf import KdfAlgorithm, KdfParams, derive_kek
from wraith.secrets.keyring import (
    Keyring,
    KeyUnwrapError,
    WrapEntry,
    create_keyring,
    load_keyring,
    unwrap_dek,
    write_keyring,
)
from wraith.secrets.records import (
    SecretDecryptError,
    SecretRecord,
    SecretType,
    compute_secret_id,
    decrypt_secret,
    encrypt_secret,
)
from wraith.secrets.redaction import SecretRedactionFilter, install_secret_log_filter
from wraith.secrets.store import SecretAlreadyStoredError, SecretStore

__all__ = [
    "KdfAlgorithm",
    "KdfParams",
    "derive_kek",
    "Keyring",
    "WrapEntry",
    "KeyUnwrapError",
    "create_keyring",
    "load_keyring",
    "write_keyring",
    "unwrap_dek",
    "SecretType",
    "SecretRecord",
    "SecretDecryptError",
    "compute_secret_id",
    "encrypt_secret",
    "decrypt_secret",
    "SecretStore",
    "SecretAlreadyStoredError",
    "SecretRedactionFilter",
    "install_secret_log_filter",
]
