"""AES-256-GCM record crypto and the secret-record data shape (research Item 1).

Each secret is encrypted under the per-case DEK with a fresh 96-bit nonce and
AAD binding the ciphertext to ``case_id || secret_id || secret_type || node_id``
so a swapped or copied record fails authentication. Plaintext is only ever held
as ``SecretBytes`` and exists transiently during encrypt/decrypt.
"""

from __future__ import annotations

import os
from enum import StrEnum
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, SecretBytes, field_validator

from wraith.common.determinism import stable_id
from wraith.common.validators import validate_sha256_hex

#: AES-GCM nonce length in bytes (96 bits — the AES-GCM standard nonce size).
NONCE_LENGTH: int = 12

#: Algorithm tag persisted per record so the store is self-describing and a
#: future cipher upgrade (e.g. AES-GCM-SIV) can coexist with old records.
ALG_AES_256_GCM: str = "AES-256-GCM"

#: Field separator inside the AAD; an ASCII unit-separator that cannot appear
#: in SIDs/GUIDs/type names.
_AAD_SEP: str = "\x1f"


class SecretType(StrEnum):
    """Kinds of recovered secret WRAITH may store (reference-only in canonical
    tables). The set is intentionally open-ended via ``OTHER``."""

    NT_HASH = "nt_hash"
    LM_HASH = "lm_hash"
    NT_HASH_HISTORY = "nt_hash_history"
    KERBEROS_KEY = "kerberos_key"
    TRUST_KEY = "trust_key"
    LAPS_PASSWORD = "laps_password"  # noqa: S105 (enum label, not a secret value)
    GMSA_PASSWORD = "gmsa_password"  # noqa: S105 (enum label, not a secret value)
    DPAPI_BACKUP_KEY = "dpapi_backup_key"
    CLEARTEXT = "cleartext"
    OTHER = "other"


class SecretDecryptError(Exception):
    """Raised when a stored record fails AEAD authentication/decryption.

    Causes: wrong DEK (wrong passphrase), a tampered/substituted record, or a
    mismatched AAD context. Never indicates a correct-but-different plaintext —
    AEAD guarantees integrity, so this is always surfaced as a counted gap.
    """


class SecretRecord(BaseModel):
    """A single encrypted secret as stored (ciphertext only — no plaintext).

    Fields:
        secret_id: run-scoped deterministic reference used by ``secret_refs``
            elsewhere (Module 2's ``Principal.secret_refs`` carries this id).
        case_id: owning case (part of the AAD).
        secret_type: the ``SecretType`` (part of the AAD).
        node_id: the owning principal/trust node id, or ``""`` when not
            node-scoped (part of the AAD).
        ingest_run_id: the producing ingest run (part of the id + AAD). The
            store is append-only and run-scoped, so each snapshot/run keeps its
            own credential evidence rather than overwriting an earlier run.
        producing_image_sha256: optional SHA-256 of the artifact the secret was
            recovered from; bound into the id + AAD when provided.
        nonce: the 96-bit AES-GCM nonce for this record.
        ciphertext: AES-256-GCM ciphertext + tag.
        alg: algorithm tag (``AES-256-GCM``).

    Failure modes:
        Raises ``pydantic.ValidationError`` if the nonce is not exactly 12
        bytes, the ciphertext is empty, or ``producing_image_sha256`` is a
        malformed (non-64-lowercase-hex) digest.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    secret_id: str
    case_id: str
    secret_type: SecretType
    node_id: str = ""
    ingest_run_id: UUID
    producing_image_sha256: str | None = None
    nonce: bytes
    ciphertext: bytes
    alg: str = ALG_AES_256_GCM

    @field_validator("nonce")
    @classmethod
    def _nonce_len(cls, value: bytes) -> bytes:
        if len(value) != NONCE_LENGTH:
            raise ValueError(f"nonce must be exactly {NONCE_LENGTH} bytes (96-bit AES-GCM nonce)")
        return value

    @field_validator("ciphertext")
    @classmethod
    def _ciphertext_nonempty(cls, value: bytes) -> bytes:
        if not value:
            raise ValueError("ciphertext must be non-empty (AES-GCM emits at least a 16-byte tag)")
        return value

    @field_validator("producing_image_sha256")
    @classmethod
    def _image_sha256_wellformed(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256_hex(value, field="producing_image_sha256")


def compute_secret_id(
    case_id: str,
    secret_type: SecretType,
    node_id: str,
    *,
    ingest_run_id: UUID,
    label: str = "",
    image_sha256: str | None = None,
) -> str:
    """Compute a deterministic, run-scoped ``secret_id`` for a logical secret.

    The id is deterministic *given its inputs* — identical inputs always map to
    the identical id across runs even though the ciphertext varies (the
    ciphertext's non-determinism is allowed; the reference is not — research
    Item 6). The id is run-scoped by folding in ``ingest_run_id`` (and the
    producing ``image_sha256`` when supplied): a second ingest of a differently
    recovered secret gets a distinct id, so the append-only store never loses an
    earlier run's credential evidence.

    Inputs:
        case_id: owning case.
        secret_type: the kind of secret.
        node_id: owning node id, or ``""`` if not node-scoped.
        ingest_run_id: the producing ingest run id (scopes the secret).
        label: optional discriminator for multiple secrets of one type on one
            node (e.g. a history index ``"1"``).
        image_sha256: optional SHA-256 of the producing artifact.

    Returns:
        A 64-char hex id.
    """
    return stable_id(
        case_id,
        str(ingest_run_id),
        secret_type.value,
        node_id,
        label,
        image_sha256 or "",
    )


def _build_aad(
    case_id: str,
    secret_id: str,
    secret_type: SecretType,
    node_id: str,
    ingest_run_id: UUID,
    image_sha256: str | None,
) -> bytes:
    """Build the AEAD additional-authenticated-data binding the record context.

    Binds ``case_id || secret_id || secret_type || node_id || ingest_run_id ||
    image_sha256`` so a record copied/swapped across case, node, or ingest run
    fails authentication.
    """
    return _AAD_SEP.join(
        (
            case_id,
            secret_id,
            secret_type.value,
            node_id,
            str(ingest_run_id),
            image_sha256 or "",
        )
    ).encode("utf-8")


def encrypt_secret(
    dek: bytes,
    *,
    case_id: str,
    secret_id: str,
    secret_type: SecretType,
    node_id: str,
    ingest_run_id: UUID,
    plaintext: SecretBytes,
    image_sha256: str | None = None,
) -> SecretRecord:
    """Encrypt one secret under the case DEK into a ``SecretRecord``.

    Inputs:
        dek: the 32-byte per-case data key.
        case_id/secret_id/secret_type/node_id: the context bound into the AAD.
        ingest_run_id: the producing run (bound into the AAD; run-scopes the
            record).
        plaintext: the secret bytes, carried as ``SecretBytes`` so it cannot be
            logged by accident.
        image_sha256: optional producing-artifact digest (bound into the AAD).

    Returns:
        A ``SecretRecord`` containing only ciphertext + nonce + context.

    Failure modes:
        Raises ``ValueError`` if ``dek`` is not 32 bytes (AES-256 key size).
    """
    if len(dek) != 32:
        raise ValueError("DEK must be 32 bytes for AES-256-GCM")
    nonce = os.urandom(NONCE_LENGTH)
    aad = _build_aad(case_id, secret_id, secret_type, node_id, ingest_run_id, image_sha256)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.get_secret_value(), aad)
    return SecretRecord(
        secret_id=secret_id,
        case_id=case_id,
        secret_type=secret_type,
        node_id=node_id,
        ingest_run_id=ingest_run_id,
        producing_image_sha256=image_sha256,
        nonce=nonce,
        ciphertext=ciphertext,
        alg=ALG_AES_256_GCM,
    )


def decrypt_secret(dek: bytes, record: SecretRecord) -> SecretBytes:
    """Decrypt a ``SecretRecord`` back to plaintext ``SecretBytes``.

    Inputs:
        dek: the 32-byte per-case data key.
        record: the stored record (ciphertext + context).

    Returns:
        The plaintext wrapped in ``SecretBytes``.

    Failure modes:
        Raises ``SecretDecryptError`` on any authentication failure (wrong DEK,
        tamper, AAD mismatch); ``ValueError`` for an unsupported ``alg``.
    """
    if record.alg != ALG_AES_256_GCM:
        raise ValueError(f"unsupported secret cipher: {record.alg!r}")
    aad = _build_aad(
        record.case_id,
        record.secret_id,
        record.secret_type,
        record.node_id,
        record.ingest_run_id,
        record.producing_image_sha256,
    )
    try:
        plaintext = AESGCM(dek).decrypt(record.nonce, record.ciphertext, aad)
    except InvalidTag as exc:
        raise SecretDecryptError(
            f"secret {record.secret_id} failed authentication (wrong passphrase "
            "or tampered record)"
        ) from exc
    return SecretBytes(plaintext)
