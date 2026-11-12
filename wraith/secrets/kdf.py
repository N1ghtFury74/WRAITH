"""Key-derivation functions for the secret-store KEK (research Item 1).

The KEK (key-encryption key) is derived from the operator passphrase with a
memory-hard KDF: argon2id (primary) or scrypt (zero-extra-dependency fallback).
Both derive a 256-bit key suitable for AES-256-GCM key wrapping. The passphrase
is handled only as transient bytes here and never persisted.
"""

from __future__ import annotations

from enum import StrEnum

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, ConfigDict, Field

#: Derived key length in bytes (AES-256).
KEK_LENGTH: int = 32

#: Default argon2id cost parameters (interactive-but-strong on a forensic box).
DEFAULT_ARGON2_TIME_COST: int = 3
DEFAULT_ARGON2_MEMORY_COST_KIB: int = 64 * 1024  # 64 MiB
DEFAULT_ARGON2_PARALLELISM: int = 4

#: Default scrypt cost parameters.
DEFAULT_SCRYPT_N: int = 2**15
DEFAULT_SCRYPT_R: int = 8
DEFAULT_SCRYPT_P: int = 1

#: Required cost-parameter keys per algorithm (validated before use).
_REQUIRED_PARAMS: dict[str, tuple[str, ...]] = {
    "argon2id": ("time_cost", "memory_cost", "parallelism"),
    "scrypt": ("n", "r", "p"),
}


class KdfAlgorithm(StrEnum):
    """Selectable KDF for the KEK."""

    ARGON2ID = "argon2id"
    SCRYPT = "scrypt"


class KdfParams(BaseModel):
    """Serializable KDF configuration stored in the keyring.

    Fields:
        algorithm: which KDF produced the KEK.
        salt_hex: the per-case random salt (16 bytes) as lowercase hex.
        params: algorithm-specific cost parameters (argon2id:
            ``time_cost``/``memory_cost``/``parallelism``; scrypt: ``n``/``r``/``p``).

    Failure modes:
        Raises ``pydantic.ValidationError`` for a malformed salt or params map.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: KdfAlgorithm
    salt_hex: str
    params: dict[str, int] = Field(default_factory=dict)


def default_params(algorithm: KdfAlgorithm, salt: bytes) -> KdfParams:
    """Build the default ``KdfParams`` for ``algorithm`` with the given salt.

    Inputs:
        algorithm: argon2id or scrypt.
        salt: a random salt (16 bytes recommended).

    Returns:
        A populated ``KdfParams``.

    Failure modes:
        Raises ``ValueError`` for an unknown algorithm.
    """
    if algorithm is KdfAlgorithm.ARGON2ID:
        params = {
            "time_cost": DEFAULT_ARGON2_TIME_COST,
            "memory_cost": DEFAULT_ARGON2_MEMORY_COST_KIB,
            "parallelism": DEFAULT_ARGON2_PARALLELISM,
        }
    elif algorithm is KdfAlgorithm.SCRYPT:
        params = {"n": DEFAULT_SCRYPT_N, "r": DEFAULT_SCRYPT_R, "p": DEFAULT_SCRYPT_P}
    else:  # pragma: no cover - exhaustive enum
        raise ValueError(f"unknown KDF algorithm: {algorithm!r}")
    return KdfParams(algorithm=algorithm, salt_hex=salt.hex(), params=params)


def derive_kek(passphrase: bytes, kdf: KdfParams) -> bytes:
    """Derive the 32-byte KEK from the operator passphrase.

    Inputs:
        passphrase: the operator passphrase as UTF-8 bytes (transient; the
            caller must not persist it).
        kdf: the KDF configuration (algorithm, salt, cost params).

    Returns:
        A 32-byte key-encryption key.

    Failure modes:
        Raises ``ValueError`` for an unknown algorithm or missing cost params;
        propagates ``argon2`` / ``cryptography`` errors for invalid params.
    """
    _require_params(kdf)
    salt = bytes.fromhex(kdf.salt_hex)
    if kdf.algorithm is KdfAlgorithm.ARGON2ID:
        return hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=kdf.params["time_cost"],
            memory_cost=kdf.params["memory_cost"],
            parallelism=kdf.params["parallelism"],
            hash_len=KEK_LENGTH,
            type=Type.ID,
        )
    if kdf.algorithm is KdfAlgorithm.SCRYPT:
        scrypt = Scrypt(
            salt=salt,
            length=KEK_LENGTH,
            n=kdf.params["n"],
            r=kdf.params["r"],
            p=kdf.params["p"],
        )
        return scrypt.derive(passphrase)
    raise ValueError(f"unknown KDF algorithm: {kdf.algorithm!r}")  # pragma: no cover


def _require_params(kdf: KdfParams) -> None:
    """Validate that ``kdf.params`` has every cost key the algorithm needs.

    Raises ``ValueError`` listing any missing keys, so a malformed keyring fails
    with a clear, typed error rather than a bare ``KeyError`` deep in the KDF.
    """
    required = _REQUIRED_PARAMS.get(kdf.algorithm.value)
    if required is None:  # pragma: no cover - exhaustive enum
        raise ValueError(f"unknown KDF algorithm: {kdf.algorithm!r}")
    missing = [key for key in required if key not in kdf.params]
    if missing:
        raise ValueError(f"missing {kdf.algorithm.value} cost params: {', '.join(sorted(missing))}")
