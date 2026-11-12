"""M1 revision regression tests (review-finding fixes only).

Scope: the specific behaviours changed in the Module 1 revision pass. The full
three-layer suite remains ``wraith-tester``'s responsibility; these lock the
fixes so they cannot silently regress.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretBytes, SecretStr, ValidationError

from wraith.common.validators import validate_sha256_hex
from wraith.secrets.kdf import KdfAlgorithm
from wraith.secrets.keyring import KeyUnwrapError, create_keyring, unwrap_dek
from wraith.secrets.records import NONCE_LENGTH, SecretRecord, SecretType, compute_secret_id
from wraith.secrets.redaction import REDACTED, SecretRedactionFilter, install_secret_log_filter
from wraith.secrets.store import SecretAlreadyStoredError, SecretStore

_DEK = b"\x01" * 32


def _capture_handler() -> tuple[io.StringIO, logging.Handler]:
    """A root-attachable handler capturing ``name|message`` into a buffer."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(name)s|%(message)s"))
    return stream, handler


# ----------------------------- Finding 1: redaction -------------------------


def test_child_logger_secret_hex_redacted_at_handler() -> None:
    """An NT/LM-shaped hex value logged via a wraith.secrets CHILD logger is
    redacted at the root HANDLER (filter-on-handler, not filter-on-logger)."""
    stream, handler = _capture_handler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()  # attaches to root's handlers, incl. ours
        logging.getLogger("wraith.secrets.store").warning("leaked %s", "a" * 32)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "a" * 32 not in out
    assert REDACTED in out


def test_audit_sha256_not_redacted() -> None:
    """A 64-hex image_sha256 in a secrets-logger audit line is NOT redacted
    (the hex backstop matches EXACTLY 32 hex, never a 64-hex forensic id)."""
    stream, handler = _capture_handler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()
        logging.getLogger("wraith.secrets.store").warning("image_sha256=%s", "a" * 64)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "a" * 64 in out


def test_hex_backstop_scoped_to_secrets_logger() -> None:
    """A 32-hex token on a NON-secrets logger is left intact (scoped backstop)."""
    stream, handler = _capture_handler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()
        logging.getLogger("wraith.model.store").warning("node %s", "b" * 32)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "b" * 32 in out


def test_filter_redacts_secret_typed_extra_on_any_logger() -> None:
    """SecretStr/SecretBytes in an ``extra=`` field is type-redacted regardless
    of the logger (defence in depth for structured fields)."""
    flt = SecretRedactionFilter()
    record = logging.LogRecord("wraith.cli", logging.INFO, __file__, 1, "op", (), None)
    record.leaked = SecretBytes(b"supersecret")  # type: ignore[attr-defined]
    flt.filter(record)
    assert record.leaked == REDACTED  # type: ignore[attr-defined]


def test_filter_redacts_secretstr_msg() -> None:
    flt = SecretRedactionFilter()
    record = logging.LogRecord("wraith.cli", logging.INFO, __file__, 1, SecretStr("x"), (), None)
    flt.filter(record)
    assert record.msg == REDACTED


# --------------------- Finding 2: SecretRecord validators -------------------


def test_secret_record_rejects_bad_nonce() -> None:
    with pytest.raises(ValidationError):
        SecretRecord(
            secret_id="s",
            case_id="c",
            secret_type=SecretType.NT_HASH,
            ingest_run_id=uuid4(),
            nonce=b"short",
            ciphertext=b"x" * 16,
        )


def test_secret_record_rejects_empty_ciphertext() -> None:
    with pytest.raises(ValidationError):
        SecretRecord(
            secret_id="s",
            case_id="c",
            secret_type=SecretType.NT_HASH,
            ingest_run_id=uuid4(),
            nonce=b"\x00" * NONCE_LENGTH,
            ciphertext=b"",
        )


# ----------------------- Finding 3: shared sha256 validator -----------------


def test_validate_sha256_hex() -> None:
    good = "a" * 64
    assert validate_sha256_hex(good) == good
    for bad in ["A" * 64, "a" * 63, "a" * 65, "g" * 64, ""]:
        with pytest.raises(ValueError):
            validate_sha256_hex(bad)


# ------------- Finding 4: append-only, run-scoped secret store --------------


def test_secret_store_run_scoped_and_append_only(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path / "store.duckdb", "case1")
    try:
        run_a, run_b = uuid4(), uuid4()
        sid_a = store.put_secret(
            _DEK,
            ingest_run_id=run_a,
            secret_type=SecretType.NT_HASH,
            node_id="n1",
            plaintext=SecretBytes(b"hash-a"),
        )
        sid_b = store.put_secret(
            _DEK,
            ingest_run_id=run_b,
            secret_type=SecretType.NT_HASH,
            node_id="n1",
            plaintext=SecretBytes(b"hash-b"),
        )
        # Different runs → different run-scoped ids → both retained (append-only).
        assert sid_a != sid_b
        assert store.count() == 2
        # Re-putting the exact same (run-scoped) secret_id is surfaced, not overwritten.
        with pytest.raises(SecretAlreadyStoredError):
            store.put_secret(
                _DEK,
                ingest_run_id=run_a,
                secret_type=SecretType.NT_HASH,
                node_id="n1",
                plaintext=SecretBytes(b"hash-a"),
            )
        # Each run's evidence round-trips to its own plaintext.
        assert store.reveal(sid_a, _DEK).get_secret_value() == b"hash-a"
        assert store.reveal(sid_b, _DEK).get_secret_value() == b"hash-b"
    finally:
        store.close()


def test_compute_secret_id_folds_run_and_image() -> None:
    run = uuid4()
    base = compute_secret_id("c", SecretType.NT_HASH, "n1", ingest_run_id=run)
    with_image = compute_secret_id(
        "c", SecretType.NT_HASH, "n1", ingest_run_id=run, image_sha256="a" * 64
    )
    other_run = compute_secret_id("c", SecretType.NT_HASH, "n1", ingest_run_id=uuid4())
    assert base != with_image
    assert base != other_run
    # Deterministic given identical inputs.
    assert base == compute_secret_id("c", SecretType.NT_HASH, "n1", ingest_run_id=run)


# ----------------------- Finding 8: keyring tamper typing -------------------


def test_keyring_malformed_hex_raises_keyunwraperror() -> None:
    # scrypt keeps the test fast (the argon2 default is deliberately memory-hard).
    keyring, _dek = create_keyring("case1", b"passphrase", algorithm=KdfAlgorithm.SCRYPT)
    tampered_entry = keyring.wrap_entries[0].model_copy(update={"wrapped_dek_hex": "zz-not-hex"})
    tampered = keyring.model_copy(update={"wrap_entries": [tampered_entry]})
    with pytest.raises(KeyUnwrapError):
        unwrap_dek(tampered, b"passphrase")
