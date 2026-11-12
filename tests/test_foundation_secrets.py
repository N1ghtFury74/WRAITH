"""Foundation gate — secrets: crypto round-trip, AAD tamper, keyring, store.

Covers Layer-1 (round-trip golden), Layer-2 (AEAD tamper / field validators /
keyring tamper) and Layer-3 (append-only run-scoped store invariant, the locked
decision) and the redaction backstop (NFR-05).

argon2id is the default KEK KDF but is deliberately memory-hard; scrypt is used
for keyring tests to keep the suite fast, with one argon2id round-trip to prove
the default path.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretBytes, SecretStr, ValidationError

from wraith.secrets.kdf import KdfAlgorithm
from wraith.secrets.keyring import (
    KeyUnwrapError,
    create_keyring,
    load_keyring,
    unwrap_dek,
    write_keyring,
)
from wraith.secrets.records import (
    ALG_AES_256_GCM,
    NONCE_LENGTH,
    SecretDecryptError,
    SecretRecord,
    SecretType,
    compute_secret_id,
    decrypt_secret,
    encrypt_secret,
)
from wraith.secrets.redaction import REDACTED, SecretRedactionFilter, install_secret_log_filter
from wraith.secrets.store import SecretAlreadyStoredError, SecretStore

_DEK = b"\x02" * 32
_OTHER_DEK = b"\x03" * 32
_IMG = "a" * 64


def _encrypt(**overrides: object) -> SecretRecord:
    kwargs: dict[str, object] = dict(
        case_id="case1",
        secret_id="sid-1",
        secret_type=SecretType.NT_HASH,
        node_id="node-1",
        ingest_run_id=uuid4(),
        plaintext=SecretBytes(b"super-secret-hash"),
        image_sha256=None,
    )
    kwargs.update(overrides)
    return encrypt_secret(_DEK, **kwargs)  # type: ignore[arg-type]


# --------------------------- crypto round-trip -----------------------------


def test_encrypt_decrypt_round_trip_exact_plaintext() -> None:
    pt = b"\x00\x01\x02 the NT hash \xff"
    rec = _encrypt(plaintext=SecretBytes(pt))
    assert decrypt_secret(_DEK, rec).get_secret_value() == pt
    assert rec.alg == ALG_AES_256_GCM


def test_ciphertext_nondeterministic_but_plaintext_stable() -> None:
    """Documented secret invariant: ciphertext varies, plaintext is stable."""
    r1 = _encrypt()
    r2 = _encrypt()
    assert r1.ciphertext != r2.ciphertext  # fresh nonce => different bytes
    assert r1.nonce != r2.nonce
    assert decrypt_secret(_DEK, r1).get_secret_value() == b"super-secret-hash"
    assert decrypt_secret(_DEK, r2).get_secret_value() == b"super-secret-hash"


def test_encrypt_rejects_wrong_dek_length() -> None:
    with pytest.raises(ValueError):
        encrypt_secret(
            b"short",
            case_id="c",
            secret_id="s",
            secret_type=SecretType.NT_HASH,
            node_id="n",
            ingest_run_id=uuid4(),
            plaintext=SecretBytes(b"x"),
        )


def test_decrypt_wrong_dek_fails() -> None:
    rec = _encrypt()
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_OTHER_DEK, rec)


# --------------------------- AEAD tamper detection -------------------------


def test_tamper_ciphertext_byte_detected() -> None:
    rec = _encrypt()
    flipped = bytes([rec.ciphertext[0] ^ 0x01]) + rec.ciphertext[1:]
    bad = rec.model_copy(update={"ciphertext": flipped})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_tamper_nonce_byte_detected() -> None:
    rec = _encrypt()
    flipped = bytes([rec.nonce[0] ^ 0x01]) + rec.nonce[1:]
    bad = rec.model_copy(update={"nonce": flipped})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_aad_context_binding_ingest_run_id() -> None:
    rec = _encrypt()
    bad = rec.model_copy(update={"ingest_run_id": uuid4()})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_aad_context_binding_node_id() -> None:
    rec = _encrypt()
    bad = rec.model_copy(update={"node_id": "different-node"})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_aad_context_binding_secret_type() -> None:
    rec = _encrypt()
    bad = rec.model_copy(update={"secret_type": SecretType.LM_HASH})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_aad_context_binding_case_id() -> None:
    rec = _encrypt()
    bad = rec.model_copy(update={"case_id": "another-case"})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_aad_context_binding_producing_image_sha256() -> None:
    rec = _encrypt(image_sha256=_IMG)
    assert decrypt_secret(_DEK, rec).get_secret_value() == b"super-secret-hash"
    bad = rec.model_copy(update={"producing_image_sha256": "b" * 64})
    with pytest.raises(SecretDecryptError):
        decrypt_secret(_DEK, bad)


def test_decrypt_rejects_unknown_alg() -> None:
    rec = _encrypt()
    bad = rec.model_copy(update={"alg": "AES-128-CBC"})
    with pytest.raises(ValueError):
        decrypt_secret(_DEK, bad)


# --------------------------- SecretRecord validators -----------------------


def test_record_rejects_wrong_nonce_length() -> None:
    with pytest.raises(ValidationError):
        SecretRecord(
            secret_id="s",
            case_id="c",
            secret_type=SecretType.NT_HASH,
            ingest_run_id=uuid4(),
            nonce=b"\x00" * (NONCE_LENGTH + 1),
            ciphertext=b"x" * 16,
        )


def test_record_rejects_empty_ciphertext() -> None:
    with pytest.raises(ValidationError):
        SecretRecord(
            secret_id="s",
            case_id="c",
            secret_type=SecretType.NT_HASH,
            ingest_run_id=uuid4(),
            nonce=b"\x00" * NONCE_LENGTH,
            ciphertext=b"",
        )


def test_record_rejects_malformed_producing_image_sha256() -> None:
    with pytest.raises(ValidationError):
        SecretRecord(
            secret_id="s",
            case_id="c",
            secret_type=SecretType.NT_HASH,
            ingest_run_id=uuid4(),
            producing_image_sha256="NOTHEX",
            nonce=b"\x00" * NONCE_LENGTH,
            ciphertext=b"x" * 16,
        )


# --------------------------- compute_secret_id -----------------------------


def test_compute_secret_id_run_scoped_and_image_scoped() -> None:
    run = uuid4()
    base = compute_secret_id("c", SecretType.NT_HASH, "n", ingest_run_id=run)
    assert base == compute_secret_id("c", SecretType.NT_HASH, "n", ingest_run_id=run)
    assert base != compute_secret_id("c", SecretType.NT_HASH, "n", ingest_run_id=uuid4())
    assert base != compute_secret_id(
        "c", SecretType.NT_HASH, "n", ingest_run_id=run, image_sha256=_IMG
    )
    assert base != compute_secret_id("c", SecretType.NT_HASH, "n", ingest_run_id=run, label="1")


# --------------------------- keyring envelope ------------------------------


def test_keyring_argon2id_round_trip() -> None:
    """The default (argon2id) KEK path wraps and unwraps the DEK."""
    keyring, dek = create_keyring("case1", b"correct horse", algorithm=KdfAlgorithm.ARGON2ID)
    assert len(dek) == 32
    assert unwrap_dek(keyring, b"correct horse") == dek


def test_keyring_scrypt_round_trip_and_persist(tmp_path: Path) -> None:
    keyring, dek = create_keyring("case1", b"pw", algorithm=KdfAlgorithm.SCRYPT)
    path = tmp_path / "keyring.json"
    write_keyring(path, keyring)
    reloaded = load_keyring(path)
    assert unwrap_dek(reloaded, b"pw") == dek


def test_keyring_wrong_passphrase_raises() -> None:
    keyring, _dek = create_keyring("case1", b"right", algorithm=KdfAlgorithm.SCRYPT)
    with pytest.raises(KeyUnwrapError):
        unwrap_dek(keyring, b"wrong")


def test_keyring_tampered_wrapped_dek_raises_typed() -> None:
    keyring, _dek = create_keyring("case1", b"pw", algorithm=KdfAlgorithm.SCRYPT)
    entry = keyring.wrap_entries[0]
    flipped = ("f" if entry.wrapped_dek_hex[0] != "f" else "0") + entry.wrapped_dek_hex[1:]
    bad = keyring.model_copy(
        update={"wrap_entries": [entry.model_copy(update={"wrapped_dek_hex": flipped})]}
    )
    with pytest.raises(KeyUnwrapError):
        unwrap_dek(bad, b"pw")


def test_keyring_malformed_salt_hex_raises_typed_not_valueerror() -> None:
    """A non-hex salt must surface as KeyUnwrapError, never a bare ValueError (N4)."""
    keyring, _dek = create_keyring("case1", b"pw", algorithm=KdfAlgorithm.SCRYPT)
    entry = keyring.wrap_entries[0]
    bad_kdf = entry.kdf.model_copy(update={"salt_hex": "nothex!!"})
    bad = keyring.model_copy(update={"wrap_entries": [entry.model_copy(update={"kdf": bad_kdf})]})
    with pytest.raises(KeyUnwrapError):
        unwrap_dek(bad, b"pw")


def test_keyring_missing_cost_params_raises_typed() -> None:
    """A keyring with cost params stripped must raise KeyUnwrapError (N4)."""
    keyring, _dek = create_keyring("case1", b"pw", algorithm=KdfAlgorithm.SCRYPT)
    entry = keyring.wrap_entries[0]
    bad_kdf = entry.kdf.model_copy(update={"params": {}})  # drop n/r/p
    bad = keyring.model_copy(update={"wrap_entries": [entry.model_copy(update={"kdf": bad_kdf})]})
    with pytest.raises(KeyUnwrapError):
        unwrap_dek(bad, b"pw")


# --------------------------- SecretStore (locked decision) -----------------


def test_store_append_only_run_scoped(tmp_path: Path) -> None:
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
        assert sid_a != sid_b
        assert store.count() == 2
        # duplicate run-scoped id -> surfaced, never silent overwrite
        with pytest.raises(SecretAlreadyStoredError):
            store.put_secret(
                _DEK,
                ingest_run_id=run_a,
                secret_type=SecretType.NT_HASH,
                node_id="n1",
                plaintext=SecretBytes(b"hash-a-again"),
            )
        assert store.count() == 2  # still two; nothing overwritten
        assert store.reveal(sid_a, _DEK).get_secret_value() == b"hash-a"
        assert store.reveal(sid_b, _DEK).get_secret_value() == b"hash-b"
    finally:
        store.close()


def test_store_reveal_unknown_raises_keyerror(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path / "store.duckdb", "case1")
    try:
        with pytest.raises(KeyError):
            store.reveal("does-not-exist", _DEK)
    finally:
        store.close()


def test_store_reveal_wrong_dek_raises_decrypt_error(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path / "store.duckdb", "case1")
    try:
        sid = store.put_secret(
            _DEK,
            ingest_run_id=uuid4(),
            secret_type=SecretType.NT_HASH,
            node_id="n1",
            plaintext=SecretBytes(b"hash"),
        )
        with pytest.raises(SecretDecryptError):
            store.reveal(sid, _OTHER_DEK)
    finally:
        store.close()


def test_store_record_persists_as_ciphertext_only(tmp_path: Path) -> None:
    """The stored record never contains the plaintext bytes."""
    store = SecretStore.open(tmp_path / "store.duckdb", "case1")
    try:
        sid = store.put_secret(
            _DEK,
            ingest_run_id=uuid4(),
            secret_type=SecretType.NT_HASH,
            node_id="n1",
            plaintext=SecretBytes(b"PLAINTEXTMARKER"),
        )
        rec = store.get_record(sid)
        assert rec is not None
        assert b"PLAINTEXTMARKER" not in rec.ciphertext
        assert rec.alg == ALG_AES_256_GCM
    finally:
        store.close()


# --------------------------- redaction backstop (NFR-05) -------------------


def _capture() -> tuple[io.StringIO, logging.Handler]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(name)s|%(message)s"))
    return stream, handler


def test_redaction_32hex_via_child_logger(tmp_path: Path) -> None:
    stream, handler = _capture()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()
        logging.getLogger("wraith.secrets.store").warning("leak %s", "d" * 32)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "d" * 32 not in out
    assert REDACTED in out


def test_redaction_leaves_64hex_image_sha256() -> None:
    stream, handler = _capture()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()
        logging.getLogger("wraith.secrets.store").warning("image=%s", "e" * 64)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "e" * 64 in out  # a forensic sha256 must NOT be masked


def test_redaction_scoped_to_secrets_subtree() -> None:
    stream, handler = _capture()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_secret_log_filter()
        logging.getLogger("wraith.model.store").warning("node %s", "c" * 32)
        handler.flush()
        out = stream.getvalue()
    finally:
        root.removeHandler(handler)
    assert "c" * 32 in out  # 32-hex only masked under wraith.secrets.*


def test_redaction_secretbytes_in_extra_any_logger() -> None:
    flt = SecretRedactionFilter()
    record = logging.LogRecord("wraith.anything", logging.INFO, __file__, 1, "op", (), None)
    record.leaked = SecretBytes(b"topsecret")  # type: ignore[attr-defined]
    flt.filter(record)
    assert record.leaked == REDACTED  # type: ignore[attr-defined]


def test_redaction_secretstr_as_msg() -> None:
    flt = SecretRedactionFilter()
    record = logging.LogRecord("wraith.cli", logging.INFO, __file__, 1, SecretStr("p"), (), None)
    flt.filter(record)
    assert record.msg == REDACTED


def test_redaction_secretbytes_in_positional_args() -> None:
    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        "wraith.cli", logging.INFO, __file__, 1, "value=%s", (SecretBytes(b"x"),), None
    )
    flt.filter(record)
    assert record.getMessage() == f"value={REDACTED}"


def test_redaction_secretbytes_in_mapping_args() -> None:
    """Dict-style ``%(k)s`` args are scrubbed too."""
    flt = SecretRedactionFilter()
    # logging passes a mapping wrapped in a 1-tuple (as logging.info does).
    record = logging.LogRecord(
        "wraith.secrets.store",
        logging.INFO,
        __file__,
        1,
        "v=%(k)s",
        ({"k": SecretBytes(b"x")},),
        None,
    )
    flt.filter(record)
    assert record.getMessage() == f"v={REDACTED}"
