"""The encrypted secret store backed by ``secrets/store.duckdb`` (ciphertext only).

A DuckDB table of ciphertext records (research Item 5 recommendation: a table
for query locality). No plaintext ever touches this file; canonical tables
elsewhere reference entries by ``secret_id`` only. Store operations log only
``{secret_id, secret_type, operation, ingest_run_id}`` — never the value.

Append-only, run-scoped (LOCKED DECISION). ``secret_id`` folds in the producing
``ingest_run_id`` (and optional producing ``image_sha256``), so a second ingest
of a differently recovered secret is a distinct row — a later run NEVER silently
overwrites an earlier run's credential evidence (important for multi-snapshot IR
cases). Re-putting a truly identical ``secret_id`` is surfaced as
``SecretAlreadyStoredError`` rather than replacing the row. (This secret-store
table is NOT part of the frozen canonical schema; the frozen ``provenance_ledger``
and entity/edge tables are untouched.)
"""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

import duckdb
from pydantic import SecretBytes

from wraith.secrets.records import (
    SecretRecord,
    SecretType,
    compute_secret_id,
    decrypt_secret,
    encrypt_secret,
)

#: Encrypted-store filename inside a case workspace ``secrets/`` dir.
STORE_DB_FILENAME: str = "store.duckdb"

_STORE_DDL = """
CREATE TABLE IF NOT EXISTS secret_store (
    secret_id              VARCHAR NOT NULL,
    case_id                VARCHAR NOT NULL,
    secret_type            VARCHAR NOT NULL,
    node_id                VARCHAR NOT NULL,
    ingest_run_id          VARCHAR NOT NULL,
    producing_image_sha256 VARCHAR,
    nonce                  BLOB    NOT NULL,
    ciphertext             BLOB    NOT NULL,
    alg                    VARCHAR NOT NULL,
    PRIMARY KEY (secret_id)
)
"""

_STORE_COLUMNS = (
    "secret_id",
    "case_id",
    "secret_type",
    "node_id",
    "ingest_run_id",
    "producing_image_sha256",
    "nonce",
    "ciphertext",
    "alg",
)

_log = logging.getLogger("wraith.secrets.store")


class SecretAlreadyStoredError(Exception):
    """Raised when a ``secret_id`` already exists on an append-only ``put``.

    The store is append-only and run-scoped, so this means the exact same
    logical secret (same case/type/node/label/run) was put twice. It is
    surfaced rather than silently overwriting the existing ciphertext row.
    """


class SecretStore:
    """Ciphertext-only persistence for recovered secrets (NFR-05).

    Open with :meth:`open`; the caller owns the DEK lifecycle (obtained from the
    keyring) and must call :meth:`close`.
    """

    def __init__(self, con: duckdb.DuckDBPyConnection, case_id: str) -> None:
        """Wrap an open connection. Prefer :meth:`open`.

        Inputs:
            con: an open DuckDB connection with ``secret_store`` present.
            case_id: the owning case id (bound into every record's AAD).
        """
        self._con = con
        self._case_id = case_id

    @classmethod
    def open(cls, db_path: Path | str, case_id: str) -> SecretStore:
        """Open (creating if absent) the encrypted store for a case.

        Inputs:
            db_path: path to ``secrets/store.duckdb``. Parent must exist.
            case_id: owning case id.

        Returns:
            An open ``SecretStore``.

        Failure modes:
            Raises ``FileNotFoundError`` if the parent directory is missing;
            ``duckdb.Error`` on a corrupt file.
        """
        path = Path(db_path)
        if not path.parent.is_dir():
            raise FileNotFoundError(f"secret store parent directory missing: {path.parent}")
        con = duckdb.connect(str(path))
        con.execute(_STORE_DDL)
        return cls(con, case_id)

    def put_secret(
        self,
        dek: bytes,
        *,
        ingest_run_id: UUID,
        secret_type: SecretType,
        node_id: str,
        plaintext: SecretBytes,
        label: str = "",
        image_sha256: str | None = None,
    ) -> str:
        """Encrypt and append one secret; return its run-scoped ``secret_id``.

        The store is append-only and run-scoped: ``ingest_run_id`` (and the
        optional producing ``image_sha256``) are folded into both the
        ``secret_id`` and the AEAD AAD. Module 2's ``Principal.secret_refs``
        carries the returned run-scoped id.

        Inputs:
            dek: the 32-byte per-case data key.
            ingest_run_id: the producing ingest run id (REQUIRED — scopes the
                id/AAD, not just the audit log line).
            secret_type: the kind of secret.
            node_id: owning node id, or ``""`` if not node-scoped.
            plaintext: the secret as ``SecretBytes`` (never logged).
            label: optional discriminator for multiple secrets of one type on
                one node.
            image_sha256: optional SHA-256 of the producing artifact.

        Returns:
            The run-scoped ``secret_id`` to record as a ``secret_ref`` elsewhere.

        Failure modes:
            Raises ``ValueError`` if the DEK is not 32 bytes;
            ``SecretAlreadyStoredError`` if this exact ``secret_id`` already
            exists (append-only — a later run never overwrites an earlier one).
        """
        secret_id = compute_secret_id(
            self._case_id,
            secret_type,
            node_id,
            ingest_run_id=ingest_run_id,
            label=label,
            image_sha256=image_sha256,
        )
        record = encrypt_secret(
            dek,
            case_id=self._case_id,
            secret_id=secret_id,
            secret_type=secret_type,
            node_id=node_id,
            ingest_run_id=ingest_run_id,
            plaintext=plaintext,
            image_sha256=image_sha256,
        )
        self._write_record(record)
        _log.info(
            "stored secret",
            extra={
                "secret_id": secret_id,
                "secret_type": secret_type.value,
                "operation": "store",
                "ingest_run_id": str(ingest_run_id),
            },
        )
        return secret_id

    def reveal(
        self, secret_id: str, dek: bytes, *, ingest_run_id: UUID | None = None
    ) -> SecretBytes:
        """Decrypt one stored secret to plaintext ``SecretBytes``.

        This is the ONLY path to plaintext (redact-by-default everywhere else).

        Inputs:
            secret_id: the id returned by :meth:`put_secret`.
            dek: the 32-byte per-case data key (from the keyring).
            ingest_run_id: the ingest run id, for the audit log line only.

        Returns:
            The plaintext wrapped in ``SecretBytes``.

        Failure modes:
            Raises ``KeyError`` if ``secret_id`` is unknown;
            ``wraith.secrets.records.SecretDecryptError`` if authentication
            fails (wrong passphrase/tamper) — the caller should count this as a
            gap, never treat it as a correct value.
        """
        record = self.get_record(secret_id)
        if record is None:
            raise KeyError(f"unknown secret_id: {secret_id}")
        plaintext = decrypt_secret(dek, record)
        _log.info(
            "revealed secret",
            extra={
                "secret_id": secret_id,
                "secret_type": record.secret_type.value,
                "operation": "reveal",
                "ingest_run_id": str(ingest_run_id) if ingest_run_id else None,
            },
        )
        return plaintext

    def get_record(self, secret_id: str) -> SecretRecord | None:
        """Fetch the raw ciphertext record (no decryption).

        Inputs:
            secret_id: the record id.

        Returns:
            A ``SecretRecord`` or ``None`` if absent.

        Failure modes:
            Raises ``duckdb.Error`` if the table is missing.
        """
        cols = ", ".join(_STORE_COLUMNS)  # constant identifiers
        row = self._con.execute(
            f"SELECT {cols} FROM secret_store WHERE secret_id = ?",  # noqa: S608 (constants)
            [secret_id],
        ).fetchone()
        if row is None:
            return None
        producing = row[5]
        return SecretRecord(
            secret_id=str(row[0]),
            case_id=str(row[1]),
            secret_type=SecretType(str(row[2])),
            node_id=str(row[3]),
            ingest_run_id=UUID(str(row[4])),
            producing_image_sha256=str(producing) if producing is not None else None,
            nonce=bytes(row[6]),
            ciphertext=bytes(row[7]),
            alg=str(row[8]),
        )

    def count(self) -> int:
        """Return the number of stored secret records.

        Failure modes:
            Raises ``duckdb.Error`` if the table is missing.
        """
        result = self._con.execute("SELECT COUNT(*) FROM secret_store").fetchone()
        return int(result[0]) if result else 0

    def close(self) -> None:
        """Close the underlying DuckDB connection. Idempotent-safe to call once."""
        self._con.close()

    def _write_record(self, record: SecretRecord) -> None:
        """Append a ciphertext record (write path, no plaintext).

        Append-only: a pre-existing ``secret_id`` is surfaced as
        ``SecretAlreadyStoredError`` instead of being overwritten, so an earlier
        run's credential evidence is never silently lost.
        """
        if self.get_record(record.secret_id) is not None:
            raise SecretAlreadyStoredError(
                f"secret_id already stored (append-only store): {record.secret_id}"
            )
        placeholders = ", ".join("?" for _ in _STORE_COLUMNS)
        self._con.execute(
            # Columns are module constants; all values are parameterized.
            f"INSERT INTO secret_store ({', '.join(_STORE_COLUMNS)}) "  # noqa: S608
            f"VALUES ({placeholders})",
            [
                record.secret_id,
                record.case_id,
                record.secret_type.value,
                record.node_id,
                str(record.ingest_run_id),
                record.producing_image_sha256,
                record.nonce,
                record.ciphertext,
                record.alg,
            ],
        )
