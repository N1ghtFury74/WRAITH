"""Canonical DuckDB store bootstrap (Phase-0 decision: DuckDB is canonical).

Module 1 created ONLY the ``provenance_ledger`` table (schema §2.4). Module 3
(the Object Normalizer) adds the canonical §3 entity tables plus the two
additive staging tables (the M3 -> M4/M5 hand-off); see
:func:`~wraith.model.store.create_canonical_tables`.
"""

from __future__ import annotations

from wraith.model.store import (
    ADCS_TABLE_DDL,
    CANONICAL_DB_FILENAME,
    CANONICAL_ENTITY_DDL,
    CONTAINER_TABLE_DDL,
    DEFAULT_SOURCE_ID,
    GPO_TABLE_DDL,
    LEDGER_TABLE_DDL,
    PRINCIPAL_TABLE_DDL,
    SOURCE_DDL,
    SOURCE_OBSERVATION_TABLE_DDL,
    SOURCE_TABLE_DDL,
    STAGING_DDL,
    STAGING_LINK_TABLE_DDL,
    STAGING_OBJECT_TABLE_DDL,
    TRUST_TABLE_DDL,
    create_canonical_tables,
    create_ledger_table,
    create_source_tables,
    open_canonical_store,
    open_canonical_store_readonly,
)

__all__ = [
    "ADCS_TABLE_DDL",
    "CANONICAL_DB_FILENAME",
    "CANONICAL_ENTITY_DDL",
    "CONTAINER_TABLE_DDL",
    "DEFAULT_SOURCE_ID",
    "GPO_TABLE_DDL",
    "LEDGER_TABLE_DDL",
    "PRINCIPAL_TABLE_DDL",
    "SOURCE_DDL",
    "SOURCE_OBSERVATION_TABLE_DDL",
    "SOURCE_TABLE_DDL",
    "STAGING_DDL",
    "STAGING_LINK_TABLE_DDL",
    "STAGING_OBJECT_TABLE_DDL",
    "TRUST_TABLE_DDL",
    "create_canonical_tables",
    "create_ledger_table",
    "create_source_tables",
    "open_canonical_store",
    "open_canonical_store_readonly",
]
