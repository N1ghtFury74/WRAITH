"""Provenance: the embedded struct (schema §2.3), the scoping block (§2.2),
and the normalized provenance ledger (§2.4).

Every entity, edge, and finding produced by any later module carries a
``ProvenanceStruct`` at the point of creation; the ``provenance_ledger`` table
is the auditable chain-of-custody view. Both are written from one in-memory
``IngestRun`` (``wraith.case.ingest_run``) so they can never diverge.
"""

from __future__ import annotations

from wraith.provenance.ledger import (
    GENESIS_PREV_HASH,
    LedgerChainBreak,
    LedgerChainReport,
    LedgerIntegrityReport,
    LedgerRow,
    read_ledger_rows,
    validate_referential_integrity,
    verify_ledger_chain,
    write_ledger_rows,
)
from wraith.provenance.models import ProvenanceStruct, ScopingBlock

__all__ = [
    "ProvenanceStruct",
    "ScopingBlock",
    "LedgerRow",
    "LedgerIntegrityReport",
    "LedgerChainBreak",
    "LedgerChainReport",
    "GENESIS_PREV_HASH",
    "write_ledger_rows",
    "read_ledger_rows",
    "validate_referential_integrity",
    "verify_ledger_chain",
]
