# ESE test fixtures

## `generic-sample.edb`

A **small, generic, non-Active-Directory** ESE (Extensible Storage Engine)
database used to exercise the swappable ESE reader backend
(`wraith/parsing/ese_backend.py`). It is **NOT** an `ntds.dit` and contains no
Active Directory data, no credentials, and no client evidence.

| Field | Value |
|---|---|
| Logical name | `generic-sample.edb` |
| SHA-256 | `39f0370d0149288c758e818f8857aff9abc2a6d605f6dbf498c43390eb3fd711` |
| Size | 1,048,576 bytes (1 MiB) |
| ESE page size | 4096 |
| `DBFILEHDR.dbstate` | 3 (CleanShutdown) |
| Tables | `MSysObjects`, `MSysObjectsShadow`, `MSysObjids`, `MSysLocales`, `basic` |
| User table | `basic` — 2 records, one column per JET column type (Bit, UnsignedByte, Short, Long, Currency, IEEESingle, IEEEDouble, DateTime, UnsignedLong, LongLong, GUID, UnsignedShort) |

### Provenance

- **Source:** `dissect.database` project test data —
  `tests/_data/ese/basic.edb.gz` (fox-it/dissect.database, Apache-2.0).
  Also published identically as `dissect.esedb` `tests/_data/basic.edb.gz`.
- **Original archive SHA-256 (`basic.edb.gz`):**
  `d1bab7fca049256efa662b0563d40c8e59b7828413412d1d2d745a49e53be395`
- **Acquisition:** one-time **build-time dev fetch** (permitted — WRAITH's
  offline guarantee governs *runtime*, not dev tooling), gzip-decompressed, and
  vendored here. No `ntds.dit` was fetched.
- **Why vendored:** the installed `dissect` wheel does not bundle a sample
  `.edb`; the adapter's unit/sanity tests need a real ESE file, and this one
  needs no AD data to validate the generic reader + the clean-shutdown
  `database_state` path.

### What it can and cannot validate

- **Can:** open, `tables()`, lazy record streaming (DNT/primary-index order),
  typed value reads across every JET column type, the raw-bytes hatch on a
  byte-valued column, absent-column -> `None` counting, and the
  **CleanShutdown** `database_state` path.
- **Cannot:** the **DirtyShutdown / recovery** `database_state` path (needs a
  real dirty `ntds.dit`), and any NTDS semantics — those are out of scope for
  the adapter and gated separately with the owner-provided `.dit`.
