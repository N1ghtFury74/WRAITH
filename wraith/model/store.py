"""Open the canonical DuckDB store and create the canonical + staging tables.

Module 1 created only ``provenance_ledger`` (§2.4). Module 3 (the Object
Normalizer) adds the canonical **entity** tables (frozen schema §3) plus two
additive **staging** tables that are the sanctioned M3 -> M4/M5 hand-off (owner
-approved): ``staging_object`` (raw per-object attrs + SD) and ``staging_link``
(raw link rows with resolved node ids). The staging tables live OUTSIDE the
frozen entity/edge contract (the freeze governs canonical entities/edges, not
parser hand-off), so they are safe to evolve without a schema version bump.

Nested shapes map directly to DuckDB native types: ``LIST`` (``spns``,
``sid_history``, ``published_templates``), ``STRUCT`` (the embedded provenance
block, ``pki_flags``), and ``LIST(STRUCT)`` (``secret_refs``, ``gplinks``,
``enrollment_rights``, ``derived_rights``). Each node table declares
``node_id`` as a PRIMARY KEY for dedup + reproducibility.

Timestamp policy: every canonical-row timestamp (including the provenance
struct's ``directory_timestamp``) is stored as a naive-UTC ``TIMESTAMP``. The
normalizer converts tz-aware UTC datetimes to naive UTC before writing so the
rows are byte-deterministic and tz-unambiguous.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

#: Canonical store filename inside a case workspace.
CANONICAL_DB_FILENAME: str = "canonical.duckdb"

#: The single-source sentinel ``source_id`` stamped on staging rows when a caller
#: runs the normalizer WITHOUT supplying a minted ``source_id`` (standalone M3
#: unit tests, legacy direct callers). The real multi-source ingest path
#: (M-MS1 :func:`wraith.model.source.derive_source_id`) always supplies a
#: deterministic per-source UUID; this fixed, well-formed UUID keeps the widened
#: ``staging_object`` PRIMARY KEY ``(node_id, source_id)`` satisfiable (NOT NULL)
#: for those legacy single-source callers with zero behaviour change.
DEFAULT_SOURCE_ID: str = "00000000-0000-5000-8000-0000000000de"

#: DDL for the §2.4 provenance ledger. Write-once / append-only; the composite
#: primary key enforces "one row per (artifact, ingest run)". ``db_state`` is
#: reserved for Module 2. ``prev_entry_hash`` / ``entry_hash`` (schema v1.1,
#: owner-approved 2026-10-26 at M6) form a deterministic SHA-256 hash-chain over
#: the rows for tamper-evidence; both are NULLABLE/additive, so a row written
#: without the chain still reads (treated as genesis by the verifier).
LEDGER_TABLE_DDL: str = """
CREATE TABLE IF NOT EXISTS provenance_ledger (
    ingest_run_id   UUID        NOT NULL,
    source_file     VARCHAR     NOT NULL,
    image_sha256    VARCHAR     NOT NULL,
    acquired_at     TIMESTAMPTZ,
    tool_versions   JSON,
    parameters      JSON,
    db_state        VARCHAR,
    coverage_counts JSON,
    skip_counts     JSON,
    ingested_at     TIMESTAMPTZ NOT NULL,
    prev_entry_hash VARCHAR,
    entry_hash      VARCHAR,
    PRIMARY KEY (ingest_run_id, source_file)
)
"""


#: Reusable DDL fragment: the embedded provenance STRUCT (§2.3). Naive-UTC
#: ``TIMESTAMP`` for ``directory_timestamp`` (see module docstring).
_PROVENANCE_STRUCT: str = (
    "STRUCT("
    "source_file VARCHAR, "
    "image_sha256 VARCHAR, "
    "source_object_id VARCHAR, "
    "directory_timestamp TIMESTAMP, "
    "ingest_run_id UUID)"
)

#: Reusable DDL fragment: the §2.2 scoping block, declared inline on every table.
_SCOPING_BLOCK: str = "forest_id VARCHAR NOT NULL, domain_id VARCHAR, domain_fqdn VARCHAR"

#: §3.1 Principal — ONE discriminated table (User/Computer/Group), nullable cols.
PRINCIPAL_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS principal (
    node_id              VARCHAR PRIMARY KEY,
    object_sid           VARCHAR,
    object_guid          VARCHAR,
    principal_type       VARCHAR NOT NULL,
    samaccountname       VARCHAR,
    upn                  VARCHAR,
    distinguished_name   VARCHAR,
    display_name         VARCHAR,
    description          VARCHAR,
    uac_flags            INTEGER,
    enabled              BOOLEAN,
    admincount           INTEGER,
    spns                 VARCHAR[],
    sid_history          VARCHAR[],
    primary_group_id     INTEGER,
    pwd_last_set         TIMESTAMP,
    last_logon_timestamp TIMESTAMP,
    when_created         TIMESTAMP,
    when_changed         TIMESTAMP,
    secret_refs          STRUCT(secret_id VARCHAR, secret_type VARCHAR,
                                label VARCHAR, decrypted BOOLEAN,
                                decryptable_offline BOOLEAN)[],
    behavior_summary_ref VARCHAR,
    {_SCOPING_BLOCK},
    provenance           {_PROVENANCE_STRUCT}
)
"""

#: §3.2 OU/Container/Domain — one discriminated table.
CONTAINER_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS container (
    node_id            VARCHAR PRIMARY KEY,
    object_guid        VARCHAR,
    object_sid         VARCHAR,
    distinguished_name VARCHAR,
    container_type     VARCHAR NOT NULL,
    parent_node_id     VARCHAR,
    gplinks            STRUCT(gpo_node_id VARCHAR, enforced BOOLEAN,
                              link_order INTEGER)[],
    functional_level   INTEGER,
    {_SCOPING_BLOCK},
    provenance         {_PROVENANCE_STRUCT}
)
"""

#: §3.3 GPO. ``derived_rights`` stays empty in M3 (filled by the SYSVOL module).
#: Each ``derived_rights`` entry carries ``image_sha256`` (schema v1.1,
#: owner-approved 2026-10-26 at M6) — the SHA-256 of the source SYSVOL artifact,
#: making every derived-rights fact self-describing. NULLABLE/additive.
GPO_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS gpo (
    node_id           VARCHAR PRIMARY KEY,
    object_guid       VARCHAR,
    display_name      VARCHAR,
    gpc_file_sys_path VARCHAR,
    derived_rights    STRUCT("right" VARCHAR, target_scope VARCHAR,
                             source_file VARCHAR, image_sha256 VARCHAR)[],
    {_SCOPING_BLOCK},
    provenance        {_PROVENANCE_STRUCT}
)
"""

#: §3.4 Trust (from ``trustedDomain`` objects).
TRUST_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS trust (
    node_id          VARCHAR PRIMARY KEY,
    source_domain_id VARCHAR,
    target_domain_id VARCHAR,
    direction        VARCHAR,
    trust_type       VARCHAR,
    trust_attributes INTEGER,
    transitive       BOOLEAN,
    sid_filtering    BOOLEAN,
    trust_key_ref    VARCHAR,
    {_SCOPING_BLOCK},
    provenance       {_PROVENANCE_STRUCT}
)
"""

#: §3.5 CertTemplate/EnterpriseCA (ADCS base facts). ``pki_flags`` is a RAW
#: struct of the public [MS-CRTD] attribute names; ``enrollment_rights`` stays
#: empty in M3 (derived from the DACL by the edge engine, M5).
ADCS_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS adcs (
    node_id             VARCHAR PRIMARY KEY,
    object_guid         VARCHAR,
    name                VARCHAR,
    adcs_type           VARCHAR NOT NULL,
    pki_flags           STRUCT(
        certificate_name_flag      VARCHAR,
        enrollment_flag            VARCHAR,
        private_key_flag           VARCHAR,
        ra_signature               VARCHAR,
        template_schema_version    VARCHAR,
        extended_key_usage         VARCHAR[],
        certificate_application_policy VARCHAR[],
        expiration_period          VARCHAR,
        overlap_period             VARCHAR,
        revision                   VARCHAR,
        flags                      VARCHAR,
        cn                         VARCHAR,
        ca_certificate             VARCHAR[],
        dns_host_name              VARCHAR,
        certificate_policy         VARCHAR[],
        ra_application_policies    VARCHAR,
        oid_to_group_link          VARCHAR,
        oid                        VARCHAR),
    enrollment_rights   STRUCT(principal_node_id VARCHAR, "right" VARCHAR)[],
    published_templates VARCHAR[],
    {_SCOPING_BLOCK},
    provenance          {_PROVENANCE_STRUCT}
)
"""

#: Staging table (OUTSIDE the frozen contract): one row per normalized node,
#: carrying the RAW attribute map (incl. objectClass), raw SD bytes, and the
#: identity keys M4/M5 need without re-reading ``ParsedNtds``. ``attributes`` is
#: a lossless typed-JSON encoding (bytes -> ``{"__bytes_hex__": ...}``), so the
#: delegation/RBCD/gMSA/keyCredentialLink raw values are preserved for M5.
#: ``source_id`` (multi-source contract §2.2b, schema v1.2) is appended as the
#: LAST column and the PRIMARY KEY is widened to ``(node_id, source_id)`` — the
#: one place two DCs' divergent raw copies of the same ``node_id`` physically
#: coexist (Phase 2). Legal because staging is OUTSIDE the frozen contract. In
#: Phase 1 (one source per node) ``(node_id, source_id)`` is still unique, so the
#: single-source path is byte-for-byte unchanged apart from the stamped column.
STAGING_OBJECT_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS staging_object (
    node_id      VARCHAR NOT NULL,
    dnt          BIGINT,
    object_guid  VARCHAR,
    object_sid   VARCHAR,
    object_class VARCHAR[],
    raw_sd       BLOB,
    attributes   JSON,
    {_SCOPING_BLOCK},
    provenance   {_PROVENANCE_STRUCT},
    source_id    VARCHAR NOT NULL DEFAULT '{DEFAULT_SOURCE_ID}',
    PRIMARY KEY (node_id, source_id)
)
"""

#: Staging table (OUTSIDE the frozen contract): raw ``link_table`` rows with the
#: endpoint DNTs resolved to node ids for M4 membership resolution. Raw dnts and
#: link bytes are retained so nothing M4 needs is dropped.
#: ``source_id`` (multi-source contract §2.2b, schema v1.2) is appended as the
#: LAST column so every staged link is attributed to its source. DEVIATION from
#: the contract's literal "widen the PK to ``(link_base, source_node_id,
#: target_node_id, source_id)``": ``staging_link`` has NO primary key today and
#: its endpoints are LEGITIMATELY NULLABLE (a dangling link whose DNT indexed to
#: no node is emitted with a NULL endpoint + a counted gap — M3
#: ``normalizer.link_unresolved``) and NON-UNIQUE (a re-added / deactivated link
#: can repeat a ``(base, source, target)`` triple). A ``PRIMARY KEY`` over those
#: NULLABLE columns would REJECT those real rows — a regression. So ``source_id``
#: is added + stamped (NOT NULL, the attribution guarantee the PK-widening exists
#: to serve) but no hard key constraint is enforced on ``staging_link``. Flagged
#: for owner/reviewer. Phase-2 merge reads/folds by ``source_id`` either way.
STAGING_LINK_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS staging_link (
    link_base         BIGINT,
    source_node_id    VARCHAR,
    target_node_id    VARCHAR,
    link_dnt          BIGINT,
    backlink_dnt      BIGINT,
    link_deactivetime BIGINT,
    link_deltime      BIGINT,
    link_usnchanged   BIGINT,
    link_ncdnt        BIGINT,
    link_data         BLOB,
    link_metadata     BLOB,
    {_SCOPING_BLOCK},
    provenance        {_PROVENANCE_STRUCT},
    source_id         VARCHAR NOT NULL DEFAULT '{DEFAULT_SOURCE_ID}'
)
"""

#: §2.2a ``source`` dimension (multi-source contract, schema v1.2) — one row per
#: ingested DC artifact set ``{ntds.dit + SYSTEM (+ SAM, + SYSVOL)}``. The
#: operator names each source (``dc_label`` + ``declared_domain``); the
#: ``domain_id``/``domain_fqdn`` are DERIVED from the actual ``ntds.dit`` and are
#: authoritative for scoping (declared values are display-only). ``UNIQUE(case_id,
#: dc_label)`` enforces label-uniqueness (§1.3). ``is_global_catalog`` /
#: ``dsa_guid`` / ``invocation_id`` are NULLABLE Phase-2/GC reservations (§4.4);
#: ``ingested_at`` is wall-clock (like ``provenance_ledger.ingested_at`` — not a
#: determinism input). ``source_id`` is a deterministic UUIDv5
#: (:func:`wraith.model.source.derive_source_id`).
SOURCE_TABLE_DDL: str = """
CREATE TABLE IF NOT EXISTS source (
    source_id           VARCHAR PRIMARY KEY,
    case_id             VARCHAR NOT NULL,
    dc_label            VARCHAR NOT NULL,
    forest_id           VARCHAR NOT NULL,
    domain_id           VARCHAR,
    domain_fqdn         VARCHAR,
    declared_domain     VARCHAR,
    ntds_image_sha256   VARCHAR NOT NULL,
    system_image_sha256 VARCHAR,
    is_global_catalog   BOOLEAN,
    dsa_guid            VARCHAR,
    invocation_id       VARCHAR,
    ingest_run_id       UUID NOT NULL,
    ingested_at         TIMESTAMPTZ NOT NULL,
    UNIQUE (case_id, dc_label)
)
"""

#: §2.2c ``source_observation`` side table (multi-source contract, schema v1.2) —
#: the per-source "which source asserted this node/edge, and when" list the single
#: embedded :class:`~wraith.provenance.models.ProvenanceStruct` cannot hold. A
#: per-source standalone view (M-MS2) is then a ``WHERE source_id = ?`` filter and
#: merge (M-MS4) a ``GROUP BY obj_id`` fold. ``directory_timestamp`` is the
#: object-level ``whenChanged`` (replicated, cross-DC comparable); ``usn_local`` is
#: STORED BUT NEVER a cross-DC winner key (local counter); ``attr_metadata_blob``
#: is NULL for now (filled IFF the ``replPropertyMetaData`` decoder lands, M-MS4).
SOURCE_OBSERVATION_TABLE_DDL: str = """
CREATE TABLE IF NOT EXISTS source_observation (
    obj_kind            VARCHAR NOT NULL,
    obj_id              VARCHAR NOT NULL,
    source_id           VARCHAR NOT NULL,
    directory_timestamp TIMESTAMP,
    when_created        TIMESTAMP,
    usn_local           BIGINT,
    is_deleted          BOOLEAN,
    attr_metadata_blob  BLOB,
    PRIMARY KEY (obj_kind, obj_id, source_id)
)
"""

#: The additive multi-source tables (M-MS1) in creation order. NOTE: the
#: ``divergence`` ledger (§2.2d) is deliberately NOT here — that is M-MS4's
#: (:data:`DIVERGENCE_TABLE_DDL` / :func:`create_divergence_table`), so the
#: single-source (M-MS1) path is byte-for-byte unchanged and only the opt-in
#: multi-DC merge path provisions the ledger.
SOURCE_DDL: tuple[str, ...] = (
    SOURCE_TABLE_DDL,
    SOURCE_OBSERVATION_TABLE_DDL,
)

#: §2.2d ``divergence`` ledger (multi-source contract, shipped under schema v1.2 — M-MS4a) — the
#: honest merge report. ONE row per disagreement the opt-in merge fold (M-MS4b)
#: finds across the sources that share a ``node_id``/``edge_id``: a whole-entity
#: divergence (``attribute`` NULL, e.g. ``deleted_on_source`` /
#: ``candidate_lingering_object``), a whole-edge divergence
#: (``edge_membership_divergence``), or a scalar-attribute divergence
#: (``attribute`` set, e.g. ``userAccountControl``). ``value_by_source`` is a JSON
#: ``{source_id: value}`` map; **a secret value is NEVER stored in plaintext here**
#: — the writer records ``{present:true,differs:true}`` instead (``secret_divergence``).
#: ``resolution`` is the policy tier that resolved the presented value (§3.3) or
#: ``'unresolved'``; ``resolved_by`` is one of
#: ``'per_attr_meta' | 'whenChanged' | 'safer_reading' | NULL`` — there is **no
#: ``'authoritative_dc'``** value (owner decision 2026-11-11, §3.3): WRAITH never
#: lets an operator silence a disagreement by decree. The table is intentionally
#: KEYLESS: a single ``(obj_id, attribute)`` can legitimately produce more than one
#: ledger row across ingest runs, and a NULL ``attribute`` (whole-entity/edge) would
#: make any natural key non-unique — a PRIMARY KEY would reject real rows. Merge is
#: idempotent per run by deleting this run's rows first (M-MS4b), not by a key.
DIVERGENCE_TABLE_DDL: str = """
CREATE TABLE IF NOT EXISTS divergence (
    obj_kind        VARCHAR NOT NULL,
    obj_id          VARCHAR NOT NULL,
    attribute       VARCHAR,
    value_by_source JSON    NOT NULL,
    divergence_type VARCHAR NOT NULL,
    resolution      VARCHAR,
    resolved_value  JSON,
    resolved_by     VARCHAR,
    counted         BOOLEAN NOT NULL DEFAULT TRUE,
    ingest_run_id   UUID    NOT NULL
)
"""

#: The additive merge tables (M-MS4) in creation order — currently just the
#: ``divergence`` ledger. Separate from :data:`SOURCE_DDL` so provisioning the
#: ledger is an explicit opt-in (the multi-DC merge path), not forced onto every
#: single-source store.
MERGE_DDL: tuple[str, ...] = (DIVERGENCE_TABLE_DDL,)


#: §4 Edge — the FROZEN core contract (the attacker-direction capability graph).
#: Module 4 is the first writer (MemberOf only); later modules add ACL/UAC/trust/
#: GPO/ADCS edge kinds into this same table. ``edge_id`` is the deterministic
#: ``stable_id(kind, source, target, derivation)`` so re-deriving an identical
#: fact yields an identical row (dedup + reproducibility). ``access_mask`` /
#: ``object_type_guid`` are populated only for ACL-derived edges (NULL for
#: MemberOf). The scoping block + embedded provenance match every entity table.
#: ``access_mask`` is BIGINT (schema v1.1, owner-approved 2026-10-26 at M6): the
#: 32-bit mask is stored as a CLEAN UNSIGNED value (0..4294967295), not a signed
#: two's-complement reinterpretation — a BIGINT holds the full unsigned range.
EDGE_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS edge (
    edge_id          VARCHAR PRIMARY KEY,
    kind             VARCHAR NOT NULL,
    source_node_id   VARCHAR NOT NULL,
    target_node_id   VARCHAR NOT NULL,
    is_inherited     BOOLEAN,
    derivation       VARCHAR,
    access_mask      BIGINT,
    object_type_guid VARCHAR,
    confidence       VARCHAR,
    {_SCOPING_BLOCK},
    provenance       {_PROVENANCE_STRUCT}
)
"""

#: Derived table (OUTSIDE the frozen §4 contract — same additive class as the
#: staging tables): the materialized reflexive-free transitive closure of the
#: direct ``MemberOf`` edges. One row per (effective member, group); keyed by
#: ``node_id`` (not SID) so a future auth-event join maps a subject to all its
#: effective groups with no re-architecture. M5/pathing reads
#: ``WHERE group_node_id = ?`` for O(1) "effective members of G".
EFFECTIVE_MEMBERSHIP_TABLE_DDL: str = """
CREATE TABLE IF NOT EXISTS effective_membership (
    member_node_id VARCHAR NOT NULL,
    group_node_id  VARCHAR NOT NULL,
    forest_id      VARCHAR NOT NULL,
    domain_id      VARCHAR,
    PRIMARY KEY (member_node_id, group_node_id)
)
"""

#: The edge + closure tables Module 4 adds, in creation order.
EDGE_DDL: tuple[str, ...] = (
    EDGE_TABLE_DDL,
    EFFECTIVE_MEMBERSHIP_TABLE_DDL,
)

#: §4b CA-host node-finding table (schema v1.4 — CA-host adapter surfacing) — the
#: additive home for the ESC11/ESC16/DCOM NODE-LEVEL findings the ADCS-ESC pass
#: computes (:class:`~wraith.analysis.adcs_esc.CaNodeFinding`). These are node
#: PROPERTIES (ESC11/ESC16/DCOM have no v1 BloodHound traversable edge), so they
#: are deliberately NOT forced into the FROZEN §4 ``edge`` table — this table is a
#: purely ADDITIVE sibling (multi-source additive-schema discipline), so a store
#: produced without a CA-host hive is byte-for-byte unchanged. ESC11/ESC16 attach
#: to the EnterpriseCA ``adcs`` node; the DCOM summary to the CA host ``principal``
#: (Computer) node. ``finding_id`` is the deterministic ``stable_id(node_id, prop)``
#: single-column PK (one finding per ``(node, prop)``; ``INSERT OR IGNORE`` makes a
#: re-run idempotent). ``value`` is the NON-SECRET decided value (``"true"`` for
#: ESC11/ESC16; the ``EnableDCOM=Y/N`` summary for DCOM — NEVER a raw security
#: descriptor). The scoping block + embedded provenance match every other table;
#: the provenance carries the CA-host HIVE anchor (source_file / image_sha256 /
#: directory_timestamp / ingest_run_id) with the registry value path as
#: ``source_object_id`` (a fact with provenance, never a loose flag).
CA_NODE_FINDING_TABLE_DDL: str = f"""
CREATE TABLE IF NOT EXISTS ca_node_finding (
    finding_id  VARCHAR PRIMARY KEY,
    node_id     VARCHAR NOT NULL,
    prop        VARCHAR NOT NULL,
    value       VARCHAR NOT NULL,
    {_SCOPING_BLOCK},
    provenance  {_PROVENANCE_STRUCT}
)
"""

#: The canonical entity tables in creation order.
CANONICAL_ENTITY_DDL: tuple[str, ...] = (
    PRINCIPAL_TABLE_DDL,
    CONTAINER_TABLE_DDL,
    GPO_TABLE_DDL,
    TRUST_TABLE_DDL,
    ADCS_TABLE_DDL,
)

#: The additive staging tables (M3 -> M4/M5 hand-off) in creation order.
STAGING_DDL: tuple[str, ...] = (
    STAGING_OBJECT_TABLE_DDL,
    STAGING_LINK_TABLE_DDL,
)


def create_canonical_tables(con: duckdb.DuckDBPyConnection) -> None:
    """Create the canonical entity, staging, and multi-source tables (idempotent).

    Creates the frozen §3 entity tables (``principal``, ``container``, ``gpo``,
    ``trust``, ``adcs``), the two additive staging tables (``staging_object``,
    ``staging_link``), and the additive multi-source tables (``source``,
    ``source_observation``; multi-source contract §2.2, schema v1.2). Safe to call
    repeatedly (each uses ``IF NOT EXISTS``). The multi-source tables are created
    here so the single-source path provisions them too (one ``source`` row, one
    ``source_observation`` per node) with no separate bootstrap.

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` if a conflicting table of the same name with an
        incompatible shape already exists.
    """
    for ddl in (*CANONICAL_ENTITY_DDL, *STAGING_DDL, *SOURCE_DDL):
        con.execute(ddl)


def create_source_tables(con: duckdb.DuckDBPyConnection) -> None:
    """Create ONLY the additive multi-source tables (idempotent; M-MS1).

    Creates ``source`` + ``source_observation`` (multi-source contract §2.2a/§2.2c)
    without touching the canonical/staging DDL. Idempotent (``IF NOT EXISTS``);
    :func:`create_canonical_tables` already includes these, so this is for callers
    that want the multi-source tables on a store created by an older bootstrap.

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` on a conflicting incompatible table of the same name.
    """
    for ddl in SOURCE_DDL:
        con.execute(ddl)


def create_divergence_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create ONLY the ``divergence`` ledger table (idempotent; M-MS4a, §2.2d).

    The opt-in multi-DC merge (M-MS4b) is the only writer; this provisions the
    ledger on a combined multi-source store so the merge fold has somewhere to
    record every disagreement. Deliberately NOT part of :func:`create_canonical_tables`
    — the single-source (M-MS1) path must stay byte-for-byte unchanged, and a store
    that is never merged never needs the ledger. Idempotent (``IF NOT EXISTS``).

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` if a conflicting table named ``divergence`` with an
        incompatible shape already exists.
    """
    for ddl in MERGE_DDL:
        con.execute(ddl)


def create_edge_tables(con: duckdb.DuckDBPyConnection) -> None:
    """Create the frozen §4 ``edge`` table and the ``effective_membership`` table.

    Module 4 (the Membership Resolver) is the first edge writer; this is
    idempotent (``IF NOT EXISTS``) so later edge modules may call it too without
    disturbing an existing table. ``create_canonical_tables`` (Module 3) is left
    untouched so the gated M3 entity/staging DDL does not change.

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` if a conflicting table of the same name with an
        incompatible shape already exists.
    """
    for ddl in EDGE_DDL:
        con.execute(ddl)


def create_ca_node_finding_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create the additive ``ca_node_finding`` table (idempotent; CA-host surfacing).

    The ADCS-ESC pass computes ESC11/ESC16/DCOM node-level findings
    (:class:`~wraith.analysis.adcs_esc.CaNodeFinding`); the pipeline persists them
    here so the dossier API can surface them per node. Deliberately NOT part of
    :func:`create_canonical_tables` nor the FROZEN §4 edge contract — it is additive
    (schema v1.4) and only materializes rows when the CA-host surfacing path runs,
    so a store built without a CA-host hive is byte-for-byte unchanged. Idempotent
    (``IF NOT EXISTS``).

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` if a conflicting table named ``ca_node_finding``
        with an incompatible shape already exists.
    """
    con.execute(CA_NODE_FINDING_TABLE_DDL)


def create_ledger_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create the ``provenance_ledger`` table if it does not already exist.

    Inputs:
        con: an open DuckDB connection.

    Returns:
        None.

    Failure modes:
        Raises ``duckdb.Error`` if the DDL cannot execute (e.g. a conflicting
        table of the same name with an incompatible shape already exists).
    """
    con.execute(LEDGER_TABLE_DDL)


def open_canonical_store(db_path: Path | str) -> duckdb.DuckDBPyConnection:
    """Open (creating if absent) the canonical store and ensure the ledger.

    Inputs:
        db_path: path to the case's ``canonical.duckdb`` file. The parent
            directory must already exist (the case workspace creates it).

    Returns:
        An open ``duckdb.DuckDBPyConnection`` with ``provenance_ledger``
        guaranteed present. The caller owns closing it.

    Failure modes:
        Raises ``FileNotFoundError`` if the parent directory does not exist;
        ``duckdb.Error`` on a corrupt database file.
    """
    path = Path(db_path)
    if not path.parent.is_dir():
        raise FileNotFoundError(f"canonical store parent directory missing: {path.parent}")
    con = duckdb.connect(str(path))
    create_ledger_table(con)
    return con


def open_canonical_store_readonly(db_path: Path | str) -> duckdb.DuckDBPyConnection:
    """Open the canonical store READ-ONLY (no DDL, no writes).

    For pure-SELECT consumers (e.g. the BloodHound export adapter) that must not
    mutate the store or run the ledger DDL. The store MUST already exist and be a
    populated canonical database (produced by an earlier ``analyze``/``ingest``).

    Inputs:
        db_path: path to an existing case ``canonical.duckdb`` file.

    Returns:
        An open read-only ``duckdb.DuckDBPyConnection``. The caller owns closing
        it. No table is created and no row is written on this connection.

    Failure modes:
        Raises ``FileNotFoundError`` if the database file does not exist (DuckDB
        cannot open a missing file read-only); ``duckdb.Error`` on a corrupt file.
    """
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"canonical store not found (run analyze first): {path}")
    return duckdb.connect(str(path), read_only=True)
