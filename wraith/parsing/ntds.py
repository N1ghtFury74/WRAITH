"""Structural NTDS object/table exposure (Module 2 sub-layer 2a).

Builds the NTDS-semantic *structural* layer on top of the gated ESE reader
(:mod:`wraith.parsing.ese_backend`) and the schema resolver
(:mod:`wraith.parsing.schema`). It opens a ``.dit``, detects the clean/dirty
database state, resolves the ``sd_table`` ``{sd_id: sd_value}`` map, and yields
one :class:`ParsedObject` per ``datatable`` object plus the raw ``link_table``
rows — each carrying a provenance struct minted via Module 1's
:class:`~wraith.case.ingest_run.IngestRun`.

**Strictly structural.** It surfaces *raw* security-descriptor bytes (resolved
through the ``sd_id`` indirection) and *raw* link rows. It does **not** parse
SDs into ACLs/ACEs, resolve memberships, decrypt secrets, or normalise to
canonical entities/edges — those are Module 2b (secrets) and Module 3
(normalisation). The boundary is deliberately crisp: this module *exposes*;
downstream *interprets*.

Determinism: objects and links are yielded in ``datatable``/``link_table``
primary-index order (DNT order), which ``dissect`` walks deterministically. No
wall-clock value enters parsed output; timestamps come only from the source
object's ``whenChanged``/``whenCreated``.

Dirty-DB handling (detect → warn → degrade): the ESE header ``dbstate`` is read
up-front and surfaced as :attr:`ParsedNtds.db_state`; a non-clean state is
WARN-logged prominently. Torn/unreadable records degrade to a counted, logged
skip (never a crash, never a silent wrong answer).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import TracebackType

from wraith.case.ingest_run import IngestRun
from wraith.parsing.ese_backend import (
    CoverageReport,
    DatabaseState,
    EseError,
    EseHandle,
    EseRecord,
    EseTable,
    EseTableNotFoundError,
    EseValue,
    open_ese,
)
from wraith.parsing.ntds_values import (
    as_scalar,
    decode_guid,
    decode_ntds_sid,
    decode_ntds_timestamp,
)
from wraith.parsing.schema import NtdsSchema, build_schema
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

# --- table + system-column names (ESE catalog constants, not attribute ids) --
_DATATABLE = "datatable"
_LINK_TABLE = "link_table"
_SD_TABLE = "sd_table"
_SD_ID_COL = "sd_id"
_SD_VALUE_COL = "sd_value"
_DNT_COL = "DNT_col"
_PDNT_COL = "PDNT_col"
# link_table raw columns (surfaced, not resolved — Module 3/4 resolves them).
_LINK_DNT = "link_DNT"
_LINK_BACKLINK_DNT = "backlink_DNT"
_LINK_BASE = "link_base"
_LINK_DELTIME = "link_deltime"
_LINK_DEACTIVETIME = "link_deactivetime"
_LINK_USNCHANGED = "link_usnchanged"
_LINK_NCDNT = "link_ncdnt"
_LINK_DATA = "link_data"
_LINK_METADATA = "link_metadata"
# -----------------------------------------------------------------------------

# Coverage / skip counter keys (surfaced via the IngestRun ledger).
_COV_OBJECTS = "ntds.objects_parsed"
_COV_LINKS = "ntds.links_parsed"
_SKIP_OBJECTS = "ntds.malformed_objects"
_SKIP_LINKS = "ntds.malformed_links"
_SKIP_DNT_LESS = "ntds.dnt_less"
_SKIP_UNRESOLVED_SD = "ntds.unresolved_sd"
_SKIP_SCHEMA_RECORDS = "ntds.malformed_schema_records"
_GAP_UNMAPPED_COLUMNS = "ntds.unmapped_columns"


@dataclass(frozen=True)
class ParsedObject:
    """One structural ``datatable`` object (no canonical interpretation).

    Attributes:
        dnt: the Distinguished Name Tag (primary key; provenance source id).
        parent_dnt: ``PDNT_col`` (tree parent DNT), raw/unresolved.
        object_guid: ``objectGUID`` decoded to a dashed GUID string, or ``None``.
        object_guid_raw: the raw 16-byte ``objectGUID`` blob, or ``None``.
        object_sid: ``objectSid`` decoded to ``S-1-...`` (NTDS byte order), or
            ``None`` for SID-less objects.
        object_sid_raw: the raw ``objectSid`` blob, or ``None``.
        sam_account_name: ``sAMAccountName`` convenience read, or ``None``.
        sd_id: the ``sd_table`` id referenced by ``nTSecurityDescriptor``, or
            ``None`` if the object has no SD.
        raw_sd_bytes: the RAW self-relative security-descriptor bytes resolved
            through ``sd_id`` → ``sd_table.sd_value``. NOT parsed into ACLs/ACEs
            (that is Module 3). ``None`` if unresolved.
        when_changed: ``whenChanged`` as a UTC datetime, or ``None``.
        when_created: ``whenCreated`` as a UTC datetime, or ``None``.
        attributes: schema-resolved populated attributes keyed by
            ``lDAPDisplayName``; values are the backend-parsed values (a
            single-valued attribute may appear as a one-element list — use
            :meth:`attribute` to collapse it).
        provenance: embedded provenance struct (source_file, image_sha256,
            source_object_id=DNT, directory_timestamp=whenChanged, run id).
    """

    dnt: int
    parent_dnt: int | None
    object_guid: str | None
    object_guid_raw: bytes | None
    object_sid: str | None
    object_sid_raw: bytes | None
    sam_account_name: str | None
    sd_id: int | None
    raw_sd_bytes: bytes | None
    when_changed: datetime | None
    when_created: datetime | None
    attributes: Mapping[str, EseValue]
    provenance: ProvenanceStruct

    def attribute(self, ldap_display_name: str, *, scalar: bool = True) -> EseValue:
        """Return a resolved attribute by ``lDAPDisplayName``.

        Inputs:
            ldap_display_name: the attribute's LDAP display name.
            scalar: if ``True`` (default), collapse a single-element list to its
                element; if ``False``, return the backend value unchanged.

        Returns:
            The attribute value, or ``None`` if the attribute is absent/unset on
            this object.

        Failure modes:
            Never raises.
        """
        value = self.attributes.get(ldap_display_name)
        return as_scalar(value) if scalar else value


@dataclass(frozen=True)
class LinkRow:
    """One RAW ``link_table`` row (unresolved — Module 3/4 resolves memberships).

    Attributes mirror the ``link_table`` columns verbatim. ``link_DNT`` and
    ``backlink_DNT`` are DNTs (not yet joined to objects); ``link_base`` is the
    link attribute's base id; ``link_data``/``link_metadata`` are raw bytes.

    Attributes:
        link_dnt: forward-link object DNT, or ``None``.
        backlink_dnt: back-link object DNT, or ``None``.
        link_base: link attribute base id, or ``None``.
        link_deltime: deletion time (raw), or ``None``.
        link_deactivetime: deactivation time (raw), or ``None``.
        link_usnchanged: USN of last change (raw), or ``None``.
        link_ncdnt: naming-context DNT (raw), or ``None``.
        link_data: raw ``link_data`` bytes, or ``None``.
        link_metadata: raw ``link_metadata`` bytes, or ``None``.
        provenance: embedded provenance struct for this link row.
    """

    link_dnt: int | None
    backlink_dnt: int | None
    link_base: int | None
    link_deltime: int | None
    link_deactivetime: int | None
    link_usnchanged: int | None
    link_ncdnt: int | None
    link_data: bytes | None
    link_metadata: bytes | None
    provenance: ProvenanceStruct


@dataclass
class _ObjectColumns:
    """Resolved ``datatable`` column names for the per-object fast fields."""

    object_sid: str | None
    object_guid: str | None
    sam_account_name: str | None
    nt_security_descriptor: str | None
    when_changed: str | None
    when_created: str | None
    # column -> ldap display name, for the resolved attributes map.
    resolved: Mapping[str, str] = field(default_factory=dict)


class ParsedNtds:
    """The structural parse of one ``ntds.dit`` — the hand-off to Module 3.

    Exposes the resolved schema, a deterministic iterator of
    :class:`ParsedObject`, the raw ``link_table`` iterator, the clean/dirty
    :class:`DatabaseState`, and coverage/skip counts. Use as a context manager
    (or call :meth:`close`) to release the underlying ESE handle when this parse
    owns it (i.e. created via :func:`open_ntds`).
    """

    def __init__(
        self,
        handle: EseHandle,
        run: IngestRun,
        schema: NtdsSchema,
        db_state: DatabaseState,
        sd_map: Mapping[int, bytes],
        *,
        source_file: str,
        owns_handle: bool = False,
    ) -> None:
        self._handle = handle
        self._run = run
        self._schema = schema
        self._db_state = db_state
        self._sd_map = sd_map
        self._source_file = source_file
        self._owns_handle = owns_handle
        self._columns = _resolve_object_columns(schema)

    @property
    def schema(self) -> NtdsSchema:
        """The resolved NTDS schema (maps + raw schema records)."""
        return self._schema

    @property
    def db_state(self) -> DatabaseState:
        """The ESE header clean/dirty state (feeds Module 1's ``db_state``)."""
        return self._db_state

    @property
    def source_file(self) -> str:
        """The logical artifact name used for provenance (e.g. ``ntds.dit``)."""
        return self._source_file

    @property
    def required_log_range(self) -> tuple[int, int]:
        """The ``(gen_min_required, gen_max_required)`` transaction-log range.

        For a dirty capture this is the log-generation span a Windows
        ``esentutl /r`` recovery would need; ``(0, 0)`` for a cleanly detached
        db. Exposed so the operator/report (and, when NTDS ingest is wired, the
        provenance ledger per schema §2.4) can record what recovery would need.
        """
        return (self._db_state.gen_min_required, self._db_state.gen_max_required)

    @property
    def sd_count(self) -> int:
        """Number of unique security descriptors in the ``sd_table`` map."""
        return len(self._sd_map)

    def coverage(self) -> CoverageReport:
        """Return the ESE-level coverage/skip snapshot (missing columns, etc.)."""
        return self._handle.coverage()

    @property
    def skip_counts(self) -> dict[str, int]:
        """Parser skip counts accumulated on the owning ``IngestRun`` (gaps)."""
        return self._run.skip_counts

    @property
    def coverage_counts(self) -> dict[str, int]:
        """Parser coverage counts accumulated on the owning ``IngestRun``."""
        return self._run.coverage_counts

    def objects(self) -> Iterator[ParsedObject]:
        """Yield every ``datatable`` object in DNT order (deterministic, lazy).

        Yields:
            One :class:`ParsedObject` per ``datatable`` row (SID-less rows and
            schema/phantom rows included — Module 3 filters). Each carries its
            provenance and raw SD bytes.

        Failure modes:
            A single malformed/torn record is skipped and counted
            (``ntds.malformed_objects``); a DNT-less row is counted separately
            (``ntds.dnt_less``). A provenance ``KeyError`` (unregistered
            ``source_file``) is NOT swallowed — it escapes so a run-config error
            cannot masquerade as every object being malformed (an empty graph).
            A missing ``datatable`` raises :class:`EseError`.
        """
        table = self._table(_DATATABLE)
        cols = self._columns
        for record in table.records():
            try:
                obj = self._build_object(record, cols)
            except KeyError:
                # Provenance misconfiguration (unregistered source_file): fail
                # fast — this is a run-config error, never a per-record gap.
                raise
            except Exception as exc:  # torn record -> counted skip, never crash
                self._run.bump_skip(_SKIP_OBJECTS)
                _log.warning("skipping malformed datatable record: %s", type(exc).__name__)
                continue
            if obj is None:
                self._run.bump_skip(_SKIP_DNT_LESS)
                continue
            self._run.bump_coverage(_COV_OBJECTS)
            yield obj

    def links(self) -> Iterator[LinkRow]:
        """Yield every ``link_table`` row RAW in primary-index order (lazy).

        Yields:
            One :class:`LinkRow` per ``link_table`` row. Unresolved by design —
            Module 3/4 joins DNTs to objects to resolve memberships.

        Failure modes:
            A malformed row is skipped and counted (``ntds.malformed_links``).
            A provenance ``KeyError`` (unregistered ``source_file``) escapes
            rather than being counted as a per-row gap. A missing ``link_table``
            yields nothing (WARN-logged).
        """
        try:
            table = self._handle.table(_LINK_TABLE)
        except EseTableNotFoundError:
            _log.warning("no %r table present; no link rows surfaced", _LINK_TABLE)
            return
        for record in table.records():
            try:
                link = self._build_link(record)
            except KeyError:
                # Provenance misconfiguration: fail fast, never a per-row gap.
                raise
            except Exception as exc:  # malformed row -> counted skip, never crash
                self._run.bump_skip(_SKIP_LINKS)
                _log.warning("skipping malformed link_table record: %s", type(exc).__name__)
                continue
            self._run.bump_coverage(_COV_LINKS)
            yield link

    # -- internals ------------------------------------------------------------

    def _table(self, name: str) -> EseTable:
        try:
            return self._handle.table(name)
        except EseTableNotFoundError as exc:
            raise EseError(f"required NTDS table {name!r} not found") from exc

    def _build_object(self, record: EseRecord, cols: _ObjectColumns) -> ParsedObject | None:
        dnt_value = as_scalar(record.value(_DNT_COL))
        if not isinstance(dnt_value, int):
            # A datatable row without a DNT is not a usable object.
            return None
        dnt = dnt_value
        parent = as_scalar(record.value(_PDNT_COL))
        parent_dnt = parent if isinstance(parent, int) else None

        guid_raw = record.raw(cols.object_guid) if cols.object_guid else None
        sid_raw = record.raw(cols.object_sid) if cols.object_sid else None
        when_changed = self._timestamp(record, cols.when_changed)
        when_created = self._timestamp(record, cols.when_created)

        sd_id, raw_sd = self._resolve_sd(record, cols.nt_security_descriptor)
        if sd_id is not None and raw_sd is None:
            # The object names an sd_id absent from sd_table — a counted gap, not
            # a silent "no SD". Log the sd_id only (never descriptor bytes).
            self._run.bump_skip(_SKIP_UNRESOLVED_SD)
            _log.warning("object DNT %d references unresolved sd_id %d", dnt, sd_id)

        sam = as_scalar(record.value(cols.sam_account_name)) if cols.sam_account_name else None
        sam_str = sam if isinstance(sam, str) else None

        attributes = self._resolve_attributes(record, cols.resolved)

        # schema §2.3 allows whenChanged "and/or" whenCreated — fall back so an
        # object missing whenChanged still carries a directory timestamp.
        directory_timestamp = when_changed if when_changed is not None else when_created
        provenance = self._run.provenance_for(
            self._source_file,
            source_object_id=str(dnt),
            directory_timestamp=directory_timestamp,
        )
        return ParsedObject(
            dnt=dnt,
            parent_dnt=parent_dnt,
            object_guid=decode_guid(guid_raw),
            object_guid_raw=guid_raw,
            object_sid=decode_ntds_sid(sid_raw),
            object_sid_raw=sid_raw,
            sam_account_name=sam_str,
            sd_id=sd_id,
            raw_sd_bytes=raw_sd,
            when_changed=when_changed,
            when_created=when_created,
            attributes=attributes,
            provenance=provenance,
        )

    def _build_link(self, record: EseRecord) -> LinkRow:
        def as_int(column: str) -> int | None:
            value = as_scalar(record.value(column))
            return value if isinstance(value, int) else None

        link_dnt = as_int(_LINK_DNT)
        backlink_dnt = as_int(_LINK_BACKLINK_DNT)
        link_base = as_int(_LINK_BASE)
        provenance = self._run.provenance_for(
            self._source_file,
            source_object_id=f"link:{link_dnt}->{backlink_dnt}:base={link_base}",
        )
        return LinkRow(
            link_dnt=link_dnt,
            backlink_dnt=backlink_dnt,
            link_base=link_base,
            link_deltime=as_int(_LINK_DELTIME),
            link_deactivetime=as_int(_LINK_DEACTIVETIME),
            link_usnchanged=as_int(_LINK_USNCHANGED),
            link_ncdnt=as_int(_LINK_NCDNT),
            link_data=record.raw(_LINK_DATA),
            link_metadata=record.raw(_LINK_METADATA),
            provenance=provenance,
        )

    def _resolve_sd(
        self, record: EseRecord, sd_column: str | None
    ) -> tuple[int | None, bytes | None]:
        """Resolve an object's SD: raw ``nTSecurityDescriptor`` -> sd_id -> bytes."""
        if sd_column is None:
            return None, None
        raw = record.raw(sd_column)
        if raw is None:
            return None, None
        sd_id = int.from_bytes(raw, "little")
        return sd_id, self._sd_map.get(sd_id)

    @staticmethod
    def _timestamp(record: EseRecord, column: str | None) -> datetime | None:
        if column is None:
            return None
        value = as_scalar(record.value(column))
        return decode_ntds_timestamp(value) if isinstance(value, int) else None

    @staticmethod
    def _resolve_attributes(record: EseRecord, resolved: Mapping[str, str]) -> dict[str, EseValue]:
        out: dict[str, EseValue] = {}
        for column, ldap in resolved.items():
            value = record.value(column)
            if value is not None:
                out[ldap] = value
        return out

    def close(self) -> None:
        """Close the underlying ESE handle if this parse owns it. Idempotent."""
        if self._owns_handle:
            self._handle.close()

    def __enter__(self) -> ParsedNtds:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _resolve_object_columns(schema: NtdsSchema) -> _ObjectColumns:
    """Resolve the per-object fast-field columns + the resolved-attribute map."""
    return _ObjectColumns(
        object_sid=schema.column_for("objectSid"),
        object_guid=schema.column_for("objectGUID"),
        sam_account_name=schema.column_for("sAMAccountName"),
        nt_security_descriptor=schema.column_for("nTSecurityDescriptor"),
        when_changed=schema.column_for("whenChanged"),
        when_created=schema.column_for("whenCreated"),
        resolved=dict(schema.column_to_ldap),
    )


def _coerce_bytes(value: object) -> bytes | None:
    """Return ``value`` as ``bytes`` if byte-like, else ``None`` (pure)."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return None


def _build_sd_map(handle: EseHandle) -> dict[int, bytes]:
    """Build the ``{sd_id: sd_value}`` map from ``sd_table`` (eager, deduped).

    ``sd_value`` is read via the decoded value path (not the raw-bytes hatch):
    larger descriptors are stored out-of-row as ESE long values, and only the
    decoded accessor resolves the full blob — the raw accessor returns just the
    4-byte long-value reference. The resolved blob is the untouched self-relative
    ``SECURITY_DESCRIPTOR`` that Module 3 will hand to an SD parser.

    SDs are deduplicated in ``sd_table`` so this set is bounded. A missing
    ``sd_table`` yields an empty map (WARN-logged); a malformed row is skipped.
    """
    try:
        table = handle.table(_SD_TABLE)
    except EseTableNotFoundError:
        _log.warning("no %r table present; object SD bytes will be unavailable", _SD_TABLE)
        return {}
    sd_map: dict[int, bytes] = {}
    for record in table.records():
        sd_id = as_scalar(record.value(_SD_ID_COL))
        if not isinstance(sd_id, int):
            continue
        sd_value = _coerce_bytes(as_scalar(record.value(_SD_VALUE_COL)))
        if sd_value is not None:
            sd_map[sd_id] = sd_value
    return sd_map


def parse_ntds(
    handle: EseHandle,
    run: IngestRun,
    *,
    source_file: str = "ntds.dit",
    owns_handle: bool = False,
) -> ParsedNtds:
    """Build the structural parse of an already-open NTDS ``.dit`` handle.

    Dependency-injected entry point (fixture-friendly): the caller owns the
    :class:`EseHandle` unless ``owns_handle=True``. Reads the clean/dirty state
    up-front (WARN-logs a non-clean state), builds the schema and the
    ``sd_table`` map, then returns a :class:`ParsedNtds` ready to stream.

    Inputs:
        handle: an open ESE handle for the ``.dit``.
        run: the :class:`IngestRun` providing provenance; its artifact for
            ``source_file`` must already be registered (``add_artifact``).
        source_file: the logical artifact name for provenance (default
            ``"ntds.dit"``).
        owns_handle: if ``True``, the returned parse closes ``handle`` on close.

    Returns:
        A :class:`ParsedNtds`.

    Failure modes:
        Raises ``KeyError`` *up-front* if ``source_file`` was never registered on
        ``run`` (``IngestRun.add_artifact`` first) — a fact must never be produced
        without provenance, and failing fast here stops a run-config error from
        masquerading as every record being malformed. Raises :class:`EseError`
        if ``datatable`` is absent. Malformed individual records degrade to
        counted skips during iteration, never here.
    """
    _require_registered_source(run, source_file)

    try:
        datatable = handle.table(_DATATABLE)
    except EseTableNotFoundError as exc:
        raise EseError(f"required NTDS table {_DATATABLE!r} not found") from exc

    db_state = handle.database_state()
    if db_state.is_clean is False:
        _log.warning(
            "Source %s is in a %s state (dbstate=%d; required log generations "
            "%d-%d). Transaction logs cannot be replayed offline: results reflect "
            "the database as of its last checkpoint. Changes committed only to the "
            "logs may be MISSING, and in-flight/uncommitted state may be PRESENT "
            "that a proper 'esentutl /r' recovery would ROLL BACK. Treat as a "
            "point-in-time snapshot, not a recovered database.",
            source_file,
            db_state.label,
            db_state.raw_dbstate,
            db_state.gen_min_required,
            db_state.gen_max_required,
        )
    elif db_state.is_clean is None:
        _log.warning(
            "Source %s has an indeterminate database state (%s, dbstate=%d; "
            "required log generations %d-%d); treating results as lower-confidence.",
            source_file,
            db_state.label,
            db_state.raw_dbstate,
            db_state.gen_min_required,
            db_state.gen_max_required,
        )

    schema = build_schema(datatable)
    # Surface schema-build gaps on the run so no drop/resolution-miss is silent.
    if schema.skipped_schema_records:
        run.bump_skip(_SKIP_SCHEMA_RECORDS, schema.skipped_schema_records)
    if schema.unmapped_columns:
        run.bump_skip(_GAP_UNMAPPED_COLUMNS, len(schema.unmapped_columns))

    sd_map = _build_sd_map(handle)
    return ParsedNtds(
        handle,
        run,
        schema,
        db_state,
        sd_map,
        source_file=source_file,
        owns_handle=owns_handle,
    )


def _require_registered_source(run: IngestRun, source_file: str) -> None:
    """Fail fast if ``source_file`` has no registered artifact on ``run``.

    Raises:
        KeyError: if no artifact with this ``source_file`` was registered via
            ``IngestRun.add_artifact`` — refusing to parse without provenance.
    """
    if not any(artifact.source_file == source_file for artifact in run.inputs):
        raise KeyError(
            f"source_file {source_file!r} is not registered on the ingest run; "
            f"call IngestRun.add_artifact before parsing (provenance is mandatory)"
        )


def open_ntds(
    path: Path | str,
    run: IngestRun,
    *,
    source_file: str = "ntds.dit",
) -> ParsedNtds:
    """Open an NTDS ``.dit`` by path and return an owning :class:`ParsedNtds`.

    Convenience over :func:`parse_ntds`: validates the (untrusted) path and
    opens the ESE handle via :func:`wraith.parsing.ese_backend.open_ese`, then
    builds the parse. The returned parse owns the handle — use it as a context
    manager or call :meth:`ParsedNtds.close`.

    Inputs:
        path: filesystem path to the ``ntds.dit``.
        run: the :class:`IngestRun` providing provenance (artifact registered).
        source_file: the logical artifact name for provenance.

    Returns:
        A :class:`ParsedNtds` that owns and will close the handle.

    Failure modes:
        Raises :class:`~wraith.parsing.ese_backend.EseOpenError` on a bad path /
        non-ESE file; :class:`EseError` if ``datatable`` is absent; ``KeyError``
        if ``source_file`` is unregistered on ``run``. The handle is closed on
        any failure during build so no descriptor leaks.
    """
    handle = open_ese(path)
    try:
        return parse_ntds(handle, run, source_file=source_file, owns_handle=True)
    except Exception:
        handle.close()
        raise
