"""NTDS schema extraction — the ``ATT<type><id>`` column resolver.

NTDS stores every object attribute in a ``datatable`` column named
``ATT<type-letter><internal-id>`` (e.g. ``ATTm590045`` = ``sAMAccountName``,
``ATTr589970`` = ``objectSid``, ``ATTp131353`` = ``nTSecurityDescriptor``). The
trailing integer is the attribute's **internal id**, which is exactly the value
stored in each ``attributeSchema`` object's ``attributeID`` column. This module
reconstructs the column ↔ attribute map *from the schema objects in the DIT
itself* (no hard-coded attribute table beyond the two bootstrap ids needed to
read the schema), so it is portable across forest schema versions.

Scope (structural only): it builds and exposes the resolved maps plus the raw
schema records. It does **not** interpret rights-GUID → edge semantics,
property sets, or UAC bits — those belong to Module 3.

Bootstrap ids (public [MS-ADA3]/[MS-ADA1] facts, reimplemented originally):

* ``lDAPDisplayName`` internal id ``131532`` → column ``ATTm131532``.
* ``attributeID`` internal id ``131102`` → column ``ATTc131102``.

These two seed the resolution; every other column (``schemaIDGUID``,
``governsID``, ``rightsGuid``, ``whenChanged``, ...) is then found *by name* via
the map this module builds.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from wraith.parsing.ese_backend import EseRecord, EseTable, EseValue
from wraith.parsing.ntds_values import as_list, as_scalar, decode_guid

_log = logging.getLogger(__name__)

# --- bootstrap column names (the only hard-coded internal ids) ---------------
#: ``lDAPDisplayName`` — seeds every attribute's human name.
LDAP_DISPLAY_NAME_COLUMN: str = "ATTm131532"
#: ``attributeID`` (internal integer form) — seeds the column↔attribute join.
ATTRIBUTE_ID_COLUMN: str = "ATTc131102"
# -----------------------------------------------------------------------------

#: LDAP display names resolved via the bootstrap map and used to read schema
#: objects. Resolved to their ``ATT`` column at build time (never hard-coded).
_SCHEMA_ID_GUID = "schemaIDGUID"
_GOVERNS_ID = "governsID"
_MSDS_INTID = "msDS-IntId"
_RIGHTS_GUID = "rightsGuid"
_DISPLAY_NAME = "displayName"
_APPLIES_TO = "appliesTo"
_VALID_ACCESSES = "validAccesses"

#: A sparse raw schema record: only the populated columns of one schema object.
RawRecord = Mapping[str, EseValue]


class AttributeDef(BaseModel):
    """A resolved ``attributeSchema`` definition.

    Fields:
        internal_id: the attribute's internal id (the trailing integer of its
            ``datatable`` column name and the value of its ``attributeID``).
        ldap_display_name: the ``lDAPDisplayName`` (e.g. ``sAMAccountName``).
        schema_id_guid: the ``schemaIDGUID`` as a dashed GUID string; this is
            the GUID an ACE ``ObjectType`` references for per-property rights
            (Module 3 consumes it). ``None`` if absent/unreadable.
        msds_intid: the ``msDS-IntId`` override if present, else ``None``.
        column_name: the ``datatable`` column that stores this attribute's
            values (e.g. ``ATTm590045``), or ``None`` if no such column exists
            in this DIT (the attribute is defined but never populated).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    internal_id: int
    ldap_display_name: str
    schema_id_guid: str | None
    msds_intid: int | None
    column_name: str | None


class ClassDef(BaseModel):
    """A resolved ``classSchema`` definition.

    Fields:
        governs_id: the class's ``governsID`` internal id.
        ldap_display_name: the class ``lDAPDisplayName`` (e.g. ``user``).
        schema_id_guid: the class ``schemaIDGUID`` as a dashed GUID string, or
            ``None`` if absent/unreadable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    governs_id: int
    ldap_display_name: str
    schema_id_guid: str | None


class ExtendedRight(BaseModel):
    """A resolved ``controlAccessRight`` (Configuration-NC extended right).

    These carry the rights-GUIDs behind DCSync / force-change-password / etc.
    Module 2 surfaces them verbatim; Module 3 maps rights-GUID → edge by name.

    Fields:
        rights_guid: the ``rightsGuid`` (lowercase dashed GUID string).
        display_name: the ``displayName`` (e.g. ``Reset Password``), or ``None``.
        applies_to: the ``appliesTo`` class schemaIDGUIDs (GUID strings), sorted.
        valid_accesses: the ``validAccesses`` access-mask integer, or ``None``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rights_guid: str
    display_name: str | None
    applies_to: tuple[str, ...]
    valid_accesses: int | None


@dataclass(frozen=True)
class NtdsSchema:
    """The resolved NTDS schema: column resolver + raw schema records.

    All maps are built from the schema objects in the DIT itself. Collections
    exposed for iteration are deterministically ordered.

    Attributes:
        column_to_ldap: ``ATT`` column name → ``lDAPDisplayName``.
        ldap_to_column: ``lDAPDisplayName`` → ``ATT`` column name.
        attributes_by_ldap: ``lDAPDisplayName`` → :class:`AttributeDef`.
        attributes_by_internal_id: internal id → :class:`AttributeDef`.
        classes_by_ldap: ``lDAPDisplayName`` → :class:`ClassDef`.
        extended_rights_by_guid: ``rightsGuid`` → :class:`ExtendedRight`.
        raw_attribute_records: sparse raw records of all ``attributeSchema``
            objects (sorted by internal id).
        raw_class_records: sparse raw records of all ``classSchema`` objects
            (sorted by governsID).
        raw_right_records: sparse raw records of all ``controlAccessRight``
            objects (sorted by rightsGuid).
        skipped_schema_records: count of schema records dropped because they were
            malformed/unreadable during the build — a surfaced, counted gap (the
            caller records it on the ingest run), never a silent drop.
        unmapped_columns: ``ATT`` columns present in the ESE catalog whose
            internal id (and msDS-IntId) resolved to no ``attributeSchema``
            object, i.e. columns we could not name — a surfaced resolution gap.
    """

    column_to_ldap: Mapping[str, str]
    ldap_to_column: Mapping[str, str]
    attributes_by_ldap: Mapping[str, AttributeDef]
    attributes_by_internal_id: Mapping[int, AttributeDef]
    classes_by_ldap: Mapping[str, ClassDef]
    extended_rights_by_guid: Mapping[str, ExtendedRight]
    raw_attribute_records: tuple[RawRecord, ...]
    raw_class_records: tuple[RawRecord, ...]
    raw_right_records: tuple[RawRecord, ...]
    skipped_schema_records: int
    unmapped_columns: tuple[str, ...]

    def column_for(self, ldap_display_name: str) -> str | None:
        """Return the ``ATT`` column that stores ``ldap_display_name``, or ``None``.

        Inputs:
            ldap_display_name: the attribute's LDAP display name.

        Returns:
            The column name, or ``None`` if the attribute is unknown or has no
            column in this DIT.

        Failure modes:
            Never raises.
        """
        return self.ldap_to_column.get(ldap_display_name)


def _parse_internal_id_from_column(column: str) -> int | None:
    """Return the trailing internal id of an ``ATT<type><id>`` column, or ``None``.

    ``ATTm590045`` → ``590045``. Non-``ATT`` columns (``DNT_col`` etc.) and
    malformed names return ``None`` (pure; never raises).
    """
    if not column.startswith("ATT") or len(column) < 5:
        return None
    digits = column[4:]
    if not digits.isdigit():
        return None
    return int(digits)


def _sparse_raw(record: EseRecord) -> dict[str, EseValue]:
    """Return a dict of this record's populated (non-``None``) columns."""
    out: dict[str, EseValue] = {}
    for column in record.columns:
        value = record.value(column)
        if value is not None:
            out[column] = value
    return out


def _guid_from_raw(record: EseRecord, column: str | None) -> str | None:
    """Decode the GUID stored in ``column`` of ``record`` (raw bytes), or ``None``."""
    if column is None:
        return None
    return decode_guid(record.raw(column))


def build_schema(table: EseTable) -> NtdsSchema:
    """Build the resolved :class:`NtdsSchema` from a ``datatable``.

    One streaming pass over ``datatable``: it first seeds the column↔attribute
    join from the two bootstrap ids, classifies each schema object
    (``attributeSchema`` / ``classSchema`` / ``controlAccessRight``) by which
    key column it populates, and resolves per-object fields *by name* via the
    column map built from the attribute objects.

    Inputs:
        table: the ``datatable`` :class:`EseTable` (from the ESE backend).

    Returns:
        A fully-populated :class:`NtdsSchema`. Malformed schema records are
        skipped and surfaced via ``NtdsSchema.skipped_schema_records``; columns
        that resolve to no attribute are surfaced via
        ``NtdsSchema.unmapped_columns``. The caller records both on the ingest
        run so no drop is silent; they never abort the build.

    Failure modes:
        Propagates only a catastrophic backend failure during iteration. A
        single unreadable schema record degrades to a counted skip, not raised.
    """
    attr_defs: dict[str, AttributeDef] = {}
    attr_by_id: dict[int, AttributeDef] = {}
    class_defs: dict[str, ClassDef] = {}
    rights_defs: dict[str, ExtendedRight] = {}
    raw_attrs: list[RawRecord] = []
    raw_classes: list[RawRecord] = []
    raw_rights: list[RawRecord] = []

    # Pass 1: attributeSchema objects (seeded by the two bootstrap columns).
    # Build the column↔attribute map first so classes/rights can resolve by name.
    attribute_records, skipped = _collect_attribute_records(table)
    column_to_ldap: dict[str, str] = {}
    ldap_to_column: dict[str, str] = {}
    # Internal id -> ATT column, built once (avoids a per-attribute column scan).
    id_to_column = _index_columns(table.column_names)

    # Preliminary primary-id mapping so the schema's own helper columns
    # (schemaIDGUID / msDS-IntId) resolve before the msDS-IntId fallback runs.
    for internal_id, ldap, _record in attribute_records:
        column_name = id_to_column.get(internal_id)
        if column_name is not None:
            column_to_ldap.setdefault(column_name, ldap)
            ldap_to_column.setdefault(ldap, column_name)

    # Resolve the schema's own helper columns *by name* (schema-driven).
    schema_guid_col = ldap_to_column.get(_SCHEMA_ID_GUID)
    msds_intid_col = ldap_to_column.get(_MSDS_INTID)

    for internal_id, ldap, record in attribute_records:
        msds_intid = (
            _coerce_int(as_scalar(record.value(msds_intid_col)))
            if msds_intid_col is not None
            else None
        )
        # Match-then-fallback: an attribute in the 0x80000000-0xBFFFFFFF ATTRTYP
        # range (dynamically assigned, e.g. LAPS/extension attrs) is stored under
        # its msDS-IntId column, not its attributeID (MS-ADTS §3.1.1.2.6).
        column_name = id_to_column.get(internal_id)
        if column_name is None and msds_intid is not None:
            column_name = id_to_column.get(msds_intid)
        if column_name is not None:
            column_to_ldap.setdefault(column_name, ldap)
            ldap_to_column.setdefault(ldap, column_name)

        attr = AttributeDef(
            internal_id=internal_id,
            ldap_display_name=ldap,
            schema_id_guid=_guid_from_raw(record, schema_guid_col),
            msds_intid=msds_intid,
            column_name=column_name,
        )
        attr_defs.setdefault(ldap, attr)
        attr_by_id.setdefault(internal_id, attr)
        raw_attrs.append(_sparse_raw(record))

    # Resolve the remaining key columns by name now that the map exists.
    governs_col = ldap_to_column.get(_GOVERNS_ID)
    rights_col = ldap_to_column.get(_RIGHTS_GUID)
    display_col = ldap_to_column.get(_DISPLAY_NAME)
    applies_col = ldap_to_column.get(_APPLIES_TO)
    valid_col = ldap_to_column.get(_VALID_ACCESSES)

    # Pass 2: classSchema + controlAccessRight objects.
    for record in table.records():
        try:
            governs = _coerce_int(as_scalar(record.value(governs_col))) if governs_col else None
            rights = as_scalar(record.value(rights_col)) if rights_col else None
            ldap_name = _coerce_str(as_scalar(record.value(LDAP_DISPLAY_NAME_COLUMN)))

            if governs is not None and ldap_name is not None:
                class_def = ClassDef(
                    governs_id=governs,
                    ldap_display_name=ldap_name,
                    schema_id_guid=_guid_from_raw(record, schema_guid_col),
                )
                class_defs.setdefault(ldap_name, class_def)
                raw_classes.append(_sparse_raw(record))
            elif rights is not None:
                rights_guid = _coerce_str(rights)
                if rights_guid is not None:
                    right = ExtendedRight(
                        rights_guid=rights_guid.lower(),
                        display_name=(
                            _coerce_str(as_scalar(record.value(display_col)))
                            if display_col
                            else None
                        ),
                        applies_to=_applies_to(record, applies_col),
                        valid_accesses=(
                            _coerce_int(as_scalar(record.value(valid_col))) if valid_col else None
                        ),
                    )
                    rights_defs.setdefault(right.rights_guid, right)
                    raw_rights.append(_sparse_raw(record))
        except Exception as exc:  # malformed schema record -> counted skip, never crash
            skipped += 1
            _log.warning("skipping malformed schema record: %s", type(exc).__name__)
            continue

    # Surface every ATT column we could not name as an explicit resolution gap.
    unmapped = tuple(sorted(set(id_to_column.values()) - set(column_to_ldap)))
    if unmapped:
        _log.warning("schema: %d ATT column(s) resolved to no attribute", len(unmapped))

    return NtdsSchema(
        column_to_ldap=dict(sorted(column_to_ldap.items())),
        ldap_to_column=dict(sorted(ldap_to_column.items())),
        attributes_by_ldap=dict(sorted(attr_defs.items())),
        attributes_by_internal_id=dict(sorted(attr_by_id.items())),
        classes_by_ldap=dict(sorted(class_defs.items())),
        extended_rights_by_guid=dict(sorted(rights_defs.items())),
        raw_attribute_records=tuple(
            sorted(raw_attrs, key=lambda r: _sort_key_int(r.get(ATTRIBUTE_ID_COLUMN)))
        ),
        raw_class_records=tuple(
            sorted(
                raw_classes,
                key=lambda r: _sort_key_int(r.get(governs_col) if governs_col else None),
            )
        ),
        raw_right_records=tuple(
            sorted(raw_rights, key=lambda r: _coerce_str(as_scalar(r.get(rights_col))) or "")
            if rights_col
            else raw_rights
        ),
        skipped_schema_records=skipped,
        unmapped_columns=unmapped,
    )


def _collect_attribute_records(
    table: EseTable,
) -> tuple[list[tuple[int, str, EseRecord]], int]:
    """Collect attributeSchema records and the count skipped as malformed.

    An ``attributeSchema`` object is identified structurally: it populates both
    the bootstrap ``attributeID`` and ``lDAPDisplayName`` columns. A record that
    raises while being read is skipped and counted (never raised).

    Returns:
        ``(records, skipped)`` where ``records`` is the list of
        ``(internal_id, ldap_display_name, record)`` tuples and ``skipped`` is
        the number of records dropped because reading them raised.
    """
    out: list[tuple[int, str, EseRecord]] = []
    skipped = 0
    for record in table.records():
        try:
            attribute_id = _coerce_int(as_scalar(record.value(ATTRIBUTE_ID_COLUMN)))
            ldap = _coerce_str(as_scalar(record.value(LDAP_DISPLAY_NAME_COLUMN)))
        except Exception as exc:  # malformed -> counted skip, never crash
            skipped += 1
            _log.warning("skipping malformed attribute record: %s", type(exc).__name__)
            continue
        if attribute_id is not None and ldap is not None:
            out.append((attribute_id, ldap, record))
    return out, skipped


def _index_columns(column_names: Iterable[str]) -> dict[int, str]:
    """Build an ``internal id -> ATT column name`` index (one pass over columns)."""
    index: dict[int, str] = {}
    for column in column_names:
        internal_id = _parse_internal_id_from_column(column)
        if internal_id is not None:
            index.setdefault(internal_id, column)
    return index


def _applies_to(record: EseRecord, column: str | None) -> tuple[str, ...]:
    """Return the sorted, lowercased ``appliesTo`` GUID strings for a right.

    Lowercasing matches the lowercased ``schemaIDGUID``/``objectGUID`` forms so
    Module 3 can join rights to classes without case normalisation.
    """
    if column is None:
        return ()
    values = [_coerce_str(v) for v in as_list(record.value(column))]
    return tuple(sorted(v.lower() for v in values if v is not None))


def _coerce_int(value: object) -> int | None:
    """Return ``value`` as ``int`` if it is a non-boolean integer, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _coerce_str(value: object) -> str | None:
    """Return ``value`` as a non-empty ``str``, else ``None``."""
    if isinstance(value, str) and value:
        return value
    return None


def _sort_key_int(value: object) -> int:
    """Deterministic integer sort key for a raw record (missing/non-int -> -1)."""
    coerced = _coerce_int(as_scalar(value))
    return coerced if coerced is not None else -1
