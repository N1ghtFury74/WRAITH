"""DI unit tests proving Module 2a counted-gap paths are reachable, not swallowed.

These use a tiny fake ESE backend wrapped by the *real* ``EseHandle`` /
``EseTable`` / ``EseRecord`` so the production code paths run unchanged. They
prove: an unresolvable ``sd_id`` is counted; an unregistered ``source_file``
fails fast (not 3834 "malformed"); a malformed schema cell is counted/surfaced;
a column resolving only via ``msDS-IntId`` is mapped. They do NOT touch the
tester's gate files.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.parsing import ese_backend as eb
from wraith.parsing.ntds import parse_ntds
from wraith.parsing.schema import build_schema

_SHA = "a" * 64


# --- tiny fake backend -------------------------------------------------------


class _Rec:
    """A fake backend record: ``get(attr, raw=False)`` over two dicts."""

    def __init__(self, values: dict[str, object], raws: dict[str, bytes] | None = None) -> None:
        self._values = values
        self._raws = raws or {}

    def get(self, attr: str, raw: bool = False) -> object:
        return self._raws.get(attr) if raw else self._values.get(attr)


class _RaisingRec:
    """A fake backend record that raises on one column (malformed cell)."""

    def __init__(self, values: dict[str, object], bad_column: str) -> None:
        self._values = values
        self._bad = bad_column

    def get(self, attr: str, raw: bool = False) -> object:
        if attr == self._bad:
            raise ValueError("torn value")
        return self._values.get(attr)


class _Table:
    def __init__(self, name: str, columns: list[str], records: list[object]) -> None:
        self.name = name
        self.column_names = columns
        self._records = records

    def records(self) -> Iterator[object]:
        return iter(self._records)


class _Header:
    dbstate = 3
    lGenMinRequired = 0
    lGenMaxRequired = 0


class _Db:
    def __init__(self, tables: dict[str, _Table]) -> None:
        self._tables = tables
        self.header = _Header()

    def table(self, name: str) -> _Table:
        if name not in self._tables:
            raise KeyError(name)
        return self._tables[name]


def _handle(tables: dict[str, _Table]) -> eb.EseHandle:
    return eb.EseHandle(_Db(tables), None, Path("fake.dit"), eb._CoverageStats())


def _run(*, register: bool = True) -> IngestRun:
    run = IngestRun(case_id="t", operator="t")
    if register:
        run.add_artifact(
            ArtifactInput(
                source_file="ntds.dit",
                abs_path_or_ref="/x/ntds.dit",
                size_bytes=1,
                image_sha256=_SHA,
                mode="reference",
            )
        )
    return run


# Bootstrap + common attributeSchema rows (attributeID in ATTc131102, name in ATTm131532).
def _attr(att_id: int, ldap: str, *, msds_intid: int | None = None) -> _Rec:
    values: dict[str, object] = {"ATTc131102": att_id, "ATTm131532": ldap}
    if msds_intid is not None:
        values["ATTj591540"] = msds_intid
    return _Rec(values)


_SCHEMA_ATTRS = [
    _attr(131102, "attributeID"),
    _attr(131532, "lDAPDisplayName"),
    _attr(589972, "schemaIDGUID"),
    _attr(591540, "msDS-IntId"),
    _attr(590045, "sAMAccountName"),
    _attr(589970, "objectSid"),
    _attr(589826, "objectGUID"),
    _attr(131353, "nTSecurityDescriptor"),
    _attr(131075, "whenChanged"),
    _attr(131074, "whenCreated"),
]

_DATATABLE_COLUMNS = [
    "DNT_col",
    "PDNT_col",
    "ATTc131102",
    "ATTm131532",
    "ATTk589972",
    "ATTj591540",
    "ATTm590045",
    "ATTr589970",
    "ATTk589826",
    "ATTp131353",
    "ATTl131075",
    "ATTl131074",
    "ATTm591999",  # the dynamic attribute's storage column (msDS-IntId target)
]


def test_unregistered_source_file_fails_fast() -> None:
    handle = _handle({"datatable": _Table("datatable", _DATATABLE_COLUMNS, list(_SCHEMA_ATTRS))})
    run = _run(register=False)
    with pytest.raises(KeyError, match="not registered"):
        parse_ntds(handle, run)
    # Fail-fast means NO per-record "malformed" counting happened.
    assert run.skip_counts == {}
    assert run.coverage_counts == {}


def test_unresolvable_sd_id_is_counted() -> None:
    obj = _Rec(
        {"DNT_col": 100, "PDNT_col": 1},
        raws={"ATTp131353": (999).to_bytes(8, "little")},  # sd_id 999 absent from sd_table
    )
    tables = {
        "datatable": _Table("datatable", _DATATABLE_COLUMNS, [*_SCHEMA_ATTRS, obj]),
        "sd_table": _Table(
            "sd_table", ["sd_id", "sd_value"], [_Rec({"sd_id": 1, "sd_value": b"x"})]
        ),
        "link_table": _Table("link_table", ["link_DNT"], []),
    }
    run = _run()
    parsed = parse_ntds(_handle(tables), run)
    objs = [o for o in parsed.objects() if o.dnt == 100]
    assert len(objs) == 1
    assert objs[0].sd_id == 999
    assert objs[0].raw_sd_bytes is None
    assert run.skip_counts.get("ntds.unresolved_sd") == 1


def test_malformed_schema_cell_is_counted_and_excluded() -> None:
    # A schema row whose attributeID cell is torn: it must be dropped from the
    # resolved map AND surfaced as a counted gap (ESE value_parse_errors), never
    # silently mapped wrong.
    bad = _RaisingRec({"ATTc131102": 777777, "ATTm131532": "bogusAttr"}, bad_column="ATTc131102")
    handle = _handle({"datatable": _Table("datatable", _DATATABLE_COLUMNS, [*_SCHEMA_ATTRS, bad])})
    schema = build_schema(handle.table("datatable"))
    assert "bogusAttr" not in schema.attributes_by_ldap
    assert handle.coverage().value_parse_errors >= 1


def test_msds_intid_fallback_maps_column() -> None:
    # A dynamically-assigned attribute (ATTRTYP 0x80000001) whose attributeID has
    # NO column, but whose msDS-IntId (591999) maps to an existing ATTm591999.
    dynamic = _attr(0x80000001, "ms-Mcs-AdmPwd", msds_intid=591999)
    handle = _handle(
        {"datatable": _Table("datatable", _DATATABLE_COLUMNS, [*_SCHEMA_ATTRS, dynamic])}
    )
    schema = build_schema(handle.table("datatable"))
    assert schema.column_for("ms-Mcs-AdmPwd") == "ATTm591999"
    assert schema.column_to_ldap["ATTm591999"] == "ms-Mcs-AdmPwd"


def test_whencreated_fallback_for_directory_timestamp() -> None:
    # whenChanged absent, whenCreated present -> provenance timestamp uses created.
    obj = _Rec({"DNT_col": 5, "ATTl131074": 13244838964})  # whenCreated only
    tables = {
        "datatable": _Table("datatable", _DATATABLE_COLUMNS, [*_SCHEMA_ATTRS, obj]),
        "sd_table": _Table("sd_table", ["sd_id", "sd_value"], []),
        "link_table": _Table("link_table", ["link_DNT"], []),
    }
    run = _run()
    parsed = parse_ntds(_handle(tables), run)
    only = next(o for o in parsed.objects() if o.dnt == 5)
    assert only.when_changed is None
    assert only.when_created is not None
    assert only.provenance.directory_timestamp == only.when_created
