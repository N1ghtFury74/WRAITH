"""Surfacing tests for the CA-host adapter (ESC11/ESC16/DCOM + rights glossary).

Three layers for the "make the CA-host adapter outputs surfaceable" module:

  1. glossary     — ManageCA / ManageCertificates / ADCSESC6a now have authored,
                    hunter-useful entries and are covered by the engine-kind oracle.
  2. persistence  — ``persist_ca_node_findings`` writes the ESC11/ESC16/DCOM node
                    findings deterministically, carrying the CA-host HIVE provenance,
                    and is idempotent on re-run; no secret bytes are stored.
  3. dossier API  — the EnterpriseCA dossier shows ESC11/ESC16; the CA host Computer
                    dossier shows the DCOM ``EnableDCOM=Y/N`` summary (never an SD);
                    a non-CA dossier is byte-UNCHANGED (the key is dropped).
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import duckdb

from wraith.analysis.adcs_esc import (
    NODE_PROP_DCOM,
    NODE_PROP_ESC11,
    NODE_PROP_ESC16,
    CaNodeFinding,
)
from wraith.analysis.ca_findings_store import persist_ca_node_findings
from wraith.api.dossier import build_dossier
from wraith.api.rights_glossary import ENGINE_EDGE_KINDS, build_glossary
from wraith.api.store import StoreReader
from wraith.common.determinism import canonical_json
from wraith.model.store import create_canonical_tables, create_edge_tables
from wraith.provenance.models import ProvenanceStruct

FOREST = "f"
DOM = "S-1-5-21-10-20-30"
RUN = UUID("00000000-0000-0000-0000-000000000001")
SCOPING: tuple[str, str | None, str | None] = (FOREST, DOM, "t.local")
_PROV_ENTITY = {
    "source_file": "ntds.dit",
    "image_sha256": "a" * 64,
    "source_object_id": None,
    "directory_timestamp": None,
    "ingest_run_id": str(RUN),
}


def _mem_store() -> tuple[duckdb.DuckDBPyConnection, StoreReader]:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    create_edge_tables(con)
    return con, StoreReader(con, Path(":memory:"))


def _enterprise_ca(con: duckdb.DuckDBPyConnection, node: str, name: str) -> None:
    con.execute(
        "INSERT INTO adcs (node_id,name,adcs_type,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            node,
            name,
            "EnterpriseCA",
            FOREST,
            DOM,
            "t.local",
            {**_PROV_ENTITY, "source_object_id": node},
        ],
    )


def _computer(con: duckdb.DuckDBPyConnection, node: str, sam: str) -> None:
    con.execute(
        "INSERT INTO principal (node_id,object_sid,principal_type,samaccountname,uac_flags,"
        "enabled,admincount,spns,sid_history,forest_id,domain_id,domain_fqdn,provenance) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            node,
            f"{DOM}-1105",
            "Computer",
            sam,
            4096,
            True,
            0,
            [],
            [],
            FOREST,
            DOM,
            "t.local",
            {**_PROV_ENTITY, "source_object_id": node},
        ],
    )


def _hive_prov(source_file: str) -> ProvenanceStruct:
    return ProvenanceStruct(
        source_file=source_file,
        image_sha256="b" * 64,
        source_object_id=None,
        directory_timestamp=None,
        ingest_run_id=RUN,
    )


def _findings(ca_node: str, host_node: str) -> list[CaNodeFinding]:
    sys_prov = _hive_prov("CAHOST/SYSTEM")
    soft_prov = _hive_prov("CAHOST/SOFTWARE")
    return [
        CaNodeFinding(ca_node, NODE_PROP_ESC11, True, "CertSvc\\...\\InterfaceFlags", sys_prov),
        CaNodeFinding(
            ca_node, NODE_PROP_ESC16, True, "CertSvc\\...\\DisableExtensionList", sys_prov
        ),
        CaNodeFinding(host_node, NODE_PROP_DCOM, "EnableDCOM=Y", "Microsoft\\Ole", soft_prov),
    ]


# --- LAYER 1: glossary -------------------------------------------------------
def test_glossary_covers_ca_host_edges() -> None:
    """ManageCA / ManageCertificates / ADCSESC6a are authored + oracle-covered."""
    g = build_glossary()
    assert g.counted_gaps == {}  # no engine kind lacks an entry
    for kind in ("ManageCA", "ManageCertificates", "ADCSESC6a"):
        assert kind in ENGINE_EDGE_KINDS
        assert kind in g.edges
    # content is accurate + hunter-useful (ESC7 / SAN-flag framing)
    assert "ESC7" in g.edges["ManageCA"].why
    assert "approve" in g.edges["ManageCertificates"].why.lower()
    assert "esc1" in g.edges["ADCSESC6a"].why.lower()


# --- LAYER 2: persistence ----------------------------------------------------
def test_persist_is_deterministic_idempotent_and_carries_hive_provenance() -> None:
    con, _reader = _mem_store()
    try:
        _enterprise_ca(con, "n-entca", "corp-ca")
        _computer(con, "n-host", "CA01$")
        findings = _findings("n-entca", "n-host")

        inserted = persist_ca_node_findings(con, findings, scoping=SCOPING)
        assert inserted == 3
        # idempotent: a second identical run inserts nothing (stable ids).
        assert persist_ca_node_findings(con, findings, scoping=SCOPING) == 0

        rows = con.execute(
            "SELECT node_id, prop, value, provenance FROM ca_node_finding ORDER BY finding_id"
        ).fetchall()
        assert len(rows) == 3
        by_prop = {r[1]: r for r in rows}
        # ESC11/ESC16 carry the SYSTEM-hive provenance + the registry value path.
        assert by_prop[NODE_PROP_ESC11][2] == "true"
        assert by_prop[NODE_PROP_ESC11][3]["source_file"] == "CAHOST/SYSTEM"
        assert by_prop[NODE_PROP_ESC11][3]["source_object_id"].endswith("InterfaceFlags")
        # DCOM carries the SOFTWARE-hive provenance + the Y/N summary (no SD bytes).
        assert by_prop[NODE_PROP_DCOM][2] == "EnableDCOM=Y"
        assert by_prop[NODE_PROP_DCOM][3]["source_file"] == "CAHOST/SOFTWARE"
        assert "EnableDCOM" in by_prop[NODE_PROP_DCOM][2] and "O:" not in by_prop[NODE_PROP_DCOM][2]
    finally:
        con.close()


def test_persist_empty_findings_writes_nothing_but_provisions_table() -> None:
    con, reader = _mem_store()
    try:
        assert persist_ca_node_findings(con, [], scoping=SCOPING) == 0
        # the table exists (reader degrades cleanly) and there are no rows / no gap.
        assert reader.ca_node_findings("anything") == []
    finally:
        con.close()


# --- LAYER 3: dossier API ----------------------------------------------------
def test_enterprise_ca_dossier_shows_esc11_esc16() -> None:
    con, reader = _mem_store()
    try:
        _enterprise_ca(con, "n-entca", "corp-ca")
        _computer(con, "n-host", "CA01$")
        persist_ca_node_findings(con, _findings("n-entca", "n-host"), scoping=SCOPING)

        d = build_dossier(reader, "n-entca")
        assert d is not None and d.kind == "EnterpriseCA"
        props = {f.prop for f in d.ca_node_findings}
        assert props == {NODE_PROP_ESC11, NODE_PROP_ESC16}
        for f in d.ca_node_findings:
            assert f.title and f.caption
            assert "CA host" in f.caption  # honest: needed the CA host hive
            assert f.provenance.source_file == "CAHOST/SYSTEM"
        # the key IS present in the serialized dossier for a CA node.
        assert "ca_node_findings" in d.model_dump()
    finally:
        con.close()


def test_ca_host_computer_dossier_shows_dcom_summary_only() -> None:
    con, reader = _mem_store()
    try:
        _enterprise_ca(con, "n-entca", "corp-ca")
        _computer(con, "n-host", "CA01$")
        persist_ca_node_findings(con, _findings("n-entca", "n-host"), scoping=SCOPING)

        d = build_dossier(reader, "n-host")
        assert d is not None and d.kind == "Computer"
        assert [f.prop for f in d.ca_node_findings] == [NODE_PROP_DCOM]
        dcom = d.ca_node_findings[0]
        assert dcom.value == "EnableDCOM=Y"  # non-secret summary only
        assert dcom.provenance.source_file == "CAHOST/SOFTWARE"
    finally:
        con.close()


def test_non_ca_dossier_is_byte_unchanged_and_drops_key() -> None:
    """A node with no CA finding has an empty list and the key is DROPPED (parity)."""
    con, reader = _mem_store()
    try:
        _computer(con, "plain", "WS01$")
        # no findings persisted for this node.
        d = build_dossier(reader, "plain")
        assert d is not None
        assert d.ca_node_findings == []
        dumped = d.model_dump()
        assert "ca_node_findings" not in dumped  # dropped -> byte-unchanged

        # determinism: identical store -> identical serialization.
        d2 = build_dossier(reader, "plain")
        assert d2 is not None
        assert canonical_json(d.model_dump()) == canonical_json(d2.model_dump())
    finally:
        con.close()
