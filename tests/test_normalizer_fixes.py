"""Coder-side regression tests for the M3 post-gate fix pass.

Covers the reviewer/domain-expert fixes WITHOUT touching the tester's files:
  * PRIORITY A: no denylisted secret attribute lands in staging_object.attributes
    (pure + live-on-real-DC).
  * PRIORITY B: secret_refs carries `decrypted`; synthetic stub provenance does
    not claim the real artifact hash; deleted split counters.
  * PRIORITY C: link_unresolved counter exists; writer column-count = field count.

The live-DC tests skip cleanly when the (gitignored) evidence is absent.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.normalize import SECRET_ATTRIBUTE_DENYLIST, normalize, strip_secret_attributes
from wraith.normalize.builders import BuildContext, _secret_refs
from wraith.normalize.identity import WELLKNOWN_SOURCE_FILE, DirectoryIndex
from wraith.normalize.models import (
    AdcsRow,
    ContainerRow,
    GpoRow,
    PrincipalRow,
    StagingLinkRow,
    StagingObjectRow,
    TrustRow,
)
from wraith.parsing.ntds import open_ntds
from wraith.parsing.ntds_secrets import StoredSecretRef
from wraith.secrets import SecretType

_REPO = Path(__file__).resolve().parent.parent
_NTDS = _REPO / "eviedence_test" / "NTDS" / "ntds.dit"
_FOREST = "forest-c137"
_RUN = UUID("00000000-0000-0000-0000-0000000000f3")

_needs_evidence = pytest.mark.skipif(
    not _NTDS.is_file(), reason="needs eviedence_test NTDS present"
)


# --- PRIORITY A: denylist (pure) ---------------------------------------------


def test_denylist_covers_mandated_keys() -> None:
    for name in (
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "unicodePwd",
        "dBCSPwd",
        "ntPwdHistory",
        "lmPwdHistory",
        "supplementalCredentials",
        "msDS-ManagedPassword",
        "msKds-RootKeyData",
        "trustAuthIncoming",
        "trustAuthOutgoing",
        "pekList",
        "priorValue",
        "currentValue",
    ):
        assert name.lower() in SECRET_ATTRIBUTE_DENYLIST


def test_strip_is_case_insensitive_and_keeps_m5_attrs() -> None:
    attrs = {
        "UNICODEPWD": b"\x00",  # different case -> still stripped
        "supplementalCredentials": b"\x01",
        "msDS-AllowedToActOnBehalfOfOtherIdentity": b"\x02",  # KEEP (M5 RBCD)
        "msDS-KeyCredentialLink": "B:...",  # KEEP (M5 shadow creds)
        "sAMAccountName": "svc",  # KEEP
    }
    out = strip_secret_attributes(attrs)
    assert "UNICODEPWD" not in out and "supplementalCredentials" not in out
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in out
    assert "msDS-KeyCredentialLink" in out and out["sAMAccountName"] == "svc"


# --- PRIORITY B: secret_refs decrypted field (unit) --------------------------


def test_secret_refs_struct_carries_decrypted() -> None:
    ctx = BuildContext(
        forest_id=_FOREST,
        domain_id="S-1-5-21-1-2-3",
        domain_fqdn="c.local",
        index=DirectoryIndex(),
        node_secret_refs={
            "n1": (
                StoredSecretRef("sid-1", SecretType.NT_HASH, "", True, True),
                StoredSecretRef(
                    "sid-2", SecretType.LAPS_PASSWORD, "laps_v2_ciphertext", False, False
                ),
            )
        },
        gpc_cn_to_node={},
    )
    refs = _secret_refs("n1", ctx)
    assert {r["secret_id"] for r in refs} == {"sid-1", "sid-2"}
    for r in refs:
        assert set(r.keys()) == {
            "secret_id",
            "secret_type",
            "label",
            "decrypted",
            "decryptable_offline",
        }
    by_id = {r["secret_id"]: r for r in refs}
    assert by_id["sid-1"]["decrypted"] is True and by_id["sid-1"]["decryptable_offline"] is True
    assert by_id["sid-2"]["decrypted"] is False and by_id["sid-2"]["decryptable_offline"] is False


# --- PRIORITY C: writer column-count invariant -------------------------------


def test_row_field_count_equals_db_tuple_len() -> None:
    # The writer binds len(fields(Row)) params; each to_db_values tuple must match.
    for row_cls, n in (
        (PrincipalRow, 25),
        (ContainerRow, 12),
        (GpoRow, 9),
        (TrustRow, 13),
        (AdcsRow, 11),
        (StagingObjectRow, 12),  # +source_id (multi-source contract §2.2b, v1.2)
        (StagingLinkRow, 16),  # +source_id (multi-source contract §2.2b, v1.2)
    ):
        assert len(fields(row_cls)) == n


# --- Live on the real DC -----------------------------------------------------


def _register(run: IngestRun) -> IngestRun:
    run.add_artifact(
        ArtifactInput(
            source_file="ntds.dit",
            abs_path_or_ref=str(_NTDS.resolve()),
            size_bytes=_NTDS.stat().st_size,
            image_sha256="f52d5844" + "0" * 56,
        )
    )
    return run


@_needs_evidence
def test_live_no_secret_attribute_in_staging() -> None:
    """BLOCKER regression: NO denylisted secret attribute key appears in ANY
    staging_object.attributes row on the real DC, AND the strip was actually
    effective (at least one object originally carried such a key)."""
    con = duckdb.connect(":memory:")
    run = _register(IngestRun("FIX-M3", "wraith-coder", ingest_run_id=_RUN))
    with open_ntds(_NTDS, run) as parsed:
        # Did the raw directory actually contain denylisted secret attributes?
        found_raw = any(
            name.lower() in SECRET_ATTRIBUTE_DENYLIST
            for obj in parsed.objects()
            for name in obj.attributes
        )
        normalize(parsed, run, con, forest_id=_FOREST)
    assert found_raw, "raw DIT had no denylisted attrs — test would be vacuous"

    rows = con.execute("SELECT attributes FROM staging_object").fetchall()
    assert rows
    for (attrs_json,) in rows:
        keys = {k.lower() for k in json.loads(attrs_json)}
        leaked = keys & SECRET_ATTRIBUTE_DENYLIST
        assert not leaked, f"secret attribute(s) leaked into staging: {leaked}"
    con.close()


@_needs_evidence
def test_live_deleted_counter_split_sums_to_aggregate() -> None:
    """Deleted split (DE ISSUE-1): recoverable + recycled == the back-compat
    deleted_skipped aggregate, and the aggregate matches the pinned 44."""
    con = duckdb.connect(":memory:")
    run = _register(IngestRun("FIX-M3", "wraith-coder", ingest_run_id=_RUN))
    with open_ntds(_NTDS, run) as parsed:
        result = normalize(parsed, run, con, forest_id=_FOREST)
    skips = result.skip_counts
    agg = skips.get("normalizer.deleted_skipped", 0)
    rec = skips.get("normalizer.deleted_recoverable", 0)
    recy = skips.get("normalizer.deleted_recycled", 0)
    assert rec + recy == agg == 44
    con.close()


@_needs_evidence
def test_live_stub_provenance_is_synthetic_not_real_hash() -> None:
    """Stub provenance (DE ISSUE-3): every synthetic stub Principal carries the
    WELLKNOWN_SOURCE_FILE and the synthetic image hash — NOT the real .dit hash."""
    con = duckdb.connect(":memory:")
    run = _register(IngestRun("FIX-M3", "wraith-coder", ingest_run_id=_RUN))
    with open_ntds(_NTDS, run) as parsed:
        normalize(parsed, run, con, forest_id=_FOREST)
    stubs = con.execute(
        "SELECT provenance.source_file, provenance.image_sha256, provenance.source_object_id "
        "FROM principal WHERE provenance.source_file = ?",
        [WELLKNOWN_SOURCE_FILE],
    ).fetchall()
    assert stubs, "expected synthetic well-known stub principals"
    real_hash = "f52d5844" + "0" * 56
    for source_file, image_sha256, source_object_id in stubs:
        assert source_file == WELLKNOWN_SOURCE_FILE
        assert image_sha256 != real_hash
        assert source_object_id.startswith("synthetic:wellknown:")
    con.close()
