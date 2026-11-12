"""Independent gate suite — structural NTDS parsing against real evidence.

Authored by ``wraith-tester`` (the gatekeeper). Exercises ``open_ntds`` /
``parse_ntds`` / ``ParsedNtds`` / ``ParsedObject`` / ``LinkRow`` / ``NtdsSchema``
against the real (untrusted, gitignored) ``eviedence_test/NTDS/ntds.dit`` across
the gate layers:

  * golden    — observed facts pinned as ground truth (object/schema counts,
                domain SID, Administrator/krbtgt identity, SD lengths, link count,
                column resolution, extended-rights presence).
  * property  — the out-of-row long-value SD path returns the FULL blob (not a
                4-byte reference); SID-less / GUID-less objects degrade to None,
                counted; coverage/skip surfaced.
  * determinism — two independent passes yield identical DNT order, GUIDs,
                provenance, and link order.
  * provenance — every object/link carries a complete ProvenanceStruct whose
                image_sha256 equals sha256_file(ntds.dit).

Every evidence-reading test skips cleanly if the artifact is absent, so the
suite stays portable/CI-safe. The file is handled read-only and never copied
into the repo.

Deferred (NOT failures): a CLEAN .dit to confirm the clean-state path
end-to-end (this capture is DirtyShutdown); all Module 2b secret decryption and
Module 3 SD->ACE / membership / edge semantics.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest

from wraith.acquisition.hashing import sha256_file
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import ArtifactInput
from wraith.parsing import LinkRow, ParsedObject, open_ntds
from wraith.provenance.models import ProvenanceStruct

# --- evidence anchor ---------------------------------------------------------

_EVIDENCE = Path(__file__).resolve().parent.parent / "eviedence_test" / "NTDS" / "ntds.dit"
_SOURCE_FILE = "ntds.dit"
_FIXED_RUN_ID = UUID("00000000-0000-0000-0000-0000000002a0")

# Independently-established ground truth (confirmed by direct probe of the DIT).
_DOMAIN_SID = "S-1-5-21-2232410529-1445159330-2725690660"
_REPLICATION_RIGHT_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # Replicating Dir Changes

_missing_evidence = not _EVIDENCE.is_file()
_skip_no_evidence = pytest.mark.skipif(
    _missing_evidence, reason=f"real evidence absent: {_EVIDENCE}"
)


def _make_run() -> IngestRun:
    """Build an IngestRun with ntds.dit registered (fixed id for determinism)."""
    sha = sha256_file(_EVIDENCE)
    run = IngestRun("GATE-CASE", "wraith-tester", ingest_run_id=_FIXED_RUN_ID)
    run.add_artifact(
        ArtifactInput(
            source_file=_SOURCE_FILE,
            abs_path_or_ref=str(_EVIDENCE.resolve()),
            size_bytes=_EVIDENCE.stat().st_size,
            image_sha256=sha,
        )
    )
    return run


@dataclass
class _Facts:
    """A single materialised parse, shared across golden tests (one scan)."""

    image_sha256: str
    db_state_raw: int
    db_label: str
    db_is_clean: bool | None
    gen_min: int
    gen_max: int
    attr_count: int
    class_count: int
    rights_raw_count: int
    rights_unique_count: int
    col_map_size: int
    col_sam: str | None
    col_sid: str | None
    col_sd: str | None
    col_uac: str | None
    col_whenchanged: str | None
    has_replication_right: bool
    sd_count: int
    objects: list[ParsedObject]
    links: list[LinkRow]
    cov_objects: int
    cov_links: int
    skip_counts: dict[str, int]
    missing_column_requests: int
    value_parse_errors: int


@pytest.fixture(scope="module")
def facts() -> _Facts:
    """Open the real DIT once and materialise everything the golden tests pin."""
    if _missing_evidence:  # pragma: no cover - CI without evidence
        pytest.skip(f"real evidence absent: {_EVIDENCE}")
    run = _make_run()
    with open_ntds(_EVIDENCE, run) as parsed:
        sch = parsed.schema
        objects = list(parsed.objects())
        links = list(parsed.links())
        cov = parsed.coverage()
        return _Facts(
            image_sha256=sha256_file(_EVIDENCE),
            db_state_raw=parsed.db_state.raw_dbstate,
            db_label=parsed.db_state.label,
            db_is_clean=parsed.db_state.is_clean,
            gen_min=parsed.db_state.gen_min_required,
            gen_max=parsed.db_state.gen_max_required,
            attr_count=len(sch.raw_attribute_records),
            class_count=len(sch.raw_class_records),
            rights_raw_count=len(sch.raw_right_records),
            rights_unique_count=len(sch.extended_rights_by_guid),
            col_map_size=len(sch.column_to_ldap),
            col_sam=sch.column_for("sAMAccountName"),
            col_sid=sch.column_for("objectSid"),
            col_sd=sch.column_for("nTSecurityDescriptor"),
            col_uac=sch.column_for("userAccountControl"),
            col_whenchanged=sch.column_for("whenChanged"),
            has_replication_right=_REPLICATION_RIGHT_GUID in sch.extended_rights_by_guid,
            sd_count=parsed.sd_count,
            objects=objects,
            links=links,
            cov_objects=parsed.coverage_counts.get("ntds.objects_parsed", 0),
            cov_links=parsed.coverage_counts.get("ntds.links_parsed", 0),
            skip_counts=dict(parsed.skip_counts),
            missing_column_requests=cov.missing_column_requests,
            value_parse_errors=cov.value_parse_errors,
        )


def _by_sam(objects: list[ParsedObject], name: str) -> ParsedObject:
    matches = [o for o in objects if o.sam_account_name == name]
    assert len(matches) == 1, f"expected exactly one {name!r}, found {len(matches)}"
    return matches[0]


# =============================================================================
# Pre-flight
# =============================================================================


@_skip_no_evidence
def test_evidence_sha256_is_the_documented_capture(facts: _Facts) -> None:
    """Proves: the suite ran against the documented capture (SHA begins f52d5844)."""
    assert len(facts.image_sha256) == 64
    assert facts.image_sha256.startswith("f52d5844")


# =============================================================================
# Golden — dirty database state (detect -> warn -> degrade)
# =============================================================================


@_skip_no_evidence
def test_db_state_is_dirty_shutdown(facts: _Facts) -> None:
    """Proves: db_state is DirtyShutdown (raw 2, not clean, gen_min/max=3)."""
    assert facts.db_state_raw == 2
    assert facts.db_label == "DirtyShutdown"
    assert facts.db_is_clean is False
    assert facts.gen_min == 3
    assert facts.gen_max == 3


# =============================================================================
# Golden — schema resolution
# =============================================================================


@_skip_no_evidence
def test_schema_object_counts(facts: _Facts) -> None:
    """Proves: 1473 attributeSchema / 264 classSchema / 80 raw rights / 79 unique."""
    assert facts.attr_count == 1473
    assert facts.class_count == 264
    assert facts.rights_raw_count == 80
    assert facts.rights_unique_count == 79


@_skip_no_evidence
def test_column_resolution_is_schema_driven(facts: _Facts) -> None:
    """Proves: key lDAPDisplayName -> ATT<type><id> columns resolve as documented."""
    assert facts.col_map_size == 1295
    assert facts.col_sam == "ATTm590045"
    assert facts.col_sid == "ATTr589970"
    assert facts.col_sd == "ATTp131353"
    assert facts.col_uac == "ATTj589832"
    assert facts.col_whenchanged == "ATTl131075"


@_skip_no_evidence
def test_replication_extended_right_present(facts: _Facts) -> None:
    """Proves: the DCSync 'Replicating Directory Changes' right-GUID is surfaced."""
    assert facts.has_replication_right


# =============================================================================
# Golden — object stream
# =============================================================================


@_skip_no_evidence
def test_total_datatable_object_count(facts: _Facts) -> None:
    """Proves: exactly 3834 datatable objects streamed (and all counted)."""
    assert len(facts.objects) == 3834
    assert facts.cov_objects == 3834


@_skip_no_evidence
def test_domain_sid_present_and_well_formed(facts: _Facts) -> None:
    """Proves: the domain object's SID equals the documented domain identifier."""
    sids = {o.object_sid for o in facts.objects if o.object_sid is not None}
    assert _DOMAIN_SID in sids


@_skip_no_evidence
def test_administrator_identity(facts: _Facts) -> None:
    """Proves: Administrator DNT 3917, RID 500, UAC 512, whenChanged 2020-09-18."""
    admin = _by_sam(facts.objects, "Administrator")
    assert admin.dnt == 3917
    assert admin.object_sid == f"{_DOMAIN_SID}-500"
    assert admin.attribute("userAccountControl") == 512
    assert admin.when_changed is not None
    assert admin.when_changed.isoformat() == "2020-09-18T00:24:04+00:00"


@_skip_no_evidence
def test_administrator_sid_big_endian_rule_independently(facts: _Facts) -> None:
    """Proves: the raw objectSid bytes decode (BY AN INDEPENDENT DECODER) to the
    same ...-500 SID — the big-endian last-sub-authority rule applied to real data.
    """
    admin = _by_sam(facts.objects, "Administrator")
    raw = admin.object_sid_raw
    assert isinstance(raw, bytes)
    # Independent reference decode (not the module's decoder).
    rev, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = []
    for i in range(count):
        chunk = raw[8 + 4 * i : 12 + 4 * i]
        subs.append(int.from_bytes(chunk, "big" if i == count - 1 else "little"))
    reference = "-".join(["S", str(rev), str(authority), *[str(s) for s in subs]])
    assert reference == f"{_DOMAIN_SID}-500"
    assert reference == admin.object_sid  # module decoder agrees with reference


@_skip_no_evidence
def test_krbtgt_identity(facts: _Facts) -> None:
    """Proves: krbtgt DNT 3971, RID 502, UAC 514."""
    krbtgt = _by_sam(facts.objects, "krbtgt")
    assert krbtgt.dnt == 3971
    assert krbtgt.object_sid == f"{_DOMAIN_SID}-502"
    assert krbtgt.attribute("userAccountControl") == 514


# =============================================================================
# Golden — security descriptors (the sd_id indirection)
# =============================================================================


@_skip_no_evidence
def test_unique_security_descriptor_count(facts: _Facts) -> None:
    """Proves: the sd_table deduplicated map holds exactly 96 descriptors."""
    assert facts.sd_count == 96


@_skip_no_evidence
def test_out_of_row_long_value_sd_returns_full_blob(facts: _Facts) -> None:
    """Proves: a large SD (Administrator, 1356 bytes) is the FULL self-relative
    descriptor, NOT the 4-byte ESE long-value reference — the out-of-row path.
    """
    admin = _by_sam(facts.objects, "Administrator")
    assert admin.raw_sd_bytes is not None
    assert len(admin.raw_sd_bytes) == 1356
    assert len(admin.raw_sd_bytes) > 4  # not a long-value pointer
    # A self-relative SECURITY_DESCRIPTOR begins with revision 0x01, sbz 0x00.
    assert admin.raw_sd_bytes[0] == 0x01
    assert admin.sd_id is not None
    krbtgt = _by_sam(facts.objects, "krbtgt")
    assert krbtgt.raw_sd_bytes is not None
    assert len(krbtgt.raw_sd_bytes) == 1356


# =============================================================================
# Golden — link rows
# =============================================================================


@_skip_no_evidence
def test_link_rows_surfaced_raw(facts: _Facts) -> None:
    """Proves: exactly 84 raw link_table rows streamed and counted."""
    assert len(facts.links) == 84
    assert facts.cov_links == 84


# =============================================================================
# Property / robustness
# =============================================================================


@_skip_no_evidence
def test_sid_less_objects_degrade_to_none_not_crash(facts: _Facts) -> None:
    """Proves: the vast majority of objects have no objectSid and yield None
    cleanly (99 of 3834 carry a SID); no crash, no silent wrong answer.
    """
    with_sid = [o for o in facts.objects if o.object_sid is not None]
    without_sid = [o for o in facts.objects if o.object_sid is None]
    assert len(with_sid) == 99
    assert len(without_sid) == 3834 - 99
    # Every SID-less object genuinely has no raw SID blob either (consistent None).
    assert all(o.object_sid_raw is None for o in without_sid)


@_skip_no_evidence
def test_guid_coverage_and_single_guid_less_object(facts: _Facts) -> None:
    """Proves: exactly one datatable object lacks an objectGUID (decodes to None),
    the other 3833 decode to a 36-char dashed GUID — None is counted, not raised.
    """
    guid_none = [o for o in facts.objects if o.object_guid is None]
    assert len(guid_none) == 1
    for o in facts.objects:
        if o.object_guid is not None:
            assert len(o.object_guid) == 36
            assert o.object_guid_raw is not None and len(o.object_guid_raw) == 16


@_skip_no_evidence
def test_coverage_and_skip_counts_surfaced_clean(facts: _Facts) -> None:
    """Proves: a clean parse surfaces zero gaps — no malformed skips, no missing
    columns, no value-parse errors (counts are exposed, not hidden).
    """
    assert facts.skip_counts == {}
    assert facts.missing_column_requests == 0
    assert facts.value_parse_errors == 0


@_skip_no_evidence
def test_objects_are_in_ascending_dnt_order(facts: _Facts) -> None:
    """Proves: objects() yields in deterministic ascending DNT (primary-index) order."""
    dnts = [o.dnt for o in facts.objects]
    assert dnts == sorted(dnts)
    assert len(set(dnts)) == len(dnts)  # DNTs are unique


# =============================================================================
# Provenance
# =============================================================================


@_skip_no_evidence
def test_every_object_carries_complete_provenance(facts: _Facts) -> None:
    """Proves: each ParsedObject has a full ProvenanceStruct — source_file,
    64-hex image_sha256 == sha256_file(ntds.dit), source_object_id == DNT,
    directory_timestamp == whenChanged, run id.
    """
    for o in facts.objects:
        p = o.provenance
        assert isinstance(p, ProvenanceStruct)
        assert p.source_file == _SOURCE_FILE
        assert p.image_sha256 == facts.image_sha256
        assert len(p.image_sha256) == 64
        assert p.source_object_id == str(o.dnt)
        assert p.directory_timestamp == o.when_changed
        assert p.ingest_run_id == _FIXED_RUN_ID


@_skip_no_evidence
def test_every_link_carries_complete_provenance(facts: _Facts) -> None:
    """Proves: each LinkRow carries a ProvenanceStruct bound to the same image hash."""
    for link in facts.links:
        p = link.provenance
        assert isinstance(p, ProvenanceStruct)
        assert p.source_file == _SOURCE_FILE
        assert p.image_sha256 == facts.image_sha256
        assert p.source_object_id is not None
        assert p.source_object_id.startswith("link:")
        assert p.ingest_run_id == _FIXED_RUN_ID


@_skip_no_evidence
def test_administrator_provenance_timestamp_matches_directory(facts: _Facts) -> None:
    """Proves: a principal's provenance directory_timestamp is its whenChanged."""
    admin = _by_sam(facts.objects, "Administrator")
    assert admin.provenance.directory_timestamp is not None
    assert admin.provenance.directory_timestamp.isoformat() == "2020-09-18T00:24:04+00:00"


# =============================================================================
# Determinism — two independent passes over the same .dit
# =============================================================================


@_skip_no_evidence
def test_two_independent_passes_are_identical() -> None:
    """Proves: identical input -> identical object order/DNTs/GUIDs/provenance and
    identical link order (determinism non-negotiable). Run id is fixed so the
    only variable is the parse itself; provenance structs must be byte-equal.
    """
    run_a = _make_run()
    run_b = _make_run()
    with open_ntds(_EVIDENCE, run_a) as pa:
        objs_a = [
            (o.dnt, o.object_guid, o.object_sid, o.provenance.model_dump(mode="json"))
            for o in pa.objects()
        ]
        links_a = [
            (lk.link_dnt, lk.backlink_dnt, lk.link_base, lk.provenance.source_object_id)
            for lk in pa.links()
        ]
    with open_ntds(_EVIDENCE, run_b) as pb:
        objs_b = [
            (o.dnt, o.object_guid, o.object_sid, o.provenance.model_dump(mode="json"))
            for o in pb.objects()
        ]
        links_b = [
            (lk.link_dnt, lk.backlink_dnt, lk.link_base, lk.provenance.source_object_id)
            for lk in pb.links()
        ]
    assert objs_a == objs_b
    assert links_a == links_b


@_skip_no_evidence
def test_raw_sd_bytes_are_byte_identical_across_passes() -> None:
    """Proves: the resolved raw SD blob for Administrator is byte-identical on a
    fresh open (serialized output is stable).
    """
    run_a = _make_run()
    run_b = _make_run()
    with open_ntds(_EVIDENCE, run_a) as pa:
        admin_a = _by_sam(list(pa.objects()), "Administrator")
        sd_a = admin_a.raw_sd_bytes
    with open_ntds(_EVIDENCE, run_b) as pb:
        admin_b = _by_sam(list(pb.objects()), "Administrator")
        sd_b = admin_b.raw_sd_bytes
    assert sd_a is not None and sd_b is not None
    assert sd_a == sd_b


# =============================================================================
# Performance budget (smoke — a 20 MB mid-size DIT must parse quickly)
# =============================================================================


@_skip_no_evidence
def test_full_parse_within_performance_budget() -> None:
    """Proves: a full object+link scan of this ~20 MB DIT stays well under the
    'minutes on a laptop' target (generous 120 s ceiling, flags a regression).
    """
    run = _make_run()
    start = time.monotonic()
    with open_ntds(_EVIDENCE, run) as parsed:
        obj_n = sum(1 for _ in parsed.objects())
        link_n = sum(1 for _ in parsed.links())
    elapsed = time.monotonic() - start
    assert obj_n == 3834
    assert link_n == 84
    assert elapsed < 120.0, f"parse took {elapsed:.1f}s (performance regression)"
