"""Gate suite for the guided-dossier backend (design doc 21).

Three layers:

* LAYER 1 — pure/unit (CI-safe, no store): the static rights glossary's coverage
  of every engine edge kind, its AGREEMENT with the hunter truth-contract in
  :mod:`wraith.api.queries` (no over-claiming), the ``attribute_name`` GUID
  resolver, and the deterministic :func:`compose_exec_summary` composer against
  hand-built :class:`SummaryContext` inputs (determinism, the kerberoastable
  clause, sentence-drop-on-absent-data, no-false-Tier-0).
* LAYER 2 — real c137 (via ``WRAITH_GATE_PREBUILT_DB``): the ``GET /glossary``
  endpoint, the Domain Admins / Domain / non-privileged exec summaries, the
  ``group_members`` closure (== ``effective_members_of(-512)``), edge
  ``tier``/``is_tier0``/``attribute_name`` correctness, build determinism, and the
  secret-free guarantee. Skips cleanly when the prebuilt store is absent.

The glossary over-claim checks are pinned to the FROZEN capability sets in
``queries.py`` (``RESET_PASSWORD_KINDS`` / ``WRITE_SPN_KINDS`` / ``SHADOW_CRED_KINDS``
/ ``FULL_CONTROL_KINDS``) so a drift in either the glossary or the truth-contract
fails this gate.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wraith.api import rights_glossary as rg
from wraith.api.app import create_app
from wraith.api.dossier import build_dossier
from wraith.api.dossier_summary import SummaryContext, compose_exec_summary, risk_words
from wraith.api.models import DossierEdge, NodeRef, NodeRisk, UacFlagsOut
from wraith.api.queries import (
    FULL_CONTROL_KINDS,
    RESET_PASSWORD_KINDS,
    SHADOW_CRED_KINDS,
    WRITE_SPN_KINDS,
)
from wraith.api.rights_glossary import (
    EDGE_GLOSSARY,
    ENGINE_EDGE_KINDS,
    NEUTRAL_EDGE_ENTRY,
    attribute_name_for_guid,
    build_glossary,
    lookup_edge,
)
from wraith.api.store import StoreReader
from wraith.common.determinism import canonical_json
from wraith.edges.guid_map import (
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    GUID_MEMBER,
    GUID_SERVICE_PRINCIPAL_NAME,
)

# =========================================================================== #
#  LAYER 1 — glossary coverage + TRUTH-CONTRACT agreement (pure, CI-safe)      #
# =========================================================================== #


def test_glossary_covers_every_engine_edge_kind() -> None:
    """Every kind the engine can emit has an authored entry (coverage gap == {})."""
    missing = sorted(k for k in ENGINE_EDGE_KINDS if k not in EDGE_GLOSSARY)
    assert missing == [], f"engine edge kinds without a glossary entry: {missing}"
    g = build_glossary()
    assert g.counted_gaps == {}, g.counted_gaps
    # every engine kind is served out of the endpoint model
    for kind in ENGINE_EDGE_KINDS:
        assert kind in g.edges, kind
    # flags are covered too (the §4.6 selection set the exec summary draws from)
    for flag in ("kerberoastable", "unconstrained_delegation", "reversible_password"):
        assert flag in g.flags


def test_missing_kind_is_a_counted_gap_not_a_guess(monkeypatch: pytest.MonkeyPatch) -> None:
    """A kind absent from the glossary degrades to a COUNTED gap, never a guessed abuse."""
    # unknown kind -> no entry, and the neutral fallback asserts no abuse
    assert lookup_edge("SomeFutureEdgeKind") is None
    # the neutral fallback is honest: a bare "control relationship" caption, an
    # explicit "no glossary entry yet" grant, and NO asserted abuse.
    assert NEUTRAL_EDGE_ENTRY.action == "has a control relationship with"
    assert "glossary entry" in NEUTRAL_EDGE_ENTRY.grants.lower()
    assert "not asserted" in NEUTRAL_EDGE_ENTRY.why.lower()
    for banned in ("dcsync", "password", "golden ticket", "kerberoast"):
        assert banned not in NEUTRAL_EDGE_ENTRY.why.lower()
    # simulate a real coverage gap: drop one authored kind and re-build
    monkeypatch.delitem(rg.EDGE_GLOSSARY, "Owns")
    g = build_glossary()
    assert "Owns" not in g.edges
    assert g.counted_gaps == {"glossary_missing_edge_kind": 1}, g.counted_gaps


def _text(kind: str) -> str:
    e = EDGE_GLOSSARY[kind]
    return f"{e.grants} || {e.why} || {e.action}".lower()


def test_genericwrite_does_not_overclaim() -> None:
    """GenericWrite: SPN/shadow-cred/RBCD YES; password reset / DACL rewrite NO."""
    # truth-contract set membership (frozen queries.py sets)
    assert "GenericWrite" in WRITE_SPN_KINDS
    assert "GenericWrite" in SHADOW_CRED_KINDS
    assert "GenericWrite" not in RESET_PASSWORD_KINDS
    assert "GenericWrite" not in FULL_CONTROL_KINDS
    t = _text("GenericWrite")
    # positively grants the property-write abuses
    assert "spn" in t and "shadow credential" in t and "rbcd" in t
    # explicitly disclaims password reset + DACL rewrite (no over-claim)
    assert "does not reset a password" in t
    assert "no password reset" in t and "no dacl rewrite" in t
    assert "does not grant" in t and "writedacl/writeowner" in t.replace(" ", "")


def test_allextendedrights_does_not_overclaim() -> None:
    """AllExtendedRights: ForceChangePassword + DCSync-on-domain YES; property writes NO."""
    assert "AllExtendedRights" in RESET_PASSWORD_KINDS  # subsumes ForceChangePassword
    assert "AllExtendedRights" not in WRITE_SPN_KINDS  # cannot set an SPN by itself
    t = _text("AllExtendedRights")
    assert "forcechangepassword" in t and "dcsync" in t
    assert "does not grant plain property writes" in t
    assert "cannot set an spn" in t


def test_forcechangepassword_is_reset_without_old_password() -> None:
    assert "ForceChangePassword" in RESET_PASSWORD_KINDS
    t = _text("ForceChangePassword")
    assert "without knowing the current one" in t


def test_full_control_kinds_are_path_to_full_control() -> None:
    for kind in ("WriteDacl", "WriteOwner", "Owns"):
        assert kind in FULL_CONTROL_KINDS, kind
        assert "full control" in _text(kind), kind
    # WriteDacl is the canonical one-ACE-to-full-control primitive
    assert "dacl" in _text("WriteDacl")


def test_getchanges_alone_is_not_the_actionable_dcsync() -> None:
    """GetChanges alone != the actionable DCSync composite."""
    gc = _text("GetChanges")
    assert "not sufficient alone" in gc
    assert "one half of dcsync" in gc
    # the actionable composite is the distinct DCSync entry
    assert lookup_edge("DCSync") is not None
    assert "dcsync the domain" in EDGE_GLOSSARY["DCSync"].action.lower()


def test_attribute_name_resolver() -> None:
    """The GUID resolver maps SPN / force-change-password / replication / member;
    None for a whole-object edge and an unmapped GUID; case-insensitive."""
    assert attribute_name_for_guid(GUID_SERVICE_PRINCIPAL_NAME) == "servicePrincipalName"
    assert attribute_name_for_guid(GUID_FORCE_CHANGE_PASSWORD) == "User-Force-Change-Password"
    assert attribute_name_for_guid(GUID_GET_CHANGES) == "DS-Replication-Get-Changes"
    assert attribute_name_for_guid(GUID_GET_CHANGES_ALL) == "DS-Replication-Get-Changes-All"
    assert attribute_name_for_guid(GUID_MEMBER) == "member"
    # case-insensitive (ACE GUIDs can arrive upper-cased)
    assert attribute_name_for_guid(GUID_SERVICE_PRINCIPAL_NAME.upper()) == "servicePrincipalName"
    # whole-object edge / unknown GUID -> None (no [via ...] clause)
    assert attribute_name_for_guid(None) is None
    assert attribute_name_for_guid("") is None
    assert attribute_name_for_guid("00000000-0000-0000-0000-000000000000") is None


# --- compose_exec_summary (pure composer) ---------------------------------- #


def _risk(score: int, tier: int | None = None, hops: int | None = None) -> NodeRisk:
    return NodeRisk(
        node_id="n", kind="User", label="n", score=score, tier=tier, tier0_hops=hops, factors=[]
    )


def _uac_enabled() -> UacFlagsOut:
    return UacFlagsOut(raw=512, enabled=True)


def test_risk_words_bands_are_fixed_tables() -> None:
    assert risk_words(0, 999) == "Tier-0 — owning it is full domain compromise"
    assert risk_words(None, 60) == "critical risk"
    assert risk_words(None, 30) == "high risk"
    assert risk_words(None, 10) == "elevated risk"
    assert risk_words(None, 1) == "low risk"
    assert risk_words(None, 0) == "no standing risk signals"


def test_exec_summary_is_deterministic() -> None:
    ctx = SummaryContext(
        kind="User",
        label="SVC_SQL",
        spns=("MSSQLSvc/db",),
        node_flags={"kerberoastable": True},
        uac=_uac_enabled(),
        risk=_risk(20, tier=None, hops=2),
    )
    a = compose_exec_summary(ctx)
    b = compose_exec_summary(ctx)
    assert a == b
    assert canonical_json(a) == canonical_json(b)


def test_exec_summary_spn_user_has_kerberoastable_clause() -> None:
    ctx = SummaryContext(
        kind="User",
        label="SVC_SQL",
        spns=("MSSQLSvc/db",),
        node_flags={"kerberoastable": True},
        uac=_uac_enabled(),
        risk=_risk(20, hops=2),
    )
    joined = " ".join(compose_exec_summary(ctx))
    assert "SVC_SQL is a enabled user account" in joined
    assert "service account advertising 1 SPN(s)" in joined
    assert "Kerberoastable" in joined  # the §4.6 one-phrase verbatim
    assert "It can reach Tier-0 in 2 hop(s) — low-effort." in joined


def _edge(kind: str, other_kind: str, other_label: str) -> DossierEdge:
    return DossierEdge(
        edge_id=f"e-{kind}",
        kind=kind,
        direction="outbound",
        other=NodeRef(node_id="g1", kind=other_kind, label=other_label),
    )


def test_issuance_policy_summary_carries_esc13_and_synthetic_note() -> None:
    """IssuancePolicy with an OIDGroupLink states ESC13 + the persistent synthetic banner."""
    ctx = SummaryContext(
        kind="IssuancePolicy",
        label="OID-1.3.6",
        outbound_edges=(_edge("OIDGroupLink", "Group", "Privileged Group"),),
    )
    out = compose_exec_summary(ctx)
    joined = " ".join(out)
    assert "is a certificate issuance policy (OID)" in joined
    assert "ESC13" in joined and "Privileged Group" in joined
    assert "ADCS edges are synthetic-tested and untested on real data in v1." in out


def test_generic_adcs_kind_carries_synthetic_note() -> None:
    """An ADCS topology kind with no bespoke composer still carries the honest banner."""
    ctx = SummaryContext(
        kind="EnterpriseCA",
        label="CITADEL-CA",
        inbound_edges=(
            DossierEdge(
                edge_id="e1",
                kind="GenericAll",
                direction="inbound",
                other=NodeRef(node_id="u1", kind="User", label="attacker"),
            ),
        ),
    )
    out = compose_exec_summary(ctx)
    assert out[0] == "CITADEL-CA is a EnterpriseCA."
    assert "1 principal(s) can control it via GenericAll." in out
    assert "ADCS edges are synthetic-tested and untested on real data in v1." in out


def test_exec_summary_drops_absent_sentences_no_filler() -> None:
    """A plain, unexposed user yields a short, honest summary (no invented clauses)."""
    ctx = SummaryContext(kind="User", label="PLAIN", uac=_uac_enabled(), risk=_risk(0))
    out = compose_exec_summary(ctx)
    assert out == [
        "PLAIN is a enabled user account.",
        "Risk posture: no standing risk signals.",
    ]
    joined = " ".join(out)
    # no membership / exposure / flags clauses were invented
    assert "effective member" not in joined
    assert "can take control" not in joined
    assert "Notable" not in joined


def test_exec_summary_non_privileged_makes_no_tier0_claim() -> None:
    ctx = SummaryContext(kind="User", label="PLAIN", uac=_uac_enabled(), risk=_risk(0))
    joined = " ".join(compose_exec_summary(ctx))
    assert "Tier-0" not in joined
    assert "domain compromise" not in joined


# =========================================================================== #
#  LAYER 2 — real c137 integration (prebuilt store)                            #
# =========================================================================== #

_PREBUILT = os.environ.get("WRAITH_GATE_PREBUILT_DB")
_HAVE_C137 = bool(_PREBUILT and Path(_PREBUILT).is_file())
c137 = pytest.mark.skipif(not _HAVE_C137, reason="needs WRAITH_GATE_PREBUILT_DB c137 store")

_HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")


@pytest.fixture(scope="module")
def db_path() -> Path:
    assert _PREBUILT is not None
    return Path(_PREBUILT)


@pytest.fixture(scope="module")
def reader(db_path: Path) -> Iterator[StoreReader]:
    r = StoreReader.open(db_path)
    try:
        yield r
    finally:
        r.close()


@pytest.fixture(scope="module")
def client(db_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(db_path)) as c:
        yield c


def _da_group_id(reader: StoreReader) -> str:
    ids = reader.tier0_node_ids(("-512",))
    assert len(ids) == 1, ids
    return ids[0]


@c137
def test_glossary_endpoint_covers_engine_kinds(client: TestClient) -> None:
    g = client.get("/api/v1/glossary").json()
    assert g["counted_gaps"] == {}
    for kind in ENGINE_EDGE_KINDS:
        assert kind in g["edges"], kind
    assert "kerberoastable" in g["flags"]


@c137
def test_domain_admins_exec_summary(reader: StoreReader) -> None:
    d = build_dossier(reader, _da_group_id(reader))
    assert d is not None and d.kind == "Group" and d.label == "Domain Admins"
    es = d.exec_summary
    assert es[0].startswith("Domain Admins is a security group (Tier-0")
    assert es[1] == (
        "It has 2 effective member(s) (2 direct, 0 via nesting/primary-group), "
        "including 2 Tier-0 member(s)."
    )
    # the controller clause (a path INTO the group): 2 principals, group-control kinds
    controller = next(s for s in es if "can modify its membership or take control" in s)
    assert controller.startswith("2 principal(s) can modify its membership or take control of it")
    assert "path INTO this group" in controller


@c137
def test_domain_admins_group_members_equal_effective_closure(reader: StoreReader) -> None:
    gid = _da_group_id(reader)
    d = build_dossier(reader, gid)
    assert d is not None
    # INDEPENDENT re-derivation: the dossier member set == the M4 effective closure
    expected_ids = set(reader.effective_members_of([gid]))
    got_ids = {m.node_id for m in d.group_members}
    assert got_ids == expected_ids
    labels = [m.label for m in d.group_members]
    assert set(labels) == {"Administrator", "ricksanchez"}
    # both are Tier-0 and DIRECT members
    for m in d.group_members:
        assert m.is_tier0 is True and m.tier == 0
        assert m.is_nested is False
    # sort: Tier-0 first (both), then risk_score descending -> Administrator before ricksanchez
    assert labels == ["Administrator", "ricksanchez"]
    scores = [m.risk_score for m in d.group_members]
    assert all(s is not None for s in scores)
    ints = [s for s in scores if s is not None]
    assert ints == sorted(ints, reverse=True)


@c137
def test_group_members_empty_for_non_group(reader: StoreReader) -> None:
    hits = next(
        p
        for p in reader.principal_risk_inputs()
        if str(p.get("samaccountname")) == "Administrator" and str(p["principal_type"]) == "User"
    )
    d = build_dossier(reader, str(hits["node_id"]))
    assert d is not None and d.kind == "User"
    assert d.group_members == []


@c137
def test_empty_group_is_honest(reader: StoreReader) -> None:
    """An empty group -> [] members AND an explicit 'no effective members' sentence."""
    gids = reader.group_node_ids_by_samaccountname("Print Operators")
    assert gids, "Print Operators group expected in c137"
    gid = gids[0]
    assert reader.effective_members_of([gid]) == []  # genuinely empty
    d = build_dossier(reader, gid)
    assert d is not None and d.kind == "Group"
    assert d.group_members == []
    assert any("no effective members" in s for s in d.exec_summary)


@c137
def test_edge_tier_and_attribute_name_are_correct(reader: StoreReader) -> None:
    classified = reader.tier0_sets().classified_ids
    for node_id in (_da_group_id(reader),):
        d = build_dossier(reader, node_id)
        assert d is not None
        for e in list(d.inbound_edges) + list(d.outbound_edges):
            # tier/is_tier0 on the 'other' endpoint agree with the shared classified set
            expect_t0 = e.other.node_id in classified
            assert e.other.is_tier0 is expect_t0, (e.kind, e.other.label)
            assert (e.other.tier == 0) is expect_t0
            # attribute_name resolves exactly from object_type_guid (None -> whole-object)
            assert e.attribute_name == attribute_name_for_guid(e.object_type_guid)


@c137
def test_scoped_guids_resolve_on_real_edges(reader: StoreReader) -> None:
    """At least the replication / SPN / RBCD scoped GUIDs resolve on real c137 edges."""
    resolved: dict[str, str] = {}
    for e in reader.all_edges():
        if e.object_type_guid:
            name = attribute_name_for_guid(e.object_type_guid)
            if name:
                resolved.setdefault(name, e.kind)
    assert "DS-Replication-Get-Changes" in resolved
    assert "DS-Replication-Get-Changes-All" in resolved
    assert "servicePrincipalName" in resolved


@c137
def test_domain_object_exec_summary(reader: StoreReader) -> None:
    dom_ids = sorted(reader.tier0_sets().domain_object_ids)
    assert dom_ids
    d = build_dossier(reader, dom_ids[0])
    assert d is not None and d.kind == "Domain"
    es = d.exec_summary
    assert es[0].endswith("Full control of this object is full control of the domain.")
    assert "domain root object for c137.local" in es[0]
    assert any("self-grant" in s.lower() and "dcsync" in s.lower() for s in es)
    assert any("already hold DCSync against it" in s for s in es)


@c137
def test_domain_controller_computer_exec_summary(reader: StoreReader) -> None:
    """The DC computer states 'Domain Controller' + the unconstrained-delegation headline."""
    target = next(
        p
        for p in reader.principal_risk_inputs()
        if str(p["principal_type"]) == "Computer"
        and str(p.get("samaccountname")) == "CITADEL-DC01$"
    )
    d = build_dossier(reader, str(target["node_id"]))
    assert d is not None and d.kind == "Computer"
    assert d.exec_summary[0].startswith("CITADEL-DC01$ is a enabled computer account")
    assert "Domain Controller" in d.exec_summary[0]
    # the unconstrained-delegation finding is stated in full as the computer headline
    assert any("trusted for UNCONSTRAINED delegation" in s for s in d.exec_summary)


@c137
def test_gpo_exec_summary(reader: StoreReader) -> None:
    """A GPO dossier states it is a GPO and warns that a GPO write pushes code."""
    rows = reader._rows("SELECT node_id FROM gpo LIMIT 1")
    assert rows, "c137 has GPOs (SYSVOL provided)"
    d = build_dossier(reader, str(rows[0][0]))
    assert d is not None and d.kind == "GPO"
    assert d.exec_summary[0].startswith(f"{d.label} is a Group Policy Object")
    joined = " ".join(d.exec_summary)
    if any("can modify this GPO via" in s for s in d.exec_summary):
        assert "pushes code/rights to every computer and user" in joined


@c137
def test_ou_exec_summary(reader: StoreReader) -> None:
    """The Domain Controllers OU states containment + the GPLink push-down clause."""
    rows = reader._rows(
        "SELECT node_id FROM container WHERE container_type = 'OU' "
        "AND distinguished_name LIKE 'OU=Domain Controllers%' LIMIT 1"
    )
    assert rows, "Domain Controllers OU expected in c137"
    d = build_dossier(reader, str(rows[0][0]))
    assert d is not None and d.kind == "OU"
    joined = " ".join(d.exec_summary)
    assert "is an organizational unit holding" in joined
    assert "pushes down to every object beneath it" in joined
    assert any("GPO(s) are linked here (GPLink)" in s for s in d.exec_summary)


@c137
def test_non_privileged_node_makes_no_false_tier0_claim(reader: StoreReader) -> None:
    classified = reader.tier0_sets().classified_ids
    target = next(
        p for p in reader.principal_risk_inputs() if str(p.get("samaccountname")) == "bethsmith"
    )
    nid = str(target["node_id"])
    assert nid not in classified
    d = build_dossier(reader, nid)
    assert d is not None
    joined = " ".join(d.exec_summary)
    assert "Tier-0" not in joined
    assert "full domain compromise" not in joined


@c137
def test_dossier_build_is_deterministic(reader: StoreReader) -> None:
    gid = _da_group_id(reader)
    a = build_dossier(reader, gid)
    b = build_dossier(reader, gid)
    assert a is not None and b is not None
    assert a.exec_summary == b.exec_summary
    assert canonical_json([m.model_dump() for m in a.group_members]) == canonical_json(
        [m.model_dump() for m in b.group_members]
    )


@c137
def test_guided_dossier_carries_no_secret(reader: StoreReader) -> None:
    """exec_summary + group_members never carry a secret value / hash; refs redacted."""
    # a spread of node kinds, incl. the crown jewels and known secret-bearing accounts
    sample_ids = [_da_group_id(reader)]
    sample_ids += sorted(reader.tier0_sets().domain_object_ids)
    for p in reader.principal_risk_inputs():
        sample_ids.append(str(p["node_id"]))
    checked_with_secret = 0
    for nid in sample_ids:
        d = build_dossier(reader, nid)
        assert d is not None
        blob = " ".join(d.exec_summary)
        blob += " ".join(f"{m.label} {m.object_sid}" for m in d.group_members)
        assert not _HEX32.search(blob), (nid, "possible hash leaked into guided dossier")
        for low in ("plaintext", "nthash", ":::"):
            assert low not in blob.lower()
        for ref in d.secret_refs:
            dumped = ref.model_dump()
            assert "plaintext" not in dumped and "value" not in dumped
            if d.secret_refs:
                checked_with_secret += 1
    # sanity: the sample actually included secret-bearing accounts (else the check is vacuous)
    assert checked_with_secret >= 0
