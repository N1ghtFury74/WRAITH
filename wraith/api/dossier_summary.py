"""Deterministic executive-summary composition for the guided dossier (doc 21 §2).

A pure function that turns the already-assembled dossier facts into 1-4 ordered
prose sentences from fixed per-kind templates + the static glossary. NO runtime
free-text / LLM: same data -> byte-identical sentences. A sentence is dropped when
its governing data is absent (no filler). All inline sets (rights lists) are sorted
and de-duplicated; band words come from the fixed :func:`risk_words` table.

Ordering is the fixed block order ``[S1 identity/role] [S2 posture] [S3 exposure]
[S4 flags]``; each returned list element is one block (one or more sentences).
Secret-free by construction — it reads only non-secret dossier fields.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from wraith.api.models import DossierEdge, GroupMemberRef, NodeRef, NodeRisk, UacFlagsOut
from wraith.api.queries import FULL_CONTROL_KINDS, TRUST_KINDS
from wraith.api.rights_glossary import EDGE_GLOSSARY, FLAG_GLOSSARY
from wraith.api.tiering import PRIVILEGED_GROUP_SID_SUFFIXES, is_control_edge

#: The control kinds that are a path INTO a group (doc 21 §2.3 Group S3): full
#: whole-object control + the member-write grants.
GROUP_CONTROL_KINDS: frozenset[str] = FULL_CONTROL_KINDS | {"AddMember", "AddSelf", "GenericWrite"}

#: ADCS node kinds that carry the persistent synthetic-only banner (doc 21 §2.3).
ADCS_SYNTHETIC_KINDS: frozenset[str] = frozenset(
    {
        "IssuancePolicy",
        "CertTemplate",
        "EnterpriseCA",
        "RootCA",
        "NTAuthStore",
        "AIACA",
        "CertificationAuthority",
    }
)

_ADCS_SYNTHETIC_NOTE: str = "ADCS edges are synthetic-tested and untested on real data in v1."

#: Fixed S4 "notable flags" priority (doc 21 §4.6 selection set), checked in order.
#: ``not_delegated`` / ``workstation_trust_account`` / ``account_disabled`` are
#: deliberately NOT here (disabled is stated in S1; the other two are neutral /
#: defensive) — avoiding a false-positive alarm.
_S4_FLAG_ORDER: tuple[str, ...] = (
    "unconstrained_delegation",
    "DCSync",
    "kerberoastable",
    "asrep_roastable",
    "password_not_required",
    "reversible_password",
    "sid_history",
    "trusted_to_auth_for_delegation",
    "dont_expire_password",
    "admincount",
)


@dataclass(frozen=True)
class SummaryContext:
    """The non-secret dossier facts :func:`compose_exec_summary` composes from.

    Populated by :func:`wraith.api.dossier.build_dossier` from the SAME store rows
    the dossier returns (one source of truth). ``tier0_classified_ids`` is the
    shared Tier-0 classification set; ``risk`` carries the transparent score, tier,
    and (doc 21 add #3) ``tier0_hops``.
    """

    kind: str
    label: str
    object_sid: str | None = None
    description: str | None = None
    spns: tuple[str, ...] = ()
    sid_history: tuple[str, ...] = ()
    admincount: int | None = None
    node_flags: Mapping[str, bool] = field(default_factory=dict)
    uac: UacFlagsOut | None = None
    inbound_edges: Sequence[DossierEdge] = ()
    outbound_edges: Sequence[DossierEdge] = ()
    group_memberships: Sequence[NodeRef] = ()
    group_members: Sequence[GroupMemberRef] = ()
    risk: NodeRisk | None = None
    tier0_classified_ids: frozenset[str] = frozenset()
    domain_fqdn: str | None = None
    functional_level: int | None = None


def risk_words(tier: int | None, score: int) -> str:
    """Return the fixed risk-band phrase for ``(tier, score)`` (doc 21 §2.2).

    Checked top-down, first match wins. Describes the score the operator already
    sees; it does not re-score. Never raises.
    """
    if tier == 0:
        return "Tier-0 — owning it is full domain compromise"
    if score >= 60:
        return "critical risk"
    if score >= 30:
        return "high risk"
    if score >= 10:
        return "elevated risk"
    if score >= 1:
        return "low risk"
    return "no standing risk signals"


def _flag_phrase(code: str) -> str:
    """Return the verbatim §4.6 one-phrase for a flag code (or the DCSync edge phrase)."""
    if code == "DCSync":
        return EDGE_GLOSSARY["DCSync"].action
    entry = FLAG_GLOSSARY.get(code)
    return entry.action if entry is not None else code


def _is_dcsync_holder(ctx: SummaryContext) -> bool:
    """Whether this node holds DCSync (an outbound DCSync edge or the risk factor)."""
    if any(e.kind == "DCSync" for e in ctx.outbound_edges):
        return True
    return ctx.risk is not None and any(f.code == "DCSYNC_HOLDER" for f in ctx.risk.factors)


def _active_s4_flags(ctx: SummaryContext, *, exclude: frozenset[str]) -> list[str]:
    """Return the ordered, de-duplicated S4 flag phrases that are set for ``ctx``."""
    uac = ctx.uac
    nf = ctx.node_flags
    active: dict[str, bool] = {
        "unconstrained_delegation": bool(nf.get("unconstrained_delegation")),
        "DCSync": _is_dcsync_holder(ctx),
        "kerberoastable": bool(nf.get("kerberoastable")),
        "asrep_roastable": bool(nf.get("asrep_roastable")),
        "password_not_required": bool(uac and uac.password_not_required),
        "reversible_password": bool(uac and uac.reversible_password),
        "sid_history": bool(ctx.sid_history),
        "trusted_to_auth_for_delegation": bool(uac and uac.trusted_to_auth_for_delegation),
        "dont_expire_password": bool(uac and uac.dont_expire_password),
        "admincount": bool(ctx.admincount),
    }
    return [
        _flag_phrase(code) for code in _S4_FLAG_ORDER if code not in exclude and active.get(code)
    ]


def _enabled_word(uac: UacFlagsOut | None) -> str:
    """Return ``"disabled"`` iff the account is explicitly disabled, else ``"enabled"``."""
    return "disabled" if (uac is not None and uac.enabled is False) else "enabled"


def _control_in(ctx: SummaryContext, kinds: frozenset[str] | None = None) -> tuple[int, list[str]]:
    """Return ``(distinct inbound controller count, sorted inbound control-kind list)``.

    Restricted to ``is_control_edge`` inbound edges (never structural), optionally
    narrowed to ``kinds`` (e.g. the group-control set). Deterministic.
    """
    edges = [
        e
        for e in ctx.inbound_edges
        if is_control_edge(e.kind) and (kinds is None or e.kind in kinds)
    ]
    controllers = {e.other.node_id for e in edges}
    rights = sorted({e.kind for e in edges})
    return len(controllers), rights


def _control_out_count(ctx: SummaryContext) -> int:
    """Return the distinct count of objects this node holds a control edge over."""
    return len({e.other.node_id for e in ctx.outbound_edges if is_control_edge(e.kind)})


def _reach_sentence(tier0_hops: int | None, *, low_effort: bool) -> str | None:
    """Return the 'reaches Tier-0 in K hops' sentence, or ``None`` when unreachable."""
    if tier0_hops is None:
        return None
    suffix = " — low-effort" if (low_effort and tier0_hops <= 2) else ""
    return f"It can reach Tier-0 in {tier0_hops} hop(s){suffix}."


def _tier0_hops(ctx: SummaryContext) -> int | None:
    return ctx.risk.tier0_hops if ctx.risk is not None else None


def _posture(ctx: SummaryContext) -> str:
    score = ctx.risk.score if ctx.risk is not None else 0
    tier = ctx.risk.tier if ctx.risk is not None else None
    return f"Risk posture: {risk_words(tier, score)}."


def _join(subs: Sequence[str]) -> str | None:
    """Join non-empty sub-sentences with a single space, or ``None`` when empty."""
    parts = [s for s in subs if s]
    return " ".join(parts) if parts else None


# --- per-kind composers -------------------------------------------------------
def _compose_user(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    s1 = f"{ctx.label} is a {_enabled_word(ctx.uac)} user account"
    if ctx.description:
        s1 += f" ({ctx.description})"
    if ctx.spns:
        s1 += f" — service account advertising {len(ctx.spns)} SPN(s)"
    out.append(s1 + ".")

    k = len(ctx.group_memberships)
    s2_subs = [_posture(ctx)]
    if k > 0:
        tier0_names = sorted(
            g.label for g in ctx.group_memberships if g.node_id in ctx.tier0_classified_ids
        )
        memb = f"It is an effective member of {k} group(s)"
        if tier0_names:
            memb += f", including {', '.join(tier0_names)} (Tier-0)"
        s2_subs.append(memb + ".")
    out.append(" ".join(s2_subs))

    n_ctrl, rights = _control_in(ctx)
    s3_subs: list[str] = []
    if n_ctrl > 0:
        s3_subs.append(f"{n_ctrl} principal(s) can take control of it via {', '.join(rights)}.")
    reach = _reach_sentence(_tier0_hops(ctx), low_effort=True)
    if reach:
        s3_subs.append(reach)
    n_out = _control_out_count(ctx)
    if n_out > 0:
        s3_subs.append(f"It holds control over {n_out} object(s).")
    if _is_dcsync_holder(ctx):
        s3_subs.append("It can replicate domain secrets (DCSync) — full domain compromise.")
    s3 = _join(s3_subs)
    if s3:
        out.append(s3)

    # DCSync stated in S3 -> excluded from the S4 notable list (no duplication).
    flags = _active_s4_flags(ctx, exclude=frozenset({"DCSync"}))
    if flags:
        out.append("Notable: " + "; ".join(flags) + ".")
    return out


def _compose_computer(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    s1 = f"{ctx.label} is a {_enabled_word(ctx.uac)} computer account"
    if ctx.uac is not None and ctx.uac.server_trust_account:
        s1 += " — a Domain Controller"
    if ctx.uac is not None and ctx.uac.partial_secrets_account:
        s1 += " (RODC)"
    out.append(s1 + ".")

    out.append(_posture(ctx))

    n_ctrl, rights = _control_in(ctx)
    s3_subs: list[str] = []
    if n_ctrl > 0:
        s3_subs.append(
            f"{n_ctrl} principal(s) can take control of this host via {', '.join(rights)}."
        )
    reach = _reach_sentence(_tier0_hops(ctx), low_effort=True)
    if reach:
        s3_subs.append(reach)
    n_admins = len({e.other.node_id for e in ctx.inbound_edges if e.kind == "AdminTo"})
    if n_admins > 0:
        s3_subs.append(f"{n_admins} principal(s) are local admin on it (AdminTo).")
    s3 = _join(s3_subs)
    if s3:
        out.append(s3)

    # Unconstrained delegation gets its full headline clause here, so it is excluded
    # from the short S4 notable list.
    flags = _active_s4_flags(ctx, exclude=frozenset({"unconstrained_delegation"}))
    s4_subs: list[str] = []
    if flags:
        s4_subs.append("Notable: " + "; ".join(flags) + ".")
    if ctx.node_flags.get("unconstrained_delegation"):
        s4_subs.append(
            "This host is trusted for UNCONSTRAINED delegation — anyone who authenticates "
            "to it (a DC can be coerced) exposes their TGT; capturing a DC's TGT is domain "
            "compromise."
        )
    s4 = _join(s4_subs)
    if s4:
        out.append(s4)
    return out


def _compose_group(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    is_tier0 = ctx.risk is not None and ctx.risk.tier == 0
    s1 = f"{ctx.label} is a security group"
    if is_tier0:
        s1 += " (Tier-0 — membership is domain-compromise-equivalent)"
    elif ctx.object_sid is not None and any(
        ctx.object_sid.endswith(sfx) for sfx in PRIVILEGED_GROUP_SID_SUFFIXES
    ):
        s1 += " (privileged)"
    out.append(s1 + ".")

    members = list(ctx.group_members)
    n_members = len(members)
    if n_members == 0:
        out.append(
            "It has no effective members — an empty group (a controller of it could still "
            "populate it)."
        )
    else:
        n_nested = sum(1 for m in members if m.is_nested)
        n_direct = n_members - n_nested
        n_tier0 = sum(1 for m in members if m.is_tier0)
        s2 = (
            f"It has {n_members} effective member(s) "
            f"({n_direct} direct, {n_nested} via nesting/primary-group)"
        )
        if n_tier0 > 0:
            s2 += f", including {n_tier0} Tier-0 member(s)"
        out.append(s2 + ".")

    n_ctrl, rights = _control_in(ctx, GROUP_CONTROL_KINDS)
    s3_subs: list[str] = []
    if n_ctrl > 0:
        s3_subs.append(
            f"{n_ctrl} principal(s) can modify its membership or take control of it via "
            f"{', '.join(rights)} — any of these is a path INTO this group."
        )
    reach = _reach_sentence(_tier0_hops(ctx), low_effort=False)
    if reach:
        s3_subs.append(reach)
    s3 = _join(s3_subs)
    if s3:
        out.append(s3)

    out_rights = sorted({e.kind for e in ctx.outbound_edges if is_control_edge(e.kind)})
    if out_rights:
        out.append("Notable: this group grants its members " + ", ".join(out_rights) + ".")
    return out


def _compose_domain(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    s1 = f"{ctx.label} is the domain root object"
    if ctx.domain_fqdn:
        s1 += f" for {ctx.domain_fqdn}"
    if ctx.functional_level is not None:
        s1 += f" (functional level {ctx.functional_level})"
    s1 += ". Full control of this object is full control of the domain."
    out.append(s1)

    n_ctrl, _ = _control_in(ctx, FULL_CONTROL_KINDS)
    out.append(
        f"{n_ctrl} principal(s) hold control (GenericAll/WriteDacl/WriteOwner/Owns) over it; "
        "rewriting its DACL self-grants DCSync (every password hash, a Golden Ticket)."
    )

    n_dcsync = len({e.other.node_id for e in ctx.inbound_edges if e.kind == "DCSync"})
    out.append(f"{n_dcsync} principal(s) already hold DCSync against it.")

    n_trusts = sum(
        1 for e in list(ctx.inbound_edges) + list(ctx.outbound_edges) if e.kind in TRUST_KINDS
    )
    if n_trusts > 0:
        out.append(f"Notable: {n_trusts} domain trust(s) present — see the trust edges below.")
    return out


def _compose_ou_container(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    noun = "an organizational unit" if ctx.kind == "OU" else "a container"
    n_contained = sum(1 for e in ctx.outbound_edges if e.kind == "Contains")
    out.append(f"{ctx.label} is {noun} holding {n_contained} object(s).")

    n_ctrl, rights = _control_in(ctx)
    if n_ctrl > 0:
        s2 = (
            f"{n_ctrl} principal(s) can control it via {', '.join(rights)}; control of an OU "
            "pushes down to every object beneath it (ACL inheritance / linked GPOs)."
        )
        if "WriteGPLink" in rights:
            s2 += " WriteGPLink here can link a malicious GPO to this container."
        out.append(s2)

    n_gplinks = sum(1 for e in ctx.inbound_edges if e.kind == "GPLink")
    if n_gplinks > 0:
        out.append(
            f"{n_gplinks} GPO(s) are linked here (GPLink) — their settings apply to objects "
            "below."
        )
    return out


def _compose_gpo(ctx: SummaryContext) -> list[str]:
    out: list[str] = []
    links = [e for e in ctx.outbound_edges if e.kind == "GPLink"]
    s1 = f"{ctx.label} is a Group Policy Object"
    if links:
        s1 += f", linked to {len(links)} container(s)"
    out.append(s1 + ".")

    n_ctrl, rights = _control_in(ctx)
    if n_ctrl > 0:
        out.append(
            f"{n_ctrl} principal(s) can modify this GPO via {', '.join(rights)}; editing a "
            "linked GPO pushes code/rights to every computer and user it applies to."
        )

    if links:
        labels = sorted({e.other.label for e in links})
        out.append(f"It applies to objects under {', '.join(labels)}.")
    return out


def _compose_issuance_policy(ctx: SummaryContext) -> list[str]:
    out: list[str] = [f"{ctx.label} is a certificate issuance policy (OID)."]
    oid_links = [e for e in ctx.outbound_edges if e.kind == "OIDGroupLink"]
    if oid_links:
        target = sorted({e.other.label for e in oid_links})[0]
        out.append(
            f"It is linked to group {target} (OIDGroupLink): enrolling a certificate carrying "
            "this policy OID grants that group's membership (ESC13)."
        )
    out.append(_ADCS_SYNTHETIC_NOTE)
    return out


def _compose_generic(ctx: SummaryContext) -> list[str]:
    out: list[str] = [f"{ctx.label} is a {ctx.kind}."]
    n_ctrl, rights = _control_in(ctx)
    if n_ctrl > 0:
        out.append(f"{n_ctrl} principal(s) can control it via {', '.join(rights)}.")
    if ctx.kind == "Base":
        # Research 11 §3.7: an honest note that a Base object is NOT an
        # attack-modeled entity — it is shown only because a principal holds
        # control over it (so the N-object control list is legible, not N dead hashes).
        out.append("Not an attack-modeled entity; shown because a principal holds control over it.")
    if ctx.kind in ADCS_SYNTHETIC_KINDS:
        out.append(_ADCS_SYNTHETIC_NOTE)
    return out


def compose_exec_summary(ctx: SummaryContext) -> list[str]:
    """Compose the ordered executive-summary sentences for a dossier (doc 21 §2).

    Inputs:
        ctx: the non-secret dossier facts (see :class:`SummaryContext`).

    Returns:
        1-4 ordered blocks (``[S1][S2][S3][S4]``); a block is omitted when its
        governing data is absent. Deterministic: identical ``ctx`` -> identical
        list. Never contains a secret value.

    Failure modes:
        Never raises; an unknown ``kind`` degrades to a minimal, honest summary.
    """
    dispatch = {
        "User": _compose_user,
        "Computer": _compose_computer,
        "Group": _compose_group,
        "Domain": _compose_domain,
        "OU": _compose_ou_container,
        "Container": _compose_ou_container,
        "GPO": _compose_gpo,
        "IssuancePolicy": _compose_issuance_policy,
    }
    composer = dispatch.get(ctx.kind, _compose_generic)
    return composer(ctx)
