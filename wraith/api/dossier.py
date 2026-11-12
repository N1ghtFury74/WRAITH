"""Per-entity dossier assembly (M7).

Builds the full inspector/dossier view for one node: identity, decoded
userAccountControl flags, derived node flags, inbound/outbound edges (ACEs) with
the other party resolved, effective group memberships (M4
``effective_membership``), secrets-by-reference (REDACTED — never plaintext,
NFR-05), the provenance block, and the node's transparent risk summary.

Pure assembly over the read-only store; no writes, no secret plaintext.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Sequence
from datetime import datetime
from typing import cast

from wraith.analysis.adcs_esc import NODE_PROP_DCOM, NODE_PROP_ESC11, NODE_PROP_ESC16
from wraith.api.dossier_summary import SummaryContext, compose_exec_summary
from wraith.api.models import (
    CaNodeFindingOut,
    DossierEdge,
    GroupMemberRef,
    NodeDossier,
    NodeRef,
    NodeRisk,
    ProvenanceOut,
    SecretRefOut,
    UacFlagsOut,
)
from wraith.api.rights_glossary import attribute_name_for_guid
from wraith.api.risk import score_nodes
from wraith.api.store import (
    GAP_UNRESOLVED_EDGE_ENDPOINT,
    CaNodeFindingRow,
    EdgeRow,
    ProvenanceRow,
    StoreReader,
    Tier0Sets,
)
from wraith.edges.node_flags import compute_node_flags
from wraith.normalize.decoders import (
    UAC_ACCOUNTDISABLE,
    UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH,
    UAC_ENCRYPTED_TEXT_PWD_ALLOWED,
    UAC_NOT_DELEGATED,
    UAC_PARTIAL_SECRETS_ACCOUNT,
    UAC_PASSWD_NOTREQD,
    UAC_SERVER_TRUST_ACCOUNT,
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
    UAC_WORKSTATION_TRUST_ACCOUNT,
    decode_uac_enabled,
)


def decode_uac(uac: int | None) -> UacFlagsOut:
    """Decode a raw ``userAccountControl`` integer into named booleans (public facts)."""
    u = uac or 0
    return UacFlagsOut(
        raw=uac,
        enabled=decode_uac_enabled(uac),
        account_disabled=bool(u & UAC_ACCOUNTDISABLE),
        password_not_required=bool(u & UAC_PASSWD_NOTREQD),
        dont_expire_password=bool(u & UAC_DONT_EXPIRE_PASSWORD),
        trusted_for_delegation=bool(u & UAC_TRUSTED_FOR_DELEGATION),
        trusted_to_auth_for_delegation=bool(u & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        not_delegated=bool(u & UAC_NOT_DELEGATED),
        dont_require_preauth=bool(u & UAC_DONT_REQ_PREAUTH),
        server_trust_account=bool(u & UAC_SERVER_TRUST_ACCOUNT),
        workstation_trust_account=bool(u & UAC_WORKSTATION_TRUST_ACCOUNT),
        partial_secrets_account=bool(u & UAC_PARTIAL_SECRETS_ACCOUNT),
        reversible_password=bool(u & UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
    )


def _prov_out(p: ProvenanceRow) -> ProvenanceOut:
    """Convert a store provenance row into the API provenance block."""
    return ProvenanceOut(
        source_file=p.source_file,
        image_sha256=p.image_sha256,
        source_object_id=p.source_object_id,
        directory_timestamp=p.directory_timestamp,
        ingest_run_id=p.ingest_run_id,
    )


def _secret_refs(raw: Sequence[object]) -> list[SecretRefOut]:
    """Map stored secret-ref structs to REDACTED references (never plaintext)."""
    out: list[SecretRefOut] = []
    for item in raw:
        d = item if isinstance(item, dict) else {}
        out.append(
            SecretRefOut(
                secret_id=d.get("secret_id"),
                secret_type=d.get("secret_type"),
                label=d.get("label"),
                decrypted=d.get("decrypted"),
                decryptable_offline=d.get("decryptable_offline"),
            )
        )
    return out


#: The explicit label for an edge endpoint id that cannot be resolved to any node.
#: The raw id is kept on :attr:`NodeRef.node_id` (the forensic / secondary line) so
#: it stays visible for investigation — it is just never the human-facing label.
_UNRESOLVED_LABEL: str = "unresolved object"
_UNRESOLVED_KIND: str = "Unresolved"


def _edge_models(
    rows: Sequence[EdgeRow], direction: str, labels: dict[str, NodeRef]
) -> tuple[list[DossierEdge], dict[str, int], int]:
    """Build dossier edge models + a ``kind -> count`` tally for one direction.

    Inputs:
        rows: the inbound or outbound edges for the node.
        direction: ``"inbound"`` (resolve the source endpoint) or ``"outbound"``
            (resolve the target endpoint).
        labels: the resolved ``node_id -> NodeRef`` map (the superset node
            id-space, incl. ``Base`` objects — research 11 Fix A).

    Returns:
        ``(models, kind_counts, unresolved_count)``. ``unresolved_count`` is the
        number of edge endpoints that resolved to no node even after the ``Base``
        projection; each such endpoint renders as an explicit ``Unresolved``
        :class:`NodeRef` (``label="unresolved object"``, raw id kept on
        ``node_id``) — never a bare hash (Fix B). The caller folds the count into
        the dossier's ``counted_gaps`` ledger.

    Failure modes:
        Never raises; an unmapped endpoint degrades to the counted ``Unresolved``
        marker, not a silent wrong answer.
    """
    models: list[DossierEdge] = []
    counts: dict[str, int] = {}
    unresolved = 0
    for e in rows:
        other_id = e.source_node_id if direction == "inbound" else e.target_node_id
        other = labels.get(other_id)
        if other is None:
            unresolved += 1
            other = NodeRef(node_id=other_id, kind=_UNRESOLVED_KIND, label=_UNRESOLVED_LABEL)
        models.append(
            DossierEdge(
                edge_id=e.edge_id,
                kind=e.kind,
                direction=direction,
                other=other,
                confidence=e.confidence,
                is_inherited=e.is_inherited,
                access_mask=e.access_mask,
                object_type_guid=e.object_type_guid,
                attribute_name=attribute_name_for_guid(e.object_type_guid),
            )
        )
        counts[e.kind] = counts.get(e.kind, 0) + 1
    return models, dict(sorted(counts.items())), unresolved


#: Static, authored ``prop -> (title, caption)`` text for a CA-host node finding.
#: Each caption states what the finding means AND that it was decided from the CA
#: host hive (the honesty rule). Closed set produced by the gated ADCS-ESC engine;
#: an unknown future prop degrades to a neutral self-describing caption (never a
#: crash, never a guessed abuse).
_CA_FINDING_TEXT: dict[str, tuple[str, str]] = {
    NODE_PROP_ESC11: (
        "ESC11 — CA does not enforce request encryption",
        "This Enterprise CA does not enforce packet-privacy (encryption) on the "
        "certificate-request RPC, so an attacker who can relay NTLM to its ICertPassage "
        "interface may obtain a certificate (ESC11). Decided from the CA host SYSTEM "
        "hive (InterfaceFlags) — it is not derivable from ntds.dit alone.",
    ),
    NODE_PROP_ESC16: (
        "ESC16 — SID security extension disabled",
        "This Enterprise CA disables the SID security extension CA-wide, so issued "
        "certificates omit the requester SID and strong certificate mapping is "
        "weakened (ESC16), enabling impersonation. Decided from the CA host SYSTEM "
        "hive (DisableExtensionList) — not derivable from ntds.dit alone.",
    ),
    NODE_PROP_DCOM: (
        "DCOM activation summary (CA host)",
        "Machine-wide DCOM activation summary for the CA host (EnableDCOM=Y/N). Remote "
        "ESC7 abuse via ICertAdmin additionally needs DCOM reachability, so this is "
        "surfaced as context. Summary only — no security-descriptor bytes are exposed. "
        "Decided from the CA host SOFTWARE hive.",
    ),
}


def _ca_findings_out(rows: Sequence[CaNodeFindingRow]) -> list[CaNodeFindingOut]:
    """Map persisted CA-host findings to their typed, self-describing dossier shape.

    Attaches the authored ``title``/``caption`` for each ``prop`` (:data:`_CA_FINDING_TEXT`)
    and carries the finding's hive provenance verbatim. An unknown ``prop`` degrades
    to a neutral caption rather than crashing (never a guessed abuse). No secret is
    surfaced — ``value`` is the stored ``Y/N`` summary / ``"true"`` flag only. Rows
    arrive already ordered by ``prop`` (deterministic).

    Failure modes:
        Never raises.
    """
    out: list[CaNodeFindingOut] = []
    for r in rows:
        title, caption = _CA_FINDING_TEXT.get(
            r.prop,
            (
                r.prop,
                "A CA-host finding WRAITH records but does not yet have a caption for "
                "(decided from the CA host hive).",
            ),
        )
        out.append(
            CaNodeFindingOut(
                prop=r.prop,
                title=title,
                caption=caption,
                value=r.value,
                provenance=_prov_out(r.provenance),
            )
        )
    return out


def _risk_for(reader: StoreReader, node_id: str, principal: dict[str, object]) -> NodeRisk | None:
    """Compute the transparent risk score for a single principal node."""
    risk_input = {
        "node_id": principal["node_id"],
        "principal_type": principal["principal_type"],
        "object_sid": principal.get("object_sid"),
        "samaccountname": principal.get("samaccountname"),
        "uac_flags": principal.get("uac_flags"),
        "enabled": principal.get("enabled"),
        "spns": principal.get("spns"),
        "sid_history": principal.get("sid_history"),
        "admincount": principal.get("admincount"),
        "label": principal.get("samaccountname") or node_id,
        "domain_fqdn": principal.get("domain_fqdn"),
    }
    scored = score_nodes([risk_input], reader.all_edges(), reader.tier0_sets())
    return scored[0] if scored else None


def _scored_map(reader: StoreReader, tier0: Tier0Sets) -> dict[str, NodeRisk]:
    """Score every principal + the Domain object once -> ``node_id -> NodeRisk``.

    The SAME scored map the Risk dashboard uses (one source of truth), consumed by
    the Group-dossier member list to attach each member's transparent score/tier.
    """
    principals = reader.principal_risk_inputs() + reader.domain_risk_inputs()
    scored = score_nodes(principals, reader.all_edges(), tier0)
    return {nr.node_id: nr for nr in scored}


def _member_confidence_map(
    all_edges: Sequence[EdgeRow], group_node_id: str, member_ids: Sequence[str]
) -> dict[str, str]:
    """Return ``member_node_id -> confidence`` for a group's effective members.

    A member is ``"confirmed"`` iff it reaches ``group_node_id`` by a ``MemberOf``
    path whose every hop is ``confidence="confirmed"`` (a stored-``member`` link or
    an implicit primary-group membership). A member reachable ONLY via at least one
    ``"inferred"`` hop — a special-identity fold-in (Everyone / Authenticated Users
    / Domain Users) — is ``"inferred"`` (research 11 §2.1/§2.2: a logon-time truth,
    not a stored fact, and forensically a weaker claim). Computed by a reverse BFS
    from the group over the confirmed-only ``MemberOf`` subgraph; every member not
    in that confirmed-reachable set is an effective member via an inferred hop.

    Pure over ``all_edges``; deterministic; never raises.
    """
    confirmed_radj: dict[str, list[str]] = defaultdict(list)
    for e in all_edges:
        if e.kind == "MemberOf" and e.confidence == "confirmed":
            # MemberOf is member(source) -> group(target); reverse for group->member.
            confirmed_radj[e.target_node_id].append(e.source_node_id)
    confirmed_reach: set[str] = set()
    queue: deque[str] = deque([group_node_id])
    while queue:
        g = queue.popleft()
        for m in confirmed_radj.get(g, ()):
            if m not in confirmed_reach:
                confirmed_reach.add(m)
                queue.append(m)
    return {m: ("confirmed" if m in confirmed_reach else "inferred") for m in member_ids}


def _build_group_members(
    reader: StoreReader,
    node_id: str,
    inbound: Sequence[EdgeRow],
    tier0: Tier0Sets,
    all_edges: Sequence[EdgeRow],
) -> list[GroupMemberRef]:
    """Build the effective-member list for a Group dossier (doc 21 §3; research 11 §2).

    Reads the M4 ``effective_membership`` closure (``effective_members_of`` — the
    SAME source the hunt catalog uses), resolves each member's label/kind/sid, and
    attaches Tier-0 classification (``tier0.classified_ids``) and the shared risk
    score. ``is_nested`` is ``True`` for a member NOT present as a direct inbound
    ``MemberOf`` source (i.e. folded in via nested-group / primary-group) and is
    the SINGLE source of truth for the direct/nested split (research 11 §2.2).
    ``confidence`` is the strongest member->group derivation (``_member_confidence_map``)
    so a special-identity-only fold-in is marked ``inferred``. Sorted Tier-0 first,
    then ``risk_score`` descending, then ``label`` (deterministic).

    Failure modes:
        Never raises; an empty group yields ``[]`` (the caller/UI surfaces "no
        members", itself a finding).
    """
    member_ids = reader.effective_members_of([node_id])
    if not member_ids:
        return []
    direct_ids = {e.source_node_id for e in inbound if e.kind == "MemberOf"}
    confidence_by_id = _member_confidence_map(all_edges, node_id, member_ids)
    scored = _scored_map(reader, tier0)
    refs: list[GroupMemberRef] = []
    for n in reader.nodes_by_ids(member_ids):
        is_t0 = n.node_id in tier0.classified_ids
        nr = scored.get(n.node_id)
        refs.append(
            GroupMemberRef(
                node_id=n.node_id,
                kind=n.kind,
                label=n.label,
                object_sid=n.object_sid,
                tier=0 if is_t0 else None,
                risk_score=nr.score if nr is not None else None,
                is_tier0=is_t0,
                is_nested=n.node_id not in direct_ids,
                confidence=confidence_by_id.get(n.node_id),
            )
        )

    def _key(m: GroupMemberRef) -> tuple[int, int, int, str]:
        return (
            0 if m.is_tier0 else 1,
            0 if m.risk_score is not None else 1,
            -(m.risk_score or 0),
            m.label,
        )

    refs.sort(key=_key)
    return refs


def build_dossier(reader: StoreReader, node_id: str) -> NodeDossier | None:
    """Assemble the full :class:`NodeDossier` for ``node_id``.

    Inputs:
        reader: the read-only store accessor.
        node_id: the surrogate node id to inspect.

    Returns:
        A :class:`NodeDossier`, or ``None`` if the id is unknown in every node
        table.

    Failure modes:
        Never raises on content; an edge endpoint id that resolves to no node even
        after the ``Base`` projection (research 11 Fix A) renders as an explicit
        ``Unresolved`` :class:`NodeRef` (raw id kept on ``node_id``, never shown as
        the label) and is counted under ``counted_gaps`` — honest, never a silent
        wrong answer. Secret references are always redacted.
    """
    inbound = reader.inbound_edges(node_id)
    outbound = reader.outbound_edges(node_id)
    tier0 = reader.tier0_sets()
    classified = tier0.classified_ids

    # Resolve labels for every "other" endpoint (and self), tagging Tier-0 so the
    # UI can badge a controller / target that is Tier-0 (same classification set as
    # everywhere else — one source of truth).
    other_ids = sorted(
        {node_id} | {e.source_node_id for e in inbound} | {e.target_node_id for e in outbound}
    )
    labels = {
        n.node_id: NodeRef(
            node_id=n.node_id,
            kind=n.kind,
            label=n.label,
            tier=0 if n.node_id in classified else None,
            is_tier0=n.node_id in classified,
        )
        for n in reader.nodes_by_ids(other_ids)
    }

    in_models, in_counts, in_unresolved = _edge_models(inbound, "inbound", labels)
    out_models, out_counts, out_unresolved = _edge_models(outbound, "outbound", labels)
    unresolved = in_unresolved + out_unresolved
    counted_gaps: dict[str, int] = {GAP_UNRESOLVED_EDGE_ENDPOINT: unresolved} if unresolved else {}

    # CA-host node-level findings (ESC11/ESC16 on an EnterpriseCA node; the DCOM
    # summary on a CA host Computer node). ``[]`` for every other node (not a gap),
    # and the dossier serializer drops the key entirely when empty — so a non-CA
    # dossier is byte-UNCHANGED.
    ca_findings = _ca_findings_out(reader.ca_node_findings(node_id))

    principal = reader.principal_detail(node_id)
    if principal is not None:
        uac = cast("int | None", principal.get("uac_flags"))
        ptype = str(principal["principal_type"])
        enabled = cast("bool | None", principal.get("enabled"))
        spns = cast("list[str]", principal.get("spns") or [])
        sam = cast("str | None", principal.get("samaccountname"))
        nf = compute_node_flags(ptype, uac, enabled, spns, sam)
        group_ids = reader.effective_groups_of(node_id)
        group_refs = [
            NodeRef(
                node_id=n.node_id,
                kind=n.kind,
                label=n.label,
                tier=0 if n.node_id in classified else None,
                is_tier0=n.node_id in classified,
            )
            for n in reader.nodes_by_ids(group_ids)
        ]
        group_members = (
            _build_group_members(reader, node_id, inbound, tier0, reader.all_edges())
            if ptype == "Group"
            else []
        )
        self_label = labels.get(node_id)
        label = self_label.label if self_label else (sam or node_id)
        object_sid = cast("str | None", principal.get("object_sid"))
        description = cast("str | None", principal.get("description"))
        sid_history = cast("list[str]", principal.get("sid_history") or [])
        admincount = cast("int | None", principal.get("admincount"))
        domain_fqdn = cast("str | None", principal.get("domain_fqdn"))
        uac_out = decode_uac(uac)
        node_flags = {
            "unconstrained_delegation": nf.unconstrained_delegation,
            "kerberoastable": nf.kerberoastable,
            "asrep_roastable": nf.asrep_roastable,
        }
        risk = _risk_for(reader, node_id, principal)
        fl = reader.domain_identity()[2] if ptype == "Domain" else None
        exec_summary = compose_exec_summary(
            SummaryContext(
                kind=ptype,
                label=label,
                object_sid=object_sid,
                description=description,
                spns=tuple(spns),
                sid_history=tuple(sid_history),
                admincount=admincount,
                node_flags=node_flags,
                uac=uac_out,
                inbound_edges=in_models,
                outbound_edges=out_models,
                group_memberships=group_refs,
                group_members=group_members,
                risk=risk,
                tier0_classified_ids=classified,
                domain_fqdn=domain_fqdn,
                functional_level=fl,
            )
        )
        return NodeDossier(
            node_id=node_id,
            kind=ptype,
            label=label,
            object_sid=object_sid,
            object_guid=cast("str | None", principal.get("object_guid")),
            samaccountname=sam,
            upn=cast("str | None", principal.get("upn")),
            distinguished_name=cast("str | None", principal.get("distinguished_name")),
            display_name=cast("str | None", principal.get("display_name")),
            description=cast("str | None", principal.get("description")),
            domain_id=cast("str | None", principal.get("domain_id")),
            domain_fqdn=domain_fqdn,
            admincount=admincount,
            primary_group_id=cast("int | None", principal.get("primary_group_id")),
            spns=spns,
            sid_history=sid_history,
            pwd_last_set=cast("datetime | None", principal.get("pwd_last_set")),
            last_logon_timestamp=cast("datetime | None", principal.get("last_logon_timestamp")),
            when_created=cast("datetime | None", principal.get("when_created")),
            when_changed=cast("datetime | None", principal.get("when_changed")),
            uac=uac_out,
            node_flags=node_flags,
            inbound_edges=in_models,
            outbound_edges=out_models,
            inbound_edge_counts=in_counts,
            outbound_edge_counts=out_counts,
            group_memberships=group_refs,
            group_members=group_members,
            exec_summary=exec_summary,
            ca_node_findings=ca_findings,
            secret_refs=_secret_refs(cast("list[object]", principal.get("secret_refs") or [])),
            behavior_summary_ref=cast("str | None", principal.get("behavior_summary_ref")),
            risk=risk,
            provenance=_prov_out(cast("ProvenanceRow", principal["provenance"])),
            counted_gaps=counted_gaps,
        )

    generic = reader.node_generic_detail(node_id)
    if generic is None:
        return None
    generic_kind = str(generic["kind"])
    generic_label = str(generic["label"])
    generic_fqdn = cast("str | None", generic.get("domain_fqdn"))
    # A ``Base`` object (Fix A) carries its most-derived objectClass under
    # ``object_class``; surface it as the dossier ``description`` so the panel can
    # honestly state what the object actually is (e.g. "rIDSet") — it is shown
    # because a principal holds control over it, not as an attack-modeled entity.
    generic_description = (
        cast("str | None", generic.get("object_class")) if generic_kind == "Base" else None
    )
    generic_fl = reader.domain_identity()[2] if generic_kind == "Domain" else None
    generic_summary = compose_exec_summary(
        SummaryContext(
            kind=generic_kind,
            label=generic_label,
            inbound_edges=in_models,
            outbound_edges=out_models,
            tier0_classified_ids=classified,
            domain_fqdn=generic_fqdn,
            functional_level=generic_fl,
        )
    )
    return NodeDossier(
        node_id=node_id,
        kind=generic_kind,
        label=generic_label,
        description=generic_description,
        object_guid=cast("str | None", generic.get("object_guid")),
        domain_id=cast("str | None", generic.get("domain_id")),
        domain_fqdn=generic_fqdn,
        inbound_edges=in_models,
        outbound_edges=out_models,
        inbound_edge_counts=in_counts,
        outbound_edge_counts=out_counts,
        exec_summary=generic_summary,
        ca_node_findings=ca_findings,
        provenance=_prov_out(cast("ProvenanceRow", generic["provenance"])),
        counted_gaps=counted_gaps,
    )
