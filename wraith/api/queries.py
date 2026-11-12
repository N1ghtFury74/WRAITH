"""Frozen prebuilt attack-query catalog + single-source-of-truth resolvers (M7+).

Implements design doc 15 §3 (the gated attack-path catalog) and the additive doc
20 hunter-analysis expansion: a *frozen* catalog of :class:`QuerySpec` entries
(pure data, like ``tiering.py``'s RID sets) plus the dispatch that maps each entry
onto the gated engine — ``find_paths_to`` (path queries) or ``build_slice`` (set
queries). ZERO schema change, NO new engine primitive. Three guarantees drive the
whole module:

* **Every query is TRUE (doc 20 §4, domain-expert gated).** A source set maps to
  the EXACT edge kinds / UAC bit / RID that *actually* grant the claimed
  capability, never "any write". The capability -> kind maps are frozen constants
  below, each commented with WHY those kinds and why looser kinds are excluded.
* **One source of truth.** Every source/target node-set is resolved by the EXACT
  predicates the risk model uses (:mod:`wraith.edges.node_flags`, the DCSync-edge
  derivation, :func:`wraith.api.risk._control_counts`, :meth:`StoreReader.tier0_sets`,
  the §7 privileged-group RID map, and ``effective_members_of`` for nested
  membership) — so the catalog and the Risk dashboard can never disagree.
* **Counted, never silent.** Every degraded/absent branch — an empty source set, a
  privileged group / DnsAdmins group absent, no trust edges, no domain controller,
  an unsupported query — is a named counted gap or a typed error, never a silent
  empty answer (project non-negotiable).

Out-of-scope entries (§5.8/§5.9 + doc 20 defers) are listed with ``supported=False``
+ an honest ``reason`` / ``data_confidence`` so the UI greys them rather than hiding
them.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from wraith.analysis.adcs_esc import (
    KIND_ENROLL_ON_BEHALF_OF,
    KIND_ESC1,
    KIND_ESC3,
    KIND_ESC4,
    KIND_ESC9,
    KIND_ESC10A,
    KIND_ESC10B,
    KIND_ESC13,
    KIND_ESC15,
    KIND_GOLDEN_CERT,
)
from wraith.api.graph import DEFAULT_LIMIT, build_slice
from wraith.api.models import GraphSlice, PathResult, PrebuiltQuery, PrebuiltQueryResult
from wraith.api.paths import PathGraph, build_case_path_graph, find_paths_to
from wraith.api.risk import _control_counts
from wraith.api.store import EdgeRow, StoreReader
from wraith.api.tiering import PRIVILEGED_GROUP_SID_SUFFIXES
from wraith.edges import KIND_AUTO_ENROLL, KIND_ENROLL, KIND_PUBLISHED_TO
from wraith.edges.adcs_topology import (
    KIND_ENTERPRISE_CA_FOR,
    KIND_EXTENDED_BY_POLICY,
    KIND_HOSTS_CA_SERVICE,
    KIND_ISSUED_SIGNED_BY,
    KIND_NTAUTH_STORE_FOR,
    KIND_OID_GROUP_LINK,
    KIND_ROOT_CA_FOR,
    KIND_TRUSTED_FOR_NTAUTH,
)
from wraith.edges.node_flags import (
    is_asrep_roastable_account,
    is_domain_controller,
    is_kerberoastable,
    is_password_never_expires,
    is_password_not_required,
    is_reversible_password,
    is_unconstrained_delegation,
)
from wraith.gpo.edges import DERIVATION_PREFIX as GPO_DERIVATION_PREFIX

#: The honest confidence badge type (mirrors the ``PrebuiltQuery`` /
#: ``PrebuiltQueryResult`` model field).
_DataConfidence = Literal["real", "synthetic-only", "none"]

# --- hunter categories (doc 20 §5) -------------------------------------------
#: The eight fixed grouping labels the Analysis panel groups queries by. Kept as
#: plain strings (not an enum) so adding a category later is additive for the UI.
CATEGORY_PRIVILEGED = "Privileged Access"
CATEGORY_ACL = "Dangerous ACLs"
CATEGORY_SHADOW = "Shadow Admins"
CATEGORY_CRED = "Credential Exposure"
CATEGORY_DELEGATION = "Delegation"
CATEGORY_STALE = "Stale/Risk"
CATEGORY_TOPOLOGY = "Topology"
CATEGORY_ADCS = "ADCS"

# --- catalog ids (stable public identifiers) ---------------------------------
# doc 15 (v1)
PATHS_TO_TIER0 = "paths-to-tier0"
PATHS_FROM_KERBEROASTABLE = "paths-from-kerberoastable"
PATHS_FROM_ASREP = "paths-from-asrep"
PATHS_FROM_DOMAIN_USERS = "paths-from-domain-users"
PATHS_TO_UNCONSTRAINED = "paths-to-unconstrained"
SET_TIER0 = "set-tier0"
SET_DCSYNC = "set-dcsync"
SET_KERBEROASTABLE = "set-kerberoastable"
SET_ASREP = "set-asrep"
SET_UNCONSTRAINED = "set-unconstrained"
# doc 20 §5.1 — Privileged Access (nested via the M4 closure)
SET_DOMAIN_ADMINS = "set-domain-admins"
SET_ENTERPRISE_ADMINS = "set-enterprise-admins"
SET_SCHEMA_ADMINS = "set-schema-admins"
SET_BUILTIN_ADMINISTRATORS = "set-builtin-administrators"
SET_DOMAIN_CONTROLLERS = "set-domain-controllers"
SET_ACCOUNT_OPERATORS = "set-account-operators"
SET_SERVER_OPERATORS = "set-server-operators"
SET_BACKUP_OPERATORS = "set-backup-operators"
SET_PRINT_OPERATORS = "set-print-operators"
SET_REPLICATORS = "set-replicators"
SET_GPO_CREATOR_OWNERS = "set-gpo-creator-owners"
SET_CERT_PUBLISHERS = "set-cert-publishers"
SET_KEY_ADMINS = "set-key-admins"
SET_ENTERPRISE_KEY_ADMINS = "set-enterprise-key-admins"
SET_PROTECTED_USERS = "set-protected-users"
SET_ALL_PRIVILEGED = "set-all-privileged"
SET_DNSADMINS = "set-dnsadmins"
# doc 20 §5.2 — Dangerous ACLs
ACL_CONTROLLERS_OF_DOMAIN = "acl-controllers-of-domain"
ACL_CONTROLLERS_OF_TIER0 = "acl-controllers-of-tier0"
ACL_RESET_PASSWORD = "acl-reset-password-holders"  # noqa: S105 - query id, not a secret
ACL_WRITESPN = "acl-writespn-holders"
ACL_SHADOWCRED = "acl-shadowcred-holders"
ACL_ADDMEMBER_PRIVGROUP = "acl-addmember-privgroup"
# doc 20 §5.3 — Shadow / Hidden Admins
SHADOW_ADMINS_TIER0 = "shadow-admins-tier0"
CONTROLS_MANY = "controls-many-principals"
# doc 20 §5.4 — Credential Exposure
SET_PASSWORD_NOT_REQUIRED = "set-password-not-required"  # noqa: S105 - query id, not a secret
SET_PASSWORD_NEVER_EXPIRES = "set-password-never-expires"  # noqa: S105 - query id, not a secret
SET_REVERSIBLE_PASSWORD = "set-reversible-password"  # noqa: S105 - query id, not a secret
SET_SID_HISTORY = "set-sid-history"
SET_ADMINCOUNT = "set-admincount"
# doc 20 §5.5 — Delegation
SET_CONSTRAINED_DELEGATION = "set-constrained-delegation"
SET_RBCD_CONFIGURED = "set-rbcd-configured"
SET_RBCD_WRITABLE = "set-rbcd-writable"
# doc 20 §5.6 — Stale / Risk
SET_DISABLED_BUT_PRIVILEGED = "set-disabled-but-privileged"
SET_ADMINCOUNT_ORPHANS = "set-admincount-orphans"
SET_PRIVILEGED_OLD_PASSWORD = "set-privileged-old-password"  # noqa: S105 - query id, not a secret
SET_UNSUPPORTED_OS = "set-unsupported-os"
# doc 20 §5.7 — Topology
SET_TRUSTS = "set-trusts"
SET_ADMIN_ON_DC = "set-admin-on-dc"
SET_FOREIGN_SECURITY_PRINCIPALS = "set-foreign-security-principals"
# doc 20 §5.8 — ADCS (honest, synthetic-only)
SET_ENROLLMENT_RIGHTS = "set-enrollment-rights"
SET_ADCS_TOPOLOGY = "set-adcs-topology"
PATHS_TO_ADCS_ESC = "paths-to-adcs-esc"
# Out-of-scope (§5.9) — listed, greyed, never hidden.
PATHS_FROM_OWNED = "paths-from-owned"
TRUST_ABUSE_PATHS = "trust-abuse-paths"
AZURE_PATHS = "azure-paths"

#: The ``-513`` Domain Users well-known RID suffix (resolved via a SID-suffix
#: lookup, identical in spirit to the Tier-0 suffix resolution).
DOMAIN_USERS_SID_SUFFIX = "-513"

#: Cert Publishers (-517). It is in :data:`PRIVILEGED_GROUP_SID_SUFFIXES` (so it is
#: listed by its own hygiene query and folded into the "All Privileged" union), but it
#: is DELIBERATELY excluded from the shadow-admin EXCLUSION set (DE hunt-audit defect
#: #6): Cert Publishers is NOT a Tier-0-equivalent admin group, so a Cert-Publishers
#: member that holds a hidden ACL backdoor over Tier-0 must still surface as a shadow
#: admin rather than being masked out by its (non-Tier-0) group membership.
CERT_PUBLISHERS_SID_SUFFIX = "-517"

#: ``controls-many`` fan-out threshold (doc 20 §5.3): a principal is "controls-many"
#: when it holds a control edge over at least this many distinct objects (reusing
#: the SAME de-duplicated outbound fan-out the risk model's OUTBOUND_CONTROL uses).
CONTROLS_MANY_THRESHOLD = 10

# =============================================================================
# The capability -> edge-kind truth contract (doc 20 §4, domain-expert gated).
# Each set is EXACTLY the kinds that grant the capability — nothing looser.
# =============================================================================

#: Reset another account's password. ``ForceChangePassword`` is the control-access
#: (extended) right; ``AllExtendedRights`` subsumes every extended right;
#: ``GenericAll`` subsumes everything. ``GenericWrite`` is EXCLUDED — a password
#: reset is a control-access/extended right, NOT a property write, so a bare
#: property write cannot force a reset.
RESET_PASSWORD_KINDS: frozenset[str] = frozenset(
    {"ForceChangePassword", "AllExtendedRights", "GenericAll"}
)

#: Write ``servicePrincipalName`` for a targeted Kerberoast. SPN is an ordinary
#: writable property, so ``WriteSPN`` (scoped), ``GenericWrite`` (all properties)
#: and ``GenericAll`` grant it. ``WritePublicInformation`` is INCLUDED (DE hunt-audit
#: defect #4): the Public-Information property set (rightsGUID
#: e48d0154-bcf8-11d1-8702-00c04fb96050; see
#: :data:`wraith.edges.guid_map.GUID_PUBLIC_INFORMATION`) CONTAINS
#: ``servicePrincipalName``, so a WRITE_PROP grant on that set can set an SPN — the
#: edge kind is :data:`wraith.edges.guid_map.KIND_WRITE_PUBLIC_INFORMATION`.
#: ``AllExtendedRights`` is EXCLUDED — it grants extended/control-access rights, not a
#: plain property write, so it cannot set an SPN.
WRITE_SPN_KINDS: frozenset[str] = frozenset(
    {"WriteSPN", "WritePublicInformation", "GenericWrite", "GenericAll"}
)

#: Add a key credential (shadow credentials) by writing ``msDS-KeyCredentialLink`` —
#: an ordinary writable property, so ``AddKeyCredentialLink`` (scoped),
#: ``GenericWrite`` and ``GenericAll`` grant it. (Doc 20 §4; this capability is not
#: in the task's 5-item truth-contract list — mapping taken from doc 20 §4.)
SHADOW_CRED_KINDS: frozenset[str] = frozenset(
    {"AddKeyCredentialLink", "GenericWrite", "GenericAll"}
)

#: Full takeover / shadow-admin / controllers-of-domain / controllers-of-tier0.
#: Each of these four grants complete control of the target object: ``GenericAll``
#: (everything), ``WriteDacl`` (rewrite the DACL to grant yourself everything,
#: incl. self-granting DCSync on the Domain object), ``WriteOwner`` (take ownership
#: then rewrite the DACL), ``Owns`` (already owner -> can rewrite the DACL).
#: ``GenericWrite`` is EXCLUDED — a bare property write is not full control of an
#: arbitrary object (it cannot reset a user's password nor self-grant DCSync on the
#: Domain object). NOTE: for a *group* target ``GenericWrite`` would grant member
#: control; that nuance is handled by :data:`ADD_MEMBER_KINDS` (with the target-is-a-
#: privileged-group filter), not folded into the whole-object takeover set.
FULL_CONTROL_KINDS: frozenset[str] = frozenset({"GenericAll", "WriteDacl", "WriteOwner", "Owns"})

#: Add a member to a privileged group. ``member`` is a writable property, so
#: ``AddMember`` (scoped), ``GenericWrite`` (all properties) and ``GenericAll``
#: grant it, and ``WriteDacl`` grants it indirectly (rewrite the group DACL to grant
#: yourself ``AddMember`` — a 2-step). ``AddSelf`` is INCLUDED: a principal with
#: AddSelf on a privileged group adds ITSELF to it, which — because this is scoped
#: to a privileged TARGET group (the ``target_in`` filter) — is a DIRECT Tier-0
#: self-elevation (the whole point of this query). Excluding the direct self-add
#: while keeping the indirect WriteDacl 2-step would be internally inconsistent.
ADD_MEMBER_KINDS: frozenset[str] = frozenset(
    {"AddMember", "AddSelf", "GenericWrite", "GenericAll", "WriteDacl"}
)

#: Domain trust relationships (emitted in the ATTACK direction by M5): same-forest,
#: cross-forest, and the trust-key possession edge.
TRUST_KINDS: frozenset[str] = frozenset({"SameForestTrust", "CrossForestTrust", "HasTrustKeys"})

# --- AD CS edge-kind truth contract (doc 16 §D; synthetic-only) --------------
# Kinds are IMPORTED from the engine modules (one source of truth, never
# re-literalled): topology kinds from :mod:`wraith.edges.adcs_topology` +
# :mod:`wraith.edges` (PublishedTo/Enroll/AutoEnroll), ESC-composite kinds from
# :mod:`wraith.analysis.adcs_esc`. These three sets are 🧪 synthetic-only (c137 has
# no usable AD CS) — the queries that use them carry ``data_confidence="synthetic-only"``.

#: The confirmed base PKI topology edges (ntds Configuration NC): which template
#: publishes to which CA, which CA serves the domain / is NTAuth-trusted / chains to
#: which root, and the OID-policy links — the structural "shape" of the PKI. This is
#: the ``SET_ADCS_TOPOLOGY`` edge set.
ADCS_TOPOLOGY_KINDS: frozenset[str] = frozenset(
    {
        KIND_PUBLISHED_TO,
        KIND_ENTERPRISE_CA_FOR,
        KIND_ROOT_CA_FOR,
        KIND_NTAUTH_STORE_FOR,
        KIND_HOSTS_CA_SERVICE,
        KIND_TRUSTED_FOR_NTAUTH,
        KIND_ISSUED_SIGNED_BY,
        KIND_EXTENDED_BY_POLICY,
        KIND_OID_GROUP_LINK,
    }
)

#: Confirmed certificate-ENROLLMENT rights (principal -> CertTemplate/CA). EXACTLY
#: ``Enroll`` + ``AutoEnroll`` — the two rights that let a principal request a
#: certificate (research 11, enrollability core). Template-TAKEOVER kinds
#: (GenericAll/WriteDacl/WritePKI*Flag) are EXCLUDED: they are ESC4, not an
#: enrollment right. This is the ``SET_ENROLLMENT_RIGHTS`` edge set.
ADCS_ENROLLMENT_KINDS: frozenset[str] = frozenset({KIND_ENROLL, KIND_AUTO_ENROLL})

#: The inferred ESC-composite edge kinds the M8 ESC pass emits. A "path to AD CS ESC
#: abuse" is any attacker path that TERMINATES at the target node of one of these
#: edges (``PATHS_TO_ADCS_ESC``). ``WraithESC4TemplateControl`` (KIND_ESC4) is the
#: WRAITH-native template-control fact (see its definition in ``adcs_esc``).
ADCS_ESC_KINDS: frozenset[str] = frozenset(
    {
        KIND_ESC1,
        KIND_ESC3,
        KIND_ESC4,
        KIND_ESC9,
        KIND_ESC10A,
        KIND_ESC10B,
        KIND_ESC13,
        KIND_ESC15,
        KIND_ENROLL_ON_BEHALF_OF,
        KIND_GOLDEN_CERT,
    }
)


class UnknownQueryError(KeyError):
    """Raised when a query id is not in the frozen catalog (-> typed 404)."""


class UnsupportedQueryError(ValueError):
    """Raised when a catalog query is out of scope for v1 (-> typed 422)."""

    def __init__(self, query_id: str, reason: str) -> None:
        self.query_id = query_id
        self.reason = reason
        super().__init__(f"query '{query_id}' is not supported: {reason}")


@dataclass(frozen=True)
class QuerySpec:
    """The static (data-only) spec for one catalog entry.

    Mirrors :class:`PrebuiltQuery` minus the live ``source_count`` (which is filled
    per-request from :func:`resolve_source_sets`). This is the frozen contract.
    """

    id: str
    label: str
    description: str
    category: str  # one of the eight CATEGORY_* labels (doc 20 §5)
    kind: str  # "path" | "set"
    direction: str  # "to-target" | "source-to-target" | "set"
    supported: bool
    reason: str | None
    data_confidence: str  # "real" | "synthetic-only" | "none"


@dataclass(frozen=True)
class _PrivGroupQuery:
    """A privileged-group ``set`` query: id + display label + the RID suffix (§7)."""

    id: str
    label: str
    suffix: str


#: The §7 privileged-group RID map, one ``set`` query each. Every suffix is a member
#: of :data:`PRIVILEGED_GROUP_SID_SUFFIXES`; membership is the M4 transitive closure
#: (nested + primary-group) via ``effective_members_of(tier0_node_ids((suffix,)))``.
PRIVILEGED_GROUP_QUERIES: tuple[_PrivGroupQuery, ...] = (
    _PrivGroupQuery(SET_DOMAIN_ADMINS, "Domain Admins", "-512"),
    _PrivGroupQuery(SET_ENTERPRISE_ADMINS, "Enterprise Admins", "-519"),
    _PrivGroupQuery(SET_SCHEMA_ADMINS, "Schema Admins", "-518"),
    _PrivGroupQuery(SET_BUILTIN_ADMINISTRATORS, "Builtin Administrators", "-544"),
    _PrivGroupQuery(SET_DOMAIN_CONTROLLERS, "Domain Controllers", "-516"),
    _PrivGroupQuery(SET_ACCOUNT_OPERATORS, "Account Operators", "-548"),
    _PrivGroupQuery(SET_SERVER_OPERATORS, "Server Operators", "-549"),
    _PrivGroupQuery(SET_BACKUP_OPERATORS, "Backup Operators", "-551"),
    _PrivGroupQuery(SET_PRINT_OPERATORS, "Print Operators", "-550"),
    _PrivGroupQuery(SET_REPLICATORS, "Replicators", "-552"),
    _PrivGroupQuery(SET_GPO_CREATOR_OWNERS, "Group Policy Creator Owners", "-520"),
    _PrivGroupQuery(SET_CERT_PUBLISHERS, "Cert Publishers", "-517"),
    _PrivGroupQuery(SET_KEY_ADMINS, "Key Admins", "-526"),
    _PrivGroupQuery(SET_ENTERPRISE_KEY_ADMINS, "Enterprise Key Admins", "-527"),
    _PrivGroupQuery(SET_PROTECTED_USERS, "Protected Users", "-525"),
)
_PRIV_SUFFIX_BY_ID: dict[str, str] = {q.id: q.suffix for q in PRIVILEGED_GROUP_QUERIES}


def _priv_group_spec(q: _PrivGroupQuery) -> QuerySpec:
    """Build the frozen :class:`QuerySpec` for one privileged-group ``set`` query."""
    return QuerySpec(
        id=q.id,
        label=f"{q.label} (effective, nested)",
        description=(
            f"Every effective (transitive — nested group + primary-group) member of "
            f"the {q.label} group (well-known RID suffix {q.suffix}), with its one-hop "
            f"MemberOf neighbourhood. The count beside the label is the number of "
            f"effective members, NOT a path count."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    )


#: The catalog — build EXACTLY this (doc 15 §3 + doc 20 §5). Order is display order;
#: ids are stable. Supported entries are backed by real c137 data unless marked
#: ``synthetic-only``.
CATALOG: tuple[QuerySpec, ...] = (
    # --- doc 15 (v1) path queries ---
    QuerySpec(
        id=PATHS_TO_TIER0,
        label="Shortest Paths to Tier Zero",
        description=(
            "One shortest attacker path from every principal that can reach a "
            "Tier-0 target (Domain/Enterprise Admins, builtin Administrators, "
            "Domain Controllers, or the Domain root object), ranked shortest-first. "
            "NOTE: the count shown beside this query is the number of Tier-0 "
            "principals in the domain, NOT the number of paths found."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="path",
        direction="to-target",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=PATHS_FROM_KERBEROASTABLE,
        label="Shortest Paths from Kerberoastable Users to Tier Zero",
        description=(
            "Shortest attacker path to Tier Zero from each enabled user that "
            "advertises an SPN (its service ticket is offline-crackable)."
        ),
        category=CATEGORY_CRED,
        kind="path",
        direction="source-to-target",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=PATHS_FROM_ASREP,
        label="Shortest Paths from AS-REP Roastable Users to Tier Zero",
        description=(
            "Shortest attacker path to Tier Zero from each account that does not "
            "require Kerberos pre-authentication (its AS-REP is offline-crackable)."
        ),
        category=CATEGORY_CRED,
        kind="path",
        direction="source-to-target",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=PATHS_FROM_DOMAIN_USERS,
        label="Shortest Paths from Domain Users to Tier Zero",
        description=(
            "Shortest attacker path to Tier Zero from each effective member of the "
            "Domain Users (-513) group — the 'any authenticated user' blast radius."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="path",
        direction="source-to-target",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=PATHS_TO_UNCONSTRAINED,
        label="Shortest Paths to Unconstrained Delegation Systems",
        description=(
            "One shortest attacker path from every principal that can reach a host "
            "trusted for unconstrained Kerberos delegation. Domain Controllers carry "
            "TRUSTED_FOR_DELEGATION by design and are already Tier-0, so DCs appear in "
            "this target set as expected (BloodHound-parity, single source of truth "
            "with the Risk model); the interesting targets are the NON-DC hosts."
        ),
        category=CATEGORY_DELEGATION,
        kind="path",
        direction="to-target",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 15 (v1) set queries ---
    QuerySpec(
        id=SET_TIER0,
        label="Tier Zero Principals",
        description=(
            "The Tier-0 principals (classification + current effective members) and "
            "their one-hop MemberOf neighborhood."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_DCSYNC,
        label="Principals with DCSync Rights to the Domain",
        description=(
            "Every principal holding a DCSync edge to the Domain object (can "
            "replicate all domain secrets / forge a Golden Ticket)."
        ),
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_KERBEROASTABLE,
        label="Kerberoastable Users",
        description="Enabled users advertising an SPN (service ticket offline-crackable).",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_ASREP,
        label="AS-REP Roastable Users",
        description="Accounts not requiring Kerberos pre-authentication (AS-REP crackable).",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_UNCONSTRAINED,
        label="Systems with Unconstrained Delegation",
        description=(
            "Accounts trusted for unconstrained Kerberos delegation. Domain "
            "Controllers carry TRUSTED_FOR_DELEGATION by design and are already "
            "Tier-0, so they appear here as expected; the novel findings are the "
            "NON-DC hosts."
        ),
        category=CATEGORY_DELEGATION,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.1 Privileged Access (generated from the §7 RID map) ---
    *tuple(_priv_group_spec(q) for q in PRIVILEGED_GROUP_QUERIES),
    QuerySpec(
        id=SET_ALL_PRIVILEGED,
        label="All Privileged Principals (union, nested)",
        description=(
            "The union of the effective (nested) membership of every sensitive "
            "well-known group (§7: Domain/Enterprise/Schema Admins, builtin "
            "Administrators, Domain Controllers, the operator groups, Cert "
            "Publishers, Key/Enterprise-Key Admins, GPO Creator Owners). The "
            "reference set subtracted by the hidden-admin hunt. Protected Users (-525) "
            "is intentionally NOT included (it is a defensive group, not a privilege)."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_DNSADMINS,
        label="DnsAdmins (effective, nested)",
        description=(
            "Effective members of the DnsAdmins group — historically a DLL-load to "
            "SYSTEM-on-DC escalation. DnsAdmins has no fixed RID (it is created on "
            "DNS-role install), so it is matched by sAMAccountName ('DnsAdmins'); if "
            "no such group exists the result is empty with a counted gap "
            "(dnsadmins_group_absent)."
        ),
        category=CATEGORY_PRIVILEGED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.2 Dangerous ACLs ---
    QuerySpec(
        id=ACL_CONTROLLERS_OF_DOMAIN,
        label="Controllers of the Domain Object (self-grant DCSync)",
        description=(
            "Principals holding full control (GenericAll/WriteDacl/WriteOwner/Owns) "
            "over the Domain root object — rewriting its DACL self-grants DCSync "
            "(full domain compromise)."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=ACL_CONTROLLERS_OF_TIER0,
        label="Controllers of any Tier-0 Object",
        description=(
            "Principals holding full control (GenericAll/WriteDacl/WriteOwner/Owns) "
            "over any Tier-0 classified object, PLUS a bare GenericWrite over a Tier-0 "
            "account/group (member-write / shadow-cred / SPN takeover). GenericWrite "
            "over the Domain object/containers is NOT counted (it is not DCSync / "
            "container control)."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=ACL_RESET_PASSWORD,
        label="Can Reset Other Accounts' Passwords",
        description=(
            "Principals that can reset an ACCOUNT's password (User/Computer target "
            "only — ForceChangePassword / AllExtendedRights / GenericAll, NOT a bare "
            "GenericWrite). Control over a group/OU/GPO is not a password reset."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=ACL_WRITESPN,
        label="Can Write SPN (targeted Kerberoast)",
        description=(
            "Principals that can write servicePrincipalName on an ACCOUNT "
            "(User/Computer target only — WriteSPN / GenericWrite / GenericAll, NOT "
            "AllExtendedRights) to make it targeted-kerberoastable."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=ACL_SHADOWCRED,
        label="Can Add Key Credentials (shadow credentials)",
        description=(
            "Principals that can write msDS-KeyCredentialLink on an ACCOUNT "
            "(User/Computer target only — AddKeyCredentialLink / GenericWrite / "
            "GenericAll) to authenticate as it via a forged certificate."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=ACL_ADDMEMBER_PRIVGROUP,
        label="Can Add Members to a Privileged Group",
        description=(
            "Principals that can add a member to a privileged group "
            "(AddMember / AddSelf / GenericWrite / GenericAll / WriteDacl, target "
            "restricted to a §7 privileged group) — direct self-elevation into Tier-0 "
            "(AddSelf adds the principal itself)."
        ),
        category=CATEGORY_ACL,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.3 Shadow / Hidden Admins ---
    QuerySpec(
        id=SHADOW_ADMINS_TIER0,
        label="Shadow Admins (control Tier-0, not in a privileged group)",
        description=(
            "Principals with full control (GenericAll/WriteDacl/WriteOwner/Owns) over "
            "a Tier-0 object that are NOT Tier-0 themselves and NOT an effective "
            "member of any privileged group — the hidden ACL backdoor."
        ),
        category=CATEGORY_SHADOW,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=CONTROLS_MANY,
        label=f"Controls Many Objects (>= {CONTROLS_MANY_THRESHOLD})",
        description=(
            f"Principals whose outbound control fan-out (distinct objects they hold a "
            f"control edge over, the SAME de-duplicated count the risk model uses) is "
            f"at least {CONTROLS_MANY_THRESHOLD} — outsized blast radius."
        ),
        category=CATEGORY_SHADOW,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.4 Credential Exposure ---
    QuerySpec(
        id=SET_PASSWORD_NOT_REQUIRED,
        label="Accounts with Password-Not-Required",
        description="Accounts with PASSWD_NOTREQD (0x20) set — may have an empty password.",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_PASSWORD_NEVER_EXPIRES,
        label="Accounts with Never-Expiring Passwords",
        description="Accounts with DONT_EXPIRE_PASSWORD (0x10000) set — stale, long-lived creds.",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_REVERSIBLE_PASSWORD,
        label="Accounts with Reversible-Encryption Passwords",
        description=(
            "Accounts with ENCRYPTED_TEXT_PWD_ALLOWED (0x80) set — the password is "
            "recoverable to plaintext from the directory."
        ),
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_SID_HISTORY,
        label="Principals carrying sIDHistory",
        description="Principals with a non-empty sIDHistory (possible privilege smuggling).",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_ADMINCOUNT,
        label="adminCount-protected Principals",
        description="Principals with adminCount set (is or was AdminSDHolder-protected).",
        category=CATEGORY_CRED,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.5 Delegation ---
    QuerySpec(
        id=SET_CONSTRAINED_DELEGATION,
        label="Constrained-Delegation Principals",
        description=(
            "Principals configured for constrained delegation (an AllowedToDelegate "
            "edge to a target SPN host they can impersonate users to)."
        ),
        category=CATEGORY_DELEGATION,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_RBCD_CONFIGURED,
        label="Resource-Based Constrained Delegation (configured)",
        description=(
            "Resources with RBCD configured (an AllowedToAct trust edge) and the "
            "principals allowed to act on them."
        ),
        category=CATEGORY_DELEGATION,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_RBCD_WRITABLE,
        label="Can Configure RBCD on a Target",
        description=(
            "Principals that can write msDS-AllowedToActOnBehalfOfOtherIdentity "
            "(an AddAllowedToAct edge) — can configure RBCD to take over the target."
        ),
        category=CATEGORY_DELEGATION,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    # --- doc 20 §5.6 Stale / Risk ---
    QuerySpec(
        id=SET_DISABLED_BUT_PRIVILEGED,
        label="Disabled-but-Privileged Accounts",
        description=(
            "Disabled accounts that are still an effective member of a privileged "
            "group (stale standing privilege)."
        ),
        category=CATEGORY_STALE,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_ADMINCOUNT_ORPHANS,
        label="adminCount Orphans",
        description=(
            "USER accounts with adminCount set that are NOT currently an effective "
            "member of any privileged group — AdminSDHolder residue from a past "
            "privilege. Restricted to real stale residue: ptype=User only, excluding "
            "krbtgt (-502) and the built-in Administrator (-500); the protected groups "
            "themselves (which also carry adminCount=1) are not orphans and are excluded."
        ),
        category=CATEGORY_STALE,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_PRIVILEGED_OLD_PASSWORD,
        label="Privileged Accounts with an Old Password",
        description="Privileged accounts whose pwdLastSet is older than a threshold.",
        category=CATEGORY_STALE,
        kind="set",
        direction="set",
        supported=False,
        reason="needs snapshot-time reference",
        data_confidence="none",
    ),
    QuerySpec(
        id=SET_UNSUPPORTED_OS,
        label="Computers running an Unsupported OS",
        description="Computer accounts running an end-of-life operating system.",
        category=CATEGORY_STALE,
        kind="set",
        direction="set",
        supported=False,
        reason="operatingSystem not collected",
        data_confidence="none",
    ),
    # --- doc 20 §5.7 Topology ---
    QuerySpec(
        id=SET_TRUSTS,
        label="Domain Trusts",
        description=(
            "Domain trust relationships (same-forest / cross-forest / trust-key "
            "edges) in the attack direction, around the Domain object."
        ),
        category=CATEGORY_TOPOLOGY,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_ADMIN_ON_DC,
        label="Principals with Admin on a Domain Controller",
        description=(
            "Principals with an AdminTo edge onto a Domain Controller computer "
            "(DC compromise). Confidence depends on the artifacts present: GPO-derived "
            "AdminTo is real; host-SAM AdminTo is synthetic until member-host images "
            "are collected."
        ),
        category=CATEGORY_TOPOLOGY,
        kind="set",
        direction="set",
        supported=True,
        reason=None,
        data_confidence="real",
    ),
    QuerySpec(
        id=SET_FOREIGN_SECURITY_PRINCIPALS,
        label="Foreign Security Principals",
        description="External principals (FSPs) that hold rights in this domain.",
        category=CATEGORY_TOPOLOGY,
        kind="set",
        direction="set",
        supported=False,
        reason="FSP reader not built",
        data_confidence="none",
    ),
    # --- doc 20 §5.8 ADCS (honest, synthetic-only) ---
    QuerySpec(
        id=SET_ENROLLMENT_RIGHTS,
        label="Certificate Enrollment Rights",
        description=(
            "Principals holding an explicitly-granted Enroll/AutoEnroll right on "
            "certificate templates — the directly-granted enrollment population, NOT "
            "every principal who could obtain a certificate. A GenericAll / "
            "AllExtendedRights holder has template control (ESC4), surfaced under the "
            "ESC paths, not here."
        ),
        category=CATEGORY_ADCS,
        kind="set",
        direction="set",
        supported=True,
        reason=(
            "AD CS Enroll/AutoEnroll holders — pure ntds Configuration-NC ACL facts "
            "(no CA-host artifact needed). The ESC pass is pipeline-wired "
            "(export/pipeline.py), so this runs; UNTESTED on real data (no AD CS-"
            "bearing ntds validated yet; Certipy parity pending) — badged "
            "data_confidence='synthetic-only'."
        ),
        data_confidence="synthetic-only",
    ),
    QuerySpec(
        id=SET_ADCS_TOPOLOGY,
        label="AD CS Topology (CA / NTAuth / templates)",
        description="The AD CS PKI topology: CAs, NTAuth store, and template links.",
        category=CATEGORY_ADCS,
        kind="set",
        direction="set",
        supported=True,
        reason=(
            "AD CS PKI topology edges (PublishedTo / EnterpriseCAFor / "
            "TrustedForNTAuth / ...). Pipeline-wired; synthetic-tested and UNTESTED "
            "on real data (c137 has no usable AD CS; doc 08 §4.1) — badged "
            "data_confidence='synthetic-only'."
        ),
        data_confidence="synthetic-only",
    ),
    QuerySpec(
        id=PATHS_TO_ADCS_ESC,
        label="Shortest Paths to AD CS ESC Abuse",
        description=(
            "One shortest attacker path from every principal that can reach an AD CS "
            "ESC-abuse sink — the target node of any inferred ESC-composite edge "
            "(ADCSESC1/3/9/10a/10b/13/15, WraithESC4TemplateControl, EnrollOnBehalfOf, "
            "GoldenCert). The count shown is the number of distinct ESC sinks, NOT the "
            "number of paths. Sinks are heterogeneous: the domain-escalation ESCs "
            "(1/3/9/15/GoldenCert) sink at the Domain object — reaching it equals "
            "domain compromise — while ESC4/10/13 sink at an intermediate "
            "template/victim/group that still requires the onward certificate step. "
            "ESC6/7/11/16 require the CA-host registry (not collected in v1) and are "
            "counted-undecidable, so they are absent here — NOT 'clean'; ESC9/10 "
            "verdicts hold for the imaged DC only."
        ),
        category=CATEGORY_ADCS,
        kind="path",
        direction="to-target",
        supported=True,
        reason=(
            "The ESC pass is pipeline-wired (export/pipeline.py), so these paths "
            "resolve; the AD CS ESC edge surface is synthetic-tested and UNTESTED on "
            "real data pending a CA artifact + Certipy parity gate (badged "
            "data_confidence='synthetic-only')."
        ),
        data_confidence="synthetic-only",
    ),
    # --- §5.9 out of scope for v1 — listed, greyed, never hidden ---
    QuerySpec(
        id=PATHS_FROM_OWNED,
        label="Shortest Paths from Owned Principals",
        description="Shortest paths to Tier Zero from the analyst's 'owned' set.",
        category=CATEGORY_PRIVILEGED,
        kind="path",
        direction="source-to-target",
        supported=False,
        reason=(
            "WRAITH stores no 'owned' marking in v1; a UI-side owned set can be fed "
            "to POST /paths as source_node_ids with no engine change."
        ),
        data_confidence="none",
    ),
    QuerySpec(
        id=TRUST_ABUSE_PATHS,
        label="Domain Trust Abuse Paths",
        description="Dedicated cross-domain trust-abuse escalation paths.",
        category=CATEGORY_TOPOLOGY,
        kind="path",
        direction="to-target",
        supported=False,
        reason=(
            "Dedicated cross-domain trust-abuse edges are not modelled in v1; "
            "generic pathing still traverses any trust edges that exist."
        ),
        data_confidence="none",
    ),
    QuerySpec(
        id=AZURE_PATHS,
        label="Azure / Entra ID Paths",
        description="Azure AD / Entra attack paths.",
        category=CATEGORY_TOPOLOGY,
        kind="path",
        direction="to-target",
        supported=False,
        reason="Azure/Entra is a permanent project non-goal (on-prem AD only).",
        data_confidence="none",
    ),
)

_SPEC_BY_ID: dict[str, QuerySpec] = {spec.id: spec for spec in CATALOG}


def edge_endpoints(
    reader: StoreReader,
    kinds: frozenset[str],
    role: Literal["source", "target"],
    target_in: Collection[str] | None = None,
) -> list[str]:
    """Return the principals that hold an edge of one of ``kinds`` (one source of truth).

    THE truth-preserving resolver that backs every "who can X" set query (doc 20
    §4): one deterministic pass over :meth:`StoreReader.all_edges`, returning the
    ``source_node_id`` (``role="source"``) or ``target_node_id`` (``role="target"``)
    of every edge whose ``kind`` is in ``kinds``, optionally restricted to edges
    whose TARGET is in ``target_in`` (e.g. the Domain object, the Tier-0 set, or the
    privileged-group set). No schema change; no new engine primitive.

    Inputs:
        reader: the read-only store accessor.
        kinds: the EXACT edge kinds that grant the claimed capability (a frozen §4
            constant — never a looser "any write").
        role: which endpoint to collect (``"source"`` = the capability holder).
        target_in: if given, keep only edges whose ``target_node_id`` is in this
            collection (the capability is INTO a specific object set).

    Returns:
        The matching endpoint node ids, de-duplicated and sorted (deterministic).

    Failure modes:
        Never raises on content; an empty match yields ``[]`` (the caller counts it).
    """
    return _edge_endpoints_from(reader.all_edges(), kinds, role, target_in)


def _edge_endpoints_from(
    edges: Sequence[EdgeRow],
    kinds: frozenset[str],
    role: Literal["source", "target"],
    target_in: Collection[str] | None,
) -> list[str]:
    """Pure endpoint collector over an already-fetched edge list (single-pass)."""
    want_source = role == "source"
    target_set = set(target_in) if target_in is not None else None
    out: set[str] = set()
    for e in edges:
        if e.kind not in kinds:
            continue
        if target_set is not None and e.target_node_id not in target_set:
            continue
        out.add(e.source_node_id if want_source else e.target_node_id)
    return sorted(out)


@dataclass(frozen=True)
class _PrincipalScan:
    """Per-principal predicate sets, resolved in one pass (risk-model predicates)."""

    kerberoastable: tuple[str, ...]
    asrep: tuple[str, ...]
    unconstrained: tuple[str, ...]
    password_not_required: tuple[str, ...]
    password_never_expires: tuple[str, ...]
    reversible_password: tuple[str, ...]
    sid_history: tuple[str, ...]
    admincount: tuple[str, ...]
    #: adminCount set restricted to real stale-residue USER accounts (ptype == User,
    #: excluding krbtgt -502 and the built-in Administrator -500) — the honest
    #: admincount-orphans population (the protected groups and krbtgt themselves carry
    #: adminCount=1 but are not "orphans", so they are filtered out — DE gate).
    admincount_users: tuple[str, ...]
    disabled: tuple[str, ...]
    dc_computers: tuple[str, ...]
    #: Node ids of account objects (ptype in {User, Computer}) — the only targets a
    #: reset-password / write-SPN / add-key-credential right is meaningful against
    #: (a group/OU/GPO has no password/SPN/keyCredentialLink) — DE gate.
    account_ids: tuple[str, ...]


def _scan_principals(reader: StoreReader) -> _PrincipalScan:
    """Resolve every per-principal predicate set in ONE pass (one source of truth).

    Applies the EXACT :mod:`wraith.edges.node_flags` predicates the risk model uses
    (identical field coercion to :func:`wraith.api.risk.score_nodes`): kerberoastable
    / AS-REP / unconstrained-delegation, plus the credential-exposure UAC predicates
    (password-not-required 0x20, never-expires 0x10000, reversible 0x80),
    sIDHistory-present, adminCount-set, disabled, and the DC computer set
    (SERVER_TRUST_ACCOUNT). Every set is deterministically ordered. Never raises;
    missing/None fields degrade an account out of a set.
    """
    kerb: list[str] = []
    asrep: list[str] = []
    uncon: list[str] = []
    pwd_notreq: list[str] = []
    pwd_never: list[str] = []
    reversible: list[str] = []
    sidh: list[str] = []
    admin: list[str] = []
    admin_users: list[str] = []
    disabled: list[str] = []
    dcs: list[str] = []
    accounts: list[str] = []
    for p in reader.principal_risk_inputs():
        node_id = str(p["node_id"])
        ptype = str(p["principal_type"])
        sid_val = p.get("object_sid")
        sid = str(sid_val) if sid_val is not None else ""
        uac = p.get("uac_flags")
        uac_int = int(uac) if isinstance(uac, int) else None
        enabled = p.get("enabled")
        enabled_b = bool(enabled) if enabled is not None else None
        sam_val = p.get("samaccountname")
        sam = str(sam_val) if sam_val is not None else None
        spns_val = p.get("spns")
        spns = [str(s) for s in spns_val] if isinstance(spns_val, (list, tuple)) else []
        sidh_val = p.get("sid_history")
        sid_hist = [str(s) for s in sidh_val] if isinstance(sidh_val, (list, tuple)) else []
        admincount = p.get("admincount")
        if is_kerberoastable(ptype, enabled_b, spns, sam):
            kerb.append(node_id)
        # Enabled-User-filtered, symmetric with kerberoastable (DE hunt-audit defect #3):
        # a disabled / non-User account carrying DONT_REQ_PREAUTH is not a live target.
        if is_asrep_roastable_account(ptype, enabled_b, uac_int):
            asrep.append(node_id)
        if is_unconstrained_delegation(uac_int):
            uncon.append(node_id)
        if is_password_not_required(uac_int):
            pwd_notreq.append(node_id)
        if is_password_never_expires(uac_int):
            pwd_never.append(node_id)
        if is_reversible_password(uac_int):
            reversible.append(node_id)
        if sid_hist:
            sidh.append(node_id)
        if isinstance(admincount, int) and admincount:
            admin.append(node_id)
            # Stale-residue USER orphans only: not krbtgt (-502), not the built-in
            # Administrator (-500), not a protected GROUP (which also carries
            # adminCount=1 but is the privilege, not an orphan).
            if ptype == "User" and not (sid.endswith("-502") or sid.endswith("-500")):
                admin_users.append(node_id)
        if enabled_b is False:
            disabled.append(node_id)
        if is_domain_controller(uac_int):
            dcs.append(node_id)
        if ptype in ("User", "Computer"):
            accounts.append(node_id)
    return _PrincipalScan(
        kerberoastable=tuple(sorted(kerb)),
        asrep=tuple(sorted(asrep)),
        unconstrained=tuple(sorted(uncon)),
        password_not_required=tuple(sorted(pwd_notreq)),
        password_never_expires=tuple(sorted(pwd_never)),
        reversible_password=tuple(sorted(reversible)),
        sid_history=tuple(sorted(sidh)),
        admincount=tuple(sorted(admin)),
        admincount_users=tuple(sorted(admin_users)),
        disabled=tuple(sorted(disabled)),
        dc_computers=tuple(sorted(dcs)),
        account_ids=tuple(sorted(accounts)),
    )


@dataclass(frozen=True)
class SourceSets:
    """The resolved node-id sets that drive every catalog query (one source of truth).

    Resolved by the EXACT predicates the risk model uses so catalog counts and the
    Risk dashboard never disagree. All tuples are deterministically ordered.
    """

    # --- doc 15 (v1) ---
    kerberoastable: tuple[str, ...]
    asrep: tuple[str, ...]
    unconstrained: tuple[str, ...]
    dcsync_holders: tuple[str, ...]
    tier0_classified: tuple[str, ...]
    tier0_members: tuple[str, ...]
    #: The Tier-0 *traversal* targets (groups + the Domain object) — the sink of the
    #: ``paths-to-tier0`` query; empty on a degenerate store (-> counted gap).
    tier0_targets: tuple[str, ...]
    domain_object_ids: tuple[str, ...]
    domain_users: tuple[str, ...]
    #: Whether a ``-513`` Domain Users group object exists at all (absent -> gap).
    domain_users_group_present: bool
    # --- doc 20 §5.1 Privileged Access (nested via the M4 closure) ---
    #: suffix -> the group node ids that carry that privileged RID.
    privileged_group_ids_by_suffix: dict[str, tuple[str, ...]]
    #: suffix -> the effective (nested) members of those groups.
    privileged_members_by_suffix: dict[str, tuple[str, ...]]
    all_privileged_group_ids: tuple[str, ...]
    all_privileged_members: tuple[str, ...]
    dnsadmins_group_ids: tuple[str, ...]
    dnsadmins_members: tuple[str, ...]
    # --- doc 20 §5.2 Dangerous ACLs (edge_endpoints) ---
    reset_password_holders: tuple[str, ...]
    write_spn_holders: tuple[str, ...]
    shadow_cred_holders: tuple[str, ...]
    add_member_privgroup_holders: tuple[str, ...]
    controllers_of_domain: tuple[str, ...]
    controllers_of_tier0: tuple[str, ...]
    # --- doc 20 §5.3 Shadow / Hidden Admins ---
    shadow_admins_tier0: tuple[str, ...]
    controls_many: tuple[str, ...]
    # --- doc 20 §5.4 Credential Exposure field predicates ---
    password_not_required: tuple[str, ...]
    password_never_expires: tuple[str, ...]
    reversible_password: tuple[str, ...]
    sid_history_present: tuple[str, ...]
    admincount_set: tuple[str, ...]
    # --- doc 20 §5.5 Delegation ---
    constrained_delegation: tuple[str, ...]
    rbcd_configured: tuple[str, ...]
    rbcd_writable: tuple[str, ...]
    # --- doc 20 §5.6 Stale / Risk ---
    disabled_but_privileged: tuple[str, ...]
    admincount_orphans: tuple[str, ...]
    # --- doc 20 §5.7 Topology ---
    trust_endpoint_ids: tuple[str, ...]
    trust_edge_count: int
    dc_computer_ids: tuple[str, ...]
    admin_on_dc_holders: tuple[str, ...]
    #: Whether >=1 contributing AdminTo-to-DC edge is GPO-derived (real SYSVOL
    #: provenance, ``derivation`` prefix ``GPO:``). Drives the honest
    #: ``set-admin-on-dc`` badge (DE hunt-audit defect #2): ``real`` only when this is
    #: true, else ``synthetic-only`` (the host-SAM-only AdminTo surface is synthetic
    #: until member-host images are collected).
    admin_on_dc_gpo_derived: bool
    #: Whether any contributing AdminTo-to-DC edge carries NO ``derivation`` at all
    #: (the field could not decide its origin) — a counted gap, never a guessed badge.
    admin_on_dc_derivation_missing: bool
    # --- doc 20 §5.8 AD CS (synthetic-only; doc 16 §D) ---
    #: Both endpoints of the base PKI topology edges — the ``SET_ADCS_TOPOLOGY`` seed.
    adcs_topology_endpoint_ids: tuple[str, ...]
    #: Count of base PKI topology edges (the ``SET_ADCS_TOPOLOGY`` headline count).
    adcs_topology_edge_count: int
    #: Principals holding Enroll/AutoEnroll (``SET_ENROLLMENT_RIGHTS`` holders).
    enrollment_rights_holders: tuple[str, ...]
    #: Both endpoints of the Enroll/AutoEnroll edges (the slice seed so the
    #: justifying enrollment edge renders beside each holder).
    enrollment_endpoint_ids: tuple[str, ...]
    #: Distinct TARGET nodes of the inferred ESC-composite edges — the
    #: ``PATHS_TO_ADCS_ESC`` sink set; empty when the ESC pass emitted nothing.
    esc_target_ids: tuple[str, ...]
    #: Count of inferred ESC-composite edges (context for the ESC path query).
    esc_edge_count: int


def resolve_source_sets(reader: StoreReader) -> SourceSets:
    """Resolve every catalog source/target node-set from the store (one source of truth).

    Inputs:
        reader: the read-only store accessor.

    Returns:
        A :class:`SourceSets` with every set deterministically ordered. Edge-derived
        sets (DCSync holders, the §4 capability holders, RBCD, trusts, admin-on-DC)
        come from a SINGLE :meth:`StoreReader.all_edges` pass; principal-predicate
        sets from a single :func:`_scan_principals` pass; privileged-group membership
        from ``effective_members_of(tier0_node_ids((suffix,)))`` (nested + primary-
        group, by construction). Domain Users is the effective-member closure of the
        ``-513`` group; ``domain_users_group_present`` is ``False`` when no such
        group object exists (the caller counts that as a gap).

    Failure modes:
        Never raises on content; an absent group/edge set yields an empty set the
        caller surfaces as a named counted gap.
    """
    scan = _scan_principals(reader)
    edges = reader.all_edges()
    dcsync = sorted({e.source_node_id for e in edges if e.kind == "DCSync"})
    t0 = reader.tier0_sets()
    t0_classified_set = set(t0.classified_ids)
    domain_obj_set = set(t0.domain_object_ids)

    du_groups = reader.tier0_node_ids((DOMAIN_USERS_SID_SUFFIX,))
    du_members = reader.effective_members_of(du_groups)

    # privileged-group membership (nested via the M4 closure). The per-suffix dicts
    # cover EVERY individual privileged-group query (incl. Protected Users -525, which
    # is intentionally NOT in PRIVILEGED_GROUP_SID_SUFFIXES — it keeps its standalone
    # hygiene query but is kept OUT of the privileged union / shadow-admin exclusion).
    priv_group_ids: dict[str, tuple[str, ...]] = {}
    priv_members: dict[str, tuple[str, ...]] = {}
    all_group_ids: set[str] = set()
    all_members: set[str] = set()
    # The shadow-admin EXCLUSION union is the privileged union MINUS Cert Publishers
    # (DE hunt-audit defect #6): Cert Publishers is listed/unioned but is NOT
    # Tier-0-equivalent, so excluding its members from the shadow-admin hunt would mask
    # a hidden backdoor. Built per-suffix (NOT as all_members - cert_members) so a
    # principal that is ALSO in a genuinely privileged group stays excluded via THAT
    # membership.
    exclusion_members: set[str] = set()
    union_suffixes = set(PRIVILEGED_GROUP_SID_SUFFIXES)
    dict_suffixes = union_suffixes | {q.suffix for q in PRIVILEGED_GROUP_QUERIES}
    for suffix in sorted(dict_suffixes):
        gids = reader.tier0_node_ids((suffix,))
        members = reader.effective_members_of(gids)
        priv_group_ids[suffix] = tuple(gids)
        priv_members[suffix] = tuple(members)
        if suffix in union_suffixes:
            all_group_ids.update(gids)
            all_members.update(members)
            if suffix != CERT_PUBLISHERS_SID_SUFFIX:
                exclusion_members.update(members)

    # DnsAdmins — no fixed RID, resolved by name.
    dns_gids = reader.group_node_ids_by_samaccountname("DnsAdmins")
    dns_members = reader.effective_members_of(dns_gids)

    # Tier-0 PRINCIPAL node ids (User/Computer/Group) — the subset over which a bare
    # GenericWrite IS a takeover (write member / shadow-cred / SPN). Container-class
    # Tier-0 nodes (the Domain object, OUs) are excluded: GenericWrite on a container
    # is NOT control of it (DE gate #3).
    _principal_kinds = {"User", "Computer", "Group"}
    tier0_principal_ids = {
        n.node_id
        for n in reader.nodes_by_ids(sorted(t0.classified_ids))
        if n.kind in _principal_kinds
    }

    # §4 capability holders (the truth-preserving edge resolvers). reset/write-SPN/
    # shadow-cred are scoped to ACCOUNT targets (User/Computer) — a password / SPN /
    # keyCredentialLink only exists on an account, so GenericAll over a group/OU/GPO
    # is NOT "can reset a password" (DE gate #5).
    account_set = set(scan.account_ids)
    reset_pw = _edge_endpoints_from(edges, RESET_PASSWORD_KINDS, "source", account_set)
    write_spn = _edge_endpoints_from(edges, WRITE_SPN_KINDS, "source", account_set)
    shadow_cred = _edge_endpoints_from(edges, SHADOW_CRED_KINDS, "source", account_set)
    # Target set = the RID-resolved privileged groups PLUS DnsAdmins (DE hunt-audit
    # defect #5): DnsAdmins has no fixed RID (name-resolved above into ``dns_gids``), so
    # a RID-only union misses AddMember->DnsAdmins — a real escalation to DC code-exec.
    # If DnsAdmins is absent, ``dns_gids`` is empty and the target is unchanged (the
    # absence is surfaced as a counted gap by the ACL_ADDMEMBER_PRIVGROUP dispatch).
    add_member_targets = all_group_ids | set(dns_gids)
    add_member = _edge_endpoints_from(edges, ADD_MEMBER_KINDS, "source", add_member_targets)
    ctrl_domain = _edge_endpoints_from(edges, FULL_CONTROL_KINDS, "source", domain_obj_set)
    # controllers-of-tier0 = full control over ANY Tier-0 object, UNION GenericWrite
    # over a Tier-0 PRINCIPAL (account/group) — but NOT GenericWrite over the Domain
    # object/containers (GenericWrite on the domain object is not DCSync) (DE gate #3).
    ctrl_tier0 = sorted(
        set(_edge_endpoints_from(edges, FULL_CONTROL_KINDS, "source", t0_classified_set))
        | set(
            _edge_endpoints_from(
                edges, FULL_CONTROL_KINDS | {"GenericWrite"}, "source", tier0_principal_ids
            )
        )
    )

    # delegation.
    constrained = _edge_endpoints_from(edges, frozenset({"AllowedToDelegate"}), "source", None)
    rbcd_src = _edge_endpoints_from(edges, frozenset({"AllowedToAct"}), "source", None)
    rbcd_tgt = _edge_endpoints_from(edges, frozenset({"AllowedToAct"}), "target", None)
    rbcd_configured = sorted(set(rbcd_src) | set(rbcd_tgt))
    rbcd_writable = _edge_endpoints_from(edges, frozenset({"AddAllowedToAct"}), "source", None)

    # topology.
    dc_set = set(scan.dc_computers)
    admin_on_dc = _edge_endpoints_from(edges, frozenset({"AdminTo"}), "source", dc_set)
    # Origin of the AdminTo-to-DC edges for the honest badge (DE hunt-audit defect #2):
    # GPO-derived (derivation prefix ``GPO:``) carries real SYSVOL provenance; host-SAM
    # (``SAM:AdminTo``) is synthetic until member-host images are collected. A
    # contributing edge with NO derivation cannot decide its origin -> counted as a gap,
    # never guessed real.
    admin_on_dc_edges = [e for e in edges if e.kind == "AdminTo" and e.target_node_id in dc_set]
    admin_on_dc_gpo_derived = any(
        e.derivation is not None and e.derivation.startswith(GPO_DERIVATION_PREFIX)
        for e in admin_on_dc_edges
    )
    admin_on_dc_derivation_missing = any(e.derivation is None for e in admin_on_dc_edges)
    trust_edges = [e for e in edges if e.kind in TRUST_KINDS]
    trust_endpoints = sorted(
        {e.source_node_id for e in trust_edges} | {e.target_node_id for e in trust_edges}
    )

    # shadow admins = full control into Tier-0, minus Tier-0 itself, minus the
    # privileged EXCLUSION union (which omits Cert Publishers -517; DE hunt-audit
    # defect #6 — see ``exclusion_members`` above).
    shadow_admins = sorted(
        set(ctrl_tier0) - t0_classified_set - set(t0.member_ids) - exclusion_members
    )
    # controls-many = outbound control fan-out >= threshold (reuse the risk counter).
    _inbound, outbound = _control_counts(edges)
    controls_many = sorted(
        node for node, controlled in outbound.items() if len(controlled) >= CONTROLS_MANY_THRESHOLD
    )

    # AD CS (doc 16 §D; synthetic-only). One pass over the already-fetched edges for
    # each kind set — base topology, Enroll/AutoEnroll rights, and the inferred ESC
    # composites. Empty on a non-ADCS store (c137) -> the caller counts the gap.
    topo_edges = [e for e in edges if e.kind in ADCS_TOPOLOGY_KINDS]
    topo_endpoints = sorted(
        {e.source_node_id for e in topo_edges} | {e.target_node_id for e in topo_edges}
    )
    enroll_edges = [e for e in edges if e.kind in ADCS_ENROLLMENT_KINDS]
    enroll_holders = sorted({e.source_node_id for e in enroll_edges})
    enroll_endpoints = sorted(
        {e.source_node_id for e in enroll_edges} | {e.target_node_id for e in enroll_edges}
    )
    esc_edges = [e for e in edges if e.kind in ADCS_ESC_KINDS]
    esc_targets = sorted({e.target_node_id for e in esc_edges})

    disabled_priv = sorted(set(scan.disabled) & all_members)
    # admincount orphans = stale USER residue (ptype==User, not krbtgt/-500) that is
    # NOT currently an effective member of any privileged group (DE gate #4).
    admincount_orphans = sorted(set(scan.admincount_users) - all_members)

    return SourceSets(
        kerberoastable=scan.kerberoastable,
        asrep=scan.asrep,
        unconstrained=scan.unconstrained,
        dcsync_holders=tuple(dcsync),
        tier0_classified=tuple(sorted(t0.classified_ids)),
        tier0_members=tuple(sorted(t0.member_ids)),
        tier0_targets=tuple(t0.target_ids),
        domain_object_ids=tuple(sorted(t0.domain_object_ids)),
        domain_users=tuple(du_members),
        domain_users_group_present=bool(du_groups),
        privileged_group_ids_by_suffix=priv_group_ids,
        privileged_members_by_suffix=priv_members,
        all_privileged_group_ids=tuple(sorted(all_group_ids)),
        all_privileged_members=tuple(sorted(all_members)),
        dnsadmins_group_ids=tuple(dns_gids),
        dnsadmins_members=tuple(dns_members),
        reset_password_holders=tuple(reset_pw),
        write_spn_holders=tuple(write_spn),
        shadow_cred_holders=tuple(shadow_cred),
        add_member_privgroup_holders=tuple(add_member),
        controllers_of_domain=tuple(ctrl_domain),
        controllers_of_tier0=tuple(ctrl_tier0),
        shadow_admins_tier0=tuple(shadow_admins),
        controls_many=tuple(controls_many),
        password_not_required=scan.password_not_required,
        password_never_expires=scan.password_never_expires,
        reversible_password=scan.reversible_password,
        sid_history_present=scan.sid_history,
        admincount_set=scan.admincount,
        constrained_delegation=tuple(constrained),
        rbcd_configured=tuple(rbcd_configured),
        rbcd_writable=tuple(rbcd_writable),
        disabled_but_privileged=tuple(disabled_priv),
        admincount_orphans=tuple(admincount_orphans),
        trust_endpoint_ids=tuple(trust_endpoints),
        trust_edge_count=len(trust_edges),
        dc_computer_ids=scan.dc_computers,
        admin_on_dc_holders=tuple(admin_on_dc),
        admin_on_dc_gpo_derived=admin_on_dc_gpo_derived,
        admin_on_dc_derivation_missing=admin_on_dc_derivation_missing,
        adcs_topology_endpoint_ids=tuple(topo_endpoints),
        adcs_topology_edge_count=len(topo_edges),
        enrollment_rights_holders=tuple(enroll_holders),
        enrollment_endpoint_ids=tuple(enroll_endpoints),
        esc_target_ids=tuple(esc_targets),
        esc_edge_count=len(esc_edges),
    )


def _source_count(sets: SourceSets, query_id: str) -> int | None:
    """Return the live defining-set size for a query id (``None`` if unsupported).

    For a privileged-group set this is the effective-member count; for a source-
    filtered path/set query it is the discrete predicate set; for the global
    ``paths-to-tier0`` it is the Tier-0 principal count; for ``set-trusts`` the
    number of trust edges — the number the analyst recognises next to the query.
    """
    priv_suffix = _PRIV_SUFFIX_BY_ID.get(query_id)
    if priv_suffix is not None:
        return len(sets.privileged_members_by_suffix.get(priv_suffix, ()))
    return {
        PATHS_TO_TIER0: len(set(sets.tier0_classified)),
        PATHS_FROM_KERBEROASTABLE: len(sets.kerberoastable),
        PATHS_FROM_ASREP: len(sets.asrep),
        PATHS_FROM_DOMAIN_USERS: len(sets.domain_users),
        PATHS_TO_UNCONSTRAINED: len(sets.unconstrained),
        SET_TIER0: len(set(sets.tier0_classified) | set(sets.tier0_members)),
        SET_DCSYNC: len(sets.dcsync_holders),
        SET_KERBEROASTABLE: len(sets.kerberoastable),
        SET_ASREP: len(sets.asrep),
        SET_UNCONSTRAINED: len(sets.unconstrained),
        SET_ALL_PRIVILEGED: len(sets.all_privileged_members),
        SET_DNSADMINS: len(sets.dnsadmins_members),
        ACL_CONTROLLERS_OF_DOMAIN: len(sets.controllers_of_domain),
        ACL_CONTROLLERS_OF_TIER0: len(sets.controllers_of_tier0),
        ACL_RESET_PASSWORD: len(sets.reset_password_holders),
        ACL_WRITESPN: len(sets.write_spn_holders),
        ACL_SHADOWCRED: len(sets.shadow_cred_holders),
        ACL_ADDMEMBER_PRIVGROUP: len(sets.add_member_privgroup_holders),
        SHADOW_ADMINS_TIER0: len(sets.shadow_admins_tier0),
        CONTROLS_MANY: len(sets.controls_many),
        SET_PASSWORD_NOT_REQUIRED: len(sets.password_not_required),
        SET_PASSWORD_NEVER_EXPIRES: len(sets.password_never_expires),
        SET_REVERSIBLE_PASSWORD: len(sets.reversible_password),
        SET_SID_HISTORY: len(sets.sid_history_present),
        SET_ADMINCOUNT: len(sets.admincount_set),
        SET_CONSTRAINED_DELEGATION: len(sets.constrained_delegation),
        SET_RBCD_CONFIGURED: len(sets.rbcd_configured),
        SET_RBCD_WRITABLE: len(sets.rbcd_writable),
        SET_DISABLED_BUT_PRIVILEGED: len(sets.disabled_but_privileged),
        SET_ADMINCOUNT_ORPHANS: len(sets.admincount_orphans),
        SET_TRUSTS: sets.trust_edge_count,
        SET_ADMIN_ON_DC: len(sets.admin_on_dc_holders),
        # AD CS (synthetic-only): topology = edge count; enrollment = holder count;
        # the ESC path query shows its distinct-sink count (like paths-to-unconstrained).
        SET_ADCS_TOPOLOGY: sets.adcs_topology_edge_count,
        SET_ENROLLMENT_RIGHTS: len(sets.enrollment_rights_holders),
        PATHS_TO_ADCS_ESC: len(sets.esc_target_ids),
    }.get(query_id)


def _resolve_data_confidence(spec: QuerySpec, sets: SourceSets) -> _DataConfidence:
    """Return the honest ``data_confidence`` badge for ``spec`` given the live sets.

    Static ``spec.data_confidence`` for every query EXCEPT ``set-admin-on-dc`` (DE
    hunt-audit defect #2): its badge is derived from the actual AdminTo-to-DC edges'
    provenance — ``real`` only when >=1 contributing edge is GPO-derived (real SYSVOL
    provenance), else the honest-conservative ``synthetic-only`` (the host-SAM-only
    AdminTo surface, or an edge whose origin could not be decided). Never guesses
    ``real``.

    Failure modes:
        Never raises.
    """
    if spec.id == SET_ADMIN_ON_DC:
        return "real" if sets.admin_on_dc_gpo_derived else "synthetic-only"
    return cast("_DataConfidence", spec.data_confidence)


def list_queries(reader: StoreReader) -> list[PrebuiltQuery]:
    """Return the full catalog with live source-set counts (``GET /analysis/queries``).

    Inputs:
        reader: the read-only store accessor.

    Returns:
        One :class:`PrebuiltQuery` per catalog entry, in display order, each carrying
        its hunter ``category`` so the UI can group. Supported entries carry a live
        ``source_count``; out-of-scope entries carry ``supported=False`` + an honest
        ``reason`` and ``source_count=None``.

    Failure modes:
        Never raises on content.
    """
    sets = resolve_source_sets(reader)
    return [
        PrebuiltQuery(
            id=spec.id,
            label=spec.label,
            description=spec.description,
            category=spec.category,
            kind=spec.kind,  # type: ignore[arg-type]
            direction=spec.direction,  # type: ignore[arg-type]
            supported=spec.supported,
            reason=spec.reason,
            data_confidence=_resolve_data_confidence(spec, sets),
            source_count=_source_count(sets, spec.id) if spec.supported else None,
        )
        for spec in CATALOG
    ]


def _empty_path_result(sources: Sequence[str], targets: Sequence[str], max_hops: int) -> PathResult:
    """Build an honest empty :class:`PathResult` (no path; targets unreachable).

    Used when a query's TARGET set is empty (so ``find_paths_to`` must not be called
    with an empty target that would silently fall back to the Tier-0 default) — the
    result honestly reports zero paths plus the (empty) target set, paired with a
    counted gap by the caller.
    """
    return PathResult(
        source_node_ids=sorted(set(sources)),
        target_node_ids=sorted(set(targets)),
        paths=[],
        paths_found=0,
        truncated=False,
        max_hops=max(1, int(max_hops)),
        unreachable_targets=sorted(set(targets)),
        over_budget_targets=[],
    )


def _empty_slice() -> GraphSlice:
    """Build an empty :class:`GraphSlice` (never the whole graph).

    ``build_slice`` with an empty seed list expands to ALL nodes; a set query whose
    source set is empty must therefore short-circuit to this honest empty slice (the
    caller counts the empty-set gap) rather than returning the entire forest.
    """
    return GraphSlice(
        nodes=[],
        edges=[],
        total_matched=0,
        returned=0,
        truncated=False,
        layout="none",
        seed_node_ids=[],
        depth=0,
    )


def _run_path(
    reader: StoreReader,
    spec: QuerySpec,
    sets: SourceSets,
    pg: PathGraph,
    max_hops: int,
    max_paths: int,
    gaps: dict[str, int],
) -> PathResult:
    """Dispatch a ``kind == "path"`` catalog entry to ``find_paths_to`` (design §3.1).

    ``pg`` is the ONE H2-filtered per-case graph (full Tier-0 classification group
    set) built by :func:`run_query`, passed to every path call so H2 holds
    uniformly regardless of the query's target (design §14 [HIGH]).
    """
    if spec.id == PATHS_TO_TIER0:
        if not sets.tier0_targets:
            gaps["empty_target_set"] = 1
            return _empty_path_result([], [], max_hops)
        return find_paths_to(
            reader,
            target="tier0",
            source_filter=None,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    if spec.id == PATHS_FROM_KERBEROASTABLE:
        if not sets.kerberoastable:
            gaps["empty_source_set"] = 1
        return find_paths_to(
            reader,
            target="tier0",
            source_filter=sets.kerberoastable,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    if spec.id == PATHS_FROM_ASREP:
        if not sets.asrep:
            gaps["empty_source_set"] = 1
        return find_paths_to(
            reader,
            target="tier0",
            source_filter=sets.asrep,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    if spec.id == PATHS_FROM_DOMAIN_USERS:
        if not sets.domain_users_group_present:
            gaps["domain_users_group_absent"] = 1
        elif not sets.domain_users:
            gaps["domain_users_empty_effective_membership"] = 1
        return find_paths_to(
            reader,
            target="tier0",
            source_filter=sets.domain_users,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    if spec.id == PATHS_TO_UNCONSTRAINED:
        if not sets.unconstrained:
            gaps["empty_target_set"] = 1
            return _empty_path_result([], [], max_hops)
        return find_paths_to(
            reader,
            target_node_ids=sets.unconstrained,
            source_filter=None,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    if spec.id == PATHS_TO_ADCS_ESC:
        # Paths that TERMINATE at an ESC-abuse sink = the target nodes of the inferred
        # ESC composites (doc 16 §D). Same bounded reverse-BFS pattern as
        # paths-to-unconstrained; an absent ESC surface is a counted empty-target gap.
        if not sets.esc_target_ids:
            gaps["empty_target_set"] = 1
            return _empty_path_result([], [], max_hops)
        return find_paths_to(
            reader,
            target_node_ids=sets.esc_target_ids,
            source_filter=None,
            max_hops=max_hops,
            max_paths=max_paths,
            path_graph=pg,
        )
    raise UnknownQueryError(spec.id)  # pragma: no cover - guarded by the catalog


def _run_set(
    reader: StoreReader, spec: QuerySpec, sets: SourceSets, gaps: dict[str, int]
) -> GraphSlice:
    """Dispatch a ``kind == "set"`` catalog entry to ``build_slice`` (design §3.1).

    Every branch is BOUNDED (``build_slice`` with a non-empty seed, capped at
    ``DEFAULT_LIMIT``) and COUNTED (an empty defining set is a named gap, never a
    silent empty answer nor the whole-forest expansion of an empty seed).
    """

    def emit(
        defining: Sequence[str],
        seed: Sequence[str],
        *,
        depth: int,
        edge_kinds: Collection[str] | None,
        gap_key: str = "empty_source_set",
    ) -> GraphSlice:
        """Build a bounded slice, or count ``gap_key`` and return an empty slice.

        ``defining`` is the set whose emptiness defines "no result" (and the count);
        ``seed`` is the (never-empty-when ``defining`` is non-empty) BFS seed so the
        slice can show the justifying edge.
        """
        if not defining:
            gaps[gap_key] = 1
            return _empty_slice()
        # expand_base_endpoints=False: a seeded SET query is a RESULT view, not a
        # drill-in — it must stay canonical-only and never flood with Base endpoints
        # (owner decision 2026-10-29; the set-unconstrained hunt regression).
        return build_slice(
            reader,
            seed_node_ids=sorted(set(seed)),
            depth=depth,
            edge_kinds=sorted(edge_kinds) if edge_kinds is not None else None,
            limit=DEFAULT_LIMIT,
            layout="none",
            expand_base_endpoints=False,
        )

    # --- privileged-group membership sets (nested via the M4 closure) ---
    priv_suffix = _PRIV_SUFFIX_BY_ID.get(spec.id)
    if priv_suffix is not None:
        gids = sets.privileged_group_ids_by_suffix.get(priv_suffix, ())
        members = sets.privileged_members_by_suffix.get(priv_suffix, ())
        if not gids:
            gaps["privileged_group_absent"] = 1
            return _empty_slice()
        if not members:
            gaps["empty_source_set"] = 1
        # Result view, not a drill-in: canonical-only (expand_base_endpoints=False).
        return build_slice(
            reader,
            seed_node_ids=sorted(set(gids) | set(members)),
            depth=0,
            edge_kinds=["MemberOf"],
            limit=DEFAULT_LIMIT,
            layout="none",
            expand_base_endpoints=False,
        )

    # --- doc 15 (v1) set queries (byte-identical to the gated behaviour) ---
    if spec.id == SET_TIER0:
        seed = sorted(set(sets.tier0_classified) | set(sets.tier0_members))
        return emit(seed, seed, depth=0, edge_kinds=["MemberOf"])
    if spec.id == SET_DCSYNC:
        seed = sorted(set(sets.dcsync_holders) | set(sets.domain_object_ids))
        return emit(seed, seed, depth=0, edge_kinds=["DCSync"])
    if spec.id == SET_KERBEROASTABLE:
        return emit(sets.kerberoastable, sets.kerberoastable, depth=0, edge_kinds=None)
    if spec.id == SET_ASREP:
        return emit(sets.asrep, sets.asrep, depth=0, edge_kinds=None)
    if spec.id == SET_UNCONSTRAINED:
        return emit(sets.unconstrained, sets.unconstrained, depth=0, edge_kinds=None)

    # --- doc 20 §5.1 Privileged Access (union + DnsAdmins) ---
    if spec.id == SET_ALL_PRIVILEGED:
        seed = sorted(set(sets.all_privileged_group_ids) | set(sets.all_privileged_members))
        return emit(sets.all_privileged_members, seed, depth=0, edge_kinds=["MemberOf"])
    if spec.id == SET_DNSADMINS:
        if not sets.dnsadmins_group_ids:
            gaps["dnsadmins_group_absent"] = 1
            return _empty_slice()
        if not sets.dnsadmins_members:
            gaps["empty_source_set"] = 1
        # Result view, not a drill-in: canonical-only (expand_base_endpoints=False).
        return build_slice(
            reader,
            seed_node_ids=sorted(set(sets.dnsadmins_group_ids) | set(sets.dnsadmins_members)),
            depth=0,
            edge_kinds=["MemberOf"],
            limit=DEFAULT_LIMIT,
            layout="none",
            expand_base_endpoints=False,
        )

    # --- doc 20 §5.2 Dangerous ACLs ---
    # NOTE (deviation from doc 20 §5.2's literal depth=1): real DITs carry ACL edges
    # (GenericWrite/WriteDacl/WriteOwner/AllExtendedRights) over ~every object, so a
    # depth=1 neighbourhood from any ACL holder expands to the WHOLE forest (bounded,
    # but useless). We therefore seed at depth=0: the slice is EXACTLY the matched
    # principals, plus (only when the target anchor is a SMALL, named set — the
    # Domain object / the Tier-0 set / the privileged groups / the DCs) that anchor,
    # so the justifying control edge still renders without pulling in hundreds of
    # victims. The headline truth is the holder count (source_count); per-victim
    # edges remain visible in each principal's dossier.
    if spec.id == ACL_CONTROLLERS_OF_DOMAIN:
        seed = sorted(set(sets.controllers_of_domain) | set(sets.domain_object_ids))
        return emit(sets.controllers_of_domain, seed, depth=0, edge_kinds=FULL_CONTROL_KINDS)
    if spec.id == ACL_CONTROLLERS_OF_TIER0:
        seed = sorted(set(sets.controllers_of_tier0) | set(sets.tier0_classified))
        return emit(sets.controllers_of_tier0, seed, depth=0, edge_kinds=FULL_CONTROL_KINDS)
    if spec.id == ACL_RESET_PASSWORD:
        return emit(
            sets.reset_password_holders, sets.reset_password_holders, depth=0, edge_kinds=None
        )
    if spec.id == ACL_WRITESPN:
        return emit(sets.write_spn_holders, sets.write_spn_holders, depth=0, edge_kinds=None)
    if spec.id == ACL_SHADOWCRED:
        return emit(sets.shadow_cred_holders, sets.shadow_cred_holders, depth=0, edge_kinds=None)
    if spec.id == ACL_ADDMEMBER_PRIVGROUP:
        # DnsAdmins is a name-resolved target (no fixed RID; DE hunt-audit defect #5):
        # seed it alongside the RID privileged groups so its justifying AddMember edge
        # renders, and count the unresolved-lookup gap when DnsAdmins is absent (never a
        # silent assumption that there is no DnsAdmins escalation path).
        if not sets.dnsadmins_group_ids:
            gaps["dnsadmins_group_absent"] = 1
        seed = sorted(
            set(sets.add_member_privgroup_holders)
            | set(sets.all_privileged_group_ids)
            | set(sets.dnsadmins_group_ids)
        )
        return emit(sets.add_member_privgroup_holders, seed, depth=0, edge_kinds=ADD_MEMBER_KINDS)

    # --- doc 20 §5.3 Shadow / Hidden Admins ---
    if spec.id == SHADOW_ADMINS_TIER0:
        seed = sorted(set(sets.shadow_admins_tier0) | set(sets.tier0_classified))
        return emit(sets.shadow_admins_tier0, seed, depth=0, edge_kinds=FULL_CONTROL_KINDS)
    if spec.id == CONTROLS_MANY:
        return emit(sets.controls_many, sets.controls_many, depth=0, edge_kinds=None)

    # --- doc 20 §5.4 Credential Exposure field predicates ---
    if spec.id == SET_PASSWORD_NOT_REQUIRED:
        return emit(
            sets.password_not_required, sets.password_not_required, depth=0, edge_kinds=None
        )
    if spec.id == SET_PASSWORD_NEVER_EXPIRES:
        return emit(
            sets.password_never_expires, sets.password_never_expires, depth=0, edge_kinds=None
        )
    if spec.id == SET_REVERSIBLE_PASSWORD:
        return emit(sets.reversible_password, sets.reversible_password, depth=0, edge_kinds=None)
    if spec.id == SET_SID_HISTORY:
        return emit(sets.sid_history_present, sets.sid_history_present, depth=0, edge_kinds=None)
    if spec.id == SET_ADMINCOUNT:
        return emit(sets.admincount_set, sets.admincount_set, depth=0, edge_kinds=None)

    # --- doc 20 §5.5 Delegation (depth=0: delegation edges are sparse, both
    #     endpoints seeded so the justifying edge still renders) ---
    if spec.id == SET_CONSTRAINED_DELEGATION:
        return emit(
            sets.constrained_delegation, sets.constrained_delegation, depth=0, edge_kinds=None
        )
    if spec.id == SET_RBCD_CONFIGURED:
        return emit(
            sets.rbcd_configured, sets.rbcd_configured, depth=0, edge_kinds=["AllowedToAct"]
        )
    if spec.id == SET_RBCD_WRITABLE:
        return emit(sets.rbcd_writable, sets.rbcd_writable, depth=0, edge_kinds=None)

    # --- doc 20 §5.6 Stale / Risk ---
    if spec.id == SET_DISABLED_BUT_PRIVILEGED:
        return emit(
            sets.disabled_but_privileged,
            sets.disabled_but_privileged,
            depth=0,
            edge_kinds=["MemberOf"],
        )
    if spec.id == SET_ADMINCOUNT_ORPHANS:
        return emit(sets.admincount_orphans, sets.admincount_orphans, depth=0, edge_kinds=None)

    # --- doc 20 §5.7 Topology ---
    if spec.id == SET_TRUSTS:
        if sets.trust_edge_count == 0:
            gaps["no_trust_edges"] = 1
            return _empty_slice()
        seed = sorted(set(sets.domain_object_ids) | set(sets.trust_endpoint_ids))
        return emit(seed, seed, depth=0, edge_kinds=TRUST_KINDS, gap_key="no_trust_edges")
    if spec.id == SET_ADMIN_ON_DC:
        if not sets.dc_computer_ids:
            gaps["no_domain_controller"] = 1
            return _empty_slice()
        # Honest badge provenance (DE hunt-audit defect #2): when the holders exist but
        # NO contributing AdminTo-to-DC edge is GPO-derived, the result is synthetic
        # (host-SAM only) — the badge is downgraded to synthetic-only and the fallback
        # is a counted gap. A contributing edge with no derivation at all is a distinct
        # counted gap (origin undecidable), never a guessed badge.
        if sets.admin_on_dc_holders and not sets.admin_on_dc_gpo_derived:
            gaps["admin_on_dc_synthetic_only"] = 1
        if sets.admin_on_dc_derivation_missing:
            gaps["admin_on_dc_derivation_unavailable"] = 1
        seed = sorted(set(sets.admin_on_dc_holders) | set(sets.dc_computer_ids))
        return emit(sets.admin_on_dc_holders, seed, depth=0, edge_kinds=["AdminTo"])

    # --- doc 20 §5.8 AD CS (synthetic-only; doc 16 §D) ---
    if spec.id == SET_ADCS_TOPOLOGY:
        # Defining set = the topology edge endpoints (empty iff no topology edges);
        # seed both endpoints so the PublishedTo/EnterpriseCAFor/... edges render.
        return emit(
            sets.adcs_topology_endpoint_ids,
            sets.adcs_topology_endpoint_ids,
            depth=0,
            edge_kinds=ADCS_TOPOLOGY_KINDS,
            gap_key="no_adcs_topology",
        )
    if spec.id == SET_ENROLLMENT_RIGHTS:
        # Defining set = the Enroll/AutoEnroll holders (the headline count); seed both
        # endpoints so the justifying enrollment edge renders beside each holder.
        return emit(
            sets.enrollment_rights_holders,
            sets.enrollment_endpoint_ids,
            depth=0,
            edge_kinds=ADCS_ENROLLMENT_KINDS,
            gap_key="no_enrollment_rights",
        )

    raise UnknownQueryError(spec.id)  # pragma: no cover - guarded by the catalog


def run_query(
    reader: StoreReader, query_id: str, *, max_hops: int, max_paths: int
) -> PrebuiltQueryResult:
    """Run one catalog query, returning a bounded :class:`PrebuiltQueryResult`.

    Inputs:
        reader: the read-only store accessor.
        query_id: a catalog id (see the module-level id constants).
        max_hops: path-length cutoff for ``path`` queries (clamped by the engine).
        max_paths: ranked-shortest-first cap for ``path`` queries (clamped).

    Returns:
        A :class:`PrebuiltQueryResult` with exactly one of ``paths`` / ``slice``
        populated and ``counted_gaps`` listing every degraded branch.

    Failure modes:
        Raises :class:`UnknownQueryError` for an unknown id (-> 404) and
        :class:`UnsupportedQueryError` for an out-of-scope entry (-> 422). Never
        returns a silent empty result — an empty source/target set is a counted gap.
    """
    spec = _SPEC_BY_ID.get(query_id)
    if spec is None:
        raise UnknownQueryError(query_id)
    if not spec.supported:
        raise UnsupportedQueryError(query_id, spec.reason or "out of scope for v1")
    sets = resolve_source_sets(reader)
    # The badge is derived from the live sets for set-admin-on-dc (DE hunt-audit
    # defect #2); static for every other query.
    data_confidence = _resolve_data_confidence(spec, sets)
    gaps: dict[str, int] = {}
    if spec.kind == "path":
        # ONE H2-filtered per-case graph passed to every path call (design §14 [HIGH]).
        pg = build_case_path_graph(reader)
        paths = _run_path(reader, spec, sets, pg, max_hops, max_paths, gaps)
        return PrebuiltQueryResult(
            query_id=query_id,
            kind="path",
            paths=paths,
            counted_gaps=gaps,
            data_confidence=data_confidence,
        )
    sl = _run_set(reader, spec, sets, gaps)
    return PrebuiltQueryResult(
        query_id=query_id,
        kind="set",
        slice=sl,
        counted_gaps=gaps,
        data_confidence=data_confidence,
    )
