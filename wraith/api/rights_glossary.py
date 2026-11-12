"""The static, forensically-true rights/attributes glossary (design doc 21 §4).

Every WRAITH edge kind and every node-flag / UAC-flag / attribute-signal maps to a
plain-language ``{grants, why, action}`` entry, authored by the domain-expert in
doc 21 and transcribed here verbatim. The mappings agree with the hunter
truth-contract in :mod:`wraith.api.queries` (the capability -> edge-kind frozen
sets) so the glossary and the hunts never disagree — e.g. ``GenericWrite`` grants
SPN / shadow-cred / RBCD but NOT a password reset or a DACL rewrite;
``AllExtendedRights`` grants ForceChangePassword + DCSync-on-domain but NOT plain
property writes.

Primary sources (public facts, reused not copied): [MS-DTYP] 2.4.3, [MS-ADTS]
5.1.3.2 / 6.1.3, [MS-ADSC] / MS ``adschema``, [MS-DRSR], [MS-GPOL], and the
BloodHound/SharpHound edge documentation as the reference for attacker intent.

Pure, offline, deterministic: these are module-level constants, no network, no
runtime text generation. :func:`build_glossary` serves them through the read-only
``GET /api/v1/glossary`` endpoint; :func:`lookup_edge` / :data:`NEUTRAL_EDGE_ENTRY`
let a caller degrade an unknown (future) edge kind to a neutral caption and count
a gap — never a guessed abuse.
"""

from __future__ import annotations

from dataclasses import dataclass

from wraith.api.models import GlossaryEntryOut, GlossaryOut
from wraith.edges.guid_map import (
    GUID_ALLOWED_TO_ACT,
    GUID_ALT_SECURITY_IDENTITIES,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    GUID_GET_CHANGES_IN_FILTERED_SET,
    GUID_GPLINK,
    GUID_KEY_CREDENTIAL_LINK,
    GUID_MEMBER,
    GUID_PUBLIC_INFORMATION,
    GUID_SERVICE_PRINCIPAL_NAME,
    GUID_USER_ACCOUNT_RESTRICTIONS,
)


@dataclass(frozen=True)
class GlossaryEntry:
    """One authored glossary row (doc 21 §4): grants / why-a-hunter-cares / action."""

    grants: str
    why: str
    action: str


# =============================================================================
# §4.1–§4.5 — edge kinds. Transcribed verbatim from doc 21 (re-gated for accuracy).
# =============================================================================
EDGE_GLOSSARY: dict[str, GlossaryEntry] = {
    # --- §4.1 whole-object control edges ---
    "GenericAll": GlossaryEntry(
        grants=(
            "Full control of the object (all property writes + all control-access "
            "rights + WriteDacl/WriteOwner implied)."
        ),
        why=(
            "The strongest ACE. On a USER/COMPUTER: reset the password, set an SPN, "
            "add a shadow credential, read LAPS. On a GROUP: add any member. On the "
            "DOMAIN object: self-grant DCSync. On a GPO: edit it."
        ),
        action="has full control of",
    ),
    "GenericWrite": GlossaryEntry(
        grants=(
            "Write every non-protected property of the object. Does NOT grant "
            "WriteDacl/WriteOwner, and does NOT reset a password (that is a "
            "control-access right, not a property write)."
        ),
        why=(
            "On an account: set an SPN (Kerberoast), add a shadow credential "
            "(msDS-KeyCredentialLink), or set RBCD. On a group: add a member. No "
            "password reset, no DACL rewrite."
        ),
        action="can write the attributes of",
    ),
    "WriteDacl": GlossaryEntry(
        grants="Rewrite the object's DACL.",
        why=(
            "Grant yourself GenericAll, then do anything. On the Domain object, add "
            "the two replication rights to yourself -> DCSync. The classic 'one ACE "
            "to full control' primitive."
        ),
        action="can rewrite the permissions (DACL) of",
    ),
    "WriteOwner": GlossaryEntry(
        grants="Set the object's owner.",
        why=(
            "Make yourself the owner; the owner can always rewrite the DACL -> full "
            "control. Two-step to the same place as WriteDacl."
        ),
        action="can take ownership of",
    ),
    "Owns": GlossaryEntry(
        grants="Is the current owner of the object (from the SD owner field).",
        why=(
            "The owner implicitly can rewrite the DACL -> full control. Surfaced so a "
            "hunter sees ownership-based control, not only explicit ACEs."
        ),
        action="owns (and can thus fully control)",
    ),
    "AllExtendedRights": GlossaryEntry(
        grants="Holds every control-access (extended) right on the object.",
        why=(
            "Includes ForceChangePassword (reset password) and, on the Domain object, "
            "the DS-Replication-Get-Changes rights -> DCSync. Does NOT grant plain "
            "property writes (cannot set an SPN by itself)."
        ),
        action="holds every extended right over",
    ),
    # --- §4.2 scoped property-write / validated-write edges ---
    "AddMember": GlossaryEntry(
        grants="Write the group's `member` attribute.",
        why=(
            "Add ANY principal — including yourself — to the group, inheriting its "
            "privileges. Against a privileged group this is direct Tier-0 "
            "self-elevation."
        ),
        action="can add members to",
    ),
    "AddSelf": GlossaryEntry(
        grants="Validated-write (`DS-Self`) on `member`.",
        why=("Add ITSELF (only) to the group. On a privileged group, direct " "self-elevation."),
        action="can add itself to",
    ),
    "ForceChangePassword": GlossaryEntry(
        grants="The User-Force-Change-Password control-access right.",
        why=(
            "Reset the account's password without knowing the current one, then log "
            "in as it. The cleanest account takeover."
        ),
        action="can reset the password of",
    ),
    "WriteSPN": GlossaryEntry(
        grants="Write `servicePrincipalName` on an account.",
        why=(
            "Set an SPN on a target account, request its service ticket, and crack it "
            "offline (targeted Kerberoast)."
        ),
        action="can set an SPN on (targeted Kerberoast)",
    ),
    "AddKeyCredentialLink": GlossaryEntry(
        grants="Write `msDS-KeyCredentialLink`.",
        why=(
            "Add an attacker-controlled key pair (shadow credential); then "
            "authenticate via PKINIT as the account with no password "
            "(Whisker/pass-the-cert)."
        ),
        action="can add a shadow credential to and log in as",
    ),
    "AddAllowedToAct": GlossaryEntry(
        grants=("Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer."),
        why=(
            "Configure RBCD so an attacker-controlled principal can impersonate ANY "
            "user to that computer (S4U) -> take the host."
        ),
        action="can configure RBCD on (impersonate any user to it)",
    ),
    "WriteAccountRestrictions": GlossaryEntry(
        grants=(
            "Write the User-Account-Restrictions property set (incl. "
            "`userAccountControl` and the RBCD attribute)."
        ),
        why=(
            "Configure RBCD, or toggle delegation/UAC bits — a route to computer "
            "takeover and delegation abuse."
        ),
        action="can write account restrictions on (set RBCD / toggle UAC)",
    ),
    "WriteAltSecurityIdentities": GlossaryEntry(
        grants="Write `altSecurityIdentities`.",
        why=(
            "Map an attacker certificate to the account (explicit cert mapping) -> "
            "authenticate as it (certificate-based impersonation / ESC)."
        ),
        action="can map a certificate to (impersonate it)",
    ),
    "WriteGPLink": GlossaryEntry(
        grants="Write `gPLink` on an OU/domain/site.",
        why=(
            "Link a malicious GPO to the container -> push code/rights to every "
            "computer and user beneath."
        ),
        action="can link a malicious GPO to",
    ),
    "WritePublicInformation": GlossaryEntry(
        grants=(
            "Write the Public-Information property set (which includes " "`servicePrincipalName`)."
        ),
        why=(
            "Enables setting an SPN on the account -> targeted Kerberoast. "
            "Conservative framing: WRAITH surfaces it as a property-set write and "
            "leaves finer abuse to the analyst."
        ),
        action="can write public info on (set an SPN)",
    ),
    # --- §4.3 replication, credential-read, delegation & identity edges ---
    "DCSync": GlossaryEntry(
        grants=(
            "(Composite) the replication rights needed to pull directory secrets from "
            "the Domain object."
        ),
        why=(
            "Replicate every account's password hash — including krbtgt — then forge "
            "a Golden Ticket. Terminal domain compromise. WRAITH derives this "
            "composite when a principal holds the Get-Changes rights that permit a "
            "full secret pull."
        ),
        action="can DCSync the domain (pull every hash, forge a Golden Ticket)",
    ),
    "GetChanges": GlossaryEntry(
        grants="DS-Replication-Get-Changes extended right on the domain NC.",
        why=(
            "One half of DCSync — NOT sufficient alone. Surfaced for transparency; "
            "the composite `DCSync` is the actionable edge."
        ),
        action="holds replication Get-Changes on",
    ),
    "GetChangesAll": GlossaryEntry(
        grants="DS-Replication-Get-Changes-All extended right.",
        why="The second half; GetChanges + GetChangesAll = full DCSync (hashes).",
        action="holds replication Get-Changes-All on",
    ),
    "GetChangesInFilteredSet": GlossaryEntry(
        grants="DS-Replication-Get-Changes-In-Filtered-Set.",
        why=(
            "Replicate the filtered attribute set (incl. some secrets / RODC-related); "
            "a DCSync nuance, not sufficient alone for full hashes."
        ),
        action="holds filtered-set replication on",
    ),
    "ReadLAPSPassword": GlossaryEntry(
        grants="Read the LAPS password attribute (`ms-Mcs-AdmPwd` / `msLAPS-Password`).",
        why=(
            "Retrieve the computer's local administrator password in cleartext -> "
            "local admin on that host."
        ),
        action="can read the LAPS local-admin password of",
    ),
    "ReadGMSAPassword": GlossaryEntry(
        grants="Read `msDS-ManagedPassword` of a group-managed service account.",
        why=(
            "Retrieve the gMSA's managed password blob -> authenticate as the service " "account."
        ),
        action="can read the gMSA password of (act as it)",
    ),
    "AllowedToDelegate": GlossaryEntry(
        grants=(
            "Constrained delegation: `msDS-AllowedToDelegateTo` lists the target " "service(s)."
        ),
        why=(
            "The principal can impersonate users to the listed service (S4U2Proxy; "
            "with protocol transition, to any user) -> take over that service/host."
        ),
        action="can impersonate users to (constrained delegation)",
    ),
    "AllowedToAct": GlossaryEntry(
        grants=(
            "RBCD is configured on the resource " "(`msDS-AllowedToActOnBehalfOfOtherIdentity`)."
        ),
        why=(
            "The named principal can impersonate ANY user to the resource (S4U) -> " "take it over."
        ),
        action="can act on behalf of users to (RBCD)",
    ),
    "CoerceToTGT": GlossaryEntry(
        grants="(Derived) a non-DC host trusted for UNCONSTRAINED delegation.",
        why=(
            "Coerce a DC (PrinterBug/PetitPotam) to authenticate to the host and "
            "capture the DC's TGT -> domain compromise. DCs carrying the flag are "
            "expected and excluded."
        ),
        action="can coerce a DC and capture its TGT (unconstrained)",
    ),
    "MemberOf": GlossaryEntry(
        grants="Group membership (member -> group).",
        why=(
            "Inherits every right and privilege the group holds, transitively. The "
            "backbone of privilege inheritance."
        ),
        action="is a member of (inherits its rights)",
    ),
    "HasSIDHistory": GlossaryEntry(
        grants="The principal's `sIDHistory` carries another principal's SID.",
        why=(
            "Wields the access of the historical SID as if it were still that "
            "principal — a classic persistence/escalation smuggle (inject a Tier-0 "
            "SID)."
        ),
        action="carries the SID (and privileges) of",
    ),
    # --- §4.4 structural, lateral-movement & trust edges ---
    "Contains": GlossaryEntry(
        grants="Directory containment (container/OU holds the object).",
        why=(
            "Structural. Controlling the parent can push ACLs/GPOs down. WRAITH's H2 "
            "rule excludes `Contains` INTO a Tier-0 group as a false control hop."
        ),
        action="contains",
    ),
    "GPLink": GlossaryEntry(
        grants="A GPO is linked to this OU/domain/site.",
        why=(
            "The GPO's settings/rights apply to all objects beneath. If the attacker "
            "controls the GPO, this is the push path."
        ),
        action="is applied to (via Group Policy)",
    ),
    "AdminTo": GlossaryEntry(
        grants="Local Administrator on the target computer.",
        why=(
            "Full control of the host: dump LSASS/SAM, run code as SYSTEM, harvest "
            "any logged-on credentials. GPO-derived AdminTo is real; host-SAM AdminTo "
            "is synthetic until member-host images are collected (confidence-tagged)."
        ),
        action="is a local administrator on",
    ),
    "CanRDP": GlossaryEntry(
        grants="Interactive logon rights via RDP (Remote Desktop Users).",
        why="RDP into the host; harvest credentials of other sessions, pivot.",
        action="can RDP into",
    ),
    "CanPSRemote": GlossaryEntry(
        grants="Remote PowerShell / WinRM rights (Remote Management Users).",
        why="Remote code execution on the host via PSRemoting.",
        action="can run remote PowerShell on",
    ),
    "ExecuteDCOM": GlossaryEntry(
        grants="Remote activation via DCOM (Distributed COM Users).",
        why="Remote code execution on the host via DCOM.",
        action="can execute code via DCOM on",
    ),
    "SameForestTrust": GlossaryEntry(
        grants="A trust relationship within the same forest.",
        why=(
            "Intra-forest trusts are transitive and share the forest's Tier-0 "
            "(Enterprise Admins); a path across them reaches the other domain."
        ),
        action="trusts (same forest)",
    ),
    "CrossForestTrust": GlossaryEntry(
        grants="A trust to a domain in another forest.",
        why=(
            "Abusable with sIDHistory injection / unconstrained coercion / forged "
            "inter-realm tickets when SID filtering is absent or weak."
        ),
        action="trusts (cross forest)",
    ),
    "HasTrustKeys": GlossaryEntry(
        grants="Possession of the inter-realm trust key (trust account keys).",
        why=(
            "Forge inter-realm (trust) tickets to the trusted domain — a cross-domain "
            "golden-ticket primitive."
        ),
        action="holds the trust keys for",
    ),
    # --- §4.5 ADCS topology & enrollment edges (Tier C/D — synthetic-only in v1) ---
    "Enroll": GlossaryEntry(
        grants="Enrollment right on a certificate template.",
        why="Precondition for every ESC: request a cert from the template.",
        action="can enroll in",
    ),
    "AutoEnroll": GlossaryEntry(
        grants="Autoenrollment right on a template.",
        why="As Enroll, via autoenrollment.",
        action="can autoenroll in",
    ),
    "WritePKIEnrollmentFlag": GlossaryEntry(
        grants="Write `msPKI-Enrollment-Flag` on a template.",
        why="Disable manager approval / alter enrollment restrictions (ESC setup).",
        action="can change enrollment flags on",
    ),
    "WritePKINameFlag": GlossaryEntry(
        grants="Write `msPKI-Certificate-Name-Flag`.",
        why=("Enable ENROLLEE_SUPPLIES_SUBJECT -> attacker-chosen SAN (ESC1 " "precondition)."),
        action="can enable attacker-supplied subject on",
    ),
    "PublishedTo": GlossaryEntry(
        grants="A template is published to (enrollable at) an Enterprise CA.",
        why="Topology: where a template can be requested.",
        action="is published to",
    ),
    "EnterpriseCAFor": GlossaryEntry(
        grants="An Enterprise CA issues for the domain/forest.",
        why="Topology. Compromising the CA host = issue arbitrary certs.",
        action="is an enterprise CA for",
    ),
    "RootCAFor": GlossaryEntry(
        grants="A root CA cert is trusted for the domain.",
        why="Topology / trust chain.",
        action="is a root CA for",
    ),
    "NTAuthStoreFor": GlossaryEntry(
        grants="The NTAuth store gating auth-capable CAs.",
        why="Topology: only NTAuth CAs issue logon certs.",
        action="is the NTAuth store for",
    ),
    "HostsCAService": GlossaryEntry(
        grants="The computer hosting the CA service.",
        why="Host compromise = CA compromise.",
        action="hosts the CA service for",
    ),
    "TrustedForNTAuth": GlossaryEntry(
        grants="A CA whose certs are trusted for authentication.",
        why="Its certs can log on; key ESC target.",
        action="is trusted for NT auth by",
    ),
    "IssuedSignedBy": GlossaryEntry(
        grants="CA chaining (issuing CA signed by root).",
        why="Topology / trust chain.",
        action="is signed by",
    ),
    "ExtendedByPolicy": GlossaryEntry(
        grants="A template extended by an issuance policy (OID).",
        why="Links templates to issuance policies (ESC13 context).",
        action="is extended by policy",
    ),
    "OIDGroupLink": GlossaryEntry(
        grants="An issuance-policy OID linked to a group.",
        why=("Enrolling a cert carrying the OID grants the linked group's membership " "(ESC13)."),
        action="grants membership of (OID group link)",
    ),
    # --- §4.5b CA-host authorization / mis-config edges (ESC6a/ESC7, research 28) ---
    "ManageCA": GlossaryEntry(
        grants=(
            "The CA-administrator role on the Enterprise CA (the `ManageCA` access "
            "right in the CA's `Security` descriptor)."
        ),
        why=(
            "A CA administrator can alter the CA configuration — e.g. enable the "
            "dangerous `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (-> ESC6, every "
            "client-auth template becomes ESC1-equivalent) or add an officer — and "
            "so escalate to issuing arbitrary authentication certificates (ESC7). "
            "Read from the CA host registry, not ntds; needs the CA host SYSTEM hive."
        ),
        action="is a CA administrator of (can reconfigure the CA -> ESC7)",
    ),
    "ManageCertificates": GlossaryEntry(
        grants=(
            "The CA-officer (certificate-manager) role on the Enterprise CA (the "
            "`ManageCertificates` access right in the CA's `Security` descriptor)."
        ),
        why=(
            "A CA officer can approve a PENDING certificate request, bypassing manager "
            "approval. Combined with a template that would otherwise require approval "
            "this yields an attacker-chosen certificate (ESC7). Read from the CA host "
            "registry, not ntds; needs the CA host SYSTEM hive."
        ),
        action="is a CA officer of (can approve pending requests -> ESC7)",
    ),
    "ADCSESC6a": GlossaryEntry(
        grants=(
            "(Composite, principal -> Domain) enrollment in a client-auth template on "
            "an Enterprise CA whose `EDITF_ATTRIBUTESUBJECTALTNAME2` policy flag is set."
        ),
        why=(
            "With `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled CA-wide, ANY requester can "
            "specify an arbitrary Subject Alternative Name, so every enrollable "
            "client-auth template behaves like ESC1: request a certificate as a "
            "privileged user (e.g. a Domain Admin) and authenticate as them. The CA "
            "flag is read from the CA host registry; needs the CA host SYSTEM hive."
        ),
        action="can enroll a certificate as any user via the CA's SAN flag (ESC6)",
    ),
}


# =============================================================================
# §4.6 — node flags, UAC flags, and attribute signals. ``action`` is the
# verbatim one-phrase caption/tooltip for the badge.
# =============================================================================
FLAG_GLOSSARY: dict[str, GlossaryEntry] = {
    # node flags (wraith/edges/node_flags.py)
    "kerberoastable": GlossaryEntry(
        grants="Enabled User (not krbtgt) advertising an SPN.",
        why="Request its service ticket and crack the service account password offline.",
        action=(
            "a service account whose Kerberos ticket can be requested and cracked "
            "offline (Kerberoastable)"
        ),
    ),
    "asrep_roastable": GlossaryEntry(
        grants="`DONT_REQ_PREAUTH` set — no Kerberos pre-auth.",
        why="Request an AS-REP for it with no authentication and crack it offline.",
        action=(
            "requires no Kerberos pre-auth — its AS-REP can be cracked offline "
            "(AS-REP roastable)"
        ),
    ),
    "unconstrained_delegation": GlossaryEntry(
        grants="`TRUSTED_FOR_DELEGATION` set.",
        why=(
            "Captures the TGT of anyone who authenticates to it; a coerced DC's TGT = "
            "domain compromise."
        ),
        action=(
            "trusted for unconstrained delegation — can capture the TGT of anyone who "
            "authenticates to it"
        ),
    ),
    # UAC flags (UacFlagsOut)
    "account_disabled": GlossaryEntry(
        grants="Account is disabled.",
        why=(
            "Cannot authenticate now, but if still privileged it is stale standing "
            "privilege / re-enable risk."
        ),
        action="account is disabled",
    ),
    "password_not_required": GlossaryEntry(
        grants="Password may be empty/not required.",
        why="Authenticate with no or trivial credential — policy bypass.",
        action="password is not required — may be empty",
    ),
    "dont_expire_password": GlossaryEntry(
        grants="Password never expires.",
        why="Long-lived, stale credential; wider cracking/reuse window.",
        action="password never expires (stale, long-lived credential)",
    ),
    "dont_require_preauth": GlossaryEntry(
        grants="= AS-REP roastable.",
        why="See asrep_roastable.",
        action="(see AS-REP roastable)",
    ),
    "trusted_for_delegation": GlossaryEntry(
        grants="= unconstrained delegation.",
        why="See unconstrained_delegation.",
        action="(see unconstrained delegation)",
    ),
    "trusted_to_auth_for_delegation": GlossaryEntry(
        grants="Protocol transition (S4U2Self any protocol).",
        why=(
            "Upgrades constrained delegation to 'any protocol' — abusable without the "
            "victim ever authenticating."
        ),
        action=(
            "can use protocol transition — constrained delegation abusable without the "
            "victim authenticating"
        ),
    ),
    "not_delegated": GlossaryEntry(
        grants="'Account is sensitive and cannot be delegated.'",
        why=(
            "DEFENSIVE / hardening. Its PRESENCE is good; its ABSENCE on a privileged "
            "account is the finding. Framed so it is never a false-positive 'risk'."
        ),
        action=("protected from delegation (sensitive; cannot be delegated) — a hardening " "flag"),
    ),
    "server_trust_account": GlossaryEntry(
        grants="The computer is a Domain Controller.",
        why="DC = Tier-0 by definition.",
        action="this is a Domain Controller (Tier-0)",
    ),
    "workstation_trust_account": GlossaryEntry(
        grants="Ordinary domain-joined computer.",
        why="Baseline computer identity (not itself a finding).",
        action="domain-joined computer account",
    ),
    "partial_secrets_account": GlossaryEntry(
        grants="Read-Only Domain Controller (RODC).",
        why="Holds a filtered secret set; RODC-specific compromise nuances.",
        action="this is a Read-Only Domain Controller (RODC)",
    ),
    "reversible_password": GlossaryEntry(
        grants="Password stored with reversible encryption.",
        why="Recoverable to plaintext directly from the directory — severe exposure.",
        action="password is stored reversibly — recoverable to plaintext",
    ),
    # other attribute signals surfaced as flags
    "admincount": GlossaryEntry(
        grants="AdminSDHolder-protected (is or was privileged).",
        why=(
            "If no longer in a protected group, it is residue — forgotten/hidden past "
            "privilege (orphan)."
        ),
        action="AdminSDHolder-protected — is or was a privileged principal",
    ),
    "sid_history": GlossaryEntry(
        grants="Carries other SIDs.",
        why="Privilege smuggling / persistence (see HasSIDHistory).",
        action="carries sIDHistory — wields another principal's SID and privileges",
    ),
    "spns": GlossaryEntry(
        grants="Advertises service principal names.",
        why="Service account surface; with enabled User -> Kerberoastable.",
        action="advertises service principal name(s)",
    ),
}


#: Every edge kind WRAITH's engine can emit (public fact strings gathered from the
#: edge builders). The glossary MUST cover all of these; any that is missing is a
#: counted gap (so a future kind degrades to a neutral caption, never a guessed
#: abuse). Kept here as the authoritative coverage oracle for the gate.
ENGINE_EDGE_KINDS: frozenset[str] = frozenset(
    {
        # ACL / control (wraith/edges/guid_map.py + acl.py)
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights",
        "Owns",
        "AddMember",
        "AddSelf",
        "WriteSPN",
        "AddKeyCredentialLink",
        "WriteAccountRestrictions",
        "WriteAltSecurityIdentities",
        "AddAllowedToAct",
        "WriteGPLink",
        "WritePublicInformation",
        "ForceChangePassword",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
        "ReadLAPSPassword",
        "DCSync",
        # derivations (wraith/edges/derivations.py)
        "AllowedToDelegate",
        "AllowedToAct",
        "ReadGMSAPassword",
        "HasSIDHistory",
        "SameForestTrust",
        "CrossForestTrust",
        "HasTrustKeys",
        "Contains",
        "GPLink",
        "CoerceToTGT",
        # membership
        "MemberOf",
        # GPO / host-SAM lateral movement
        "AdminTo",
        "CanRDP",
        "CanPSRemote",
        "ExecuteDCOM",
        # ADCS topology + enrollment (Tier C/D, synthetic-only)
        "EnterpriseCAFor",
        "RootCAFor",
        "NTAuthStoreFor",
        "HostsCAService",
        "TrustedForNTAuth",
        "IssuedSignedBy",
        "ExtendedByPolicy",
        "OIDGroupLink",
        "Enroll",
        "AutoEnroll",
        "WritePKIEnrollmentFlag",
        "WritePKINameFlag",
        "PublishedTo",
        # CA-host authorization / mis-config edges (ESC6a/ESC7; emitted by the
        # ADCS-ESC pass when a CA host hive is provided — research 28).
        "ManageCA",
        "ManageCertificates",
        "ADCSESC6a",
    }
)

#: The neutral caption a caller renders for an edge kind not in the glossary (a
#: future/unmapped kind) — honest "control relationship" wording, never a guessed
#: abuse (doc 21 §5.6). Callers that fall back to this MUST count a glossary gap.
NEUTRAL_EDGE_ENTRY: GlossaryEntry = GlossaryEntry(
    grants="A relationship WRAITH records but does not yet have a glossary entry for.",
    why="Surfaced verbatim; its abuse is not asserted (unmapped edge kind).",
    action="has a control relationship with",
)

#: ``object_type_guid`` -> readable attribute/right name (doc 21 §5.1 ``[via ...]``).
#: Reuses the public MS ``adschema`` GUID constants from the gated
#: :mod:`wraith.edges.guid_map` so the dossier and the edge engine agree on one set.
ATTRIBUTE_NAME_BY_GUID: dict[str, str] = {
    GUID_MEMBER: "member",
    GUID_SERVICE_PRINCIPAL_NAME: "servicePrincipalName",
    GUID_KEY_CREDENTIAL_LINK: "msDS-KeyCredentialLink",
    GUID_USER_ACCOUNT_RESTRICTIONS: "User-Account-Restrictions",
    GUID_ALT_SECURITY_IDENTITIES: "altSecurityIdentities",
    GUID_ALLOWED_TO_ACT: "msDS-AllowedToActOnBehalfOfOtherIdentity",
    GUID_GPLINK: "gPLink",
    GUID_PUBLIC_INFORMATION: "Public-Information",
    GUID_FORCE_CHANGE_PASSWORD: "User-Force-Change-Password",
    GUID_GET_CHANGES: "DS-Replication-Get-Changes",
    GUID_GET_CHANGES_ALL: "DS-Replication-Get-Changes-All",
    GUID_GET_CHANGES_IN_FILTERED_SET: "DS-Replication-Get-Changes-In-Filtered-Set",
}


def lookup_edge(kind: str) -> GlossaryEntry | None:
    """Return the authored glossary entry for an edge ``kind``, or ``None``.

    Inputs:
        kind: a WRAITH edge-kind string.

    Returns:
        The :class:`GlossaryEntry`, or ``None`` when the kind has no entry (the
        caller degrades to :data:`NEUTRAL_EDGE_ENTRY` and counts a glossary gap).

    Failure modes:
        Never raises.
    """
    return EDGE_GLOSSARY.get(kind)


def attribute_name_for_guid(object_type_guid: str | None) -> str | None:
    """Return the readable attribute/right name for a scoped ``object_type_guid``.

    Inputs:
        object_type_guid: the ACE ObjectType GUID (any case), or ``None`` for a
            whole-object edge.

    Returns:
        The attribute name (e.g. ``"member"``), or ``None`` when the GUID is absent
        or unmapped (a whole-object edge or an unknown scoped GUID — rendered
        without a ``[via ...]`` clause).

    Failure modes:
        Never raises.
    """
    if not object_type_guid:
        return None
    return ATTRIBUTE_NAME_BY_GUID.get(object_type_guid.lower())


def _entry_out(entry: GlossaryEntry) -> GlossaryEntryOut:
    """Convert an authored entry into its API model."""
    return GlossaryEntryOut(grants=entry.grants, why=entry.why, action=entry.action)


def build_glossary() -> GlossaryOut:
    """Build the full :class:`~wraith.api.models.GlossaryOut` served by the endpoint.

    Returns:
        A :class:`GlossaryOut` with the edge and flag entries (deterministically
        key-sorted) and ``counted_gaps`` reporting any engine edge kind that lacks a
        glossary entry under ``glossary_missing_edge_kind`` (normally absent).

    Failure modes:
        Never raises; the glossary is a static constant.
    """
    missing = sorted(k for k in ENGINE_EDGE_KINDS if k not in EDGE_GLOSSARY)
    gaps: dict[str, int] = {}
    if missing:
        gaps["glossary_missing_edge_kind"] = len(missing)
    return GlossaryOut(
        edges={k: _entry_out(EDGE_GLOSSARY[k]) for k in sorted(EDGE_GLOSSARY)},
        flags={k: _entry_out(FLAG_GLOSSARY[k]) for k in sorted(FLAG_GLOSSARY)},
        counted_gaps=gaps,
    )
