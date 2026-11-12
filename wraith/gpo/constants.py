"""Public [MS-*] facts the GPO module keys off (reusable constants, not code).

Well-known SIDs, the local-group alias -> BloodHound edge map, the high-value
privilege set, the registry-policy signal catalog, and the published [MS-GPPREF]
static AES key are all public specification facts (reusable per CLAUDE.md). None
are copied from foreign source code.
"""

from __future__ import annotations

# =============================================================================
# §4 edge kinds / derivations + confidence for GPO-derived facts
# =============================================================================

#: Every GPO-derived edge is INFERRED (schema §4: "GPO-pushed subset is
#: inferred"): full RSoP / WMI-filter / security-filter resolution is impossible
#: offline, so WRAITH emits the SharpHound-parity union of non-disabled links.
CONFIDENCE_INFERRED: str = "inferred"

#: BloodHound-native local-group edge kinds (direction: principal -> computer).
KIND_ADMIN_TO: str = "AdminTo"
KIND_CAN_RDP: str = "CanRDP"
KIND_EXECUTE_DCOM: str = "ExecuteDCOM"
KIND_CAN_PSREMOTE: str = "CanPSRemote"

#: Documented kind-prefix marking a WRAITH-native (NOT BloodHound-native) edge,
#: so the future M6 SharpHound export can filter these out and never claim BH
#: parity for them. The privilege-rights edges below all carry this prefix.
WRAITH_NATIVE_KIND_PREFIX: str = "WRAITH:"

#: Local-group well-known alias SID -> the BloodHound edge it pushes. This is the
#: open "alias-SID -> edge-kind" generalization hook; Tier B's in-scope target is
#: Administrators (544) -> AdminTo, the other three are the same mechanism.
#: Mapping is the BloodHound canon (DCOM=562, PSRemote=580).
LOCAL_GROUP_SID_TO_KIND: dict[str, str] = {
    "S-1-5-32-544": KIND_ADMIN_TO,  # Administrators
    "S-1-5-32-555": KIND_CAN_RDP,  # Remote Desktop Users
    "S-1-5-32-562": KIND_EXECUTE_DCOM,  # Distributed COM Users
    "S-1-5-32-580": KIND_CAN_PSREMOTE,  # Remote Management Users
}

#: Local-group well-known alias RID -> edge kind (for name tokens like the bare
#: ``Administrators`` string, resolved via its RID when a SID is not supplied).
LOCAL_GROUP_RID_TO_KIND: dict[int, str] = {
    544: KIND_ADMIN_TO,
    555: KIND_CAN_RDP,
    562: KIND_EXECUTE_DCOM,
    580: KIND_CAN_PSREMOTE,
}


# =============================================================================
# High-value privileges ([Privilege Rights]) — WRAITH-native enrichment
# =============================================================================

#: The dangerous user-rights WRAITH surfaces as node facts AND emits as tagged
#: WRAITH-native edges (BloodHound CE mainline has NO native privilege edge).
#: Each maps to a one-line abuse class for the finding/doc. Priority set per
#: research 10 §3.
HIGH_VALUE_PRIVILEGES: dict[str, str] = {
    "SeEnableDelegationPrivilege": (
        "Configure Kerberos delegation on accounts -> Tier-0 delegation attacks."
    ),
    "SeBackupPrivilege": (
        "Read any file ignoring DACL -> on a DC, read ntds.dit+SYSTEM = domain compromise."
    ),
    "SeRestorePrivilege": "Write any file / load hives -> overwrite binaries, registry implant.",
    "SeDebugPrivilege": "Open any process -> LSASS dump / token theft / code injection.",
    "SeTakeOwnershipPrivilege": "Take ownership of any securable -> then WriteDacl = full control.",
    "SeLoadDriverPrivilege": "Load a (vulnerable) kernel driver -> kernel code exec (BYOVD).",
    "SeImpersonatePrivilege": "Token impersonation -> Potato-family local SYSTEM.",
    "SeAssignPrimaryTokenPrivilege": "Assign primary token -> Potato-family local SYSTEM.",
}


# =============================================================================
# Admin-baseline SID predicate (delta-from-baseline suppression for privileges)
# =============================================================================

#: Well-known SIDs that ARE the default DC admin/system baseline. A high-value
#: privilege held by one of these is NOT a privilege-escalation delta (the
#: holder is already admin-equivalent/system), so no WRAITH-native privilege
#: edge or finding is emitted for it — matching the true-negative expected on a
#: real DC. Restricted-groups/GPP AdminTo edges are NOT suppressed (membership
#: push is the attack fact regardless of who is pushed, SharpHound parity).
_BASELINE_WELLKNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-19",  # LocalService
        "S-1-5-20",  # NetworkService
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    }
)

#: Domain RID suffixes (on an ``S-1-5-21-<domain>-<RID>`` SID) that ARE the
#: default privileged baseline: Administrator, the admin groups, and DCs.
_BASELINE_DOMAIN_RIDS: frozenset[int] = frozenset(
    {
        500,  # Administrator
        512,  # Domain Admins
        516,  # Domain Controllers
        517,  # Cert Publishers (CA hosts)
        518,  # Schema Admins
        519,  # Enterprise Admins
        520,  # Group Policy Creator Owners
        521,  # Read-only Domain Controllers
    }
)

#: NT SERVICE SID prefix (``S-1-5-80-...``) — managed-service identities are part
#: of the DC baseline, never an attacker-relevant privilege delta.
_NT_SERVICE_PREFIX: str = "S-1-5-80-"


def is_baseline_privileged_sid(sid: str) -> bool:
    """Return whether ``sid`` is a default admin/system baseline principal.

    Used to suppress the WRAITH-native privilege edge/finding for holders that
    are already admin-equivalent (so a real DC yields the expected true
    negative). Matches well-known SIDs exactly, ``S-1-5-80-*`` by prefix, and
    ``S-1-5-21-<domain>-<RID>`` by the privileged RID suffix.

    Inputs:
        sid: a canonical SID string (``*`` already stripped).

    Returns:
        ``True`` if the SID is part of the privileged baseline.

    Failure modes:
        Never raises (a malformed token returns ``False``).
    """
    if sid in _BASELINE_WELLKNOWN_SIDS:
        return True
    if sid.startswith(_NT_SERVICE_PREFIX):
        return True
    if sid.startswith("S-1-5-21-"):
        tail = sid.rsplit("-", 1)[-1]
        if tail.isdigit() and int(tail) in _BASELINE_DOMAIN_RIDS:
            return True
    return False


# =============================================================================
# Registry.pol / GptTmpl [Registry Values] signal catalog
# =============================================================================

#: Attack-relevant policy value names -> (signal label, interpretation). Keyed
#: by the value NAME (case-insensitive); the key path varies by GPO but the
#: value name is stable. These surface as node facts/findings, not graph edges
#: (posture signals, not traversable capability) — the conservative BH stance.
REGISTRY_SIGNAL_CATALOG: dict[str, tuple[str, str]] = {
    "localaccounttokenfilterpolicy": (
        "LocalAccountTokenFilterPolicy",
        "=1 disables remote-UAC filtering -> local admins usable over the network.",
    ),
    "filteradministratortoken": (
        "FilterAdministratorToken",
        "Companion UAC remote-elevation setting.",
    ),
    "runasppl": ("RunAsPPL", "LSA protection (PPL) on/off -> affects LSASS-dump feasibility."),
    "uselogoncredential": (
        "WDigestUseLogonCredential",
        "=1 re-enables cleartext credentials in LSASS (WDigest).",
    ),
    "disablerestrictedadmin": (
        "DisableRestrictedAdmin",
        "RDP Restricted-Admin mode toggle (Pass-the-Hash over RDP).",
    ),
    "disablerestrictedadminoutboundcreds": (
        "DisableRestrictedAdminOutboundCreds",
        "RDP Restricted-Admin outbound-credential toggle.",
    ),
    "fdenytsconnections": (
        "fDenyTSConnections",
        "=0 RDP ENABLED on affected computers (reachability/scope signal).",
    ),
    "nolmhash": ("NoLMHash", "LM-hash storage policy (=1 disables weak LM hashes)."),
    "requiresecuritysignature": (
        "SmbRequireSecuritySignature",
        "SMB signing required (hardening posture).",
    ),
    "admpwdenable": ("LapsEnabled", "LAPS (AdmPwd) enabled -> context for ReadLAPSPassword."),
    "adminaccountname": ("LapsAdminAccountName", "LAPS-managed local admin account name."),
}


# =============================================================================
# GPP cpassword — public [MS-GPPREF] 2.2.1.1 static AES-256 key
# =============================================================================

#: The 32-byte AES-256 key Microsoft PUBLISHED in [MS-GPPREF] 2.2.1.1, making
#: every GPP ``cpassword`` trivially reversible. This is a public specification
#: fact (reusable); using it to read a lawfully-held artifact is in-charter
#: (reading an acquired file, not live credential cracking).
GPP_STATIC_AES_KEY: bytes = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)
