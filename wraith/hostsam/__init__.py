"""WRAITH Tier-C host-SAM local-group module (offline local-group edges).

Derives all four BloodHound-faithful local-group edges (``member principal ->
host Computer``) from a member host's ``SAM`` hive, entirely offline/dead-disk —
the same membership a live SharpHound ``SamrGetMembersInAlias`` (SAMR) call would
return, read from the on-disk built-in alias ``C`` arrays that SAMR exposes. The
four built-in aliases and their edge kinds (research 27 §2.1, SID-anchored):

* Administrators (``0x220`` / ``S-1-5-32-544``) -> ``AdminTo`` (``SAM:AdminTo``)
* Remote Desktop Users (``0x22B`` / ``S-1-5-32-555``) -> ``CanRDP``
* Distributed COM Users (``0x232`` / ``S-1-5-32-562``) -> ``ExecuteDCOM``
* Remote Management Users (``0x244`` / ``S-1-5-32-580``) -> ``CanPSRemote``

No network, no boot key (alias membership is plaintext). References:
``docs/research/09-host-sam-adminto-reference.md`` and
``docs/research/27-host-sam-rdp-dcom-psremote-aliases.md``.

Public surface:

* :func:`~wraith.hostsam.cblob.parse_c_blob` / :func:`~wraith.hostsam.cblob.parse_binary_sid`
  — the pure, bounds-checked alias ``C``-blob + binary-SID parser.
* :func:`~wraith.hostsam.reader.read_host_sam` / :func:`~wraith.hostsam.reader.read_computer_name`
  — the Impacket-``winregistry`` I/O seam (NOT regipy; no new dependency).
* :func:`~wraith.hostsam.admin_edges.compute_host_admin_edges` — the orchestrator
  that emits the ``AdminTo`` edges; :func:`~wraith.hostsam.admin_edges.build_admin_to_edges`
  — the pure edge builder; :func:`~wraith.hostsam.admin_edges.account_host_coverage`
  — the ``hosts_imaged / total_computers`` coverage accounting.
"""

from __future__ import annotations

from wraith.hostsam.admin_edges import (
    ALIAS_GAP_TOKENS,
    CONFIDENCE_CONFIRMED,
    DERIVATION_SAM_ADMIN_TO,
    DERIVATION_SAM_CAN_PSREMOTE,
    DERIVATION_SAM_CAN_RDP,
    DERIVATION_SAM_EXECUTE_DCOM,
    GAP_CBLOB_PARSE_ERROR,
    GAP_HOST_NOT_IMAGED,
    GAP_HOST_UNRESOLVED,
    GAP_MACHINE_SID_UNRESOLVED,
    GAP_MEMBER_SID_UNRESOLVED,
    GAP_MEMBER_UNCLASSIFIABLE,
    GAP_SAM_ALIAS_ABSENT,
    GAP_SAM_HIVE_UNREADABLE,
    KIND_ADMIN_TO,
    KIND_CAN_PSREMOTE,
    KIND_CAN_RDP,
    KIND_EXECUTE_DCOM,
    AdminEdgeBuild,
    AliasEdgeResult,
    AliasGapTokens,
    ComputerIndex,
    HostSamResult,
    MemberClass,
    account_host_coverage,
    build_admin_to_edges,
    build_computer_index,
    build_local_group_edges,
    classify_member,
    compute_host_admin_edges,
)
from wraith.hostsam.cblob import (
    DOMAIN_ALIAS_RID_ADMINS,
    DOMAIN_ALIAS_RID_DCOM_USERS,
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS,
    DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS,
    CBlobParse,
    parse_binary_sid,
    parse_c_blob,
)
from wraith.hostsam.reader import AliasRead, HostSamRead, read_computer_name, read_host_sam

__all__ = [
    "ALIAS_GAP_TOKENS",
    "CONFIDENCE_CONFIRMED",
    "DERIVATION_SAM_ADMIN_TO",
    "DERIVATION_SAM_CAN_PSREMOTE",
    "DERIVATION_SAM_CAN_RDP",
    "DERIVATION_SAM_EXECUTE_DCOM",
    "DOMAIN_ALIAS_RID_ADMINS",
    "DOMAIN_ALIAS_RID_DCOM_USERS",
    "DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS",
    "DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS",
    "GAP_CBLOB_PARSE_ERROR",
    "GAP_HOST_NOT_IMAGED",
    "GAP_HOST_UNRESOLVED",
    "GAP_MACHINE_SID_UNRESOLVED",
    "GAP_MEMBER_SID_UNRESOLVED",
    "GAP_MEMBER_UNCLASSIFIABLE",
    "GAP_SAM_ALIAS_ABSENT",
    "GAP_SAM_HIVE_UNREADABLE",
    "KIND_ADMIN_TO",
    "KIND_CAN_PSREMOTE",
    "KIND_CAN_RDP",
    "KIND_EXECUTE_DCOM",
    "AdminEdgeBuild",
    "AliasEdgeResult",
    "AliasGapTokens",
    "AliasRead",
    "CBlobParse",
    "ComputerIndex",
    "HostSamRead",
    "HostSamResult",
    "MemberClass",
    "account_host_coverage",
    "build_admin_to_edges",
    "build_computer_index",
    "build_local_group_edges",
    "classify_member",
    "compute_host_admin_edges",
    "parse_binary_sid",
    "parse_c_blob",
    "read_computer_name",
    "read_host_sam",
]
