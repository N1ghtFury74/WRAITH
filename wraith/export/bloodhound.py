"""BloodHound CE ingest-JSON export adapter (M6).

Reads the complete canonical graph (nodes + frozen-schema §4 edges) from the
case DuckDB store and emits BloodHound Community Edition ingest JSON: one file
per object type (``users``/``groups``/``computers``/``domains``/``ous``/``gpos``/
``containers`` + the six ADCS types), each wrapped as
``{"data":[...],"meta":{"methods":<bitmask>,"type":"<type>","count":<n>,"version":<V>}}``.

Design (decisions locked in ``docs/research/12-m6-bloodhound-export-decisions.md``):

* **``node_id`` -> ``ObjectIdentifier``** — uppercased ``objectSID`` for
  SID-keyed principals/domains; brace-wrapped uppercased ``objectGUID`` for
  GPO/OU/Container/ADCS. A ``node_id`` -> natural-key projection is built once
  and every edge endpoint resolved through it (deterministic — both schemes
  derive from the same natural keys).
* **Two edge encodings.** BloodHound AD ingest has NO explicit edge-record
  format; it carries (1) ACL edges as an ``Aces[]`` list on the *target* node
  (``{PrincipalSID, PrincipalType, RightName, IsInherited}``) and (2) structural
  / derived edges as typed ``{ObjectIdentifier, ObjectType}`` arrays on the
  owning node (``Members``, ``ChildObjects``, ``Links``, ``AllowedToDelegate``,
  ``AllowedToAct``, ``HasSIDHistory``, the local-group lanes). Everything else
  BHCE derives post-ingest from the exported base facts.
* **No silent drops (standing rule).** Every WRAITH edge kind routes to exactly
  one disposition; a kind that is *not* exported to a BH kind is explicitly
  counted/annotated (``dropped_native`` / ``dropped_composed`` /
  ``dropped_trust_postprocess`` / ``adcs_pending_spike`` / ``unmapped``) so the
  :class:`ExportResult` is a provable accounting ledger.
* **``meta.version`` is a configurable constant defaulting to 6** (current BHCE
  ``main``). It MUST be pinned to whatever the bundled BloodHound CE image
  accepts: a wrong version = silent zip rejection (doc 12 open risk #1).
* **Determinism.** Nodes emit sorted by ``ObjectIdentifier``; arrays/ACEs are
  sorted; JSON uses the canonical serializer. Identical store -> identical bytes.

This adapter is read-only over the store and performs no network I/O.
"""

from __future__ import annotations

import logging
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import duckdb

from wraith.common.determinism import canonical_json

_log = logging.getLogger(__name__)

# --- version + collection-method pin -----------------------------------------
#: Default ``meta.version`` — the integer the current SpecterOps BHCE ``main``
#: ingest schema uses. **PIN THIS** to the version the bundled BloodHound CE
#: image accepts (``models.go`` ``DataType``/version of that image). A wrong
#: value makes BHCE SILENTLY REJECT the uploaded zip (doc 12 open risk #1).
DEFAULT_INGEST_VERSION: int = 6

# SharpHound ``CollectionMethod`` flags (public enum values) composed into a
# DCOnly-consistent bitmask so BHCE does not read missing session/local data as
# "collected = empty". These are documentation-grade; ``meta.methods`` affects
# BHCE post-processing, not the edges themselves, and is overridable via config.
_CM_GROUP = 1
_CM_ACL = 32
_CM_TRUSTS = 64
_CM_CONTAINER = 128
_CM_OBJECTPROPS = 256
_CM_GPOLOCALGROUP = 2048
#: DCOnly-consistent default for ``meta.methods``.
DCONLY_METHODS: int = (
    _CM_GROUP | _CM_ACL | _CM_TRUSTS | _CM_CONTAINER | _CM_OBJECTPROPS | _CM_GPOLOCALGROUP
)

# --- BloodHound object-type vocabulary ---------------------------------------
#: The BH ``ObjectType`` for synthetic / non-BH-modeled nodes (overflow ``Base``
#: file). Defined here so :data:`_OBJECT_TYPE` can reuse it as the single source of
#: truth for the ``Base`` ObjectType string.
_BASE_OBJECT_TYPE: str = "Base"

#: ``(source_table, discriminator)`` -> BHCE ``meta.type`` (the per-type file).
_META_TYPE: Mapping[tuple[str, str | None], str] = {
    ("principal", "User"): "users",
    ("principal", "Computer"): "computers",
    ("principal", "Group"): "groups",
    ("container", "Domain"): "domains",
    ("container", "OU"): "ous",
    ("container", "Container"): "containers",
    ("gpo", None): "gpos",
    ("adcs", "EnterpriseCA"): "enterprisecas",
    ("adcs", "RootCA"): "rootcas",
    ("adcs", "AIACA"): "aiacas",
    ("adcs", "NTAuthStore"): "ntauthstores",
    ("adcs", "CertTemplate"): "certtemplates",
    ("adcs", "IssuancePolicy"): "issuancepolicies",
}

#: ``(source_table, discriminator)`` -> BHCE ``ObjectType`` (edge-endpoint kind).
_OBJECT_TYPE: Mapping[tuple[str, str | None], str] = {
    ("principal", "User"): "User",
    ("principal", "Computer"): "Computer",
    ("principal", "Group"): "Group",
    # M-MS3 cross-domain stub (``wraith.edges.cross_domain.FOREIGN_PRINCIPAL_TYPE``):
    # a foreign principal whose owning domain was NOT ingested. It has no
    # BH-modeled principal type, so it maps to the ``Base`` ObjectType and (being
    # absent from ``_META_TYPE``) is emitted into the ``Base`` overflow file — an
    # EXPLICIT, intentional mapping (not an ``_OBJECT_TYPE`` dict-default) so every
    # edge that points at the stub (e.g. a cross-domain ``HasSIDHistory`` target)
    # has a resolvable node-table home instead of a dangling endpoint.
    ("principal", "Foreign"): _BASE_OBJECT_TYPE,
    ("container", "Domain"): "Domain",
    ("container", "OU"): "OU",
    ("container", "Container"): "Container",
    ("gpo", None): "GPO",
    ("adcs", "EnterpriseCA"): "EnterpriseCA",
    ("adcs", "RootCA"): "RootCA",
    ("adcs", "AIACA"): "AIACA",
    ("adcs", "NTAuthStore"): "NTAuthStore",
    ("adcs", "CertTemplate"): "CertTemplate",
    ("adcs", "IssuancePolicy"): "IssuancePolicy",
}

#: The ordered per-type ``meta.type`` list — the complete file set (determinism).
FILE_TYPES: tuple[str, ...] = (
    "users",
    "groups",
    "computers",
    "domains",
    "ous",
    "gpos",
    "containers",
    "enterprisecas",
    "rootcas",
    "aiacas",
    "ntauthstores",
    "certtemplates",
    "issuancepolicies",
)

#: BH ObjectTypes keyed by objectSID (uppercased SID); all others key by
#: ``{objectGUID}`` (brace-wrapped, uppercased).
_SID_KEYED_TYPES: frozenset[str] = frozenset({"User", "Computer", "Group", "Domain"})

#: ``meta.type`` for the overflow file holding BH ``Base`` nodes — the synthetic
#: / non-BH-modeled nodes referenced by some array/ACE endpoint (doc 12 §B.3).
#: It is NOT part of :data:`FILE_TYPES`: the file is emitted ONLY when at least
#: one such node exists, so a normal DC keeps the standard 13-file set and the
#: synthetic path has no dangling ``ObjectIdentifier`` references.
BASE_META_TYPE: str = "base"

# --- edge-kind routing (every known WRAITH kind -> one disposition) ----------
# ACL edges -> an ``Aces[]`` entry on the target node (RightName == BH kind).
_ACE_KINDS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        "ForceChangePassword",
        "AddMember",
        "AddSelf",
        "AddKeyCredentialLink",
        "WriteSPN",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
        "ReadLAPSPassword",
        "ReadGMSAPassword",
        "Enroll",
        "AutoEnroll",
        "WriteAccountRestrictions",
        "WriteGPLink",
        "AddAllowedToAct",
        "WritePKIEnrollmentFlag",
        "WritePKINameFlag",
    }
)

#: Structural / derived edge kind -> the typed node array it populates. Value is
#: ``(array_field, owner)`` where owner ``"source"`` puts the entry on the edge
#: source node (the entry references the target) and ``"target"`` the reverse.
_ARRAY_KINDS: Mapping[str, tuple[str, str]] = {
    "MemberOf": ("Members", "target"),  # on the group; element = the member
    "Contains": ("ChildObjects", "source"),  # on the container; element = child
    "AllowedToDelegate": ("AllowedToDelegate", "source"),
    "AllowedToAct": ("AllowedToAct", "target"),  # on the resource computer
    "HasSIDHistory": ("HasSIDHistory", "source"),
}

#: GPLink is a structural array (``Links``) but needs the IsEnforced+GUID shape,
#: so it is routed separately from :data:`_ARRAY_KINDS`.
_GPLINK_KIND: str = "GPLink"

#: Local-group lane kind -> the computer-node field (non-session local data).
_LOCALGROUP_KINDS: Mapping[str, str] = {
    "AdminTo": "LocalAdmins",
    "CanRDP": "RemoteDesktopUsers",
    "ExecuteDCOM": "DcomUsers",
    "CanPSRemote": "PSRemoteUsers",
}

#: Trust-family kinds carried by the domain ``Trusts[]`` array + BHCE
#: post-processing (dropped as explicit edges, counted, never silent).
_TRUST_POSTPROCESS_KINDS: frozenset[str] = frozenset(
    {"SameForestTrust", "CrossForestTrust", "HasTrustKeys"}
)

#: Kinds BHCE composes itself post-ingest from the exported base ACEs/properties
#: (dropped as explicit edges, counted). ``DCSync`` additionally re-adds the
#: ``AllExtendedRights`` ACE on the domain for each holder (see B.2).
_COMPOSED_KINDS: frozenset[str] = frozenset(
    {
        "DCSync",
        "CoerceToTGT",
        "ADCSESC1",
        "ADCSESC3",
        "ADCSESC9",
        "ADCSESC10a",
        "ADCSESC10b",
        "ADCSESC13",
        "ADCSESC15",
        "EnrollOnBehalfOf",
        "GoldenCert",
    }
)

#: M-MS3 cross-domain FSP alias edge (``wraith.edges.cross_domain.KIND_FOREIGN_IDENTITY``:
#: the REAL foreign principal -> its local ``ForeignSecurityPrincipal`` stub). WRAITH
#: keys the FSP stub and the real foreign principal by DISTINCT ``objectGUID``s but the
#: SAME ``objectSID`` (the FSP RDN *is* the foreign SID); on BHCE export both project to
#: the same uppercased-SID ``ObjectIdentifier`` and COLLAPSE to one node, so a literal
#: ``ForeignIdentity`` edge would be a same-SID self-loop. It is therefore dropped
#: (counted) as ``composed_by_bhce``: BHCE reconstructs the capability from the
#: ``MemberOf``/ACL edges keyed by that shared SID. Never emitted, never silent.
_FOREIGN_IDENTITY_KIND: str = "ForeignIdentity"

#: Phase-1 ADCS topology edge kinds — the ADCS export lane is best-effort pending
#: the field-by-field ``expected_ingest_adcs.go`` spike (doc 12 open risk #2).
#: The ADCS *nodes* are emitted; these topology *edges* are counted as pending
#: so nothing is silently dropped.
_ADCS_TOPOLOGY_KINDS: frozenset[str] = frozenset(
    {
        "EnterpriseCAFor",
        "RootCAFor",
        "NTAuthStoreFor",
        "HostsCAService",
        "TrustedForNTAuth",
        "IssuedSignedBy",
        "ExtendedByPolicy",
        "OIDGroupLink",
        "PublishedTo",
    }
)

#: WRAITH-native kinds with no BloodHound equivalent (dropped, counted).
_NATIVE_KINDS: frozenset[str] = frozenset(
    {"WritePublicInformation", "WriteAltSecurityIdentities", "WriteDnsHostName"}
)

#: WRAITH composite needing conditional composition into BH ``ADCSESC4``.
_ESC4_KIND: str = "WraithESC4TemplateControl"

#: Prefix marking WRAITH-native GPO privilege edges (``WRAITH:<Priv>``) — these
#: exist specifically to prevent a false BloodHound-parity claim.
_WRAITH_NATIVE_PREFIX: str = "WRAITH:"

# --- userAccountControl flags (public [MS-ADTS] facts) for BH tag properties --
_UAC_ACCOUNTDISABLE = 0x0002
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


@dataclass(frozen=True)
class ExportConfig:
    """Tunables for one BloodHound export.

    Attributes:
        ingest_version: the ``meta.version`` integer. MUST match the bundled BHCE
            image (:data:`DEFAULT_INGEST_VERSION`); a wrong value = silent zip
            rejection.
        methods: the ``meta.methods`` collection-method bitmask
            (:data:`DCONLY_METHODS`).
        zip_name: filename of the produced ingest zip inside the output dir.
    """

    ingest_version: int = DEFAULT_INGEST_VERSION
    methods: int = DCONLY_METHODS
    zip_name: str = "bloodhound.zip"


@dataclass(frozen=True)
class NodeKey:
    """The BH identity + display facts projected from a WRAITH node.

    Attributes:
        node_id: the WRAITH surrogate key.
        object_identifier: the BH ``ObjectIdentifier`` (uppercased SID or
            ``{GUID}``), or a stable synthetic ``WRAITH:<node_id>`` fallback.
        object_type: the BH ``ObjectType`` (edge-endpoint kind).
        meta_type: the BH per-type file (``meta.type``), or ``None`` if the node
            is export-only synthetic (emitted into the ``base``-less set as a
            ``containers`` ``Base`` node is not valid; such nodes are flagged).
        synthetic: ``True`` when neither SID nor GUID was present (fallback id).
    """

    node_id: str
    object_identifier: str
    object_type: str
    meta_type: str | None
    synthetic: bool


@dataclass
class _NodeDoc:
    """Mutable accumulator for one BH node JSON object (built, then serialized)."""

    object_identifier: str
    object_type: str
    meta_type: str
    properties: dict[str, object]
    aces: list[dict[str, object]] = field(default_factory=list)
    members: list[dict[str, str]] = field(default_factory=list)
    child_objects: list[dict[str, str]] = field(default_factory=list)
    links: list[dict[str, object]] = field(default_factory=list)
    allowed_to_delegate: list[dict[str, str]] = field(default_factory=list)
    allowed_to_act: list[dict[str, str]] = field(default_factory=list)
    has_sid_history: list[dict[str, str]] = field(default_factory=list)
    trusts: list[dict[str, object]] = field(default_factory=list)
    local_groups: dict[str, list[dict[str, str]]] = field(default_factory=dict)


@dataclass(frozen=True)
class KindDisposition:
    """One row of the export completeness ledger (per WRAITH edge kind).

    Every edge of a kind lands in exactly one bucket: ``exported`` (emitted as a
    BH ACE/array entry) or one of the ``dropped`` reasons — so
    ``exported + sum(dropped.values()) == count`` always holds (no silent drops).

    Attributes:
        kind: the WRAITH edge kind.
        count: how many edges of this kind the store held.
        exported: edges emitted as a BH ACE/array/local-group entry.
        dropped: ``reason -> count`` for the edges not emitted (e.g.
            ``target_not_bh_node`` / ``composed_by_bhce`` / ``native`` /
            ``trust_postprocess`` / ``adcs_pending_spike`` / ``esc4_no_ca`` /
            ``unmapped`` / ``*_unresolved``).
        bh_repr: the primary BloodHound representation for the exported subset
            (RightName / array field), or the drop reason when nothing exported.
    """

    kind: str
    count: int
    exported: int
    dropped: Mapping[str, int]
    bh_repr: str


@dataclass(frozen=True)
class ExportResult:
    """The outcome of a BloodHound export (counts + provable no-silent-drop ledger).

    Attributes:
        file_counts: ``meta.type`` -> number of node objects written.
        dispositions: one :class:`KindDisposition` per WRAITH edge kind seen.
        nodes_total: total node objects emitted across all files.
        edges_total: total edge rows read from the store.
        edges_exported: edges emitted as a BH ACE/array entry.
        edges_dropped: edges intentionally not emitted (composed/native/trust/adcs).
        unmapped_kinds: kinds with no routing rule (a loud gap; should be 0).
        skip_counts: adapter-level counted gaps (node/endpoint resolution, etc.).
        output_dir: where the per-type files + zip + ledger were written (or None
            for an in-memory build).
    """

    file_counts: Mapping[str, int]
    dispositions: tuple[KindDisposition, ...]
    nodes_total: int
    edges_total: int
    edges_exported: int
    edges_dropped: int
    unmapped_kinds: Mapping[str, int]
    skip_counts: Mapping[str, int]
    output_dir: str | None


# --- small pure helpers -------------------------------------------------------
def _brace_guid(guid: str) -> str:
    """Return a GUID in BloodHound ``{GUID}`` uppercased form (idempotent)."""
    core = guid.strip().strip("{}")
    return "{" + core.upper() + "}"


def _object_identifier(
    object_sid: str | None, object_guid: str | None, object_type: str
) -> tuple[str, bool]:
    """Resolve a node's BH ``ObjectIdentifier`` and whether it is synthetic.

    SID-keyed BH types use the uppercased SID when present; everything else uses
    the brace-wrapped uppercased GUID. If the preferred key is absent the other
    is used; if neither exists a stable synthetic marker is returned (never a
    silent drop — the caller counts it).

    Returns:
        ``(object_identifier, synthetic)``.
    """
    if object_type in _SID_KEYED_TYPES and object_sid:
        return object_sid.upper(), False
    if object_guid:
        return _brace_guid(object_guid), False
    if object_sid:
        return object_sid.upper(), False
    return "", True


def _epoch(value: object) -> int:
    """Convert a stored timestamp to a Unix-epoch int (``-1`` when absent).

    BloodHound encodes AD timestamps as integer Unix seconds; ``-1`` is its
    "not set" sentinel. Deterministic; never raises on ``None``.
    """
    if isinstance(value, datetime):
        return int(value.timestamp())
    return -1


def _str_list(value: object) -> list[str]:
    """Coerce a nullable DuckDB ``VARCHAR[]`` cell to a list of ``str``."""
    if not isinstance(value, (list, tuple)):
        return []
    return [str(v) for v in value]


def _endpoint(projection: Mapping[str, NodeKey], node_id: str) -> dict[str, str] | None:
    """Return the ``{ObjectIdentifier, ObjectType}`` entry for a node, or None."""
    key = projection.get(node_id)
    if key is None or not key.object_identifier:
        return None
    return {"ObjectIdentifier": key.object_identifier, "ObjectType": key.object_type}


# --- store reads (read-only; typed rows) -------------------------------------
@dataclass(frozen=True)
class _PrincipalRow:
    node_id: str
    object_sid: str | None
    object_guid: str | None
    principal_type: str
    samaccountname: str | None
    upn: str | None
    distinguished_name: str | None
    uac_flags: int | None
    enabled: bool | None
    admincount: int | None
    spns: list[str]
    sid_history: list[str]
    primary_group_id: int | None
    pwd_last_set: object
    last_logon_timestamp: object
    when_created: object
    domain_id: str | None
    domain_fqdn: str | None


def _read_principals(con: duckdb.DuckDBPyConnection) -> list[_PrincipalRow]:
    """Read all principals (User/Computer/Group) ordered by ``node_id``."""
    rows = con.execute("""
        SELECT node_id, object_sid, object_guid, principal_type, samaccountname, upn,
               distinguished_name, uac_flags, enabled, admincount, spns, sid_history,
               primary_group_id, pwd_last_set, last_logon_timestamp, when_created,
               domain_id, domain_fqdn
        FROM principal ORDER BY node_id
        """).fetchall()
    return [
        _PrincipalRow(
            node_id=r[0],
            object_sid=r[1],
            object_guid=r[2],
            principal_type=r[3],
            samaccountname=r[4],
            upn=r[5],
            distinguished_name=r[6],
            uac_flags=r[7],
            enabled=r[8],
            admincount=r[9],
            spns=_str_list(r[10]),
            sid_history=_str_list(r[11]),
            primary_group_id=r[12],
            pwd_last_set=r[13],
            last_logon_timestamp=r[14],
            when_created=r[15],
            domain_id=r[16],
            domain_fqdn=r[17],
        )
        for r in rows
    ]


@dataclass(frozen=True)
class _ContainerRow:
    node_id: str
    object_sid: str | None
    object_guid: str | None
    distinguished_name: str | None
    container_type: str
    domain_id: str | None
    domain_fqdn: str | None


def _read_containers(con: duckdb.DuckDBPyConnection) -> list[_ContainerRow]:
    rows = con.execute("""
        SELECT node_id, object_sid, object_guid, distinguished_name, container_type,
               domain_id, domain_fqdn
        FROM container ORDER BY node_id
        """).fetchall()
    return [
        _ContainerRow(
            node_id=r[0],
            object_sid=r[1],
            object_guid=r[2],
            distinguished_name=r[3],
            container_type=r[4],
            domain_id=r[5],
            domain_fqdn=r[6],
        )
        for r in rows
    ]


@dataclass(frozen=True)
class _GpoRow:
    node_id: str
    object_guid: str | None
    display_name: str | None
    gpc_file_sys_path: str | None
    domain_id: str | None
    domain_fqdn: str | None


def _read_gpos(con: duckdb.DuckDBPyConnection) -> list[_GpoRow]:
    rows = con.execute("""
        SELECT node_id, object_guid, display_name, gpc_file_sys_path, domain_id, domain_fqdn
        FROM gpo ORDER BY node_id
        """).fetchall()
    return [
        _GpoRow(
            node_id=r[0],
            object_guid=r[1],
            display_name=r[2],
            gpc_file_sys_path=r[3],
            domain_id=r[4],
            domain_fqdn=r[5],
        )
        for r in rows
    ]


@dataclass(frozen=True)
class _AdcsRow:
    node_id: str
    object_guid: str | None
    name: str | None
    adcs_type: str
    domain_id: str | None
    domain_fqdn: str | None


def _read_adcs(con: duckdb.DuckDBPyConnection) -> list[_AdcsRow]:
    rows = con.execute("""
        SELECT node_id, object_guid, name, adcs_type, domain_id, domain_fqdn
        FROM adcs ORDER BY node_id
        """).fetchall()
    return [
        _AdcsRow(
            node_id=r[0],
            object_guid=r[1],
            name=r[2],
            adcs_type=r[3],
            domain_id=r[4],
            domain_fqdn=r[5],
        )
        for r in rows
    ]


@dataclass(frozen=True)
class _TrustRow:
    source_domain_id: str | None
    target_domain_id: str | None
    direction: str | None
    trust_type: str | None
    trust_attributes: int | None
    transitive: bool | None
    sid_filtering: bool | None


def _read_trusts(con: duckdb.DuckDBPyConnection) -> list[_TrustRow]:
    rows = con.execute("""
        SELECT source_domain_id, target_domain_id, direction, trust_type,
               trust_attributes, transitive, sid_filtering
        FROM trust ORDER BY node_id
        """).fetchall()
    return [
        _TrustRow(
            source_domain_id=r[0],
            target_domain_id=r[1],
            direction=r[2],
            trust_type=r[3],
            trust_attributes=r[4],
            transitive=r[5],
            sid_filtering=r[6],
        )
        for r in rows
    ]


@dataclass(frozen=True)
class _EdgeRow:
    kind: str
    source_node_id: str
    target_node_id: str
    is_inherited: bool | None
    edge_id: str


def _read_edges(con: duckdb.DuckDBPyConnection) -> list[_EdgeRow]:
    """Read every §4 edge in a TOTAL deterministic order.

    The ORDER BY is total by construction: ``(kind, source, target, is_inherited,
    edge_id)``. Adding ``is_inherited`` disambiguates two edges that differ only
    in inheritance, and the ``edge_id`` primary key is the final unique tiebreaker
    — so the emitted byte stream is identical regardless of the physical DB read
    order (no reliance on an unspecified stable-sort fallback).
    """
    rows = con.execute("""
        SELECT kind, source_node_id, target_node_id, is_inherited, edge_id
        FROM edge ORDER BY kind, source_node_id, target_node_id, is_inherited, edge_id
        """).fetchall()
    return [
        _EdgeRow(
            kind=r[0], source_node_id=r[1], target_node_id=r[2], is_inherited=r[3], edge_id=r[4]
        )
        for r in rows
    ]


def _read_directory_node_ids(con: duckdb.DuckDBPyConnection) -> frozenset[str]:
    """Return every directory-object ``node_id`` from the M3 ``staging_object`` hand-off.

    Used to classify an ACE whose target is NOT a BloodHound-modeled node type:
    a target present here is a real directory object BloodHound simply does not
    model (schema/config/DNS/etc. — SharpHound DCOnly omits these too), whereas a
    target absent here is a genuine gap. If the staging table is absent (export
    run against a store without the M3 hand-off), returns empty — then such
    targets fall into ``target_unresolved`` (still counted, never silent).
    """
    try:
        rows = con.execute("SELECT node_id FROM staging_object").fetchall()
    except duckdb.Error:
        return frozenset()
    return frozenset(str(r[0]) for r in rows)


def _read_gplink_enforced(
    con: duckdb.DuckDBPyConnection, skips: Counter[str]
) -> dict[tuple[str, str], bool]:
    """Map ``(container_node, gpo_node) -> enforced`` from ``container.gplinks``.

    Recovers the ``IsEnforced`` flag the ``edge`` table does not carry, so the
    exported ``Links[]`` entries have the correct enforcement. Missing entries
    default to ``False`` at the call site (and are counted). A gplink element that
    is not a mapping, or carries no ``gpo_node_id``, is a malformed entry: it is
    counted into ``skips['export.gplink_malformed']`` (standing no-silent-gap
    rule) rather than silently ignored.
    """
    out: dict[tuple[str, str], bool] = {}
    rows = con.execute(
        "SELECT node_id, gplinks FROM container WHERE gplinks IS NOT NULL ORDER BY node_id"
    ).fetchall()
    for container_node, gplinks in rows:
        for link in gplinks or []:
            if not isinstance(link, Mapping):
                skips["export.gplink_malformed"] += 1
                continue
            gpo_node = link.get("gpo_node_id")
            if gpo_node is None:
                skips["export.gplink_malformed"] += 1
                continue
            out[(container_node, str(gpo_node))] = bool(link.get("enforced"))
    return out


# --- projection + node docs ---------------------------------------------------
def build_projection(
    principals: Sequence[_PrincipalRow],
    containers: Sequence[_ContainerRow],
    gpos: Sequence[_GpoRow],
    adcs: Sequence[_AdcsRow],
    skips: Counter[str],
) -> dict[str, NodeKey]:
    """Build the ``node_id -> NodeKey`` projection across all node tables.

    Every node resolves to a BH ``ObjectIdentifier`` + ``ObjectType`` + file
    type. Nodes with neither SID nor GUID get a stable synthetic identifier and
    are counted in ``skips`` (never silently dropped — the "never silent" rule
    crosses the adapter boundary too).
    """
    projection: dict[str, NodeKey] = {}

    def add(node_id: str, sid: str | None, guid: str | None, table: str, disc: str | None) -> None:
        object_type = _OBJECT_TYPE.get((table, disc), _BASE_OBJECT_TYPE)
        meta_type = _META_TYPE.get((table, disc))
        oid, synthetic = _object_identifier(sid, guid, object_type)
        if synthetic:
            oid = f"{_WRAITH_NATIVE_PREFIX}{node_id}"
            skips["synthetic_objectidentifier"] += 1
        projection[node_id] = NodeKey(node_id, oid, object_type, meta_type, synthetic)

    for p in principals:
        add(p.node_id, p.object_sid, p.object_guid, "principal", p.principal_type)
    for c in containers:
        add(c.node_id, c.object_sid, c.object_guid, "container", c.container_type)
    for g in gpos:
        add(g.node_id, g.object_guid, g.object_guid, "gpo", None)
    for a in adcs:
        add(a.node_id, a.object_guid, a.object_guid, "adcs", a.adcs_type)
    return projection


def _principal_properties(p: _PrincipalRow) -> dict[str, object]:
    """Assemble the BH ``Properties`` map for a principal (lowercase keys).

    Populates the tag-driving properties BHCE post-processing reads
    (``unconstraineddelegation``, ``admincount``, ``enabled``,
    ``serviceprincipalnames``, ``sidhistory``, ...). ``highvalue``/Tier-0 is
    intentionally NOT set — BHCE derives it post-ingest (doc 12 §4).
    """
    domain = (p.domain_fqdn or "").upper()
    name = p.samaccountname or ""
    display = f"{name}@{domain}" if name and domain else (name or domain)
    uac = p.uac_flags or 0
    enabled = p.enabled if p.enabled is not None else not bool(uac & _UAC_ACCOUNTDISABLE)
    props: dict[str, object] = {
        "domain": domain or None,
        "domainsid": (p.domain_id or "").upper() or None,
        "name": display.upper() or None,
        "distinguishedname": (p.distinguished_name or "").upper() or None,
        "objectid": (p.object_sid or p.object_guid or "").upper() or None,
        "enabled": enabled,
        "admincount": bool(p.admincount),
        "unconstraineddelegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
        "trustedtoauth": bool(uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        "pwdlastset": _epoch(p.pwd_last_set),
        "lastlogontimestamp": _epoch(p.last_logon_timestamp),
        "whencreated": _epoch(p.when_created),
    }
    if p.principal_type in ("User", "Computer"):
        props["serviceprincipalnames"] = sorted(p.spns)
        props["hasspn"] = bool(p.spns)
    if p.upn:
        props["userprincipalname"] = p.upn
    if p.sid_history:
        props["sidhistory"] = sorted(s.upper() for s in p.sid_history)
    return props


def _simple_properties(
    name: str | None, dn: str | None, domain_fqdn: str | None, domain_id: str | None, oid: str
) -> dict[str, object]:
    """Assemble a minimal ``Properties`` map for a container/GPO/ADCS node."""
    domain = (domain_fqdn or "").upper()
    return {
        "domain": domain or None,
        "domainsid": (domain_id or "").upper() or None,
        "name": ((name or "") + ("@" + domain if name and domain else "")).upper()
        or domain
        or None,
        "distinguishedname": (dn or "").upper() or None,
        "objectid": oid,
    }


def _build_node_docs(
    principals: Sequence[_PrincipalRow],
    containers: Sequence[_ContainerRow],
    gpos: Sequence[_GpoRow],
    adcs: Sequence[_AdcsRow],
    projection: Mapping[str, NodeKey],
    skips: Counter[str],
) -> dict[str, _NodeDoc]:
    """Create one :class:`_NodeDoc` per node.

    Keyed by ``node_id``. A node with no BH ``meta.type`` (an unknown/non-modeled
    discriminator) or a synthetic identifier (no SID/GUID) is emitted as a minimal
    BH ``Base`` node into the :data:`BASE_META_TYPE` overflow file (doc 12 §B.3)
    and counted in ``skips['node_emitted_as_base']`` — so an array/ACE endpoint
    that resolves to such a node is never a dangling ``ObjectIdentifier``.
    """
    docs: dict[str, _NodeDoc] = {}

    def make(node_id: str, props: dict[str, object]) -> None:
        key = projection[node_id]
        if key.meta_type is None or key.synthetic:
            skips["node_emitted_as_base"] += 1
            docs[node_id] = _NodeDoc(
                object_identifier=key.object_identifier,
                object_type=_BASE_OBJECT_TYPE,
                meta_type=BASE_META_TYPE,
                properties={"objectid": key.object_identifier},
            )
            return
        docs[node_id] = _NodeDoc(
            object_identifier=key.object_identifier,
            object_type=key.object_type,
            meta_type=key.meta_type,
            properties=props,
        )

    for p in principals:
        make(p.node_id, _principal_properties(p))
    for c in containers:
        key = projection[c.node_id]
        make(
            c.node_id,
            _simple_properties(
                None, c.distinguished_name, c.domain_fqdn, c.domain_id, key.object_identifier
            ),
        )
    for g in gpos:
        key = projection[g.node_id]
        make(
            g.node_id,
            _simple_properties(
                g.display_name, None, g.domain_fqdn, g.domain_id, key.object_identifier
            ),
        )
    for a in adcs:
        key = projection[a.node_id]
        make(
            a.node_id,
            _simple_properties(a.name, None, a.domain_fqdn, a.domain_id, key.object_identifier),
        )
    return docs


def _add_ace(doc: _NodeDoc, principal: NodeKey, right_name: str, is_inherited: bool) -> None:
    """Append one ``Aces[]`` entry (idempotent on identical (principal, right))."""
    entry: dict[str, object] = {
        "PrincipalSID": principal.object_identifier,
        "PrincipalType": principal.object_type,
        "RightName": right_name,
        "IsInherited": is_inherited,
    }
    if entry not in doc.aces:
        doc.aces.append(entry)


#: ``_NodeDoc`` attribute name backing each :data:`_ARRAY_KINDS` field.
_ARRAY_ATTR: Mapping[str, str] = {
    "MemberOf": "members",
    "Contains": "child_objects",
    "AllowedToDelegate": "allowed_to_delegate",
    "AllowedToAct": "allowed_to_act",
    "HasSIDHistory": "has_sid_history",
}


@dataclass
class _Router:
    """Routes each WRAITH edge to its BloodHound encoding, keeping the ledger.

    Per-kind accounting is exact: every routed edge increments either
    ``exported_by_kind`` or exactly one ``dropped_by_kind[kind][reason]`` bucket,
    so ``exported + sum(dropped) == count`` per kind (the no-silent-drop proof).
    ``directory_ids`` is the set of real directory object node_ids (from
    ``staging_object``) used to distinguish an ACE whose target is a real object
    BloodHound simply does not model (expected, SharpHound-DCOnly parity) from an
    ACE whose target is genuinely absent (a real gap).
    """

    projection: Mapping[str, NodeKey]
    docs: Mapping[str, _NodeDoc]
    gplink_enforced: Mapping[tuple[str, str], bool]
    esc4_composable: frozenset[str]
    directory_ids: frozenset[str]
    skips: Counter[str]
    repr_by_kind: dict[str, str] = field(default_factory=dict)
    count_by_kind: Counter[str] = field(default_factory=Counter)
    exported_by_kind: Counter[str] = field(default_factory=Counter)
    dropped_by_kind: dict[str, Counter[str]] = field(default_factory=dict)
    exported: int = 0
    dropped: int = 0
    unmapped: Counter[str] = field(default_factory=Counter)

    def _repr(self, kind: str, bh_repr: str) -> None:
        self.repr_by_kind.setdefault(kind, bh_repr)

    def _exp(self, kind: str, bh_repr: str) -> None:
        self.exported_by_kind[kind] += 1
        self.exported += 1
        self._repr(kind, bh_repr)

    def _drop(self, kind: str, reason: str, bh_repr: str) -> None:
        self.dropped_by_kind.setdefault(kind, Counter())[reason] += 1
        self.dropped += 1
        self._repr(kind, bh_repr)

    def route(self, edge: _EdgeRow) -> None:
        """Apply one edge to its target encoding and update the ledger."""
        self.count_by_kind[edge.kind] += 1
        kind = edge.kind
        if kind in _ACE_KINDS:
            self._route_ace(edge)
        elif kind == _GPLINK_KIND:
            self._route_gplink(edge)
        elif kind in _ARRAY_KINDS:
            self._route_array(edge)
        elif kind in _LOCALGROUP_KINDS:
            self._route_localgroup(edge)
        elif kind in _TRUST_POSTPROCESS_KINDS:
            self._route_trust_postprocess(edge)
        elif kind == _ESC4_KIND:
            self._route_esc4(edge)
        elif kind in _COMPOSED_KINDS:
            self._drop(kind, "composed_by_bhce", "BHCE composes from exported base facts")
            if kind == "DCSync":
                self._reinforce_dcsync(edge)
        elif kind == _FOREIGN_IDENTITY_KIND:
            # The local FSP stub and the real foreign principal collapse onto one
            # SID-keyed ObjectIdentifier at BHCE export, so a literal ForeignIdentity
            # edge is a same-SID self-loop. Drop it (counted) — BHCE reconstructs the
            # capability from the MemberOf/ACL edges keyed by that shared SID.
            self._drop(
                kind,
                "composed_by_bhce",
                "FSP+foreign principal collapse to one SID; BHCE reconstructs via MemberOf/ACL",
            )
        elif kind in _ADCS_TOPOLOGY_KINDS:
            self._drop(kind, "adcs_pending_spike", "ADCS lane pending field-by-field spike")
        elif kind in _NATIVE_KINDS or kind.startswith(_WRAITH_NATIVE_PREFIX):
            self._drop(kind, "native", "WRAITH-native; no BloodHound edge")
        else:
            self.unmapped[kind] += 1
            self._drop(kind, "unmapped", "no routing rule (LOUD gap)")

    def _target_drop_reason(self, target_node_id: str) -> str:
        """Classify a target that is not a BH node: modeled-elsewhere vs absent."""
        if target_node_id in self.directory_ids:
            return "target_not_bh_node"
        return "target_unresolved"

    def _route_ace(self, edge: _EdgeRow) -> None:
        target_doc = self.docs.get(edge.target_node_id)
        principal = self.projection.get(edge.source_node_id)
        if principal is None or not principal.object_identifier:
            self._drop(edge.kind, "source_unresolved", f"Aces[].RightName={edge.kind}")
            return
        if target_doc is None:
            reason = self._target_drop_reason(edge.target_node_id)
            self._drop(edge.kind, reason, f"Aces[].RightName={edge.kind}")
            return
        _add_ace(target_doc, principal, edge.kind, bool(edge.is_inherited))
        self._exp(edge.kind, f"Aces[].RightName={edge.kind}")

    def _route_gplink(self, edge: _EdgeRow) -> None:
        # WRAITH GPLink: source = GPO, target = container. BH Links[] live on the
        # container and reference the GPO.
        container_doc = self.docs.get(edge.target_node_id)
        gpo = self.projection.get(edge.source_node_id)
        if container_doc is None or gpo is None or not gpo.object_identifier:
            self._drop(edge.kind, "endpoint_unresolved", "Links[]{IsEnforced,GUID}")
            return
        enforced = self.gplink_enforced.get((edge.target_node_id, edge.source_node_id))
        if enforced is None:
            self.skips["gplink_enforced_defaulted"] += 1
            enforced = False
        entry: dict[str, object] = {"IsEnforced": enforced, "GUID": gpo.object_identifier}
        if entry not in container_doc.links:
            container_doc.links.append(entry)
        self._exp(edge.kind, "Links[]{IsEnforced,GUID}")

    def _route_array(self, edge: _EdgeRow) -> None:
        field_name, owner = _ARRAY_KINDS[edge.kind]
        owner_id = edge.source_node_id if owner == "source" else edge.target_node_id
        other_id = edge.target_node_id if owner == "source" else edge.source_node_id
        owner_doc = self.docs.get(owner_id)
        entry = _endpoint(self.projection, other_id)
        if owner_doc is None or entry is None:
            self._drop(edge.kind, "endpoint_unresolved", f"{field_name}[]")
            return
        bucket = getattr(owner_doc, _ARRAY_ATTR[edge.kind])
        if entry not in bucket:
            bucket.append(entry)
        self._exp(edge.kind, f"{field_name}[]")

    def _route_localgroup(self, edge: _EdgeRow) -> None:
        field_name = _LOCALGROUP_KINDS[edge.kind]
        computer_doc = self.docs.get(edge.target_node_id)
        entry = _endpoint(self.projection, edge.source_node_id)
        if computer_doc is None or entry is None:
            self._drop(edge.kind, "endpoint_unresolved", f"{field_name}.Results[]")
            return
        bucket = computer_doc.local_groups.setdefault(field_name, [])
        if entry not in bucket:
            bucket.append(entry)
        self._exp(edge.kind, f"{field_name}.Results[]")

    def _route_trust_postprocess(self, edge: _EdgeRow) -> None:
        # Trust-family edges are carried by the domain Trusts[] array (built from
        # the trust table) and composed by BHCE. The explicit edge is dropped +
        # counted. For HasTrustKeys, note when the trust-account User node is
        # absent (BHCE wires Domain -> User from Trusts[] post-ingest).
        if edge.kind == "HasTrustKeys" and edge.target_node_id not in self.docs:
            self.skips["hastrustkeys_user_absent"] += 1
        self._drop(edge.kind, "trust_postprocess", "domain Trusts[] + BHCE post-process")

    def _route_esc4(self, edge: _EdgeRow) -> None:
        # ADCSESC4 only when the controlled template is published to an
        # NTAuth-trusted Enterprise CA; otherwise drop the composite (the
        # underlying GenericAll/WriteDacl/Owns ACEs on the template are exported
        # by their own edges) and annotate. BHCE composes ADCSESC4 itself.
        if edge.target_node_id in self.esc4_composable:
            self._drop(edge.kind, "esc4_composed", "ADCSESC4 (NTAuth-trusted CA publication)")
        else:
            self._drop(edge.kind, "esc4_no_ca", "no NTAuth-trusted CA; underlying ACEs kept")

    def _reinforce_dcsync(self, edge: _EdgeRow) -> None:
        # Re-add the AllExtendedRights ACE on the domain for each DCSync holder so
        # the exported shape matches SharpHound and BHCE composes DCSync from
        # AllExtendedRights + GetChanges/GetChangesAll (B.2). Idempotent.
        domain_doc = self.docs.get(edge.target_node_id)
        principal = self.projection.get(edge.source_node_id)
        if domain_doc is None or principal is None or not principal.object_identifier:
            self.skips["dcsync_reinforce_unresolved"] += 1
            return
        _add_ace(domain_doc, principal, "AllExtendedRights", False)


def _trust_direction(direction: str | None) -> int:
    """Map a WRAITH trust direction to BloodHound's ``TrustDirection`` int."""
    return {"inbound": 1, "outbound": 2, "bidirectional": 3}.get((direction or "").lower(), 0)


def _apply_trusts(
    docs: Mapping[str, _NodeDoc],
    trusts: Sequence[_TrustRow],
    skips: Counter[str],
) -> None:
    """Populate each domain node's ``Trusts[]`` array from the ``trust`` table.

    BHCE post-processes these into the structural trust edges and the abuse edges
    (SpoofSIDHistory / AbuseTGTDelegation / HasTrustKeys) — the native,
    version-robust path (B.2), so WRAITH never emits a direction-flipped edge
    directly. On the real DC there are no trusts (empty).
    """
    by_domain_sid: dict[str, _NodeDoc] = {
        doc.object_identifier: doc for doc in docs.values() if doc.object_type == "Domain"
    }
    for t in trusts:
        src = (t.source_domain_id or "").upper()
        owner = by_domain_sid.get(src)
        if owner is None or not t.target_domain_id:
            skips["trust_domain_unresolved"] += 1
            continue
        owner.trusts.append(
            {
                "TargetDomainSid": t.target_domain_id.upper(),
                "TargetDomainName": None,
                "IsTransitive": bool(t.transitive),
                "TrustDirection": _trust_direction(t.direction),
                "TrustType": t.trust_type or "Unknown",
                "SidFilteringEnabled": bool(t.sid_filtering),
                "TGTDelegationEnabled": False,
            }
        )


def _esc4_composable_templates(con: duckdb.DuckDBPyConnection) -> frozenset[str]:
    """Return CertTemplate node ids published to an NTAuth-trusted Enterprise CA.

    A ``WraithESC4TemplateControl`` composite becomes ``ADCSESC4`` only for these
    templates (B.2); otherwise it is dropped (underlying ACEs retained). Derived
    from the Phase-1 topology edges: template --PublishedTo--> CA and
    CA --TrustedForNTAuth--> NTAuthStore. On the real DC (no CA) this is empty.
    """
    trusted_cas = {
        r[0]
        for r in con.execute(
            "SELECT source_node_id FROM edge WHERE kind = 'TrustedForNTAuth'"
        ).fetchall()
    }
    if not trusted_cas:
        return frozenset()
    return frozenset(
        r[0]
        for r in con.execute(
            "SELECT source_node_id, target_node_id FROM edge WHERE kind = 'PublishedTo'"
        ).fetchall()
        if r[1] in trusted_cas
    )


# --- serialization + writing --------------------------------------------------
def _node_to_json(doc: _NodeDoc) -> dict[str, object]:
    """Serialize a :class:`_NodeDoc` to its BHCE node JSON object (sorted lists)."""
    props = {k: v for k, v in sorted(doc.properties.items()) if v is not None}
    out: dict[str, object] = {
        "ObjectIdentifier": doc.object_identifier,
        "Properties": props,
        "Aces": sorted(
            doc.aces,
            key=lambda a: (str(a["PrincipalSID"]), str(a["RightName"]), bool(a["IsInherited"])),
        ),
        "IsDeleted": False,
        "IsACLProtected": False,
    }
    if doc.object_type == "Group":
        out["Members"] = sorted(doc.members, key=lambda e: e["ObjectIdentifier"])
    if doc.object_type in ("Domain", "OU", "Container"):
        out["ChildObjects"] = sorted(doc.child_objects, key=lambda e: e["ObjectIdentifier"])
        out["Links"] = sorted(doc.links, key=lambda e: str(e["GUID"]))
    if doc.object_type == "Domain":
        out["Trusts"] = sorted(doc.trusts, key=lambda e: str(e["TargetDomainSid"]))
    if doc.object_type in ("Computer", "User"):
        out["AllowedToDelegate"] = sorted(
            doc.allowed_to_delegate, key=lambda e: e["ObjectIdentifier"]
        )
        out["HasSIDHistory"] = sorted(doc.has_sid_history, key=lambda e: e["ObjectIdentifier"])
    if doc.object_type == "Computer":
        out["AllowedToAct"] = sorted(doc.allowed_to_act, key=lambda e: e["ObjectIdentifier"])
        for field_name in ("LocalAdmins", "RemoteDesktopUsers", "DcomUsers", "PSRemoteUsers"):
            results = sorted(
                doc.local_groups.get(field_name, []), key=lambda e: e["ObjectIdentifier"]
            )
            out[field_name] = {
                "Collected": True,
                "FailureReason": None,
                "Results": results,
                "LocalNames": [],
            }
    return out


def _file_payload(
    meta_type: str, docs: Sequence[dict[str, object]], config: ExportConfig
) -> dict[str, object]:
    """Wrap a per-type node list in the BHCE ``{data, meta}`` envelope."""
    return {
        "data": list(docs),
        "meta": {
            "methods": config.methods,
            "type": meta_type,
            "count": len(docs),
            "version": config.ingest_version,
        },
    }


def build_export(
    con: duckdb.DuckDBPyConnection, config: ExportConfig | None = None
) -> tuple[dict[str, dict[str, object]], ExportResult]:
    """Build the full BloodHound ingest payload in memory (pure of disk I/O).

    Reads the canonical graph, builds the ``node_id`` projection, assembles the
    per-node documents, routes every §4 edge to its BloodHound encoding, and
    returns one ``{data, meta}`` payload per ``meta.type`` plus the completeness
    :class:`ExportResult`. Every edge kind is accounted for (no silent drops).

    Inputs:
        con: an open canonical store with the gated node + ``edge`` tables.
        config: the :class:`ExportConfig` (version/methods/zip); defaults applied.

    Returns:
        ``(payloads, result)`` where ``payloads`` maps ``meta.type`` -> envelope.

    Failure modes:
        ``duckdb.Error`` on a store read failure. Unresolvable endpoints / nodes
        degrade to counted gaps on the result (never a crash, never a silent drop).
    """
    cfg = config or ExportConfig()
    skips: Counter[str] = Counter()

    principals = _read_principals(con)
    containers = _read_containers(con)
    gpos = _read_gpos(con)
    adcs = _read_adcs(con)
    trusts = _read_trusts(con)
    edges = _read_edges(con)
    gplink_enforced = _read_gplink_enforced(con, skips)
    esc4_composable = _esc4_composable_templates(con)

    projection = build_projection(principals, containers, gpos, adcs, skips)
    docs = _build_node_docs(principals, containers, gpos, adcs, projection, skips)
    directory_ids = _read_directory_node_ids(con)

    router = _Router(
        projection=projection,
        docs=docs,
        gplink_enforced=gplink_enforced,
        esc4_composable=esc4_composable,
        directory_ids=directory_ids,
        skips=skips,
    )
    for edge in edges:
        router.route(edge)

    _apply_trusts(docs, trusts, skips)

    payloads: dict[str, dict[str, object]] = {}
    file_counts: dict[str, int] = {}
    for meta_type in FILE_TYPES:
        type_docs = [_node_to_json(doc) for doc in docs.values() if doc.meta_type == meta_type]
        type_docs.sort(key=lambda d: str(d["ObjectIdentifier"]))
        payloads[meta_type] = _file_payload(meta_type, type_docs, cfg)
        file_counts[meta_type] = len(type_docs)

    # Overflow BH Base nodes (doc 12 §B.3): emit the file ONLY when non-empty so a
    # normal DC keeps the standard 13-file set; prevents dangling endpoints.
    base_docs = [_node_to_json(doc) for doc in docs.values() if doc.meta_type == BASE_META_TYPE]
    if base_docs:
        base_docs.sort(key=lambda d: str(d["ObjectIdentifier"]))
        payloads[BASE_META_TYPE] = _file_payload(BASE_META_TYPE, base_docs, cfg)
        file_counts[BASE_META_TYPE] = len(base_docs)

    # Defense-in-depth tripwire for the no-silent-drop ledger: every routed edge
    # lands in exactly one bucket, overall AND per kind. These asserts are an
    # internal invariant guard over our own accounting (not input validation), so
    # S101 is intentionally suppressed here.
    assert router.exported + router.dropped == len(edges), (  # noqa: S101
        "edge disposition ledger imbalance"
    )
    for kind, total in router.count_by_kind.items():
        dropped_total = sum(router.dropped_by_kind.get(kind, Counter()).values())
        assert router.exported_by_kind[kind] + dropped_total == total, (  # noqa: S101
            f"per-kind ledger imbalance for {kind!r}"
        )

    dispositions = tuple(
        KindDisposition(
            kind=kind,
            count=router.count_by_kind[kind],
            exported=router.exported_by_kind[kind],
            dropped=dict(sorted(router.dropped_by_kind.get(kind, Counter()).items())),
            bh_repr=router.repr_by_kind[kind],
        )
        for kind in sorted(router.count_by_kind)
    )
    result = ExportResult(
        file_counts=file_counts,
        dispositions=dispositions,
        nodes_total=sum(file_counts.values()),
        edges_total=len(edges),
        edges_exported=router.exported,
        edges_dropped=router.dropped,
        unmapped_kinds=dict(router.unmapped),
        skip_counts=dict(skips),
        output_dir=None,
    )
    return payloads, result


def _ledger_json(result: ExportResult) -> dict[str, object]:
    """Render the completeness ledger as a deterministic JSON-able dict."""
    return {
        "nodes_total": result.nodes_total,
        "edges_total": result.edges_total,
        "edges_exported": result.edges_exported,
        "edges_dropped": result.edges_dropped,
        "file_counts": dict(sorted(result.file_counts.items())),
        "unmapped_kinds": dict(sorted(result.unmapped_kinds.items())),
        "skip_counts": dict(sorted(result.skip_counts.items())),
        "dispositions": [
            {
                "kind": d.kind,
                "count": d.count,
                "exported": d.exported,
                "dropped": dict(sorted(d.dropped.items())),
                "bh_repr": d.bh_repr,
            }
            for d in result.dispositions
        ],
    }


def export_bloodhound(
    con: duckdb.DuckDBPyConnection,
    output_dir: Path | str,
    config: ExportConfig | None = None,
) -> ExportResult:
    """Export the canonical graph to BloodHound CE ingest files + a zip.

    Writes one ``<type>.json`` per ``meta.type`` into ``output_dir``, bundles
    them into ``config.zip_name``, and writes ``export_ledger.json`` (the
    provable no-silent-drop accounting). All writes are deterministic (sorted
    keys, LF newlines, fixed file order). No network I/O.

    Inputs:
        con: an open canonical store with the gated node + ``edge`` tables.
        output_dir: destination directory (created if absent).
        config: the :class:`ExportConfig`; defaults applied when ``None``.

    Returns:
        The :class:`ExportResult` with ``output_dir`` set.

    Failure modes:
        ``duckdb.Error`` on a store read failure; ``OSError`` if the output
        directory cannot be written. Unresolvable graph endpoints degrade to
        counted gaps on the result (never silent).
    """
    cfg = config or ExportConfig()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    payloads, result = build_export(con, cfg)

    # Fixed, deterministic file order: the 13 standard types, then the Base
    # overflow file only when build_export actually produced it (doc 12 §B.3).
    write_order = [*FILE_TYPES]
    if BASE_META_TYPE in payloads:
        write_order.append(BASE_META_TYPE)

    written: list[Path] = []
    for meta_type in write_order:
        text = canonical_json(payloads[meta_type]) + "\n"
        path = out / f"{meta_type}.json"
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)

    ledger_path = out / "export_ledger.json"
    ledger_path.write_text(
        canonical_json(_ledger_json(result)) + "\n", encoding="utf-8", newline="\n"
    )

    zip_path = out / cfg.zip_name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in written:
            # Fixed ZipInfo (no wall-clock mtime) keeps the archive deterministic.
            info = zipfile.ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            # Pin the host-dependent fields so the archive bytes are identical
            # across platforms: create_system defaults to 0 on Windows and 3 on
            # Unix, and external_attr carries host file mode. Freeze both.
            info.create_system = 3
            info.external_attr = 0
            zf.writestr(info, path.read_text(encoding="utf-8"))

    _log.info(
        "bloodhound export: %d nodes, %d edges (%d exported / %d dropped) -> %s",
        result.nodes_total,
        result.edges_total,
        result.edges_exported,
        result.edges_dropped,
        out,
    )
    return ExportResult(
        file_counts=result.file_counts,
        dispositions=result.dispositions,
        nodes_total=result.nodes_total,
        edges_total=result.edges_total,
        edges_exported=result.edges_exported,
        edges_dropped=result.edges_dropped,
        unmapped_kinds=result.unmapped_kinds,
        skip_counts=result.skip_counts,
        output_dir=str(out),
    )
