"""Data shapes for the Tier-B GPO / SYSVOL module (frozen dataclasses only).

None of these are canonical §3/§4 rows — they are the parser outputs and the
intermediate facts the :mod:`wraith.gpo.engine` turns into ``edge`` rows and the
GPO node's ``derived_rights[]`` struct. No secret plaintext is ever carried on
any of these (the GPP finding holds only a redacted marker + a secret-store
reference), matching the "secrets by reference only" non-negotiable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class PrivilegeRight:
    """One ``[Privilege Rights]`` line: a privilege and its grantee SIDs/names.

    Attributes:
        name: the privilege name verbatim (case preserved), e.g.
            ``SeBackupPrivilege``.
        holders: the grantee tokens with the leading ``*`` stripped — SID
            strings (``S-1-5-32-544``) or bare group-name strings.
    """

    name: str
    holders: tuple[str, ...]


@dataclass(frozen=True)
class GroupMembership:
    """One ``[Group Membership]`` setting ([MS-GPSB] 2.2.10).

    Attributes:
        group_token: the local-group token with ``*`` stripped — a SID
            (``S-1-5-32-544``) or a bare group name.
        relation: ``"Members"`` (the group's membership is set to ``values``) or
            ``"Memberof"`` (the group is made a member of each value).
        values: the valuelist tokens with ``*`` stripped.
    """

    group_token: str
    relation: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class GptTmplData:
    """The parsed, attack-relevant sections of one ``GptTmpl.inf``.

    Attributes:
        privilege_rights: parsed ``[Privilege Rights]`` lines.
        group_memberships: parsed ``[Group Membership]`` settings.
        registry_values: ``[Registry Values]`` as ``{full_key: raw_value}``
            (e.g. ``MACHINE\\...\\NoLMHash`` -> ``4,1``).
        parse_ok: ``False`` if the file could not be decoded/parsed at all
            (a counted gap); the other fields are then empty.
    """

    privilege_rights: tuple[PrivilegeRight, ...] = ()
    group_memberships: tuple[GroupMembership, ...] = ()
    registry_values: tuple[tuple[str, str], ...] = ()
    parse_ok: bool = True


@dataclass(frozen=True)
class PregRecord:
    """One [MS-GPREG] ``Registry.pol`` record ``[key;value;type;size;data]``.

    Attributes:
        key: the registry subkey path (root hive implied by Machine/User dir).
        value: the value name.
        reg_type: the ``REG_*`` type DWORD.
        size: the declared byte length of ``data``.
        data: the raw value bytes (may be binary, e.g. an EFS cert blob).
    """

    key: str
    value: str
    reg_type: int
    size: int
    data: bytes


@dataclass(frozen=True)
class PregResult:
    """The outcome of parsing one ``Registry.pol`` blob.

    Attributes:
        records: the records decoded before any failure (valid records are
            retained even when a later record is malformed).
        ok: ``True`` if the whole blob parsed cleanly; ``False`` on a bad
            magic / truncation / bounds violation (a counted gap).
        reason: a short machine reason when ``ok`` is ``False`` (else ``None``).
        version: the preg version DWORD (``1`` on real files), or ``None`` if
            the header was unreadable.
    """

    records: tuple[PregRecord, ...] = ()
    ok: bool = True
    reason: str | None = None
    version: int | None = None


@dataclass(frozen=True)
class RegistrySignal:
    """An attack-relevant policy value surfaced from ``Registry.pol`` / GptTmpl.

    Attributes:
        signal: the catalog label, e.g. ``LocalAccountTokenFilterPolicy``.
        key: the originating registry subkey path.
        value_name: the originating registry value name.
        raw_value: the decoded value rendered as text (DWORDs as decimal;
            binary as ``<NNN bytes>``).
        interpretation: the human-readable attack meaning.
        source_file: the SYSVOL-relative file the signal came from.
        image_sha256: SHA-256 of the SYSVOL artifact the signal came from, so
            the fact stays self-describing once serialized into a dossier.
        directory_timestamp: the source file's image-filesystem mtime (UTC), or
            ``None`` when it could not be read.
    """

    signal: str
    key: str
    value_name: str
    raw_value: str
    interpretation: str
    source_file: str
    image_sha256: str
    directory_timestamp: datetime | None = None


@dataclass(frozen=True)
class GppMember:
    """One ``<Member>`` of a GPP ``Groups.xml`` local-group action.

    Attributes:
        sid: the member SID, or ``None`` if only a name was given.
        name: the member name (``DOMAIN\\user``), or ``None``.
        action: ``"ADD"`` or ``"REMOVE"`` (default ``"ADD"``).
    """

    sid: str | None
    name: str | None
    action: str


@dataclass(frozen=True)
class GppGroup:
    """One GPP ``Groups.xml`` Local-Users-and-Groups group action.

    Attributes:
        group_sid: the targeted local group's SID, or ``None``.
        group_name: the targeted local group's name, or ``None``.
        members: the member actions.
    """

    group_sid: str | None
    group_name: str | None
    members: tuple[GppMember, ...]


@dataclass(frozen=True)
class GppCpassword:
    """One GPP element carrying a ``cpassword`` attribute.

    The ``cpassword`` value is the on-disk, publicly-reversible obfuscation (not
    yet decrypted plaintext); the engine routes any recovered plaintext to the
    encrypted secret store by reference and NEVER logs it.

    Attributes:
        cpassword: the raw ``cpassword`` attribute value (obfuscated, base64).
        user_name: the account the password is for, if present on the element.
    """

    cpassword: str
    user_name: str | None


@dataclass(frozen=True)
class GppDocument:
    """A parsed GPP ``Groups.xml`` document: group actions + cpassword elements.

    Parsed in ONE pass so a single malformed file is counted exactly once. The
    groups feed local-group edges; the cpasswords feed redacted findings.

    Attributes:
        groups: the parsed ``<Group>`` local-group actions.
        cpasswords: every element bearing a ``cpassword`` attribute.
        parse_ok: ``False`` if the XML could not be parsed at all (a counted gap
            at the engine); ``groups`` and ``cpasswords`` are then empty.
    """

    groups: tuple[GppGroup, ...] = ()
    cpasswords: tuple[GppCpassword, ...] = ()
    parse_ok: bool = True


@dataclass(frozen=True)
class GppPasswordFinding:
    """A recovered GPP ``cpassword`` — a finding, NEVER a graph edge.

    The plaintext is routed to the encrypted secret store by reference; this
    object carries only the redacted marker and the store reference, so it is
    safe to log/serialize.

    Attributes:
        source_file: the SYSVOL-relative XML file the cpassword was in.
        user_name: the account the password is for (if present in the XML).
        secret_ref: the encrypted-store ``secret_id`` when stored, else ``None``
            (``None`` means decryption succeeded but no secret store was wired).
        image_sha256: SHA-256 of the SYSVOL artifact the finding came from, so
            the finding stays self-describing once serialized into a dossier.
        directory_timestamp: the source file's image-filesystem mtime (UTC), or
            ``None`` when it could not be read.
        redacted: always the literal ``"<redacted>"`` marker.
    """

    source_file: str
    user_name: str | None
    secret_ref: str | None
    image_sha256: str
    directory_timestamp: datetime | None = None
    redacted: str = "<redacted>"


@dataclass
class GpoProcessResult:
    """The outcome of a SYSVOL processing run (counts + facts; never secrets).

    Attributes:
        edges_written: distinct §4 edge rows written this pass (deduped).
        admin_to_edges: local-group-derived edges (AdminTo/CanRDP/ExecuteDCOM/
            CanPSRemote) emitted.
        privilege_edges: WRAITH-native ``GPO:<Priv>`` edges emitted (delta from
            the admin baseline).
        derived_rights_written: ``derived_rights[]`` fact entries written across
            all GPO nodes.
        stubs_minted: stub Principals minted for unresolved member/holder SIDs.
        signals: the attack-relevant registry/policy signals surfaced.
        findings: the GPP cpassword findings (redacted).
        gpos_matched: SYSVOL folders matched to a GPO node.
        coverage_counts / skip_counts: the run's counter snapshots.
    """

    edges_written: int = 0
    admin_to_edges: int = 0
    privilege_edges: int = 0
    derived_rights_written: int = 0
    stubs_minted: int = 0
    signals: list[RegistrySignal] = field(default_factory=list)
    findings: list[GppPasswordFinding] = field(default_factory=list)
    gpos_matched: int = 0
    coverage_counts: dict[str, int] = field(default_factory=dict)
    skip_counts: dict[str, int] = field(default_factory=dict)
