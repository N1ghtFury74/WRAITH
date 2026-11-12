"""Coder-side sanity for the Tier-B GPO/SYSVOL parsers (not the gate).

Layered: (1) the REAL SYSVOL at eviedence_test/ exercises GptTmpl `[Privilege
Rights]`, the UTF-16LE-BOM decode, and the preg parser (incl. surviving the EFS
binary cert blob); (2) hand-crafted inputs with KNOWN output exercise the
restricted-groups `[Group Membership]` parse, the GPP `Groups.xml` parse, and the
public-static-key `cpassword` decrypt (the paths the real SYSVOL has none of).
The authoritative three-layer gate is the tester's.
"""

from __future__ import annotations

from pathlib import Path

from wraith.gpo.constants import is_baseline_privileged_sid
from wraith.gpo.gpp_parser import (
    decrypt_gpp_cpassword_text,
    parse_gpp_document,
    parse_groups_xml,
)
from wraith.gpo.inf_parser import decode_inf_bytes, parse_gpttmpl
from wraith.gpo.preg_parser import REG_DWORD, dword_value, parse_registry_pol
from wraith.gpo.signals import signals_from_preg

_REPO = Path(__file__).resolve().parents[1]
_SYSVOL = _REPO / "eviedence_test" / "SYSVOL" / "domain" / "Policies"
_DC_POLICY = _SYSVOL / "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
_GPTTMPL = _DC_POLICY / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
_RDP_POL = _SYSVOL / "{D4FC302A-E668-4E39-B591-8727A952E04C}" / "Machine" / "Registry.pol"
_EFS_POL = _SYSVOL / "{31B2F340-016D-11D2-945F-00C04FB984F9}" / "MACHINE" / "Registry.pol"


# --- REAL GptTmpl [Privilege Rights] -----------------------------------------


def test_real_gpttmpl_utf16_bom_decode() -> None:
    raw = _GPTTMPL.read_bytes()
    assert raw[:2] == b"\xff\xfe"  # UTF-16LE BOM
    text = decode_inf_bytes(raw)
    assert "[Privilege Rights]" in text
    assert "SeEnableDelegationPrivilege" in text


def test_real_gpttmpl_privilege_rights_parsed_case_preserved() -> None:
    data = parse_gpttmpl(_GPTTMPL.read_bytes())
    assert data.parse_ok
    names = {p.name for p in data.privilege_rights}
    # Case preserved (optionxform=str): mixed-case privilege names survive.
    assert "SeEnableDelegationPrivilege" in names
    assert "SeBackupPrivilege" in names
    assert "SeRestorePrivilege" in names
    assert "SeDebugPrivilege" in names
    assert "SeTakeOwnershipPrivilege" in names
    assert "SeLoadDriverPrivilege" in names
    assert "SeAssignPrimaryTokenPrivilege" in names
    # 24 privilege lines; the '*' SID prefix is stripped from holders.
    assert len(data.privilege_rights) == 24
    backup = next(p for p in data.privilege_rights if p.name == "SeBackupPrivilege")
    assert backup.holders == ("S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-544")
    # No restricted groups / no GPP on the real DC.
    assert data.group_memberships == ()


def test_real_gpttmpl_all_privilege_holders_are_admin_baseline() -> None:
    # The real-DC true negative: every holder of a HIGH-VALUE privilege is an
    # admin/system baseline SID, so no escalation edge would be emitted.
    data = parse_gpttmpl(_GPTTMPL.read_bytes())
    high_value = {
        "SeEnableDelegationPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeDebugPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeAssignPrimaryTokenPrivilege",
    }
    for priv in data.privilege_rights:
        if priv.name not in high_value:
            continue
        for holder in priv.holders:
            assert is_baseline_privileged_sid(holder), (priv.name, holder)


# --- REAL Registry.pol (preg) ------------------------------------------------


def test_real_registry_pol_rdp_signal() -> None:
    result = parse_registry_pol(_RDP_POL.read_bytes())
    assert result.ok
    assert result.version == 1
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.value == "fDenyTSConnections"
    assert rec.reg_type == REG_DWORD
    assert dword_value(rec) is not None
    signals = signals_from_preg(result.records, "SYSVOL/.../Registry.pol", "a" * 64)
    assert [s.signal for s in signals] == ["fDenyTSConnections"]
    # Facts are self-describing: the SYSVOL image hash is stamped on each signal.
    assert signals[0].image_sha256 == "a" * 64


def test_real_registry_pol_survives_efs_binary_blob() -> None:
    # The {31B2F340} file has a ~969-byte EFS cert blob (REG_BINARY): the parser
    # must not crash or mis-read it, and must keep parsing the trailing records.
    result = parse_registry_pol(_EFS_POL.read_bytes())
    assert result.ok
    assert len(result.records) == 4
    first = result.records[0]
    assert first.value == "EFSBlob"
    assert first.reg_type == 3  # REG_BINARY
    assert len(first.data) == first.size == 969
    # A binary record is NOT mis-decoded to an integer.
    assert dword_value(first) is None


# --- preg robustness (bounds checking on untrusted input) --------------------


def test_preg_bad_magic_is_counted_gap_not_crash() -> None:
    result = parse_registry_pol(b"NOPE" + b"\x01\x00\x00\x00")
    assert not result.ok
    assert result.reason == "bad_magic"
    assert result.records == ()


def test_preg_absurd_size_is_bounds_checked() -> None:
    # A record claiming a 4 GiB data field must not OOB-read; it degrades to a gap
    # while retaining any records parsed before it (here: none).
    blob = (
        b"PReg"
        + b"\x01\x00\x00\x00"
        + b"[\x00"
        + "k".encode("utf-16-le")
        + b"\x00\x00"
        + b";\x00"
        + "v".encode("utf-16-le")
        + b"\x00\x00"
        + b";\x00"
        + (4).to_bytes(4, "little")
        + b";\x00"
        + (0xFFFFFFFF).to_bytes(4, "little")  # absurd size
        + b";\x00"
    )
    result = parse_registry_pol(blob)
    assert not result.ok
    assert result.reason == "data_size_overflow"


# --- SYNTHETIC [Group Membership] (restricted groups) ------------------------


def _utf16_inf(body: str) -> bytes:
    return ("﻿" + body).encode("utf-16-le")


def test_synthetic_group_membership_members_and_memberof() -> None:
    inf = _utf16_inf(
        "[Unicode]\r\nUnicode=yes\r\n"
        "[Group Membership]\r\n"
        "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1107,*S-1-5-21-1-2-3-1108\r\n"
        "*S-1-5-21-1-2-3-1200__Memberof = *S-1-5-32-555\r\n"
    )
    data = parse_gpttmpl(inf)
    assert data.parse_ok
    members = {m.group_token: m for m in data.group_memberships}
    admins = members["S-1-5-32-544"]
    assert admins.relation == "Members"
    assert admins.values == ("S-1-5-21-1-2-3-1107", "S-1-5-21-1-2-3-1108")
    rdp = members["S-1-5-21-1-2-3-1200"]
    assert rdp.relation == "Memberof"
    assert rdp.values == ("S-1-5-32-555",)


# --- SYNTHETIC GPP Groups.xml + cpassword ------------------------------------


def test_synthetic_groups_xml_members() -> None:
    xml = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Groups><Group name="Administrators (built-in)">'
        b'<Properties action="U" groupSid="S-1-5-32-544" '
        b'groupName="Administrators (built-in)">'
        b'<Members><Member name="CORP\\helpdesk" action="ADD" '
        b'sid="S-1-5-21-1-2-3-1500"/>'
        b'<Member name="CORP\\old" action="REMOVE" sid="S-1-5-21-1-2-3-1600"/>'
        b"</Members></Properties></Group></Groups>"
    )
    groups = parse_groups_xml(xml)
    assert len(groups) == 1
    g = groups[0]
    assert g.group_sid == "S-1-5-32-544"
    sids = {m.sid: m.action for m in g.members}
    assert sids == {"S-1-5-21-1-2-3-1500": "ADD", "S-1-5-21-1-2-3-1600": "REMOVE"}


def test_gpp_document_single_pass_groups_and_cpassword() -> None:
    # ONE parse yields both the group actions and the cpassword-bearing element.
    xml = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Groups><Group name="Administrators">'
        b'<Properties action="U" groupSid="S-1-5-32-544">'
        b'<Members><Member action="ADD" sid="S-1-5-21-1-2-3-1500"/></Members>'
        b"</Properties></Group>"
        b'<User name="localadmin"><Properties userName="localadmin" '
        b'cpassword="Xpk4DyKDjYQQ/EUHClHlP2oQjgNneSFq7H7+yjl/xNw"/></User>'
        b"</Groups>"
    )
    doc = parse_gpp_document(xml)
    assert doc.parse_ok
    assert len(doc.groups) == 1 and doc.groups[0].group_sid == "S-1-5-32-544"
    assert len(doc.cpasswords) == 1
    assert doc.cpasswords[0].user_name == "localadmin"


def test_gpp_document_malformed_signals_not_ok() -> None:
    # Truncated XML -> parse_ok=False (the engine counts gpo.gpp_parse_error),
    # NOT an indistinguishable empty ().
    doc = parse_gpp_document(b"<Groups><Group><Properties groupSid=")
    assert doc.parse_ok is False
    assert doc.groups == ()
    assert doc.cpasswords == ()
    # The convenience wrapper still returns () (back-compat).
    assert parse_groups_xml(b"<Groups><Group><Properties groupSid=") == ()


def test_gpp_document_rejects_doctype_defense_in_depth() -> None:
    # A DOCTYPE (where internal entities would be declared) is rejected outright.
    billion = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz [<!ENTITY lol "lol">]>'
        b'<Groups><Group><Properties groupSid="S-1-5-32-544"/></Group></Groups>'
    )
    doc = parse_gpp_document(billion)
    assert doc.parse_ok is False
    assert doc.groups == ()


def test_cpassword_decrypts_with_public_static_key() -> None:
    # Self-consistent fixture: "Passw0rd!2024" encrypted with the PUBLIC
    # [MS-GPPREF] 2.2.1.1 static key (AES-256-CBC, zero IV, UTF-16LE, PKCS7),
    # base64 with MS's trailing '=' stripped — exactly the on-disk cpassword form.
    cpassword = "Xpk4DyKDjYQQ/EUHClHlP2oQjgNneSFq7H7+yjl/xNw"
    assert decrypt_gpp_cpassword_text(cpassword) == "Passw0rd!2024"


def test_cpassword_malformed_is_none_not_crash() -> None:
    assert decrypt_gpp_cpassword_text("") is None
    assert decrypt_gpp_cpassword_text("!!!not-base64!!!") is None


def test_baseline_sid_predicate() -> None:
    assert is_baseline_privileged_sid("S-1-5-32-544")  # Administrators
    assert is_baseline_privileged_sid("S-1-5-18")  # LocalSystem
    assert is_baseline_privileged_sid("S-1-5-21-1-2-3-512")  # Domain Admins
    assert is_baseline_privileged_sid("S-1-5-80-1-2-3-4-5")  # NT SERVICE
    assert not is_baseline_privileged_sid("S-1-5-21-1-2-3-1107")  # a custom user
