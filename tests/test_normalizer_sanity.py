"""Minimal coder-side sanity for Module 3 pure seams (the gate is the tester's).

Covers the pure decoders, the classifier precedence, the SID resolver, DN
reconstruction, and that the canonical/staging DDL creates cleanly. It does NOT
exercise the full normalize pipeline against a real ``.dit`` (that is the
tester's parity/golden layer).
"""

from __future__ import annotations

from datetime import datetime

import duckdb

from wraith.model.store import create_canonical_tables
from wraith.normalize.classify import EntityKind, classify
from wraith.normalize.decoders import (
    decode_filetime,
    decode_trust_type,
    decode_uac_enabled,
    parse_gplink,
)
from wraith.normalize.identity import (
    DirectoryIndex,
    IndexEntry,
    is_domain_specific_sid,
    node_id_for_sid,
)


def test_decode_filetime_known_value() -> None:
    # 132460800000000000 ticks -> 2020-09-18 (approx); never/unset -> None.
    assert decode_filetime(0) is None
    assert decode_filetime(0x7FFFFFFFFFFFFFFF) is None
    dt = decode_filetime(132460800000000000)
    assert isinstance(dt, datetime) and dt.year == 2020


def test_decode_uac_enabled() -> None:
    assert decode_uac_enabled(0x200) is True  # NORMAL_ACCOUNT, not disabled
    assert decode_uac_enabled(0x202) is False  # ACCOUNTDISABLE set
    assert decode_uac_enabled(None) is None


def test_parse_gplink_order_flags_and_cn_guid() -> None:
    raw = (
        "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,"
        "CN=System,DC=c137,DC=local;0]"
        "[LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,"
        "CN=System,DC=c137,DC=local;2]"
    )
    entries = parse_gplink(raw)
    assert len(entries) == 2
    assert entries[0].gpo_cn_guid == "31b2f340-016d-11d2-945f-00c04fb984f9"
    assert entries[0].enforced is False and entries[0].link_order == 0
    assert entries[1].enforced is True and entries[1].link_order == 1


def test_classify_computer_before_user() -> None:
    kind = classify(
        ["computer", "user", "person", "top"], "computer", 0x30000001, "CN=X,DC=c137,DC=local"
    )
    assert kind.entity is EntityKind.PRINCIPAL and kind.principal_type == "Computer"


def test_classify_user_group_domain_gpo_fsp_notmodeled() -> None:
    assert classify(["user", "top"], "user", 0x30000000, None).principal_type == "User"
    assert classify(["group", "top"], "group", 0x10000000, None).principal_type == "Group"
    assert classify(["domainDNS", "top"], "domainDNS", None, None).container_type == "Domain"
    assert classify(["groupPolicyContainer"], "groupPolicyContainer", None, None).entity is (
        EntityKind.GPO
    )
    fsp = classify(["foreignSecurityPrincipal"], "foreignSecurityPrincipal", None, None)
    assert fsp.is_fsp and fsp.principal_type == "Group"
    skip = classify(["displaySpecifier", "top"], "displaySpecifier", None, None)
    assert skip.entity is EntityKind.SKIP and skip.skip_reason == "not_modeled"


def test_decode_trust_type() -> None:
    assert decode_trust_type(2, 0x8) == "forest"
    assert decode_trust_type(2, 0x20) == "parent-child"
    assert decode_trust_type(3, 0) == "realm"
    assert decode_trust_type(2, 0) == "external"


def test_node_id_for_sid_scoping() -> None:
    assert is_domain_specific_sid("S-1-5-21-1-2-3-500") is True
    assert is_domain_specific_sid("S-1-5-32-544") is False
    # well-known is domain-scoped (differs across domains); domain SID is not.
    a = node_id_for_sid("f", "dom-A", "S-1-5-32-544")
    b = node_id_for_sid("f", "dom-B", "S-1-5-32-544")
    assert a != b
    c = node_id_for_sid("f", "dom-A", "S-1-5-21-1-2-3-500")
    d = node_id_for_sid("f", "dom-B", "S-1-5-21-1-2-3-500")
    assert c == d


def test_dn_reconstruction() -> None:
    index = DirectoryIndex()
    index.add(IndexEntry(1, None, "$ROOT_OBJECT$", frozenset({"top"}), "root", None, None))
    index.add(IndexEntry(2, 1, "local", frozenset(), "n-local", None, None))
    index.add(
        IndexEntry(3, 2, "c137", frozenset({"domainDNS", "domain"}), "n-dom", "S-1-5-21-1", "g")
    )
    index.add(IndexEntry(4, 3, "Users", frozenset({"container"}), "n-users", None, "g2"))
    index.add(
        IndexEntry(5, 4, "Administrator", frozenset({"user"}), "n-adm", "S-1-5-21-1-500", "g3")
    )
    assert index.reconstruct_dn(5) == "CN=Administrator,CN=Users,DC=c137,DC=local"
    assert index.domain_fqdn_for(3) == "c137.local"
    assert index.parent_node_id(5) == "n-users"


def test_create_canonical_tables_smoke() -> None:
    con = duckdb.connect(":memory:")
    create_canonical_tables(con)
    tables = {row[0] for row in con.execute("SHOW TABLES").fetchall()}
    assert {"principal", "container", "gpo", "trust", "adcs", "staging_object", "staging_link"} <= (
        tables
    )
    con.close()
