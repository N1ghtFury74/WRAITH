"""Minimal sanity for Module 2b pure secret-mapping logic (no Impacket needed).

The crypto/Impacket integration and the live-DC parity are the tester's gate;
these cover only the pure, deterministic mapping seam (Impacket line -> SecretType
+ node_id) and the node_id contract shared with Module 3.
"""

from __future__ import annotations

import importlib.util

import pytest

from wraith.common.determinism import stable_id
from wraith.parsing.ntds_secrets import (
    EMPTY_LM_HASH_HEX,
    IdentityIndex,
    compute_node_id,
    map_secret_line,
    parse_cleartext_line,
    parse_kerberos_line,
    parse_ntds_ntlm_line,
)
from wraith.secrets import SecretType

FOREST = "forest-1"
_NT = "aabbccddeeff00112233445566778899"
_KRB = "0011223344556677889900aabbccddee00112233445566778899aabbccddeeff"

# Impacket SECRET_TYPE ints.
NTDS, CLEARTEXT, KERBEROS = 0, 1, 2


def _index(sam: str, node: str, uac: int = 512) -> IdentityIndex:
    return IdentityIndex(sam_to_node={sam.upper(): node}, sam_to_uac={sam.upper(): uac})


def test_compute_node_id_prefers_guid_then_sid() -> None:
    guid = "11111111-2222-3333-4444-555555555555"
    sid = "S-1-5-21-1-2-3-500"
    assert compute_node_id(FOREST, guid, sid) == stable_id(FOREST, guid)
    assert compute_node_id(FOREST, None, sid) == stable_id(FOREST, sid)
    assert compute_node_id(FOREST, None, None) is None


def test_parse_helpers() -> None:
    assert parse_ntds_ntlm_line(f"CORP\\bob:1104:{EMPTY_LM_HASH_HEX}:{_NT}:::") == (
        "CORP\\bob",
        "1104",
        EMPTY_LM_HASH_HEX,
        _NT,
    )
    assert parse_kerberos_line(f"CORP\\bob:aes256-cts-hmac-sha1-96:{_KRB}") == (
        "CORP\\bob",
        "aes256-cts-hmac-sha1-96",
        _KRB,
    )
    # Cleartext password legitimately contains a colon.
    assert parse_cleartext_line("CORP\\bob:CLEARTEXT:p:a:ss") == ("CORP\\bob", "p:a:ss")
    assert parse_ntds_ntlm_line("garbage") is None
    assert parse_kerberos_line("garbage") is None
    assert parse_cleartext_line("garbage") is None


def test_map_nt_hash_to_node() -> None:
    node = stable_id(FOREST, "guid-bob")
    result = map_secret_line(
        NTDS, f"CORP\\bob:1104:{EMPTY_LM_HASH_HEX}:{_NT}:::", _index("bob", node)
    )
    assert result.gaps == ["ntds_secrets.empty_lm_skipped"]  # empty LM not stored
    assert len(result.mapped) == 1
    nt = result.mapped[0]
    assert nt.secret_type is SecretType.NT_HASH
    assert nt.node_id == node
    assert nt.label == ""
    assert nt.payload == bytes.fromhex(_NT)
    assert nt.decrypted is True


def test_interdomain_trust_account_maps_to_trust_key() -> None:
    node = stable_id(FOREST, "guid-trust")
    # UAC 0x0800 = INTERDOMAIN_TRUST_ACCOUNT.
    idx = _index("CONTOSO$", node, uac=0x0800)
    result = map_secret_line(NTDS, f"CONTOSO$:1120:{EMPTY_LM_HASH_HEX}:{_NT}:::", idx)
    assert [m.secret_type for m in result.mapped] == [SecretType.TRUST_KEY]


def test_history_line_labels_and_type() -> None:
    node = stable_id(FOREST, "guid-bob")
    line = f"CORP\\bob_history0:1104:{EMPTY_LM_HASH_HEX}:{_NT}:::"
    result = map_secret_line(NTDS, line, _index("bob", node))
    assert [(m.secret_type, m.label) for m in result.mapped] == [
        (SecretType.NT_HASH_HISTORY, "history0")
    ]


def test_non_empty_lm_is_stored() -> None:
    node = stable_id(FOREST, "guid-bob")
    lm = "11223344556677881122334455667788"
    result = map_secret_line(NTDS, f"bob:1104:{lm}:{_NT}:::", _index("bob", node))
    types = {m.secret_type for m in result.mapped}
    assert types == {SecretType.NT_HASH, SecretType.LM_HASH}


def test_kerberos_key_subtype_label_and_payload() -> None:
    node = stable_id(FOREST, "guid-bob")
    result = map_secret_line(
        KERBEROS, f"CORP\\bob:aes256-cts-hmac-sha1-96:{_KRB}", _index("bob", node)
    )
    assert len(result.mapped) == 1
    key = result.mapped[0]
    assert key.secret_type is SecretType.KERBEROS_KEY
    assert key.label == "aes256-cts-hmac-sha1-96"
    assert key.payload == bytes.fromhex(_KRB)


def test_cleartext_mapping() -> None:
    node = stable_id(FOREST, "guid-bob")
    result = map_secret_line(CLEARTEXT, "CORP\\bob:CLEARTEXT:Sekret:1", _index("bob", node))
    assert len(result.mapped) == 1
    assert result.mapped[0].secret_type is SecretType.CLEARTEXT
    assert result.mapped[0].payload == b"Sekret:1"


def test_unmapped_account_is_counted_gap() -> None:
    result = map_secret_line(
        NTDS, f"CORP\\ghost:9:{EMPTY_LM_HASH_HEX}:{_NT}:::", _index("bob", "n")
    )
    assert result.mapped == []
    assert result.gaps == ["ntds_secrets.unmapped_account"]


def test_extract_secrets_refuses_without_impacket() -> None:
    """When Impacket is unimportable, extraction fails fast (never silent)."""
    if importlib.util.find_spec("impacket") is not None:
        pytest.skip("impacket present; fail-fast path not exercisable here")
    from wraith.parsing.ntds_secrets import ImpacketUnavailableError, extract_secrets

    with pytest.raises(ImpacketUnavailableError):
        extract_secrets(
            ntds_path="nonexistent.dit",
            system_hive_path="nonexistent.SYSTEM",
            parsed=None,  # type: ignore[arg-type]  # never reached (fails at import check)
            store=None,  # type: ignore[arg-type]
            dek=b"\x00" * 32,
            run=None,  # type: ignore[arg-type]
            forest_id=FOREST,
        )
