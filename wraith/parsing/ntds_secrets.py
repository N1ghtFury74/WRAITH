"""NTDS secret decryption (Module 2 sub-layer 2b).

Given a parsed ``ntds.dit`` (Module 2a :class:`~wraith.parsing.ntds.ParsedNtds`
for identity), the matching ``SYSTEM`` registry hive (the boot-key source), a
case DEK, an open Module-1 :class:`~wraith.secrets.store.SecretStore`, an
:class:`~wraith.case.ingest_run.IngestRun` and a ``forest_id``, this layer
recovers the directory secrets and writes them — encrypted at rest — into the
secret store, returning a ``node_id -> [secret_id, ...]`` map for Module 3 to
attach as ``Principal.secret_refs``.

Crypto is delegated entirely to Impacket (CLAUDE.md: never hand-roll
PEK/DES/RC4/AES). Impacket is routed through the ``dissect`` impacket shim
(:mod:`dissect.database.ese.tools.impacket`) so it reads the dissect-parsed
``.dit`` offline; if the shim is unavailable, Impacket's own native ESE read is
an acceptable fallback (still fully offline, identical crypto). Which read path
was used is reported on the result.

Design (quality bar):

* **Secrets never leave the encrypted store.** Recovered material is wrapped in
  ``SecretBytes`` and handed straight to ``SecretStore.put_secret`` with the
  ``.dit`` image SHA-256 as provenance; plaintext lifetime is minimised
  (encrypt-and-drop). Nothing here logs or returns a secret value — only
  ``secret_id`` / ``secret_type`` / counts.
* **Pure mapping, impure driver.** The correctness-critical correlation
  (Impacket's per-account output -> ``SecretType`` + owning ``node_id``) is a set
  of small pure functions (:func:`map_secret_line`, :func:`parse_*`) that are
  unit-testable without Impacket. The Impacket invocation
  (:func:`_collect_raw_secrets`, :func:`_derive_boot_key`) is an isolated,
  lazily-imported I/O seam.
* **Counted gaps, never silent, never a crash.** An unmappable/undecodable/
  duplicate secret is counted + logged (id/type/reason only, never the value)
  and surfaced in :attr:`SecretExtractionResult.gap_counts`.
* **Deferred blobs are kept, not lost.** ``msLAPS-EncryptedPassword`` (LAPSv2),
  ``msDS-ManagedPassword`` / ``msKds-RootKeyData`` (gMSA), and
  ``trustAuthIncoming``/``trustAuthOutgoing`` are stored as RAW CIPHERTEXT with
  ``decrypted=False`` — offline decryption of these is deferred (LOCKED
  decision), nothing is dropped.
* **Deterministic.** Objects are processed in DNT order; collected secrets are
  sorted by ``(node_id, secret_type, label)`` before storage. Ciphertext itself
  legitimately varies (Module 1 contract).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from pydantic import SecretBytes

from wraith.case.ingest_run import IngestRun
from wraith.common.determinism import stable_id
from wraith.parsing.ntds import ParsedNtds, ParsedObject
from wraith.secrets import SecretAlreadyStoredError, SecretStore, SecretType

_log = logging.getLogger(__name__)

# --- public [MS-ADTS]/[MS-DTYP] facts (reusable; original implementation) ----

#: ``userAccountControl`` bit marking an interdomain trust account (0x0800).
#: An account carrying this bit stores a trust key, not an ordinary NT hash.
UAC_INTERDOMAIN_TRUST_ACCOUNT: int = 0x0800

#: The well-known constant "empty"/absent LM hash (``LMOWFv1("", "")``). When an
#: account's LM hash equals this it carries no LM secret — stored LM is skipped
#: (counted informationally), never a gap.
EMPTY_LM_HASH_HEX: str = "aad3b435b51404eeaad3b435b51404ee"

#: LAPS v1 clear-text password attribute (lDAPDisplayName). Stored in the
#: ``datatable`` as a normal cleartext attribute (NOT a PEK secret), read via the
#: 2a resolver and stored as ``LAPS_PASSWORD`` (decrypted=True).
_LAPS_V1_ATTRIBUTE: str = "ms-Mcs-AdmPwd"

#: Deferred-decryption attributes (LOCKED decision): their RAW CIPHERTEXT is
#: stored with ``decrypted=False``; offline decryption is out of scope for 2b.
#: Maps lDAPDisplayName (lowercased) -> (SecretType, storage label).
_DEFERRED_CIPHERTEXT_ATTRIBUTES: Mapping[str, tuple[SecretType, str]] = {
    "mslaps-encryptedpassword": (SecretType.LAPS_PASSWORD, "laps_v2_ciphertext"),
    "msds-managedpassword": (SecretType.GMSA_PASSWORD, "gmsa_managed_password"),
    "mskds-rootkeydata": (SecretType.OTHER, "kds_root_key"),
    "trustauthincoming": (SecretType.TRUST_KEY, "trust_auth_incoming"),
    "trustauthoutgoing": (SecretType.TRUST_KEY, "trust_auth_outgoing"),
}

# --- Impacket SECRET_TYPE enum values (impacket 0.13.1 NTDSHashes) ------------
_SECRET_NTDS: int = 0  # NTLM line: userName:rid:lmhash:nthash:::
_SECRET_NTDS_CLEARTEXT: int = 1  # userName:CLEARTEXT:password
_SECRET_NTDS_KERBEROS: int = 2  # userName:etype:keyhex

_HISTORY_RE = re.compile(r"_history(\d+)$")

# --- coverage / gap counter keys (surfaced on the IngestRun ledger) ----------
_COV_STORED = "ntds_secrets.stored"
_GAP_UNMAPPED_ACCOUNT = "ntds_secrets.unmapped_account"
_GAP_UNDECODABLE_LINE = "ntds_secrets.undecodable_line"
_GAP_DUPLICATE_SECRET = "ntds_secrets.duplicate_secret"  # noqa: S105 (counter key)
_GAP_NON_BYTE_BLOB = "ntds_secrets.non_byte_blob"
_INFO_EMPTY_LM = "ntds_secrets.empty_lm_skipped"


class SecretExtractionError(Exception):
    """Base error for the 2b secret-extraction layer."""


class ImpacketUnavailableError(SecretExtractionError):
    """Raised when Impacket (the mandated crypto library) cannot be imported.

    Secret decryption is intentionally refused rather than silently skipped: a
    missing crypto backend is a configuration error, not a per-record gap.
    """


class ImpacketReadPath(StrEnum):
    """Which ESE read path Impacket used for the ``.dit``.

    ``DISSECT_SHIM`` routes Impacket through the dissect impacket shim (reads the
    dissect-parsed ``.dit``); ``IMPACKET_NATIVE`` uses Impacket's own ESE reader.
    Both are fully offline and share identical secret crypto.
    """

    DISSECT_SHIM = "dissect_shim"
    IMPACKET_NATIVE = "impacket_native"


@dataclass(frozen=True)
class StoredSecretRef:
    """A reference to one stored secret (NEVER the value).

    Attributes:
        secret_id: the run-scoped id returned by ``SecretStore.put_secret`` —
            what Module 3 records in ``Principal.secret_refs``.
        secret_type: the stored :class:`~wraith.secrets.records.SecretType`.
        label: discriminator (kerberos etype, ``history<n>``, deferred-blob tag),
            or ``""`` for a principal's primary NT/LM hash.
        decrypted: ``True`` when the stored payload is the recovered plaintext/
            hash; ``False`` when it is raw ciphertext we cannot decrypt offline
            (LAPSv2 / gMSA / raw trustAuth / KDS root).
        decryptable_offline: whether offline decryption is even possible for this
            kind in WRAITH's scope (``False`` for the deferred blobs).
    """

    secret_id: str
    secret_type: SecretType
    label: str
    decrypted: bool
    decryptable_offline: bool


@dataclass(frozen=True)
class SecretExtractionResult:
    """The hand-off to Module 3 (counts + references only, never secrets).

    Attributes:
        node_secret_refs: ``node_id -> (StoredSecretRef, ...)`` — the map Module
            3 attaches as ``Principal.secret_refs``. ``node_id`` is computed here
            exactly as Module 3 computes it (``stable_id(forest_id, objectGUID)``
            with objectSid fallback) so the refs line up.
        type_counts: number of secrets stored per :class:`SecretType`.
        gap_counts: counted gaps by reason (unmapped account, undecodable line,
            duplicate, non-byte blob, empty-LM skipped).
        accounts_with_secrets: distinct ``node_id`` count with >= 1 stored secret.
        bootkey_derived: whether the SYSTEM-hive boot key was derived.
        read_path: which Impacket ESE read path was used.
    """

    node_secret_refs: Mapping[str, tuple[StoredSecretRef, ...]]
    type_counts: Mapping[SecretType, int]
    gap_counts: Mapping[str, int]
    accounts_with_secrets: int
    bootkey_derived: bool
    read_path: ImpacketReadPath


# -----------------------------------------------------------------------------
# Identity correlation (pure)
# -----------------------------------------------------------------------------


def compute_node_id(forest_id: str, object_guid: str | None, object_sid: str | None) -> str | None:
    """Compute the canonical ``node_id`` for a principal (schema §2.1).

    Deterministic hash of ``forest_id || object_guid``, falling back to
    ``forest_id || object_sid`` when the GUID is absent. This MUST match Module
    3's computation so the stored ``secret_id`` references line up with the
    ``Principal`` rows.

    Inputs:
        forest_id: the stable forest identifier (scoping block).
        object_guid: the object's GUID string, or ``None``.
        object_sid: the object's SID string, or ``None``.

    Returns:
        A 64-hex ``node_id``, or ``None`` if the object has neither a GUID nor a
        SID (not an addressable node — its secrets cannot be attributed).

    Failure modes:
        Never raises.
    """
    if object_guid:
        return stable_id(forest_id, object_guid)
    if object_sid:
        return stable_id(forest_id, object_sid)
    return None


@dataclass(frozen=True)
class IdentityIndex:
    """sAMAccountName/SID -> ``node_id`` correlation built from the 2a parse.

    Impacket keys its output by ``sAMAccountName`` (and RID); this index maps
    those back to the ``node_id`` Module 3 will mint. ``sam_to_uac`` lets the
    mapper tell an interdomain trust account's hash (``TRUST_KEY``) from an
    ordinary NT hash.
    """

    sam_to_node: Mapping[str, str]
    sam_to_uac: Mapping[str, int]

    def node_for_account(self, username: str) -> str | None:
        """Resolve the ``node_id`` for an Impacket username token.

        Strips an optional ``DOMAIN\\`` prefix, a trailing ``_history<n>`` and
        any trailing `` (annotation)`` before a case-insensitive lookup.

        Inputs:
            username: the first ``:``-field of an Impacket secret line.

        Returns:
            The matching ``node_id``, or ``None`` if the account is unknown.

        Failure modes:
            Never raises.
        """
        base, _ = _clean_account_name(username)
        return self.sam_to_node.get(base.upper())

    def uac_for_account(self, username: str) -> int | None:
        """Return the ``userAccountControl`` of the named account, or ``None``."""
        base, _ = _clean_account_name(username)
        return self.sam_to_uac.get(base.upper())


def _clean_account_name(username: str) -> tuple[str, int | None]:
    """Normalise an Impacket username token (pure).

    Returns ``(base_sam, history_index)`` where ``history_index`` is the integer
    from a ``_history<n>`` suffix, or ``None`` for a current (non-history) line.
    """
    name = username.split(" (", 1)[0]
    name = name.rsplit("\\", 1)[-1]
    history: int | None = None
    match = _HISTORY_RE.search(name)
    if match:
        history = int(match.group(1))
        name = name[: match.start()]
    return name, history


# -----------------------------------------------------------------------------
# Secret-line mapping (pure)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class MappedSecret:
    """One secret resolved to its owning node + type, ready to store (no store).

    ``account`` is the (non-secret) sAMAccountName carried only for deterministic
    ordering and diagnostics; ``payload`` holds the raw secret bytes handed to
    the encrypted store and is never logged.
    """

    node_id: str
    secret_type: SecretType
    label: str
    payload: bytes
    decrypted: bool
    decryptable_offline: bool
    account: str


@dataclass
class LineResult:
    """Result of mapping one Impacket secret line: secrets produced + gaps."""

    mapped: list[MappedSecret] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def parse_ntds_ntlm_line(answer: str) -> tuple[str, str, str, str] | None:
    """Parse an Impacket ``SECRET_TYPE.NTDS`` line (pure).

    Expected form ``userName:rid:lmhash:nthash:::`` (``userName`` may be
    ``DOMAIN\\sam`` and may carry a ``_history<n>`` suffix).

    Inputs:
        answer: the raw callback string.

    Returns:
        ``(userName, rid, lm_hash_hex, nt_hash_hex)`` or ``None`` if the line is
        malformed (too few fields).

    Failure modes:
        Never raises.
    """
    parts = answer.split(":")
    if len(parts) < 4:
        return None
    return parts[0], parts[1], parts[2], parts[3]


def parse_kerberos_line(answer: str) -> tuple[str, str, str] | None:
    """Parse an Impacket ``SECRET_TYPE.NTDS_KERBEROS`` line (pure).

    Expected form ``userName:etype:keyhex`` (``etype`` is e.g.
    ``aes256-cts-hmac-sha1-96`` or ``0x<hex>`` for an unknown type).

    Returns:
        ``(userName, etype, key_hex)`` or ``None`` if malformed.

    Failure modes:
        Never raises.
    """
    parts = answer.rsplit(":", 2)
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def parse_cleartext_line(answer: str) -> tuple[str, str] | None:
    """Parse an Impacket ``SECRET_TYPE.NTDS_CLEARTEXT`` line (pure).

    Expected form ``userName:CLEARTEXT:<password>`` (the password may itself
    contain ``:``; a ``0x``-prefixed value denotes a non-UTF16 raw payload).

    Returns:
        ``(userName, password_or_0xhex)`` or ``None`` if the marker is absent.

    Failure modes:
        Never raises.
    """
    marker = ":CLEARTEXT:"
    idx = answer.find(marker)
    if idx < 0:
        return None
    return answer[:idx], answer[idx + len(marker) :]


def _decode_hex(value: str) -> bytes | None:
    """Return ``bytes.fromhex(value)`` or ``None`` if ``value`` is not hex."""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def map_secret_line(secret_type_int: int, answer: str, identity: IdentityIndex) -> LineResult:
    """Map one Impacket secret line to :class:`MappedSecret`\\ s (pure).

    Resolves the owning ``node_id`` via ``identity`` and the correct
    :class:`SecretType` (NT/LM + history, Kerberos-key-by-etype, cleartext, and
    interdomain-trust reclassification of an NT hash to ``TRUST_KEY``). The empty
    LM/absent-LM constant is skipped (counted informationally, not a gap).

    Inputs:
        secret_type_int: Impacket's ``NTDSHashes.SECRET_TYPE`` integer.
        answer: the raw callback string (never logged in full).
        identity: the sAMAccountName/SID -> node_id correlation index.

    Returns:
        A :class:`LineResult` with 0..2 :class:`MappedSecret` and 0..n gap
        reasons (e.g. ``unmapped_account``, ``undecodable_line``).

    Failure modes:
        Never raises; a malformed line degrades to a counted gap.
    """
    if secret_type_int == _SECRET_NTDS:
        return _map_ntlm(answer, identity)
    if secret_type_int == _SECRET_NTDS_KERBEROS:
        return _map_kerberos(answer, identity)
    if secret_type_int == _SECRET_NTDS_CLEARTEXT:
        return _map_cleartext(answer, identity)
    return LineResult(gaps=[_GAP_UNDECODABLE_LINE])


def _map_ntlm(answer: str, identity: IdentityIndex) -> LineResult:
    result = LineResult()
    parsed = parse_ntds_ntlm_line(answer)
    if parsed is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
        return result
    username, _rid, lm_hex, nt_hex = parsed
    node_id = identity.node_for_account(username)
    if node_id is None:
        result.gaps.append(_GAP_UNMAPPED_ACCOUNT)
        return result
    base, history = _clean_account_name(username)

    nt_bytes = _decode_hex(nt_hex)
    if nt_bytes is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
    else:
        if history is not None:
            nt_type, label = SecretType.NT_HASH_HISTORY, f"history{history}"
        else:
            uac = identity.uac_for_account(username) or 0
            is_trust = bool(uac & UAC_INTERDOMAIN_TRUST_ACCOUNT)
            nt_type = SecretType.TRUST_KEY if is_trust else SecretType.NT_HASH
            label = ""
        result.mapped.append(
            MappedSecret(
                node_id=node_id,
                secret_type=nt_type,
                label=label,
                payload=nt_bytes,
                decrypted=True,
                decryptable_offline=True,
                account=base,
            )
        )

    lm_bytes = _decode_hex(lm_hex)
    if lm_bytes is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
    elif lm_hex.lower() == EMPTY_LM_HASH_HEX:
        # Absent LM secret (NoLMHash policy / disabled) — not stored, counted.
        result.gaps.append(_INFO_EMPTY_LM)
    else:
        lm_label = f"history{history}" if history is not None else ""
        result.mapped.append(
            MappedSecret(
                node_id=node_id,
                secret_type=SecretType.LM_HASH,
                label=lm_label,
                payload=lm_bytes,
                decrypted=True,
                decryptable_offline=True,
                account=base,
            )
        )
    return result


def _map_kerberos(answer: str, identity: IdentityIndex) -> LineResult:
    result = LineResult()
    parsed = parse_kerberos_line(answer)
    if parsed is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
        return result
    username, etype, key_hex = parsed
    node_id = identity.node_for_account(username)
    if node_id is None:
        result.gaps.append(_GAP_UNMAPPED_ACCOUNT)
        return result
    key_bytes = _decode_hex(key_hex)
    if key_bytes is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
        return result
    base, _ = _clean_account_name(username)
    # The etype IS the subtype label (e.g. "aes256-cts-hmac-sha1-96"); an unknown
    # etype arrives from Impacket as "0x<hex>" and is kept verbatim.
    result.mapped.append(
        MappedSecret(
            node_id=node_id,
            secret_type=SecretType.KERBEROS_KEY,
            label=etype,
            payload=key_bytes,
            decrypted=True,
            decryptable_offline=True,
            account=base,
        )
    )
    return result


def _map_cleartext(answer: str, identity: IdentityIndex) -> LineResult:
    result = LineResult()
    parsed = parse_cleartext_line(answer)
    if parsed is None:
        result.gaps.append(_GAP_UNDECODABLE_LINE)
        return result
    username, value = parsed
    node_id = identity.node_for_account(username)
    if node_id is None:
        result.gaps.append(_GAP_UNMAPPED_ACCOUNT)
        return result
    base, _ = _clean_account_name(username)
    if value.startswith("0x"):
        payload = _decode_hex(value[2:])
        if payload is None:
            result.gaps.append(_GAP_UNDECODABLE_LINE)
            return result
    else:
        payload = value.encode("utf-8")
    result.mapped.append(
        MappedSecret(
            node_id=node_id,
            secret_type=SecretType.CLEARTEXT,
            label="",
            payload=payload,
            decrypted=True,
            decryptable_offline=True,
            account=base,
        )
    )
    return result


# -----------------------------------------------------------------------------
# Identity + deferred-blob pass over the 2a parse
# -----------------------------------------------------------------------------


def _coerce_bytes(value: object) -> bytes | None:
    """Return ``value`` as ``bytes`` if byte-like, UTF-8 if ``str``, else None."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _scan_objects(
    parsed: ParsedNtds, forest_id: str
) -> tuple[IdentityIndex, list[MappedSecret], int]:
    """One DNT-ordered pass: build the identity index + collect LAPS/deferred.

    Streams the 2a objects once (bounded memory: only the sAM->node/uac index and
    the discovered LAPS/deferred blobs are retained, never the object stream).
    Returns the :class:`IdentityIndex`, the LAPS/deferred
    :class:`MappedSecret`\\ s discovered directly on objects, and the count of
    deferred attributes that were present but not byte-coercible (a counted gap).
    """
    sam_to_node: dict[str, str] = {}
    sam_to_uac: dict[str, int] = {}
    deferred: list[MappedSecret] = []
    non_byte_blobs = 0

    for obj in parsed.objects():
        node_id = compute_node_id(forest_id, obj.object_guid, obj.object_sid)
        if node_id is None:
            continue
        sam = obj.sam_account_name
        if sam:
            sam_to_node.setdefault(sam.upper(), node_id)
            uac = obj.attribute("userAccountControl")
            if isinstance(uac, int):
                sam_to_uac[sam.upper()] = uac
        found, non_byte = _object_laps_and_deferred(obj, node_id)
        deferred.extend(found)
        non_byte_blobs += non_byte

    index = IdentityIndex(sam_to_node=sam_to_node, sam_to_uac=sam_to_uac)
    return index, deferred, non_byte_blobs


def _attributes_ci(obj: ParsedObject) -> dict[str, object]:
    """Return the object's attributes keyed by lowercased lDAPDisplayName."""
    return {name.lower(): value for name, value in obj.attributes.items()}


def _object_laps_and_deferred(obj: ParsedObject, node_id: str) -> tuple[list[MappedSecret], int]:
    """Extract LAPS v1 cleartext + deferred-ciphertext blobs from one object.

    LAPS v1 (``ms-Mcs-AdmPwd``) is a cleartext attribute -> ``LAPS_PASSWORD``
    (decrypted=True). The deferred blobs (LAPSv2/gMSA/KDS/raw trustAuth) are
    stored as RAW CIPHERTEXT (decrypted=False, decryptable_offline=False).

    Returns:
        ``(secrets, non_byte_blob_count)`` — the second element counts deferred
        attributes that were present but not byte-coercible (a counted gap, never
        a silent drop).
    """
    found: list[MappedSecret] = []
    non_byte = 0
    attrs = _attributes_ci(obj)
    sam = obj.sam_account_name or ""

    laps_v1 = attrs.get(_LAPS_V1_ATTRIBUTE.lower())
    laps_bytes = _coerce_bytes(_first(laps_v1))
    if laps_bytes is not None:
        found.append(
            MappedSecret(
                node_id=node_id,
                secret_type=SecretType.LAPS_PASSWORD,
                label="laps_v1",
                payload=laps_bytes,
                decrypted=True,
                decryptable_offline=True,
                account=sam,
            )
        )

    for attr_lower, (secret_type, label) in _DEFERRED_CIPHERTEXT_ATTRIBUTES.items():
        raw = attrs.get(attr_lower)
        if raw is None:
            continue
        blob = _coerce_bytes(_first(raw))
        if blob is None:
            non_byte += 1
            continue
        found.append(
            MappedSecret(
                node_id=node_id,
                secret_type=secret_type,
                label=label,
                payload=blob,
                decrypted=False,
                decryptable_offline=False,
                account=sam,
            )
        )
    return found, non_byte


def _first(value: object) -> object:
    """Collapse a one-or-more-element list to its first element (pure)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


# -----------------------------------------------------------------------------
# Impacket seam (lazily imported; impure)
# -----------------------------------------------------------------------------


def _require_impacket() -> None:
    """Import-check Impacket, raising :class:`ImpacketUnavailableError` if absent."""
    try:
        import impacket.examples.secretsdump  # noqa: F401
    except Exception as exc:  # ImportError or a quarantined-module OSError
        raise ImpacketUnavailableError(
            "Impacket (mandated crypto backend) could not be imported; secret "
            "decryption refused. Install impacket==0.13.1 in an environment where "
            f"its modules are readable. Underlying error: {type(exc).__name__}"
        ) from exc


def _derive_boot_key(system_hive_path: Path) -> bytes:
    """Derive the SYSTEM-hive boot key offline via Impacket ``LocalOperations``.

    Inputs:
        system_hive_path: resolved path to the ``SYSTEM`` registry hive.

    Returns:
        The 16-byte boot key.

    Failure modes:
        Raises :class:`ImpacketUnavailableError` if Impacket is missing;
        propagates Impacket's error if the hive is unreadable/invalid.
    """
    from impacket.examples.secretsdump import LocalOperations

    local = LocalOperations(str(system_hive_path))
    boot_key: bytes = local.getBootKey()
    return boot_key


def _apply_dissect_shim() -> bool:
    """Monkeypatch Impacket's ``ESENT_DB`` to the dissect reader; report success.

    Importing the shim module monkeypatches ``impacket.ese.ESENT_DB`` so that
    ``NTDSHashes(ntdsFile=...)`` reads the dissect-parsed ``.dit``. Returns
    ``True`` if the shim was applied, ``False`` to fall back to Impacket's native
    ESE reader (both fully offline, identical crypto).
    """
    try:
        import dissect.database.ese.tools.impacket  # noqa: F401
    except Exception as exc:
        _log.warning(
            "dissect impacket shim unavailable (%s); falling back to Impacket's "
            "native ESE reader (still offline)",
            type(exc).__name__,
        )
        return False
    return True


def _collect_raw_secrets(
    ntds_path: Path, boot_key: bytes, *, use_shim: bool
) -> list[tuple[int, str]]:
    """Run Impacket ``NTDSHashes`` offline and collect ``(type, line)`` tuples.

    The per-secret callback appends each ``(SECRET_TYPE int, formatted line)``;
    nothing is printed and no output file is written. History is requested so
    NT/LM history is recovered.

    Inputs:
        ntds_path: resolved path to the ``.dit``.
        boot_key: the SYSTEM boot key.
        use_shim: whether the dissect shim was applied (reporting only).

    Returns:
        The collected ``(secret_type_int, line)`` tuples in Impacket's emission
        order (NT/LM per account in table order, then Kerberos, then cleartext).

    Failure modes:
        Propagates Impacket errors raised before iteration; per-record Impacket
        errors are logged by Impacket and do not abort the run.
    """
    from impacket.examples.secretsdump import NTDSHashes

    collected: list[tuple[int, str]] = []

    def _callback(secret_type: int, secret: object) -> None:
        # Impacket passes its NTDSHashes.SECRET_TYPE int (0/1/2) and the formatted
        # secret string; it is untyped (Any) so this call site needs no cast.
        collected.append((secret_type, str(secret)))

    worker = NTDSHashes(
        ntdsFile=str(ntds_path),
        bootKey=boot_key,
        isRemote=False,
        useVSSMethod=True,
        justNTLM=False,
        history=True,
        noLMHash=False,
        perSecretCallback=_callback,
    )
    try:
        worker.dump()
    finally:
        try:
            worker.finish()
        except Exception:  # pragma: no cover - cleanup best-effort
            _log.debug("NTDSHashes.finish() raised during cleanup", exc_info=True)
    return collected


# -----------------------------------------------------------------------------
# Orchestrator
# -----------------------------------------------------------------------------


def extract_secrets(
    *,
    ntds_path: Path | str,
    system_hive_path: Path | str,
    parsed: ParsedNtds,
    store: SecretStore,
    dek: bytes,
    run: IngestRun,
    forest_id: str,
    ntds_source_file: str = "ntds.dit",
    system_source_file: str = "SYSTEM",
    read_path: ImpacketReadPath = ImpacketReadPath.DISSECT_SHIM,
) -> SecretExtractionResult:
    """Recover + encrypt-store NTDS secrets; return the ``node_id -> refs`` map.

    Pipeline: derive the SYSTEM boot key -> scan the 2a parse for identity and
    LAPS/deferred blobs -> run Impacket ``NTDSHashes`` (via the dissect shim when
    available) -> map each recovered secret to its owning ``node_id`` +
    ``SecretType`` -> store every secret encrypted with the ``.dit`` image hash
    as provenance. Secrets are never logged or returned.

    Inputs:
        ntds_path: path to the ``ntds.dit`` (untrusted; validated before read).
        system_hive_path: path to the ``SYSTEM`` hive (the boot-key source).
        parsed: the gated 2a :class:`ParsedNtds` for this same ``.dit`` (identity
            + cleartext/deferred attributes).
        store: an open Module-1 :class:`SecretStore` for this case.
        dek: the 32-byte case data key (from the keyring).
        run: the :class:`IngestRun`; both ``ntds_source_file`` and
            ``system_source_file`` must already be registered (provenance).
        forest_id: the scoping forest id used to mint ``node_id`` (must match
            Module 3).
        ntds_source_file / system_source_file: logical artifact names for
            provenance lookup on ``run``.
        read_path: preferred Impacket ESE read path (shim vs native).

    Returns:
        A :class:`SecretExtractionResult` (references + counts only).

    Failure modes:
        Raises :class:`ImpacketUnavailableError` if Impacket cannot be imported;
        ``KeyError`` if ``ntds_source_file`` / ``system_source_file`` are not
        registered on ``run`` (provenance is mandatory — fail fast);
        ``ValueError`` if ``dek`` is not 32 bytes. Individual unmappable/
        undecodable/duplicate secrets degrade to counted gaps, never a crash.
    """
    if len(dek) != 32:
        raise ValueError("DEK must be 32 bytes for AES-256-GCM")
    _require_impacket()

    # Provenance is mandatory: resolve both artifacts up-front (raises KeyError
    # if unregistered). The secret material lives in the .dit, so its image hash
    # is the producing-artifact provenance recorded on every stored secret.
    dit_sha256 = run.provenance_for(ntds_source_file).image_sha256
    run.provenance_for(system_source_file)  # assert the SYSTEM hive is registered

    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        dit_resolved = ensure_existing_file(ntds_path)
        system_resolved = ensure_existing_file(system_hive_path)
    except PathSafetyError as exc:
        raise SecretExtractionError(str(exc)) from exc

    boot_key = _derive_boot_key(system_resolved)
    bootkey_derived = bool(boot_key)

    use_shim = read_path == ImpacketReadPath.DISSECT_SHIM and _apply_dissect_shim()
    used_path = ImpacketReadPath.DISSECT_SHIM if use_shim else ImpacketReadPath.IMPACKET_NATIVE

    # Pass 1 (deterministic, DNT order): identity index + LAPS/deferred blobs.
    gap_counts: dict[str, int] = {}
    identity, deferred_secrets, non_byte_blobs = _scan_objects(parsed, forest_id)
    if non_byte_blobs:
        _record_gap(run, gap_counts, _GAP_NON_BYTE_BLOB, non_byte_blobs)

    # Pass 2: Impacket secret enumeration + pure mapping to node/type.
    credential_secrets: list[MappedSecret] = []
    for secret_type_int, line in _collect_raw_secrets(dit_resolved, boot_key, use_shim=use_shim):
        line_result = map_secret_line(secret_type_int, line, identity)
        credential_secrets.extend(line_result.mapped)
        for reason in line_result.gaps:
            _record_gap(run, gap_counts, reason)

    # Store everything (deferred blobs + recovered credentials) in a deterministic
    # order so processing is reproducible (ciphertext itself still varies).
    all_secrets = sorted(
        [*deferred_secrets, *credential_secrets],
        key=lambda s: (s.node_id, s.secret_type.value, s.label, s.account),
    )

    node_refs: dict[str, list[StoredSecretRef]] = {}
    type_counts: dict[SecretType, int] = {}
    for secret in all_secrets:
        ref = _store_one(store, dek, run, secret, dit_sha256, gap_counts)
        if ref is None:
            continue
        node_refs.setdefault(secret.node_id, []).append(ref)
        type_counts[secret.secret_type] = type_counts.get(secret.secret_type, 0) + 1
        run.bump_coverage(_COV_STORED)

    frozen_refs: dict[str, tuple[StoredSecretRef, ...]] = {
        node_id: tuple(sorted(refs, key=lambda r: (r.secret_type.value, r.label)))
        for node_id, refs in sorted(node_refs.items())
    }

    return SecretExtractionResult(
        node_secret_refs=frozen_refs,
        type_counts=dict(sorted(type_counts.items(), key=lambda kv: kv[0].value)),
        gap_counts=dict(sorted(gap_counts.items())),
        accounts_with_secrets=len(frozen_refs),
        bootkey_derived=bootkey_derived,
        read_path=used_path,
    )


def _store_one(
    store: SecretStore,
    dek: bytes,
    run: IngestRun,
    secret: MappedSecret,
    dit_sha256: str,
    gap_counts: dict[str, int],
) -> StoredSecretRef | None:
    """Encrypt-store one :class:`MappedSecret`; return its ref or a counted gap.

    Minimises plaintext lifetime (wrap -> put -> drop). A duplicate
    ``secret_id`` (append-only store) becomes a counted ``duplicate_secret`` gap
    rather than a crash. Never logs the payload.
    """
    try:
        secret_id = store.put_secret(
            dek,
            ingest_run_id=run.ingest_run_id,
            secret_type=secret.secret_type,
            node_id=secret.node_id,
            plaintext=SecretBytes(secret.payload),
            label=secret.label,
            image_sha256=dit_sha256,
        )
    except SecretAlreadyStoredError:
        _record_gap(run, gap_counts, _GAP_DUPLICATE_SECRET)
        _log.warning(
            "duplicate secret for node (append-only): type=%s label=%s",
            secret.secret_type.value,
            secret.label,
        )
        return None
    return StoredSecretRef(
        secret_id=secret_id,
        secret_type=secret.secret_type,
        label=secret.label,
        decrypted=secret.decrypted,
        decryptable_offline=secret.decryptable_offline,
    )


def _record_gap(run: IngestRun, gap_counts: dict[str, int], reason: str, count: int = 1) -> None:
    """Count a gap both on the run ledger and in the local result tally."""
    gap_counts[reason] = gap_counts.get(reason, 0) + count
    run.bump_skip(reason, count)


def summarise_counts(secrets: Iterable[MappedSecret]) -> dict[SecretType, int]:
    """Count mapped secrets by :class:`SecretType` (pure; test helper)."""
    counts: dict[SecretType, int] = {}
    for secret in secrets:
        counts[secret.secret_type] = counts.get(secret.secret_type, 0) + 1
    return counts
