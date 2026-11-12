"""Offline Enterprise-CA-host registry adapter (fills :class:`CaHostFacts`).

Reads a CA host's ``SYSTEM`` + ``SOFTWARE`` registry hives FULLY OFFLINE via
Impacket ``winregistry`` (the SAME seam the DC-config reader uses — no new
dependency, no network, Linux-clean, deterministic) and builds the frozen
:class:`~wraith.analysis.adcs_esc.CaHostFacts` the ADCS-ESC composer consumes to
decide ESC6/ESC7/ESC11/ESC16 (research ``docs/research/28-ca-host-registry-
adapter.md``).

Design rules (CLAUDE.md quality bar): the hive paths are UNTRUSTED (validated by
``ensure_existing_file``; nothing from the artifact is executed); every value read
is GUARDED end-to-end so a missing/malformed value degrades to ``None`` (an
undecidable value the composer later counts as a specific gap) — never a crash and
never a guessed default; the security-descriptor parse is delegated to
``impacket.ldap.ldaptypes`` (CLAUDE.md: never hand-roll an SD parser); provenance
is attached at creation; and the output is a pure function of the input bytes.

SPIKE (empirically confirmed against a real binary hive, Impacket 0.13.1):
``Registry.getValue`` returns ``(ValueType, data)`` where ``data`` is

* REG_DWORD -> ``int`` (small inline values live in the record's 4-byte field);
* REG_SZ -> ``bytes`` (UTF-16LE, NUL-terminated) for >4-byte strings, but an
  ``int`` for a <=4-byte inline string (e.g. ``EnableDCOM="Y"`` came back as the
  int ``0x0059`` — UTF-16LE ``"Y"``);
* REG_MULTI_SZ -> ``bytes`` (UTF-16LE, each string NUL-separated, list
  double-NUL-terminated);
* REG_BINARY -> ``bytes``;
* a zero-length value -> ``''`` (empty ``str``).

The guarded readers below normalize every one of those shapes.

SPIKE (provenance, empirically confirmed against the real ``eviedence_test``
SYSTEM/SOFTWARE hives, Impacket 0.13.1 ``saveRegistryParser``): the per-key
LastWrite IS reachable through the vendored API — ``reader.findKey(path)`` returns
the ``nk`` key record (``REG_NK``) whose ``lastChange`` field is the key LastWrite
FILETIME (``getValue`` only reaches VALUES, not the key record). It is therefore
wired into ``directory_timestamp`` (deterministic; artifact data, not wall-clock)
from the CA ``Configuration\\<CAName>`` key (CA facts) and the ``\\Microsoft\\Ole``
key (DCOM) — see :func:`_key_lastwrite`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from wraith.analysis.adcs_esc import (
    CA_RIGHT_MANAGE_CA,
    CA_RIGHT_MANAGE_CERTIFICATES,
    CaHostFacts,
    CaRegistryFacts,
    DcomRestrictions,
    _open_system_hive,
    _read_dword,
    normalize_ca_name,
)
from wraith.provenance.models import ProvenanceStruct

_log = logging.getLogger(__name__)

#: Public [MS-DTYP] ACE-type ints (ALLOW/DENY, object + non-object). CA ``Security``
#: uses the non-object forms, but both are handled for robustness.
_ACE_ALLOWED: int = 0x00
_ACE_ALLOWED_OBJECT: int = 0x05
_ACE_DENIED: int = 0x01
_ACE_DENIED_OBJECT: int = 0x06

#: Stock default active policy-module subkey ([MS-CSRA]); only used as a fallback
#: when ``PolicyModules\Active`` is unreadable (research §3.2).
DEFAULT_POLICY_MODULE: str = "CertificationAuthority_MicrosoftDefault.Policy"

#: CertSvc configuration base, relative to the resolved ControlSet.
_CERTSVC_BASE: str = "Services\\CertSvc\\Configuration"
#: SOFTWARE OLE base (no ControlSet; SOFTWARE has no CurrentControlSet alias).
_OLE_BASE: str = "\\Microsoft\\Ole"


# =============================================================================
# Guarded value readers (mirror ``adcs_esc._read_dword``; never raise)
# =============================================================================


def _get_value(reader: object, key_path: str) -> object | None:
    """Return the raw ``getValue`` payload for ``key_path``, or ``None`` if absent.

    Guarded end-to-end: a missing key or any Impacket exception degrades to
    ``None`` (never a crash). Returns the second element of Impacket's
    ``(ValueType, data)`` tuple.
    """
    try:
        result = reader.getValue(key_path)  # type: ignore[attr-defined]
    except Exception as exc:  # absent key / malformed hive node -> None
        _log.debug("ca-host: value %s unreadable: %s", key_path, type(exc).__name__)
        return None
    if not result:
        return None
    data: object = result[1]
    return data


def _utf16_first(raw: bytes) -> str | None:
    """Decode UTF-16LE bytes and return the first NUL-delimited token, or ``None``."""
    text = raw.decode("utf-16le", errors="replace")
    token = text.split("\x00", 1)[0]
    return token or None


def _read_sz(reader: object, key_path: str) -> str | None:
    """Read one REG_SZ value as a Python ``str``, or ``None`` if absent/unreadable.

    Handles all three SPIKE-confirmed shapes: ``bytes`` (UTF-16LE, NUL-terminated),
    an inline ``int`` (<=4-byte string packed into the record field), and ``''``
    (a zero-length value -> ``None``, i.e. "present but empty" is not a usable name).
    Guarded; never raises.
    """
    data = _get_value(reader, key_path)
    if data is None:
        return None
    if isinstance(data, str):  # Impacket returns '' for a zero-length value
        return data or None
    if isinstance(data, bool):  # bool is an int subclass; not a string payload
        return None
    if isinstance(data, int):
        return _utf16_first((data & 0xFFFF_FFFF).to_bytes(4, "little"))
    if isinstance(data, (bytes, bytearray)):
        return _utf16_first(bytes(data))
    return None


def _read_multi_sz(reader: object, key_path: str) -> tuple[str, ...] | None:
    """Read one REG_MULTI_SZ value as a tuple of strings, or ``None`` if unreadable.

    ``None`` means UNREAD (the value key is absent) -> the composer counts a gap;
    a read value that is empty returns ``()`` (DECIDED, no gap) — the two are kept
    distinct exactly like :class:`~wraith.analysis.adcs_esc.DcConfigFlags.hive_read`.
    Tokenizes UTF-16LE on the NUL separator, dropping empty (terminator) tokens.
    Guarded; never raises.
    """
    data = _get_value(reader, key_path)
    if data is None:
        return None
    if isinstance(data, str):  # zero-length value -> read-empty, DECIDED
        return (data,) if data else ()
    if isinstance(data, bool):
        return None
    if isinstance(data, int):
        raw = (data & 0xFFFF_FFFF).to_bytes(4, "little")
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        return None
    text = raw.decode("utf-16le", errors="replace")
    return tuple(part for part in text.split("\x00") if part)


def _read_binary(reader: object, key_path: str) -> bytes | None:
    """Read one REG_BINARY value as ``bytes``, or ``None`` if absent/unreadable.

    A security descriptor is always >4 bytes, so an inline ``int``/empty ``str``
    payload is treated as "not a descriptor" -> ``None`` (the composer counts the
    matching absent gap). Guarded; never raises.
    """
    data = _get_value(reader, key_path)
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return None


#: Windows FILETIME epoch (1601-01-01 UTC); the ``nk`` key record's ``lastChange``
#: is 100-nanosecond intervals since this instant.
_FILETIME_EPOCH: datetime = datetime(1601, 1, 1, tzinfo=UTC)


def _filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert a Windows FILETIME (100-ns since 1601) to a UTC ``datetime``.

    Deterministic and purely arithmetic (artifact data, not wall-clock). ``0`` (an
    unset LastWrite) and any out-of-range value degrade to ``None``; never raises.
    """
    if filetime <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (OverflowError, ValueError, OSError):  # implausible FILETIME -> no stamp
        return None


def _key_lastwrite(reader: object, key_path: str) -> datetime | None:
    """Return a registry key's LastWrite time as a UTC ``datetime``, or ``None``.

    SPIKE (confirmed against the real ``eviedence_test`` SYSTEM/SOFTWARE hives with
    Impacket ``winregistry`` 0.13.1, ``saveRegistryParser``): ``reader.findKey(path)``
    returns the ``nk`` key record (``REG_NK``) whose ``lastChange`` field is the
    per-key LastWrite FILETIME — exposed at the KEY level (``getValue`` only reaches
    values). A missing key yields ``None``; the read is deterministic. Guarded
    end-to-end: a reader without ``findKey`` (e.g. a test stub) or any Impacket
    exception degrades to ``None`` — never a crash. This is a WRAITH provenance
    non-negotiable AND a hunt signal (a fresh LastWrite on the CA ``Configuration``
    key = a recently re-weaponized CA).
    """
    find_key = getattr(reader, "findKey", None)
    if not callable(find_key):
        return None
    try:
        nk = find_key(key_path)
        if nk is None:
            return None
        return _filetime_to_datetime(int(nk["lastChange"]))
    except Exception as exc:  # malformed nk / absent field -> no stamp, never crash
        _log.debug("ca-host: key %s LastWrite unreadable: %s", key_path, type(exc).__name__)
        return None


# =============================================================================
# CA ``Security`` descriptor -> effective ManageCA / ManageCertificates grantees
# =============================================================================


def _parse_ca_security_counted(
    sd_bytes: bytes,
) -> tuple[frozenset[str], frozenset[str], int] | None:
    """Parse a CA ``Security`` descriptor, also returning the per-ACE skip count.

    The real implementation behind :func:`parse_ca_security`; see that function for
    the semantics. The third tuple element is the number of individual DACL ACEs
    that could not be decoded (a per-ACE degrade during an otherwise-successful
    parse). ``None`` is still returned for a top-level parse failure (distinct from
    "no grant"). Never raises.
    """
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception as exc:  # malformed/truncated SD -> counted gap, never crash
        _log.debug("ca-host: unparseable CA Security descriptor: %s", type(exc).__name__)
        return None

    try:
        dacl = sd["Dacl"]
    except Exception as exc:
        _log.debug("ca-host: unreadable CA DACL: %s", type(exc).__name__)
        return frozenset(), frozenset(), 0
    if not dacl or not hasattr(dacl, "aces"):
        return frozenset(), frozenset(), 0

    allow: dict[str, int] = {}
    deny: dict[str, int] = {}
    ace_skipped = 0
    for ace in dacl.aces:
        try:
            ace_type = int(ace["AceType"])
            body = ace["Ace"]
            mask = int(body["Mask"]["Mask"])
            sid = body["Sid"].formatCanonical()
        except Exception as exc:  # one malformed ACE -> skip it only, never crash
            # A dropped ACE could have carried a ManageCA/Officer grant (false-
            # negative bias), so it is COUNTED (coverage-class), never silent.
            ace_skipped += 1
            _log.debug("ca-host: undecodable CA ACE (skipped): %s", type(exc).__name__)
            continue
        if ace_type in (_ACE_ALLOWED, _ACE_ALLOWED_OBJECT):
            allow[sid] = allow.get(sid, 0) | mask
        elif ace_type in (_ACE_DENIED, _ACE_DENIED_OBJECT):
            deny[sid] = deny.get(sid, 0) | mask

    manage_ca: set[str] = set()
    manage_cert: set[str] = set()
    for sid, allow_mask in allow.items():
        effective = allow_mask & ~deny.get(sid, 0)
        if effective & CA_RIGHT_MANAGE_CA:
            manage_ca.add(sid)
        if effective & CA_RIGHT_MANAGE_CERTIFICATES:
            manage_cert.add(sid)
    return frozenset(manage_ca), frozenset(manage_cert), ace_skipped


def parse_ca_security(sd_bytes: bytes) -> tuple[frozenset[str], frozenset[str]] | None:
    """Parse a CA ``Security`` descriptor into (ManageCA, ManageCertificates) SIDs.

    Delegates the binary parse to ``impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR``
    (never hand-rolled). Applies SID-level **deny-before-allow**: a grantee's
    effective mask is ``union(allow) & ~union(deny)`` for that exact SID, then the
    ManageCA (``0x1``) / ManageCertificates (``0x2``) bits select the role sets.
    Group-level cross-principal deny is NOT expanded here (members reach the CA via
    their own ``MemberOf`` traversal, exactly as the M5 base ACL edges model it).

    Inputs:
        sd_bytes: the raw self-relative security-descriptor bytes.

    Returns:
        ``(manage_ca_sids, manage_cert_sids)`` (either may be empty = decided-none),
        or ``None`` if the descriptor could not be parsed at all (the caller counts
        this as ``ca_security_parse_error`` — distinct from "no grant"). The adapter
        reads the per-ACE skip count via :func:`_parse_ca_security_counted`.

    Failure modes:
        Never raises; a top-level parse failure returns ``None`` and a per-ACE
        decode failure skips that ACE only (counted by the adapter).
    """
    parsed = _parse_ca_security_counted(sd_bytes)
    if parsed is None:
        return None
    manage_ca, manage_cert, _ace_skipped = parsed
    return manage_ca, manage_cert


# =============================================================================
# Hive -> CaHostFacts (the public adapter entry point)
# =============================================================================


def _resolve_control_set(reader: object) -> str:
    """Return the resolved ``ControlSetNNN`` name (default ``ControlSet001``).

    Mirrors :func:`wraith.analysis.adcs_esc.read_dc_config_flags`: CertSvc config
    lives under the SAME resolved ControlSet (it is a ``Services`` subkey).
    """
    current = _read_dword(reader, "\\Select\\Current")
    return f"ControlSet{current:03d}" if current is not None else "ControlSet001"


def _read_one_ca(
    reader: object, control_set: str, prov: ProvenanceStruct
) -> CaRegistryFacts | None:
    """Read the single active CA's registry facts from an open ``SYSTEM`` reader.

    Uses ``Configuration\\Active`` as the CA name (correlation key); returns
    ``None`` when no active CA name is present (the host runs no CA, or the value
    is unreadable) so the caller leaves ``cas`` empty and every graph CA falls
    through to a LOUD counted gap. Pure w.r.t. ``reader``; never raises.
    """
    base = f"\\{control_set}\\{_CERTSVC_BASE}"
    active = _read_sz(reader, f"{base}\\Active")
    if not active:
        _log.warning("ca-host: no active CA name under %s\\Active", base)
        return None

    ca_base = f"{base}\\{active}"
    security_sd = _read_binary(reader, f"{ca_base}\\Security")
    manage_ca: frozenset[str] = frozenset()
    manage_cert: frozenset[str] = frozenset()
    security_parse_error = False
    security_ace_skipped = 0
    if security_sd is not None:
        parsed = _parse_ca_security_counted(security_sd)
        if parsed is None:
            # Parse failure: flag it DISTINCTLY (security_parse_error) so the composer
            # counts ca_security_parse_error (present-but-unparseable), NOT
            # ca_security_absent. KEEP security_sd=None so NO ManageCA edge is ever
            # emitted from a grant set we could not compute (false-positive-forbidden).
            _log.warning("ca-host: CA %s Security present but unparseable", active)
            security_sd = None
            security_parse_error = True
        else:
            manage_ca, manage_cert, security_ace_skipped = parsed

    interface_flags = _read_dword(reader, f"{ca_base}\\InterfaceFlags")

    active_module = _read_sz(reader, f"{ca_base}\\PolicyModules\\Active")
    module = active_module or DEFAULT_POLICY_MODULE
    pm_base = f"{ca_base}\\PolicyModules\\{module}"
    edit_flags = _read_dword(reader, f"{pm_base}\\EditFlags")
    disable_ext = _read_multi_sz(reader, f"{pm_base}\\DisableExtensionList")
    policy_resolved = active_module is not None or edit_flags is not None or disable_ext is not None

    # Provenance directory_timestamp = the CA ``Configuration\<CAName>`` key LastWrite
    # (where Security/InterfaceFlags live). A fresh stamp is a weaponization signal;
    # EditFlags/DisableExtensionList live under the ``PolicyModules\<active>`` subkey
    # whose own LastWrite differs — the per-CA anchor uses the CA config key.
    key_ts = _key_lastwrite(reader, ca_base)
    ca_prov = prov if key_ts is None else prov.model_copy(update={"directory_timestamp": key_ts})

    return CaRegistryFacts(
        ca_name=active,
        host_fqdn=None,
        security_sd=security_sd,
        manage_ca_sids=manage_ca,
        manage_cert_sids=manage_cert,
        edit_flags=edit_flags,
        interface_flags=interface_flags,
        disable_extension_list=disable_ext,
        policy_module_resolved=policy_resolved,
        provenance=ca_prov,
        security_parse_error=security_parse_error,
        security_ace_skipped=security_ace_skipped,
    )


def _read_dcom(reader: object, prov: ProvenanceStruct) -> DcomRestrictions:
    """Read the machine-wide DCOM restrictions from an open ``SOFTWARE`` reader.

    Every value is independently guarded; an all-``None`` result is returned as-is
    (the composer then counts ``dcom_restrictions_absent``). The provenance
    ``directory_timestamp`` is the ``\\Microsoft\\Ole`` key LastWrite when readable.
    Pure; never raises.
    """
    key_ts = _key_lastwrite(reader, _OLE_BASE)
    ole_prov = prov if key_ts is None else prov.model_copy(update={"directory_timestamp": key_ts})
    return DcomRestrictions(
        enable_dcom=_read_sz(reader, f"{_OLE_BASE}\\EnableDCOM"),
        machine_access_sd=_read_binary(reader, f"{_OLE_BASE}\\MachineAccessRestriction"),
        machine_launch_sd=_read_binary(reader, f"{_OLE_BASE}\\MachineLaunchRestriction"),
        default_access_sd=_read_binary(reader, f"{_OLE_BASE}\\DefaultAccessPermission"),
        default_launch_sd=_read_binary(reader, f"{_OLE_BASE}\\DefaultLaunchPermission"),
        provenance=ole_prov,
    )


def _close(reader: object) -> None:
    """Best-effort close of an Impacket registry reader (never raises)."""
    close = getattr(reader, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # pragma: no cover - best-effort cleanup
            _log.debug("ca-host: hive close raised", exc_info=True)


def _hive_provenance(path: Path, source_file: str, ingest_run_id: UUID) -> ProvenanceStruct:
    """Build the base HIVE provenance anchor for one CA-host hive (SHA-256 of image).

    ``directory_timestamp`` starts ``None`` here; the per-CA / DCOM readers refine it
    to the relevant registry KEY's LastWrite FILETIME via :func:`_key_lastwrite`
    (SPIKE-confirmed reachable through ``winregistry.findKey(...).['lastChange']``,
    deterministic, artifact data). May raise if ``sha256_file`` fails — the caller
    wraps this so ``build_ca_host_facts`` degrades to a counted
    ``ca_host_hive_read_error`` instead of propagating.
    """
    from wraith.acquisition.hashing import sha256_file

    return ProvenanceStruct(
        source_file=source_file,
        image_sha256=sha256_file(path),
        source_object_id=None,
        directory_timestamp=None,
        ingest_run_id=ingest_run_id,
    )


def build_ca_host_facts(
    *,
    system_hive_path: Path | str,
    ingest_run_id: UUID,
    software_hive_path: Path | str | None = None,
    host_fqdn: str | None = None,
    system_source_file: str = "CAHOST/SYSTEM",
    software_source_file: str = "CAHOST/SOFTWARE",
) -> tuple[CaHostFacts, int]:
    """Build :class:`CaHostFacts` from a CA host's ``SYSTEM`` (+ ``SOFTWARE``) hives.

    Reads, fully offline via Impacket ``winregistry`` (NO new dependency, NO
    network): the active CA's ``Security`` / ``InterfaceFlags`` /
    ``PolicyModules\\<active>\\EditFlags`` / ``DisableExtensionList`` from
    ``SYSTEM``, and (when supplied) the machine-wide ``Microsoft\\Ole`` DCOM
    restrictions from ``SOFTWARE``. The hive paths are UNTRUSTED — each is validated
    by ``ensure_existing_file`` and read with bounded, guarded value reads; nothing
    from the artifact is executed.

    Inputs:
        system_hive_path: the CA host ``SYSTEM`` hive (required).
        ingest_run_id: the run id stamped into every hive provenance struct.
        software_hive_path: the CA host ``SOFTWARE`` hive (optional; DCOM plane).
        host_fqdn: operator-supplied CA host FQDN (for the ``hosts_ca`` cross-check).
        system_source_file/software_source_file: provenance ``source_file`` labels.

    Returns:
        ``(CaHostFacts, hive_read_errors)`` — the facts (``provided=True`` once the
        SYSTEM path was accepted, even if a value is unreadable) and the count of
        hive-level read errors (a rejected/unopenable hive). ``hive_read_errors`` is
        surfaced by the run as ``adcs.ca_host_hive_read_error``; a value simply
        being UNSET is NOT an error (it is an undecidable ``None`` the composer
        counts as its own specific gap), so the two concerns stay distinct.

    Failure modes:
        Never raises; an unopenable/rejected SYSTEM hive degrades to
        ``CaHostFacts(provided=False)`` (the absent-accounting path) with
        ``hive_read_errors >= 1``.
    """
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    errors = 0
    cas: dict[str, CaRegistryFacts] = {}
    try:
        system_resolved = ensure_existing_file(system_hive_path)
    except PathSafetyError as exc:
        _log.warning("ca-host: SYSTEM hive path rejected: %s", exc)
        return CaHostFacts(provided=False), 1

    try:
        reader = _open_system_hive(system_resolved)
    except Exception as exc:
        _log.warning("ca-host: SYSTEM hive unreadable (%s)", type(exc).__name__)
        return CaHostFacts(provided=False), 1

    try:
        control_set = _resolve_control_set(reader)
        prov = _hive_provenance(system_resolved, system_source_file, ingest_run_id)
        ca = _read_one_ca(reader, control_set, prov)
    except Exception as exc:
        # _read_one_ca is guarded; the realistic raiser is _hive_provenance ->
        # sha256_file. Without provenance we cannot attach a non-negotiable anchor,
        # so degrade to the LOUD absent-accounting path with a counted hive error
        # (build_ca_host_facts truly never raises).
        _log.warning("ca-host: SYSTEM provenance/read failed (%s)", type(exc).__name__)
        return CaHostFacts(provided=False), errors + 1
    finally:
        _close(reader)

    if ca is not None:
        ca = _with_host_fqdn(ca, host_fqdn)
        cas[normalize_ca_name(ca.ca_name)] = ca

    dcom, dcom_errors = _build_dcom(software_hive_path, ingest_run_id, software_source_file)
    errors += dcom_errors

    return CaHostFacts(provided=True, cas=cas, dcom=dcom), errors


def _with_host_fqdn(ca: CaRegistryFacts, host_fqdn: str | None) -> CaRegistryFacts:
    """Return ``ca`` with ``host_fqdn`` set (frozen dataclasses are not mutated)."""
    if host_fqdn is None:
        return ca
    return CaRegistryFacts(
        ca_name=ca.ca_name,
        host_fqdn=host_fqdn,
        security_sd=ca.security_sd,
        manage_ca_sids=ca.manage_ca_sids,
        manage_cert_sids=ca.manage_cert_sids,
        edit_flags=ca.edit_flags,
        interface_flags=ca.interface_flags,
        disable_extension_list=ca.disable_extension_list,
        policy_module_resolved=ca.policy_module_resolved,
        provenance=ca.provenance,
        security_parse_error=ca.security_parse_error,
        security_ace_skipped=ca.security_ace_skipped,
    )


def _build_dcom(
    software_hive_path: Path | str | None, ingest_run_id: UUID, source_file: str
) -> tuple[DcomRestrictions | None, int]:
    """Read the ``SOFTWARE`` DCOM plane, or ``(None, errors)`` if absent/unreadable.

    A missing ``SOFTWARE`` path is not an error (``(None, 0)`` -> the composer
    counts ``dcom_restrictions_absent``); a rejected/unopenable supplied path is a
    counted hive read error.
    """
    if software_hive_path is None:
        return None, 0
    from wraith.acquisition.paths import PathSafetyError, ensure_existing_file

    try:
        resolved = ensure_existing_file(software_hive_path)
    except PathSafetyError as exc:
        _log.warning("ca-host: SOFTWARE hive path rejected: %s", exc)
        return None, 1
    try:
        reader = _open_system_hive(resolved)
    except Exception as exc:
        _log.warning("ca-host: SOFTWARE hive unreadable (%s)", type(exc).__name__)
        return None, 1
    try:
        prov = _hive_provenance(resolved, source_file, ingest_run_id)
        dcom = _read_dcom(reader, prov)
    except Exception as exc:
        # _hive_provenance -> sha256_file may raise; degrade to a counted hive read
        # error (the DCOM plane is then absent) rather than propagating.
        _log.warning("ca-host: SOFTWARE provenance/read failed (%s)", type(exc).__name__)
        return None, 1
    finally:
        _close(reader)
    return dcom, 0


def ca_names_in(facts: CaHostFacts) -> Mapping[str, CaRegistryFacts]:
    """Return the per-CA facts mapping (keyed by normalized CA name). Pure helper."""
    return facts.cas
