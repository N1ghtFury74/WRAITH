"""GPP ``Groups.xml`` parsing (ElementTree) + [MS-GPPREF] ``cpassword`` decrypt.

Group Policy Preferences store Local-Users-and-Groups actions as XML (not INF).
Our real SYSVOL has none, so this path is synthetic-tested, but it is the second
way local admin is pushed and is parsed natively here. Two concerns:

* :func:`parse_groups_xml` — ``<Group>``/``<Member action=...>`` -> the local
  group SID/name and its member actions (``ADD``/``REMOVE``). GPP uses per-member
  actions (vs Restricted Groups' authoritative replace); the engine applies
  Restricted-Groups-wins precedence when both target the same group.
* :func:`decrypt_gpp_cpassword` — AES-256-CBC with the PUBLIC [MS-GPPREF] 2.2.1.1
  static key. A recovered cpassword is a SECRET -> the engine routes it to the
  encrypted store by reference and raises a redacted finding, NEVER a graph edge
  and never logged in plaintext.

Security: XML is untrusted input. The stdlib ElementTree is safe against the
offline-critical threats — it does NOT fetch external DTDs and does NOT expand
external entities (so no SSRF / local-file exfiltration via XXE). It is NOT,
however, hardened against INTERNAL entity-expansion blowups (billion-laughs /
quadratic entity expansion); as defense-in-depth we parse with a parser that
rejects any ``<!DOCTYPE>`` outright, so internal-entity definitions cannot be
declared in the first place. We never resolve external resources and never
execute anything. We deliberately do NOT vendor ``defusedxml`` (no new dep).
"""

from __future__ import annotations

import base64
import logging
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wraith.gpo.constants import GPP_STATIC_AES_KEY
from wraith.gpo.models import GppCpassword, GppDocument, GppGroup, GppMember

_log = logging.getLogger(__name__)


def _local(tag: str) -> str:
    """Strip any XML namespace from a tag (``{ns}Group`` -> ``Group``)."""
    return tag.rsplit("}", 1)[-1]


def _attr_ci(elem: ET.Element, name: str) -> str | None:
    """Case-insensitive attribute lookup on an element (GPP casing varies)."""
    target = name.lower()
    for key, value in elem.attrib.items():
        if _local(key).lower() == target:
            return value
    return None


def _parse_xml(raw: bytes) -> ET.Element | None:
    """Parse untrusted GPP XML, returning the root or ``None`` on any rejection.

    Defense-in-depth on untrusted input: any ``<!DOCTYPE>`` is rejected before
    parsing so no internal entity (billion-laughs / quadratic blowup) can be
    declared. External entities / DTD retrieval are already impossible with
    stdlib ElementTree. A reject or genuine parse error returns ``None``.

    Failure modes:
        Never raises.
    """
    if b"<!doctype" in raw.lower():
        _log.debug("gpo: GPP XML rejected: DOCTYPE present")
        return None
    try:
        return ET.fromstring(raw)  # noqa: S314 - DTD rejected above; no ext entities
    except ET.ParseError as exc:
        _log.debug("gpo: GPP XML parse failed: %s", type(exc).__name__)
        return None


def _groups_from_root(root: ET.Element) -> tuple[GppGroup, ...]:
    """Extract ``<Group>`` local-group actions from an already-parsed GPP root."""
    groups: list[GppGroup] = []
    for group_elem in root.iter():
        if _local(group_elem.tag) != "Group":
            continue
        props = next(
            (c for c in group_elem if _local(c.tag) == "Properties"),
            None,
        )
        if props is None:
            continue
        group_sid = _attr_ci(props, "groupSid") or None
        group_name = _attr_ci(props, "groupName") or _attr_ci(group_elem, "name") or None
        members: list[GppMember] = []
        for members_elem in props:
            if _local(members_elem.tag) != "Members":
                continue
            for member_elem in members_elem:
                if _local(member_elem.tag) != "Member":
                    continue
                members.append(
                    GppMember(
                        sid=_attr_ci(member_elem, "sid") or None,
                        name=_attr_ci(member_elem, "name") or None,
                        action=(_attr_ci(member_elem, "action") or "ADD").upper(),
                    )
                )
        groups.append(GppGroup(group_sid=group_sid, group_name=group_name, members=tuple(members)))
    return tuple(groups)


def _cpasswords_from_root(root: ET.Element) -> tuple[GppCpassword, ...]:
    """Extract every element bearing a ``cpassword`` from an already-parsed root.

    The ``cpassword`` is the on-disk obfuscated value (never plaintext here); the
    engine decrypts it to the encrypted store by reference and never logs it.
    """
    found: list[GppCpassword] = []
    for elem in root.iter():
        cpassword: str | None = None
        user_name: str | None = None
        for attr_key, attr_value in elem.attrib.items():
            local = _local(attr_key).lower()
            if local == "cpassword":
                cpassword = attr_value
            elif local in ("username", "newname", "name"):
                user_name = user_name or attr_value
        if cpassword:
            found.append(GppCpassword(cpassword=cpassword, user_name=user_name))
    return tuple(found)


def parse_gpp_document(raw: bytes) -> GppDocument:
    """Parse a GPP ``Groups.xml`` blob ONCE into groups + cpassword elements.

    Inputs:
        raw: the raw XML bytes.

    Returns:
        A :class:`GppDocument`. ``parse_ok=False`` (with empty ``groups`` /
        ``cpasswords``) when the XML cannot be parsed or is rejected for a
        ``<!DOCTYPE>`` — the caller counts that gap exactly once. Otherwise
        ``groups`` holds the ``<Group>`` local-group actions and ``cpasswords``
        holds every element carrying a ``cpassword`` attribute.

    Failure modes:
        Never raises — malformed/rejected XML degrades to ``parse_ok=False``.
    """
    root = _parse_xml(raw)
    if root is None:
        return GppDocument(parse_ok=False)
    return GppDocument(
        groups=_groups_from_root(root),
        cpasswords=_cpasswords_from_root(root),
        parse_ok=True,
    )


def parse_groups_xml(raw: bytes) -> tuple[GppGroup, ...]:
    """Parse a GPP ``Groups.xml`` blob into its local-group actions (convenience).

    Thin wrapper over :func:`parse_gpp_document` for callers that only need the
    group actions. Returns ``()`` on a parse error OR when no group actions are
    present (the two are indistinguishable here — use :func:`parse_gpp_document`
    and its ``parse_ok`` flag when the malformed/empty distinction matters).

    Failure modes:
        Never raises — malformed XML degrades to ``()``.
    """
    return parse_gpp_document(raw).groups


def decrypt_gpp_cpassword(cpassword: str) -> bytes | None:
    """Decrypt a GPP ``cpassword`` with the public [MS-GPPREF] 2.2.1.1 static key.

    The value is base64 (Microsoft omits ``=`` padding), AES-256-CBC with a
    zero IV; the plaintext is UTF-16LE. This reverses a lawfully-held artifact's
    reversible obfuscation (public key), not live credential cracking.

    Inputs:
        cpassword: the ``cpassword`` attribute value (base64, possibly unpadded).

    Returns:
        The decrypted plaintext bytes (still UTF-16LE), or ``None`` if the input
        is empty or cannot be decoded/decrypted.

    Failure modes:
        Never raises — a malformed cpassword returns ``None``.
    """
    if not cpassword:
        return None
    try:
        padded = cpassword + "=" * ((4 - len(cpassword) % 4) % 4)
        blob = base64.b64decode(padded)
        if not blob or len(blob) % 16 != 0:
            return None
        cipher = Cipher(algorithms.AES(GPP_STATIC_AES_KEY), modes.CBC(b"\x00" * 16))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(blob) + decryptor.finalize()
        return _strip_pkcs7(plaintext)
    except Exception as exc:  # untrusted input: never crash
        _log.debug("gpo: cpassword decrypt failed: %s", type(exc).__name__)
        return None


def decrypt_gpp_cpassword_text(cpassword: str) -> str | None:
    """Decrypt a GPP ``cpassword`` and decode the UTF-16LE plaintext to ``str``.

    Returns ``None`` on any failure. The result is a SECRET; callers must route
    it to the encrypted store and never log it.

    Failure modes:
        Never raises.
    """
    raw = decrypt_gpp_cpassword(cpassword)
    if raw is None:
        return None
    try:
        return raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None


def _strip_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding if present and valid; else return ``data`` as-is."""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and pad <= len(data) and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data
