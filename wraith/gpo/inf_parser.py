"""``GptTmpl.inf`` parsing via stdlib ``configparser`` (reuse, don't reinvent).

Two must-get-right gotchas (research 10 §6), both silent-corruption traps if
missed:

* **Encoding** — ``GptTmpl.inf`` declares ``[Unicode] Unicode=yes`` and is
  (on the real DC) UTF-16LE with a BOM. ``configparser.read()`` with the default
  locale encoding would choke/mangle; we detect the BOM and decode the bytes
  ourselves, then feed the text to ``read_string``.
* **Key case** — ``configparser`` lowercases option keys by default, which would
  destroy privilege names (``SeBackupPrivilege``) and ``*SID__Members`` keys. We
  subclass ``RawConfigParser`` to override ``optionxform`` to the identity so
  keys are preserved verbatim.

A decode/parse failure never raises out of here: it returns a ``GptTmplData``
with ``parse_ok=False`` (a counted gap at the engine).
"""

from __future__ import annotations

import configparser
import logging

from wraith.gpo.models import GptTmplData, GroupMembership, PrivilegeRight

_log = logging.getLogger(__name__)

#: Section headers we extract (matched case-insensitively against the raw name).
_SECTION_PRIVILEGE_RIGHTS: str = "privilege rights"
_SECTION_GROUP_MEMBERSHIP: str = "group membership"
_SECTION_REGISTRY_VALUES: str = "registry values"


class _CasePreservingParser(configparser.RawConfigParser):
    """A ``RawConfigParser`` that preserves option-key case (identity xform).

    Overriding ``optionxform`` (instead of assigning ``str`` to the attribute)
    keeps it a method, which is both correct and mypy-``strict`` clean.
    """

    def optionxform(self, optionstr: str) -> str:  # noqa: D102 - trivial override
        return optionstr


def decode_inf_bytes(raw: bytes) -> str:
    """Decode ``GptTmpl.inf`` bytes to text, honoring a UTF-16/UTF-8 BOM.

    Inputs:
        raw: the raw file bytes.

    Returns:
        The decoded text. A UTF-16 BOM (``FF FE`` / ``FE FF``) decodes as
        UTF-16; a UTF-8 BOM decodes as UTF-8; otherwise UTF-8 is tried and
        Latin-1 is the never-fail fallback (so we never raise on odd bytes).

    Failure modes:
        Never raises.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _split_valuelist(raw_value: str) -> tuple[str, ...]:
    """Split a comma-separated secedit valuelist, stripping ``*`` SID prefixes.

    ``*S-1-5-32-544,*S-1-5-32-549`` -> ``("S-1-5-32-544", "S-1-5-32-549")``.
    Empty tokens are dropped. A bare group-name token keeps its text (only the
    leading ``*`` SID marker is removed).
    """
    tokens: list[str] = []
    for part in raw_value.split(","):
        token = part.strip()
        if not token:
            continue
        tokens.append(token[1:] if token.startswith("*") else token)
    return tuple(tokens)


def _parse_group_key(key: str) -> tuple[str, str] | None:
    """Split a ``[Group Membership]`` key into ``(group_token, relation)``.

    ``*S-1-5-32-544__Members`` -> ``("S-1-5-32-544", "Members")``;
    ``CORP\\helpdesk__Memberof`` -> ``("CORP\\helpdesk", "Memberof")``. Returns
    ``None`` if the key has neither recognized suffix.
    """
    for suffix, relation in (("__Members", "Members"), ("__Memberof", "Memberof")):
        if key.endswith(suffix):
            group = key[: -len(suffix)].strip()
            group = group[1:] if group.startswith("*") else group
            return group, relation
    return None


def parse_gpttmpl(raw: bytes) -> GptTmplData:
    """Parse a ``GptTmpl.inf`` blob into its attack-relevant sections.

    Inputs:
        raw: the raw file bytes (any BOM; see :func:`decode_inf_bytes`).

    Returns:
        A :class:`GptTmplData`. On a decode/parse error, ``parse_ok=False`` with
        empty sections (the caller counts a gap). ``[Privilege Rights]`` and
        ``[Group Membership]`` SIDs have their ``*`` prefix stripped;
        ``[Registry Values]`` is preserved verbatim as ``(key, raw_value)``.

    Failure modes:
        Never raises — configparser errors degrade to ``parse_ok=False``.
    """
    try:
        text = decode_inf_bytes(raw)
    except Exception as exc:  # defensive: decode is already fallback-safe
        _log.debug("gpo: GptTmpl decode failed: %s", type(exc).__name__)
        return GptTmplData(parse_ok=False)

    # RawConfigParser: no interpolation; '=' only delimiter; tolerate duplicate
    # keys (strict=False); do not treat ';' as an inline comment (reg paths /
    # values can contain it). '#'-prefixed full lines remain comments (benign).
    parser = _CasePreservingParser(
        strict=False,
        delimiters=("=",),
        comment_prefixes=("#",),
        inline_comment_prefixes=None,
        interpolation=None,
    )
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        _log.debug("gpo: GptTmpl parse failed: %s", type(exc).__name__)
        return GptTmplData(parse_ok=False)

    privileges: list[PrivilegeRight] = []
    memberships: list[GroupMembership] = []
    registry_values: list[tuple[str, str]] = []

    for section in parser.sections():
        lowered = section.strip().lower()
        if lowered == _SECTION_PRIVILEGE_RIGHTS:
            for key, value in parser.items(section):
                privileges.append(PrivilegeRight(name=key.strip(), holders=_split_valuelist(value)))
        elif lowered == _SECTION_GROUP_MEMBERSHIP:
            for key, value in parser.items(section):
                parsed_key = _parse_group_key(key.strip())
                if parsed_key is None:
                    continue
                group_token, relation = parsed_key
                memberships.append(
                    GroupMembership(
                        group_token=group_token,
                        relation=relation,
                        values=_split_valuelist(value),
                    )
                )
        elif lowered == _SECTION_REGISTRY_VALUES:
            for key, value in parser.items(section):
                registry_values.append((key.strip(), value.strip()))

    return GptTmplData(
        privilege_rights=tuple(privileges),
        group_memberships=tuple(memberships),
        registry_values=tuple(registry_values),
        parse_ok=True,
    )
