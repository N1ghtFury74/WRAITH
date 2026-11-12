"""SYSVOL filesystem discovery — locate a GPO's policy files on disk.

Treats SYSVOL as an untrusted artifact tree: every path is resolved and
confined under the policy folder (no traversal outside it), files are read as
bytes only, and nothing is executed. Discovery is case-insensitive on the
``MACHINE`` / ``Machine`` and filename components because real SYSVOL casing
varies across the three sample GPOs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: Relative path of the secedit template under a policy folder (case varies).
_GPTTMPL_RELATIVE: tuple[str, ...] = (
    "MACHINE",
    "Microsoft",
    "Windows NT",
    "SecEdit",
    "GptTmpl.inf",
)

#: Relative path of the machine Registry.pol under a policy folder.
_REGISTRY_POL_RELATIVE: tuple[str, ...] = ("MACHINE", "Registry.pol")

#: Relative path of the GPP machine Groups.xml under a policy folder.
_GROUPS_XML_RELATIVE: tuple[str, ...] = (
    "MACHINE",
    "Preferences",
    "Groups",
    "Groups.xml",
)


@dataclass(frozen=True)
class PolicyFiles:
    """The located policy files for one GPO folder (any may be ``None``).

    Attributes:
        folder_guid: the normalized folder GUID (lowercase, no braces).
        gpttmpl: the ``GptTmpl.inf`` path, if present.
        registry_pol: the machine ``Registry.pol`` path, if present.
        groups_xml: the GPP ``Groups.xml`` path, if present.
    """

    folder_guid: str
    gpttmpl: Path | None
    registry_pol: Path | None
    groups_xml: Path | None


def _resolve_ci(base: Path, parts: tuple[str, ...]) -> Path | None:
    """Resolve ``base/parts`` case-insensitively; return the path if it is a file.

    Each component is matched case-insensitively against the real directory
    entries (SYSVOL casing is inconsistent). Returns ``None`` if any component is
    missing or the final target is not a regular file. The result is confirmed to
    stay under ``base`` (no symlink/`..` escape).
    """
    current = base
    for part in parts:
        if not current.is_dir():
            return None
        match: Path | None = None
        target = part.lower()
        try:
            for entry in current.iterdir():
                if entry.name.lower() == target:
                    match = entry
                    break
        except OSError:
            return None
        if match is None:
            return None
        current = match
    if not current.is_file():
        return None
    try:
        resolved = current.resolve()
        resolved.relative_to(base.resolve())
    except (OSError, ValueError):
        return None
    return current


def normalize_folder_guid(name: str) -> str:
    """Normalize a policy folder name to a lowercase, brace-free GUID token.

    ``{6AC1786C-016F-11D2-945F-00C04fB984F9}`` -> ``6ac1786c-...-00c04fb984f9``.
    Mirrors M3's GPC ``cn`` normalization so the folder joins the GPO node.
    """
    return name.strip().lstrip("{").rstrip("}").lower()


def discover_policy_folders(policies_dir: Path) -> list[PolicyFiles]:
    """Discover every ``{GUID}`` policy folder under ``Policies`` and its files.

    Inputs:
        policies_dir: the ``SYSVOL/<domain>/Policies`` directory.

    Returns:
        A list of :class:`PolicyFiles`, one per sub-folder whose name normalizes
        to a GUID-like token, sorted by ``folder_guid`` (determinism). A folder
        with none of the three files still yields a row (all paths ``None``) so
        the engine can surface an orphan/empty folder.

    Failure modes:
        Never raises — an unreadable directory yields ``[]``.
    """
    if not policies_dir.is_dir():
        return []
    found: list[PolicyFiles] = []
    try:
        entries = sorted(policies_dir.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return []
    for entry in entries:
        if not entry.is_dir():
            continue
        guid = normalize_folder_guid(entry.name)
        if not guid:
            continue
        found.append(
            PolicyFiles(
                folder_guid=guid,
                gpttmpl=_resolve_ci(entry, _GPTTMPL_RELATIVE),
                registry_pol=_resolve_ci(entry, _REGISTRY_POL_RELATIVE),
                groups_xml=_resolve_ci(entry, _GROUPS_XML_RELATIVE),
            )
        )
    return found
