"""Path-safety primitives for untrusted input (NFR-10; research Item 4).

Every artifact/case path is canonicalized and proven to be contained within an
allowed root before use, defeating symlink escape and ``..`` traversal. These
functions are pure and raise ``PathSafetyError`` on any violation so a bad path
becomes an explicit, counted failure rather than a silent out-of-bounds write.
"""

from __future__ import annotations

import re
from pathlib import Path

#: ``case_id`` must be a filesystem-safe slug: it becomes a directory name and
#: must never traverse. Letters, digits, dash, underscore, dot (not leading).
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}$")


class PathSafetyError(Exception):
    """Raised when a path escapes its allowed root or a ``case_id`` is unsafe."""


def validate_case_id(case_id: str) -> str:
    """Validate an operator-supplied ``case_id`` as a safe directory name.

    Inputs:
        case_id: the proposed case id/slug.

    Returns:
        The same ``case_id`` if valid.

    Failure modes:
        Raises ``PathSafetyError`` if it is empty, too long, contains path
        separators, is ``.``/``..``, or has disallowed characters.
    """
    if case_id in {".", ".."}:
        raise PathSafetyError(f"case_id may not be {case_id!r}")
    if "/" in case_id or "\\" in case_id:
        raise PathSafetyError("case_id may not contain path separators")
    if not _CASE_ID_RE.match(case_id):
        raise PathSafetyError(
            "case_id must be 1-127 chars of [A-Za-z0-9_.-] and not start with '.' or '-'"
        )
    return case_id


def resolve_within(root: Path | str, candidate: Path | str) -> Path:
    """Resolve ``candidate`` and assert it stays inside ``root``.

    Both paths are fully resolved (following symlinks) before the containment
    check, so a symlink pointing outside ``root`` is rejected.

    Inputs:
        root: the allowed root directory.
        candidate: a path that must resolve to within ``root`` (may be given
            relative to ``root``).

    Returns:
        The resolved, contained absolute ``Path``.

    Failure modes:
        Raises ``PathSafetyError`` if the resolved candidate is not within the
        resolved root.
    """
    root_resolved = Path(root).resolve()
    cand = Path(candidate)
    cand_resolved = (root_resolved / cand).resolve() if not cand.is_absolute() else cand.resolve()
    if not cand_resolved.is_relative_to(root_resolved):
        raise PathSafetyError(
            f"path escapes allowed root: {cand_resolved} not under {root_resolved}"
        )
    return cand_resolved


def ensure_existing_file(path: Path | str) -> Path:
    """Resolve ``path`` and assert it is an existing regular file.

    Inputs:
        path: the candidate file path.

    Returns:
        The resolved absolute ``Path``.

    Failure modes:
        Raises ``PathSafetyError`` if the path does not exist, is not a regular
        file, or is a symlink to a non-regular target.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise PathSafetyError(f"input file does not exist: {resolved}")
    if not resolved.is_file():
        raise PathSafetyError(f"input path is not a regular file: {resolved}")
    return resolved
