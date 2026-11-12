"""Foundation gate — Layer 2 (adversarial): untrusted-input path safety (NFR-10).

Probes ``validate_case_id``, ``resolve_within`` and ``ensure_existing_file``:
case-id slug hardening, ``..`` traversal rejection, symlink-escape rejection,
and absolute-path containment.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wraith.acquisition.paths import (
    PathSafetyError,
    ensure_existing_file,
    resolve_within,
    validate_case_id,
)

# --------------------------- validate_case_id ------------------------------


@pytest.mark.parametrize("good", ["case1", "a_b-c.d", "A", "_hidden", "Z9", "a" * 127])
def test_validate_case_id_accepts_safe_slugs(good: str) -> None:
    assert validate_case_id(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "",  # empty
        ".",  # dot
        "..",  # dotdot
        "a/b",  # unix separator
        "a\\b",  # windows separator
        ".hidden",  # leading dot
        "-flag",  # leading dash
        "a" * 128,  # overlong (>127)
        "bad\x00null",  # control char
        "line\nbreak",  # control char
        "with space",  # space not allowed
    ],
)
def test_validate_case_id_rejects_unsafe(bad: str) -> None:
    with pytest.raises(PathSafetyError):
        validate_case_id(bad)


# --------------------------- resolve_within --------------------------------


def test_resolve_within_accepts_contained_relative(tmp_path: Path) -> None:
    target = resolve_within(tmp_path, "sub/child.txt")
    assert target.is_relative_to(tmp_path.resolve())
    assert target.name == "child.txt"


def test_resolve_within_rejects_dotdot_traversal(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        resolve_within(tmp_path, "../escape.txt")


def test_resolve_within_rejects_deep_traversal(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(PathSafetyError):
        resolve_within(root, "a/b/../../../outside.txt")


def test_resolve_within_rejects_absolute_outside(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    with pytest.raises(PathSafetyError):
        resolve_within(root, outside)


def test_resolve_within_rejects_symlink_escape(tmp_path: Path) -> None:
    """A symlink inside root pointing outside must be rejected after resolve().

    Symlink creation needs privilege on Windows; skip cleanly if unavailable.
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform dependent
        pytest.skip(f"symlink unsupported on this host: {exc}")
    with pytest.raises(PathSafetyError):
        resolve_within(root, "link/secret.txt")


# --------------------------- ensure_existing_file --------------------------


def test_ensure_existing_file_ok(tmp_path: Path) -> None:
    p = tmp_path / "f.bin"
    p.write_bytes(b"x")
    assert ensure_existing_file(p) == p.resolve()


def test_ensure_existing_file_missing(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        ensure_existing_file(tmp_path / "missing.bin")


def test_ensure_existing_file_directory_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        ensure_existing_file(tmp_path)
