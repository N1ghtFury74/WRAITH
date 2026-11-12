"""Foundation gate — Layer 2 (adversarial): safe archive extraction (NFR-10, N3).

Crafts malicious tar/zip archives in-memory (no reliance on host symlink
privilege) and asserts the extractor:
  * never writes outside the destination,
  * never leaves a link member on disk,
  * reports truthful ``skipped`` counts,
  * and that every path in ``files`` exists and carries a correct hash (N3).
"""

from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from wraith.acquisition.extract import (
    extract_archive,
    is_archive,
    safe_extract_tar,
    safe_extract_zip,
)
from wraith.acquisition.paths import PathSafetyError

# --------------------------- is_archive ------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("x.zip", True),
        ("x.tar", True),
        ("x.tar.gz", True),
        ("x.tgz", True),
        ("x.TAR.GZ", True),
        ("ntds.dit", False),
        ("x.txt", False),
    ],
)
def test_is_archive(name: str, expected: bool) -> None:
    assert is_archive(name) is expected


# --------------------------- tar: traversal / absolute ---------------------


def _make_tar(path: Path, members: list[tuple[str, bytes]], links: list[tuple[str, str]]) -> None:
    with tarfile.open(path, "w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in links:
            link = tarfile.TarInfo(name)
            link.type = tarfile.SYMTYPE
            link.linkname = target
            tar.addfile(link)


def test_tar_traversal_member_rejected_nothing_escapes(tmp_path: Path) -> None:
    archive = tmp_path / "evil.tar"
    _make_tar(archive, [("../escape.txt", b"evil")], [])
    dest = tmp_path / "dest"
    with pytest.raises((PathSafetyError, tarfile.TarError)):
        safe_extract_tar(archive, dest)
    assert not (tmp_path / "escape.txt").exists()  # never written outside dest


def test_tar_absolute_member_does_not_escape(tmp_path: Path) -> None:
    """An absolute-path member must never land outside dest (fail-safe)."""
    archive = tmp_path / "abs.tar"
    _make_tar(archive, [("/abs_evil.txt", b"evil")], [])
    dest = tmp_path / "dest"
    # The data filter strips the leading '/', then the module's own
    # resolve_within on the original absolute name rejects it. Either way the
    # byte never escapes dest.
    with pytest.raises((PathSafetyError, tarfile.TarError)):
        safe_extract_tar(archive, dest)
    assert not Path(archive.anchor or "/", "abs_evil.txt").exists()


def test_tar_symlink_and_hardlink_skipped_and_counted(tmp_path: Path) -> None:
    """N3: links are never extracted; files that ARE extracted exist + hashed."""
    archive = tmp_path / "mix.tar"
    good = b"good-bytes"
    _make_tar(
        archive,
        members=[("good.txt", good)],
        links=[("badlink", "good.txt")],
    )
    # add a hardlink member too
    with tarfile.open(archive, "a") as tar:
        hl = tarfile.TarInfo("hardlink")
        hl.type = tarfile.LNKTYPE
        hl.linkname = "good.txt"
        tar.addfile(hl)

    dest = tmp_path / "dest"
    result = safe_extract_tar(archive, dest)

    assert [f.inner_path for f in result.files] == ["good.txt"]
    assert set(result.skipped) == {"badlink", "hardlink"}
    # every extracted file exists and its recorded hash is correct
    for f in result.files:
        assert f.abs_path.exists()
        assert f.image_sha256 == hashlib.sha256(f.abs_path.read_bytes()).hexdigest()
    assert result.files[0].image_sha256 == hashlib.sha256(good).hexdigest()
    # nothing was left on disk for the link members
    assert not (dest / "badlink").exists()
    assert not (dest / "hardlink").exists()


# --------------------------- zip: slip / symlink ---------------------------


def test_zip_slip_traversal_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "slip.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "evil")
    dest = tmp_path / "dest"
    with pytest.raises(PathSafetyError):
        safe_extract_zip(archive, dest)
    assert not (tmp_path / "escape.txt").exists()


def test_zip_absolute_member_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/abs_evil.txt", "evil")
    dest = tmp_path / "dest"
    # zipfile may normalise the stored name; whatever it does the resolved target
    # must stay inside dest or be rejected. Assert nothing escapes.
    try:
        result = safe_extract_zip(archive, dest)
    except PathSafetyError:
        pass
    else:
        for f in result.files:
            assert f.abs_path.resolve().is_relative_to(dest.resolve())
    assert not Path(archive.anchor or "/", "abs_evil.txt").exists()


def test_zip_symlink_member_skipped_and_counted(tmp_path: Path) -> None:
    """A zip member carrying Unix symlink mode bits is skipped, not written."""
    archive = tmp_path / "sym.zip"
    good = b"regular-bytes"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("regular.txt", good)
        link = zipfile.ZipInfo("evil_link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16  # mark as symlink
        zf.writestr(link, "/etc/passwd")

    dest = tmp_path / "dest"
    result = safe_extract_zip(archive, dest)

    assert [f.inner_path for f in result.files] == ["regular.txt"]
    assert set(result.skipped) == {"evil_link"}
    assert not (dest / "evil_link").exists()
    assert result.files[0].image_sha256 == hashlib.sha256(good).hexdigest()
    assert result.files[0].abs_path.exists()


def test_extract_archive_dispatch_and_unknown(tmp_path: Path) -> None:
    zpath = tmp_path / "a.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("f.txt", "data")
    res = extract_archive(zpath, tmp_path / "out")
    assert [f.inner_path for f in res.files] == ["f.txt"]

    not_archive = tmp_path / "thing.bin"
    not_archive.write_bytes(b"x")
    with pytest.raises(ValueError):
        extract_archive(not_archive, tmp_path / "out2")
