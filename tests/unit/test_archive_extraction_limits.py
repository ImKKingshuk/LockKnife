from __future__ import annotations

import pathlib
import stat
import zipfile

import pytest

from lockknife.core.path_safety import safe_extract_zip


def _archive(tmp_path: pathlib.Path, entries) -> pathlib.Path:
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return path


@pytest.mark.parametrize(
    "limits",
    [
        {"max_members": 1},
        {"max_member_bytes": 2},
        {"max_total_bytes": 4},
        {"max_compression_ratio": 1},
        {"max_members": 0},
    ],
)
def test_limits_reject_archive_before_any_write(tmp_path, limits) -> None:
    path = _archive(tmp_path, [("first.txt", b"a" * 1000), ("second.txt", b"data")])
    output = tmp_path / "out"
    with zipfile.ZipFile(path) as archive, pytest.raises(ValueError):
        safe_extract_zip(archive, output, **limits)
    assert not output.exists()


@pytest.mark.parametrize(
    "entries",
    [
        [("first.txt", b"okay"), ("../escape", b"bad")],
        [("Name", b"first"), ("name", b"second")],
        [("parent", b"file"), ("parent/child", b"child")],
    ],
)
def test_unsafe_inventory_has_no_partial_output(tmp_path, entries) -> None:
    path = _archive(tmp_path, entries)
    output = tmp_path / "out"
    with zipfile.ZipFile(path) as archive, pytest.raises(ValueError):
        safe_extract_zip(archive, output)
    assert not output.exists()


def test_zip_symlink_is_rejected(tmp_path) -> None:
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    path = _archive(tmp_path, [(link, b"../outside")])
    with zipfile.ZipFile(path) as archive, pytest.raises(ValueError, match="member type"):
        safe_extract_zip(archive, tmp_path / "out")


def test_existing_files_are_not_overwritten(tmp_path) -> None:
    path = _archive(tmp_path, [("first", b"new"), ("existing", b"replacement")])
    output = tmp_path / "out"
    output.mkdir()
    (output / "existing").write_bytes(b"original")
    with zipfile.ZipFile(path) as archive, pytest.raises(FileExistsError):
        safe_extract_zip(archive, output)
    assert (output / "existing").read_bytes() == b"original"
    assert not (output / "first").exists()


def test_corrupt_member_is_not_published(tmp_path) -> None:
    path = _archive(tmp_path, [("file", b"some data")])
    output = tmp_path / "out"
    with zipfile.ZipFile(path) as archive:
        archive.infolist()[0].CRC ^= 1
        with pytest.raises(zipfile.BadZipFile):
            safe_extract_zip(archive, output)
    assert not (output / "file").exists()
    assert not list(output.glob(".extract-*"))
