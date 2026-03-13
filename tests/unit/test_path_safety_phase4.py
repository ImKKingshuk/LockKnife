import pathlib
import zipfile

import pytest

from lockknife.core.case import case_output_path
from lockknife.core.path_safety import ensure_child_path, safe_extract_zip, validate_archive_member, validate_relative_component, validate_user_path_text
from lockknife.modules.apk._decompile_archive import archive_inventory, output_directory_overview, unpack_archive


def test_case_output_path_rejects_traversal_components(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="area"):
        case_output_path(tmp_path, area="../derived", filename="artifact.json")
    with pytest.raises(ValueError, match="filename"):
        case_output_path(tmp_path, area="derived", filename="../artifact.json")


def test_path_safety_helpers_cover_error_branches(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_user_path_text("   ")
    with pytest.raises(ValueError, match="control characters"):
        validate_user_path_text("bad\npath")
    with pytest.raises(ValueError, match=r"cannot be '\.' or '\.\.'"):
        validate_relative_component("..", label="name")
    with pytest.raises(ValueError, match="separators"):
        validate_relative_component("nested/file", label="name")
    with pytest.raises(ValueError, match="escapes"):
        ensure_child_path(tmp_path, tmp_path.parent / "outside.txt")
    with pytest.raises(ValueError, match="Unsafe archive member"):
        validate_archive_member("/absolute.txt")
    with pytest.raises(ValueError, match="Unsafe archive member"):
        validate_archive_member("C:/windows.txt")


def test_safe_extract_zip_blocks_traversal_and_unpack_archive_extracts_expected_files(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
        archive.writestr("assets/config.json", b"{}")
        archive.writestr("lib/arm64-v8a/libdemo.so", b"so")
        archive.writestr("empty/", b"")

    unpack_dir = tmp_path / "unpack"
    result = unpack_archive(apk_path, unpack_dir)
    overview = output_directory_overview(unpack_dir)
    inventory = archive_inventory(apk_path)

    assert result["status"] == "completed"
    assert result["extracted_path_count"] == 4
    assert (unpack_dir / "assets" / "config.json").read_text(encoding="utf-8") == "{}"
    assert (unpack_dir / "empty").is_dir()
    assert inventory["dex_count"] == 1
    assert inventory["native_library_count"] == 1
    assert overview["file_count"] == 3

    bad_apk = tmp_path / "bad.apk"
    with zipfile.ZipFile(bad_apk, "w") as archive:
        archive.writestr("../escape.txt", b"oops")

    with zipfile.ZipFile(bad_apk, "r") as archive:
        with pytest.raises(ValueError, match="Unsafe archive member"):
            safe_extract_zip(archive, tmp_path / "bad-out")

    assert not (tmp_path / "escape.txt").exists()