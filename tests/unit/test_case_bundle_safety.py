import zipfile

import pytest

from lockknife.core._case_store import CaseStore
from lockknife.core.case import create_case_workspace, export_case_bundle


def _case(tmp_path):
    path = tmp_path / "case"
    create_case_workspace(case_dir=path, case_id="SAFE", examiner="Analyst", title="Safety")
    return path


def test_bundle_excludes_output_and_symlinks(tmp_path):
    case_dir = _case(tmp_path)
    private = tmp_path / "private.txt"
    private.write_text("not case evidence")
    (case_dir / "reports" / "outside.txt").symlink_to(private)
    output = case_dir / "reports" / "bundle.zip"
    output.write_bytes(b"old bundle")
    export_case_bundle(case_dir=case_dir, output_path=output)
    with zipfile.ZipFile(output) as archive:
        assert "SAFE/case_store.sqlite3" in archive.namelist()
        assert not any(
            name.endswith("outside.txt") or name.endswith("bundle.zip")
            for name in archive.namelist()
        )
        assert not any(".lockknife-export-" in name for name in archive.namelist())


def test_failed_bundle_preserves_existing_output(tmp_path, monkeypatch):
    case_dir = _case(tmp_path)
    output = tmp_path / "bundle.zip"
    output.write_bytes(b"existing bundle")

    def fail(*args, **kwargs):
        raise OSError("backup failed")

    monkeypatch.setattr(CaseStore, "backup", fail)
    with pytest.raises(OSError, match="backup failed"):
        export_case_bundle(case_dir=case_dir, output_path=output)
    assert output.read_bytes() == b"existing bundle"
    assert not list(tmp_path.glob(".lockknife-export-*"))


def test_bundle_rejects_unsafe_case_id(tmp_path):
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir, case_id="../outside", examiner="Analyst", title="Unsafe"
    )
    with pytest.raises(ValueError, match="Unsafe"):
        export_case_bundle(case_dir=case_dir, output_path=tmp_path / "bundle.zip")
