import pathlib

from lockknife.core import version as version_mod


def _write_versions(
    root: pathlib.Path, py_version: str, cargo_version: str, init_version: str
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    pyproject = root / "pyproject.toml"
    cargo = root / "Cargo.toml"
    init = root / "__init__.py"
    pyproject.write_text(f'[project]\nversion = "{py_version}"\n', encoding="utf-8")
    cargo.write_text(
        f'[package]\nname = "lockknife-core"\nversion = "{cargo_version}"\n', encoding="utf-8"
    )
    init.write_text(f'__version__ = "{init_version}"\n', encoding="utf-8")
    return pyproject, cargo, init


def test_check_versions_match(monkeypatch, tmp_path) -> None:
    pyproject, cargo, init = _write_versions(tmp_path, "1.2.3", "1.2.3", "1.2.3")
    monkeypatch.setattr(version_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(version_mod, "CARGO", cargo)
    monkeypatch.setattr(version_mod, "INIT", init)
    assert version_mod.check_versions() == 0


def test_check_versions_mismatch(monkeypatch, tmp_path) -> None:
    pyproject, cargo, init = _write_versions(tmp_path, "1.2.3", "1.2.4", "1.2.3")
    monkeypatch.setattr(version_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(version_mod, "CARGO", cargo)
    monkeypatch.setattr(version_mod, "INIT", init)
    assert version_mod.check_versions() == 1


def test_sync_versions_updates_files(monkeypatch, tmp_path) -> None:
    pyproject, cargo, init = _write_versions(tmp_path, "2.0.0", "1.0.0", "1.0.0")
    monkeypatch.setattr(version_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(version_mod, "CARGO", cargo)
    monkeypatch.setattr(version_mod, "INIT", init)
    version_mod.sync_versions()
    assert 'version = "2.0.0"' in cargo.read_text(encoding="utf-8")
    assert '__version__ = "2.0.0"' in init.read_text(encoding="utf-8")
    assert version_mod.check_versions() == 0
