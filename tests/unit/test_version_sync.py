import pathlib

from lockknife.core import version as version_mod


def _write_versions(
    root: pathlib.Path, py_version: str, cargo_version: str, init_version: str
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    pyproject = root / "pyproject.toml"
    core_cargo = root / "core-Cargo.toml"
    tui_cargo = root / "tui-Cargo.toml"
    cargo_lock = root / "Cargo.lock"
    uv_lock = root / "uv.lock"
    init = root / "__init__.py"
    pyproject.write_text(f'[project]\nversion = "{py_version}"\n', encoding="utf-8")
    core_cargo.write_text(
        f'[package]\nname = "lockknife-core"\nversion = "{cargo_version}"\n'
        f'[dependencies]\nlockknife-tui = {{ version = "{cargo_version}", path = "../tui" }}\n',
        encoding="utf-8",
    )
    tui_cargo.write_text(
        f'[package]\nname = "lockknife-tui"\nversion = "{cargo_version}"\n',
        encoding="utf-8",
    )
    cargo_lock.write_text(
        f'[[package]]\nname = "lockknife-core"\nversion = "{cargo_version}"\n\n'
        f'[[package]]\nname = "lockknife-tui"\nversion = "{cargo_version}"\n',
        encoding="utf-8",
    )
    uv_lock.write_text(
        f'version = 1\n\n[[package]]\nname = "lockknife"\nversion = "{cargo_version}"\n',
        encoding="utf-8",
    )
    init.write_text(f'__version__ = "{init_version}"\n', encoding="utf-8")
    return pyproject, core_cargo, tui_cargo, cargo_lock, uv_lock, init


def _patch_paths(monkeypatch, paths: tuple[pathlib.Path, ...]) -> None:
    pyproject, core_cargo, tui_cargo, cargo_lock, uv_lock, init = paths
    monkeypatch.setattr(version_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(version_mod, "CORE_CARGO", core_cargo)
    monkeypatch.setattr(version_mod, "TUI_CARGO", tui_cargo)
    monkeypatch.setattr(version_mod, "CARGO_LOCK", cargo_lock)
    monkeypatch.setattr(version_mod, "UV_LOCK", uv_lock)
    monkeypatch.setattr(version_mod, "INIT", init)


def test_check_versions_match(monkeypatch, tmp_path) -> None:
    paths = _write_versions(tmp_path, "1.2.3", "1.2.3", "1.2.3")
    _patch_paths(monkeypatch, paths)
    assert version_mod.check_versions() == 0


def test_check_versions_mismatch(monkeypatch, tmp_path) -> None:
    paths = _write_versions(tmp_path, "1.2.3", "1.2.4", "1.2.3")
    _patch_paths(monkeypatch, paths)
    assert version_mod.check_versions() == 1


def test_check_versions_accepts_matching_release_tag(monkeypatch, tmp_path) -> None:
    paths = _write_versions(tmp_path, "1.2.3", "1.2.3", "1.2.3")
    _patch_paths(monkeypatch, paths)
    assert version_mod.check_versions("v1.2.3") == 0
    assert version_mod.check_versions("v1.2.4") == 1


def test_sync_versions_updates_files(monkeypatch, tmp_path) -> None:
    paths = _write_versions(tmp_path, "2.0.0", "1.0.0", "1.0.0")
    _patch_paths(monkeypatch, paths)
    version_mod.sync_versions()
    _, core_cargo, tui_cargo, cargo_lock, uv_lock, init = paths
    assert 'version = "2.0.0"' in core_cargo.read_text(encoding="utf-8")
    assert 'version = "2.0.0"' in tui_cargo.read_text(encoding="utf-8")
    assert cargo_lock.read_text(encoding="utf-8").count('version = "2.0.0"') == 2
    assert 'version = "2.0.0"' in uv_lock.read_text(encoding="utf-8")
    assert '__version__ = "2.0.0"' in init.read_text(encoding="utf-8")
    assert version_mod.check_versions() == 0
