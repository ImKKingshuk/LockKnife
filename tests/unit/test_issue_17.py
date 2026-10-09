from __future__ import annotations

import pathlib
import sys
import types
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from lockknife.core.config import LoadedConfig, LockKnifeConfig
from lockknife.core.health import (
    EXTRA_REQUIREMENTS,
    _check_module,
    doctor_status,
    enable_fallback_site_packages,
    get_fallback_site_packages,
    install_missing_dependencies,
)
from lockknife_headless_cli.health import doctor_cmd
from lockknife_headless_cli.main import AppContext
from lockknife_headless_cli.tui_callback import build_tui_callback


def test_fallback_site_packages_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    fake_user_site = tmp_path / "fake_user_site"
    fake_user_site.mkdir()

    import site

    monkeypatch.setattr(site, "getusersitepackages", lambda: str(fake_user_site))
    candidates = get_fallback_site_packages()
    assert str(fake_user_site) in candidates

    # Enable fallback adds to sys.path
    if str(fake_user_site) in sys.path:
        sys.path.remove(str(fake_user_site))
    added = enable_fallback_site_packages()
    assert str(fake_user_site) in added
    assert str(fake_user_site) in sys.path


def test_check_module_finds_module_in_fallback_site_packages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    # Create a fake installed module in a fallback directory not initially in sys.path
    fallback_dir = tmp_path / "custom_fallback_site"
    fallback_dir.mkdir()
    mod_file = fallback_dir / "custom_tool.py"
    mod_file.write_text("IS_LOADED = True\n", encoding="utf-8")

    monkeypatch.setattr(
        "lockknife.core.health.get_fallback_site_packages", lambda: [str(fallback_dir)]
    )

    # Initially custom_tool is not in sys.modules or sys.path
    if "custom_tool" in sys.modules:
        del sys.modules["custom_tool"]
    if str(fallback_dir) in sys.path:
        sys.path.remove(str(fallback_dir))

    res = _check_module("custom_tool", extra="tool")
    assert res["ok"] is True
    assert res["module"] == "custom_tool"
    assert res.get("loaded_from_fallback") is True
    assert str(fallback_dir) in sys.path


def test_check_module_reports_accurate_hint_and_extra() -> None:
    res = _check_module("nonexistent_special_module_xyz", extra="special")
    assert res["ok"] is False
    assert res["module"] == "nonexistent_special_module_xyz"
    assert res["extra"] == "special"
    assert "lockknife[special]" in res["hint"]
    assert sys.executable in res["hint"]


def test_doctor_status_includes_environment_and_hints() -> None:
    status = doctor_status()
    assert "environment" in status
    env = status["environment"]
    assert env["python_executable"] == sys.executable
    assert env["python_version"] == sys.version.split()[0]
    assert "is_venv" in env
    assert "fallback_paths" in env


def test_install_missing_dependencies_dry_run() -> None:
    res = install_missing_dependencies(dry_run=True)
    assert res["ok"] is True
    assert res["dry_run"] is True
    assert res["installed"] is False
    assert sys.executable in res["command"]
    assert "-m" in res["command"]
    assert "pip" in res["command"]
    assert "install" in res["command"]


def test_install_missing_dependencies_all_extras_dry_run() -> None:
    res = install_missing_dependencies(all_extras=True, dry_run=True)
    assert res["ok"] is True
    assert set(res["target_extras"]) == set(EXTRA_REQUIREMENTS.keys())


def test_install_missing_dependencies_subprocesses_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_run = MagicMock()
    mock_run.return_value = types.SimpleNamespace(
        returncode=0, stdout="Successfully installed", stderr=""
    )
    import subprocess

    monkeypatch.setattr(subprocess, "run", mock_run)

    res = install_missing_dependencies(extras=["apk"], dry_run=False)
    assert res["ok"] is True
    assert res["installed"] is True
    assert mock_run.called
    cmd_executed = mock_run.call_args[0][0]
    assert any("androguard" in arg for arg in cmd_executed)


def test_cli_doctor_install_missing_dry_run() -> None:
    runner = CliRunner()
    result = runner.invoke(doctor_cmd, ["--install-missing", "--dry-run"])
    assert result.exit_code == 0
    assert "Dry-run: command to install" in result.output
    assert sys.executable in result.output


def test_cli_doctor_displays_environment_section() -> None:
    runner = CliRunner()
    result = runner.invoke(doctor_cmd, [])
    assert result.exit_code == 0
    assert "Environment:" in result.output
    assert "Python:" in result.output
    assert sys.executable in result.output


def test_tui_callback_doctor_install_missing() -> None:
    config = LoadedConfig(config=LockKnifeConfig(), path=None)
    app = AppContext(config)
    callback = build_tui_callback(app)

    res = callback("core.doctor.install_missing", {"dry_run": True})
    assert res["ok"] is True
    import json

    data = json.loads(res["data_json"])
    assert data["dry_run"] is True
    assert "command" in data
