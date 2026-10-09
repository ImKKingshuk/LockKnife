"""Tests for deep audit robustness improvements."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from lockknife.core.adb import resolve_adb_binary
from lockknife.core.device import DeviceManager
from lockknife.core.health import resolve_tool_binary
from lockknife.modules.exploitation.auto_exploit import (
    _ACCESS_LEVEL_PRIORITY,
    AutoExploiter,
)
from lockknife.modules.exploitation.results import (
    AccessLevel,
    ExploitResult,
    VectorType,
)
from lockknife_headless_cli._tui_callback_helpers import _load_config_text
from lockknife_headless_cli.exploit import exploit, get_auth_manager_from_obj, get_scope_from_obj
from lockknife_headless_cli.main import AppContext
from lockknife_headless_cli.tui_callback import build_tui_callback


def test_resolve_adb_binary_configured_path():
    """Configured path takes precedence if provided."""
    assert resolve_adb_binary("/custom/path/adb") == "/custom/path/adb"


def test_resolve_adb_binary_fallback_env(monkeypatch, tmp_path):
    """Fallback discovers adb inside ANDROID_HOME or ANDROID_SDK_ROOT."""
    fake_sdk = tmp_path / "sdk"
    fake_adb = fake_sdk / "platform-tools" / "adb"
    fake_adb.parent.mkdir(parents=True)
    fake_adb.write_text("#!/bin/sh\n")
    fake_adb.chmod(0o755)

    monkeypatch.setenv("ANDROID_HOME", str(fake_sdk))
    with patch("shutil.which", return_value=None):
        discovered = resolve_adb_binary(None)
        assert discovered == str(fake_adb)


def test_resolve_adb_binary_fallback_default():
    """When adb cannot be found in SDK or PATH, default 'adb' string is returned."""
    with patch("shutil.which", return_value=None), patch("pathlib.Path.is_file", return_value=False):
        assert resolve_adb_binary(None) == "adb"


def test_resolve_tool_binary_candidates(monkeypatch, tmp_path):
    """Tool resolver looks in standard candidate directories."""
    fake_tool = tmp_path / ".local" / "bin" / "apktool"
    fake_tool.parent.mkdir(parents=True)
    fake_tool.write_text("#!/bin/sh\n")
    fake_tool.chmod(0o755)

    monkeypatch.setenv("HOME", str(tmp_path))
    with patch("shutil.which", return_value=None):
        assert resolve_tool_binary("apktool") == str(fake_tool)


def test_access_level_priority_ranking():
    """Verify ROOT is strictly higher priority than SHELL."""
    assert _ACCESS_LEVEL_PRIORITY[AccessLevel.ROOT] > _ACCESS_LEVEL_PRIORITY[AccessLevel.SHELL]
    assert _ACCESS_LEVEL_PRIORITY[AccessLevel.SHELL] > _ACCESS_LEVEL_PRIORITY[AccessLevel.NETWORK]
    assert _ACCESS_LEVEL_PRIORITY[AccessLevel.NETWORK] > _ACCESS_LEVEL_PRIORITY[AccessLevel.NONE]


def test_auto_exploiter_prefers_root_over_shell():
    """AutoExploiter should choose ROOT over SHELL regardless of alphabetical sorting."""
    exploiter = AutoExploiter()

    shell_result = ExploitResult(
        target_id="192.168.1.100",
        vector_used=VectorType.ADB_TCP,
        success=True,
        access_level=AccessLevel.SHELL,
    )
    root_result = ExploitResult(
        target_id="192.168.1.100",
        vector_used=VectorType.USB_DEBUGGING,
        success=True,
        access_level=AccessLevel.ROOT,
    )

    with patch.object(exploiter, "_try_vector", side_effect=[shell_result, root_result]):
        # Test seeking root access
        best = exploiter.exploit("192.168.1.100", access_level="root")
        assert best.success
        assert best.access_level == AccessLevel.ROOT
        assert best.vector_used == VectorType.USB_DEBUGGING


def test_auto_exploiter_exception_containment():
    """An exception raised inside a vector runner should not abort the run."""
    exploiter = AutoExploiter()
    with patch.object(
        exploiter, "_try_vector", side_effect=RuntimeError("Vector execution crashed")
    ):
        result = exploiter.exploit("192.168.1.100", access_level="shell")
        # Should complete gracefully with failed result
        assert not result.success


def test_map_devices_string_serial_parsing():
    """Passing comma-separated string to map_devices should split serials properly."""
    manager = DeviceManager(adb=MagicMock())
    results = manager.map_devices(lambda s: f"done-{s}", serials="dev-1, dev-2")
    assert results == {"dev-1": "done-dev-1", "dev-2": "done-dev-2"}


def test_app_context_config_property():
    """AppContext.config property should safely return LockKnifeConfig."""
    ctx = AppContext()
    assert ctx.config is not None
    assert ctx.config.log_level is not None


def test_load_config_text_resilience():
    """_load_config_text should not crash when app or object has no devices attribute."""
    dummy_app = MagicMock(spec=[])
    text, path = _load_config_text(dummy_app)
    assert isinstance(text, str)
    assert path is None or isinstance(path, str)


def test_exploit_cli_helpers_resilience():
    """get_scope_from_obj and get_auth_manager_from_obj handle None and empty dicts."""
    scope = get_scope_from_obj(None)
    assert scope is not None
    assert scope.scope_id is not None

    manager = get_auth_manager_from_obj(None)
    assert manager is not None

    empty_scope = get_scope_from_obj({})
    assert empty_scope is not None


def test_exploit_cli_status_cmd_runner():
    """Invoking exploit status via Click CliRunner executes cleanly."""
    runner = CliRunner()
    result = runner.invoke(exploit, ["status"])
    assert result.exit_code == 0
    assert "Authorization Scope" in result.output


def test_extract_devices_fallback_and_passthrough():
    """_extract_devices provides safe fallback and preserves existing devices."""
    from lockknife_headless_cli._extract_helpers import _extract_devices

    # Passthrough when devices attribute is present
    mock_devs = MagicMock()
    app_with_devs = MagicMock()
    app_with_devs.devices = mock_devs
    assert _extract_devices(app_with_devs) is mock_devs

    # Fallback when app is None or empty dict
    fallback = _extract_devices(None)
    assert isinstance(fallback, DeviceManager)

    fallback_dict = _extract_devices({})
    assert isinstance(fallback_dict, DeviceManager)


def test_extract_all_rows_resilience():
    """_extract_rows in _extract_all works seamlessly with duck-typed app."""
    from lockknife_headless_cli._extract_all import _extract_rows

    mock_cli = MagicMock()
    mock_extractor = MagicMock(return_value=[])
    errors: list[dict[str, str]] = []

    res = _extract_rows(
        "sms",
        cli=mock_cli,
        app=MagicMock(spec=[]),
        serial="dummy-serial",
        progress_callback=None,
        current=1,
        total=5,
        extractor=mock_extractor,
        errors=errors,
    )
    assert res == []
    assert len(errors) == 0
    mock_extractor.assert_called_once()

