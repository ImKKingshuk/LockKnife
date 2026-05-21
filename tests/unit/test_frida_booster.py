from __future__ import annotations

import lzma
import pathlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.runtime._session_manager_preflight import runtime_preflight
from lockknife.modules.runtime.booster import FridaBooster


@pytest.fixture
def mock_adb() -> MagicMock:
    adb = MagicMock()
    # Mock default responses
    adb.getprop.return_value = {"ro.product.cpu.abi": "arm64-v8a"}
    adb.has_su.return_value = True
    adb.shell.return_value = ""
    return adb


def test_booster_is_server_running(mock_adb: MagicMock) -> None:
    booster = FridaBooster(mock_adb, "device123")

    # 1. Server is running
    mock_adb.shell.return_value = "root      1234  1     0 12:00:00 /data/local/tmp/frida-server"
    assert booster.is_server_running() is True

    # 2. Server is not running
    mock_adb.shell.return_value = ""
    assert booster.is_server_running() is False

    # 3. Exception raised
    mock_adb.shell.side_effect = Exception("ADB connection lost")
    assert booster.is_server_running() is False


def test_booster_get_device_abi(mock_adb: MagicMock) -> None:
    booster = FridaBooster(mock_adb, "device123")

    # ARM64 mapping
    mock_adb.getprop.return_value = {"ro.product.cpu.abi": "arm64-v8a"}
    assert booster.get_device_abi() == "android-arm64"

    # ARM v7 mapping
    mock_adb.getprop.return_value = {"ro.product.cpu.abi": "armeabi-v7a"}
    assert booster.get_device_abi() == "android-arm"

    # x86_64 mapping
    mock_adb.getprop.return_value = {"ro.product.cpu.abi": "x86_64"}
    assert booster.get_device_abi() == "android-x86_64"

    # Fallback to arm64
    mock_adb.getprop.side_effect = Exception("failed")
    assert booster.get_device_abi() == "android-arm64"


def test_booster_download_server(
    mock_adb: MagicMock, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    booster = FridaBooster(mock_adb, "device123")

    # Prepare dummy compressed data of size > 1MB to satisfy caching checks
    dummy_binary = b"x" * 1000005
    compressed_data = lzma.compress(dummy_binary)

    # Mock http_get to return the compressed data
    mock_http_get = MagicMock(return_value=compressed_data)
    monkeypatch.setattr("lockknife.modules.runtime.booster.http_get", mock_http_get)

    # Mock the home directory to use tmp_path
    mock_home = MagicMock(return_value=tmp_path)
    monkeypatch.setattr("pathlib.Path.home", mock_home)

    dest_path = booster.download_server("16.2.1", "android-arm64")
    assert dest_path.exists()
    assert dest_path.read_bytes() == dummy_binary
    mock_http_get.assert_called_once()

    # Call again, should load from cache without downloading
    mock_http_get.reset_mock()
    dest_path_cached = booster.download_server("16.2.1", "android-arm64")
    assert dest_path_cached == dest_path
    mock_http_get.assert_not_called()


def test_booster_deploy_and_start(mock_adb: MagicMock, tmp_path: pathlib.Path) -> None:
    booster = FridaBooster(mock_adb, "device123")
    local_bin = tmp_path / "frida-server-dummy"
    local_bin.write_bytes(b"dummy")

    # 1. Start with SU root access
    mock_adb.has_su.return_value = True
    assert booster.deploy_and_start(local_bin) is True
    mock_adb.push.assert_called_with("device123", local_bin, "/data/local/tmp/frida-server")
    mock_adb.shell.assert_any_call(
        "device123", "su -c '/data/local/tmp/frida-server -D'", timeout_s=10.0
    )

    # 2. Start without SU (fallback to background)
    mock_adb.reset_mock()
    mock_adb.has_su.return_value = False
    assert booster.deploy_and_start(local_bin) is True
    mock_adb.shell.assert_any_call("device123", "/data/local/tmp/frida-server -D", timeout_s=10.0)


def test_booster_remediate_flow(
    mock_adb: MagicMock, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    booster = FridaBooster(mock_adb, "device123")

    # Mock downloads and cache path
    dummy_binary = b"fake-frida-server-code"
    compressed_data = lzma.compress(dummy_binary)
    mock_http_get = MagicMock(return_value=compressed_data)
    monkeypatch.setattr("lockknife.modules.runtime.booster.http_get", mock_http_get)
    monkeypatch.setattr("pathlib.Path.home", MagicMock(return_value=tmp_path))

    # Mock running state sequence: Initially not running, then running after deployment
    running_states = [
        "",  # 1. check inside remediate: is_server_running() -> False
        "",  # 2. check inside deploy_and_start: stop existing
        "frida-server",  # 3. check inside remediate verification poll: is_server_running() -> True
    ]

    def mock_shell(serial: str, cmd: str, timeout_s: float = 30.0) -> str:
        if "grep frida-server" in cmd:
            return running_states.pop(0) if running_states else "frida-server"
        return ""

    mock_adb.shell.side_effect = mock_shell

    assert booster.remediate() is True


def test_preflight_diagnostics_integration(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Setup a failing FridaManager mock factory
    class FailingFridaManager:
        def __init__(self, device_id: str | None = None) -> None:
            self.device_id = device_id

        def describe_device(self) -> dict[str, Any]:
            raise Exception("Device connection timeout")

    # 2. Mock FridaBooster to report that frida-server is offline
    mock_is_running = MagicMock(return_value=False)
    monkeypatch.setattr(FridaBooster, "is_server_running", mock_is_running)

    # 3. Run preflight
    res = runtime_preflight(
        app_id="com.example.app",
        device_id="device123",
        manager_factory=lambda dev_id: FailingFridaManager(dev_id),  # type: ignore
    )

    assert res["status"] == "fail"

    # Assert custom frida-server check failed
    frida_server_check = next((c for c in res["checks"] if c["check"] == "frida-server"), None)
    assert frida_server_check is not None
    assert frida_server_check["status"] == "fail"
    assert "not running" in frida_server_check["message"]

    # Assert recovery action is injected correctly
    assert "Trigger Frida Server Auto-Remediation" in res["readiness"]["recommended_action"]

    # Assert the auto-remediate-frida action is proposed
    remediate_action = next(
        (a for a in res["readiness"]["next_actions"] if a["action"] == "auto-remediate-frida"), None
    )
    assert remediate_action is not None
    assert remediate_action["status"] == "ready"
