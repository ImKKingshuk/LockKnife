from __future__ import annotations

import lzma
import pathlib
import subprocess
from typing import Any
from unittest.mock import MagicMock

import pytest

from lockknife.core.case import create_case_workspace
from lockknife.core.exceptions import DeviceError
from lockknife.core.execution_policy import ExecutionGateway, ExecutionIntent
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


def _intent(tmp_path: pathlib.Path, *, mode: str = "dry-run") -> ExecutionIntent:
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-FRIDA", examiner="Tester", title="Frida")
    return ExecutionIntent(
        operator="Tester",
        case_dir=case_dir,
        target="device123",
        vector="runtime.frida",
        risk="high",
        mode=mode,
        capability_status="implemented-live",
        confirmed=mode == "lab-live",
    )


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


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
    booster = FridaBooster(
        mock_adb, "device123", execution_intent=_intent(tmp_path, mode="lab-live")
    )

    # Prepare dummy compressed data of size > 1MB to satisfy caching checks
    dummy_binary = b"x" * 1000005
    compressed_data = lzma.compress(dummy_binary)
    expected_sha256 = _sha256(dummy_binary)

    # Mock http_get to return the compressed data
    mock_http_get = MagicMock(return_value=compressed_data)
    monkeypatch.setattr("lockknife.modules.runtime.booster.http_get", mock_http_get)

    # Mock the home directory to use tmp_path
    mock_home = MagicMock(return_value=tmp_path)
    monkeypatch.setattr("pathlib.Path.home", mock_home)

    dest_path = booster.download_server("16.2.1", "android-arm64", expected_sha256=expected_sha256)
    assert dest_path.exists()
    assert dest_path.read_bytes() == dummy_binary
    mock_http_get.assert_called_once()

    # Call again, should load from cache without downloading
    mock_http_get.reset_mock()
    dest_path_cached = booster.download_server(
        "16.2.1", "android-arm64", expected_sha256=expected_sha256
    )
    assert dest_path_cached == dest_path
    mock_http_get.assert_not_called()


def test_booster_download_requires_checksum(mock_adb: MagicMock, tmp_path: pathlib.Path) -> None:
    booster = FridaBooster(mock_adb, "device123", execution_intent=_intent(tmp_path))

    with pytest.raises(DeviceError, match="pinned SHA-256"):
        booster.download_server("16.2.1", "android-arm64")


def test_booster_deploy_and_start_dry_run_has_no_adb_side_effects(
    mock_adb: MagicMock, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intent = _intent(tmp_path)
    booster = FridaBooster(
        mock_adb,
        "device123",
        execution_intent=intent,
        execution_gateway=ExecutionGateway(),
    )
    local_bin = tmp_path / "frida-server-dummy"
    local_bin.write_bytes(b"dummy-frida-server-binary")
    expected_sha256 = _sha256(local_bin.read_bytes())

    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess.run must not execute during Frida dry-run")

    monkeypatch.setattr(subprocess, "run", fail_run)

    assert booster.deploy_and_start(local_bin, expected_sha256=expected_sha256) is True
    mock_adb.push.assert_not_called()
    mock_adb.has_su.assert_not_called()


def test_booster_remediate_flow(
    mock_adb: MagicMock, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intent = _intent(tmp_path)
    booster = FridaBooster(mock_adb, "device123", execution_intent=intent)

    local_bin = tmp_path / "frida-server"
    local_bin.write_bytes(b"fake-frida-server-code")

    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError))

    assert (
        booster.remediate(local_binary=local_bin, expected_sha256=_sha256(local_bin.read_bytes()))
        is True
    )

    mock_adb.push.assert_not_called()


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
    assert "policy-gated Frida remediation" in res["readiness"]["recommended_action"]

    # Assert the safe remediation preparation action is proposed
    remediate_action = next(
        (a for a in res["readiness"]["next_actions"] if a["action"] == "prepare-frida-remediation"),
        None,
    )
    assert remediate_action is not None
    assert remediate_action["status"] == "ready"
