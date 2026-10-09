from __future__ import annotations

import pathlib

import pytest

from lockknife.core.config import LoadedConfig, LockKnifeConfig
from lockknife_headless_cli.main import AppContext
from lockknife_headless_cli.tui_callback import build_tui_callback


def test_app_context_has_selected_device_serial_attribute() -> None:
    config = LoadedConfig(config=LockKnifeConfig(), path=None)
    app = AppContext(config)
    assert hasattr(app, "selected_device_serial")
    assert app.selected_device_serial is None


def test_tui_callback_credentials_with_real_app_context(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = LoadedConfig(config=LockKnifeConfig(), path=None)
    app = AppContext(config)
    # Target a device
    app.selected_device_serial = "TARGET_DEV_123"

    callback = build_tui_callback(app)

    from lockknife.core.device import DeviceHandle, DeviceState

    # Mock device methods so we don't need real hardware
    monkeypatch.setattr(
        app.devices,
        "list_handles",
        lambda: [DeviceHandle(serial="TARGET_DEV_123", adb_state="device", state=DeviceState.authorized)],
    )
    monkeypatch.setattr(app.devices, "has_root", lambda s: True)
    monkeypatch.setattr(app.devices, "shell", lambda s, c, **kw: "mock_output")

    from lockknife_headless_cli import tui_callback as tcb

    monkeypatch.setattr(tcb, "recover_pin", lambda devs, s, length: "1234")
    monkeypatch.setattr(tcb, "recover_gesture", lambda devs, s: [0, 1, 2])
    monkeypatch.setattr(tcb, "extract_wifi_passwords", lambda devs, s: [])
    monkeypatch.setattr(tcb, "list_keystore", lambda devs, s: [])
    monkeypatch.setattr(tcb, "pull_passkey_artifacts", lambda *a, **kw: [])

    import json

    # Test all 5 credentials actions with real AppContext
    res_pin = callback("credentials.pin", {"length": 4})
    assert res_pin["ok"] is True
    assert json.loads(res_pin["data_json"])["serial"] == "TARGET_DEV_123"

    res_gesture = callback("credentials.gesture", {})
    assert res_gesture["ok"] is True
    assert json.loads(res_gesture["data_json"])["serial"] == "TARGET_DEV_123"

    res_wifi = callback("credentials.wifi", {})
    assert res_wifi["ok"] is True
    assert json.loads(res_wifi["data_json"])["serial"] == "TARGET_DEV_123"

    res_keystore = callback("credentials.keystore", {})
    assert res_keystore["ok"] is True
    assert json.loads(res_keystore["data_json"])["serial"] == "TARGET_DEV_123"

    res_passkeys = callback("credentials.passkeys", {"output_dir": str(tmp_path)})
    assert res_passkeys["ok"] is True
    assert json.loads(res_passkeys["data_json"])["serial"] == "TARGET_DEV_123"


def test_tui_callback_credentials_without_selected_device_serial_attr(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that an app object without selected_device_serial does NOT crash with AttributeError."""
    import types

    from lockknife.core.device import DeviceHandle, DeviceState
    from lockknife_headless_cli import tui_callback as tcb

    dummy_app = types.SimpleNamespace(
        devices=types.SimpleNamespace(
            list_handles=lambda: [DeviceHandle(serial="DEV_999", adb_state="device", state=DeviceState.authorized)],
            has_root=lambda s: True,
            shell=lambda s, c, **kw: "mock_output",
        ),
    )
    assert not hasattr(dummy_app, "selected_device_serial")

    callback = build_tui_callback(dummy_app)
    monkeypatch.setattr(tcb, "recover_pin", lambda devs, s, length: "4321")

    # Should not raise AttributeError: 'SimpleNamespace' object has no attribute 'selected_device_serial'
    res = callback("credentials.pin", {"serial": "DEV_999", "length": 4})
    assert res["ok"] is True


def test_tui_callback_credentials_param_serial_updates_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that passing serial in params updates app.selected_device_serial."""
    config = LoadedConfig(config=LockKnifeConfig(), path=None)
    app = AppContext(config)
    assert app.selected_device_serial is None

    from lockknife.core.device import DeviceHandle, DeviceState
    from lockknife_headless_cli import tui_callback as tcb

    monkeypatch.setattr(
        app.devices,
        "list_handles",
        lambda: [DeviceHandle(serial="NEW_DEV_777", adb_state="device", state=DeviceState.authorized)],
    )
    monkeypatch.setattr(app.devices, "has_root", lambda s: True)
    monkeypatch.setattr(app.devices, "shell", lambda s, c, **kw: "mock_output")
    monkeypatch.setattr(tcb, "recover_pin", lambda devs, s, length: "9999")

    callback = build_tui_callback(app)
    res = callback("credentials.pin", {"serial": "NEW_DEV_777", "length": 4})
    assert res["ok"] is True
    assert app.selected_device_serial == "NEW_DEV_777"


