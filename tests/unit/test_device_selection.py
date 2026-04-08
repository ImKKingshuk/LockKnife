import pytest

from lockknife.core.device import DeviceHandle, DeviceState
from lockknife.core.device_selection import normalize_target_serials, resolve_single_device_serial
from lockknife.core.device_targeting import build_device_readiness_report
from lockknife.core.exceptions import DeviceError


class _Devices:
    def __init__(self, handles, *, root=True):
        self._handles = handles
        self._root = root

    def list_handles(self):
        return list(self._handles)

    def has_root(self, _serial: str) -> bool:
        return self._root


def test_normalize_target_serials_splits_csv_and_dedupes() -> None:
    assert normalize_target_serials(["abc, def", "def", "ghi"]) == ["abc", "def", "ghi"]


def test_resolve_single_device_serial_auto_selects_only_authorized_device() -> None:
    devices = _Devices(
        [DeviceHandle(serial="SER-1", adb_state="device", state=DeviceState.authorized)]
    )
    assert resolve_single_device_serial(devices, action_label="gesture recovery") == "SER-1"


def test_resolve_single_device_serial_rejects_multiple_authorized_devices_without_selection() -> (
    None
):
    devices = _Devices(
        [
            DeviceHandle(serial="SER-1", adb_state="device", state=DeviceState.authorized),
            DeviceHandle(serial="SER-2", adb_state="device", state=DeviceState.authorized),
        ]
    )
    with pytest.raises(DeviceError, match="Multiple authorized devices"):
        resolve_single_device_serial(devices, action_label="WiFi credential recovery")


def test_resolve_single_device_serial_rejects_unauthorized_explicit_target() -> None:
    devices = _Devices(
        [DeviceHandle(serial="SER-1", adb_state="unauthorized", state=DeviceState.connecting)]
    )
    with pytest.raises(DeviceError, match="currently unauthorized"):
        resolve_single_device_serial(devices, serial="SER-1", action_label="PIN recovery")


def test_build_device_readiness_report_surfaces_root_and_target_guidance() -> None:
    devices = _Devices(
        [
            DeviceHandle(serial="SER-1", adb_state="device", state=DeviceState.authorized),
            DeviceHandle(serial="SER-2", adb_state="device", state=DeviceState.authorized),
        ],
        root=False,
    )
    report = build_device_readiness_report(
        devices,
        workflow="tui credentials.passkeys",
        serial="SER-1",
        requires_root=True,
    )
    assert report.selected_serial == "SER-1"
    assert report.multiple_authorized is True
    assert report.root_available is False
    assert any("locked to SER-1" in line for line in report.guidance)
    assert any("does not expose root access" in line for line in report.guidance)
