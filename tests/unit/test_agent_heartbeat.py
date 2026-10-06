from __future__ import annotations

from unittest.mock import MagicMock
from lockknife.core.adb import AdbDevice
from lockknife.core.agent.heartbeat import DeviceHeartbeatDaemon


def test_device_heartbeat_daemon_detection():
    mock_adb = MagicMock()
    dev1 = AdbDevice(serial="emulator-5554", state="device", model="Pixel_7")
    dev2 = AdbDevice(serial="device_physical_1", state="device", model="Galaxy_S23")

    mock_adb.list_devices.side_effect = [
        [dev1],          # Tick 1: emulator-5554 present
        [dev1, dev2],    # Tick 2: device_physical_1 attached
        [dev2],          # Tick 3: emulator-5554 detached
    ]

    attached_devices = []
    detached_devices = []

    daemon = DeviceHeartbeatDaemon(
        interval_s=0.1,
        adb_client=mock_adb,
        on_device_attached=lambda d: attached_devices.append(d.serial),
        on_device_detached=lambda s: detached_devices.append(s),
    )

    # Tick 1
    t1 = daemon.tick()
    assert t1["ok"] is True
    assert "emulator-5554" in attached_devices

    # Tick 2
    t2 = daemon.tick()
    assert t2["ok"] is True
    assert "device_physical_1" in attached_devices

    # Tick 3
    t3 = daemon.tick()
    assert t3["ok"] is True
    assert "emulator-5554" in detached_devices
