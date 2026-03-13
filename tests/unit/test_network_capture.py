import pathlib

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.network.capture import capture_pcap


class _FakeAdb:
    def shell(self, serial: str, cmd: str, timeout_s: float = 0.0) -> str:
        return ""

    def pull(self, serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        local.write_bytes(b"pcap-bytes")


class _FakeDevices:
    def __init__(self, *, root: bool) -> None:
        self._adb = _FakeAdb()
        self._root = root

    def shell(self, serial: str, cmd: str, timeout_s: float = 0.0) -> str:
        return self._adb.shell(serial, cmd, timeout_s=timeout_s)

    def pull(self, serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        return self._adb.pull(serial, remote, local, timeout_s=timeout_s)

    def has_root(self, serial: str) -> bool:
        return bool(self._root)


def test_capture_pcap_requires_root(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=False)
    with pytest.raises(DeviceError):
        capture_pcap(devices, "SERIAL", output_path=tmp_path / "x.pcap")  # type: ignore[arg-type]


def test_capture_pcap_writes_output(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=True)
    out = tmp_path / "cap.pcap"
    res = capture_pcap(devices, "SERIAL", output_path=out, duration_s=1.0)  # type: ignore[arg-type]
    assert out.exists()
    assert out.read_bytes() == b"pcap-bytes"
    assert res.local_path == str(out)


def test_capture_pcap_rejects_unsafe_iface(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=True)
    with pytest.raises(ValueError, match="unsafe"):
        capture_pcap(devices, "SERIAL", output_path=tmp_path / "cap.pcap", iface="any;id")  # type: ignore[arg-type]


def test_capture_pcap_accepts_iface_with_at_symbol(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=True)
    out = tmp_path / "cap2.pcap"
    res = capture_pcap(devices, "SERIAL", output_path=out, duration_s=1.0, iface="wlan0@if2")  # type: ignore[arg-type]
    assert out.exists()
    assert res.local_path == str(out)


def test_capture_pcap_emits_progress_and_tolerates_cleanup_failures(tmp_path: pathlib.Path) -> None:
    events: list[dict[str, object]] = []

    class _CleanupDevices(_FakeDevices):
        def shell(self, serial: str, cmd: str, timeout_s: float = 0.0) -> str:
            if "rm -f" in cmd:
                raise DeviceError("cleanup blocked")
            return super().shell(serial, cmd, timeout_s=timeout_s)

    devices = _CleanupDevices(root=True)
    capture_pcap(
        devices,
        "SERIAL",
        output_path=tmp_path / "cap3.pcap",
        duration_s=1.0,
        progress_callback=events.append,
    )  # type: ignore[arg-type]

    assert [str(event["step"]) for event in events] == ["start", "pull", "cleanup", "complete"]


def test_capture_pcap_rejects_invalid_snaplen(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=True)
    with pytest.raises(ValueError, match="snaplen"):
        capture_pcap(devices, "SERIAL", output_path=tmp_path / "cap4.pcap", snaplen=70000)  # type: ignore[arg-type]
