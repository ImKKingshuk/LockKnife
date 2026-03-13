from __future__ import annotations

import builtins
import dataclasses
import enum
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, TypeVar

from lockknife.core.adb import AdbClient, AdbDevice
from lockknife.core.logging import get_logger


@dataclasses.dataclass(frozen=True)
class DeviceInfo:
    """Device properties captured via `getprop`."""

    serial: str
    props: dict[str, str]


class DeviceState(str, enum.Enum):
    """High-level LockKnife state derived from adb state."""

    disconnected = "disconnected"
    connecting = "connecting"
    connected = "connected"
    authorized = "authorized"


@dataclasses.dataclass(frozen=True)
class DeviceHandle:
    """Decorated device record combining adb and LockKnife states."""

    serial: str
    adb_state: str
    state: DeviceState
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None


T = TypeVar("T")


class DeviceManager:
    """Tracks device state and fans out operations across multiple devices."""

    def __init__(self, adb: AdbClient) -> None:
        """Create a manager bound to an adb client."""
        self._adb = adb
        self._states: dict[str, DeviceState] = {}
        self._log = get_logger()

    def list(self) -> builtins.list[AdbDevice]:
        """List raw adb devices."""
        self._log.debug("devices_list")
        return self._adb.list_devices()

    def list_handles(self) -> builtins.list[DeviceHandle]:
        """List devices as `DeviceHandle` entries and cache their state."""
        self._log.debug("devices_list_handles_start")
        out: builtins.list[DeviceHandle] = []
        for d in self._adb.list_devices():
            state = self._classify_state(d.state)
            out.append(
                DeviceHandle(
                    serial=d.serial,
                    adb_state=d.state,
                    state=state,
                    model=d.model,
                    device=d.device,
                    transport_id=d.transport_id,
                )
            )
            self._states[d.serial] = state
        self._log.debug("devices_list_handles_done", count=len(out))
        return out

    def get_state(self, serial: str) -> DeviceState:
        """Return the cached or currently observed device state."""
        if serial in self._states:
            return self._states[serial]
        for d in self._adb.list_devices():
            if d.serial == serial:
                st = self._classify_state(d.state)
                self._states[serial] = st
                return st
        return DeviceState.disconnected

    def connect_device(self, host: str) -> str:
        """Connect to a device by host:port and update manager state."""
        self._states[host] = DeviceState.connecting
        self._log.info("device_connect_start", host=host)
        out = self._adb.connect(host)
        self._states[host] = DeviceState.connected
        self._log.info("device_connect_done", host=host)
        return out

    def connect(self, host: str) -> str:
        """Connect to a device by host:port."""
        self._log.info("device_connect", host=host)
        return self._adb.connect(host)

    def info(self, serial: str) -> DeviceInfo:
        """Return `getprop` values for a device."""
        self._log.debug("device_info", serial=serial)
        props = self._adb.getprop(serial)
        return DeviceInfo(serial=serial, props=props)

    def has_root(self, serial: str) -> bool:
        """Return True if root (su) is available on the device."""
        self._log.debug("device_has_root", serial=serial)
        return self._adb.has_su(serial)

    def shell(self, serial: str, command: str, timeout_s: float = 30.0) -> str:
        """Run a shell command on a device."""
        self._log.debug("device_shell", serial=serial, timeout_s=timeout_s)
        return self._adb.shell(serial, command, timeout_s=timeout_s)

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 120.0) -> None:
        """Pull a file from a device and record it in the chain-of-custody log."""
        from lockknife.core.custody import log_pull
        from lockknife.core.metrics import track
        self._log.debug("device_pull", serial=serial, remote_path=remote_path, local_path=str(local_path), timeout_s=timeout_s)
        with track("adb.pull"):
            self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)
        log_pull(serial=serial, remote_path=remote_path, local_path=local_path)

    def push(self, serial: str, local_path: pathlib.Path, remote_path: str, timeout_s: float = 120.0) -> None:
        """Push a file to a device and record it in the chain-of-custody log."""
        from lockknife.core.custody import log_push
        from lockknife.core.metrics import track
        self._log.debug("device_push", serial=serial, local_path=str(local_path), remote_path=remote_path, timeout_s=timeout_s)
        with track("adb.push"):
            self._adb.push(serial, local_path, remote_path, timeout_s=timeout_s)
        log_push(serial=serial, local_path=local_path, remote_path=remote_path)

    def install(self, serial: str, apk_path: pathlib.Path, replace: bool = True, timeout_s: float = 300.0) -> str:
        """Install an APK on a device."""
        self._log.info("device_install", serial=serial, apk_path=str(apk_path), replace=replace)
        return self._adb.install(serial, apk_path, replace=replace, timeout_s=timeout_s)

    def uninstall(self, serial: str, package_name: str, keep_data: bool = False, timeout_s: float = 60.0) -> str:
        """Uninstall a package from a device."""
        self._log.info("device_uninstall", serial=serial, package_name=package_name, keep_data=keep_data)
        return self._adb.uninstall(serial, package_name, keep_data=keep_data, timeout_s=timeout_s)

    def authorized_serials(self) -> builtins.list[str]:
        """Return adb serials that are in the 'authorized' state."""
        serials = [d.serial for d in self._adb.list_devices() if self._classify_state(d.state) == DeviceState.authorized]
        self._log.debug("devices_authorized_serials", count=len(serials))
        return serials

    def map_devices(
        self,
        func: Callable[[str], T],
        *,
        serials: builtins.list[str] | None = None,
        max_workers: int = 8,
    ) -> dict[str, T | Exception]:
        """Run `func(serial)` over devices in parallel.

        Args:
            func: Callable executed per serial.
            serials: Optional subset of serials to operate on.
            max_workers: Max thread pool size.

        Returns:
            Mapping of serial to result or exception.
        """
        targets = serials or [d.serial for d in self._adb.list_devices()]
        results: dict[str, T | Exception] = {}
        if not targets:
            return results
        workers = min(max_workers, max(1, len(targets)))
        self._log.debug("devices_map_start", targets=len(targets), workers=workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(func, s): s for s in targets}
            for fut in as_completed(futs):
                s = futs[fut]
                try:
                    results[s] = fut.result()
                except Exception as e:
                    self._log.debug("devices_map_error", serial=s, exc_info=True)
                    results[s] = e
        self._log.debug("devices_map_done", results=len(results))
        return results

    def _classify_state(self, adb_state: str) -> DeviceState:
        s = (adb_state or "").strip().lower()
        if s == "device":
            return DeviceState.authorized
        if s in {"unauthorized", "recovery", "sideload", "rescue"}:
            return DeviceState.connected
        if s in {"offline", "disconnected"}:
            return DeviceState.disconnected
        return DeviceState.connected
