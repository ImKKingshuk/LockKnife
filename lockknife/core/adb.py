from __future__ import annotations

import dataclasses
import pathlib
import re
import subprocess  # nosec B404
import time
from typing import Sequence

from lockknife.core.exceptions import DeviceError, ExternalToolError
from lockknife.core.logging import get_logger


@dataclasses.dataclass(frozen=True)
class AdbDevice:
    """Represents a single `adb devices -l` entry."""

    serial: str
    state: str
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None


class AdbClient:
    """Type-safe wrapper around the `adb` CLI."""

    def __init__(self, adb_path: str = "adb") -> None:
        """Create a new client.

        Args:
            adb_path: Path to the adb binary.
        """
        self._adb_path = adb_path
        self._log = get_logger()

    @property
    def adb_path(self) -> str:
        """Return the adb binary path."""
        return self._adb_path

    def run(self, args: Sequence[str], timeout_s: float = 30.0) -> str:
        """Run an adb command and return stdout.

        Args:
            args: adb arguments, excluding the adb binary itself.
            timeout_s: Maximum runtime.

        Returns:
            Command stdout.

        Raises:
            ExternalToolError: If adb is missing, times out, or returns non-zero.
        """
        start = time.perf_counter()
        self._log.debug("adb_run_start", adb_path=self._adb_path, args=list(args), timeout_s=timeout_s)
        try:
            proc = subprocess.run(  # nosec B603
                [self._adb_path, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except FileNotFoundError as e:
            self._log.error("adb_run_missing", adb_path=self._adb_path, args=list(args), exc_info=True)
            raise ExternalToolError(f"adb not found: {self._adb_path}") from e
        except subprocess.TimeoutExpired as e:
            self._log.error("adb_run_timeout", adb_path=self._adb_path, args=list(args), timeout_s=timeout_s, exc_info=True)
            raise ExternalToolError(f"adb timed out: {args}") from e

        if proc.returncode != 0:
            msg = proc.stderr.strip() or proc.stdout.strip() or f"adb failed: {args}"
            self._log.error(
                "adb_run_failed",
                adb_path=self._adb_path,
                args=list(args),
                rc=proc.returncode,
                elapsed_s=round(time.perf_counter() - start, 6),
                stderr=(proc.stderr.strip()[:400] if proc.stderr else ""),
                stdout=(proc.stdout.strip()[:400] if proc.stdout else ""),
            )
            raise ExternalToolError(msg)
        self._log.debug("adb_run_ok", adb_path=self._adb_path, args=list(args), elapsed_s=round(time.perf_counter() - start, 6))
        return proc.stdout

    def list_devices(self) -> list[AdbDevice]:
        """List devices visible to adb."""
        out = self.run(["devices", "-l"])
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        devices: list[AdbDevice] = []
        for ln in lines[1:]:
            if ln.startswith("*"):
                continue
            parts = ln.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            kv = {}
            for p in parts[2:]:
                if ":" not in p:
                    continue
                k, v = p.split(":", 1)
                kv[k] = v
            devices.append(
                AdbDevice(
                    serial=serial,
                    state=state,
                    model=kv.get("model"),
                    device=kv.get("device"),
                    transport_id=kv.get("transport_id"),
                )
            )
        return devices

    def connect(self, host: str, timeout_s: float = 10.0) -> str:
        """Connect to a TCP/IP device.

        Args:
            host: Host:port endpoint.
            timeout_s: Maximum runtime.
        """
        self._log.info("adb_connect", host=host, timeout_s=timeout_s)
        return self.run(["connect", host], timeout_s=timeout_s).strip()

    def shell(self, serial: str, command: str, timeout_s: float = 30.0) -> str:
        """Run `adb shell` on a device and return stdout.

        Args:
            serial: Device serial.
            command: Shell command.
            timeout_s: Maximum runtime.

        Raises:
            DeviceError: If serial is missing.
            ExternalToolError: If adb fails.
        """
        if not serial:
            raise DeviceError("Missing device serial")
        self._log.debug(
            "adb_shell",
            serial=serial,
            command=(command[:256] + "…" if len(command) > 256 else command),
            timeout_s=timeout_s,
        )
        return self.run(["-s", serial, "shell", command], timeout_s=timeout_s)

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 120.0) -> None:
        """Pull a file from the device.

        Args:
            serial: Device serial.
            remote_path: Path on the device.
            local_path: Destination path.
            timeout_s: Maximum runtime.
        """
        if not serial:
            raise DeviceError("Missing device serial")
        local_path.parent.mkdir(parents=True, exist_ok=True)
        self._log.debug("adb_pull", serial=serial, remote_path=remote_path, local_path=str(local_path), timeout_s=timeout_s)
        self.run(["-s", serial, "pull", remote_path, str(local_path)], timeout_s=timeout_s)

    def push(self, serial: str, local_path: pathlib.Path, remote_path: str, timeout_s: float = 120.0) -> None:
        """Push a file to the device.

        Args:
            serial: Device serial.
            local_path: Source path.
            remote_path: Destination path on the device.
            timeout_s: Maximum runtime.
        """
        if not serial:
            raise DeviceError("Missing device serial")
        if not local_path.exists():
            raise DeviceError(f"Local path does not exist: {local_path}")
        self._log.debug("adb_push", serial=serial, local_path=str(local_path), remote_path=remote_path, timeout_s=timeout_s)
        self.run(["-s", serial, "push", str(local_path), remote_path], timeout_s=timeout_s)

    def install(self, serial: str, apk_path: pathlib.Path, replace: bool = True, timeout_s: float = 300.0) -> str:
        """Install an APK on the device."""
        if not serial:
            raise DeviceError("Missing device serial")
        if not apk_path.exists():
            raise DeviceError(f"APK does not exist: {apk_path}")
        args = ["-s", serial, "install"]
        if replace:
            args.append("-r")
        args.append(str(apk_path))
        self._log.info("adb_install", serial=serial, apk_path=str(apk_path), replace=replace, timeout_s=timeout_s)
        return self.run(args, timeout_s=timeout_s).strip()

    def uninstall(self, serial: str, package_name: str, keep_data: bool = False, timeout_s: float = 60.0) -> str:
        """Uninstall a package from the device."""
        if not serial:
            raise DeviceError("Missing device serial")
        args = ["-s", serial, "uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package_name)
        self._log.info("adb_uninstall", serial=serial, package_name=package_name, keep_data=keep_data, timeout_s=timeout_s)
        return self.run(args, timeout_s=timeout_s).strip()

    def has_su(self, serial: str) -> bool:
        """Return True if `su` exists on the device."""
        self._log.debug("adb_has_su", serial=serial)
        out = self.shell(serial, "command -v su >/dev/null 2>&1; echo $?", timeout_s=10.0)
        return out.strip().endswith("0")

    def getprop(self, serial: str) -> dict[str, str]:
        """Return Android system properties via `getprop`."""
        self._log.debug("adb_getprop", serial=serial)
        raw = self.shell(serial, "getprop", timeout_s=15.0)
        props: dict[str, str] = {}
        pattern = re.compile(r"^\[(?P<k>.+?)\]: \[(?P<v>.*)\]$")
        for line in raw.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            props[m.group("k")] = m.group("v")
        return props
