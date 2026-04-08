from __future__ import annotations

import dataclasses
import pathlib
import re
import subprocess  # nosec B404
import time
from collections.abc import Sequence

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
        self._log.debug(
            "adb_run_start", adb_path=self._adb_path, args=list(args), timeout_s=timeout_s
        )
        try:
            proc = subprocess.run(  # nosec B603
                [self._adb_path, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except FileNotFoundError as e:
            self._log.error(
                "adb_run_missing", adb_path=self._adb_path, args=list(args), exc_info=True
            )
            raise ExternalToolError(f"adb not found: {self._adb_path}") from e
        except subprocess.TimeoutExpired as e:
            self._log.error(
                "adb_run_timeout",
                adb_path=self._adb_path,
                args=list(args),
                timeout_s=timeout_s,
                exc_info=True,
            )
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
        self._log.debug(
            "adb_run_ok",
            adb_path=self._adb_path,
            args=list(args),
            elapsed_s=round(time.perf_counter() - start, 6),
        )
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

    def pull(
        self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 120.0
    ) -> None:
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
        self._log.debug(
            "adb_pull",
            serial=serial,
            remote_path=remote_path,
            local_path=str(local_path),
            timeout_s=timeout_s,
        )
        self.run(["-s", serial, "pull", remote_path, str(local_path)], timeout_s=timeout_s)

    def push(
        self, serial: str, local_path: pathlib.Path, remote_path: str, timeout_s: float = 120.0
    ) -> None:
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
        self._log.debug(
            "adb_push",
            serial=serial,
            local_path=str(local_path),
            remote_path=remote_path,
            timeout_s=timeout_s,
        )
        self.run(["-s", serial, "push", str(local_path), remote_path], timeout_s=timeout_s)

    def install(
        self, serial: str, apk_path: pathlib.Path, replace: bool = True, timeout_s: float = 300.0
    ) -> str:
        """Install an APK on the device."""
        if not serial:
            raise DeviceError("Missing device serial")
        if not apk_path.exists():
            raise DeviceError(f"APK does not exist: {apk_path}")
        args = ["-s", serial, "install"]
        if replace:
            args.append("-r")
        args.append(str(apk_path))
        self._log.info(
            "adb_install",
            serial=serial,
            apk_path=str(apk_path),
            replace=replace,
            timeout_s=timeout_s,
        )
        return self.run(args, timeout_s=timeout_s).strip()

    def uninstall(
        self, serial: str, package_name: str, keep_data: bool = False, timeout_s: float = 60.0
    ) -> str:
        """Uninstall a package from the device."""
        if not serial:
            raise DeviceError("Missing device serial")
        args = ["-s", serial, "uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package_name)
        self._log.info(
            "adb_uninstall",
            serial=serial,
            package_name=package_name,
            keep_data=keep_data,
            timeout_s=timeout_s,
        )
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

    # ========================================================================
    # Exploitation Methods (Phase 2)
    # ========================================================================

    def disconnect(self, host: str, timeout_s: float = 10.0) -> str:
        """Disconnect from a TCP/IP device.

        Args:
            host: Host:port endpoint.
            timeout_s: Maximum runtime.

        Returns:
            Command output.
        """
        self._log.info("adb_disconnect", host=host)
        return self.run(["disconnect", host], timeout_s=timeout_s).strip()

    def tcp_port(self, serial: str, port: int = 5555, timeout_s: float = 10.0) -> str:
        """Restart ADB daemon on device with TCP on specified port.

        Args:
            serial: Device serial.
            port: TCP port (default 5555).
            timeout_s: Maximum runtime.

        Returns:
            Command output.
        """
        if not serial:
            raise DeviceError("Missing device serial")
        self._log.info("adb_tcp_port", serial=serial, port=port)
        return self.run(["-s", serial, "tcpip", str(port)], timeout_s=timeout_s).strip()

    def is_tcp_device(self, serial: str) -> bool:
        """Check if a device serial is a TCP/IP endpoint.

        Args:
            serial: Device serial.

        Returns:
            True if serial looks like IP:port.
        """
        import re

        # Match IP:port pattern
        ip_port_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$"
        return bool(re.match(ip_port_pattern, serial))

    def check_adb_auth(self, serial: str, timeout_s: float = 10.0) -> dict[str, Any]:
        """Check if ADB requires authorization.

        Args:
            serial: Device serial.
            timeout_s: Maximum runtime.

        Returns:
            Dict with auth status information.
        """

        result: dict[str, Any] = {
            "authorized": False,
            "unauthorized": False,
            "offline": False,
            "error": None,
        }

        try:
            # Check device state
            devices = self.list_devices()
            for dev in devices:
                if dev.serial == serial:
                    if dev.state == "device":
                        result["authorized"] = True
                    elif dev.state == "unauthorized":
                        result["unauthorized"] = True
                    elif dev.state == "offline":
                        result["offline"] = True
                    break

            # Try a simple command to verify
            if result["authorized"]:
                try:
                    self.shell(serial, "echo test", timeout_s=timeout_s)
                    result["shell_access"] = True
                except ExternalToolError:
                    result["shell_access"] = False

        except Exception as e:
            result["error"] = str(e)

        return result

    def check_root(self, serial: str, timeout_s: float = 10.0) -> dict[str, Any]:
        """Check for root access on device.

        Args:
            serial: Device serial.
            timeout_s: Maximum runtime.

        Returns:
            Dict with root status information.
        """
        result: dict[str, Any] = {
            "has_su": False,
            "has_root": False,
            "has_adb_root": False,
            "error": None,
        }

        try:
            # Check for su binary
            result["has_su"] = self.has_su(serial)

            # Check current user
            user = self.shell(serial, "id", timeout_s=timeout_s).strip()
            result["current_user"] = user

            if "uid=0" in user or "root" in user:
                result["has_root"] = True

            # Try adb root
            try:
                root_out = self.run(["-s", serial, "root"], timeout_s=timeout_s)
                if (
                    "restarting adbd as root" in root_out.lower()
                    or "already running as root" in root_out.lower()
                ):
                    result["has_adb_root"] = True
            except ExternalToolError:
                pass

        except Exception as e:
            result["error"] = str(e)

        return result

    def get_device_info(self, serial: str, timeout_s: float = 30.0) -> dict[str, Any]:
        """Get comprehensive device information.

        Args:
            serial: Device serial.
            timeout_s: Maximum runtime.

        Returns:
            Dict with device information.
        """
        info: dict[str, Any] = {}

        try:
            # Get system properties
            props = self.getprop(serial)

            info["android_version"] = props.get("ro.build.version.release", "Unknown")
            info["sdk_version"] = props.get("ro.build.version.sdk", "Unknown")
            info["build_fingerprint"] = props.get("ro.build.fingerprint", "Unknown")
            info["model"] = props.get("ro.product.model", "Unknown")
            info["manufacturer"] = props.get("ro.product.manufacturer", "Unknown")
            info["device"] = props.get("ro.product.device", "Unknown")
            info["product"] = props.get("ro.product.name", "Unknown")
            info["brand"] = props.get("ro.product.brand", "Unknown")
            info["security_patch"] = props.get("ro.build.version.security_patch", "Unknown")
            info["is_secure"] = props.get("ro.secure", "1") == "1"
            info["is_debuggable"] = props.get("ro.debuggable", "0") == "1"
            info["build_type"] = props.get("ro.build.type", "Unknown")
            info["build_tags"] = props.get("ro.build.tags", "Unknown")

            # Get current user
            info["current_user"] = self.shell(serial, "id", timeout_s=timeout_s).strip()

            # Check for root
            root_info = self.check_root(serial, timeout_s)
            info["has_root"] = root_info.get("has_root", False)
            info["has_su"] = root_info.get("has_su", False)

            # Get network info
            try:
                ip_info = self.shell(
                    serial, "ip addr show wlan0 2>/dev/null | grep 'inet '", timeout_s=timeout_s
                )
                if ip_info:
                    import re

                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_info)
                    if match:
                        info["ip_address"] = match.group(1)
            except Exception:
                pass

        except Exception as e:
            info["error"] = str(e)

        return info

    def list_packages(
        self, serial: str, filter_type: str = "all", timeout_s: float = 60.0
    ) -> list[str]:
        """List installed packages on device.

        Args:
            serial: Device serial.
            filter_type: Filter type (all, third-party, system, enabled, disabled).
            timeout_s: Maximum runtime.

        Returns:
            List of package names.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        args = ["-s", serial, "shell", "pm", "list", "packages"]

        if filter_type == "third-party":
            args.append("-3")
        elif filter_type == "system":
            args.append("-s")
        elif filter_type == "enabled":
            args.append("-e")
        elif filter_type == "disabled":
            args.append("-d")

        self._log.debug("adb_list_packages", serial=serial, filter=filter_type)

        output = self.run(args, timeout_s=timeout_s)
        packages: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line[8:])

        return packages

    def get_package_info(
        self, serial: str, package_name: str, timeout_s: float = 30.0
    ) -> dict[str, Any]:
        """Get detailed package information.

        Args:
            serial: Device serial.
            package_name: Package name.
            timeout_s: Maximum runtime.

        Returns:
            Dict with package information.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        info: dict[str, Any] = {"package_name": package_name}

        try:
            output = self.shell(serial, f"dumpsys package {package_name}", timeout_s=timeout_s)

            for line in output.splitlines():
                line = line.strip()

                if line.startswith("versionName="):
                    info["version_name"] = line.split("=")[1]
                elif line.startswith("versionCode="):
                    try:
                        info["version_code"] = int(line.split("=")[1])
                    except ValueError:
                        pass
                elif "dataDir=" in line:
                    info["data_dir"] = line.split("dataDir=")[1].split()[0]
                elif "sourceDir=" in line:
                    info["apk_path"] = line.split("sourceDir=")[1].split()[0]
                elif "primaryCpuAbi=" in line:
                    info["abi"] = line.split("primaryCpuAbi=")[1].split()[0]
                elif "targetSdk=" in line:
                    try:
                        info["target_sdk"] = int(line.split("targetSdk=")[1].split()[0])
                    except (ValueError, IndexError):
                        pass

            # Check if debuggable
            if "debuggable" in output.lower():
                info["is_debuggable"] = True

        except Exception as e:
            info["error"] = str(e)

        return info

    def pull_directory(
        self,
        serial: str,
        remote_dir: str,
        local_dir: pathlib.Path,
        timeout_s: float = 600.0,
    ) -> bool:
        """Pull a directory from the device.

        Args:
            serial: Device serial.
            remote_dir: Remote directory path.
            local_dir: Local destination directory.
            timeout_s: Maximum runtime.

        Returns:
            True if successful.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        local_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._log.info(
                "adb_pull_directory", serial=serial, remote=remote_dir, local=str(local_dir)
            )
            self.run(["-s", serial, "pull", remote_dir, str(local_dir)], timeout_s=timeout_s)
            return True
        except ExternalToolError:
            return False

    def push_directory(
        self,
        serial: str,
        local_dir: pathlib.Path,
        remote_dir: str,
        timeout_s: float = 600.0,
    ) -> bool:
        """Push a directory to the device.

        Args:
            serial: Device serial.
            local_dir: Local source directory.
            remote_dir: Remote destination directory.
            timeout_s: Maximum runtime.

        Returns:
            True if successful.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        if not local_dir.exists():
            raise DeviceError(f"Local directory does not exist: {local_dir}")

        try:
            self._log.info(
                "adb_push_directory", serial=serial, local=str(local_dir), remote=remote_dir
            )
            self.run(["-s", serial, "push", str(local_dir), remote_dir], timeout_s=timeout_s)
            return True
        except ExternalToolError:
            return False

    def backup(
        self,
        serial: str,
        output_path: pathlib.Path,
        packages: list[str] | None = None,
        include_apk: bool = True,
        include_shared: bool = True,
        timeout_s: float = 600.0,
    ) -> bool:
        """Create an ADB backup.

        Note: Requires user interaction on device to confirm backup.

        Args:
            serial: Device serial.
            output_path: Output file path (.ab).
            packages: Specific packages to backup (None for all).
            include_apk: Include APK files.
            include_shared: Include shared storage.
            timeout_s: Maximum runtime.

        Returns:
            True if backup file was created.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        args = ["-s", serial, "backup", "-f", str(output_path)]

        if include_apk:
            args.append("-apk")
        if include_shared:
            args.append("-shared")

        if packages:
            args.extend(packages)
        else:
            args.append("-all")

        self._log.info("adb_backup", serial=serial, output=str(output_path))

        try:
            # This will wait for user interaction
            self.run(args, timeout_s=timeout_s)
            return output_path.exists()
        except ExternalToolError:
            return output_path.exists()  # May have partial backup

    def restore(self, serial: str, backup_path: pathlib.Path, timeout_s: float = 600.0) -> str:
        """Restore an ADB backup.

        Note: Requires user interaction on device to confirm restore.

        Args:
            serial: Device serial.
            backup_path: Backup file path (.ab).
            timeout_s: Maximum runtime.

        Returns:
            Command output.
        """
        if not serial:
            raise DeviceError("Missing device serial")

        if not backup_path.exists():
            raise DeviceError(f"Backup file does not exist: {backup_path}")

        self._log.info("adb_restore", serial=serial, backup=str(backup_path))
        return self.run(["-s", serial, "restore", str(backup_path)], timeout_s=timeout_s).strip()


# Type annotation for Any
from typing import Any
