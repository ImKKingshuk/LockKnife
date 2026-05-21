from __future__ import annotations

import lzma
import os
import pathlib
import time

from lockknife.core.adb import AdbClient
from lockknife.core.exceptions import DeviceError
from lockknife.core.http import http_get
from lockknife.core.logging import get_logger

log = get_logger()


class FridaBooster:
    """Manages frida-server detection, mapping, downloading, and auto-remediation on Android targets."""

    def __init__(self, adb: AdbClient, serial: str) -> None:
        self._adb = adb
        self._serial = serial

    def is_server_running(self) -> bool:
        """Return True if a process containing 'frida-server' is running on the device."""
        if not self._serial:
            return False
        try:
            out = self._adb.shell(
                self._serial,
                "ps -A 2>/dev/null | grep frida-server || ps 2>/dev/null | grep frida-server",
                timeout_s=5.0,
            )
            return "frida-server" in out
        except Exception:
            return False

    def get_device_abi(self) -> str:
        """Detect the primary CPU ABI of the device and map to the corresponding Frida architecture."""
        if not self._serial:
            return "android-arm64"
        try:
            props = self._adb.getprop(self._serial)
            abi = props.get("ro.product.cpu.abi") or ""
            abilist = props.get("ro.product.cpu.abilist") or ""
        except Exception as e:
            log.warning("booster_getprop_failed", serial=self._serial, exc_info=True)
            return "android-arm64"

        # Match CPU architectures
        candidates = [abi] + [a.strip() for a in abilist.split(",") if a.strip()]
        for cand in candidates:
            c = cand.lower()
            if "arm64" in c or "aarch64" in c:
                return "android-arm64"
            if "armeabi-v7" in c or "armeabi" in c or "arm" in c:
                return "android-arm"
            if "x86_64" in c:
                return "android-x86_64"
            if "x86" in c:
                return "android-x86"

        return "android-arm64"  # Default fallback

    def download_server(self, version: str, arch: str) -> pathlib.Path:
        """Download and extract matching frida-server release binary into the local cache."""
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-{arch}.xz"

        cache_root = pathlib.Path.home() / ".cache" / "lockknife" / "frida"
        cache_root.mkdir(parents=True, exist_ok=True)
        dest_path = cache_root / f"frida-server-{version}-{arch}"

        # If already cached, return immediately
        if dest_path.exists() and dest_path.stat().st_size > 1000000:
            return dest_path

        log.info("booster_downloading_frida_server", version=version, arch=arch, url=url)
        try:
            # Cache the download for 30 days
            xz_data = http_get(url, cache_ttl_s=30 * 86400)
            if not xz_data:
                raise DeviceError("Empty payload received from Frida release URL.")

            log.info("booster_decompressing_frida_server", version=version, arch=arch)
            decompressed = lzma.decompress(xz_data)

            dest_path.write_bytes(decompressed)
            os.chmod(dest_path, 0o755)  # nosec B103 - frida-server binary must be executable
            return dest_path
        except Exception as e:
            raise DeviceError(f"Failed to fetch/decompress frida-server release: {e}") from e

    def deploy_and_start(self, local_bin_path: pathlib.Path) -> bool:
        """Push frida-server to the device, configure permissions, and spawn the daemon."""
        if not self._serial:
            raise DeviceError("Missing device serial for deployment.")

        remote_path = "/data/local/tmp/frida-server"

        # 1. Stop any existing running instances
        log.info("booster_stopping_existing_frida", serial=self._serial)
        try:
            self._adb.shell(
                self._serial,
                "pkill -f frida-server || killall frida-server || kill -9 $(pgrep frida-server)",
                timeout_s=5.0,
            )
            time.sleep(0.5)
        except Exception:
            pass

        # 2. Push to target
        log.info("booster_pushing_binary", serial=self._serial, local=str(local_bin_path))
        try:
            self._adb.push(self._serial, local_bin_path, remote_path)
        except Exception as e:
            raise DeviceError(f"Failed to push frida-server binary to target device: {e}") from e

        # 3. Grant execution permissions
        try:
            self._adb.shell(self._serial, f"chmod 755 {remote_path}", timeout_s=5.0)
        except Exception as e:
            raise DeviceError(f"Failed to chmod frida-server: {e}") from e

        # 4. Spawning
        log.info("booster_spawning_daemon", serial=self._serial)
        try:
            if self._adb.has_su(self._serial):
                # Spawn daemon securely as root
                self._adb.shell(self._serial, f"su -c '{remote_path} -D'", timeout_s=10.0)
            else:
                # Fallback to direct background execution
                self._adb.shell(self._serial, f"{remote_path} -D", timeout_s=10.0)
            return True
        except Exception as e:
            raise DeviceError(f"Failed to execute frida-server daemon: {e}") from e

    def remediate(self) -> bool:
        """Execute full auto-remediation flow: check status, download matching release, deploy and verify."""
        if self.is_server_running():
            log.info("booster_frida_already_running", serial=self._serial)
            return True

        # Get local frida version
        try:
            import frida

            version = frida.__version__
        except ImportError:
            version = "16.2.1"  # A solid default fallback version

        arch = self.get_device_abi()
        log.info("booster_start_remediation", serial=self._serial, version=version, arch=arch)

        # Download
        local_path = self.download_server(version, arch)

        # Deploy & Start
        self.deploy_and_start(local_path)

        # Verification Poll
        for _attempt in range(5):
            time.sleep(1.0)
            if self.is_server_running():
                log.info("booster_remediation_success", serial=self._serial)
                return True

        log.warning("booster_remediation_unverified", serial=self._serial)
        return False
