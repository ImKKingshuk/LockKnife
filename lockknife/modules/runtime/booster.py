from __future__ import annotations

import lzma
import os
import pathlib
import re
import time

from lockknife.core.adb import AdbClient
from lockknife.core.exceptions import DeviceError
from lockknife.core.execution_policy import ExecutionGateway, ExecutionIntent
from lockknife.core.http import http_get
from lockknife.core.logging import get_logger

log = get_logger()


class FridaBooster:
    """Manages frida-server detection, mapping, downloading, and auto-remediation on Android targets."""

    def __init__(
        self,
        adb: AdbClient,
        serial: str,
        *,
        execution_intent: ExecutionIntent | None = None,
        execution_gateway: ExecutionGateway | None = None,
    ) -> None:
        self._adb = adb
        self._serial = serial
        self._execution_intent = execution_intent
        self._execution_gateway = execution_gateway or ExecutionGateway()

    def _intent(self, override: ExecutionIntent | None = None) -> ExecutionIntent:
        intent = override or self._execution_intent
        if intent is None:
            raise DeviceError("Frida remediation requires an ExecutionIntent")
        return intent

    def _adb_path(self) -> str:
        path = getattr(self._adb, "adb_path", "adb")
        return str(path or "adb")

    def _run_adb(
        self,
        argv: list[str],
        *,
        timeout_s: float,
        execution_intent: ExecutionIntent | None = None,
        check: bool = True,
    ) -> str:
        intent = self._intent(execution_intent)
        result = self._execution_gateway.run_adb(
            intent,
            argv,
            adb_path=self._adb_path(),
            timeout_s=timeout_s,
        )
        if check and result.return_code != 0:
            msg = result.stderr.strip() or result.stdout.strip() or f"adb failed: {argv}"
            raise DeviceError(msg)
        return result.stdout

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

    def download_server(
        self,
        version: str,
        arch: str,
        *,
        expected_sha256: str | None = None,
        execution_intent: ExecutionIntent | None = None,
    ) -> pathlib.Path:
        """Download and extract matching frida-server release binary into the local cache."""
        intent = self._intent(execution_intent)
        expected_sha256 = expected_sha256 or _expected_sha256_from_env(version, arch)
        if not expected_sha256:
            raise DeviceError("Refusing to download frida-server without a pinned SHA-256 digest.")
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-{arch}.xz"

        cache_root = pathlib.Path.home() / ".cache" / "lockknife" / "frida"
        dest_path = cache_root / f"frida-server-{version}-{arch}"

        if dest_path.exists() and dest_path.stat().st_size > 1000000:
            _require_file_sha256(dest_path, expected_sha256)
            return dest_path

        self._execution_gateway.authorize_external_http(
            intent,
            method="GET",
            url=url,
            metadata={"component": "frida-server", "version": version, "arch": arch},
        )
        if intent.mode == "dry-run":
            return dest_path

        cache_root.mkdir(parents=True, exist_ok=True)
        log.info("booster_downloading_frida_server", version=version, arch=arch, url=url)
        try:
            xz_data = http_get(url, cache_ttl_s=30 * 86400)
            if not xz_data:
                raise DeviceError("Empty payload received from Frida release URL.")

            log.info("booster_decompressing_frida_server", version=version, arch=arch)
            decompressed = lzma.decompress(xz_data)

            dest_path.write_bytes(decompressed)
            os.chmod(dest_path, 0o755)  # nosec B103 - frida-server binary must be executable
            _require_file_sha256(dest_path, expected_sha256)
            return dest_path
        except Exception as e:
            raise DeviceError(f"Failed to fetch/decompress frida-server release: {e}") from e

    def deploy_and_start(
        self,
        local_bin_path: pathlib.Path,
        *,
        expected_sha256: str,
        execution_intent: ExecutionIntent | None = None,
    ) -> bool:
        """Push frida-server to the device, configure permissions, and spawn the daemon."""
        if not self._serial:
            raise DeviceError("Missing device serial for deployment.")
        intent = self._intent(execution_intent)
        if not local_bin_path.exists():
            raise DeviceError(f"frida-server binary does not exist: {local_bin_path}")
        _require_file_sha256(local_bin_path, expected_sha256)

        remote_path = "/data/local/tmp/frida-server"

        log.info("booster_stopping_existing_frida", serial=self._serial)
        self._run_adb(
            [
                "-s",
                self._serial,
                "shell",
                "pkill -f frida-server || killall frida-server || kill -9 $(pgrep frida-server)",
            ],
            timeout_s=5.0,
            execution_intent=intent,
            check=False,
        )
        if intent.mode != "dry-run":
            time.sleep(0.5)

        log.info("booster_pushing_binary", serial=self._serial, local=str(local_bin_path))
        self._run_adb(
            ["-s", self._serial, "push", str(local_bin_path), remote_path],
            timeout_s=120.0,
            execution_intent=intent,
        )

        self._run_adb(
            ["-s", self._serial, "shell", f"chmod 755 {remote_path}"],
            timeout_s=5.0,
            execution_intent=intent,
        )

        log.info("booster_spawning_daemon", serial=self._serial)
        if intent.mode == "dry-run":
            self._run_adb(
                ["-s", self._serial, "shell", f"{remote_path} -D"],
                timeout_s=10.0,
                execution_intent=intent,
            )
            return True
        if self._adb.has_su(self._serial):
            spawn_cmd = f"su -c '{remote_path} -D'"
        else:
            spawn_cmd = f"{remote_path} -D"
        self._run_adb(
            ["-s", self._serial, "shell", spawn_cmd],
            timeout_s=10.0,
            execution_intent=intent,
        )
        return True

    def remediate(
        self,
        *,
        local_binary: pathlib.Path | None = None,
        expected_sha256: str | None = None,
        version: str | None = None,
        arch: str | None = None,
        execution_intent: ExecutionIntent | None = None,
    ) -> bool:
        """Execute full auto-remediation flow: check status, download matching release, deploy and verify."""
        if self.is_server_running():
            log.info("booster_frida_already_running", serial=self._serial)
            return True
        intent = self._intent(execution_intent)

        if local_binary is not None:
            expected_sha256 = expected_sha256 or _expected_sha256_from_env("local", "local")
            if not expected_sha256:
                raise DeviceError("Local frida-server deployment requires expected_sha256.")
            local_path = local_binary
        else:
            if version is None:
                try:
                    import frida

                    version = frida.__version__
                except ImportError as exc:
                    raise DeviceError(
                        "Frida Python package is required to infer frida-server version."
                    ) from exc

            arch = arch or self.get_device_abi()
            expected_sha256 = expected_sha256 or _expected_sha256_from_env(version, arch)
            log.info("booster_start_remediation", serial=self._serial, version=version, arch=arch)
            local_path = self.download_server(
                version,
                arch,
                expected_sha256=expected_sha256,
                execution_intent=intent,
            )

        self.deploy_and_start(
            local_path, expected_sha256=expected_sha256 or "", execution_intent=intent
        )

        if intent.mode == "dry-run":
            return True
        for _attempt in range(5):
            time.sleep(1.0)
            if self.is_server_running():
                log.info("booster_remediation_success", serial=self._serial)
                return True

        log.warning("booster_remediation_unverified", serial=self._serial)
        return False


def _sha256_file(path: pathlib.Path) -> str:
    h = __import__("hashlib").sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_file_sha256(path: pathlib.Path, expected_sha256: str) -> None:
    expected = expected_sha256.strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise DeviceError("Expected frida-server SHA-256 must be a 64-character hex digest.")
    actual = _sha256_file(path)
    if actual != expected:
        raise DeviceError(f"frida-server SHA-256 mismatch: expected {expected}, got {actual}")


def _expected_sha256_from_env(version: str, arch: str) -> str | None:
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", f"{version}_{arch}").strip("_").upper()
    return os.environ.get(f"LOCKKNIFE_FRIDA_SERVER_SHA256_{suffix}") or os.environ.get(
        "LOCKKNIFE_FRIDA_SERVER_SHA256"
    )
