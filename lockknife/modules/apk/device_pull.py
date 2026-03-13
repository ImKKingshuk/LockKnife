from __future__ import annotations

import os
import pathlib
import re
import tempfile
import time

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger

log = get_logger()
_RE_ANDROID_PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def validate_android_package_name(package_name: str) -> str:
    candidate = package_name.strip()
    if not _RE_ANDROID_PKG.match(candidate):
        raise DeviceError("Invalid Android package name")
    return candidate


def pull_apk_from_device(devices: DeviceManager, serial: str, package_name: str, *, timeout_s: float = 180.0) -> pathlib.Path:
    package_name = validate_android_package_name(package_name)
    if not devices.has_root(serial):
        raise DeviceError("Root required to pull APK from /data/app")
    out = devices.shell(serial, f"pm path {package_name}", timeout_s=20.0)
    apk_paths = []
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("package:"):
            apk_paths.append(s.split("package:", 1)[1].strip())
    if not apk_paths:
        raise DeviceError("Unable to locate APK path via pm")

    remote_apk = apk_paths[0]
    tmp_remote = f"/sdcard/lockknife-{package_name}-{int(time.time())}.apk"
    devices.shell(
        serial,
        f'su -c "cp {_sh_quote(remote_apk)} {_sh_quote(tmp_remote)} 2>/dev/null"',
        timeout_s=60.0,
    )

    f = tempfile.NamedTemporaryFile(prefix="lockknife-apkpull-", suffix=".apk", delete=False)
    try:
        os.chmod(f.name, 0o600)
        f.close()
        local = pathlib.Path(f.name)
        devices.pull(serial, tmp_remote, local, timeout_s=timeout_s)
        return local
    finally:
        try:
            devices.shell(serial, f'su -c "rm -f {_sh_quote(tmp_remote)} 2>/dev/null"', timeout_s=10.0)
        except Exception:
            log.warning("apk_pull_cleanup_failed", exc_info=True, serial=serial, remote=tmp_remote)
