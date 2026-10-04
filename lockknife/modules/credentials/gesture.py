from __future__ import annotations

import dataclasses
import pathlib

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.security import secure_temp_dir
from lockknife.modules.credentials._gesture_patterns import (
    gesture_point_count,
    recover_pattern_from_keyfile,
)


class GestureKeyNotFound(DeviceError):
    pass


@dataclasses.dataclass(frozen=True)
class GestureRecovery:
    serial: str
    pattern: str
    point_count: int
    key_path: pathlib.Path
    key_size: int
    source_remote_path: str = "/data/system/gesture.key"


def _try_pull_file_with_root(
    devices: DeviceManager, serial: str, remote: str, local: pathlib.Path, *, timeout_s: float = 60.0
) -> bool:
    try:
        devices.pull(serial, remote, local, timeout_s=timeout_s)
        if local.exists() and local.stat().st_size > 0:
            return True
    except Exception:
        pass

    staging_remote = f"/sdcard/lockknife-staging-{local.name}"
    quoted_remote = "'" + remote.replace("'", "'\"'\"'") + "'"
    quoted_staging = "'" + staging_remote.replace("'", "'\"'\"'") + "'"
    try:
        devices.shell(
            serial,
            f'su -c "cp {quoted_remote} {quoted_staging} 2>/dev/null || cat {quoted_remote} > {quoted_staging} 2>/dev/null"',
            timeout_s=timeout_s,
        )
        devices.pull(serial, staging_remote, local, timeout_s=timeout_s)
    except Exception:
        return False
    finally:
        try:
            devices.shell(serial, f'su -c "rm -f {quoted_staging} 2>/dev/null"', timeout_s=10.0)
        except Exception:
            pass
    return local.exists() and local.stat().st_size > 0


def _detect_synthetic_password(devices: DeviceManager, serial: str) -> bool:
    try:
        out = devices.shell(
            serial,
            'su -c "ls -1 /data/system_ce/0/spblob /data/system_de/0/spblob /data/system/spblob 2>/dev/null || true"',
            timeout_s=10.0,
        )
        return bool(out.strip())
    except Exception:
        return False


def pull_gesture_key(devices: DeviceManager, serial: str, out_dir: pathlib.Path) -> pathlib.Path:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access gesture key files")
    target = out_dir / "gesture.key"
    candidates = [
        "/data/system/users/0/gatekeeper.pattern.key",
        "/data/system/gatekeeper.pattern.key",
        "/data/system/users/0/gesture.key",
        "/data/system/gesture.key",
    ]
    for remote in candidates:
        if _try_pull_file_with_root(devices, serial, remote, target, timeout_s=60.0):
            return target

    if _detect_synthetic_password(devices, serial):
        raise GestureKeyNotFound(
            "Device uses modern Android Synthetic Password (spblob) / Gatekeeper hardware-backed encryption. "
            "Offline SHA1 pattern recovery is not possible without hardware TEE/weaver keys; live lockscreen bypass or runtime instrumentation is required."
        )
    raise GestureKeyNotFound("gesture.key or gatekeeper.pattern.key not found or accessible")


def recover_gesture_from_keyfile(path: pathlib.Path) -> str:
    return recover_pattern_from_keyfile(path)


def export_gesture_recovery(
    devices: DeviceManager, serial: str, output_dir: pathlib.Path
) -> GestureRecovery:
    output_dir.mkdir(parents=True, exist_ok=True)
    key_path = pull_gesture_key(devices, serial, output_dir)
    pattern = recover_gesture_from_keyfile(key_path)
    return GestureRecovery(
        serial=serial,
        pattern=pattern,
        point_count=gesture_point_count(pattern),
        key_path=key_path,
        key_size=key_path.stat().st_size,
    )


def recover_gesture(devices: DeviceManager, serial: str) -> str:
    with secure_temp_dir(prefix="lockknife-gesture-") as d:
        return export_gesture_recovery(devices, serial, d).pattern
