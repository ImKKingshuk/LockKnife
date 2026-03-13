from __future__ import annotations

import pathlib
import dataclasses

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


def pull_gesture_key(devices: DeviceManager, serial: str, out_dir: pathlib.Path) -> pathlib.Path:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access gesture.key")
    target = out_dir / "gesture.key"
    devices.pull(serial, "/data/system/gesture.key", target, timeout_s=60.0)
    if not target.exists() or target.stat().st_size == 0:
        raise GestureKeyNotFound("gesture.key not found or empty")
    return target


def recover_gesture_from_keyfile(path: pathlib.Path) -> str:
    return recover_pattern_from_keyfile(path)


def export_gesture_recovery(devices: DeviceManager, serial: str, output_dir: pathlib.Path) -> GestureRecovery:
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
