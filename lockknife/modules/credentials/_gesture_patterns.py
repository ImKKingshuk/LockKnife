from __future__ import annotations

import pathlib

from lockknife.core.exceptions import DeviceError


def recover_pattern_from_key_bytes(raw: bytes) -> str:
    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as exc:
        raise DeviceError("lockknife_core extension is not available") from exc
    return lockknife_core.recover_android_gesture(raw)


def recover_pattern_from_keyfile(path: pathlib.Path) -> str:
    return recover_pattern_from_key_bytes(path.read_bytes())


def gesture_point_count(pattern: str) -> int:
    return len([item for item in pattern.split("-") if item.strip()])