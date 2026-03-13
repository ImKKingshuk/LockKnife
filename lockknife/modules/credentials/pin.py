from __future__ import annotations

import pathlib
import sqlite3
import dataclasses

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.security import secure_temp_dir


class PinDataNotFound(DeviceError):
    pass


@dataclasses.dataclass(frozen=True)
class PinRecovery:
    serial: str
    length: int
    pin: str
    salt: int
    password_key_sha1: str
    locksettings_db_path: pathlib.Path
    password_key_path: pathlib.Path


def _extract_salt_from_locksettings_db(db_path: pathlib.Path) -> int | None:
    if not db_path.exists() or db_path.stat().st_size == 0:
        return None
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT value FROM locksettings WHERE name = ?", ("lockscreen.password_salt",))
        row = cur.fetchone()
        if not row or row[0] is None:
            return None
        return int(row[0])
    finally:
        con.close()


def _extract_sha1_from_password_key(path: pathlib.Path) -> str | None:
    if not path.exists() or path.stat().st_size < 20:
        return None
    raw = path.read_bytes()
    sha1 = raw[:20]
    return sha1.hex()


def pull_locksettings_db(devices: DeviceManager, serial: str, out_dir: pathlib.Path) -> pathlib.Path:
    target = out_dir / "locksettings.db"
    devices.pull(serial, "/data/system/locksettings.db", target, timeout_s=60.0)
    return target


def pull_password_key(devices: DeviceManager, serial: str, out_dir: pathlib.Path) -> pathlib.Path:
    target = out_dir / "password.key"
    devices.pull(serial, "/data/system/password.key", target, timeout_s=60.0)
    return target


def recover_pin(devices: DeviceManager, serial: str, length: int) -> str:
    if length <= 0 or length > 12:
        raise DeviceError("length must be between 1 and 12")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access lock credentials data")

    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as e:
        raise DeviceError("lockknife_core extension is not available") from e

    with secure_temp_dir(prefix="lockknife-pin-") as d:
        return export_pin_recovery(devices, serial, length, d).pin


def export_pin_recovery(devices: DeviceManager, serial: str, length: int, output_dir: pathlib.Path) -> PinRecovery:
    if length <= 0 or length > 12:
        raise DeviceError("length must be between 1 and 12")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access lock credentials data")

    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as exc:
        raise DeviceError("lockknife_core extension is not available") from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = pull_locksettings_db(devices, serial, output_dir)
    key_path = pull_password_key(devices, serial, output_dir)
    salt = _extract_salt_from_locksettings_db(db_path)
    sha1_hex = _extract_sha1_from_password_key(key_path)
    if salt is None or sha1_hex is None:
        raise PinDataNotFound("Unable to locate salt/hash for PIN recovery")

    pin = lockknife_core.bruteforce_android_pin_sha1(sha1_hex, int(salt), int(length))
    if pin is None:
        raise PinDataNotFound("PIN not found")
    return PinRecovery(
        serial=serial,
        length=length,
        pin=pin,
        salt=int(salt),
        password_key_sha1=sha1_hex,
        locksettings_db_path=db_path,
        password_key_path=key_path,
    )
