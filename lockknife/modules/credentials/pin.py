from __future__ import annotations

import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.security import secure_temp_dir
from lockknife.modules.extraction._extraction_common import try_root_staging_pull


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


def _try_pull_file_with_root(
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 60.0,
) -> bool:
    return try_root_staging_pull(devices, serial, remote, local, timeout_s=timeout_s)


def pull_locksettings_db(
    devices: DeviceManager, serial: str, out_dir: pathlib.Path
) -> pathlib.Path:
    target = out_dir / "locksettings.db"
    candidates = [
        "/data/system/users/0/locksettings.db",
        "/data/system/locksettings.db",
    ]
    for remote in candidates:
        if _try_pull_file_with_root(devices, serial, remote, target, timeout_s=60.0):
            # Also attempt to pull WAL file if present
            wal_target = out_dir / "locksettings.db-wal"
            _try_pull_file_with_root(devices, serial, remote + "-wal", wal_target, timeout_s=30.0)
            return target
    raise DeviceError("Unable to locate or pull locksettings.db from device")


def pull_password_key(devices: DeviceManager, serial: str, out_dir: pathlib.Path) -> pathlib.Path:
    target = out_dir / "password.key"
    candidates = [
        "/data/system/users/0/gatekeeper.password.key",
        "/data/system/gatekeeper.password.key",
        "/data/system/users/0/password.key",
        "/data/system/password.key",
    ]
    for remote in candidates:
        if _try_pull_file_with_root(devices, serial, remote, target, timeout_s=60.0):
            return target
    raise DeviceError("Unable to locate or pull password key file from device")


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


def recover_pin(devices: DeviceManager, serial: str, length: int) -> str:
    if length <= 0 or length > 12:
        raise DeviceError("length must be between 1 and 12")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access lock credentials data")

    with secure_temp_dir(prefix="lockknife-pin-") as d:
        return export_pin_recovery(devices, serial, length, d).pin


def export_pin_recovery(
    devices: DeviceManager, serial: str, length: int, output_dir: pathlib.Path
) -> PinRecovery:
    if length <= 0 or length > 12:
        raise DeviceError("length must be between 1 and 12")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access lock credentials data")

    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as exc:
        raise DeviceError("lockknife_core extension is not available") from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        db_path = pull_locksettings_db(devices, serial, output_dir)
        key_path = pull_password_key(devices, serial, output_dir)
    except DeviceError as err:
        if _detect_synthetic_password(devices, serial):
            raise PinDataNotFound(
                "Device uses modern Android Synthetic Password (spblob) / Gatekeeper hardware-backed encryption. "
                "Offline SHA1 cracking is not possible without hardware TEE/weaver keys; live lockscreen bypass or runtime instrumentation is required."
            ) from err
        raise PinDataNotFound(str(err)) from err

    salt = _extract_salt_from_locksettings_db(db_path)
    sha1_hex = _extract_sha1_from_password_key(key_path)
    if salt is None or sha1_hex is None:
        if _detect_synthetic_password(devices, serial):
            raise PinDataNotFound(
                "Device uses modern Android Synthetic Password (spblob) / Gatekeeper hardware-backed encryption. "
                "Offline SHA1 cracking is not possible without hardware TEE/weaver keys; live lockscreen bypass or runtime instrumentation is required."
            )
        raise PinDataNotFound("Unable to locate salt/hash for PIN recovery")

    pin = lockknife_core.bruteforce_android_pin_sha1(sha1_hex, int(salt), int(length))
    if pin is None:
        raise PinDataNotFound("PIN not found within specified search length")
    return PinRecovery(
        serial=serial,
        length=length,
        pin=pin,
        salt=int(salt),
        password_key_sha1=sha1_hex,
        locksettings_db_path=db_path,
        password_key_path=key_path,
    )
