from __future__ import annotations

import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger

log = get_logger()

_DEVICE_IO_ERRORS: tuple[type[BaseException], ...] = (
    LockKnifeError,
    OSError,
    RuntimeError,
    ValueError,
)


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    cur = con.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def _try_root_pull_file(
    devices: DeviceManager, serial: str, remote: str, local: pathlib.Path, *, timeout_s: float
) -> bool:
    try:
        devices.pull(serial, remote, local, timeout_s=timeout_s)
        return local.exists() and local.stat().st_size > 0
    except _DEVICE_IO_ERRORS:
        log.warning("browser_pull_failed", exc_info=True, serial=serial, remote=remote)

    tmp_remote = f"/sdcard/lockknife-tmp-{local.name}"
    try:
        devices.shell(
            serial,
            f'su -c "cp {_sh_quote(remote)} {_sh_quote(tmp_remote)} 2>/dev/null || cat {_sh_quote(remote)} > {_sh_quote(tmp_remote)} 2>/dev/null"',
            timeout_s=timeout_s,
        )
        devices.pull(serial, tmp_remote, local, timeout_s=timeout_s)
    except _DEVICE_IO_ERRORS:
        log.warning("browser_root_pull_failed", exc_info=True, serial=serial, remote=remote)
        return False
    finally:
        try:
            devices.shell(
                serial, f'su -c "rm -f {_sh_quote(tmp_remote)} 2>/dev/null"', timeout_s=10.0
            )
        except _DEVICE_IO_ERRORS:
            log.warning(
                "browser_root_pull_cleanup_failed", exc_info=True, serial=serial, remote=tmp_remote
            )
    return local.exists() and local.stat().st_size > 0
