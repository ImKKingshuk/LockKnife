from __future__ import annotations

import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger
from lockknife.modules.extraction._extraction_common import try_root_staging_pull

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
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 60.0,
) -> bool:
    return try_root_staging_pull(devices, serial, remote, local, timeout_s=timeout_s)
