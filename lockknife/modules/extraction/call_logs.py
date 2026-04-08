from __future__ import annotations

import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir

log = get_logger()


@dataclasses.dataclass(frozen=True)
class CallLogEntry:
    """Call log entry extracted from a call log database."""

    number: str | None
    date_ms: int | None
    duration_s: int | None
    call_type: int | None
    cached_name: str | None = None


def _parse_calls_db(db_path: pathlib.Path, limit: int) -> list[CallLogEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls'")
        if cur.fetchone() is None:
            raise sqlite3.Error("calls table not found")
        cur.execute(
            "SELECT number, date, duration, type, name FROM calls ORDER BY date DESC LIMIT ?",
            (limit,),
        )
        out: list[CallLogEntry] = []
        for number, date, duration, call_type, name in cur.fetchall():
            out.append(
                CallLogEntry(
                    number=number,
                    date_ms=int(date) if date is not None else None,
                    duration_s=int(duration) if duration is not None else None,
                    call_type=int(call_type) if call_type is not None else None,
                    cached_name=name,
                )
            )
        return out
    finally:
        con.close()


def extract_call_logs(devices: DeviceManager, serial: str, limit: int = 200) -> list[CallLogEntry]:
    """Extract recent call logs from a rooted Android device."""
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access call log data")

    candidates = [
        "/data/data/com.android.providers.contacts/databases/calllog.db",
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/user_de/0/com.android.providers.contacts/databases/calllog.db",
        "/data/user_de/0/com.android.providers.contacts/databases/contacts2.db",
    ]
    with secure_temp_dir(prefix="lockknife-calllog-") as d:
        for remote in candidates:
            local = d / pathlib.Path(remote).name
            try:
                devices.pull(serial, remote, local, timeout_s=90.0)
            except (DeviceError, TimeoutError, OSError) as e:
                log.debug(
                    "call_log_pull_failed",
                    exc_info=True,
                    serial=serial,
                    remote_path=remote,
                    error=str(e),
                )
                continue
            if not local.exists() or local.stat().st_size == 0:
                continue
            try:
                return _parse_calls_db(local, limit)
            except sqlite3.Error:
                log.debug(
                    "call_log_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    raise DeviceError("Unable to extract call logs")
