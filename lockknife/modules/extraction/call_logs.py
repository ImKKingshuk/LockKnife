from __future__ import annotations

import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.extraction._extraction_common import (
    content_query_command,
    parse_content_query_rows,
    try_root_staging_pull,
)

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


def _query_call_log_content_provider(
    devices: DeviceManager, serial: str, limit: int
) -> list[CallLogEntry]:
    try:
        cmd = content_query_command(
            "content://call_log/calls",
            ("number", "date", "duration", "type", "name"),
            sort="date DESC",
        )
        raw = devices.shell(serial, cmd, timeout_s=30.0)
        parsed = parse_content_query_rows(raw)
        out: list[CallLogEntry] = []
        for row in parsed[:limit]:
            date_val = int(row["date"]) if row.get("date") and row["date"].isdigit() else None
            dur_val = (
                int(row["duration"]) if row.get("duration") and row["duration"].isdigit() else None
            )
            type_val = int(row["type"]) if row.get("type") and row["type"].isdigit() else None
            out.append(
                CallLogEntry(
                    number=row.get("number") or None,
                    date_ms=date_val,
                    duration_s=dur_val,
                    call_type=type_val,
                    cached_name=row.get("name") or None,
                )
            )
        return out
    except Exception:
        log.warning("call_log_content_query_fallback_failed", exc_info=True, serial=serial)
        return []


def extract_call_logs(devices: DeviceManager, serial: str, limit: int = 200) -> list[CallLogEntry]:
    """Extract recent call logs from a rooted Android device."""
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access call log data")

    candidates = [
        # Dedicated call log provider (Android 9+)
        "/data/user/0/com.android.providers.calllog/databases/calllog.db",
        "/data/user_de/0/com.android.providers.calllog/databases/calllog.db",
        "/data/data/com.android.providers.calllog/databases/calllog.db",
        # Dialer databases
        "/data/user/0/com.google.android.dialer/databases/dialer.db",
        "/data/data/com.google.android.dialer/databases/dialer.db",
        # Legacy contacts provider calllog
        "/data/user/0/com.android.providers.contacts/databases/calllog.db",
        "/data/user_de/0/com.android.providers.contacts/databases/calllog.db",
        "/data/data/com.android.providers.contacts/databases/calllog.db",
        "/data/user/0/com.android.providers.contacts/databases/contacts2.db",
        "/data/user_de/0/com.android.providers.contacts/databases/contacts2.db",
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
    ]
    with secure_temp_dir(prefix="lockknife-calllog-") as d:
        for remote in candidates:
            local = d / pathlib.Path(remote).name
            if not try_root_staging_pull(devices, serial, remote, local, timeout_s=90.0):
                continue
            try:
                results = _parse_calls_db(local, limit)
                if results:
                    return results
            except sqlite3.Error:
                log.debug(
                    "call_log_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    # ContentProvider fallback when SQLite database cannot be staged or opened
    fallback_rows = _query_call_log_content_provider(devices, serial, limit)
    if fallback_rows:
        return fallback_rows

    raise DeviceError("Unable to extract call logs or query call log content provider")
