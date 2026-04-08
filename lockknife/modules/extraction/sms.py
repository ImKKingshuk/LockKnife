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
class SmsMessage:
    """Single SMS row from the device SMS database."""

    address: str | None
    body: str | None
    date_ms: int | None
    msg_type: int | None


def _parse_mmssms_db(db_path: pathlib.Path, limit: int) -> list[SmsMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = None
        for q in [
            "SELECT address, body, date, type FROM sms ORDER BY date DESC LIMIT ?",
            "SELECT address, body, date, NULL as type FROM sms ORDER BY date DESC LIMIT ?",
            "SELECT address, body, NULL as date, NULL as type FROM sms LIMIT ?",
        ]:
            try:
                cur = con.execute(q, (limit,))
                break
            except sqlite3.Error:
                cur = None
        if cur is None:
            return []
        out: list[SmsMessage] = []
        for address, body, date, msg_type in cur.fetchall():
            out.append(
                SmsMessage(
                    address=address,
                    body=body,
                    date_ms=int(date) if date is not None else None,
                    msg_type=int(msg_type) if msg_type is not None else None,
                )
            )
        return out
    finally:
        con.close()


def extract_sms(devices: DeviceManager, serial: str, limit: int = 200) -> list[SmsMessage]:
    """Extract recent SMS messages from a rooted Android device.

    Args:
        devices: Device manager.
        serial: Device serial.
        limit: Max number of messages.

    Returns:
        Parsed SMS messages, newest-first when available.

    Raises:
        DeviceError: If the device is not rooted or the database cannot be accessed.
        ValueError: If limit is invalid.
    """
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access mmssms.db")

    candidates = [
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
    ]
    with secure_temp_dir(prefix="lockknife-sms-") as d:
        for remote in candidates:
            local = d / "mmssms.db"
            try:
                devices.pull(serial, remote, local, timeout_s=90.0)
            except Exception:
                log.debug("sms_db_pull_failed", exc_info=True, serial=serial, remote_path=remote)
                continue
            if not local.exists() or local.stat().st_size == 0:
                continue
            try:
                return _parse_mmssms_db(local, limit)
            except sqlite3.Error:
                log.debug(
                    "sms_db_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    raise DeviceError("Unable to extract SMS database")
