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
        out: list[SmsMessage] = []
        if cur is not None:
            for address, body, date, msg_type in cur.fetchall():
                out.append(
                    SmsMessage(
                        address=address,
                        body=body,
                        date_ms=int(date) if date is not None else None,
                        msg_type=int(msg_type) if msg_type is not None else None,
                    )
                )

        # Also extract MMS text parts from pdu/part tables if present
        try:
            mms_query = """
SELECT addr.address, part.text, pdu.date * 1000, pdu.msg_box
FROM pdu
JOIN part ON part.mid = pdu._id AND (part.ct = 'text/plain' OR part.text IS NOT NULL)
LEFT JOIN addr ON addr.msg_id = pdu._id AND addr.type = 137
WHERE part.text IS NOT NULL AND length(part.text) > 0
ORDER BY pdu.date DESC LIMIT ?
""".strip()
            for addr_val, text_val, mms_date, box_type in con.execute(
                mms_query, (limit,)
            ).fetchall():
                out.append(
                    SmsMessage(
                        address=addr_val,
                        body=text_val,
                        date_ms=int(mms_date) if mms_date is not None else None,
                        msg_type=int(box_type) if box_type is not None else None,
                    )
                )
        except sqlite3.Error:
            pass

        if out:
            out.sort(key=lambda m: m.date_ms or 0, reverse=True)
            return out[:limit]
        return []
    finally:
        con.close()


def _query_sms_content_provider(
    devices: DeviceManager, serial: str, limit: int
) -> list[SmsMessage]:
    """Query SMS messages directly via Android ContentProvider shell command."""
    try:
        cmd = content_query_command(
            "content://sms", ("address", "body", "date", "type"), sort="date DESC"
        )
        raw = devices.shell(serial, cmd, timeout_s=30.0)
        parsed = parse_content_query_rows(raw)
        out: list[SmsMessage] = []
        for row in parsed[:limit]:
            out.append(
                SmsMessage(
                    address=row.get("address") or None,
                    body=row.get("body") or None,
                    date_ms=int(row["date"]) if row.get("date") and row["date"].isdigit() else None,
                    msg_type=int(row["type"])
                    if row.get("type") and row["type"].isdigit()
                    else None,
                )
            )
        return out
    except Exception:
        log.warning("sms_content_query_fallback_failed", exc_info=True, serial=serial)
        return []


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
        "/data/user/0/com.android.providers.telephony/databases/mmssms.db",
        "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "/data/user/0/com.android.providers.telephony/databases/telephony.db",
        "/data/user_de/0/com.android.providers.telephony/databases/telephony.db",
    ]
    with secure_temp_dir(prefix="lockknife-sms-") as d:
        for remote in candidates:
            local = d / "mmssms.db"
            if not try_root_staging_pull(devices, serial, remote, local, timeout_s=90.0):
                continue
            try:
                results = _parse_mmssms_db(local, limit)
                if results:
                    return results
            except sqlite3.Error:
                log.debug(
                    "sms_db_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    # ContentProvider fallback when SQLite database cannot be staged or opened
    fallback_rows = _query_sms_content_provider(devices, serial, limit)
    if fallback_rows:
        return fallback_rows

    raise DeviceError("Unable to extract SMS database or query SMS content provider")
