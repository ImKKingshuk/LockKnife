from __future__ import annotations

import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.extraction._extraction_common import (
    parse_content_query_rows,
    try_root_staging_pull,
)

log = get_logger()


@dataclasses.dataclass(frozen=True)
class Contact:
    """Contact record extracted from the contacts provider database."""

    display_name: str | None
    number: str | None
    contact_id: int | None = None
    email: str | None = None
    organization: str | None = None


def _parse_contacts2_db(db_path: pathlib.Path, limit: int) -> list[Contact]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        # 1. Attempt enriched query joining phone, email, and organization
        try:
            cur.execute(
                """
SELECT c._id, c.display_name,
       MAX(CASE WHEN d.mimetype = 'vnd.android.cursor.item/phone_v2' THEN d.data1 END) AS phone,
       MAX(CASE WHEN d.mimetype = 'vnd.android.cursor.item/email_v2' THEN d.data1 END) AS email,
       MAX(CASE WHEN d.mimetype = 'vnd.android.cursor.item/organization' THEN d.data1 END) AS org
FROM contacts c
JOIN raw_contacts rc ON rc.contact_id = c._id
JOIN data d ON d.raw_contact_id = rc._id
WHERE c.display_name IS NOT NULL
GROUP BY c._id, c.display_name
ORDER BY c.display_name
LIMIT ?
""".strip(),
                (limit,),
            )
            rows = cur.fetchall()
            if rows:
                return [
                    Contact(
                        contact_id=int(cid),
                        display_name=name,
                        number=phone,
                        email=email,
                        organization=org,
                    )
                    for cid, name, phone, email, org in rows
                ]
        except sqlite3.Error:
            pass

        # 2. Fallback to phone-only join
        try:
            cur.execute(
                """
SELECT c._id, c.display_name, d.data1
FROM contacts c
JOIN raw_contacts rc ON rc.contact_id = c._id
JOIN data d ON d.raw_contact_id = rc._id
WHERE d.mimetype = 'vnd.android.cursor.item/phone_v2'
  AND d.data1 IS NOT NULL
ORDER BY c.display_name
LIMIT ?
""".strip(),
                (limit,),
            )
            rows = cur.fetchall()
            return [
                Contact(contact_id=int(cid), display_name=name, number=num)
                for cid, name, num in rows
            ]
        except sqlite3.Error:
            cur.execute(
                "SELECT _id, display_name FROM contacts ORDER BY display_name LIMIT ?", (limit,)
            )
            rows = cur.fetchall()
            return [
                Contact(contact_id=int(cid), display_name=name, number=None) for cid, name in rows
            ]
    finally:
        con.close()


def _query_contacts_content_provider(
    devices: DeviceManager, serial: str, limit: int
) -> list[Contact]:
    """Fallback query via Android ContentProvider shell command."""
    try:
        raw = devices.shell(
            serial,
            f'su -c "content query --uri content://contacts/phones --projection contact_id,display_name,number | head -n {limit * 4}"',
            timeout_s=30.0,
        )
        parsed = parse_content_query_rows(raw)
        out: list[Contact] = []
        for row in parsed[:limit]:
            cid = int(row["contact_id"]) if row.get("contact_id") and row["contact_id"].isdigit() else None
            out.append(
                Contact(
                    contact_id=cid,
                    display_name=row.get("display_name") or None,
                    number=row.get("number") or None,
                )
            )
        return out
    except Exception:
        log.warning("contacts_content_query_fallback_failed", exc_info=True, serial=serial)
        return []


def extract_contacts(devices: DeviceManager, serial: str, limit: int = 200) -> list[Contact]:
    """Extract contacts from a rooted Android device.

    Args:
        devices: Device manager.
        serial: Device serial.
        limit: Max number of contacts.

    Returns:
        Contacts with display name and (when accessible) a phone number.
    """
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access contacts2.db")

    candidates = [
        "/data/user/0/com.android.providers.contacts/databases/contacts2.db",
        "/data/user_de/0/com.android.providers.contacts/databases/contacts2.db",
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/data/com.google.android.providers.contacts/databases/contacts2.db",
        "/data/user_de/0/com.google.android.providers.contacts/databases/contacts2.db",
    ]
    with secure_temp_dir(prefix="lockknife-contacts-") as d:
        for remote in candidates:
            local = d / "contacts2.db"
            if not try_root_staging_pull(devices, serial, remote, local, timeout_s=90.0):
                continue
            try:
                results = _parse_contacts2_db(local, limit)
                if results:
                    return results
            except sqlite3.Error:
                log.debug(
                    "contacts_db_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    # ContentProvider fallback when SQLite database cannot be staged or opened
    fallback_rows = _query_contacts_content_provider(devices, serial, limit)
    if fallback_rows:
        return fallback_rows

    raise DeviceError("Unable to extract contacts database or query contacts content provider")
