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
class Contact:
    """Contact record extracted from the contacts provider database."""

    display_name: str | None
    number: str | None
    contact_id: int | None = None


def _parse_contacts2_db(db_path: pathlib.Path, limit: int) -> list[Contact]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
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
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/user_de/0/com.android.providers.contacts/databases/contacts2.db",
    ]
    with secure_temp_dir(prefix="lockknife-contacts-") as d:
        for remote in candidates:
            local = d / "contacts2.db"
            try:
                devices.pull(serial, remote, local, timeout_s=90.0)
            except (DeviceError, TimeoutError, OSError) as e:
                log.debug(
                    "contacts_db_pull_failed", exc_info=True, serial=serial, remote_path=remote, error=str(e)
                )
                continue
            if not local.exists() or local.stat().st_size == 0:
                continue
            try:
                return _parse_contacts2_db(local, limit)
            except sqlite3.Error:
                log.debug(
                    "contacts_db_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    raise DeviceError("Unable to extract contacts database")
