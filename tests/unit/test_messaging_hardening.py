from __future__ import annotations

import pathlib
import sqlite3

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.extraction.messaging import (
    _extract_signal_passphrase,
    _parse_telegram_cache,
    _parse_whatsapp_msgstore,
    extract_signal_artifacts,
    extract_signal_messages,
    extract_whatsapp_messages,
)


class _MockMessagingDevices:
    def __init__(
        self,
        remote_files: dict[str, bytes] | None = None,
        has_root_flag: bool = True,
    ) -> None:
        self.remote_files = remote_files or {}
        self.has_root_flag = has_root_flag
        self.shell_calls: list[str] = []
        self.pulled: list[tuple[str, str]] = []

    def has_root(self, _serial: str) -> bool:
        return self.has_root_flag

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 60.0) -> None:
        self.pulled.append((serial, remote_path))
        if remote_path in self.remote_files:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(self.remote_files[remote_path])
            return
        raise FileNotFoundError(f"Remote file not found: {remote_path}")

    def shell(self, serial: str, command: str, timeout_s: float = 60.0) -> str:
        self.shell_calls.append(command)
        if "cp '" in command and "/sdcard/lockknife-tmp-" in command:
            import re
            m = re.search(r"cp '([^']+)' '([^']+)'", command)
            if m:
                src, dst = m.group(1), m.group(2)
                if src in self.remote_files:
                    self.remote_files[dst] = self.remote_files[src]
            return ""
        if "rm -f " in command and "/sdcard/lockknife-tmp-" in command:
            return ""
        if "ls -1 " in command:
            if "org.thoughtcrime.securesms/databases" in command:
                return "signal.db\nsignal.db-wal\n"
            if "org.thoughtcrime.securesms/shared_prefs" in command:
                return "org.thoughtcrime.securesms_preferences.xml\n"
            return ""
        return ""


def test_parse_modern_whatsapp_message_table(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "msgstore.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE jid (_id INTEGER, raw_string TEXT)")
        con.execute("CREATE TABLE chat (_id INTEGER, jid_row_id INTEGER, subject TEXT)")
        con.execute(
            "CREATE TABLE message (_id INTEGER, chat_row_id INTEGER, text_data TEXT, timestamp INTEGER, from_me INTEGER)"
        )

        con.execute("INSERT INTO jid VALUES (1, '15551234567@s.whatsapp.net')")
        con.execute("INSERT INTO chat VALUES (10, 1, 'Alice Smith')")
        con.execute("INSERT INTO message VALUES (100, 10, 'Hello from modern WhatsApp', 1700000000000, 0)")
        con.execute("INSERT INTO message VALUES (101, 10, 'Outbound response', 1700000001000, 1)")
        con.commit()
    finally:
        con.close()

    msgs = _parse_whatsapp_msgstore(db, limit=10)
    assert len(msgs) == 2
    # Newest first
    assert msgs[0].text == "Outbound response"
    assert msgs[0].from_me == 1
    assert msgs[0].sender_name == "Alice Smith"

    assert msgs[1].text == "Hello from modern WhatsApp"
    assert msgs[1].from_me == 0
    assert msgs[1].jid == "15551234567@s.whatsapp.net"


def test_parse_whatsapp_view_fallback(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "msgstore_view.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE VIEW message_view AS SELECT 'test_jid@s.whatsapp.net' AS jid, 'View text' AS text_data, 1690000000000 AS timestamp, 1 AS from_me"
        )
        con.commit()
    finally:
        con.close()

    msgs = _parse_whatsapp_msgstore(db, limit=5)
    assert len(msgs) == 1
    assert msgs[0].text == "View text"
    assert msgs[0].jid == "test_jid@s.whatsapp.net"
    assert msgs[0].from_me == 1


def test_extract_whatsapp_business_discovery(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "msgstore_biz.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE messages (key_remote_jid TEXT, data TEXT, timestamp INTEGER)")
        con.execute("INSERT INTO messages VALUES ('corp@s.whatsapp.net', 'Business Inquiry', 1710000000000)")
        con.commit()
    finally:
        con.close()

    biz_path = "/data/user/0/com.whatsapp.w4b/databases/msgstore.db"
    dev = _MockMessagingDevices(remote_files={biz_path: db.read_bytes()})

    extracted = extract_whatsapp_messages(dev, "TEST_SERIAL", limit=5)  # type: ignore[arg-type]
    assert len(extracted) == 1
    assert extracted[0].text == "Business Inquiry"
    assert extracted[0].jid == "corp@s.whatsapp.net"


def test_signal_sqlcipher_passphrase_recovery(tmp_path: pathlib.Path) -> None:
    pref_xml = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="pref_database_passphrase">a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90</string>
</map>
"""

    pref_remote = "/data/user/0/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml"
    dev = _MockMessagingDevices(remote_files={pref_remote: pref_xml})

    passphrase = _extract_signal_passphrase(dev, "TEST_SERIAL", tmp_path)  # type: ignore[arg-type]
    assert passphrase == "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

    artifacts = extract_signal_artifacts(dev, "TEST_SERIAL")  # type: ignore[arg-type]
    assert artifacts.encrypted is True
    assert artifacts.encryption_key == "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert "Passphrase successfully recovered" in str(artifacts.note)


def test_signal_encrypted_db_surfaces_recovered_passphrase(tmp_path: pathlib.Path) -> None:
    # Simulates encrypted database raising sqlite3.DatabaseError
    encrypted_blob = b"SQLite format 3\x00corrupt-or-sqlcipher-encrypted-data-payload"
    pref_xml = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="pref_database_passphrase">beefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead</string>
</map>
"""

    db_remote = "/data/user/0/org.thoughtcrime.securesms/databases/signal.db"
    pref_remote = "/data/user/0/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml"

    dev = _MockMessagingDevices(remote_files={
        db_remote: encrypted_blob,
        pref_remote: pref_xml,
    })

    with pytest.raises(DeviceError) as exc_info:
        extract_signal_messages(dev, "TEST_SERIAL", limit=10)  # type: ignore[arg-type]

    assert "SQLCipher encrypted" in str(exc_info.value)
    assert "beefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead" in str(exc_info.value)


def test_telegram_enriched_user_and_chat_metadata(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "cache4.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE users (id INTEGER, first_name TEXT, last_name TEXT, username TEXT)")
        con.execute("CREATE TABLE chats (id INTEGER, title TEXT)")
        con.execute("CREATE TABLE messages_v2 (uid INTEGER, mid INTEGER, date INTEGER, out INTEGER, data BLOB)")

        con.execute("INSERT INTO users VALUES (777, 'Pavel', 'Durov', 'durov')")
        con.execute("INSERT INTO chats VALUES (888, 'SecOps Channel')")
        con.execute("INSERT INTO messages_v2 VALUES (777, 1, 1680000000, 0, X'DEADBEEF')")
        con.commit()
    finally:
        con.close()

    msgs = _parse_telegram_cache(db, limit=10)
    assert len(msgs) == 1
    assert msgs[0].uid == 777
    assert msgs[0].user_name == "Pavel Durov"
    assert msgs[0].data_b64 is not None
