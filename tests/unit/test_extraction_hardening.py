from __future__ import annotations

import pathlib
import sqlite3

from lockknife.modules.extraction._browser_extract_chrome import (
    _candidate_paths,
)
from lockknife.modules.extraction._extraction_common import (
    parse_content_query_rows,
    try_root_staging_pull,
)
from lockknife.modules.extraction.call_logs import (
    _parse_calls_db,
    extract_call_logs,
)
from lockknife.modules.extraction.contacts import (
    _parse_contacts2_db,
    extract_contacts,
)
from lockknife.modules.extraction.sms import (
    _parse_mmssms_db,
    extract_sms,
)


class _MockExtractionDevices:
    """Simulates Android device with both direct-pull failures and ContentProvider fallback."""

    def __init__(
        self,
        remote_files: dict[str, bytes] | None = None,
        has_root_flag: bool = True,
        content_provider_output: dict[str, str] | None = None,
        simulate_direct_permission_denied: bool = False,
    ) -> None:
        self.remote_files = remote_files or {}
        self.has_root_flag = has_root_flag
        self.content_provider_output = content_provider_output or {}
        self.simulate_direct_permission_denied = simulate_direct_permission_denied
        self.shell_calls: list[str] = []
        self.pulled: list[tuple[str, str]] = []
        self._staged_files: dict[str, bytes] = {}

    def has_root(self, serial: str) -> bool:
        return self.has_root_flag

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 60.0) -> None:
        self.pulled.append((serial, remote_path))

        # Check if direct pull to /data should simulate permission denied
        if self.simulate_direct_permission_denied and remote_path.startswith("/data/"):
            raise PermissionError(f"adb: error: failed to copy '{remote_path}': Permission denied")

        if remote_path in self.remote_files:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(self.remote_files[remote_path])
            return

        if remote_path in self._staged_files:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(self._staged_files[remote_path])
            return

        raise FileNotFoundError(f"Remote file not found: {remote_path}")

    def shell(self, serial: str, command: str, timeout_s: float = 60.0) -> str:
        self.shell_calls.append(command)

        # Content provider queries
        for uri, output in self.content_provider_output.items():
            if uri in command:
                return output

        # Root staging cp command
        if "cp " in command and "/sdcard/lockknife-staging-" in command:
            for remote_path, content in self.remote_files.items():
                if remote_path in command:
                    import re
                    m = re.search(r"(/sdcard/lockknife-staging-[^\s'\"]+)", command)
                    if m:
                        staging_path = m.group(1)
                        self._staged_files[staging_path] = content
                        return ""
            return ""

        # Cleanup
        if "rm -f /sdcard/lockknife-staging-" in command:
            import re
            m = re.search(r"(/sdcard/lockknife-staging-[^\s'\"]+)", command)
            if m and m.group(1) in self._staged_files:
                del self._staged_files[m.group(1)]
            return ""

        return ""


def test_parse_content_query_rows_multi() -> None:
    raw = """
Row: 0 address=+15550100, body=Hello from analyst, date=1672531199000, type=1
Row: 1 address=+15550200, body=Test message with, comma inside, date=1672531100000, type=2
Row: 2 address=+15550300, body=null, date=1672531000000, type=1
"""
    rows = parse_content_query_rows(raw)
    assert len(rows) == 3
    assert rows[0]["address"] == "+15550100"
    assert rows[0]["body"] == "Hello from analyst"
    assert rows[0]["date"] == "1672531199000"
    assert rows[0]["type"] == "1"

    assert rows[1]["address"] == "+15550200"
    assert rows[1]["body"] == "Test message with, comma inside"

    assert rows[2]["address"] == "+15550300"
    assert rows[2]["body"] == ""


def test_try_root_staging_pull(tmp_path: pathlib.Path) -> None:
    content = b"database-binary-content-12345"
    remote = "/data/user/0/com.android.providers.telephony/databases/mmssms.db"
    dev = _MockExtractionDevices(
        remote_files={remote: content},
        simulate_direct_permission_denied=True,
    )
    local = tmp_path / "pulled.db"
    success = try_root_staging_pull(dev, "TEST_SERIAL", remote, local)  # type: ignore[arg-type]
    assert success is True
    assert local.read_bytes() == content


def test_parse_mmssms_db_with_mms_parts(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "mmssms.db"
    con = sqlite3.connect(str(db))
    try:
        # Standard SMS table
        con.execute("CREATE TABLE sms (address TEXT, body TEXT, date INTEGER, type INTEGER)")
        con.execute("INSERT INTO sms VALUES ('+111', 'SMS text message', 1000, 1)")

        # MMS pdu, part, addr tables
        con.execute("CREATE TABLE pdu (_id INTEGER, date INTEGER, msg_box INTEGER)")
        con.execute("CREATE TABLE part (mid INTEGER, ct TEXT, text TEXT)")
        con.execute("CREATE TABLE addr (msg_id INTEGER, type INTEGER, address TEXT)")

        con.execute("INSERT INTO pdu VALUES (10, 2, 1)")  # date in seconds: 2 -> 2000 ms
        con.execute("INSERT INTO part VALUES (10, 'text/plain', 'MMS text payload')")
        con.execute("INSERT INTO addr VALUES (10, 137, '+222')")  # type 137 is FROM

        con.commit()
    finally:
        con.close()

    msgs = _parse_mmssms_db(db, limit=10)
    assert len(msgs) == 2
    # Newest first: MMS (2000ms) then SMS (1000ms)
    assert msgs[0].address == "+222"
    assert msgs[0].body == "MMS text payload"
    assert msgs[0].date_ms == 2000

    assert msgs[1].address == "+111"
    assert msgs[1].body == "SMS text message"
    assert msgs[1].date_ms == 1000


def test_sms_extraction_content_provider_fallback() -> None:
    sms_output = "Row: 0 address=+199988877, body=Fallback SMS through provider, date=1700000000000, type=1\n"
    dev = _MockExtractionDevices(
        remote_files={},
        content_provider_output={"content://sms": sms_output},
    )

    msgs = extract_sms(dev, "TEST_SERIAL", limit=5)  # type: ignore[arg-type]
    assert len(msgs) == 1
    assert msgs[0].address == "+199988877"
    assert msgs[0].body == "Fallback SMS through provider"
    assert msgs[0].date_ms == 1700000000000


def test_contacts_extraction_enriched_fields(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "contacts2.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE contacts (_id INTEGER, display_name TEXT)")
        con.execute("CREATE TABLE raw_contacts (_id INTEGER, contact_id INTEGER)")
        con.execute("CREATE TABLE data (_id INTEGER, raw_contact_id INTEGER, mimetype TEXT, data1 TEXT)")

        con.execute("INSERT INTO contacts VALUES (1, 'Dr. Sarah Connor')")
        con.execute("INSERT INTO raw_contacts VALUES (10, 1)")
        con.execute("INSERT INTO data VALUES (101, 10, 'vnd.android.cursor.item/phone_v2', '+15551234')")
        con.execute("INSERT INTO data VALUES (102, 10, 'vnd.android.cursor.item/email_v2', 'sarah@cyberdyne.org')")
        con.execute("INSERT INTO data VALUES (103, 10, 'vnd.android.cursor.item/organization', 'Resistance Corp')")
        con.commit()
    finally:
        con.close()

    contacts = _parse_contacts2_db(db, limit=10)
    assert len(contacts) == 1
    c = contacts[0]
    assert c.display_name == "Dr. Sarah Connor"
    assert c.number == "+15551234"
    assert c.email == "sarah@cyberdyne.org"
    assert c.organization == "Resistance Corp"


def test_contacts_extraction_content_provider_fallback() -> None:
    provider_output = "Row: 0 contact_id=42, display_name=John Doe, number=+15559876\n"
    dev = _MockExtractionDevices(
        remote_files={},
        content_provider_output={"content://contacts/phones": provider_output},
    )

    contacts = extract_contacts(dev, "TEST_SERIAL", limit=5)  # type: ignore[arg-type]
    assert len(contacts) == 1
    assert contacts[0].display_name == "John Doe"
    assert contacts[0].number == "+15559876"
    assert contacts[0].contact_id == 42


def test_call_logs_parsing_and_content_provider_fallback(tmp_path: pathlib.Path) -> None:
    # 1. Test parsing calls table
    db = tmp_path / "calllog.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE calls (number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT)")
        con.execute("INSERT INTO calls VALUES ('+14155552671', 1710000000000, 142, 1, 'Dispatch Center')")
        con.commit()
    finally:
        con.close()

    logs = _parse_calls_db(db, limit=10)
    assert len(logs) == 1
    assert logs[0].number == "+14155552671"
    assert logs[0].duration_s == 142
    assert logs[0].cached_name == "Dispatch Center"

    # 2. Test ContentProvider fallback
    provider_output = "Row: 0 number=+14155559999, date=1710000050000, duration=45, type=2, name=HQ Desk\n"
    dev = _MockExtractionDevices(
        remote_files={},
        content_provider_output={"content://call_log/calls": provider_output},
    )
    extracted = extract_call_logs(dev, "TEST_SERIAL", limit=5)  # type: ignore[arg-type]
    assert len(extracted) == 1
    assert extracted[0].number == "+14155559999"
    assert extracted[0].cached_name == "HQ Desk"
    assert extracted[0].duration_s == 45


def test_chromium_candidate_paths_and_samsung_browser() -> None:
    chrome_paths = _candidate_paths("chrome", "Network/Cookies")
    assert any("/data/user/0/com.android.chrome/app_chrome/Default/Network/Cookies" in p for p in chrome_paths)
    assert any("/data/data/com.android.chrome/app_chrome/Default/Network/Cookies" in p for p in chrome_paths)

    samsung_paths = _candidate_paths("samsung", "History")
    assert any("com.sec.android.app.sbrowser" in p for p in samsung_paths)
