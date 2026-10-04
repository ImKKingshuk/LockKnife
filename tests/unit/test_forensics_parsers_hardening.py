from __future__ import annotations

import pathlib
import sqlite3
from unittest.mock import MagicMock

from lockknife.core.device import DeviceManager
from lockknife.modules.extraction.location import extract_location_snapshot
from lockknife.modules.extraction.media import extract_media_with_exif
from lockknife.modules.forensics.parsers.accounts import parse_accounts_artifacts
from lockknife.modules.forensics.parsers.bluetooth import parse_bluetooth_artifacts


def test_sqlite_accounts_db_parsing(tmp_path: pathlib.Path) -> None:
    db_path = tmp_path / "accounts_ce.db"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE accounts (
            _id INTEGER PRIMARY KEY,
            name TEXT,
            type TEXT,
            password TEXT,
            previous_name TEXT,
            last_password_entry_time_millis_epoch INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE authtokens (
            _id INTEGER PRIMARY KEY,
            accounts_id INTEGER,
            type TEXT,
            authtoken TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE extras (
            _id INTEGER PRIMARY KEY,
            accounts_id INTEGER,
            key TEXT,
            value TEXT
        )
        """
    )

    cur.execute(
        "INSERT INTO accounts VALUES (1, 'alice@example.com', 'com.google', 'hashed_pw', NULL, 1700000000)"
    )
    cur.execute(
        "INSERT INTO authtokens VALUES (1, 1, 'oauth2_refresh_token', '1//token_alice_secret')"
    )
    cur.execute("INSERT INTO extras VALUES (1, 1, 'sync_enabled', 'true')")

    cur.execute(
        "INSERT INTO accounts VALUES (2, '+15559876543', 'org.telegram.messenger', NULL, NULL, 1705000000)"
    )
    conn.commit()
    conn.close()

    records = parse_accounts_artifacts(db_path)
    assert len(records) == 2

    acc1 = next(r for r in records if r["name"] == "alice@example.com")
    assert acc1["type"] == "com.google"
    assert acc1["auth_tokens"] == {"oauth2_refresh_token": "1//token_alice_secret"}
    assert acc1["extras"] == {"sync_enabled": "true"}
    assert acc1["last_password_entry_epoch"] == 1700000000

    acc2 = next(r for r in records if r["name"] == "+15559876543")
    assert acc2["type"] == "org.telegram.messenger"
    assert acc2["auth_tokens"] == {}


def test_bluetooth_ini_config_parsing(tmp_path: pathlib.Path) -> None:
    bt_conf = tmp_path / "bt_config.conf"
    bt_conf.write_text(
        """
        # Android Bluetooth configuration file
        [00:11:22:33:44:55]
        Name = Sony WH-1000XM4
        DevClass = 00240404
        LinkKey = 11223344556677889900aabbccddeeff
        KeyType = 4
        PinLength = 16
        Timestamp = 1650000000

        [AA:BB:CC:DD:EE:FF]
        Name = Tesla Model 3
        DevClass = 00200408
        LinkKey = ffeeddccbbaa99887766554433221100
        Timestamp = 1651000000

        [Adapter]
        Address = 12:34:56:78:9A:BC
        Name = Pixel 8 Pro
        """,
        encoding="utf-8",
    )

    devices = parse_bluetooth_artifacts(bt_conf)
    assert len(devices) == 2

    dev1 = next(d for d in devices if d["address"] == "00:11:22:33:44:55")
    assert dev1["name"] == "Sony WH-1000XM4"
    assert dev1["dev_class"] == "00240404"
    assert dev1["link_key"] == "11223344556677889900aabbccddeeff"

    dev2 = next(d for d in devices if d["address"] == "AA:BB:CC:DD:EE:FF")
    assert dev2["name"] == "Tesla Model 3"


def test_mediastore_content_provider_fallback() -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = False

    def fake_shell(serial: str, cmd: str, timeout_s: float = 30.0) -> str:
        if "ls -1t" in cmd:
            return ""
        if "content query --uri content://media/external/images/media" in cmd:
            return (
                "Row: 0 _data=/sdcard/DCIM/Camera/IMG_2026.jpg, _size=204800, "
                "latitude=37.7749, longitude=-122.4194, mime_type=image/jpeg\n"
            )
        return ""

    dev.shell.side_effect = fake_shell
    media = extract_media_with_exif(dev, "serial-123", limit=10)
    assert len(media) == 1
    assert media[0].path == "/sdcard/DCIM/Camera/IMG_2026.jpg"
    assert media[0].size == 204800
    assert media[0].gps_lat == 37.7749
    assert media[0].gps_lon == -122.4194
    assert media[0].kind == "jpg"


def test_location_non_root_unprivileged_fallback() -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = False

    def fake_shell(serial: str, cmd: str, timeout_s: float = 20.0) -> str:
        if "dumpsys location" in cmd:
            return "last location: provider=fused lat=34.0522 lon=-118.2437 accuracy=10.0\n"
        return ""

    dev.shell.side_effect = fake_shell
    snap = extract_location_snapshot(dev, "serial-123")
    assert snap.provider == "fused"
    assert snap.latitude == 34.0522
    assert snap.longitude == -118.2437
