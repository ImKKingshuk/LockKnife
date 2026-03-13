import json
import pathlib

from lockknife.modules.forensics.artifacts import parse_forensics_directory


def test_parse_forensics_directory_detects_new_artifact_families(tmp_path: pathlib.Path) -> None:
    (tmp_path / "accounts.json").write_text(
        json.dumps({"accounts": [{"name": "alice@example.com", "type": "com.google", "last_authenticated_ms": 1710000000000}]}),
        encoding="utf-8",
    )
    (tmp_path / "usagestats.xml").write_text(
        "<usagestats><packages><package name='com.example' lastTimeUsed='1710000005000'/></packages></usagestats>",
        encoding="utf-8",
    )
    (tmp_path / "wifi_history.xml").write_text(
        "<WifiConfigStoreData><Network><string name='SSID'>CorpWifi</string><long name='LastConnectedTime'>1710000010000</long></Network></WifiConfigStoreData>",
        encoding="utf-8",
    )
    (tmp_path / "bluetooth.json").write_text(
        json.dumps({"devices": [{"name": "Headset", "address": "AA:BB:CC:DD:EE:FF", "last_seen_ms": 1710000015000}]}),
        encoding="utf-8",
    )
    (tmp_path / "notifications.json").write_text(
        json.dumps({"notifications": [{"package": "com.example", "title": "Alert", "posted_at_ms": 1710000020000}]}),
        encoding="utf-8",
    )

    report = parse_forensics_directory(tmp_path)

    families = {artifact.artifact_family for artifact in report.artifacts}
    assert {"accounts", "app_usage", "wifi_history", "bluetooth", "notifications"} <= families
    assert report.summary["artifact_family_counts"]["accounts"] == 1