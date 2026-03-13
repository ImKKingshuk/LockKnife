import json
import pathlib

from lockknife.modules.forensics.timeline import build_timeline, build_timeline_report


def test_build_timeline_sorts() -> None:
    events = build_timeline(
        sms=[{"date_ms": 20, "body": "b"}],
        call_logs=[{"date_ms": 10, "number": "+1"}],
        notifications=[{"posted_at_ms": 15, "title": "Alert"}],
    )
    assert events[0].ts_ms == 10
    assert [item.ts_ms for item in events] == [10, 15, 20]


def test_build_timeline_report_normalizes_browser_and_media(tmp_path: pathlib.Path) -> None:
    browser = tmp_path / "browser.json"
    media = tmp_path / "media.json"
    browser.write_text(
        json.dumps(
            {
                "history": [
                    {"url": "https://example.com", "last_visit_time_raw": 13217451500000000}
                ]
            }
        ),
        encoding="utf-8",
    )
    media.write_text(
        json.dumps([
            {"path": "/sdcard/DCIM/IMG_20240203_040506.jpg", "kind": "image"}
        ]),
        encoding="utf-8",
    )

    report = build_timeline_report(browser_path=browser, media_path=media)

    assert report["event_count"] == 2
    assert report["summary"]["source_counts"]["browser"] == 1
    assert report["summary"]["source_counts"]["media"] == 1


def test_build_timeline_report_handles_phase_one_forensics_sources(tmp_path: pathlib.Path) -> None:
    accounts = tmp_path / "accounts.json"
    app_usage = tmp_path / "usagestats.json"
    wifi = tmp_path / "wifi_history.json"
    bluetooth = tmp_path / "bluetooth.json"
    notifications = tmp_path / "notifications.json"
    accounts.write_text(json.dumps([{"name": "alice@example.com", "last_authenticated_ms": 1710000000000}]), encoding="utf-8")
    app_usage.write_text(json.dumps({"events": [{"package": "com.example", "timestamp_ms": 1710000005000}]}), encoding="utf-8")
    wifi.write_text(json.dumps([{"ssid": "CorpWifi", "last_connected_ms": 1710000010000}]), encoding="utf-8")
    bluetooth.write_text(json.dumps([{"name": "Watch", "last_seen_ms": 1710000015000}]), encoding="utf-8")
    notifications.write_text(json.dumps([{"title": "Alert", "posted_at_ms": 1710000020000}]), encoding="utf-8")

    report = build_timeline_report(
        accounts_path=accounts,
        app_usage_path=app_usage,
        wifi_history_path=wifi,
        bluetooth_path=bluetooth,
        notifications_path=notifications,
    )

    assert report["event_count"] == 5
    assert report["summary"]["source_counts"]["accounts"] == 1
    assert report["summary"]["source_counts"]["notifications"] == 1

