import pathlib
import types

from lockknife.modules.forensics._timeline_helpers import (
    TimelineSource,
    coerce_ts_ms,
    discover_case_timeline_sources,
    media_filename_ts_ms,
    unique_sources,
)
from lockknife.modules.forensics.timeline import build_timeline


def test_timeline_helpers_cover_timestamp_coercion_and_case_source_discovery(tmp_path: pathlib.Path, monkeypatch) -> None:
    sms_path = tmp_path / "sms.json"
    sms_path.write_text("[]", encoding="utf-8")

    import lockknife.core.case as case_mod

    manifest = types.SimpleNamespace(
        artifacts=[types.SimpleNamespace(path=str(sms_path), category="extract-sms", artifact_id="artifact-1")]
    )
    monkeypatch.setattr(case_mod, "load_case_manifest", lambda _case_dir: manifest)

    discovered = discover_case_timeline_sources(tmp_path)

    assert coerce_ts_ms("1700000000", field_name="date_s") == 1700000000000
    assert coerce_ts_ms("2024-01-02T03:04:05Z") is not None
    assert media_filename_ts_ms("/sdcard/DCIM/IMG_20240102_030405.jpg") is not None
    assert unique_sources(discovered, [TimelineSource(family="sms", path=str(sms_path), origin="explicit")]) == discovered
    assert discovered[0].artifact_id == "artifact-1"


def test_build_timeline_covers_multiple_artifact_families() -> None:
    events = build_timeline(
        sms=[{"date_ms": 1, "body": "sms"}],
        call_logs=[{"date_ms": 2, "number": "+1"}],
        browser={"downloads": [{"start_time_raw": 11644473600000000 + 3_000_000, "url": "https://example.com"}]},
        messaging={"app": "whatsapp", "messages": [{"timestamp_ms": 4, "body": "hello"}]},
        media=[{"path": "/sdcard/DCIM/IMG_20240102_030405.jpg", "kind": "photo"}],
        location={"snapshot": {"captured_at_ms": 6, "provider": "gps"}},
        accounts=[{"timestamp_ms": 7, "account_name": "alice"}],
        app_usage={"packages": [{"last_time_used_ms": 8, "package": "pkg"}], "events": [{"time": 9, "class": "Main"}]},
        wifi_history=[{"last_connected_ms": 10, "ssid": "Cafe"}],
        bluetooth=[{"last_seen_ms": 11, "name": "Headset"}],
        notifications=[{"posted_at_ms": 12, "title": "Alert"}],
        parsed_artifacts={"artifacts": [{"artifact_family": "messaging", "records": [{"timestamp_ms": 13, "text": "from parsed"}]}]},
    )

    sources = [event.source for event in events]
    assert [event.ts_ms for event in events] == sorted(event.ts_ms for event in events)
    assert {"sms", "call_logs", "browser", "messaging", "media", "location", "accounts", "app_usage", "wifi_history", "bluetooth", "notifications"} <= set(sources)