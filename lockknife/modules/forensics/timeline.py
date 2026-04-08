from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from lockknife.modules.forensics._timeline_helpers import (
    TimelineSource,
    coerce_ts_ms,
    discover_case_timeline_sources,
    ensure_dict_list,
    fallback_file_ts_ms,
    family_from_category_or_name,
    load_json_payload,
    media_filename_ts_ms,
    record_preview,
    unique_sources,
)


@dataclasses.dataclass(frozen=True)
class TimelineEvent:
    ts_ms: int
    source: str
    kind: str
    data: dict[str, Any]
    summary: str | None = None
    source_file: str | None = None
    artifact_family: str | None = None
    artifact_id: str | None = None


def build_timeline(
    *,
    sms: list[dict[str, Any]] | None = None,
    call_logs: list[dict[str, Any]] | None = None,
    browser: Any | None = None,
    messaging: Any | None = None,
    media: Any | None = None,
    location: Any | None = None,
    accounts: Any | None = None,
    app_usage: Any | None = None,
    wifi_history: Any | None = None,
    bluetooth: Any | None = None,
    notifications: Any | None = None,
    parsed_artifacts: Any | None = None,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    events.extend(
        _timeline_events_for_family(
            "sms", ensure_dict_list(sms), source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "call_logs",
            ensure_dict_list(call_logs),
            source_file=None,
            artifact_id=None,
            fallback_ts_ms=None,
        )
    )
    events.extend(
        _timeline_events_for_family(
            "browser", browser, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "messaging", messaging, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "media", media, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "location", location, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "accounts", accounts, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "app_usage", app_usage, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "wifi_history", wifi_history, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "bluetooth", bluetooth, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "notifications", notifications, source_file=None, artifact_id=None, fallback_ts_ms=None
        )
    )
    events.extend(
        _timeline_events_for_family(
            "parsed_artifacts",
            parsed_artifacts,
            source_file=None,
            artifact_id=None,
            fallback_ts_ms=None,
        )
    )
    events.sort(key=lambda item: item.ts_ms)
    return events


def build_timeline_report(
    *,
    sms_path: pathlib.Path | None = None,
    call_logs_path: pathlib.Path | None = None,
    browser_path: pathlib.Path | None = None,
    messaging_path: pathlib.Path | None = None,
    media_path: pathlib.Path | None = None,
    location_path: pathlib.Path | None = None,
    accounts_path: pathlib.Path | None = None,
    app_usage_path: pathlib.Path | None = None,
    wifi_history_path: pathlib.Path | None = None,
    bluetooth_path: pathlib.Path | None = None,
    notifications_path: pathlib.Path | None = None,
    parsed_artifacts_path: pathlib.Path | None = None,
    case_dir: pathlib.Path | None = None,
    max_events: int = 5000,
) -> dict[str, Any]:
    explicit_sources = [
        TimelineSource(family, str(path), "explicit")
        for family, path in [
            ("sms", sms_path),
            ("call_logs", call_logs_path),
            ("browser", browser_path),
            ("messaging", messaging_path),
            ("media", media_path),
            ("location", location_path),
            ("accounts", accounts_path),
            ("app_usage", app_usage_path),
            ("wifi_history", wifi_history_path),
            ("bluetooth", bluetooth_path),
            ("notifications", notifications_path),
            ("parsed_artifacts", parsed_artifacts_path),
        ]
        if path is not None
    ]
    case_sources = discover_case_timeline_sources(case_dir) if case_dir is not None else []
    sources = unique_sources(explicit_sources, case_sources)

    events: list[TimelineEvent] = []
    source_rows: list[dict[str, Any]] = []
    undated_items: list[dict[str, Any]] = []
    for source in sources:
        path = pathlib.Path(source.path)
        if not path.exists():
            continue
        payload = load_json_payload(path)
        family = (
            source.family
            if source.family != "generic"
            else family_from_category_or_name(source.category, path)
        )
        family_events, family_undated = _timeline_rows_from_payload(
            family,
            payload,
            source_file=str(path),
            artifact_id=source.artifact_id,
            fallback_ts_ms=fallback_file_ts_ms(path),
        )
        events.extend(family_events)
        undated_items.extend(family_undated)
        source_rows.append(
            {
                "family": family,
                "path": str(path),
                "origin": source.origin,
                "artifact_id": source.artifact_id,
                "category": source.category,
                "event_count": len(family_events),
                "undated_count": len(family_undated),
            }
        )
    events.sort(key=lambda item: item.ts_ms)
    if len(events) > max_events:
        events = events[:max_events]
    source_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for event in events:
        source_counts[event.source] = source_counts.get(event.source, 0) + 1
        kind_counts[event.kind] = kind_counts.get(event.kind, 0) + 1
    return {
        "case_dir": str(case_dir) if case_dir is not None else None,
        "event_count": len(events),
        "undated_item_count": len(undated_items),
        "sources": source_rows,
        "summary": {
            "first_ts_ms": events[0].ts_ms if events else None,
            "last_ts_ms": events[-1].ts_ms if events else None,
            "source_counts": source_counts,
            "kind_counts": kind_counts,
        },
        "events": [dataclasses.asdict(event) for event in events],
        "undated_items": undated_items[:40],
    }


def _timeline_rows_from_payload(
    family: str,
    payload: Any,
    *,
    source_file: str | None,
    artifact_id: str | None,
    fallback_ts_ms: int | None,
) -> tuple[list[TimelineEvent], list[dict[str, Any]]]:
    events = _timeline_events_for_family(
        family,
        payload,
        source_file=source_file,
        artifact_id=artifact_id,
        fallback_ts_ms=fallback_ts_ms,
    )
    undated = _undated_rows_for_family(family, payload, source_file=source_file)
    return events, undated


def _timeline_events_for_family(
    family: str,
    payload: Any,
    *,
    source_file: str | None,
    artifact_id: str | None,
    fallback_ts_ms: int | None,
) -> list[TimelineEvent]:
    out: list[TimelineEvent] = []
    for record in _records_for_family(family, payload):
        event = _event_for_record(
            family,
            record,
            source_file=source_file,
            artifact_id=artifact_id,
            fallback_ts_ms=fallback_ts_ms,
        )
        if event is not None:
            out.append(event)
    return out


def _undated_rows_for_family(
    family: str, payload: Any, *, source_file: str | None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for record in _records_for_family(family, payload):
        if (
            _event_for_record(
                family, record, source_file=source_file, artifact_id=None, fallback_ts_ms=None
            )
            is not None
        ):
            continue
        out.append(
            {
                "family": family,
                "source_file": source_file,
                "summary": record_preview(
                    record, keys=("body", "text", "title", "path", "url", "ssid", "provider")
                ),
                "data": record,
            }
        )
        if len(out) >= 20:
            break
    return out


def _records_for_family(family: str, payload: Any) -> list[dict[str, Any]]:
    if family == "browser" and isinstance(payload, dict):
        browser_rows: list[dict[str, Any]] = []
        for section in ["history", "bookmarks", "downloads", "cookies"]:
            for item in ensure_dict_list(payload.get(section)):
                browser_rows.append({"_section": section, **item})
        return browser_rows
    if (
        family == "messaging"
        and isinstance(payload, dict)
        and isinstance(payload.get("messages"), list)
    ):
        return [
            {"_app": payload.get("app"), **item}
            for item in ensure_dict_list(payload.get("messages"))
        ]
    if family == "location" and isinstance(payload, dict):
        location_rows: list[dict[str, Any]] = []
        if isinstance(payload.get("snapshot"), dict):
            location_rows.append({"_section": "snapshot", **payload["snapshot"]})
        for section in ["wifi", "cell"]:
            for item in ensure_dict_list(payload.get(section)):
                location_rows.append({"_section": section, **item})
        return location_rows
    if family == "app_usage" and isinstance(payload, dict):
        rows: list[dict[str, Any]] = []
        for section in ["packages", "events"]:
            for item in ensure_dict_list(payload.get(section)):
                rows.append({"_section": section, **item})
        return rows
    if family == "parsed_artifacts":
        artifact_rows: list[dict[str, Any]] = []
        artifacts_payload = payload.get("artifacts") if isinstance(payload, dict) else payload
        for artifact in ensure_dict_list(artifacts_payload):
            artifact_family = str(
                artifact.get("artifact_family") or artifact.get("artifact_name") or "generic"
            ).lower()
            for item in ensure_dict_list(artifact.get("records")):
                artifact_rows.append({"_artifact_family": artifact_family, **item})
        return artifact_rows
    return ensure_dict_list(payload)


def _event_for_record(
    family: str,
    record: dict[str, Any],
    *,
    source_file: str | None,
    artifact_id: str | None,
    fallback_ts_ms: int | None,
) -> TimelineEvent | None:
    effective_family = family
    if family == "parsed_artifacts":
        artifact_family = str(record.get("_artifact_family") or "")
        if "sms" in artifact_family:
            effective_family = "sms"
        elif "call" in artifact_family:
            effective_family = "call_logs"
        elif "browser" in artifact_family:
            effective_family = "browser"
        elif "messag" in artifact_family:
            effective_family = "messaging"
        elif "location" in artifact_family:
            effective_family = "location"
        elif "media" in artifact_family:
            effective_family = "media"
        elif "account" in artifact_family:
            effective_family = "accounts"
        elif "usage" in artifact_family:
            effective_family = "app_usage"
        elif "wifi" in artifact_family:
            effective_family = "wifi_history"
        elif "bluetooth" in artifact_family:
            effective_family = "bluetooth"
        elif "notification" in artifact_family:
            effective_family = "notifications"

    if effective_family == "sms":
        ts_ms = coerce_ts_ms(
            record.get("date_ms") or record.get("timestamp_ms") or record.get("date"),
            field_name="date_ms",
        )
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="sms",
            kind="message",
            data=record,
            summary=record_preview(record, keys=("body", "address")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "call_logs":
        ts_ms = coerce_ts_ms(record.get("date_ms") or record.get("date"), field_name="date_ms")
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="call_logs",
            kind="call",
            data=record,
            summary=record_preview(record, keys=("number", "name", "type")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "browser":
        section = str(record.get("_section") or "history")
        field = {
            "history": "last_visit_time_raw",
            "bookmarks": "date_added_raw",
            "downloads": "start_time_raw",
            "cookies": "last_access_utc_raw",
        }.get(section, "last_visit_time_raw")
        ts_ms = coerce_ts_ms(record.get(field), field_name=field)
        if ts_ms is None and section == "downloads":
            ts_ms = coerce_ts_ms(record.get("end_time_raw"), field_name="end_time_raw")
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="browser",
            kind=section.rstrip("s"),
            data=record,
            summary=record_preview(record, keys=("title", "url", "target_path", "host")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "messaging":
        field_name = (
            "timestamp_ms"
            if record.get("timestamp_ms") is not None
            else ("date_ms" if record.get("date_ms") is not None else "date_s")
        )
        ts_ms = coerce_ts_ms(record.get(field_name), field_name=field_name)
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="messaging",
            kind="message",
            data=record,
            summary=record_preview(record, keys=("body", "text", "jid", "mid")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "media":
        ts_ms = coerce_ts_ms(
            record.get("timestamp_ms") or record.get("date_ms"), field_name="timestamp_ms"
        )
        if ts_ms is None:
            ts_ms = media_filename_ts_ms(record.get("path"))
        if ts_ms is None:
            ts_ms = fallback_ts_ms
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="media",
            kind="media",
            data=record,
            summary=record_preview(record, keys=("path", "kind")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "location":
        ts_ms = coerce_ts_ms(
            record.get("captured_at_ms") or record.get("timestamp_ms"), field_name="captured_at_ms"
        )
        if ts_ms is None:
            ts_ms = fallback_ts_ms
        if ts_ms is None:
            return None
        section = str(record.get("_section") or "snapshot")
        return TimelineEvent(
            ts_ms=ts_ms,
            source="location",
            kind=section,
            data=record,
            summary=record_preview(record, keys=("provider", "ssid", "raw")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "accounts":
        ts_ms = coerce_ts_ms(
            record.get("last_authenticated_ms")
            or record.get("last_login_ms")
            or record.get("timestamp_ms"),
            field_name="timestamp_ms",
        )
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="accounts",
            kind="account",
            data=record,
            summary=record_preview(record, keys=("name", "type", "account_name")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "app_usage":
        ts_ms = coerce_ts_ms(
            record.get("time")
            or record.get("timestamp_ms")
            or record.get("lastTimeUsed")
            or record.get("last_time_used_ms"),
            field_name="timestamp_ms",
        )
        if ts_ms is None:
            return None
        section = str(record.get("_section") or "usage")
        return TimelineEvent(
            ts_ms=ts_ms,
            source="app_usage",
            kind=section.rstrip("s"),
            data=record,
            summary=record_preview(record, keys=("package", "class", "package_name")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "wifi_history":
        ts_ms = coerce_ts_ms(
            record.get("LastConnectedTime")
            or record.get("last_connected_ms")
            or record.get("timestamp_ms"),
            field_name="timestamp_ms",
        )
        if ts_ms is None:
            ts_ms = fallback_ts_ms
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="wifi_history",
            kind="wifi",
            data=record,
            summary=record_preview(record, keys=("SSID", "ssid", "ConfigKey")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "bluetooth":
        ts_ms = coerce_ts_ms(
            record.get("last_seen_ms") or record.get("LastSeen") or record.get("timestamp_ms"),
            field_name="timestamp_ms",
        )
        if ts_ms is None:
            ts_ms = fallback_ts_ms
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="bluetooth",
            kind="device",
            data=record,
            summary=record_preview(record, keys=("name", "address", "Name")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    if effective_family == "notifications":
        ts_ms = coerce_ts_ms(
            record.get("posted_at_ms") or record.get("postedAt") or record.get("timestamp_ms"),
            field_name="timestamp_ms",
        )
        if ts_ms is None:
            return None
        return TimelineEvent(
            ts_ms=ts_ms,
            source="notifications",
            kind="notification",
            data=record,
            summary=record_preview(record, keys=("title", "package", "text")),
            source_file=source_file,
            artifact_family=family,
            artifact_id=artifact_id,
        )
    return None
