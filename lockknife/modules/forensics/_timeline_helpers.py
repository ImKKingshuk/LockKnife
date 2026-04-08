from __future__ import annotations

import dataclasses
import datetime as dt
import json
import pathlib
import re
from typing import Any

WINDOWS_EPOCH_OFFSET_MS = 11644473600000
WINDOWS_EPOCH_OFFSET_US = 11644473600000000

_MEDIA_TS_RE = re.compile(
    r"(?P<year>20\d{2})(?P<month>[01]\d)(?P<day>[0-3]\d)[-_]?(?P<hour>[0-2]\d)(?P<minute>[0-5]\d)(?P<second>[0-5]\d)"
)


@dataclasses.dataclass(frozen=True)
class TimelineSource:
    family: str
    path: str
    origin: str
    artifact_id: str | None = None
    category: str | None = None


def coerce_ts_ms(value: Any, *, field_name: str | None = None) -> int | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            try:
                return _int_to_ts_ms(int(text), field_name=field_name)
            except (OverflowError, ValueError):
                return None
        return _parse_datetime(text)
    if isinstance(value, (int, float)):
        return _int_to_ts_ms(int(value), field_name=field_name)
    return None


def load_json_payload(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def record_preview(record: dict[str, Any], *, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().replace("\n", " ")[:120]
    return None


def media_filename_ts_ms(path_value: str | None) -> int | None:
    if not path_value:
        return None
    match = _MEDIA_TS_RE.search(pathlib.PurePosixPath(path_value).name)
    if not match:
        return None
    try:
        parsed = dt.datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=dt.UTC,
        )
    except ValueError:
        return None
    return int(parsed.timestamp() * 1000)


def fallback_file_ts_ms(path: pathlib.Path | None) -> int | None:
    if path is None or not path.exists():
        return None
    try:
        return int(path.stat().st_mtime * 1000)
    except OSError:
        return None


def family_from_category_or_name(category: str | None, path: pathlib.Path) -> str:
    category_l = (category or "").lower()
    name_l = path.name.lower()
    if "sms" in category_l or name_l == "sms.json":
        return "sms"
    if "call" in category_l or name_l in {"call_logs.json", "calls.json"}:
        return "call_logs"
    if "browser" in category_l or name_l in {
        "browser.json",
        "history.json",
        "bookmarks.json",
        "downloads.json",
    }:
        return "browser"
    if "messaging" in category_l or name_l in {
        "messaging.json",
        "messages.json",
        "whatsapp.json",
        "telegram.json",
        "signal.json",
    }:
        return "messaging"
    if "media" in category_l or name_l in {"media.json", "photos.json"}:
        return "media"
    if "location" in category_l or name_l == "location.json":
        return "location"
    if "account" in category_l or "accounts" in name_l:
        return "accounts"
    if "usage" in category_l or "usagestats" in name_l or "app_usage" in name_l:
        return "app_usage"
    if "wifi" in category_l or "wifi" in name_l:
        return "wifi_history"
    if "bluetooth" in category_l or "bluetooth" in name_l or "bt_config" in name_l:
        return "bluetooth"
    if "notification" in category_l or "notification" in name_l:
        return "notifications"
    if "forensics-parse" in category_l or name_l == "parsed_artifacts.json":
        return "parsed_artifacts"
    return "generic"


def discover_case_timeline_sources(case_dir: pathlib.Path) -> list[TimelineSource]:
    try:
        from lockknife.core.case import load_case_manifest
    except ImportError:
        return []
    try:
        manifest = load_case_manifest(case_dir)
    except (FileNotFoundError, OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return []
    allowed_categories = {
        "extract-sms",
        "extract-call-logs",
        "extract-browser",
        "extract-messaging",
        "extract-media",
        "extract-location",
        "forensics-accounts",
        "forensics-app-usage",
        "forensics-wifi-history",
        "forensics-bluetooth",
        "forensics-notifications",
        "forensics-parse",
    }
    seen: set[str] = set()
    out: list[TimelineSource] = []
    for artifact in getattr(manifest, "artifacts", []):
        path = pathlib.Path(getattr(artifact, "path", ""))
        category = getattr(artifact, "category", None)
        if category not in allowed_categories or not path.exists():
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            TimelineSource(
                family=family_from_category_or_name(category, path),
                path=str(path),
                origin="case-artifact",
                artifact_id=getattr(artifact, "artifact_id", None),
                category=category,
            )
        )
    return out


def unique_sources(*groups: list[TimelineSource]) -> list[TimelineSource]:
    seen: set[tuple[str, str]] = set()
    out: list[TimelineSource] = []
    for group in groups:
        for source in group:
            key = (source.family, source.path)
            if key in seen:
                continue
            seen.add(key)
            out.append(source)
    return out


def _int_to_ts_ms(value: int, *, field_name: str | None = None) -> int | None:
    if value <= 0:
        return None
    field_name_l = (field_name or "").lower()
    if field_name_l.endswith("_utc_raw") or field_name_l.endswith("_time_raw"):
        if value >= WINDOWS_EPOCH_OFFSET_US:
            return int(value / 1000) - WINDOWS_EPOCH_OFFSET_MS
    if value > 10**17:
        return int(value / 1_000_000)
    if value >= WINDOWS_EPOCH_OFFSET_US:
        return int(value / 1000) - WINDOWS_EPOCH_OFFSET_MS
    if value > 10**14:
        return int(value / 1000)
    if value > 10**11:
        return value
    if value > 10**9:
        return value * 1000
    return value if field_name is not None else None


def _parse_datetime(text: str) -> int | None:
    candidate = text.replace("Z", "+00:00")
    for parser_name in ("isoformat", "space", "t"):
        try:
            if parser_name == "isoformat":
                parsed = dt.datetime.fromisoformat(candidate)
            elif parser_name == "space":
                parsed = dt.datetime.strptime(candidate, "%Y-%m-%d %H:%M:%S")
            else:
                parsed = dt.datetime.strptime(candidate, "%Y-%m-%dT%H:%M:%S")
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.UTC)
            return int(parsed.timestamp() * 1000)
        except ValueError:
            continue
    return None
