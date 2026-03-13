from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any, Callable

from defusedxml.ElementTree import ParseError, fromstring

from lockknife.modules.forensics.aleapp_compat import looks_like_aleapp_output
from lockknife.modules.forensics.parsers import (
    decode_protobuf_file,
    parse_accounts_artifacts,
    parse_app_usage_artifacts,
    parse_bluetooth_artifacts,
    parse_notifications_artifacts,
    parse_wifi_history_artifacts,
)


ArtifactLoader = Callable[[pathlib.Path], list[dict[str, Any]]]


@dataclasses.dataclass(frozen=True)
class ArtifactParserSpec:
    parser_id: str
    artifact_name: str
    artifact_family: str
    filenames: tuple[str, ...]
    loader: ArtifactLoader | None = None


REGISTRY: tuple[ArtifactParserSpec, ...] = (
    ArtifactParserSpec("android-sms", "Android SMS", "sms", ("sms.json",)),
    ArtifactParserSpec("android-contacts", "Android Contacts", "contacts", ("contacts.json",)),
    ArtifactParserSpec("android-call-logs", "Android Call Logs", "call_logs", ("call_logs.json", "calls.json")),
    ArtifactParserSpec("android-browser", "Browser Artifacts", "browser", ("browser.json", "history.json", "bookmarks.json", "downloads.json")),
    ArtifactParserSpec("android-messaging", "Messaging Artifacts", "messaging", ("messaging.json", "messages.json", "whatsapp.json", "telegram.json", "signal.json")),
    ArtifactParserSpec("android-media", "Media Artifacts", "media", ("media.json", "photos.json")),
    ArtifactParserSpec("android-location", "Location Artifacts", "location", ("location.json",)),
    ArtifactParserSpec("android-accounts", "Android Accounts", "accounts", ("accounts.json", "accounts.xml", "*accounts*.json", "*accounts*.xml"), parse_accounts_artifacts),
    ArtifactParserSpec("android-app-usage", "Android App Usage", "app_usage", ("app_usage.json", "usagestats.json", "*usagestats*.xml"), parse_app_usage_artifacts),
    ArtifactParserSpec("android-wifi-history", "Wi-Fi History", "wifi_history", ("wifi_history.json", "wifi_history.xml", "*wifi*.json", "*Wifi*.xml"), parse_wifi_history_artifacts),
    ArtifactParserSpec("android-bluetooth", "Bluetooth Artifacts", "bluetooth", ("bluetooth.json", "bluetooth.xml", "*bluetooth*.json", "*bluetooth*.xml", "bt_config.conf"), parse_bluetooth_artifacts),
    ArtifactParserSpec("android-notifications", "Notification Artifacts", "notifications", ("notifications.json", "notifications.xml", "*notifications*.json", "*notifications*.xml"), parse_notifications_artifacts),
)


def iter_registered_artifacts(input_dir: pathlib.Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for spec in REGISTRY:
        for path in _candidate_paths(input_dir, spec.filenames):
            records = _records_for_spec(spec, path)
            if not records:
                continue
            out.append(
                {
                    "artifact_name": spec.artifact_name,
                    "artifact_family": spec.artifact_family,
                    "parser_id": spec.parser_id,
                    "source_file": str(path),
                    "records": records,
                    "summary": {"record_count": len(records), "filename": path.name},
                }
            )
            break
    return out


def parse_app_data_artifacts(input_dir: pathlib.Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    app_data: list[dict[str, Any]] = []
    protobufs: list[dict[str, Any]] = []
    if looks_like_aleapp_output(input_dir):
        return app_data, protobufs
    registered_names = {name for spec in REGISTRY for name in spec.filenames if "*" not in name and "?" not in name}
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in registered_names:
            continue
        if path.suffix.lower() in {".xml", ".json"}:
            parsed = _parse_app_data_file(path)
            if parsed is not None:
                app_data.append(parsed)
            continue
        if _looks_like_protobuf_candidate(path):
            parsed = _parse_protobuf_file(path)
            if parsed is not None:
                protobufs.append(parsed)
    return app_data[:40], protobufs[:40]


def _load_json(path: pathlib.Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _candidate_paths(input_dir: pathlib.Path, patterns: tuple[str, ...]) -> list[pathlib.Path]:
    seen: set[str] = set()
    out: list[pathlib.Path] = []
    for pattern in patterns:
        matches = sorted(input_dir.rglob(pattern)) if any(token in pattern for token in "*?[]") else [input_dir / pattern]
        for path in matches:
            if not path.exists() or not path.is_file():
                continue
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
    return out


def _records_for_spec(spec: ArtifactParserSpec, path: pathlib.Path) -> list[dict[str, Any]]:
    if spec.loader is not None:
        try:
            return [item for item in spec.loader(path) if isinstance(item, dict)]
        except (OSError, UnicodeError, ValueError, TypeError, ParseError, json.JSONDecodeError):
            return []
    payload = _load_json(path)
    if payload is None:
        return []
    return _records_from_payload(payload)


def _records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        expanded: list[dict[str, Any]] = []
        for key, value in payload.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        expanded.append({"_section": key, **item})
        if expanded:
            return expanded
        return [payload]
    return []


def _parse_app_data_file(path: pathlib.Path) -> dict[str, Any] | None:
    if path.stat().st_size > 1_000_000:
        return None
    if path.suffix.lower() == ".json":
        data = _load_json(path)
        if not isinstance(data, dict):
            return None
        preview = [{"key": str(key), "value": _value_preview(value)} for key, value in list(data.items())[:8]]
        return {"source_file": str(path), "format": "json", "key_count": len(data), "preview": preview}
    try:
        root = fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ParseError, TypeError, ValueError):
        return None
    preview = []
    for child in list(root)[:12]:
        key = child.attrib.get("name") or child.tag
        text = (child.text or "").strip()
        if not text:
            attrs = {k: v for k, v in child.attrib.items() if k != "name"}
            text = ", ".join(f"{k}={v}" for k, v in attrs.items())
        preview.append({"key": key, "value": text[:160]})
    return {
        "source_file": str(path),
        "format": "xml",
        "root_tag": root.tag,
        "key_count": len(preview),
        "preview": preview,
    }


def _looks_like_protobuf_candidate(path: pathlib.Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".pb", ".pbf", ".protobuf", ".proto", ".bin", ".dat"}:
        return path.stat().st_size <= 1_000_000
    return "proto" in path.name.lower() and path.stat().st_size <= 1_000_000


def _parse_protobuf_file(path: pathlib.Path) -> dict[str, Any] | None:
    return decode_protobuf_file(path)


def _value_preview(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)[:120]
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, dict):
        return f"dict[{len(value)}]"
    return type(value).__name__