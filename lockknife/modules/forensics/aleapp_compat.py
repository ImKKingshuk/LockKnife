from __future__ import annotations

import csv
import json
import pathlib
import re
import sqlite3
from collections import Counter
from typing import Any, cast

_LAVA_JSON_NAMES = ("_lava_data.json", "lava_data.json")
_LAVA_DB_NAMES = ("_lava_artifacts.db", "lava_artifacts.db")


def looks_like_aleapp_output(input_dir: pathlib.Path) -> bool:
    return _find_first(input_dir, _LAVA_JSON_NAMES) is not None or any(input_dir.rglob("*.tsv"))


def import_aleapp_artifacts(input_dir: pathlib.Path) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    source_formats: Counter[str] = Counter()
    lava_json = _find_first(input_dir, _LAVA_JSON_NAMES)
    lava_db = _find_first(input_dir, _LAVA_DB_NAMES)
    if lava_json is not None and lava_db is not None:
        try:
            imported = _import_lava_artifacts(lava_json, lava_db)
            artifacts.extend(imported)
            source_formats["lava"] += len(imported)
        except (json.JSONDecodeError, OSError, sqlite3.DatabaseError, TypeError, ValueError) as exc:
            warnings.append(f"Failed to import LAVA artifacts: {exc}")
    if not artifacts:
        tsv_artifacts = _import_tsv_artifacts(input_dir)
        artifacts.extend(tsv_artifacts)
        source_formats["tsv"] += len(tsv_artifacts)
    artifact_family_counts = Counter(
        str(item.get("artifact_family") or "generic") for item in artifacts
    )
    return {
        "source_dir": str(input_dir),
        "artifacts": artifacts,
        "summary": {
            "artifact_count": len(artifacts),
            "artifact_family_counts": dict(sorted(artifact_family_counts.items())),
            "source_format_counts": dict(sorted(source_formats.items())),
            "lava_metadata_path": str(lava_json) if lava_json else None,
            "lava_database_path": str(lava_db) if lava_db else None,
            "warning_count": len(warnings),
        },
        "warnings": warnings,
    }


def _find_first(input_dir: pathlib.Path, names: tuple[str, ...]) -> pathlib.Path | None:
    for name in names:
        for path in sorted(input_dir.rglob(name)):
            if path.is_file():
                return path
    return None


def _import_lava_artifacts(
    metadata_path: pathlib.Path, database_path: pathlib.Path
) -> list[dict[str, Any]]:
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    artifacts_root = payload.get("artifacts") or {}
    if not isinstance(artifacts_root, dict):
        return []
    conn = sqlite3.connect(str(database_path))
    conn.row_factory = sqlite3.Row
    out: list[dict[str, Any]] = []
    try:
        for category, entries in artifacts_root.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                table_name = str(entry.get("tablename") or "").strip()
                if not table_name:
                    continue
                column_map = cast(
                    dict[str, Any],
                    entry.get("column_map") if isinstance(entry.get("column_map"), dict) else {},
                )
                rows = _query_table(conn, table_name)
                if not rows:
                    continue
                artifact_name = str(entry.get("name") or table_name)
                module_name = str(entry.get("module") or table_name)
                normalized = [
                    _normalize_lava_row(dict(row), column_map, artifact_name=artifact_name)
                    for row in rows
                ]
                family = infer_aleapp_family(
                    artifact_name=artifact_name,
                    category=str(category),
                    module_name=module_name,
                    rows=normalized,
                )
                out.append(
                    {
                        "artifact_name": artifact_name,
                        "artifact_family": family,
                        "parser_id": f"aleapp:{module_name}",
                        "source_file": f"{database_path}::{table_name}",
                        "records": normalized,
                        "summary": {
                            "record_count": len(normalized),
                            "source_format": "lava",
                            "aleapp_category": category,
                            "aleapp_module": module_name,
                            "table_name": table_name,
                            "metadata_path": str(metadata_path),
                        },
                    }
                )
    finally:
        conn.close()
    return out


def _query_table(
    conn: sqlite3.Connection, table_name: str, *, limit: int = 500
) -> list[sqlite3.Row]:
    if not re.fullmatch(r"[A-Za-z0-9_]+", table_name):
        return []
    escaped = table_name.replace('"', '""')
    query = f'SELECT * FROM "{escaped}" LIMIT {int(limit)}'  # nosec B608
    try:
        return list(conn.execute(query))
    except sqlite3.DatabaseError:
        return []


def _normalize_lava_row(
    row: dict[str, Any], column_map: dict[str, Any], *, artifact_name: str
) -> dict[str, Any]:
    out: dict[str, Any] = {"_artifact_name": artifact_name}
    for key, value in row.items():
        original = str(column_map.get(key) or key)
        normalized_key = _normalize_key(original)
        normalized_value = _normalize_value(value)
        out[original] = normalized_value
        out.setdefault(normalized_key, normalized_value)
    return _augment_aliases(out)


def _import_tsv_artifacts(input_dir: pathlib.Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(input_dir.rglob("*.tsv")):
        try:
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                reader = csv.DictReader(handle, delimiter="\t")
                rows = [
                    _normalize_tsv_row(row, artifact_name=path.stem)
                    for row in reader
                    if isinstance(row, dict)
                ]
        except (csv.Error, OSError, UnicodeError):
            continue
        if not rows:
            continue
        family = infer_aleapp_family(
            artifact_name=path.stem, category=path.parent.name, module_name=path.stem, rows=rows
        )
        out.append(
            {
                "artifact_name": path.stem.replace("_", " ").title(),
                "artifact_family": family,
                "parser_id": f"aleapp:tsv:{path.stem}",
                "source_file": str(path),
                "records": rows,
                "summary": {
                    "record_count": len(rows),
                    "source_format": "tsv",
                    "aleapp_category": path.parent.name,
                    "table_name": path.stem,
                },
            }
        )
    return out


def _normalize_tsv_row(row: dict[str, Any], *, artifact_name: str) -> dict[str, Any]:
    out = {"_artifact_name": artifact_name}
    for key, value in row.items():
        if key is None:
            continue
        normalized_key = _normalize_key(str(key))
        normalized_value = _normalize_value(value)
        out[str(key)] = normalized_value
        out.setdefault(normalized_key, normalized_value)
    return _augment_aliases(out)


def infer_aleapp_family(
    *, artifact_name: str, category: str, module_name: str, rows: list[dict[str, Any]]
) -> str:
    tokens = " ".join([artifact_name, category, module_name]).lower()
    row_keys = {str(key).lower() for row in rows[:10] for key in row.keys()}
    if any(token in tokens for token in ["sms", "mms"]):
        return "sms"
    if any(token in tokens for token in ["call", "phone"]):
        return "call_logs"
    if any(token in tokens for token in ["browser", "chrome", "firefox", "bookmark", "history"]):
        return "browser"
    if any(
        token in tokens
        for token in ["whatsapp", "telegram", "signal", "discord", "message", "chat"]
    ):
        return "messaging"
    if any(token in tokens for token in ["location", "gps", "geofence"]):
        return "location"
    if any(token in tokens for token in ["photo", "image", "media", "gallery"]):
        return "media"
    if any(token in tokens for token in ["account", "google account"]):
        return "accounts"
    if any(token in tokens for token in ["usage", "app launch", "app usage"]):
        return "app_usage"
    if "wifi" in tokens:
        return "wifi_history"
    if "bluetooth" in tokens:
        return "bluetooth"
    if "notification" in tokens:
        return "notifications"
    if {"body", "address", "date", "date_ms"} & row_keys:
        return "sms"
    if {"number", "type", "duration"} & row_keys:
        return "call_logs"
    if {"url", "title", "last_visit_time_raw"} & row_keys:
        return "browser"
    if {"body", "text", "jid", "mid"} & row_keys:
        return "messaging"
    if {"latitude", "longitude", "timestamp_ms"} <= row_keys or {
        "provider",
        "latitude",
        "longitude",
    } <= row_keys:
        return "location"
    return "generic"


def _normalize_key(value: str) -> str:
    normalized = []
    last_was_sep = False
    for ch in value.strip():
        if ch.isalnum():
            normalized.append(ch.lower())
            last_was_sep = False
        elif not last_was_sep:
            normalized.append("_")
            last_was_sep = True
    return "".join(normalized).strip("_") or "value"


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return text
        if (text.startswith("{") and text.endswith("}")) or (
            text.startswith("[") and text.endswith("]")
        ):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return text
    return value


def _augment_aliases(row: dict[str, Any]) -> dict[str, Any]:
    alias_pairs = {
        "timestamp": "timestamp_ms",
        "date": "date_ms",
        "time": "timestamp_ms",
        "last_time_used": "last_time_used_ms",
        "lastconnectedtime": "last_connected_ms",
        "last_connected_time": "last_connected_ms",
        "ssid_name": "ssid",
        "package_name": "package",
        "account": "account_name",
    }
    for source, target in alias_pairs.items():
        if source in row and target not in row:
            row[target] = row[source]
    return row
