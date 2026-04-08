from __future__ import annotations

import json
import pathlib
from typing import Any

from defusedxml.ElementTree import fromstring


def parse_wifi_history_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        if isinstance(payload, dict):
            return [item for item in payload.get("networks") or [] if isinstance(item, dict)]
        return (
            [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, list)
            else []
        )
    if path.suffix.lower() == ".xml":
        root = fromstring(text)
        rows: list[dict[str, Any]] = []
        for network in root.findall(".//Network") + root.findall(".//WifiConfiguration"):
            row = dict(network.attrib)
            for child in list(network):
                key = child.attrib.get("name") or child.tag
                row[key] = (child.text or "").strip()
            rows.append(row)
        return rows
    rows = []
    for line in text.splitlines():
        if "ssid=" not in line.lower():
            continue
        text_row: dict[str, Any] = {}
        for part in line.split(","):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            text_row[key.strip()] = value.strip()
        if text_row:
            rows.append(text_row)
    return rows
