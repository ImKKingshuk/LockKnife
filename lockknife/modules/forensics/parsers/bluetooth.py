from __future__ import annotations

import json
import pathlib
from typing import Any

from defusedxml.ElementTree import fromstring


def parse_bluetooth_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        if isinstance(payload, dict):
            return [item for item in payload.get("devices") or [] if isinstance(item, dict)]
        return (
            [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, list)
            else []
        )
    if path.suffix.lower() == ".xml":
        root = fromstring(text)
        return [dict(node.attrib) for node in root.findall(".//device")]
    rows = []
    for line in text.splitlines():
        if "address=" not in line.lower():
            continue
        row: dict[str, Any] = {}
        for part in line.split(","):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            row[key.strip()] = value.strip()
        if row:
            rows.append(row)
    return rows
