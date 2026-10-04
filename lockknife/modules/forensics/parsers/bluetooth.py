from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from defusedxml.ElementTree import fromstring

_RE_MAC_SECTION = re.compile(r"^\[([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\]\s*$")


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

    # Try parsing as Android bt_config.conf INI format
    ini_rows: list[dict[str, Any]] = []
    current_device: dict[str, Any] | None = None

    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#") or trimmed.startswith(";"):
            continue

        mac_match = _RE_MAC_SECTION.match(trimmed)
        if mac_match:
            if current_device:
                ini_rows.append(current_device)
            current_device = {"address": mac_match.group(1)}
            continue

        if trimmed.startswith("[") and trimmed.endswith("]"):
            # Other section (e.g. [Adapter], [General])
            if current_device:
                ini_rows.append(current_device)
                current_device = None
            continue

        if current_device is not None and "=" in trimmed:
            part_key, part_val = trimmed.split("=", 1)
            k = part_key.strip()
            v = part_val.strip()
            current_device[k] = v
            k_low = k.lower()
            if k_low == "name" and "name" not in current_device:
                current_device["name"] = v
            elif k_low == "devclass":
                current_device["dev_class"] = v
            elif k_low == "linkkey":
                current_device["link_key"] = v
            elif k_low == "keytype":
                current_device["key_type"] = v
            elif k_low == "timestamp":
                current_device["timestamp"] = v

    if current_device:
        ini_rows.append(current_device)

    if ini_rows:
        return ini_rows

    # Fallback to legacy comma-delimited key=value lines
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
