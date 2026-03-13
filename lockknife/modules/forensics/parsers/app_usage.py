from __future__ import annotations

import json
import pathlib
from typing import Any

from defusedxml.ElementTree import fromstring


def parse_app_usage_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            rows: list[dict[str, Any]] = []
            for section in ("packages", "events"):
                for item in payload.get(section) or []:
                    if isinstance(item, dict):
                        rows.append({"_section": section, **item})
            return rows
        return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
    root = fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    xml_rows: list[dict[str, Any]] = []
    for package in root.findall(".//package"):
        xml_rows.append({"_section": "packages", **package.attrib})
    for event in root.findall(".//event"):
        xml_rows.append({"_section": "events", **event.attrib})
    return xml_rows