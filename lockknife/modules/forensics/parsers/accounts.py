from __future__ import annotations

import json
import pathlib
from typing import Any

from defusedxml.ElementTree import fromstring


def parse_accounts_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        return _json_records(json.loads(path.read_text(encoding="utf-8")))
    return _xml_records(path.read_text(encoding="utf-8", errors="ignore"))


def _json_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        rows: list[dict[str, Any]] = []
        for section in ("accounts", "users", "items"):
            for item in payload.get(section) or []:
                if isinstance(item, dict):
                    rows.append({"_section": section, **item})
        return rows or [payload]
    return []


def _xml_records(text: str) -> list[dict[str, Any]]:
    root = fromstring(text)
    rows: list[dict[str, Any]] = []
    for node in root.findall(".//account") + root.findall(".//item"):
        row = dict(node.attrib)
        if node.text and node.text.strip() and "name" not in row:
            row["name"] = node.text.strip()
        rows.append(row)
    return rows