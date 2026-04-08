from __future__ import annotations

import json
import pathlib
from typing import Any

from defusedxml.ElementTree import fromstring


def parse_notifications_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return [item for item in payload.get("notifications") or [] if isinstance(item, dict)]
        return (
            [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, list)
            else []
        )
    root = fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    return [dict(node.attrib) for node in root.findall(".//notification")]
