from __future__ import annotations

from collections import Counter
from typing import Any


def summarize_evidence_inventory(evidence_inventory: list[dict[str, Any]], artifacts: Any) -> dict[str, Any]:
    category_counts = Counter(str(item.get("category") or "unknown") for item in evidence_inventory if isinstance(item, dict))
    command_counts = Counter(str(item.get("source_command") or "unknown") for item in evidence_inventory if isinstance(item, dict))
    return {
        "artifact_count": len(evidence_inventory),
        "top_categories": [{"name": name, "count": count} for name, count in category_counts.most_common(6)],
        "top_source_commands": [{"name": name, "count": count} for name, count in command_counts.most_common(6)],
        "artifact_payload_rows": _top_level_row_count(artifacts),
    }


def _top_level_row_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 0