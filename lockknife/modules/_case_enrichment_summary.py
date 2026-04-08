from __future__ import annotations

from collections import Counter
from typing import Any


def summarize_case_enrichment_runs(
    runs: list[dict[str, Any]], skipped_artifacts: list[dict[str, Any]]
) -> dict[str, Any]:
    workflow_counts = Counter(str(run.get("workflow") or "unknown") for run in runs)
    status_counts = Counter(str(run.get("status") or "unknown") for run in runs)
    provider_counts = Counter(str(run.get("provider") or "unknown") for run in runs)
    skipped_reason_counts = Counter(
        str(item.get("reason") or "unknown") for item in skipped_artifacts
    )
    return {
        "workflow_status": [
            {"name": name, "count": count} for name, count in workflow_counts.most_common()
        ],
        "run_status": [
            {"name": name, "count": count} for name, count in status_counts.most_common()
        ],
        "provider_usage": [
            {"name": name, "count": count} for name, count in provider_counts.most_common()
        ],
        "skipped_reasons": [
            {"name": name, "count": count} for name, count in skipped_reason_counts.most_common()
        ],
        "error_count": status_counts.get("error", 0),
        "success_count": status_counts.get("ok", 0),
    }
