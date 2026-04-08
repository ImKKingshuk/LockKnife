from __future__ import annotations

from collections.abc import Callable
from typing import Any

ProgressCallback = Callable[[dict[str, Any]], None]


def emit_progress(
    callback: ProgressCallback | None,
    *,
    operation: str,
    step: str,
    message: str,
    current: int | None = None,
    total: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    if callback is None:
        return
    payload: dict[str, Any] = {
        "operation": operation,
        "step": step,
        "message": message,
        "current": current,
        "total": total,
        "metadata": metadata or {},
    }
    if current is not None and total:
        payload["percent"] = round((current / total) * 100, 2)
    callback(payload)
