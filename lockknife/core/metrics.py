from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Iterator

_metrics: dict[str, dict[str, float]] = {}


def _entry(name: str) -> dict[str, float]:
    if name not in _metrics:
        _metrics[name] = {"count": 0.0, "error_count": 0.0, "total_ms": 0.0, "max_ms": 0.0}
    return _metrics[name]


@contextmanager
def track(name: str) -> Iterator[None]:
    start = time.perf_counter()
    err = False
    try:
        yield None
    except Exception:
        err = True
        raise
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        entry = _entry(name)
        entry["count"] += 1.0
        if err:
            entry["error_count"] += 1.0
        entry["total_ms"] += elapsed_ms
        if elapsed_ms > entry["max_ms"]:
            entry["max_ms"] = elapsed_ms


def snapshot() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, entry in _metrics.items():
        count = max(1.0, entry["count"])
        out[name] = {
            "count": int(entry["count"]),
            "error_count": int(entry["error_count"]),
            "avg_ms": entry["total_ms"] / count,
            "max_ms": entry["max_ms"],
        }
    return out
