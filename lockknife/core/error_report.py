from __future__ import annotations

"""Structured error reporting for forensic-grade bug reports.

Usage::

    from lockknife.core.error_report import capture, format_report

    try:
        result = some_operation()
    except Exception:
        report = capture("some_operation", device_serial="abc123")
        print(format_report(report))
"""

import datetime
import platform
import sys
import traceback
from dataclasses import dataclass
from typing import Any


@dataclass
class ErrorReport:
    operation: str
    timestamp: str
    exc_type: str
    exc_message: str
    traceback: str
    device_serial: str | None
    platform_info: dict[str, str]
    extra: dict[str, Any]


def capture(
    operation: str,
    *,
    device_serial: str | None = None,
    extra: dict[str, Any] | None = None,
) -> ErrorReport:
    """Capture the current exception into a structured ``ErrorReport``.

    Must be called from inside an ``except`` block.
    """
    exc_type, exc_value, tb = sys.exc_info()
    tb_text = (
        "".join(traceback.format_exception(exc_type, exc_value, tb)) if exc_type is not None else ""
    )
    return ErrorReport(
        operation=operation,
        timestamp=datetime.datetime.now(datetime.UTC).isoformat(),
        exc_type=exc_type.__name__ if exc_type else "UnknownError",
        exc_message=str(exc_value) if exc_value else "",
        traceback=tb_text,
        device_serial=device_serial,
        platform_info={
            "python": sys.version,
            "platform": platform.platform(),
            "arch": platform.machine(),
        },
        extra=extra or {},
    )


def format_report(report: ErrorReport) -> str:
    """Format an error report as a sanitized text block for bug reports."""
    lines = [
        "─" * 60,
        "LockKnife Error Report",
        "─" * 60,
        f"Operation : {report.operation}",
        f"Timestamp : {report.timestamp}",
        f"Exception : {report.exc_type}: {report.exc_message}",
        f"Device    : {report.device_serial or 'N/A'}",
        f"Python    : {report.platform_info.get('python', '?')}",
        f"Platform  : {report.platform_info.get('platform', '?')}",
    ]
    if report.extra:
        lines.append(f"Extra     : {report.extra}")
    lines += ["", "Traceback:", report.traceback.rstrip(), "─" * 60]
    return "\n".join(lines)
