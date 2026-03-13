from __future__ import annotations

from typing import Any


def build_runtime_event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_level: dict[str, int] = {}
    by_type: dict[str, int] = {}
    normalized = []
    recent = []
    for event in events:
        level = str(event.get("level") or "info")
        event_type = str(event.get("event_type") or "event")
        by_level[level] = by_level.get(level, 0) + 1
        by_type[event_type] = by_type.get(event_type, 0) + 1
        normalized.append(
            {
                "timestamp_utc": event.get("timestamp_utc"),
                "level": level,
                "event_type": event_type,
                "message": event.get("message"),
            }
        )
    recent = normalized[-5:]
    latest = recent[-1] if recent else None
    return {
        "event_count": len(events),
        "levels": by_level,
        "types": by_type,
        "latest": latest,
        "recent": recent,
    }


def build_runtime_failure_context(
    session: dict[str, Any],
    preflight: dict[str, Any] | None,
) -> dict[str, Any] | None:
    error_message = str(session.get("error_message") or "").strip()
    status = str(session.get("status") or "")
    recovery_hint = str(session.get("recovery_hint") or "").strip()
    if not error_message and status != "failed":
        return None
    blocked_checks = []
    warned_checks = []
    compatibility_findings = []
    if isinstance(preflight, dict):
        for check in preflight.get("checks") or []:
            if not isinstance(check, dict):
                continue
            check_name = str(check.get("check") or "check")
            check_status = str(check.get("status") or "unknown")
            if check_status == "fail":
                blocked_checks.append(check_name)
            elif check_status == "warn":
                warned_checks.append(check_name)
        compatibility = preflight.get("compatibility") or {}
        if isinstance(compatibility, dict):
            for finding in compatibility.get("findings") or []:
                if isinstance(finding, dict) and finding.get("severity") in {"warn", "fail"}:
                    compatibility_findings.append(str(finding.get("title") or finding.get("rule_id") or "compatibility"))
    return {
        "status": status or "unknown",
        "error_message": error_message or None,
        "recovery_hint": recovery_hint or None,
        "blocked_checks": blocked_checks,
        "warned_checks": warned_checks,
        "compatibility_findings": compatibility_findings,
    }
