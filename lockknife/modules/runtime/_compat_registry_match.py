from __future__ import annotations

from typing import Any

from lockknife.modules.runtime._compat_registry_models import (
    RuntimeCompatibilityContext,
    RuntimeCompatibilityRule,
)
from lockknife.modules.runtime._compat_registry_rules import RUNTIME_COMPATIBILITY_RULES


def evaluate_runtime_compatibility(
    *,
    app_id: str,
    device_id: str | None,
    attach_mode: str,
    session_kind: str | None = None,
    application_available: bool | None = None,
    running_pid: int | None = None,
    device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = RuntimeCompatibilityContext(
        app_id=app_id,
        device_id=device_id,
        attach_mode=attach_mode,
        session_kind=session_kind,
        application_available=application_available,
        running_pid=running_pid,
        device=device or {},
    )
    findings = [
        _build_finding(rule, context)
        for rule in RUNTIME_COMPATIBILITY_RULES
        if _rule_matches(rule, context)
    ]
    severities = [str(item.get("severity") or "info") for item in findings]
    status = "fail" if "fail" in severities else ("warn" if "warn" in severities else "pass")
    return {
        "status": status,
        "finding_count": len(findings),
        "warning_count": sum(1 for item in findings if item["severity"] == "warn"),
        "fail_count": sum(1 for item in findings if item["severity"] == "fail"),
        "findings": findings,
        "recommended_next_action": _recommended_next_action(context, findings, status),
    }


def _rule_matches(rule: RuntimeCompatibilityRule, context: RuntimeCompatibilityContext) -> bool:
    if rule.attach_modes and context.attach_mode not in rule.attach_modes:
        return False
    if rule.session_kinds:
        if context.session_kind is None or context.session_kind not in rule.session_kinds:
            return False
    condition = rule.condition
    if condition == "spawn_restarts_app":
        return True
    if condition == "attach_requires_running_process":
        return context.running_pid is None
    if condition == "trace_high_volume":
        return True
    if condition == "visibility_unconfirmed":
        return context.application_available is False
    if condition == "ssl_attach_fragile":
        return True
    if condition == "root_attach_fragile":
        return True
    return False


def _build_finding(
    rule: RuntimeCompatibilityRule,
    context: RuntimeCompatibilityContext,
) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "message": rule.message,
        "recovery_hint": rule.recovery_hint,
        "recommended_next": rule.recommended_next,
        "attach_mode": context.attach_mode,
        "session_kind": context.session_kind,
        "tags": list(rule.tags),
    }


def _recommended_next_action(
    context: RuntimeCompatibilityContext,
    findings: list[dict[str, Any]],
    status: str,
) -> str:
    for severity in ("fail", "warn"):
        for finding in findings:
            if finding.get("severity") == severity and finding.get("recommended_next"):
                return str(finding["recommended_next"])
    if status == "pass" and context.attach_mode == "attach":
        return "Attach-mode readiness looks good; reconnect or launch while the target process stays live."
    if status == "pass":
        return "Spawn-mode readiness looks good; launch when you are ready for the app to restart under Frida."
    return "Review the compatibility findings before starting or reconnecting a managed runtime session."
