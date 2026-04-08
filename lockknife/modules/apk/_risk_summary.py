from __future__ import annotations

from typing import Any


def build_apk_risk_summary(
    info: dict[str, Any], findings: list[Any], permission_score: int
) -> dict[str, Any]:
    component_summary = info.get("component_summary") or {}
    strings = info.get("string_analysis") or {}
    signing = info.get("signing") or {}
    stats = strings.get("stats") or {}
    severity_counts = _severity_counts(findings)
    breakdown: list[dict[str, Any]] = []
    score = 0

    finding_score = sum(
        _severity_weight(_finding_value(item, "severity") or "info") for item in findings
    )
    score += _add_breakdown(
        breakdown,
        factor="finding-severity",
        points=min(60, finding_score),
        summary="Manifest, signing, and code findings contribute weighted severity pressure.",
        evidence=[_trace_from_finding(item) for item in findings[:6]],
    )

    score += _add_breakdown(
        breakdown,
        factor="permission-risk",
        points=min(permission_score, 24),
        summary="Dangerous permissions add contextual risk even when no direct exploit path is proven.",
        evidence=[{"permission_count": len(info.get("permissions") or [])}],
    )

    exported_total = int(component_summary.get("exported_total") or 0)
    deeplink_total = int(component_summary.get("browsable_deeplink_total") or 0)
    weak_provider_total = int(component_summary.get("provider_weak_permission_total") or 0)
    surface_points = min(22, exported_total * 2 + deeplink_total * 3 + weak_provider_total * 6)
    score += _add_breakdown(
        breakdown,
        factor="component-surface",
        points=surface_points,
        summary="Exported components, browsable deep links, and weak providers widen the reachable Android surface.",
        evidence=[component_summary],
    )

    strict_signing = signing.get("strict_verification") or {}
    signing_findings = strict_signing.get("findings") or []
    signing_points = 0
    if signing.get("has_debug_or_test_certificate"):
        signing_points += 12
    if any(
        item.get("id") == "legacy-v1-only-signing"
        for item in signing_findings
        if isinstance(item, dict)
    ):
        signing_points += 6
    if strict_signing.get("status") == "fail":
        signing_points += 8
    score += _add_breakdown(
        breakdown,
        factor="signing-posture",
        points=min(20, signing_points),
        summary="Signing posture affects APK provenance confidence and update-integrity trust assumptions.",
        evidence=signing_findings[:4],
    )

    secret_count = int(stats.get("secret_indicator_count") or 0)
    tracker_count = int(stats.get("tracker_count") or 0)
    code_signal_count = int(stats.get("code_signal_count") or 0)
    string_points = min(18, secret_count * 6 + tracker_count * 2 + code_signal_count * 3)
    score += _add_breakdown(
        breakdown,
        factor="embedded-signals",
        points=string_points,
        summary="Secrets, trackers, and code-signal heuristics raise review pressure even before dynamic validation.",
        evidence=_string_signal_traces(strings),
    )

    score = min(100, score)
    top_findings = [
        {
            "id": _finding_value(item, "id"),
            "severity": _finding_value(item, "severity"),
            "title": _finding_value(item, "title"),
        }
        for item in findings[:5]
    ]
    return {
        "score": score,
        "level": _risk_level(score),
        "exploitability": _exploitability_level(
            exported_total, weak_provider_total, secret_count > 0, severity_counts
        ),
        "evidence_strength": _evidence_strength(findings, component_summary, secret_count),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "permission_score": permission_score,
        "permission_count": len(info.get("permissions") or []),
        "exported_component_count": exported_total,
        "browsable_deeplink_count": deeplink_total,
        "weak_provider_count": weak_provider_total,
        "has_debug_or_test_certificate": bool(signing.get("has_debug_or_test_certificate")),
        "secret_indicator_count": secret_count,
        "tracker_count": tracker_count,
        "code_signal_count": code_signal_count,
        "top_findings": top_findings,
        "score_breakdown": breakdown,
        "evidence_traces": _collect_evidence_traces(findings, strings, signing_findings),
    }


def _severity_weight(severity: str) -> int:
    return {
        "critical": 25,
        "high": 16,
        "medium": 8,
        "low": 3,
        "info": 0,
    }.get(str(severity).lower(), 0)


def _severity_counts(findings: list[Any]) -> dict[str, int]:
    counts = dict.fromkeys(["critical", "high", "medium", "low", "info"], 0)
    for finding in findings:
        severity = str(_finding_value(finding, "severity") or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _exploitability_level(
    exported_total: int,
    provider_weak_total: int,
    has_secret: bool,
    severity_counts: dict[str, int],
) -> str:
    pressure = exported_total + (provider_weak_total * 2) + (2 if has_secret else 0)
    if (
        provider_weak_total
        or severity_counts.get("critical", 0)
        or severity_counts.get("high", 0) >= 2
    ):
        return "high"
    if pressure >= 4 or severity_counts.get("medium", 0):
        return "medium"
    return "low"


def _evidence_strength(
    findings: list[Any], component_summary: dict[str, Any], secret_count: int
) -> str:
    if secret_count > 0 or int(component_summary.get("provider_weak_permission_total") or 0) > 0:
        return "strong"
    if any(
        str(_finding_value(item, "severity") or "").lower() in {"critical", "high"}
        for item in findings
    ):
        return "strong"
    if findings:
        return "moderate"
    return "heuristic"


def _finding_value(item: Any, key: str) -> Any:
    if isinstance(item, dict):
        return item.get(key)
    return getattr(item, key, None)


def _trace_from_finding(item: Any) -> dict[str, Any]:
    return {
        "source": "finding",
        "id": _finding_value(item, "id"),
        "severity": _finding_value(item, "severity"),
        "title": _finding_value(item, "title"),
    }


def _add_breakdown(
    breakdown: list[dict[str, Any]],
    *,
    factor: str,
    points: int,
    summary: str,
    evidence: list[Any],
) -> int:
    points = int(points)
    if points <= 0:
        return 0
    breakdown.append({"factor": factor, "points": points, "summary": summary, "evidence": evidence})
    return points


def _string_signal_traces(strings: dict[str, Any]) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for item in (strings.get("hardcoded_secret_indicators") or [])[:2]:
        if isinstance(item, dict):
            traces.append(
                {
                    "source": "string-analysis",
                    "id": "secret-indicator",
                    "preview": item.get("preview"),
                }
            )
    for item in (strings.get("trackers") or [])[:2]:
        if isinstance(item, dict):
            traces.append({"source": "tracker", "id": item.get("id"), "title": item.get("label")})
    for item in (strings.get("code_signals") or [])[:2]:
        if isinstance(item, dict):
            traces.append(
                {"source": "code-signal", "id": item.get("id"), "title": item.get("label")}
            )
    return traces


def _collect_evidence_traces(
    findings: list[Any],
    strings: dict[str, Any],
    signing_findings: list[Any],
) -> list[dict[str, Any]]:
    traces = [_trace_from_finding(item) for item in findings[:8]]
    traces.extend(_string_signal_traces(strings))
    for item in signing_findings[:3]:
        if isinstance(item, dict):
            traces.append(
                {
                    "source": "signing",
                    "id": item.get("id"),
                    "severity": item.get("severity"),
                    "title": item.get("title"),
                }
            )
    return traces[:12]
