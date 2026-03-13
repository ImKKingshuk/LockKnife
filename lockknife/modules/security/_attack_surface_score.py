from __future__ import annotations

from typing import Any


SEVERITY_WEIGHTS = {"high": 28, "medium": 14, "low": 6, "info": 2}


def risk_summary(
    findings: list[dict[str, Any]],
    *,
    static_analysis: dict[str, Any],
    live_analysis: dict[str, Any],
) -> dict[str, Any]:
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    top_findings = sorted(findings, key=_finding_priority, reverse=True)[:5]
    score_breakdown: list[dict[str, Any]] = []

    severity_points = 0
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        severity_points += SEVERITY_WEIGHTS.get(severity, 1)
    _add_factor(score_breakdown, "finding-severity", min(36, severity_points), "Static/live findings contribute baseline severity pressure.")

    static_summary = static_analysis.get("summary") or {}
    live_summary = live_analysis.get("summary") or {}
    _add_factor(
        score_breakdown,
        "component-surface",
        min(18, int(static_summary.get("exported_total") or 0) * 2),
        f"{int(static_summary.get('exported_total') or 0)} exported components expand reachable entry points.",
    )
    _add_factor(
        score_breakdown,
        "deeplink-surface",
        min(12, int(static_summary.get("browsable_deeplink_total") or 0) * 3),
        f"{int(static_summary.get('browsable_deeplink_total') or 0)} browsable deep links increase external invocation paths.",
    )
    _add_factor(
        score_breakdown,
        "provider-surface",
        min(18, int(static_summary.get("provider_weak_permission_total") or 0) * 6),
        f"{int(static_summary.get('provider_weak_permission_total') or 0)} exported providers lack explicit read/write guards.",
    )
    _add_factor(
        score_breakdown,
        "permission-gaps",
        min(18, int(static_summary.get("component_permission_gap_total") or 0) * 6),
        f"{int(static_summary.get('component_permission_gap_total') or 0)} exported components expose intent or deep-link surface without permission enforcement.",
    )
    _add_factor(
        score_breakdown,
        "routing-overlaps",
        min(10, int(static_summary.get("intent_filter_overlap_total") or 0) * 3),
        f"{int(static_summary.get('intent_filter_overlap_total') or 0)} intent-filter overlaps may create ambiguous or unintended routing paths.",
    )
    _add_factor(
        score_breakdown,
        "live-validation",
        min(
            24,
            int(live_summary.get("provider_resolved_total") or 0) * 8
            + int(live_summary.get("deeplink_resolved_total") or 0) * 4
            + int(live_summary.get("component_resolved_total") or 0) * 4
            + int(live_summary.get("component_permission_gap_total") or 0) * 4,
        ),
        "On-device resolution confirms that at least part of the static surface is actually reachable.",
    )

    score = min(100, sum(int(item.get("points") or 0) for item in score_breakdown))
    if score >= 70:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "info"

    exploitability, exploitability_reasons = _exploitability(static_analysis, live_analysis, severity_counts)
    evidence_strength = _evidence_strength(live_analysis, severity_counts)
    attack_paths = _attack_paths(static_analysis, live_analysis)
    evidence_traces = _evidence_traces(findings, static_analysis, live_analysis)
    next_steps = _next_steps(static_analysis, live_analysis)
    return {
        "score": score,
        "level": level,
        "exploitability": exploitability,
        "exploitability_reasons": exploitability_reasons,
        "evidence_strength": evidence_strength,
        "severity_counts": severity_counts,
        "finding_count": len(findings),
        "top_findings": [
            {"id": finding.get("id"), "severity": finding.get("severity"), "title": finding.get("title")}
            for finding in top_findings
        ],
        "score_breakdown": score_breakdown,
        "attack_paths": attack_paths,
        "evidence_traces": evidence_traces,
        "next_steps": next_steps,
    }


def _add_factor(rows: list[dict[str, Any]], factor: str, points: int, reason: str) -> None:
    if points <= 0:
        return
    rows.append({"factor": factor, "points": points, "reason": reason})


def _finding_priority(finding: dict[str, Any]) -> tuple[int, int]:
    severity = str(finding.get("severity") or "info").lower()
    return (SEVERITY_WEIGHTS.get(severity, 1), len(finding.get("evidence") or []))


def _exploitability(
    static_analysis: dict[str, Any],
    live_analysis: dict[str, Any],
    severity_counts: dict[str, int],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    static_summary = static_analysis.get("summary") or {}
    live_summary = live_analysis.get("summary") or {}
    if int(live_summary.get("provider_resolved_total") or 0):
        reasons.append("Exported provider authorities resolved on-device")
    if int(live_summary.get("deeplink_resolved_total") or 0):
        reasons.append("Browsable deep links resolved on-device")
    if int(live_summary.get("component_resolved_total") or 0):
        reasons.append("Exported components resolved on-device")
    if int(static_summary.get("provider_weak_permission_total") or 0):
        reasons.append("Exported providers lack explicit permission guards")
    if int(static_summary.get("browsable_deeplink_total") or 0):
        reasons.append("Browsable deep links create user-triggerable entry points")
    if severity_counts.get("high", 0):
        reasons.append("High-severity evidence is present")

    if int(live_summary.get("provider_resolved_total") or 0) or severity_counts.get("high", 0):
        return "high", reasons[:5]
    if int(live_summary.get("deeplink_resolved_total") or 0) or int(static_summary.get("provider_weak_permission_total") or 0):
        return "medium", reasons[:5]
    if any(severity_counts.values()):
        return "low", reasons[:5]
    return "minimal", ["No high-signal exported or live-resolved surface was observed."]


def _evidence_strength(live_analysis: dict[str, Any], severity_counts: dict[str, int]) -> str:
    live_summary = live_analysis.get("summary") or {}
    if (int(live_summary.get("provider_resolved_total") or 0) + int(live_summary.get("deeplink_resolved_total") or 0) + int(live_summary.get("component_resolved_total") or 0)) >= 2:
        return "strong"
    if severity_counts.get("high", 0) or severity_counts.get("medium", 0):
        return "moderate"
    return "limited"


def _attack_paths(static_analysis: dict[str, Any], live_analysis: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for provider in (static_analysis.get("weak_providers") or [])[:3]:
        authorities = ", ".join(str(item) for item in provider.get("authorities") or [])
        paths.append(f"Exported provider {provider.get('name')} exposes authority {authorities or 'unknown'} without explicit read/write protection.")
    for deeplink in (static_analysis.get("browsable_deeplinks") or [])[:2]:
        paths.append(f"Browsable deep link {deeplink.get('uri')} can be externally invoked through {deeplink.get('component') or 'an exported activity'}.")
    for component in (live_analysis.get("components") or [])[:2]:
        if component.get("status") == "resolved":
            paths.append(f"Live probe resolved exported {component.get('type')} {component.get('component')} on-device.")
    return paths[:6]


def _evidence_traces(
    findings: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    live_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    traces: list[dict[str, str]] = []
    for finding in findings[:4]:
        traces.append({"source": "finding", "title": str(finding.get("title") or finding.get("id") or "finding")})
    for component in (static_analysis.get("weak_providers") or [])[:2]:
        traces.append({"source": "provider", "title": str(component.get("name") or "provider")})
    for item in (live_analysis.get("deeplinks") or [])[:2]:
        if item.get("status") == "resolved":
            traces.append({"source": "live-deeplink", "title": str(item.get("uri") or "uri")})
    return traces[:6]


def _next_steps(static_analysis: dict[str, Any], live_analysis: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    if static_analysis.get("weak_providers"):
        steps.append("Inspect exported providers for readable URI patterns, grants, and missing caller validation.")
    if static_analysis.get("browsable_deeplinks"):
        steps.append("Exercise browsable deep links and review auth/session assumptions around each route.")
    if any(item.get("status") == "resolved" for item in live_analysis.get("components") or []):
        steps.append("Pivot from resolved components into OWASP mapping and runtime validation for the confirmed entry points.")
    steps.append("Capture the scoped findings in reporting once the reachable surface is triaged.")
    return steps[:4]