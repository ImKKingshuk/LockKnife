from __future__ import annotations

from typing import Any


def build_highlights(
    *,
    case_summary: dict[str, Any] | None,
    integrity: dict[str, Any] | None,
    evidence_summary: dict[str, Any],
    mastg: dict[str, Any],
) -> list[str]:
    highlights: list[str] = []
    if case_summary:
        highlights.append(
            f"Case workspace tracks {case_summary['total_artifact_count']} artifact(s) across {len(case_summary['artifacts_by_category'])} category buckets."
        )
    if integrity:
        summary = integrity["summary"]
        highlights.append(
            f"Integrity verification: {summary['verified_count']} verified · {summary['modified_count']} modified · {summary['missing_count']} missing."
        )
    if evidence_summary.get("artifact_count"):
        highlights.append(
            f"Evidence inventory contributes {evidence_summary['artifact_count']} item(s) with {len(evidence_summary.get('top_categories') or [])} visible category buckets."
        )
    if mastg.get("mastg_ids"):
        highlights.append(
            f"OWASP MASTG alignment present for {len(mastg.get('mastg_ids', []))} reference(s)."
        )
    if not highlights:
        highlights.append("Automated extraction and analysis completed.")
    return highlights[:5]


def build_report_sections(
    *,
    evidence_summary: dict[str, Any],
    mastg: dict[str, Any],
    pdf_backend_status: dict[str, Any],
    integrity: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    sections = [
        {
            "title": "Evidence posture",
            "summary": f"{evidence_summary.get('artifact_count', 0)} evidence item(s) summarized for reporting.",
            "status": "low" if evidence_summary.get("artifact_count") else "medium",
            "details": [
                f"Top categories: {', '.join(str(item.get('name')) for item in (evidence_summary.get('top_categories') or [])[:3]) or 'n/a'}",
            ],
        },
        {
            "title": "OWASP / MASTG",
            "summary": f"{len(mastg.get('mastg_ids') or [])} MASTG IDs and {len(mastg.get('owasp_categories') or [])} OWASP Mobile categories mapped.",
            "status": "low" if mastg.get("mastg_ids") else "medium",
            "details": [
                f"OWASP categories: {', '.join(mastg.get('owasp_categories') or []) or 'n/a'}"
            ],
        },
        {
            "title": "PDF readiness",
            "summary": "PDF backend ready."
            if pdf_backend_status.get("available")
            else "PDF backend unavailable; HTML fallback may be required.",
            "status": "low" if pdf_backend_status.get("available") else "medium",
            "details": [str(pdf_backend_status.get("message") or "")],
        },
    ]
    if integrity:
        summary = integrity.get("summary") or {}
        sections.append(
            {
                "title": "Integrity",
                "summary": f"Verified {summary.get('verified_count', 0)} / {summary.get('artifact_count', 0)} tracked artifact(s).",
                "status": "critical"
                if summary.get("modified_count", 0) or summary.get("missing_count", 0)
                else "low",
                "details": [
                    f"Modified: {summary.get('modified_count', 0)}",
                    f"Missing: {summary.get('missing_count', 0)}",
                ],
            }
        )
    return sections
