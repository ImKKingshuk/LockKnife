from __future__ import annotations

import pathlib
import time
from typing import Any

from lockknife.core.case import (
    case_evidence_inventory,
    case_integrity_report,
    load_case_manifest,
    summarize_case_manifest,
)
from lockknife.modules.reporting._context_sections import build_highlights, build_report_sections
from lockknife.modules.reporting._evidence_summaries import summarize_evidence_inventory
from lockknife.modules.reporting.pdf_report import pdf_backend_status
from lockknife.modules.security.owasp import mastg_summary


def _top_level_row_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 0


def build_report_context(
    *,
    case_id: str | None,
    artifacts: Any,
    case_dir: pathlib.Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or time.strftime("%Y-%m-%d %H:%M:%S %z")
    manifest = load_case_manifest(case_dir) if case_dir else None
    resolved_case_id = case_id or (manifest.case_id if manifest else "CASE")
    case_summary = summarize_case_manifest(case_dir) if case_dir else None
    evidence_inventory = case_evidence_inventory(case_dir) if case_dir else []
    integrity = case_integrity_report(case_dir) if case_dir else None
    mastg = mastg_summary(artifacts)
    evidence_summary = summarize_evidence_inventory(evidence_inventory, artifacts)
    pdf_status = pdf_backend_status()

    highlights = build_highlights(
        case_summary=case_summary,
        integrity=integrity,
        evidence_summary=evidence_summary,
        mastg=mastg,
    )
    row_count = _top_level_row_count(artifacts)
    if row_count > 0 and all("top-level artifact row" not in item for item in highlights):
        highlights.append(
            f"Report payload includes {row_count} top-level artifact row(s) for review."
        )

    return {
        "case_id": resolved_case_id,
        "case_title": manifest.title if manifest else None,
        "examiner": manifest.examiner if manifest else None,
        "generated_at": generated,
        "case_dir": str(case_dir) if case_dir else None,
        "highlights": highlights,
        "artifacts": artifacts,
        "mastg": mastg,
        "case_summary": case_summary,
        "evidence_inventory": evidence_inventory,
        "evidence_summary": evidence_summary,
        "integrity": integrity,
        "custody_preview": {
            "artifact_count": len(evidence_inventory),
            "examiner": manifest.examiner if manifest else None,
            "case_manifest_backed": bool(manifest),
        },
        "report_sections": build_report_sections(
            evidence_summary=evidence_summary,
            mastg=mastg,
            pdf_backend_status=pdf_status,
            integrity=integrity,
        ),
        "report_preview": {
            "pdf_backend_status": pdf_status,
            "template_readiness": "complete" if evidence_inventory else "partial",
            "notes": [
                "Report preview is derived from current case inventory and may lag manual file edits until artifacts are re-registered.",
                "Review integrity and chain-of-custody sections before exporting final evidentiary packages.",
            ],
        },
        "report_metrics": {
            "artifact_row_count": row_count,
            "evidence_item_count": len(evidence_inventory),
            "mastg_reference_count": len(mastg.get("mastg_ids") or []),
            "integrity_verified_count": int(
                ((integrity or {}).get("summary") or {}).get("verified_count") or 0
            ),
        },
        "operator_guidance": [
            "Treat generated reports as summaries over preserved case artifacts, not replacements for original evidence.",
            "Review integrity and chain-of-custody sections before sharing downstream or exporting bundles externally.",
            "Use the feature matrix and dependency doctor to verify maturity and environment readiness for optional workflows.",
        ],
    }
