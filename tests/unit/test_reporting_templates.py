import pathlib

from lockknife.modules.reporting.html_report import render_html_report


def test_render_bundled_templates() -> None:
    base = pathlib.Path(__file__).resolve().parents[2] / "lockknife" / "templates"
    context = {
        "case_id": "CASE1",
        "case_title": "Case Title",
        "examiner": "Examiner",
        "generated_at": "now",
        "highlights": ["h1"],
        "artifacts": [{"id": "x", "severity": "high", "title": "t", "details": {"k": "v"}}],
        "case_summary": {
            "total_artifact_count": 1,
            "artifact_count": 1,
            "jobs": {"total": 0},
            "runtime_sessions": {"total": 0},
            "artifacts_by_category": {"extract-sms": 1},
        },
        "integrity": {
            "summary": {
                "verified_count": 1,
                "modified_count": 0,
                "missing_count": 0,
                "unreadable_count": 0,
                "unsupported_count": 0,
            },
            "advisory": "ok",
        },
        "evidence_inventory": [
            {
                "artifact_id": "artifact-0001",
                "category": "extract-sms",
                "status": "verified",
                "path": "evidence/sms.json",
            }
        ],
        "evidence_summary": {
            "artifact_count": 1,
            "artifact_payload_rows": 1,
            "top_categories": [{"name": "extract-sms", "count": 1}],
        },
        "report_sections": [
            {
                "title": "PDF readiness",
                "summary": "PDF backend unavailable; HTML fallback may be required.",
                "status": "medium",
                "details": ["wkhtmltopdf missing"],
            }
        ],
        "report_preview": {"pdf_backend_status": {"preferred": None}},
        "report_metrics": {"artifact_row_count": 1, "evidence_item_count": 1},
        "operator_guidance": ["review integrity"],
    }
    for name in ["executive_report.html", "technical_report.html"]:
        html = render_html_report(base / name, context)
        assert "CASE1" in html
        assert "PDF readiness" in html
        assert "review integrity" in html
        assert "artifact row count" in html.lower() or "Artifact preview" in html


def test_render_chain_of_custody_template() -> None:
    base = pathlib.Path(__file__).resolve().parents[2] / "lockknife" / "templates"
    html = render_html_report(
        base / "chain_of_custody.html",
        {
            "report_title": "Chain of Custody",
            "case_id": "CASE1",
            "examiner": "Examiner",
            "generated_at": "now",
            "entry_count": 1,
            "chain_head_sha256": "a" * 64,
            "verification": {"status": "verified"},
            "entries": [
                {
                    "name": "sms",
                    "path": "/tmp/sms.json",
                    "sha256": "b" * 64,
                    "previous_hash": "0" * 64,
                    "entry_hash": "c" * 64,
                }
            ],
        },
    )
    assert "Chain head SHA256" in html
    assert "sms" in html
