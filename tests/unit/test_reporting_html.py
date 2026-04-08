import pathlib

from lockknife.core.case import create_case_workspace, register_case_artifact
from lockknife.modules.reporting.context import build_report_context
from lockknife.modules.reporting.html_report import (
    _artifact_preview_rows,
    render_html_report,
    write_html_report,
)


def test_render_html_report(tmp_path: pathlib.Path) -> None:
    tpl = tmp_path / "t.html"
    tpl.write_text("<h1>{{ case_id }}</h1>", encoding="utf-8")
    html = render_html_report(tpl, {"case_id": "X"})
    assert "<h1>X</h1>" in html


def test_render_builtin_report_templates(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-HTML", examiner="Examiner", title="Phase 2 Report"
    )
    evidence = case_dir / "evidence" / "sample.json"
    evidence.write_text('{"package": "com.example.app", "score": 9}', encoding="utf-8")
    register_case_artifact(
        case_dir=case_dir, path=evidence, category="apk-analyze", source_command="apk analyze"
    )

    context = build_report_context(
        case_id=None, artifacts=[{"name": "apk", "count": 1}], case_dir=case_dir
    )
    template_root = pathlib.Path(__file__).resolve().parents[2] / "lockknife" / "templates"

    executive = render_html_report(template_root / "executive.html", context)
    technical = render_html_report(template_root / "technical.html", context)

    assert "CASE-HTML" in executive
    assert "Phase 2 Report" in executive
    assert "report payload includes 1 top-level artifact row" in executive.lower()
    assert "operator guidance" in technical.lower()
    assert "template_readiness" in technical


def test_write_html_report_alias_resolution_and_preview_rows(tmp_path: pathlib.Path) -> None:
    alias_dir = tmp_path / "templates"
    alias_dir.mkdir()
    (alias_dir / "executive_report.html").write_text(
        "<p>{{ artifact_preview_rows[0].value }}</p>", encoding="utf-8"
    )

    output = tmp_path / "out.html"
    write_html_report(alias_dir / "executive.html", {"artifacts": "scalar-preview"}, output)

    assert output.read_text(encoding="utf-8") == "<p>scalar-preview</p>"
    assert _artifact_preview_rows({"x": 1}) == [{"x": 1}]
