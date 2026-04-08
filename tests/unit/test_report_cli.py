import json
import pathlib

from click.testing import CliRunner

from lockknife.core.case import create_case_workspace, load_case_manifest, register_case_artifact
from lockknife_headless_cli.report import report


def _seed_case(tmp_path: pathlib.Path) -> pathlib.Path:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-200", examiner="Examiner", title="Reporting"
    )
    evidence_path = case_dir / "evidence" / "sms.json"
    evidence_path.write_text("[]", encoding="utf-8")
    register_case_artifact(
        case_dir=case_dir,
        path=evidence_path,
        category="extract-sms",
        source_command="extract sms",
        device_serial="SER-1",
    )
    return case_dir


def test_report_generate_uses_case_defaults_and_registers_output(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    case_dir = _seed_case(tmp_path)

    result = runner.invoke(report, ["generate", "--case-dir", str(case_dir), "--format", "json"])

    assert result.exit_code == 0, result.output
    output_path = case_dir / "reports" / "technical_CASE-200.json"
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["case_id"] == "CASE-200"
    assert payload["integrity"]["summary"]["verified_count"] == 1
    assert payload["evidence_inventory"][0]["artifact_id"] == "artifact-0001"

    manifest = load_case_manifest(case_dir)
    assert manifest.artifacts[-1].category == "report-json"


def test_report_chain_of_custody_and_integrity_use_case_defaults(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    case_dir = _seed_case(tmp_path)

    custody = runner.invoke(report, ["chain-of-custody", "--case-dir", str(case_dir)])
    integrity = runner.invoke(
        report, ["integrity", "--case-dir", str(case_dir), "--format", "text"]
    )

    assert custody.exit_code == 0, custody.output
    assert integrity.exit_code == 0, integrity.output

    custody_path = case_dir / "reports" / "chain_of_custody_CASE-200.txt"
    integrity_path = case_dir / "reports" / "integrity_CASE-200.txt"
    assert custody_path.exists()
    assert integrity_path.exists()
    assert "Integrity status: verified" in custody_path.read_text(encoding="utf-8")
    assert "Case integrity report: CASE-200" in integrity_path.read_text(encoding="utf-8")
    assert "Custody chain:" in integrity_path.read_text(encoding="utf-8")

    manifest = load_case_manifest(case_dir)
    categories = [artifact.category for artifact in manifest.artifacts]
    assert "chain-of-custody" in categories
    assert "report-integrity" in categories


def test_report_chain_of_custody_supports_html_output(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    case_dir = _seed_case(tmp_path)

    result = runner.invoke(
        report, ["chain-of-custody", "--case-dir", str(case_dir), "--format", "html"]
    )

    assert result.exit_code == 0, result.output
    custody_path = case_dir / "reports" / "chain_of_custody_CASE-200.html"
    assert custody_path.exists()
    text = custody_path.read_text(encoding="utf-8")
    assert "Chain head SHA256" in text
    assert "Entry hash" in text
