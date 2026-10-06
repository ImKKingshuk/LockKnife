from __future__ import annotations

import pathlib

from click.testing import CliRunner

from lockknife_headless_cli.main import cli


def test_cli_pipeline_list() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--cli", "pipeline", "list"])
    assert result.exit_code == 0
    assert "triage" in result.output
    assert "deep-forensics" in result.output
    assert "crypto-audit" in result.output


def test_cli_pipeline_list_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--cli", "pipeline", "list", "--format", "json"])
    assert result.exit_code == 0
    assert '"name": "triage"' in result.output


def test_cli_pipeline_plan() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--cli", "pipeline", "plan", "--playbook", "triage"])
    assert result.exit_code == 0
    assert "Rapid Security & Device Triage" in result.output
    assert "Execution Tier 0" in result.output


def test_cli_pipeline_run_dry_run_and_status(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "test-case-cli"
    runner = CliRunner()

    run_res = runner.invoke(
        cli,
        ["--cli", "pipeline", "run", "--playbook", "triage", "--case-dir", str(case_dir), "--dry-run"],
    )
    assert run_res.exit_code == 0
    assert "Pipeline Summary: COMPLETED" in run_res.output

    status_res = runner.invoke(cli, ["--cli", "pipeline", "status", "--case-dir", str(case_dir)])
    assert status_res.exit_code == 0
    assert "triage" in status_res.output
    assert "COMPLETED" in status_res.output


def test_cli_pipeline_resume(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "test-case-resume"
    runner = CliRunner()

    runner.invoke(
        cli,
        ["--cli", "pipeline", "run", "--playbook", "triage", "--case-dir", str(case_dir), "--dry-run"],
    )
    resume_res = runner.invoke(cli, ["--cli", "pipeline", "resume", "--case-dir", str(case_dir)])
    assert resume_res.exit_code == 0
    assert "Resumed Pipeline Finished: COMPLETED" in resume_res.output
