import json
import pathlib
import sqlite3

import pytest

from click.testing import CliRunner

from lockknife.core.case import (
    complete_case_job,
    create_case_workspace,
    fail_case_job,
    load_case_manifest,
    start_case_job,
)
from lockknife_headless_cli.case import case_group


def _parse_cli_json(output: str) -> dict:
    clean_lines = [
        line
        for line in output.splitlines()
        if not ("cli_start" in line or "cli_done" in line or "[info" in line or "[debug" in line)
    ]
    clean_text = "\n".join(clean_lines).strip()
    return json.loads(clean_text)


def test_case_jobs_and_job_cli_commands(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case_jobs_test"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-JOB-1", examiner="Analyst", title="Job Test"
    )

    # Start and complete a job
    j1 = start_case_job(
        case_dir,
        action_id="forensics.sqlite",
        action_label="SQLite Analysis",
        params={"path": "test.db"},
    )
    complete_case_job(case_dir, job_id=j1.job_id, message="Extracted 42 records")

    # Start and fail a job
    j2 = start_case_job(
        case_dir,
        action_id="forensics.snapshot",
        action_label="Device Snapshot",
        params={"serial": "DEV123", "full": False},
        device_serial="DEV123",
    )
    fail_case_job(
        case_dir,
        job_id=j2.job_id,
        error_message="Device connection lost during pull",
        recovery_hint="Check ADB connection and retry",
    )

    runner = CliRunner()

    # 1. Test case jobs (text format)
    res = runner.invoke(case_group, ["jobs", "--case-dir", str(case_dir)])
    assert res.exit_code == 0, res.output
    assert "Case Jobs: CASE-JOB-1" in res.output
    assert "Jobs: 2 of 2" in res.output
    assert j1.job_id in res.output
    assert j2.job_id in res.output
    assert "[resumable]" in res.output
    assert "Device connection lost" in res.output

    # 2. Test case jobs with status filter
    res_filtered = runner.invoke(
        case_group, ["jobs", "--case-dir", str(case_dir), "--status", "failed"]
    )
    assert res_filtered.exit_code == 0
    assert j2.job_id in res_filtered.output
    assert j1.job_id not in res_filtered.output

    # 3. Test case jobs (json format)
    res_json = runner.invoke(case_group, ["jobs", "--case-dir", str(case_dir), "--format", "json"])
    assert res_json.exit_code == 0
    payload = _parse_cli_json(res_json.output)
    assert payload["total_job_count"] == 2
    assert len(payload["jobs"]) == 2

    # 4. Test case job details (text format)
    res_detail = runner.invoke(
        case_group, ["job", "--case-dir", str(case_dir), "--job-id", j2.job_id]
    )
    assert res_detail.exit_code == 0, res_detail.output
    assert f"Job: {j2.job_id}" in res_detail.output
    assert "Device: DEV123" in res_detail.output
    assert "Recovery Hint: Check ADB connection and retry" in res_detail.output
    assert "Parameters:" in res_detail.output
    assert "Steps:" in res_detail.output

    # 5. Test case job details (json format)
    res_detail_json = runner.invoke(
        case_group,
        ["job", "--case-dir", str(case_dir), "--job-id", j1.job_id, "--format", "json"],
    )
    assert res_detail_json.exit_code == 0
    job_payload = _parse_cli_json(res_detail_json.output)["job"]
    assert job_payload["job_id"] == j1.job_id
    assert job_payload["status"] == "succeeded"


def test_case_resume_and_retry_cli_dry_run(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case_resume_test"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-JOB-2", examiner="Analyst", title="Resume Test"
    )

    # Job that succeeded (can be retried, but not resumed)
    j1 = start_case_job(
        case_dir,
        action_id="forensics.sqlite",
        action_label="SQLite Analysis",
        params={"path": "evidence.db"},
    )
    complete_case_job(case_dir, job_id=j1.job_id, message="Done")

    # Job that failed (can be resumed or retried)
    j2 = start_case_job(
        case_dir,
        action_id="forensics.snapshot",
        action_label="Device Snapshot",
        params={"serial": "DEV456"},
    )
    fail_case_job(case_dir, job_id=j2.job_id, error_message="Timeout")

    runner = CliRunner()

    # Dry-run resume
    res_resume = runner.invoke(
        case_group,
        ["resume", "--case-dir", str(case_dir), "--job-id", j2.job_id, "--dry-run"],
    )
    assert res_resume.exit_code == 0, res_resume.output
    assert f"Resume Plan for Job: {j2.job_id}" in res_resume.output
    assert "forensics.snapshot" in res_resume.output
    assert "serial: DEV456" in res_resume.output

    # Resume on succeeded job should fail with clean message
    res_resume_invalid = runner.invoke(
        case_group,
        ["resume", "--case-dir", str(case_dir), "--job-id", j1.job_id, "--dry-run"],
    )
    assert res_resume_invalid.exit_code != 0
    assert "not resumable" in res_resume_invalid.output

    # Dry-run retry
    res_retry = runner.invoke(
        case_group,
        ["retry", "--case-dir", str(case_dir), "--job-id", j1.job_id, "--dry-run"],
    )
    assert res_retry.exit_code == 0, res_retry.output
    assert f"Retry Plan for Job: {j1.job_id}" in res_retry.output
    assert "Attempt Count: 2" in res_retry.output


@pytest.mark.parametrize("mode", ["resume", "retry"])
@pytest.mark.parametrize("out_format", ["text", "json"])
def test_case_job_live_dispatch(tmp_path, mode, out_format):
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="LIVE", examiner="Analyst", title="Live")
    source = tmp_path / "evidence.db"
    with sqlite3.connect(source) as con:
        con.execute("CREATE TABLE evidence (value TEXT)")
        con.execute("INSERT INTO evidence VALUES ('sample')")
    job = start_case_job(
        case_dir, action_id="forensics.sqlite", action_label="SQLite", params={"path": str(source)}
    )
    fail_case_job(case_dir, job_id=job.job_id, error_message="Interrupted")
    result = CliRunner().invoke(
        case_group,
        [mode, "--case-dir", str(case_dir), "--job-id", job.job_id, "--format", out_format],
    )
    assert result.exit_code == 0, result.output
    if out_format == "json":
        assert _parse_cli_json(result.output)["ok"] is True
    updated = load_case_manifest(case_dir).jobs[0]
    assert updated.status == "succeeded"
    assert updated.attempt_count == 2


def test_case_job_dispatch_failure_has_nonzero_status(tmp_path):
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="FAIL", examiner="Analyst", title="Failure")
    job = start_case_job(
        case_dir,
        action_id="forensics.sqlite",
        action_label="SQLite",
        params={"path": str(tmp_path / "missing.db")},
    )
    fail_case_job(case_dir, job_id=job.job_id, error_message="Interrupted")
    result = CliRunner().invoke(
        case_group,
        ["retry", "--case-dir", str(case_dir), "--job-id", job.job_id, "--format", "json"],
    )
    assert result.exit_code == 1
    assert _parse_cli_json(result.output)["ok"] is False
