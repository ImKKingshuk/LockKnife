from __future__ import annotations

import pathlib
from click.testing import CliRunner
from lockknife_headless_cli.main import cli


def test_cli_agent_goal_mock_text(tmp_path: pathlib.Path):
    case_dir = tmp_path / "agent_case_text"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--cli",
            "agent",
            "goal",
            "Triage connected Android target",
            "--case-dir",
            str(case_dir),
            "--mock",
            "--budget",
            "5",
        ],
    )
    assert result.exit_code == 0
    assert "LockKnife Autonomous Agent Kernel" in result.output
    assert "COMPLETED" in result.output
    assert "Mission Outcome" in result.output


def test_cli_agent_goal_mock_json(tmp_path: pathlib.Path):
    case_dir = tmp_path / "agent_case_json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--cli",
            "agent",
            "goal",
            "Scan APK manifest for exposed exported components",
            "--case-dir",
            str(case_dir),
            "--mock",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert '"status": "completed"' in result.output
    assert '"turns_count": 2' in result.output


def test_cli_agent_daemon_once():
    runner = CliRunner()
    result = runner.invoke(cli, ["--cli", "agent", "daemon", "--once"])
    assert result.exit_code == 0
    assert '"ok": true' in result.output


def test_cli_agent_memory_cmd(tmp_path: pathlib.Path):
    case_dir = tmp_path / "agent_case_mem"
    runner = CliRunner()
    # First run a goal to generate memory
    runner.invoke(
        cli,
        ["--cli", "agent", "goal", "Inspect device", "--case-dir", str(case_dir), "--mock"],
    )

    mem_res = runner.invoke(cli, ["--cli", "agent", "memory", "--case-dir", str(case_dir)])
    assert mem_res.exit_code == 0
    assert "Agent Memory State" in mem_res.output
    assert "Episodic Turns Recorded: 2" in mem_res.output
