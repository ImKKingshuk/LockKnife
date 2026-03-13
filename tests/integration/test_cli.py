import subprocess

from click.testing import CliRunner

from lockknife_headless_cli.main import cli


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "--cli" in result.output
    assert "--headless" in result.output
    assert "device" in result.output
    assert "crack" in result.output
    assert "extract" in result.output
    assert "apk" in result.output
    assert "analyze" in result.output
    assert "forensics" in result.output
    assert "runtime" in result.output
    assert "report" in result.output
    assert "security" in result.output
    assert "intel" in result.output
    assert "ai" in result.output
    assert "network" in result.output
    assert "crypto-wallet" in result.output
    assert "interactive" in result.output
    assert "health" in result.output
    assert "doctor" in result.output
    assert "features" in result.output
    assert "case" in result.output


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_crack_help_lists_new_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["crack", "--help"])
    assert result.exit_code == 0
    assert "gesture" in result.output
    assert "pin-device" in result.output
    assert "wifi" in result.output
    assert "keystore" in result.output
    assert "password-rules" in result.output


def test_extract_help_lists_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["extract", "--help"])
    assert result.exit_code == 0
    assert "sms" in result.output
    assert "contacts" in result.output
    assert "call-logs" in result.output
    assert "browser" in result.output
    assert "messaging" in result.output
    assert "media" in result.output
    assert "location" in result.output
    assert "all" in result.output


def test_device_list_table(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="List of devices attached\nserial123\tdevice\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = CliRunner()
    result = runner.invoke(cli, ["device", "list"])
    assert result.exit_code == 0
    assert "serial123" in result.output
