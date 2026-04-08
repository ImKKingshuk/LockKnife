import click
from click.testing import CliRunner


class _Console:
    def print(self, message) -> None:
        click.echo(message)

    def print_json(self, message: str) -> None:
        click.echo(message)


def test_health_command_text_output(monkeypatch) -> None:
    from lockknife_headless_cli import health as health_cli

    monkeypatch.setattr(health_cli, "console", _Console())
    monkeypatch.setattr(
        health_cli, "health_status", lambda: {"ok": True, "checks": {"adb": {"ok": True}}}
    )

    result = CliRunner().invoke(health_cli.health_cmd, [])
    assert result.exit_code == 0
    assert "Overall: OK" in result.output
    assert "adb: OK" in result.output


def test_doctor_command_json_output(monkeypatch) -> None:
    from lockknife_headless_cli import health as health_cli

    monkeypatch.setattr(health_cli, "console", _Console())
    monkeypatch.setattr(
        health_cli,
        "doctor_status",
        lambda: {
            "ok": True,
            "full_ok": False,
            "checks": {"adb": {"ok": True}},
            "optional": {"vt": {"ok": False}},
        },
    )

    result = CliRunner().invoke(health_cli.doctor_cmd, ["--format", "json"])
    assert result.exit_code == 0
    assert '"full_ok": false' in result.output.lower()


def test_lockknife_command_normalizes_lockknife_errors() -> None:
    from lockknife.core.cli_instrumentation import LockKnifeCommand
    from lockknife.core.exceptions import LockKnifeError

    @click.command(cls=LockKnifeCommand)
    def boom() -> None:
        raise LockKnifeError("plain failure")

    result = CliRunner().invoke(boom, [])
    assert result.exit_code != 0
    assert "plain failure" in result.output


def test_lockknife_command_hides_unexpected_tracebacks() -> None:
    from lockknife.core.cli_instrumentation import LockKnifeCommand

    @click.command(cls=LockKnifeCommand)
    def boom() -> None:
        raise RuntimeError("surprise")

    result = CliRunner().invoke(boom, [])
    assert result.exit_code != 0
    assert "Unexpected error while running boom" in result.output
