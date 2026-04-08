import click
from click.testing import CliRunner
from rich.console import Console


class _Console:
    def __init__(self) -> None:
        self.buffer: list[str] = []

    def print(self, message) -> None:
        if isinstance(message, str):
            self.buffer.append(message)
            click.echo(message)
            return
        console = Console(record=True, force_terminal=False, width=140)
        console.print(message)
        rendered = console.export_text()
        self.buffer.append(rendered)
        click.echo(rendered)

    def print_json(self, message: str) -> None:
        self.buffer.append(message)
        click.echo(message)


def test_features_command_json(monkeypatch) -> None:
    from lockknife_headless_cli import features as features_cli

    fake_console = _Console()
    monkeypatch.setattr(features_cli, "console", fake_console)
    result = CliRunner().invoke(
        features_cli.features_cmd, ["--format", "json", "--status", "dependency-gated"]
    )
    assert result.exit_code == 0
    assert '"rows"' in result.output
    assert '"status": "dependency-gated"' in result.output


def test_features_command_table(monkeypatch) -> None:
    from lockknife_headless_cli import features as features_cli

    fake_console = _Console()
    monkeypatch.setattr(features_cli, "console", fake_console)
    result = CliRunner().invoke(features_cli.features_cmd, ["--category", "apk"])
    assert result.exit_code == 0
    rendered = "\n".join(fake_console.buffer)
    assert "LockKnife Feature Matrix" in rendered
    assert fake_console.buffer
