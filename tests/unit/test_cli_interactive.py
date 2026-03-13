from click.testing import CliRunner

from lockknife_headless_cli import interactive as interactive_mod


def test_interactive_quits_immediately(monkeypatch) -> None:
    monkeypatch.setattr(interactive_mod.Prompt, "ask", lambda *args, **kwargs: "q")

    class _App:
        devices = object()

    runner = CliRunner()
    res = runner.invoke(interactive_mod.interactive, ["--serial", "SERIAL"], obj=_App())
    assert res.exit_code == 0, res.output
