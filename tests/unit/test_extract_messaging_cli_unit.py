import dataclasses
import json
import pathlib
from types import SimpleNamespace

import click
from click.testing import CliRunner

from lockknife_headless_cli import _extract_messaging as messaging_cli


@dataclasses.dataclass
class _Row:
    value: str


@dataclasses.dataclass
class _Artifacts:
    app: str
    files: list[str]


def _build_cli(tmp_path: pathlib.Path):
    @click.group()
    def extract() -> None:
        return None

    captured: list[dict[str, object]] = []
    cli = SimpleNamespace(
        _resolve_case_output=lambda output, case_dir, filename: (
            (case_dir / filename) if output is None and case_dir is not None else output,
            output is None and case_dir is not None,
        ),
        _register_output=lambda **kwargs: captured.append(kwargs),
        console=SimpleNamespace(print=lambda *_a, **_k: None, print_json=lambda *_a, **_k: None),
        extract_whatsapp_messages=lambda *_a, **_k: [_Row("wa-msg")],
        extract_telegram_messages=lambda *_a, **_k: [_Row("tg-msg")],
        extract_signal_messages=lambda *_a, **_k: [_Row("sig-msg")],
        extract_whatsapp_artifacts=lambda *_a, **_k: _Artifacts(app="whatsapp", files=["wa.db"]),
        extract_telegram_artifacts=lambda *_a, **_k: _Artifacts(app="telegram", files=["tg.db"]),
        extract_signal_artifacts=lambda *_a, **_k: _Artifacts(app="signal", files=["sig.db"]),
    )
    messaging_cli.register(extract, cli)
    return extract, captured


def test_extract_messaging_routes_messages_and_artifacts(tmp_path: pathlib.Path) -> None:
    extract, captured = _build_cli(tmp_path)
    runner = CliRunner()
    app = SimpleNamespace(devices=SimpleNamespace())
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    for args in [
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "whatsapp",
            "--mode",
            "messages",
            "--format",
            "json",
            "--case-dir",
            str(case_dir),
        ],
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "telegram",
            "--mode",
            "messages",
            "--format",
            "csv",
            "--output",
            str(tmp_path / "tg.csv"),
        ],
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "signal",
            "--mode",
            "messages",
            "--format",
            "json",
            "--output",
            str(tmp_path / "sig.json"),
        ],
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "whatsapp",
            "--mode",
            "artifacts",
            "--format",
            "json",
            "--output",
            str(tmp_path / "wa-artifacts.json"),
        ],
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "telegram",
            "--mode",
            "artifacts",
            "--format",
            "json",
            "--output",
            str(tmp_path / "tg-artifacts.json"),
        ],
        [
            "messaging",
            "-s",
            "S",
            "--app",
            "signal",
            "--mode",
            "artifacts",
            "--format",
            "json",
            "--case-dir",
            str(case_dir),
        ],
    ]:
        result = runner.invoke(extract, args, obj=app)
        assert result.exit_code == 0, result.output

    assert (
        json.loads((case_dir / "messaging_whatsapp_messages.json").read_text(encoding="utf-8"))[0][
            "value"
        ]
        == "wa-msg"
    )
    assert json.loads((tmp_path / "sig.json").read_text(encoding="utf-8"))[0]["value"] == "sig-msg"
    assert (
        json.loads((tmp_path / "wa-artifacts.json").read_text(encoding="utf-8"))["app"]
        == "whatsapp"
    )
    assert json.loads((case_dir / "messaging_signal_artifacts.json").read_text(encoding="utf-8"))[
        "files"
    ] == ["sig.db"]
    assert len(captured) >= 4


def test_extract_messaging_rejects_csv_for_artifacts(tmp_path: pathlib.Path) -> None:
    extract, _captured = _build_cli(tmp_path)
    runner = CliRunner()
    app = SimpleNamespace(devices=SimpleNamespace())

    result = runner.invoke(
        extract,
        ["messaging", "-s", "S", "--app", "telegram", "--mode", "artifacts", "--format", "csv"],
        obj=app,
    )
    assert result.exit_code != 0
    assert "not supported" in result.output.lower()
