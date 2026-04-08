import dataclasses
import json
import pathlib
from types import SimpleNamespace

import click
from click.testing import CliRunner

from lockknife_headless_cli import _extract_browser as browser_cli


@dataclasses.dataclass
class _Row:
    value: str


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
        extract_chrome_history=lambda *_a, **_k: [_Row("history")],
        extract_chrome_bookmarks=lambda *_a, **_k: [_Row("bookmarks")],
        extract_chrome_downloads=lambda *_a, **_k: [_Row("downloads")],
        extract_chrome_cookies=lambda *_a, **_k: [_Row("cookies")],
        extract_chrome_saved_logins=lambda *_a, **_k: [_Row("passwords")],
        extract_firefox_history=lambda *_a, **_k: [_Row("ff-history")],
        extract_firefox_bookmarks=lambda *_a, **_k: [_Row("ff-bookmarks")],
        extract_firefox_saved_logins=lambda *_a, **_k: [_Row("ff-passwords")],
    )
    browser_cli.register(extract, cli)
    return extract, cli, captured


def test_extract_browser_all_and_single_kind_routes(tmp_path: pathlib.Path) -> None:
    extract, _cli, captured = _build_cli(tmp_path)
    runner = CliRunner()
    app = SimpleNamespace(devices=SimpleNamespace())

    case_dir = tmp_path / "case"
    case_dir.mkdir()

    for args in [
        [
            "browser",
            "-s",
            "S",
            "--app",
            "firefox",
            "--kind",
            "all",
            "--format",
            "json",
            "--case-dir",
            str(case_dir),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "edge",
            "--kind",
            "bookmarks",
            "--format",
            "csv",
            "--output",
            str(tmp_path / "bookmarks.csv"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "edge",
            "--kind",
            "downloads",
            "--format",
            "csv",
            "--output",
            str(tmp_path / "downloads.csv"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "edge",
            "--kind",
            "cookies",
            "--format",
            "json",
            "--output",
            str(tmp_path / "cookies.json"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "edge",
            "--kind",
            "passwords",
            "--format",
            "csv",
            "--output",
            str(tmp_path / "passwords.csv"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "firefox",
            "--kind",
            "history",
            "--format",
            "json",
            "--case-dir",
            str(case_dir),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "firefox",
            "--kind",
            "bookmarks",
            "--format",
            "csv",
            "--output",
            str(tmp_path / "ff-bookmarks.csv"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "firefox",
            "--kind",
            "passwords",
            "--format",
            "json",
            "--output",
            str(tmp_path / "ff-passwords.json"),
        ],
        [
            "browser",
            "-s",
            "S",
            "--app",
            "firefox",
            "--kind",
            "downloads",
            "--format",
            "json",
            "--output",
            str(tmp_path / "ff-downloads.json"),
        ],
    ]:
        result = runner.invoke(extract, args, obj=app)
        assert result.exit_code == 0, result.output

    payload = json.loads((case_dir / "browser_firefox.json").read_text(encoding="utf-8"))
    assert payload["app"] == "firefox"
    assert (
        json.loads((tmp_path / "cookies.json").read_text(encoding="utf-8"))[0]["value"] == "cookies"
    )
    assert (
        json.loads((tmp_path / "ff-passwords.json").read_text(encoding="utf-8"))[0]["value"]
        == "ff-passwords"
    )
    assert json.loads((tmp_path / "ff-downloads.json").read_text(encoding="utf-8")) == []
    assert len(captured) >= 5


def test_extract_browser_rejects_csv_for_all(tmp_path: pathlib.Path) -> None:
    extract, _cli, _captured = _build_cli(tmp_path)
    runner = CliRunner()
    app = SimpleNamespace(devices=SimpleNamespace())

    result = runner.invoke(
        extract,
        ["browser", "-s", "S", "--app", "chrome", "--kind", "all", "--format", "csv"],
        obj=app,
    )
    assert result.exit_code != 0
    assert "not supported" in result.output.lower()
