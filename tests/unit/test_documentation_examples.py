from __future__ import annotations

import pathlib
import shlex
from unittest.mock import Mock
from urllib.parse import unquote, urlsplit

import click
import pytest
from markdown_it import MarkdownIt

from lockknife.core.cli_types import ReadableFileType
from lockknife_headless_cli.main import cli

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCUMENTS = (ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")))


def _command_examples() -> list[tuple[pathlib.Path, list[str]]]:
    examples = []
    for path in DOCUMENTS:
        for token in MarkdownIt().parse(path.read_text()):
            if token.type != "fence" or token.info.strip() not in {"bash", "sh", "shell"}:
                continue
            for line in token.content.replace("\\\n", " ").splitlines():
                argv = shlex.split(line, comments=True)
                if argv and argv[0] == "lockknife":
                    examples.append((path, argv[1:]))
    return examples


EXAMPLES = _command_examples()


@pytest.mark.parametrize("path,argv", EXAMPLES, ids=[" ".join(a) for _, a in EXAMPLES])
def test_documented_commands_parse_without_execution(path, argv, monkeypatch):
    # Example evidence paths are placeholders; all other argument validation remains active.
    monkeypatch.setattr(
        click.Path, "convert", lambda self, value, param, ctx: self.coerce_path_result(value)
    )
    monkeypatch.setattr(
        ReadableFileType, "convert", lambda self, value, param, ctx: pathlib.Path(value)
    )
    callbacks = []
    command = cli
    name = "lockknife"
    parent = None
    remaining = list(argv)
    try:
        while True:
            if command.callback is not None:
                callback = Mock(
                    side_effect=AssertionError("Documentation must not execute actions")
                )
                monkeypatch.setattr(command, "callback", callback)
                callbacks.append(callback)
            try:
                context = command.make_context(name, remaining, parent=parent)
            except click.exceptions.Exit as exc:
                assert exc.exit_code == 0, path
                break
            if not isinstance(command, click.Group):
                break
            remaining = [*context._protected_args, *context.args]
            if not remaining:
                break
            name, child, remaining = command.resolve_command(context, remaining)
            assert child is not None, path
            command = child
            parent = context
    except click.ClickException as exc:
        pytest.fail(f"{path.name}: {' '.join(argv)}: {exc.format_message()}")
    for callback in callbacks:
        callback.assert_not_called()


def test_documentation_has_examples():
    assert len(EXAMPLES) >= 50


@pytest.mark.parametrize("path", (*DOCUMENTS, ROOT / "SECURITY.md"), ids=lambda p: p.name)
def test_user_guides_exclude_maintainer_instructions(path):
    text = path.read_text().lower()
    for phrase in (
        "build from source",
        "git clone",
        "pre-commit install",
        "contributing.md",
        "release validation",
        "pre-release-checks.yml",
        "pull request instructions",
    ):
        assert phrase not in text, f"{path.name}: {phrase}"


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_documentation_local_links_resolve(path):
    for token in MarkdownIt().parse(path.read_text()):
        for child in token.children or ():
            target = child.attrGet("href") or child.attrGet("src")
            if not target:
                continue
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            assert (path.parent / unquote(parsed.path)).exists(), f"{path.name}: {target}"
