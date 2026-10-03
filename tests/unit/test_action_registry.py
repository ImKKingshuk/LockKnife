from __future__ import annotations

import json

import click
import pytest
from click.testing import CliRunner

from lockknife_headless_cli.actions import (
    ActionDefinition,
    ActionRegistry,
    bind_click_commands,
    build_default_registry,
)
from lockknife_headless_cli.actions.metadata import load_action_metadata
from lockknife_headless_cli.tui_callback import _HANDLERS, build_action_registry, build_tui_callback


class _Cb:
    pass


class _Console:
    def print(self, message: object) -> None:
        click.echo(str(message))

    def print_json(self, message: str) -> None:
        click.echo(message)


def _handler(_app, action, _params, *, cb):
    _ = cb
    if action == "demo.hidden":
        return {"ok": True}
    if action == "demo.visible":
        return {"ok": True}
    return None


def test_action_registry_rejects_duplicate_ids() -> None:
    registry = ActionRegistry()
    definition = ActionDefinition(
        id="demo.visible",
        module_id="demo",
        module_label="Demo",
        label="Visible",
        handler=lambda *_a: {"ok": True},
    )
    registry.register(definition)
    with pytest.raises(ValueError, match="Duplicate action"):
        registry.register(definition)


def test_action_registry_dispatch_and_hidden_catalog() -> None:
    registry = ActionRegistry()
    registry.register_handler_group(_handler, cb=_Cb(), hidden={"demo.hidden"})

    assert registry.dispatch(object(), "demo.visible", {})["ok"] is True
    assert registry.dispatch(object(), "demo.hidden", {})["ok"] is True
    unsupported = registry.dispatch(object(), "missing.action", {})
    assert unsupported["ok"] is False
    assert unsupported["error"] == "Unsupported action: missing.action"
    public_ids = {
        action["id"] for module in registry.catalog()["modules"] for action in module["actions"]
    }
    all_ids = {
        action["id"]
        for module in registry.catalog(include_hidden=True)["modules"]
        for action in module["actions"]
    }
    assert "demo.visible" in public_ids
    assert "demo.hidden" not in public_ids
    assert "demo.hidden" in all_ids


def test_default_tui_action_registry_has_unique_actions() -> None:
    registry = build_default_registry(_HANDLERS, cb=_Cb())
    ids = [action.id for action in registry.actions()]
    assert len(ids) == len(set(ids))
    assert "device.list" in ids
    assert "credentials.pin" in ids
    assert "config.load" in ids


def test_cli_metadata_helpers_resolve_shared_actions() -> None:
    registry = build_action_registry()

    device_list = registry.get_by_cli_path(("device", "list"))
    assert device_list is not None
    assert device_list.id == "device.list"
    assert device_list.cli is not None
    assert device_list.cli.output_adapter == "device-list"

    cli_ids = {action.id for action in registry.cli_actions()}
    assert {"core.health", "core.doctor", "core.features", "device.list"} <= cli_ids
    assert "config.load" not in cli_ids


def test_tui_callback_catalog_comes_from_same_registry() -> None:
    callback = build_tui_callback(object())
    registry = build_action_registry()

    assert json.loads(callback.action_catalog_json) == registry.catalog()


def test_actions_click_command_uses_shared_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    from lockknife_headless_cli import main

    monkeypatch.setattr(main, "console", _Console())

    text_result = CliRunner().invoke(main.actions_cmd, ["--cli-only"])
    assert text_result.exit_code == 0, text_result.output
    assert "device.list -> device list" in text_result.output

    json_result = CliRunner().invoke(main.actions_cmd, ["--format", "json", "--cli-only"])
    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.output)
    ids = {action["id"] for action in payload["actions"]}
    assert "device.list" in ids
    assert "config.load" not in ids


def test_click_catalog_covers_every_public_leaf_command() -> None:
    from lockknife_headless_cli import main

    registry = bind_click_commands(build_action_registry(), main.cli)
    catalog_paths = {
        tuple(action["cli"]["command_path"])
        for action in registry.cli_catalog()["actions"]
        if action.get("cli")
    }
    command_paths: set[tuple[str, ...]] = set()

    def collect(command: click.Command, prefix: tuple[str, ...] = ()) -> None:
        if isinstance(command, click.Group):
            for name, child in command.commands.items():
                if not child.hidden:
                    collect(child, (*prefix, name))
            return
        if prefix:
            command_paths.add(prefix)

    collect(main.cli)

    assert command_paths
    assert command_paths <= catalog_paths
    assert ("actions",) in catalog_paths


def test_hidden_actions_are_only_exported_when_requested() -> None:
    registry = build_action_registry()

    public_ids = {
        action["id"] for module in registry.catalog()["modules"] for action in module["actions"]
    }
    hidden_ids = {
        action["id"]
        for module in registry.catalog(include_hidden=True)["modules"]
        for action in module["actions"]
    }

    assert "config.load" not in public_ids
    assert "config.load" in hidden_ids


def test_every_public_cli_command_has_working_help() -> None:
    from lockknife_headless_cli import main

    runner = CliRunner()
    pending: list[tuple[click.Command, tuple[str, ...]]] = [(main.cli, ())]
    checked = 0
    while pending:
        command, path = pending.pop()
        result = runner.invoke(command, ["--help"])
        assert result.exit_code == 0, (path, result.output, result.exception)
        assert "Usage:" in result.output, path
        checked += 1
        if isinstance(command, click.Group):
            pending.extend(
                (child, (*path, name))
                for name, child in command.commands.items()
                if not child.hidden
            )
    assert checked > 1


def test_public_actions_have_complete_shared_form_metadata() -> None:
    registry = build_action_registry()
    metadata = load_action_metadata()
    public = {action.id: action for action in registry.actions() if not action.hidden}
    assert public.keys() == metadata.keys()
    assert len(public) == 120
    for action_id, action in public.items():
        spec = metadata[action_id]
        assert action.module_id == spec["module_id"]
        assert action.confirm == spec["confirm"]
        assert action.requires_device == spec["requires_device"]
        assert [field.key for field in action.fields] == [field["key"] for field in spec["fields"]]
    assert public["extraction.sms"].requires_device
    assert public["exploit.run.wifi"].confirm
    assert {field.key for field in public["extraction.sms"].fields} >= {"output", "case_dir"}


def _grouped_handler(_app, action, _params, *, cb):
    # A comment mentioning action == "demo.not_an_action" is not a registration.
    if action in ("demo.first", "demo.second"):
        return {"ok": True}
    return None


def test_action_discovery_parses_grouped_branches_and_ignores_comments() -> None:
    registry = ActionRegistry()
    registry.register_handler_group(_grouped_handler, cb=_Cb())
    assert {action.id for action in registry.actions()} == {"demo.first", "demo.second"}
