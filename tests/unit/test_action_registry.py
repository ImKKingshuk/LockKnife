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
