from __future__ import annotations

import inspect
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast

import click

ActionFieldKind = Literal["text", "number", "bool", "choice", "path", "json"]
ActionHandler = Callable[[Any, str, dict[str, Any]], dict[str, Any] | None]
DEFAULT_HIDDEN_ACTION_IDS = frozenset(
    {"config.load", "config.save", "config.metrics", "export.result"}
)


class HandlerAdapter(Protocol):
    def __call__(
        self, app: Any, action: str, params: dict[str, Any], *, cb: Any
    ) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class ActionField:
    key: str
    label: str
    kind: ActionFieldKind
    required: bool = False
    default: object | None = None
    choices: tuple[str, ...] = ()
    cli_option: str | None = None


@dataclass(frozen=True)
class CapabilityMetadata:
    status: Literal[
        "implemented-live",
        "dependency-gated",
        "dry-run-only",
        "simulated",
        "poc-only",
        "not-implemented",
    ] = "implemented-live"
    requirements: str = ""
    notes: str = ""


@dataclass(frozen=True)
class CliBinding:
    command_path: tuple[str, ...]
    output_adapter: str | None = None


DEFAULT_CLI_BINDINGS: Mapping[str, CliBinding] = {
    "core.doctor": CliBinding(("doctor",), "health"),
    "core.features": CliBinding(("features",), "features"),
    "core.health": CliBinding(("health",), "health"),
    "device.connect": CliBinding(("device", "connect"), "message"),
    "device.info": CliBinding(("device", "info"), "device-info"),
    "device.list": CliBinding(("device", "list"), "device-list"),
    "plugins.list": CliBinding(("plugins", "list"), "plugins-list"),
}


@dataclass(frozen=True)
class ActionLog:
    level: str
    message: str


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    message: str | None = None
    data: object | None = None
    error: str | None = None
    logs: tuple[ActionLog, ...] = ()
    job: object | None = None

    def to_bridge_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": self.ok}
        if self.message is not None:
            payload["message"] = self.message
        if self.error is not None:
            payload["error"] = self.error
        if self.data is not None:
            payload["data_json"] = json.dumps(self.data, default=str)
        if self.job is not None:
            payload["job_json"] = json.dumps(self.job, default=str)
        if self.logs:
            payload["logs"] = [log.__dict__ for log in self.logs]
        return payload


@dataclass(frozen=True)
class ActionDefinition:
    id: str
    module_id: str
    module_label: str
    label: str
    fields: tuple[ActionField, ...] = ()
    requires_device: bool = False
    confirm: bool = False
    hidden: bool = False
    description: str | None = None
    help_lines: tuple[str, ...] = ()
    recovery_hint: str | None = None
    capability: CapabilityMetadata | None = None
    cli: CliBinding | None = None
    handler: ActionHandler | None = field(default=None, compare=False, repr=False)

    def catalog_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "module_id": self.module_id,
            "module_label": self.module_label,
            "label": self.label,
            "fields": [
                {
                    "key": field.key,
                    "label": field.label,
                    "kind": field.kind,
                    "required": field.required,
                    "default": field.default,
                    "choices": list(field.choices),
                    "cli_option": field.cli_option,
                }
                for field in self.fields
            ],
            "requires_device": self.requires_device,
            "confirm": self.confirm,
            "hidden": self.hidden,
            "description": self.description,
            "help_lines": list(self.help_lines),
            "recovery_hint": self.recovery_hint,
            "capability": self.capability.__dict__ if self.capability else None,
        }

    def cli_payload(self) -> dict[str, object]:
        payload = self.catalog_payload()
        payload["cli"] = (
            {
                "command_path": list(self.cli.command_path),
                "output_adapter": self.cli.output_adapter,
            }
            if self.cli
            else None
        )
        return payload


class ActionRegistry:
    def __init__(self) -> None:
        self._actions: dict[str, ActionDefinition] = {}

    def register(self, definition: ActionDefinition) -> None:
        self._register(definition, require_handler=True)

    def register_metadata(self, definition: ActionDefinition) -> None:
        self._register(definition, require_handler=False)

    def _register(self, definition: ActionDefinition, *, require_handler: bool) -> None:
        if definition.id in self._actions:
            raise ValueError(f"Duplicate action registration: {definition.id}")
        if require_handler and definition.handler is None:
            raise ValueError(f"Action {definition.id} has no handler")
        self._actions[definition.id] = definition

    def register_handler_group(
        self,
        handler: HandlerAdapter,
        *,
        module_label: str | None = None,
        cb: Any,
        hidden: Iterable[str] = (),
    ) -> None:
        hidden_ids = set(hidden)
        for action_id in _extract_handler_action_ids(handler):
            module_id, _, slug = action_id.partition(".")
            self.register(
                ActionDefinition(
                    id=action_id,
                    module_id=module_id,
                    module_label=module_label or module_id.replace("_", " ").title(),
                    label=slug.replace("_", " ").replace(".", " ").title() or action_id,
                    hidden=action_id in hidden_ids,
                    capability=_capability_for_action(action_id),
                    cli=_cli_binding_for_action(action_id),
                    handler=_adapter(handler, cb),
                )
            )

    def get(self, action_id: str) -> ActionDefinition | None:
        return self._actions.get(action_id)

    def actions(self) -> tuple[ActionDefinition, ...]:
        return tuple(self._actions.values())

    def cli_actions(self, *, include_hidden: bool = False) -> tuple[ActionDefinition, ...]:
        return tuple(
            action
            for action in self.actions()
            if action.cli is not None and (include_hidden or not action.hidden)
        )

    def get_by_cli_path(self, command_path: Iterable[str]) -> ActionDefinition | None:
        normalized = tuple(command_path)
        for action in self.actions():
            if action.cli is not None and action.cli.command_path == normalized:
                return action
        return None

    def dispatch(self, app: Any, action_id: str, params: Mapping[str, Any]) -> dict[str, Any]:
        definition = self.get(action_id)
        if definition is None or definition.handler is None:
            return ActionResult(ok=False, error=f"Unsupported action: {action_id}").to_bridge_dict()
        result = definition.handler(app, action_id, dict(params))
        if result is None:
            return ActionResult(ok=False, error=f"Unsupported action: {action_id}").to_bridge_dict()
        return result

    def catalog(self, *, include_hidden: bool = False) -> dict[str, object]:
        modules: dict[str, dict[str, object]] = {}
        for action in self.actions():
            if action.hidden and not include_hidden:
                continue
            module = modules.setdefault(
                action.module_id,
                {
                    "id": action.module_id,
                    "label": action.module_label,
                    "actions": [],
                },
            )
            cast(list[dict[str, object]], module["actions"]).append(action.catalog_payload())
        return {"modules": list(modules.values())}

    def catalog_json(self, *, include_hidden: bool = False) -> str:
        return json.dumps(self.catalog(include_hidden=include_hidden), sort_keys=True)

    def cli_catalog(self, *, include_hidden: bool = False) -> dict[str, object]:
        return {
            "actions": [
                action.cli_payload() for action in self.cli_actions(include_hidden=include_hidden)
            ]
        }

    def cli_catalog_json(self, *, include_hidden: bool = False) -> str:
        return json.dumps(self.cli_catalog(include_hidden=include_hidden), sort_keys=True)


def _extract_handler_action_ids(handler: HandlerAdapter) -> list[str]:
    source = inspect.getsource(handler)
    ids = re.findall(r'action\s*==\s*"([^"]+)"', source)
    return sorted(dict.fromkeys(ids))


def _adapter(handler: HandlerAdapter, cb: Any) -> ActionHandler:
    def call(app: Any, action: str, params: dict[str, Any]) -> dict[str, Any] | None:
        return handler(app, action, params, cb=cb)

    return call


def _capability_for_action(action_id: str) -> CapabilityMetadata | None:
    if not action_id.startswith("exploit."):
        return None
    status = "implemented-live"
    if any(part in action_id for part in (".zeroclick", ".chain.", ".run.")):
        status = "poc-only"
    if action_id.startswith("exploit.scan."):
        status = "dependency-gated"
    return CapabilityMetadata(
        status=status,
        requirements="Explicit case scope, target scope, lab mode, and operator confirmation.",
        notes="Exploit actions are policy-gated and audited before live execution.",
    )


def _cli_binding_for_action(action_id: str) -> CliBinding | None:
    return DEFAULT_CLI_BINDINGS.get(action_id)


def bind_click_commands(registry: ActionRegistry, root: click.Group) -> ActionRegistry:
    """Add metadata-only action definitions for every concrete Click command.

    These definitions are intentionally CLI-only. They make Click's public command
    surface visible in the shared action catalog without teaching the TUI to
    dispatch arbitrary Click callbacks.
    """
    existing_paths = {
        action.cli.command_path
        for action in registry.cli_actions(include_hidden=True)
        if action.cli is not None
    }
    for command_path, command in _iter_click_commands(root):
        if command_path in existing_paths:
            continue
        registry.register_metadata(
            ActionDefinition(
                id="cli." + ".".join(command_path),
                module_id=command_path[0],
                module_label=command_path[0].replace("-", " ").title(),
                label=(command.name or command_path[-1]).replace("-", " ").title(),
                fields=tuple(_field_from_click_param(param) for param in command.params),
                hidden=command.hidden,
                description=command.short_help or command.help,
                cli=CliBinding(command_path),
                handler=None,
            )
        )
        existing_paths.add(command_path)
    return registry


def _iter_click_commands(
    command: click.Command, prefix: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], click.Command]]:
    if isinstance(command, click.Group):
        for name, child in command.commands.items():
            yield from _iter_click_commands(child, (*prefix, name))
        return
    if prefix:
        yield prefix, command


def _field_from_click_param(param: click.Parameter) -> ActionField:
    choices: tuple[str, ...] = ()
    kind: ActionFieldKind = "text"
    if isinstance(param.type, click.Choice):
        kind = "choice"
        choices = tuple(str(choice) for choice in param.type.choices)
    elif isinstance(param.type, click.Path):
        kind = "path"
    elif isinstance(
        param.type,
        (
            click.types.IntParamType,
            click.types.FloatParamType,
            click.types.IntRange,
            click.types.FloatRange,
        ),
    ):
        kind = "number"
    if isinstance(param, click.Option) and param.is_bool_flag:
        kind = "bool"

    default = param.default
    if callable(default) or not isinstance(
        default, (str, int, float, bool, list, tuple, dict, type(None))
    ):
        default = None
    cli_option = None
    if isinstance(param, click.Option):
        cli_option = next((opt for opt in reversed(param.opts) if opt.startswith("--")), None)
        cli_option = cli_option or (param.opts[-1] if param.opts else None)

    return ActionField(
        key=param.name or "value",
        label=(param.name or "value").replace("_", " ").title(),
        kind=kind,
        required=bool(param.required),
        default=default,
        choices=choices,
        cli_option=cli_option,
    )


def build_default_registry(handlers: Iterable[HandlerAdapter], *, cb: Any) -> ActionRegistry:
    registry = ActionRegistry()
    for handler in handlers:
        registry.register_handler_group(handler, cb=cb, hidden=DEFAULT_HIDDEN_ACTION_IDS)
    return registry


def catalog_json(registry: ActionRegistry) -> str:
    return registry.catalog_json()


def cli_catalog_json(registry: ActionRegistry) -> str:
    return registry.cli_catalog_json()
