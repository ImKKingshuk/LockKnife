from __future__ import annotations

import importlib
import os
import re
import signal
from importlib.metadata import entry_points
from types import ModuleType
from typing import Any, cast

import click

from lockknife import __version__
from lockknife.core.logging import get_logger
from lockknife.core.plugin_contract import (
    LOCKKNIFE_PLUGIN_API_VERSION,
    LOCKKNIFE_PLUGIN_ENTRY_POINT_GROUP,
    LockKnifePlugin,
    PluginRegistrationContext,
)
from lockknife.core.plugin_models import LoadedPlugin, PluginFailure, PluginMetadata

PLUGIN_MODULES_ENV = "LOCKKNIFE_PLUGIN_MODULES"
PLUGIN_DISABLE_ENV = "LOCKKNIFE_DISABLE_PLUGINS"
_PLUGIN_MANAGER: PluginManager | None = None
log = get_logger()

# Sandbox configuration
_SANDBOX_BLOCKED_MODULES = {
    "os",
    "subprocess",
    "sys",
    "socket",
    "multiprocessing",
    "threading",
    "ctypes",
    "ctypes.util",
}
_SANDBOX_ALLOWED_MODULES = {
    "logging",
    "typing",
    "dataclasses",
    "collections",
    "pathlib",
    "re",
    "json",
    "datetime",
    "decimal",
    "fractions",
    "numbers",
    "enum",
    "itertools",
    "functools",
    "contextlib",
    "copy",
    "hashlib",
    "random",
    "uuid",
}


class TimeoutError(RuntimeError):
    """Raised when plugin execution times out."""

    pass


def _timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for timeout."""
    raise TimeoutError("Plugin execution timed out")


def with_timeout(timeout_s: float):
    """Decorator to add timeout to a function using signal.alarm()."""

    def decorator(func):
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            def set_timeout():
                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(int(timeout_s))

            def clear_timeout():
                signal.alarm(0)

            set_timeout()
            try:
                return func(*args, **kwargs)
            finally:
                clear_timeout()

        return wrapper

    return decorator


def _sandbox_import(
    name: str, globals: Any = None, locals: Any = None, fromlist: Any = None, level: int = 0
) -> Any:
    """Restricted __import__ wrapper that blocks dangerous modules."""
    base_module = name.split(".")[0]

    if base_module in _SANDBOX_BLOCKED_MODULES:
        log.warning(
            "plugin_sandbox_import_blocked",
            module=name,
            reason="Module is in blocked list for security",
        )
        raise ImportError(f"Import of '{name}' is not allowed in plugin sandbox")

    # Check if the module is explicitly allowed
    if base_module not in _SANDBOX_ALLOWED_MODULES:
        log.warning(
            "plugin_sandbox_import_unsafe",
            module=name,
            reason="Module is not in explicit allow list",
        )

    # Use the original __import__
    return __builtins__.__import__(name, globals, locals, fromlist, level)


def _apply_sandbox() -> None:
    """Apply sandbox restrictions to the current import system."""
    __builtins__.__import__ = _sandbox_import


def _remove_sandbox() -> None:
    """Remove sandbox restrictions from the import system."""
    __builtins__.__import__ = __builtins__.__dict__.get(
        "__original_import__", __builtins__.__import__
    )


class PluginLoadError(RuntimeError):
    pass


def _parse_version(version: str) -> tuple[int, ...]:
    numbers = [int(piece) for piece in re.findall(r"[0-9]+", version)]
    return tuple(numbers or [0])


def _compare_versions(left: str, right: str) -> int:
    lhs = _parse_version(left)
    rhs = _parse_version(right)
    width = max(len(lhs), len(rhs))
    lhs += (0,) * (width - len(lhs))
    rhs += (0,) * (width - len(rhs))
    return (lhs > rhs) - (lhs < rhs)


def _satisfies_version(version: str, requirement: str | None) -> bool:
    if requirement is None or not requirement.strip():
        return True
    for raw_clause in requirement.split(","):
        clause = raw_clause.strip()
        if not clause:
            continue
        op = "=="
        target = clause
        for candidate in (">=", "<=", "==", ">", "<"):
            if clause.startswith(candidate):
                op = candidate
                target = clause[len(candidate) :].strip()
                break
        cmp = _compare_versions(version, target)
        if op == "==" and cmp != 0:
            return False
        if op == ">=" and cmp < 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == "<" and cmp >= 0:
            return False
    return True


def _entry_point_records() -> list[tuple[str, Any]]:
    discovered = entry_points()
    if hasattr(discovered, "select"):
        items = list(discovered.select(group=LOCKKNIFE_PLUGIN_ENTRY_POINT_GROUP))
    elif isinstance(discovered, dict):
        items = list(discovered.get(LOCKKNIFE_PLUGIN_ENTRY_POINT_GROUP, ()))
    else:
        items = list(discovered)
    return [(f"entry-point:{item.name}", item) for item in items]


def _env_module_records() -> list[tuple[str, str]]:
    raw = os.environ.get(PLUGIN_MODULES_ENV, "")
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return [(f"module:{item}", item) for item in values]


def _load_module_spec(spec: str) -> Any:
    if ":" in spec:
        module_name, attr_name = spec.split(":", 1)
        module = importlib.import_module(module_name)
        return getattr(module, attr_name)
    module = importlib.import_module(spec)
    if hasattr(module, "get_plugin"):
        return module.get_plugin
    if hasattr(module, "PLUGIN"):
        return module.PLUGIN
    return module


def _coerce_plugin(value: Any) -> LockKnifePlugin:
    if isinstance(value, ModuleType):
        if hasattr(value, "get_plugin"):
            return _coerce_plugin(value.get_plugin)
        if hasattr(value, "PLUGIN"):
            return _coerce_plugin(value.PLUGIN)
        raise PluginLoadError("module does not expose get_plugin() or PLUGIN")
    if isinstance(value, LockKnifePlugin):
        return value
    if isinstance(value, type) and issubclass(value, LockKnifePlugin):
        return value()
    if callable(value) and not isinstance(value, click.Command):
        return _coerce_plugin(value())
    if hasattr(value, "metadata") and hasattr(value, "register"):
        return cast(LockKnifePlugin, value)
    raise PluginLoadError(f"unsupported plugin object: {type(value).__name__}")


class PluginManager:
    def __init__(self) -> None:
        self.loaded: list[LoadedPlugin] = []
        self.failures: list[PluginFailure] = []
        self._commands: dict[str, click.Command] = {}
        self._health_checks: dict[str, dict[str, Any]] = {}
        self._attached_groups: set[int] = set()
        self._discover()

    def _discover(self) -> None:
        disabled = os.environ.get(PLUGIN_DISABLE_ENV, "").strip().lower()
        if disabled in {"1", "true", "yes", "on"}:
            return
        seen_sources: set[str] = set()
        for source, record in [*_entry_point_records(), *_env_module_records()]:
            if source in seen_sources:
                continue
            seen_sources.add(source)
            try:
                # Apply sandbox before loading plugin
                _apply_sandbox()

                @with_timeout(30.0)  # 30 second timeout for plugin loading
                def load_plugin(rec=record) -> LockKnifePlugin:
                    loader = getattr(rec, "load", None)
                    loaded = loader() if callable(loader) else _load_module_spec(rec)
                    return _coerce_plugin(loaded)

                plugin = load_plugin()
                self._register_plugin(plugin, source)
            except TimeoutError:
                self.failures.append(
                    PluginFailure(source=source, error="Plugin loading timed out (30s)")
                )
            except ImportError as exc:
                self.failures.append(
                    PluginFailure(source=source, error=f"Import blocked by sandbox: {exc}")
                )
            except Exception as exc:
                self.failures.append(PluginFailure(source=source, error=str(exc)))
            finally:
                # Remove sandbox after loading
                _remove_sandbox()

    def _register_plugin(self, plugin: LockKnifePlugin, source: str) -> None:
        metadata = plugin.metadata
        if not isinstance(metadata, PluginMetadata):
            raise PluginLoadError("plugin metadata must be a PluginMetadata instance")
        if metadata.api_version != LOCKKNIFE_PLUGIN_API_VERSION:
            raise PluginLoadError(
                f"plugin API mismatch: expected {LOCKKNIFE_PLUGIN_API_VERSION}, got {metadata.api_version}"
            )
        if not _satisfies_version(__version__, metadata.requires_lockknife):
            raise PluginLoadError(
                f"plugin requires lockknife {metadata.requires_lockknife}, current version is {__version__}"
            )
        if any(item.metadata.name == metadata.name for item in self.loaded):
            raise PluginLoadError(f"duplicate plugin name: {metadata.name}")

        registry = PluginRegistrationContext(metadata=metadata, source=source)

        @with_timeout(60.0)  # 60 second timeout for plugin registration
        def register_plugin() -> None:
            plugin.register(registry)

        register_plugin()

        commands = registry.commands
        for command in commands:
            if not command.name:
                raise PluginLoadError(f"plugin command from {metadata.name} is missing a name")
            if command.name in self._commands:
                raise PluginLoadError(f"duplicate plugin command name: {command.name}")

        for command in commands:
            if command.name is None:
                continue
            self._commands[command.name] = command
        self._health_checks[metadata.name] = registry.health_checks
        self.loaded.append(
            LoadedPlugin(
                metadata=metadata,
                source=source,
                commands=tuple(command.name or "" for command in commands),
                health_checks=tuple(registry.health_checks.keys()),
                capabilities=registry.capabilities,
            )
        )

    def attach_group(self, group: click.Group) -> None:
        group_id = id(group)
        if group_id in self._attached_groups:
            return
        for name, command in self._commands.items():
            existing = group.commands.get(name)
            if existing is not None and existing is not command:
                self.failures.append(
                    PluginFailure(
                        source=f"command:{name}",
                        error=f"cannot attach plugin command because '{name}' already exists",
                    )
                )
                continue
            if existing is None:
                group.add_command(command)
        self._attached_groups.add(group_id)

    def inventory(self) -> dict[str, object]:
        return {
            "api_version": LOCKKNIFE_PLUGIN_API_VERSION,
            "entry_point_group": LOCKKNIFE_PLUGIN_ENTRY_POINT_GROUP,
            "module_env_var": PLUGIN_MODULES_ENV,
            "loaded": [item.to_dict() for item in self.loaded],
            "failures": [item.to_dict() for item in self.failures],
        }

    def health_summary(self) -> dict[str, object]:
        plugin_checks: dict[str, object] = {}
        ok = not self.failures
        for plugin in self.loaded:
            callbacks = self._health_checks.get(plugin.metadata.name, {})
            for name, callback in callbacks.items():
                key = f"{plugin.metadata.name}:{name}"
                try:

                    @with_timeout(30.0)  # 30 second timeout for health checks
                    def run_health_check(cb=callback) -> Any:
                        return cb()

                    payload = run_health_check()
                    if isinstance(payload, bool):
                        payload = {"ok": payload}
                    elif not isinstance(payload, dict):
                        payload = {"ok": True, "value": payload}
                except TimeoutError:
                    payload = {"ok": False, "error": "Health check timed out (30s)"}
                except Exception as exc:
                    payload = {"ok": False, "error": str(exc)}
                plugin_checks[key] = payload
                ok = bool(ok and payload.get("ok"))
        summary: dict[str, object] = {
            "ok": ok,
            "loaded": len(self.loaded),
            "failed": len(self.failures),
            "commands": sorted(self._commands.keys()),
            "plugin_checks": plugin_checks,
        }
        if self.failures:
            summary["hint"] = (
                "Inspect `lockknife --cli plugins list --format json` for discovery or compatibility errors."
            )
            summary["failures"] = [item.to_dict() for item in self.failures]
        return summary


def reset_plugin_manager() -> None:
    global _PLUGIN_MANAGER
    _PLUGIN_MANAGER = None


def get_plugin_manager(*, reload: bool = False) -> PluginManager:
    global _PLUGIN_MANAGER
    if reload or _PLUGIN_MANAGER is None:
        _PLUGIN_MANAGER = PluginManager()
    return _PLUGIN_MANAGER


def attach_plugin_commands(group: click.Group) -> None:
    get_plugin_manager().attach_group(group)


def plugin_inventory(*, reload: bool = False) -> dict[str, object]:
    return get_plugin_manager(reload=reload).inventory()


def plugin_health_summary(*, reload: bool = False) -> dict[str, object]:
    return get_plugin_manager(reload=reload).health_summary()
