from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import click

from lockknife.core.plugin_models import PluginCapability, PluginMetadata

LOCKKNIFE_PLUGIN_API_VERSION = "1"
LOCKKNIFE_PLUGIN_ENTRY_POINT_GROUP = "lockknife.plugins"

PluginHealthCheck = Callable[[], bool | dict[str, Any]]


class PluginRegistrationContext:
    def __init__(self, metadata: PluginMetadata, source: str) -> None:
        self.metadata = metadata
        self.source = source
        self._commands: list[click.Command] = []
        self._capabilities: list[PluginCapability] = list(metadata.capabilities)
        self._health_checks: dict[str, PluginHealthCheck] = {}

    def register_command(self, command: click.Command) -> click.Command:
        self._commands.append(command)
        return command

    def register_capability(self, capability: PluginCapability) -> PluginCapability:
        self._capabilities.append(capability)
        return capability

    def register_health_check(self, name: str, callback: PluginHealthCheck) -> None:
        self._health_checks[name] = callback

    @property
    def commands(self) -> tuple[click.Command, ...]:
        return tuple(self._commands)

    @property
    def capabilities(self) -> tuple[PluginCapability, ...]:
        return tuple(self._capabilities)

    @property
    def health_checks(self) -> dict[str, PluginHealthCheck]:
        return dict(self._health_checks)


class LockKnifePluginProtocol(Protocol):
    metadata: PluginMetadata

    def register(self, registry: PluginRegistrationContext) -> None: ...


class LockKnifePlugin:
    metadata: PluginMetadata

    def register(self, registry: PluginRegistrationContext) -> None:
        raise NotImplementedError
