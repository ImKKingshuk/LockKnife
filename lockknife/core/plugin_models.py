from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class PluginCapability:
    category: str
    capability: str
    cli: str
    status: str
    requirements: str
    notes: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class PluginMetadata:
    name: str
    version: str
    api_version: str
    description: str = ""
    homepage: str | None = None
    author: str | None = None
    requires_lockknife: str | None = None
    capabilities: tuple[PluginCapability, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["capabilities"] = [cap.to_dict() for cap in self.capabilities]
        return payload


@dataclass(frozen=True)
class LoadedPlugin:
    metadata: PluginMetadata
    source: str
    commands: tuple[str, ...]
    health_checks: tuple[str, ...]
    capabilities: tuple[PluginCapability, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "loaded",
            "metadata": self.metadata.to_dict(),
            "source": self.source,
            "commands": list(self.commands),
            "health_checks": list(self.health_checks),
            "capabilities": [cap.to_dict() for cap in self.capabilities],
        }


@dataclass(frozen=True)
class PluginFailure:
    source: str
    error: str
    plugin_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": "failed",
            "source": self.source,
            "error": self.error,
        }
        if self.plugin_name:
            payload["plugin_name"] = self.plugin_name
        return payload
