from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RuntimeCompatibilityContext:
    app_id: str
    device_id: str | None
    attach_mode: str
    session_kind: str | None = None
    application_available: bool | None = None
    running_pid: int | None = None
    device: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeCompatibilityRule:
    rule_id: str
    title: str
    severity: str
    condition: str
    message: str
    recovery_hint: str | None = None
    recommended_next: str | None = None
    attach_modes: tuple[str, ...] = ()
    session_kinds: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
