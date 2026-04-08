from __future__ import annotations

import dataclasses
from typing import Any


class FridaError(RuntimeError):
    pass


def _require_frida() -> Any:
    try:
        import frida
    except ImportError as e:
        raise FridaError("frida is required (install extras: lockknife[frida])") from e
    return frida


@dataclasses.dataclass(frozen=True)
class FridaSessionHandle:
    pid: int
    app_id: str


class FridaManager:
    def __init__(self, device_id: str | None = None) -> None:
        self._device_id = device_id
        self._frida = _require_frida()

    @property
    def device_id(self) -> str | None:
        return self._device_id

    def _device(self) -> Any:
        if self._device_id:
            return self._frida.get_device(self._device_id)
        return self._frida.get_usb_device(timeout=5)

    def _lookup_errors(self) -> tuple[type[BaseException], ...]:
        candidates = [AttributeError, LookupError, OSError, RuntimeError, TypeError, ValueError]
        for name in (
            "TransportError",
            "TimedOutError",
            "ServerNotRunningError",
            "ProcessNotFoundError",
            "InvalidOperationError",
            "InvalidArgumentError",
            "PermissionDeniedError",
            "NotSupportedError",
        ):
            candidate = getattr(self._frida, name, None)
            if isinstance(candidate, type) and issubclass(candidate, BaseException):
                candidates.append(candidate)
        return tuple(candidates)

    def describe_device(self) -> dict[str, Any]:
        device = self._device()
        return {
            "id": getattr(device, "id", self._device_id),
            "name": getattr(device, "name", None),
            "type": getattr(device, "type", None),
        }

    def application_available(self, app_id: str) -> bool:
        device = self._device()
        enumerate_applications = getattr(device, "enumerate_applications", None)
        if not callable(enumerate_applications):
            return False
        try:
            return any(
                getattr(app, "identifier", None) == app_id for app in enumerate_applications()
            )
        except self._lookup_errors():
            return False

    def running_pid(self, app_id: str) -> int | None:
        device = self._device()
        try:
            return int(device.get_process(app_id).pid)
        except self._lookup_errors():
            return None

    def spawn_and_attach(self, app_id: str) -> tuple[FridaSessionHandle, Any]:
        device = self._device()
        pid = device.spawn([app_id])
        session = device.attach(pid)
        device.resume(pid)
        return FridaSessionHandle(pid=int(pid), app_id=app_id), session

    def attach_running(self, app_id: str) -> tuple[FridaSessionHandle, Any]:
        device = self._device()
        pid = device.get_process(app_id).pid
        session = device.attach(pid)
        return FridaSessionHandle(pid=int(pid), app_id=app_id), session

    def load_script(self, session: Any, source: str) -> Any:
        script = session.create_script(source)
        script.load()
        return script
