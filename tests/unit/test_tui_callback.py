import dataclasses
import json
import pathlib

import pytest

from lockknife.core.device import DeviceHandle, DeviceInfo, DeviceState
from lockknife_headless_cli.tui_callback import build_tui_callback


@dataclasses.dataclass
class DummyRow:
    value: str


@dataclasses.dataclass
class DummyAnalysis:
    tables: list[str]


@dataclasses.dataclass
class DummySnapshot:
    output: str


@dataclasses.dataclass
class DummyStatus:
    status: str


@dataclasses.dataclass
class DummyBoot:
    ok: bool


@dataclasses.dataclass
class DummyHardware:
    ok: bool


@dataclasses.dataclass
class DummyAudit:
    rule: str


@dataclasses.dataclass
class DummyVuln:
    score: float


@dataclasses.dataclass
class DummyAnalysisReport:
    package: str
    manifest: dict[str, object]
    findings: list[DummyRow]
    permission_risk: dict[str, object]
    risk_summary: dict[str, object]
    mastg: dict[str, object]


@dataclasses.dataclass
class DummyIoc:
    ioc: str
    kind: str
    location: str


@dataclasses.dataclass
class DummyScan:
    dns: list[str]
    dns_cache: list[str]
    listening: list[DummyRow]


class DummyScript:
    def __init__(self) -> None:
        self.handlers: dict[str, object] = {}

    def on(self, _event: str, _handler) -> None:
        self.handlers[_event] = _handler

    def emit(self, event: str, message, data=None) -> None:
        handler = self.handlers.get(event)
        if callable(handler):
            handler(message, data)

    def unload(self) -> None:
        return None


class DummySession:
    def __init__(self) -> None:
        self.handlers: dict[str, object] = {}

    def on(self, event: str, handler) -> None:
        self.handlers[event] = handler

    def emit_detached(self, reason: str = "transport-lost", crash=None) -> None:
        handler = self.handlers.get("detached")
        if callable(handler):
            handler(reason, crash)

    def detach(self) -> None:
        return None


class DummyFridaManager:
    def __init__(self, device_id: str | None = None) -> None:
        self.device_id = device_id

    def spawn_and_attach(self, _app_id: str):
        return 4242, DummySession()

    def attach_running(self, _app_id: str):
        return 4343, DummySession()

    def load_script(self, _session, _script: str):
        return DummyScript()

    def describe_device(self) -> dict[str, str]:
        return {"id": self.device_id or "usb", "name": "Demo", "type": "usb"}

    def application_available(self, _app_id: str) -> bool:
        return True

    def running_pid(self, _app_id: str) -> int:
        return 4343


class DummyPredictor:
    def generate(
        self, *, count: int, min_len: int, max_len: int, seed: int | None, personal_data=None
    ):
        _ = (min_len, max_len, seed, personal_data)
        return [f"pwd{i}" for i in range(count)]


class DummyDevices:
    def list_handles(self):
        return [
            DeviceHandle(
                serial="SERIAL",
                adb_state="device",
                state=DeviceState.authorized,
                model="Model",
                device="device",
                transport_id="1",
            )
        ]

    def info(self, serial: str):
        return DeviceInfo(serial=serial, props={"brand": "demo"})

    def connect(self, host: str):
        return f"connected {host}"

    def has_root(self, _serial: str) -> bool:
        return True


class DummyApp:
    def __init__(self) -> None:
        self.devices = DummyDevices()
        self.selected_device_serial = "SERIAL"


def test_tui_callback_export_json(tmp_path: pathlib.Path) -> None:
    callback = build_tui_callback(DummyApp())
    out = tmp_path / "export.json"
    payload = {"format": "json", "output": str(out), "data_json": json.dumps({"ok": True})}
    result = callback("export.result", payload)
    assert result["ok"] is True
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8")) == {"ok": True}


def test_tui_callback_apk_permissions_includes_manifest_and_risk_summary(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb

    @dataclasses.dataclass
    class _Risk:
        permission: str
        score: int

    @dataclasses.dataclass
    class _Finding:
        id: str
        severity: str
        title: str
        details: dict[str, object]

    callback = build_tui_callback(DummyApp())
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    monkeypatch.setattr(
        cb,
        "parse_apk_manifest",
        lambda _path: {
            "package": "com.example",
            "version_name": "1.0",
            "version_code": "7",
            "permissions": ["android.permission.READ_SMS"],
            "component_summary": {"exported_total": 2},
            "signing": {"has_debug_or_test_certificate": True},
            "string_analysis": {"stats": {"secret_indicator_count": 1}},
        },
    )
    monkeypatch.setattr(
        cb, "score_permissions", lambda _perms: (9, [_Risk(permission="READ_SMS", score=9)])
    )
    monkeypatch.setattr(
        cb,
        "findings_from_manifest",
        lambda _info: [
            _Finding(
                id="debuggable",
                severity="high",
                title="App is debuggable",
                details={"debuggable": True},
            )
        ],
    )
    monkeypatch.setattr(
        cb,
        "build_apk_risk_summary",
        lambda *_args: {"score": 88, "level": "high", "exploitability": "high"},
    )

    result = callback("apk.permissions", {"path": str(apk)})
    payload = json.loads(result["data_json"])

    assert result["ok"] is True
    assert payload["manifest"]["package"] == "com.example"
    assert payload["permission_risk"]["score"] == 9
    assert payload["risk_summary"]["score"] == 88
    assert payload["findings"][0]["id"] == "debuggable"
