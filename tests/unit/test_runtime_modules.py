import json
import types


def test_hooks_scripts() -> None:
    from lockknife.modules.runtime.hooks import (
        get_builtin_runtime_script,
        list_builtin_runtime_scripts,
        root_bypass_script,
        ssl_pinning_bypass_script,
        suggest_builtin_runtime_scripts,
    )

    assert "ssl_bypass" in ssl_pinning_bypass_script()
    assert "root_bypass" in root_bypass_script()
    assert {item["name"] for item in list_builtin_runtime_scripts()} >= {
        "ssl_bypass",
        "root_bypass",
        "debug_bypass",
        "crypto_intercept",
    }
    assert get_builtin_runtime_script("ssl-bypass")["name"] == "ssl_bypass"
    assert suggest_builtin_runtime_scripts("com.secure.bank.app")


def test_method_tracer_script() -> None:
    from lockknife.modules.runtime.tracer import method_tracer_script

    out = method_tracer_script("com.example.Class", "m")
    assert "com.example.Class" in out
    assert "m" in out


def test_memory_search_and_heap_dump(monkeypatch) -> None:
    from lockknife.modules.runtime import memory as mem_mod

    class _Script:
        def on(self, _event: str, handler):
            handler(
                {
                    "type": "send",
                    "payload": json.dumps({"hits": ["0x1"], "ok": True, "output_path": "/tmp/x"}),
                },
                None,
            )
            return None

    class _Mgr:
        def __init__(self, device_id=None) -> None:
            _ = device_id

        def spawn_and_attach(self, _app_id: str):
            return 0, object()

        def load_script(self, _session, _script: str):
            return _Script()

    monkeypatch.setattr(mem_mod, "FridaManager", _Mgr)
    out = mem_mod.memory_search("app", "abc")
    payload = json.loads(out)
    assert payload["hits"] == ["0x1"]
    assert payload["status"] == "pass"
    assert payload["hit_count"] == 1
    assert payload["runtime_dashboard"]["mode"] == "memory-search"
    out2 = mem_mod.heap_dump("app", "/tmp/heap.hprof")
    payload2 = json.loads(out2)
    assert payload2["output_path"] == "/tmp/x"
    assert payload2["status"] == "pass"
    assert payload2["remote_output_path"] == "/tmp/heap.hprof"
    assert payload2["runtime_dashboard"]["mode"] == "heap-dump"


def test_runtime_preflight_includes_readiness_and_compatibility() -> None:
    from lockknife.modules.runtime._session_manager_preflight import runtime_preflight

    class _Mgr:
        def __init__(self, device_id=None) -> None:
            self.device_id = device_id

        def describe_device(self) -> dict[str, str]:
            return {"id": self.device_id or "usb", "name": "Demo", "type": "usb"}

        def application_available(self, _app_id: str) -> bool:
            return True

        def running_pid(self, _app_id: str) -> int:
            return 4242

    payload = runtime_preflight(
        app_id="app",
        device_id="usb",
        attach_mode="attach",
        session_kind="bypass_ssl",
        manager_factory=_Mgr,
    )
    assert payload["status"] == "warn"
    assert payload["readiness"]["ready"] is True
    assert payload["compatibility"]["status"] == "warn"
    assert any(
        finding["rule_id"] == "ssl-attach-misses-early-hooks"
        for finding in payload["compatibility"]["findings"]
    )
    assert payload["suggested_builtin_scripts"]
    assert payload["runtime_dashboard"]["mode"] == "preflight"


def test_frida_manager_spawns(monkeypatch) -> None:
    from lockknife.modules.runtime import frida_manager as fm_mod

    class _Device:
        def spawn(self, _args):
            return 123

        def attach(self, _pid):
            return object()

        def resume(self, _pid):
            return None

        def get_process(self, _app_id):
            return types.SimpleNamespace(pid=321)

    fake_frida = types.SimpleNamespace(
        get_usb_device=lambda timeout=0: _Device(), get_device=lambda _id: _Device()
    )
    monkeypatch.setitem(__import__("sys").modules, "frida", fake_frida)

    mgr = fm_mod.FridaManager()
    handle, session = mgr.spawn_and_attach("app")
    assert handle.pid == 123
    assert session is not None
