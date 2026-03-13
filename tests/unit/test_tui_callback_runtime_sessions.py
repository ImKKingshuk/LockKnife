import json
import pathlib
import types

import pytest

from tests.unit.test_tui_callback import DummyApp, DummyFridaManager, build_tui_callback

def test_tui_callback_runtime_session_actions_route_outputs_into_case_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    import lockknife.modules.runtime.session_manager as runtime_sessions
    import lockknife.modules.runtime._session_manager_shared as runtime_shared
    from lockknife.core.case import create_case_workspace

    registered: list[dict[str, object]] = []

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb, "method_tracer_script", lambda *_a, **_k: "trace-script")
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)

    def _register(**kwargs):
        registered.append(kwargs)
        return types.SimpleNamespace(artifact_id=f"artifact-{len(registered):04d}")

    monkeypatch.setattr(cb, "register_case_artifact", _register)
    monkeypatch.setattr(runtime_sessions, "register_case_artifact", _register)
    monkeypatch.setattr(runtime_shared, "register_case_artifact", _register)

    callback = build_tui_callback(DummyApp())

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-RT", examiner="Examiner", title="Runtime")
    script_path = tmp_path / "hook.js"
    script_path.write_text("send('hook');", encoding="utf-8")

    for action, payload in [
        (
            "runtime.hook",
            {"app_id": "com.example.app", "script": str(script_path), "case_dir": str(case_dir), "output": "", "timeout": "0"},
        ),
        (
            "runtime.bypass_ssl",
            {"app_id": "com.example.app", "case_dir": str(case_dir), "output": "", "timeout": "0"},
        ),
        (
            "runtime.bypass_root",
            {"app_id": "com.example.app", "case_dir": str(case_dir), "output": "", "timeout": "0"},
        ),
        (
            "runtime.trace",
            {"app_id": "com.example.app", "class": "com.example.Class", "method": "run", "case_dir": str(case_dir), "output": "", "timeout": "0"},
        ),
        (
            "runtime.load_builtin_script",
            {"app_id": "com.example.app", "builtin_script": "debug_bypass", "case_dir": str(case_dir), "output": "", "timeout": "0"},
        ),
    ]:
        result = callback(action, payload)
        assert result["ok"] is True

    runtime_script_paths = [pathlib.Path(entry["path"]) for entry in registered if entry["category"] == "runtime-script"]
    runtime_log_paths = [pathlib.Path(entry["path"]) for entry in registered if entry["category"] == "runtime-session-log"]
    runtime_session_paths = [pathlib.Path(entry["path"]) for entry in registered if entry["category"] == "runtime-session"]

    assert len(runtime_script_paths) == 5
    assert len(runtime_log_paths) == 5
    assert len(runtime_session_paths) == 5
    assert all(path.name.startswith("runtime_rt-") and path.suffix == ".js" for path in runtime_script_paths)
    assert all(path.parent == case_dir / "logs" / "runtime" and path.suffix == ".jsonl" for path in runtime_log_paths)
    assert all(path.parent == case_dir / "derived" / "runtime" and path.suffix == ".json" for path in runtime_session_paths)

def test_tui_callback_runtime_session_messages_use_session_terminology(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    from lockknife.core.case import create_case_workspace

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb, "method_tracer_script", lambda *_a, **_k: "trace-script")
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)

    callback = build_tui_callback(DummyApp())
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-SESSION", examiner="Examiner", title="Runtime")
    script_path = tmp_path / "hook.js"
    script_path.write_text("send('hook');", encoding="utf-8")

    assert callback(
        "runtime.hook",
        {"app_id": "app", "script": str(script_path), "timeout": "0", "case_dir": str(case_dir)},
    )["message"].startswith("Managed runtime session saved to ")
    assert callback("runtime.bypass_ssl", {"app_id": "app", "timeout": "0", "case_dir": str(case_dir)})[
        "message"
    ].startswith("Managed SSL bypass session saved to ")
    assert callback("runtime.bypass_root", {"app_id": "app", "timeout": "0", "case_dir": str(case_dir)})[
        "message"
    ].startswith("Managed root bypass session saved to ")
    assert callback(
        "runtime.trace",
        {
            "app_id": "app",
            "class": "com.example.Class",
            "method": "run",
            "timeout": "0",
            "case_dir": str(case_dir),
        },
    )["message"].startswith("Managed trace session saved to ")
    assert callback(
        "runtime.load_builtin_script",
        {"app_id": "app", "builtin_script": "crypto_intercept", "timeout": "0", "case_dir": str(case_dir)},
    )["message"].startswith("Managed built-in runtime session saved to ")

def test_tui_callback_runtime_session_management_actions_work(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import lockknife_headless_cli.tui_callback as cb
    from lockknife.core.case import create_case_workspace

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb, "method_tracer_script", lambda *_a, **_k: "trace-script")
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-300", examiner="Examiner", title="Runtime Sessions")
    callback = build_tui_callback(DummyApp())
    script_path = tmp_path / "hook.js"
    reload_path = tmp_path / "reload.js"
    script_path.write_text("send('hook');", encoding="utf-8")
    reload_path.write_text("send('reload');", encoding="utf-8")

    start = callback(
        "runtime.hook",
        {"app_id": "app", "script": str(script_path), "timeout": "0", "case_dir": str(case_dir)},
    )
    assert start["ok"] is True
    start_payload = json.loads(start["data_json"])
    session_id = start_payload["session"]["session_id"]
    assert start_payload["runtime_dashboard"]["mode"] == "session-detail"
    assert start_payload["session"]["script_inventory_summary"]["count"] == 1
    assert start_payload["session"]["script_inventory_summary"]["items"][0]["size_bytes"] >= 1
    assert start_payload["session"]["preflight"]["readiness"]["ready"] is True

    sessions = callback("runtime.sessions", {"case_dir": str(case_dir)})
    assert sessions["ok"] is True
    sessions_payload = json.loads(sessions["data_json"])
    assert sessions_payload["sessions"][0]["session_id"] == session_id
    assert sessions_payload["runtime_dashboard"]["mode"] == "inventory"
    assert sessions_payload["runtime_dashboard"]["script_count"] >= 1
    assert sessions_payload["available_builtin_scripts"]

    detail = callback("runtime.session", {"case_dir": str(case_dir), "session_id": session_id})
    assert detail["ok"] is True
    detail_payload = json.loads(detail["data_json"])
    assert detail_payload["session"]["status"] == "active"
    assert detail_payload["session"]["event_summary"]["event_count"] >= 1
    assert detail_payload["runtime_watchdog"]["bounded"] is True
    assert detail_payload["session"]["event_stream"]["next_cursor"] >= 1
    assert detail_payload["suggested_builtin_scripts"]

    detail_after_cursor = callback(
        "runtime.session",
        {"case_dir": str(case_dir), "session_id": session_id, "event_cursor": str(detail_payload["session"]["event_stream"]["next_cursor"])},
    )
    assert detail_after_cursor["ok"] is True
    detail_after_payload = json.loads(detail_after_cursor["data_json"])
    assert detail_after_payload["session"]["event_stream"]["requested_cursor"] >= 1

    reload = callback(
        "runtime.session_reload",
        {"case_dir": str(case_dir), "session_id": session_id, "script": str(reload_path), "timeout": "0"},
    )
    assert reload["ok"] is True
    reload_payload = json.loads(reload["data_json"])
    assert reload_payload["session"]["reload_count"] >= 1
    assert reload_payload["session"]["script_inventory_summary"]["count"] >= 2
    assert reload_payload["script_snapshot_path"].endswith(".js")

    reconnect = callback(
        "runtime.session_reconnect",
        {"case_dir": str(case_dir), "session_id": session_id, "timeout": "0", "attach_mode": "attach"},
    )
    assert reconnect["ok"] is True
    reconnect_payload = json.loads(reconnect["data_json"])
    assert reconnect_payload["session"]["attach_mode"] == "attach"
    assert reconnect_payload["preflight"]["readiness"]["ready"] is True
    assert reconnect_payload["runtime_dashboard"]["mode"] == "session-detail"

    stop = callback("runtime.session_stop", {"case_dir": str(case_dir), "session_id": session_id})
    assert stop["ok"] is True
    stop_payload = json.loads(stop["data_json"])
    assert stop_payload["session"]["status"] == "stopped"
    assert stop_payload["runtime_dashboard"]["mode"] == "session-detail"


def test_runtime_session_detach_is_recorded(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import lockknife_headless_cli.tui_callback as cb
    import lockknife.modules.runtime._session_manager_live as runtime_live
    from lockknife.core.case import create_case_workspace

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-DETACH", examiner="Examiner", title="Runtime Detach")
    callback = build_tui_callback(DummyApp())
    script_path = tmp_path / "hook.js"
    script_path.write_text("send('hook');", encoding="utf-8")

    started = callback("runtime.hook", {"app_id": "app", "script": str(script_path), "timeout": "0", "case_dir": str(case_dir)})
    session_id = json.loads(started["data_json"])["session"]["session_id"]

    with runtime_live._LIVE_SESSIONS_LOCK:
        runtime_live._LIVE_SESSIONS[session_id].session.emit_detached("transport-lost")

    detail = callback("runtime.session", {"case_dir": str(case_dir), "session_id": session_id})
    payload = json.loads(detail["data_json"])
    assert payload["session"]["status"] == "detached"
    assert payload["live"] is False
    assert payload["session"]["event_summary"]["recent"][-1]["event_type"] == "detached"


def test_tui_callback_runtime_preflight_supports_session_kind_guidance(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    callback = build_tui_callback(DummyApp())

    result = callback(
        "runtime.preflight",
        {
            "app_id": "app",
            "device_id": "usb",
            "attach_mode": "attach",
            "session_kind": "bypass_ssl",
        },
    )

    assert result["ok"] is True
    payload = json.loads(result["data_json"])
    assert payload["readiness"]["ready"] is True
    assert payload["compatibility"]["status"] == "warn"
    assert payload["suggested_builtin_scripts"]
    assert any(
        finding["rule_id"] == "ssl-attach-misses-early-hooks"
        for finding in payload["compatibility"]["findings"]
    )
