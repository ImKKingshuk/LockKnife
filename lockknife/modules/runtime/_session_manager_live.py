from __future__ import annotations

import pathlib
import time
from collections.abc import Callable
from typing import Any

from lockknife.core.case import (
    add_case_runtime_session_script,
    case_runtime_session_details,
    query_case_runtime_sessions,
    start_case_runtime_session,
    update_case_runtime_session,
)
from lockknife.modules.runtime._session_manager_inventory import (
    enrich_runtime_inventory_payload,
    enrich_runtime_session_payload,
)
from lockknife.modules.runtime._session_manager_preflight import runtime_preflight
from lockknife.modules.runtime._session_manager_shared import (
    _LIVE_SESSIONS,
    _LIVE_SESSIONS_LOCK,
    LiveRuntimeSession,
    _close_live_session,
    _read_session_payload,
    _recovery_hint,
    _register_runtime_artifact,
    _resolve_script_source,
    _snapshot_script,
    _write_event,
)
from lockknife.modules.runtime.frida_manager import FridaManager


def _connect_live_runtime_session(
    session_payload: dict[str, Any],
    *,
    case_dir: pathlib.Path,
    source: str,
    device_id: str | None,
    attach_mode: str,
    manager_factory: Callable[[str | None], FridaManager] | None,
) -> LiveRuntimeSession:
    manager = (manager_factory or FridaManager)(device_id)
    session_id = str(session_payload["session_id"])

    def _normalize_message(message: Any) -> dict[str, Any]:
        if isinstance(message, dict):
            return message
        return {"value": str(message)}

    def on_message(message: Any, data: Any) -> None:
        payload = _normalize_message(message)
        _write_event(
            case_dir,
            session_id=session_id,
            event_type="message",
            level=str(payload.get("type") or "info"),
            message=str(
                payload.get("description")
                or payload.get("payload")
                or payload.get("type")
                or payload.get("value")
                or "Runtime message"
            ),
            payload={"message": payload, "data_present": data is not None},
        )

    def on_detached(reason: Any, crash: Any) -> None:
        message = str(reason or "Frida session detached")
        update_case_runtime_session(
            case_dir,
            session_id=session_id,
            status="detached",
            latest_message=message,
            error_message=message,
            recovery_hint="Reconnect the runtime session to continue instrumentation.",
            ended=True,
        )
        _write_event(
            case_dir,
            session_id=session_id,
            event_type="detached",
            level="warn",
            message=message,
            payload={
                "reason": reason,
                "crash": crash
                if isinstance(crash, dict)
                else (str(crash) if crash is not None else None),
            },
        )
        with _LIVE_SESSIONS_LOCK:
            _LIVE_SESSIONS.pop(session_id, None)

    if attach_mode == "attach":
        handle, session = manager.attach_running(str(session_payload["app_id"]))
    else:
        handle, session = manager.spawn_and_attach(str(session_payload["app_id"]))
    script = manager.load_script(session, source)

    on = getattr(script, "on", None)
    if callable(on):
        on("message", on_message)
    session_on = getattr(session, "on", None)
    if callable(session_on):
        session_on("detached", on_detached)
    return LiveRuntimeSession(
        session_id=session_id,
        case_dir=case_dir,
        manager=manager,
        handle=handle,
        session=session,
        script=script,
    )


def start_managed_runtime_session(
    *,
    case_dir: pathlib.Path | str,
    name: str,
    app_id: str,
    session_kind: str,
    source_command: str,
    script_source: str | None = None,
    script_label: str | None = None,
    builtin_script: str | None = None,
    device_id: str | None = None,
    attach_mode: str = "spawn",
    metadata: dict[str, Any] | None = None,
    input_paths: list[str] | None = None,
    initial_wait_s: float = 0.0,
    manager_factory: Callable[[str | None], FridaManager] | None = None,
) -> dict[str, Any]:
    case_path = pathlib.Path(case_dir)
    resolved_source, resolved_label, resolved_source_path, source_kind, builtin_metadata = (
        _resolve_script_source(
            {},
            script_path=None,
            script_source=script_source,
            builtin_script=builtin_script,
        )
    )
    preflight = runtime_preflight(
        app_id=app_id,
        device_id=device_id,
        attach_mode=attach_mode,
        session_kind=session_kind,
        manager_factory=manager_factory,
    )
    session = start_case_runtime_session(
        case_path,
        name=name,
        app_id=app_id,
        session_kind=session_kind,
        attach_mode=attach_mode,
        device_id=device_id,
        metadata={**(metadata or {}), **builtin_metadata, "preflight": preflight},
    )
    _write_event(
        case_path,
        session_id=session.session_id,
        event_type="lifecycle",
        message="Runtime session created.",
        payload={"preflight": preflight},
    )

    script_snapshot = _snapshot_script(
        case_dir=case_path,
        session_id=session.session_id,
        label=script_label or resolved_label,
        source=resolved_source,
    )
    session = add_case_runtime_session_script(
        case_path,
        session_id=session.session_id,
        label=script_label or resolved_label,
        path=str(script_snapshot),
        source_command=source_command,
        source_kind=source_kind,
        source_path=(
            str(resolved_source_path)
            if resolved_source_path is not None
            else (input_paths[0] if input_paths else None)
        ),
        metadata={**(metadata or {}), **builtin_metadata},
    )
    script_artifact_id = _register_runtime_artifact(
        case_dir=case_path,
        path=script_snapshot,
        category="runtime-script",
        source_command=source_command,
        device_id=device_id,
        input_paths=input_paths
        or ([str(resolved_source_path)] if resolved_source_path is not None else None),
        metadata={
            "app_id": app_id,
            "session_id": session.session_id,
            "session_kind": session_kind,
            **builtin_metadata,
        },
    )
    log_artifact_id = _register_runtime_artifact(
        case_dir=case_path,
        path=pathlib.Path(str(session.logs_path)),
        category="runtime-session-log",
        source_command=source_command,
        device_id=device_id,
        parent_artifact_ids=[artifact_id for artifact_id in [script_artifact_id] if artifact_id],
        metadata={"app_id": app_id, "session_id": session.session_id, "session_kind": session_kind},
    )
    summary_artifact_id = _register_runtime_artifact(
        case_dir=case_path,
        path=pathlib.Path(str(session.summary_path)),
        category="runtime-session",
        source_command=source_command,
        device_id=device_id,
        parent_artifact_ids=[
            artifact_id for artifact_id in [script_artifact_id, log_artifact_id] if artifact_id
        ],
        metadata={"app_id": app_id, "session_id": session.session_id, "session_kind": session_kind},
    )
    session = update_case_runtime_session(
        case_path,
        session_id=session.session_id,
        result_artifact_ids_append=[
            artifact_id
            for artifact_id in [script_artifact_id, log_artifact_id, summary_artifact_id]
            if artifact_id
        ],
    )

    try:
        live = _connect_live_runtime_session(
            _read_session_payload(case_path, session.session_id),
            case_dir=case_path,
            source=resolved_source,
            device_id=device_id,
            attach_mode=attach_mode,
            manager_factory=manager_factory,
        )
        with _LIVE_SESSIONS_LOCK:
            _LIVE_SESSIONS[session.session_id] = live
        pid = getattr(live.handle, "pid", live.handle if isinstance(live.handle, int) else None)
        session = update_case_runtime_session(
            case_path,
            session_id=session.session_id,
            status="active",
            pid=int(pid) if pid is not None else None,
            latest_message="Runtime session active",
            connect_increment=1,
            clear_error=True,
            metadata_updates={"preflight": preflight},
        )
        _write_event(
            case_path,
            session_id=session.session_id,
            event_type="connected",
            message="Attached and loaded the active Frida script.",
            payload={"pid": pid, "attach_mode": attach_mode},
        )
    except Exception as exc:
        session = update_case_runtime_session(
            case_path,
            session_id=session.session_id,
            status="failed",
            latest_message="Runtime session failed to start",
            error_message=str(exc),
            recovery_hint=_recovery_hint(exc),
            metadata_updates={"preflight": preflight},
        )
        _write_event(
            case_path,
            session_id=session.session_id,
            event_type="error",
            level="error",
            message="Runtime session start failed.",
            payload={"error": str(exc), "recovery_hint": _recovery_hint(exc)},
        )
        raise RuntimeError(f"{exc} ({_recovery_hint(exc)})") from exc

    if initial_wait_s > 0:
        time.sleep(initial_wait_s)

    detail = (
        case_runtime_session_details(case_path, session_id=session.session_id, event_limit=100)
        or {}
    )
    detail["preflight"] = preflight
    detail["live"] = True
    detail["script_snapshot_path"] = str(script_snapshot)
    detail["lifecycle"] = {
        "action": "start",
        "status": "active",
        "message": "Managed runtime session is active.",
    }
    return enrich_runtime_session_payload(detail, live=True)


def list_managed_runtime_sessions(
    *, case_dir: pathlib.Path | str, **filters: Any
) -> dict[str, Any]:
    payload = query_case_runtime_sessions(pathlib.Path(case_dir), **filters)
    with _LIVE_SESSIONS_LOCK:
        live_ids = set(_LIVE_SESSIONS)
    payload["live_session_ids"] = sorted(live_ids)
    for session in payload.get("sessions", []):
        session["live"] = str(session.get("session_id")) in live_ids
    return enrich_runtime_inventory_payload(payload)


def get_managed_runtime_session(
    *,
    case_dir: pathlib.Path | str,
    session_id: str,
    event_limit: int = 100,
    event_cursor: int | None = None,
) -> dict[str, Any]:
    payload = case_runtime_session_details(
        pathlib.Path(case_dir),
        session_id=session_id,
        event_limit=event_limit,
        event_cursor=event_cursor,
    )
    if payload is None:
        raise ValueError(f"Runtime session {session_id} not found")
    with _LIVE_SESSIONS_LOCK:
        live = session_id in _LIVE_SESSIONS
    payload["live"] = live
    payload["runtime_watchdog"] = {
        "recommended_poll_interval_s": 1.0 if live else 0.0,
        "bounded": True,
        "status": "attached" if live else "snapshot-only",
    }
    return enrich_runtime_session_payload(payload, live=live)


def reconnect_managed_runtime_session(
    *,
    case_dir: pathlib.Path | str,
    session_id: str,
    attach_mode: str | None = None,
    initial_wait_s: float = 0.0,
    manager_factory: Callable[[str | None], FridaManager] | None = None,
) -> dict[str, Any]:
    case_path = pathlib.Path(case_dir)
    session_payload = _read_session_payload(case_path, session_id)
    mode = attach_mode or str(session_payload.get("attach_mode") or "spawn")
    source, _label, _source_path, _source_kind, _script_metadata = _resolve_script_source(
        session_payload,
        script_path=None,
        script_source=None,
    )
    preflight = runtime_preflight(
        app_id=str(session_payload.get("app_id") or ""),
        device_id=session_payload.get("device_id"),
        attach_mode=mode,
        session_kind=session_payload.get("session_kind"),
        manager_factory=manager_factory,
    )

    with _LIVE_SESSIONS_LOCK:
        _close_live_session(_LIVE_SESSIONS.pop(session_id, None))
    update_case_runtime_session(
        case_path,
        session_id=session_id,
        status="reconnecting",
        latest_message="Reconnecting runtime session",
        attach_mode=mode,
        metadata_updates={"preflight": preflight},
    )
    _write_event(
        case_path,
        session_id=session_id,
        event_type="reconnect",
        message="Attempting to reconnect runtime session.",
        payload={"attach_mode": mode, "preflight": preflight},
    )
    try:
        live = _connect_live_runtime_session(
            session_payload,
            case_dir=case_path,
            source=source,
            device_id=session_payload.get("device_id"),
            attach_mode=mode,
            manager_factory=manager_factory,
        )
        with _LIVE_SESSIONS_LOCK:
            _LIVE_SESSIONS[session_id] = live
        pid = getattr(live.handle, "pid", live.handle if isinstance(live.handle, int) else None)
        update_case_runtime_session(
            case_path,
            session_id=session_id,
            status="active",
            pid=int(pid) if pid is not None else None,
            latest_message="Runtime session reconnected",
            connect_increment=1,
            clear_error=True,
            attach_mode=mode,
            metadata_updates={"preflight": preflight},
        )
        _write_event(
            case_path,
            session_id=session_id,
            event_type="connected",
            message="Runtime session reconnected.",
            payload={"pid": pid, "attach_mode": mode, "preflight": preflight},
        )
    except Exception as exc:
        update_case_runtime_session(
            case_path,
            session_id=session_id,
            status="failed",
            latest_message="Runtime session reconnect failed",
            error_message=str(exc),
            recovery_hint=_recovery_hint(exc),
            attach_mode=mode,
            metadata_updates={"preflight": preflight},
        )
        _write_event(
            case_path,
            session_id=session_id,
            event_type="error",
            level="error",
            message="Runtime session reconnect failed.",
            payload={
                "error": str(exc),
                "recovery_hint": _recovery_hint(exc),
                "preflight": preflight,
            },
        )
        raise RuntimeError(f"{exc} ({_recovery_hint(exc)})") from exc
    if initial_wait_s > 0:
        time.sleep(initial_wait_s)
    payload = get_managed_runtime_session(
        case_dir=case_path, session_id=session_id, event_limit=100
    )
    payload["preflight"] = preflight
    payload["lifecycle"] = {
        "action": "reconnect",
        "status": "active",
        "message": "Managed runtime session reconnected.",
    }
    return enrich_runtime_session_payload(payload, live=bool(payload.get("live")))


def reload_managed_runtime_session(
    *,
    case_dir: pathlib.Path | str,
    session_id: str,
    source_command: str,
    script_path: pathlib.Path | str | None = None,
    script_source: str | None = None,
    script_label: str | None = None,
    builtin_script: str | None = None,
    initial_wait_s: float = 0.0,
    manager_factory: Callable[[str | None], FridaManager] | None = None,
) -> dict[str, Any]:
    case_path = pathlib.Path(case_dir)
    session_payload = _read_session_payload(case_path, session_id)
    resolved_path = pathlib.Path(script_path) if script_path else None
    source, default_label, source_path, source_kind, script_metadata = _resolve_script_source(
        session_payload,
        script_path=resolved_path,
        script_source=script_source,
        builtin_script=builtin_script,
    )
    label = script_label or default_label
    snapshot = _snapshot_script(
        case_dir=case_path, session_id=session_id, label=label, source=source
    )
    session = add_case_runtime_session_script(
        case_path,
        session_id=session_id,
        label=label,
        path=str(snapshot),
        source_command=source_command,
        source_kind=source_kind,
        source_path=str(source_path) if source_path is not None else None,
        metadata=script_metadata,
    )
    script_artifact_id = _register_runtime_artifact(
        case_dir=case_path,
        path=snapshot,
        category="runtime-script",
        source_command=source_command,
        device_id=session.device_id,
        input_paths=[str(source_path)]
        if source_path is not None and source_kind in {"file", "builtin"}
        else None,
        metadata={
            "app_id": session.app_id,
            "session_id": session_id,
            "session_kind": session.session_kind,
            **script_metadata,
        },
    )
    update_case_runtime_session(
        case_path,
        session_id=session_id,
        latest_message="Reloading runtime script",
        reload_increment=1,
        result_artifact_ids_append=[
            artifact_id for artifact_id in [script_artifact_id] if artifact_id
        ],
    )

    with _LIVE_SESSIONS_LOCK:
        live = _LIVE_SESSIONS.get(session_id)
    if live is None:
        reconnect_managed_runtime_session(
            case_dir=case_path, session_id=session_id, manager_factory=manager_factory
        )
        with _LIVE_SESSIONS_LOCK:
            live = _LIVE_SESSIONS.get(session_id)
    if live is None:
        raise RuntimeError("Runtime session could not be reconnected before script reload")

    unload = getattr(live.script, "unload", None)
    if callable(unload):
        unload()
    live.script = live.manager.load_script(live.session, source)
    on = getattr(live.script, "on", None)
    if callable(on):
        on(
            "message",
            lambda message, _data: _write_event(
                case_path,
                session_id=session_id,
                event_type="message",
                level=str(message.get("type") or "info"),
                message=str(message.get("description") or message.get("type") or "Runtime message"),
                payload={"message": message},
            ),
        )
    update_case_runtime_session(
        case_path,
        session_id=session_id,
        status="active",
        latest_message=f"Reloaded runtime script {label}",
        clear_error=True,
    )
    _write_event(
        case_path,
        session_id=session_id,
        event_type="reload",
        message=f"Reloaded runtime script {label}.",
        payload={"script_path": str(snapshot), "source_kind": source_kind},
    )
    if initial_wait_s > 0:
        time.sleep(initial_wait_s)
    payload = get_managed_runtime_session(
        case_dir=case_path, session_id=session_id, event_limit=100
    )
    payload["script_snapshot_path"] = str(snapshot)
    payload["lifecycle"] = {
        "action": "reload",
        "status": "active",
        "message": f"Reloaded runtime script {label}.",
    }
    return enrich_runtime_session_payload(payload, live=bool(payload.get("live")))


def stop_managed_runtime_session(
    *, case_dir: pathlib.Path | str, session_id: str
) -> dict[str, Any]:
    case_path = pathlib.Path(case_dir)
    with _LIVE_SESSIONS_LOCK:
        live = _LIVE_SESSIONS.pop(session_id, None)
    _close_live_session(live)
    update_case_runtime_session(
        case_path,
        session_id=session_id,
        status="stopped",
        latest_message="Runtime session stopped",
        ended=True,
        clear_error=True,
    )
    _write_event(
        case_path,
        session_id=session_id,
        event_type="stopped",
        message="Stopped runtime session and detached Frida handles.",
    )
    payload = get_managed_runtime_session(
        case_dir=case_path, session_id=session_id, event_limit=100
    )
    payload["lifecycle"] = {
        "action": "stop",
        "status": "stopped",
        "message": "Managed runtime session stopped.",
    }
    return enrich_runtime_session_payload(payload, live=False)
