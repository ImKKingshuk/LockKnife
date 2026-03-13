from __future__ import annotations

from lockknife.core.case import register_case_artifact

from lockknife.modules.runtime._session_manager_shared import (
    _safe_name,
    _runtime_now,
    _artifact_id,
    _recovery_hint,
    LiveRuntimeSession,
    _register_runtime_artifact,
    _read_session_payload,
    _snapshot_script,
    _write_event,
    _close_live_session,
    _resolve_script_source,
    _LIVE_SESSIONS,
    _LIVE_SESSIONS_LOCK,
)

from lockknife.modules.runtime._session_manager_preflight import runtime_preflight

from lockknife.modules.runtime._session_manager_live import (
    _connect_live_runtime_session,
    start_managed_runtime_session,
    list_managed_runtime_sessions,
    get_managed_runtime_session,
    reconnect_managed_runtime_session,
    reload_managed_runtime_session,
    stop_managed_runtime_session,
)

__all__ = [
    "LiveRuntimeSession",
    "runtime_preflight",
    "start_managed_runtime_session",
    "list_managed_runtime_sessions",
    "get_managed_runtime_session",
    "reconnect_managed_runtime_session",
    "reload_managed_runtime_session",
    "stop_managed_runtime_session",
]
