from __future__ import annotations

import atexit
import contextlib
import dataclasses
import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, cast

_daemon: Any = None
_daemon_lock = threading.Lock()
_CHAT_LIMIT = 8
_CHAT_IDLE_SECONDS = 1800
_chat_lock = threading.RLock()


@dataclasses.dataclass
class _ChatSession:
    runtime: Any
    owner: Any
    last_used: float = dataclasses.field(default_factory=time.monotonic)
    lock: Any = dataclasses.field(default_factory=threading.Lock)
    users: int = 0


_chat_sessions: OrderedDict[tuple[Any, ...], _ChatSession] = OrderedDict()

_orcarouter_catalog: Any = None


def _catalog_cache() -> Any:
    """Lazily create the OrcaRouter catalog cache shared by all agents in-process."""
    global _orcarouter_catalog
    if _orcarouter_catalog is None:
        from lockknife.core.agent import ModelCatalogCache

        _orcarouter_catalog = ModelCatalogCache()
    return _orcarouter_catalog


def _resolve_provider_config(*, provider_id: str | None, model: str | None) -> Any:
    """Resolve the agent provider config, including the named OrcaRouter preset."""
    from lockknife.core.agent import ProviderConfig, orcarouter

    if provider_id is None:
        cfg = ProviderConfig.from_env()
        return dataclasses.replace(cfg, model_name=model) if model else cfg
    if provider_id != orcarouter.PROVIDER_ID:
        raise ValueError(
            f"Unknown agent provider '{provider_id}'; choose '{orcarouter.PROVIDER_ID}'"
        )
    cfg = ProviderConfig.for_orcarouter(model=model)
    catalog = _catalog_cache().discover(
        orcarouter.OrcaRouterSettings(api_base=cfg.api_base, api_key=cfg.api_key)
    )
    ok, reason = orcarouter.ensure_model_supported(cfg.model_name, catalog.models)
    if ok:
        return cfg
    # The stored/selected model is not in the current catalog: reset to the
    # provider default instead of silently keeping an incompatible value.
    return dataclasses.replace(cfg, model_name=orcarouter.DEFAULT_MODEL)


def _close_chat_sessions() -> None:
    with _chat_lock:
        for session in _chat_sessions.values():
            session.runtime.close()
        _chat_sessions.clear()


atexit.register(_close_chat_sessions)


@contextlib.contextmanager
def _chat_runtime(key: tuple[Any, ...], owner: Any, factory: Callable[[], Any]):
    with _chat_lock:
        now = time.monotonic()
        for old_key, entry in list(_chat_sessions.items()):
            if not entry.users and now - entry.last_used >= _CHAT_IDLE_SECONDS:
                _chat_sessions.pop(old_key).runtime.close()
        session = _chat_sessions.get(key)
        if session is None:
            if len(_chat_sessions) >= _CHAT_LIMIT:
                oldest = next((k for k, entry in _chat_sessions.items() if not entry.users), None)
                if oldest is None:
                    raise RuntimeError("All chat sessions are busy")
                _chat_sessions.pop(oldest).runtime.close()
            session = _ChatSession(factory(), owner)
            _chat_sessions[key] = session
        session.users += 1
        _chat_sessions.move_to_end(key)
    try:
        with session.lock:
            yield session.runtime
    finally:
        with _chat_lock:
            session.users -= 1
            session.last_used = time.monotonic()


def _safe_int(val: Any, default: int) -> int:
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_bool(val: Any, default: bool) -> bool:
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
    global _daemon
    pathlib = cb.pathlib
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    _err = cast(Callable[[str], dict[str, Any]], cb._err)
    _opt = cb._opt
    _path_param = cb._path_param

    from lockknife.core.agent import (
        AgentGoal,
        AutonomousRuntime,
        DeterministicMockProvider,
        DeviceHeartbeatDaemon,
        ModelDecision,
        OpenAICompatibleProvider,
        ProviderConfig,
        ResearcherPolicy,
        ToolInvocation,
    )
    from lockknife.core.agent.memory import MemoryStore

    if action == "agent.goal":
        objective = params.get("objective") or "Triage connected device and assess security posture"
        case_dir_path = _path_param(params.get("case_dir"))
        target_device = _opt(params.get("serial")) or _opt(params.get("target_device"))
        budget = _safe_int(params.get("budget"), 25)
        model = _opt(params.get("model"))
        provider_id = (params.get("provider") or "").strip().lower() or None
        mock = _safe_bool(params.get("mock"), False)
        unrestricted = _safe_bool(params.get("unrestricted"), True)

        goal = AgentGoal(
            objective=objective,
            target_device=target_device,
            budget_iterations=budget,
        )
        policy = ResearcherPolicy(unrestricted=unrestricted, auto_provision_case=True)

        if mock:
            provider = DeterministicMockProvider(
                [
                    ModelDecision.call_tools(
                        [
                            ToolInvocation(
                                call_id="call_triage", tool_id="core.health", arguments={}
                            )
                        ],
                        reasoning="Initiating triage.",
                    ),
                    ModelDecision.finish(
                        f"Completed goal: {objective}",
                        reasoning="Goal finished.",
                    ),
                ]
            )
        else:
            try:
                cfg = _resolve_provider_config(provider_id=provider_id, model=model)
            except ValueError as exc:
                return _err(str(exc))
            provider = OpenAICompatibleProvider(cfg)

        runtime = AutonomousRuntime(
            goal=goal,
            provider=provider,
            policy=policy,
            case_dir=case_dir_path,
        )
        result = runtime.run()
        if result.status.value != "completed":
            failure = _err(result.error or result.final_response)
            failure["data_json"] = json.dumps(result.to_dict())
            return failure
        return _ok(
            result.to_dict(),
            f"Agent goal completed with status: {result.status.value}",
        )

    if action == "agent.chat":
        prompt = params.get("prompt") or params.get("message") or "Status check"
        case_dir_path = _path_param(params.get("case_dir"))
        target_device = _opt(params.get("serial")) or _opt(params.get("target_device"))
        model = _opt(params.get("model"))
        provider_id = (params.get("provider") or "").strip().lower() or None
        mock = _safe_bool(params.get("mock"), False)

        budget = max(1, _safe_int(params.get("budget"), 25))
        try:
            cfg = _resolve_provider_config(provider_id=provider_id, model=model)
        except ValueError as exc:
            return _err(str(exc))
        key = (
            id(app),
            str(case_dir_path.resolve()) if case_dir_path is not None else None,
            target_device,
            cfg.model_name,
            cfg.api_base,
            hashlib.sha256(cfg.api_key.encode()).hexdigest(),
            mock,
            budget,
        )

        def create_chat_runtime() -> Any:
            provider = (
                DeterministicMockProvider(
                    decision_hook=lambda messages: ModelDecision.finish(
                        f"Echo response to: '{next(m['content'] for m in reversed(messages) if m['role'] == 'user')}'"
                    )
                )
                if mock
                else OpenAICompatibleProvider(cfg)
            )
            return AutonomousRuntime(
                goal=AgentGoal(
                    objective="Interactive security research session",
                    target_device=target_device,
                    budget_iterations=budget,
                ),
                provider=provider,
                case_dir=case_dir_path,
                policy=ResearcherPolicy(unrestricted=True, auto_provision_case=True),
            )

        try:
            with _chat_runtime(key, app, create_chat_runtime) as runtime:
                response = runtime.chat_step(prompt)
        except Exception as exc:
            return _err(str(exc))
        return _ok(
            {"response": response, "prompt": prompt},
            "Agent response generated",
        )

    if action == "agent.daemon":
        daemon_action = (params.get("action") or "status").lower()
        interval = _safe_int(params.get("interval"), 30)
        if daemon_action not in {"start", "stop", "status"}:
            return _err(f"Unknown daemon action: {daemon_action}")
        with _daemon_lock:
            if daemon_action == "start":
                if _daemon is None or _daemon.status()["status"] == "stopped":
                    _daemon = DeviceHeartbeatDaemon(interval_s=float(interval))
                    _daemon.start()
            elif daemon_action == "stop" and _daemon is not None:
                _daemon.stop()
            state = _daemon.status() if _daemon is not None else {"status": "stopped"}
        return _ok(
            {
                "daemon_action": daemon_action,
                **state,
            },
            f"Agent daemon action '{daemon_action}' executed",
        )

    if action == "agent.models":
        from lockknife.core.agent import orcarouter

        provider_id = (params.get("provider") or orcarouter.PROVIDER_ID).strip().lower()
        if provider_id != orcarouter.PROVIDER_ID:
            return _err(f"Unknown agent provider '{provider_id}'")
        settings = orcarouter.resolve_settings()
        result = _catalog_cache().discover(settings)
        payload = orcarouter.describe_catalog(result)
        payload["api_key_configured"] = bool(settings.api_key)
        return _ok(
            payload,
            f"{len(result.models)} text models (catalog source: {result.source})",
        )

    if action == "agent.memory":
        case_dir_path = _path_param(params.get("case_dir")) or pathlib.Path("./cases/CASE-AGENT")
        query = _opt(params.get("query")) or ""
        limit = _safe_int(params.get("limit"), 10)

        store = MemoryStore(case_dir_path)
        facts = store.get_facts()
        turns = store.load_episodic_turns()
        if query:
            q_lower = query.lower()
            filtered_facts = {
                k: v for k, v in facts.items() if q_lower in k.lower() or q_lower in str(v).lower()
            }
            filtered_turns = [t for t in turns if q_lower in json.dumps(t).lower()][:limit]
        else:
            filtered_facts = facts
            filtered_turns = turns[-limit:] if turns else []

        return _ok(
            {
                "facts": filtered_facts,
                "turns": filtered_turns,
                "turns_count": len(turns),
                "facts_count": len(facts),
            },
            f"Retrieved memory with {len(filtered_facts)} facts and {len(filtered_turns)} episodic turns",
        )

    return None
