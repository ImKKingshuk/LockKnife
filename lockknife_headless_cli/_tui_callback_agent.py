from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast


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
        mock = _safe_bool(params.get("mock"), False)
        unrestricted = _safe_bool(params.get("unrestricted"), True)

        goal = AgentGoal(
            objective=objective,
            target_device=target_device,
            budget_iterations=budget,
        )
        policy = ResearcherPolicy(unrestricted=unrestricted, auto_provision_case=True)

        if mock:
            provider = DeterministicMockProvider([
                ModelDecision.call_tools(
                    [ToolInvocation(call_id="call_triage", tool_id="core.health", arguments={})],
                    reasoning="Initiating triage.",
                ),
                ModelDecision.finish(
                    f"Completed goal: {objective}",
                    reasoning="Goal finished.",
                ),
            ])
        else:
            cfg = ProviderConfig.from_env()
            if model:
                cfg = ProviderConfig(api_base=cfg.api_base, api_key=cfg.api_key, model_name=model)
            provider = OpenAICompatibleProvider(cfg)

        runtime = AutonomousRuntime(
            goal=goal,
            provider=provider,
            policy=policy,
            case_dir=case_dir_path,
        )
        result = runtime.run()
        return _ok(
            result.to_dict(),
            f"Agent goal completed with status: {result.status.value}",
        )

    if action == "agent.chat":
        prompt = params.get("prompt") or params.get("message") or "Status check"
        case_dir_path = _path_param(params.get("case_dir"))
        target_device = _opt(params.get("serial"))
        model = _opt(params.get("model"))
        mock = _safe_bool(params.get("mock"), True)

        goal = AgentGoal(
            objective=prompt,
            target_device=target_device,
            budget_iterations=5,
        )
        policy = ResearcherPolicy(unrestricted=True, auto_provision_case=True)

        if mock:
            provider = DeterministicMockProvider([
                ModelDecision.finish(f"Echo response to: '{prompt}'", reasoning="Chat reply.")
            ])
        else:
            cfg = ProviderConfig.from_env()
            if model:
                cfg = ProviderConfig(api_base=cfg.api_base, api_key=cfg.api_key, model_name=model)
            provider = OpenAICompatibleProvider(cfg)

        runtime = AutonomousRuntime(
            goal=goal,
            provider=provider,
            policy=policy,
            case_dir=case_dir_path,
        )
        response = runtime.chat_step(prompt)
        return _ok(
            {"response": response, "prompt": prompt},
            "Agent response generated",
        )

    if action == "agent.daemon":
        daemon_action = (params.get("action") or "status").lower()
        serial = _opt(params.get("serial"))
        interval = _safe_int(params.get("interval"), 30)

        daemon = DeviceHeartbeatDaemon(interval_s=float(interval))
        tick_res = daemon.tick()
        return _ok(
            {
                "daemon_action": daemon_action,
                "target_device": serial,
                "interval_s": interval,
                "status": "active" if tick_res.get("ok") else "ready",
                "events": tick_res.get("events", []),
            },
            f"Agent daemon action '{daemon_action}' executed",
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
                k: v
                for k, v in facts.items()
                if q_lower in k.lower() or q_lower in str(v).lower()
            }
            filtered_turns = [
                t for t in turns if q_lower in json.dumps(t).lower()
            ][:limit]
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
