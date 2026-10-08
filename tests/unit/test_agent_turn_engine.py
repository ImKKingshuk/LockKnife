from __future__ import annotations

import pathlib

from lockknife.core.agent.memory import MemoryStore
from lockknife.core.agent.models import (
    AgentGoal,
    GoalStatus,
    ModelDecision,
    ToolInvocation,
)
from lockknife.core.agent.policy import ResearcherPolicy
from lockknife.core.agent.provider import DeterministicMockProvider
from lockknife.core.agent.tools import AgentToolRegistry
from lockknife.core.agent.turn import TurnEngine


def test_turn_engine_successful_mission(tmp_path: pathlib.Path):
    goal = AgentGoal(objective="Triage target device", case_dir=tmp_path, budget_iterations=5)
    policy = ResearcherPolicy(unrestricted=True)
    memory = MemoryStore(case_dir=tmp_path)
    tools = AgentToolRegistry(
        case_dir=tmp_path,
        action_callback=lambda act, params: {"ok": True, "triage": "passed"},
        memory_store=memory,
    )

    # Turn 1: Call triage tool
    # Turn 2: Finish
    provider = DeterministicMockProvider([
        ModelDecision.call_tools([
            ToolInvocation(call_id="c1", tool_id="core.health", arguments={})
        ], reasoning="Checking health."),
        ModelDecision.finish("All security checks passed. Device is healthy."),
    ])

    engine = TurnEngine(
        goal=goal,
        provider=provider,
        tools=tools,
        memory=memory,
        policy=policy,
    )

    result = engine.run_loop()
    assert result.status == GoalStatus.COMPLETED
    assert "Device is healthy" in result.final_response
    assert len(result.turns) == 2


def test_turn_engine_budget_exhaustion(tmp_path: pathlib.Path):
    goal = AgentGoal(objective="Infinite loop test", case_dir=tmp_path, budget_iterations=2)
    policy = ResearcherPolicy(unrestricted=True)
    memory = MemoryStore(case_dir=tmp_path)
    tools = AgentToolRegistry(
        case_dir=tmp_path,
        action_callback=lambda act, params: {"ok": True},
        memory_store=memory,
    )

    # Provider always calls tools without finishing
    provider = DeterministicMockProvider([
        ModelDecision.call_tools([ToolInvocation(call_id="c1", tool_id="core.doctor")]),
        ModelDecision.call_tools([ToolInvocation(call_id="c2", tool_id="core.doctor")]),
        ModelDecision.respond("Summary after budget expired."),
    ])

    engine = TurnEngine(
        goal=goal,
        provider=provider,
        tools=tools,
        memory=memory,
        policy=policy,
    )

    result = engine.run_loop()
    assert result.status == GoalStatus.BUDGET_EXHAUSTED
    assert len(result.turns) == 2


def test_turn_engine_stall_detection(tmp_path: pathlib.Path):
    goal = AgentGoal(objective="Stall test", case_dir=tmp_path, budget_iterations=5)
    policy = ResearcherPolicy(unrestricted=True)
    memory = MemoryStore(case_dir=tmp_path)
    tools = AgentToolRegistry(
        case_dir=tmp_path,
        action_callback=lambda act, params: {"ok": False, "error": "device busy"},
        memory_store=memory,
    )

    # Provider keeps repeating exact same failing call
    call = ToolInvocation(call_id="dup", tool_id="core.health", arguments={"retry": 1})
    provider = DeterministicMockProvider([
        ModelDecision.call_tools([call]),
        ModelDecision.call_tools([call]),
        ModelDecision.call_tools([call]),
        ModelDecision.finish("Aborted due to repeated failures."),
    ])

    engine = TurnEngine(
        goal=goal,
        provider=provider,
        tools=tools,
        memory=memory,
        policy=policy,
    )

    result = engine.run_loop()
    # Turn 3 should have hit stall detection
    turn3_obs = result.turns[2].observations[0]
    assert "Stall detected" in (turn3_obs.error or "")


def test_autonomous_runtime_chat_step(tmp_path: pathlib.Path):
    from lockknife.core.agent.runtime import AutonomousRuntime

    provider = DeterministicMockProvider([
        ModelDecision.call_tools([
            ToolInvocation(call_id="c_chat", tool_id="record_fact", arguments={"key": "status", "value": "audited"})
        ], reasoning="Recording audit fact."),
        ModelDecision.respond("Device audited successfully."),
    ])

    runtime = AutonomousRuntime(
        goal=AgentGoal(objective="Interactive session"),
        case_dir=tmp_path,
        provider=provider,
    )

    step1 = runtime.chat_step("Check audit status")
    assert "Calling tool: record_fact" in step1

    step2 = runtime.chat_step("Summarize findings")
    assert "Device audited successfully." in step2
    assert runtime.memory.get_facts()["status"] == "audited"
