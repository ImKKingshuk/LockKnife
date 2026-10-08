from __future__ import annotations

import pathlib

from lockknife.core.agent.models import (
    AgentGoal,
    AgentRunResult,
    DecisionKind,
    GoalStatus,
    ModelDecision,
    ToolInvocation,
    ToolObservation,
    TurnRecord,
)


def test_tool_invocation_serialization():
    inv = ToolInvocation(call_id="call_1", tool_id="core.health", arguments={"verbose": True})
    data = inv.to_dict()
    assert data["call_id"] == "call_1"
    assert data["tool_id"] == "core.health"
    assert data["arguments"] == {"verbose": True}

    restored = ToolInvocation.from_dict(data)
    assert restored.call_id == inv.call_id
    assert restored.tool_id == inv.tool_id
    assert restored.arguments == inv.arguments


def test_tool_observation_serialization():
    obs = ToolObservation(
        call_id="call_1",
        tool_id="core.health",
        success=True,
        output={"status": "healthy"},
        error=None,
        duration_s=0.12,
        artifacts_created=["artifact.json"],
    )
    data = obs.to_dict()
    assert data["success"] is True
    assert data["output"] == {"status": "healthy"}
    assert "artifact.json" in data["artifacts_created"]

    restored = ToolObservation.from_dict(data)
    assert restored.call_id == obs.call_id
    assert restored.success is True
    assert restored.artifacts_created == ["artifact.json"]


def test_model_decision_factories():
    dec_resp = ModelDecision.respond("Analysis complete.")
    assert dec_resp.kind == DecisionKind.RESPOND
    assert dec_resp.text == "Analysis complete."
    assert not dec_resp.is_tool_call
    assert dec_resp.is_terminal

    inv = ToolInvocation(call_id="c1", tool_id="apk.analyze", arguments={})
    dec_tools = ModelDecision.call_tools([inv], reasoning="Need to analyze apk")
    assert dec_tools.kind == DecisionKind.TOOL_CALL
    assert dec_tools.is_tool_call
    assert not dec_tools.is_terminal
    assert dec_tools.reasoning == "Need to analyze apk"
    assert len(dec_tools.tool_calls) == 1

    dec_fin = ModelDecision.finish("Success")
    assert dec_fin.kind == DecisionKind.FINISH
    assert dec_fin.is_terminal


def test_agent_goal_and_result(tmp_path: pathlib.Path):
    goal = AgentGoal(
        objective="Inspect device security posture",
        case_dir=tmp_path,
        budget_iterations=15,
    )
    assert goal.status == GoalStatus.PENDING
    goal_dict = goal.to_dict()
    assert goal_dict["objective"] == "Inspect device security posture"
    assert goal_dict["budget_iterations"] == 15

    dec = ModelDecision.respond("Device verified.")
    turn = TurnRecord(turn_index=1, decision=dec, duration_s=0.5)
    result = AgentRunResult(
        goal=goal,
        status=GoalStatus.COMPLETED,
        final_response="All checks passed.",
        turns=[turn],
        artifacts_created=["report.md"],
        duration_s=1.2,
    )
    res_dict = result.to_dict()
    assert res_dict["status"] == "completed"
    assert res_dict["turns_count"] == 1
    assert res_dict["duration_s"] == 1.2
