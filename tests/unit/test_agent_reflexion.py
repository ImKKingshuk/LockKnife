from __future__ import annotations

from lockknife.core.agent.models import AgentGoal, ToolInvocation, ToolObservation
from lockknife.core.agent.planner import GoalPlan, MilestoneStatus
from lockknife.core.agent.reflexion import ReflexionEngine


def test_reflexion_engine_detects_permission_failure():
    goal = AgentGoal(objective="Triage target")
    plan = GoalPlan(goal)
    engine = ReflexionEngine(plan)

    call = ToolInvocation(call_id="c1", tool_id="extract.whatsapp", arguments={})
    obs = ToolObservation(
        call_id="c1",
        tool_id="extract.whatsapp",
        success=False,
        error="Permission denied: /data/data/com.whatsapp",
    )

    critique = engine.evaluate([call], [obs])
    assert critique.has_issues is True
    assert any("permission" in n.lower() for n in critique.critique_notes)
    assert critique.suggested_recovery is not None
    assert "non-root" in critique.suggested_recovery

    prompt_block = critique.format_prompt_block()
    assert prompt_block is not None
    assert "=== EVALUATIVE SELF-CRITIQUE (REFLEXION) ===" in prompt_block
    assert "Strategy Recovery Hint" in prompt_block


def test_reflexion_engine_advances_milestone():
    goal = AgentGoal(objective="Triage device health")
    plan = GoalPlan(goal)
    engine = ReflexionEngine(plan)

    call = ToolInvocation(call_id="c1", tool_id="core.health", arguments={})
    obs = ToolObservation(call_id="c1", tool_id="core.health", success=True, output={"status": "ok"})

    critique = engine.evaluate([call], [obs])
    assert critique.has_issues is False
    assert critique.milestone_advance is not None
    assert plan.milestones[0].status == MilestoneStatus.COMPLETED
