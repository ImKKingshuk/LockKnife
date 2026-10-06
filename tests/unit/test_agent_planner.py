from __future__ import annotations

from lockknife.core.agent.models import AgentGoal
from lockknife.core.agent.planner import GoalPlan, MilestoneStatus, PlanMilestone


def test_goal_plan_default_generation():
    # APK objective generates APK-focused milestones
    goal_apk = AgentGoal(objective="Decompile and audit malicious APK")
    plan_apk = GoalPlan(goal_apk)
    assert len(plan_apk.milestones) == 3
    assert "Static Analysis" in plan_apk.milestones[0].title

    # Exploit objective generates Exploit-focused milestones
    goal_exploit = AgentGoal(objective="Check root privilege escalation exploit")
    plan_exploit = GoalPlan(goal_exploit)
    assert "Reconnaissance" in plan_exploit.milestones[0].title
    assert "Attack Vector Correlation" in plan_exploit.milestones[1].title

    # General forensic audit
    goal_general = AgentGoal(objective="Extract SMS and messaging evidence")
    plan_general = GoalPlan(goal_general)
    assert "Triage" in plan_general.milestones[0].title


def test_goal_plan_milestone_transitions():
    goal = AgentGoal(objective="Audit device")
    plan = GoalPlan(goal)

    active = plan.get_active_milestone()
    assert active is not None
    assert active.status == MilestoneStatus.PENDING

    # Transition to in-progress
    plan.update_milestone_progress("m1", MilestoneStatus.IN_PROGRESS)
    assert plan.milestones[0].status == MilestoneStatus.IN_PROGRESS
    assert plan.milestones[0].started_at is not None

    # Complete m1 with evidence
    plan.update_milestone_progress("m1", MilestoneStatus.COMPLETED, evidence="Device is rooted")
    assert plan.milestones[0].status == MilestoneStatus.COMPLETED
    assert "Device is rooted" in plan.milestones[0].evidence_found

    # Active should now be m2
    active2 = plan.get_active_milestone()
    assert active2 is not None
    assert active2.milestone_id == "m2"


def test_goal_plan_format_context():
    goal = AgentGoal(objective="Investigate threat")
    plan = GoalPlan(goal)
    plan.update_milestone_progress("m1", MilestoneStatus.COMPLETED, evidence="Checked ADB")

    context = plan.format_plan_context()
    assert "=== INVESTIGATION MILESTONE PLAN ===" in context
    assert "[COMPLETED ✓]" in context
    assert "Checked ADB" in context
