from __future__ import annotations

import pathlib
from unittest.mock import MagicMock

from lockknife.core.agent.models import AgentGoal, AgentRunResult, GoalStatus
from lockknife.core.agent.subagent import SubagentManager


def test_subagent_manager_spawn_and_run(tmp_path: pathlib.Path):
    mock_runtime_instance = MagicMock()
    mock_runtime_instance.run.return_value = AgentRunResult(
        goal=AgentGoal(objective="Sub mission"),
        status=GoalStatus.COMPLETED,
        final_response="Subagent found vulnerable endpoint /api/v1/debug",
        artifacts_created=["sub_evidence.json"],
    )

    mock_factory = MagicMock(return_value=mock_runtime_instance)

    manager = SubagentManager(parent_case_dir=tmp_path, runtime_factory=mock_factory)

    result = manager.spawn_and_run(
        objective="Inspect app APK",
        target_device="test-dev-1",
        budget_iterations=8,
    )

    assert result.status == GoalStatus.COMPLETED
    assert "Subagent found vulnerable" in result.final_response
    assert "sub_evidence.json" in result.artifacts_created
    assert len(manager.active_subagents) == 1
