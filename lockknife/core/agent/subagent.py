from __future__ import annotations

import logging
import pathlib
import uuid
from typing import Any

from lockknife.core.agent.models import AgentGoal, AgentRunResult, GoalStatus

logger = logging.getLogger("lockknife.agent.subagent")


class SubagentManager:
    """Orchestrates nested, delegated agent runs for parallel deep-dives."""

    def __init__(
        self,
        *,
        parent_case_dir: pathlib.Path,
        runtime_factory: Any,
        parent_goal_id: str = "main",
    ) -> None:
        self.parent_case_dir = pathlib.Path(parent_case_dir).resolve()
        self.runtime_factory = runtime_factory
        self.parent_goal_id = parent_goal_id
        self.active_subagents: dict[str, AgentRunResult] = {}

    def spawn_and_run(
        self,
        objective: str,
        target_device: str | None = None,
        budget_iterations: int = 10,
    ) -> AgentRunResult:
        """Spawn a subagent runtime, execute the sub-goal, and collect results."""
        sub_id = f"sub_{str(uuid.uuid4())[:6]}"
        logger.info("Spawning subagent %s for objective: %s", sub_id, objective)

        sub_goal = AgentGoal(
            objective=objective,
            goal_id=sub_id,
            case_dir=self.parent_case_dir,
            target_device=target_device,
            budget_iterations=max(1, min(budget_iterations, 30)),
        )

        try:
            # Instantiate an isolated runtime for the subagent
            sub_runtime = self.runtime_factory(
                goal=sub_goal,
                case_dir=self.parent_case_dir,
                target_device=target_device,
            )
            result = sub_runtime.run()
            self.active_subagents[sub_id] = result
            return result
        except Exception as exc:
            logger.error("Subagent %s failed: %s", sub_id, exc)
            err_res = AgentRunResult(
                goal=sub_goal,
                status=GoalStatus.FAILED,
                final_response=f"Subagent execution failed: {exc}",
                error=str(exc),
            )
            self.active_subagents[sub_id] = err_res
            return err_res
