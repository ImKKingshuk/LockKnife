from __future__ import annotations

import logging
import pathlib
from collections.abc import Callable
from typing import Any

from lockknife.core.agent.memory import MemoryStore
from lockknife.core.agent.models import (
    AgentGoal,
    AgentRunResult,
    ModelDecision,
    ToolObservation,
    TurnRecord,
)
from lockknife.core.agent.planner import GoalPlan
from lockknife.core.agent.policy import ResearcherPolicy
from lockknife.core.agent.provider import (
    DeterministicMockProvider,
    LLMProvider,
    OpenAICompatibleProvider,
    ProviderConfig,
)
from lockknife.core.agent.steering import SteeringQueue
from lockknife.core.agent.subagent import SubagentManager
from lockknife.core.agent.tools import AgentToolRegistry
from lockknife.core.agent.turn import TurnEngine

logger = logging.getLogger("lockknife.agent.runtime")


class AutonomousRuntime:
    """The master runtime coordinating goal execution, memory, tools, and turn engine."""

    def __init__(
        self,
        *,
        goal: AgentGoal,
        case_dir: pathlib.Path | None = None,
        target_device: str | None = None,
        provider: LLMProvider | None = None,
        policy: ResearcherPolicy | None = None,
        plan: GoalPlan | None = None,
        steering: SteeringQueue | None = None,
        max_concurrency: int = 4,
        action_callback: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        on_turn_start: Callable[[int], None] | None = None,
        on_turn_decision: Callable[[TurnRecord], None] | None = None,
        on_tool_execute: Callable[[str, dict[str, Any]], None] | None = None,
        on_tool_result: Callable[[ToolObservation], None] | None = None,
    ) -> None:
        self.goal = goal
        self.policy = policy or ResearcherPolicy(unrestricted=True, auto_provision_case=True)
        self.case_dir = self.policy.ensure_case_workspace(case_dir)
        self.goal.case_dir = self.case_dir
        self.target_device = target_device or self.goal.target_device

        self.plan = plan or GoalPlan(goal)
        self.steering = steering or SteeringQueue()
        self.max_concurrency = max(1, max_concurrency)

        self.provider = provider or OpenAICompatibleProvider()
        self.memory = MemoryStore(case_dir=self.case_dir)

        # Wire subagent manager with a factory targeting this runtime class
        def _subagent_runtime_factory(
            sub_goal: AgentGoal, case_dir: pathlib.Path, target_device: str | None
        ) -> AutonomousRuntime:
            return AutonomousRuntime(
                goal=sub_goal,
                case_dir=case_dir,
                target_device=target_device,
                provider=self.provider,
                policy=self.policy,
                action_callback=action_callback,
                max_concurrency=self.max_concurrency,
            )

        self.subagent_manager = SubagentManager(
            parent_case_dir=self.case_dir,
            runtime_factory=_subagent_runtime_factory,
            parent_goal_id=self.goal.goal_id,
        )

        self.tools = AgentToolRegistry(
            case_dir=self.case_dir,
            target_serial=self.target_device,
            action_callback=action_callback,
            subagent_manager=self.subagent_manager,
            memory_store=self.memory,
        )

        self.turn_engine = TurnEngine(
            goal=self.goal,
            provider=self.provider,
            tools=self.tools,
            memory=self.memory,
            policy=self.policy,
            plan=self.plan,
            steering=self.steering,
            max_concurrency=self.max_concurrency,
            on_turn_start=on_turn_start,
            on_turn_decision=on_turn_decision,
            on_tool_execute=on_tool_execute,
            on_tool_result=on_tool_result,
        )

    def run(self) -> AgentRunResult:
        """Execute the goal to completion or terminal budget."""
        return self.turn_engine.run_loop()

    def steer(self, guidance: str) -> None:
        """Inject mid-flight guidance into the running agent's steering queue."""
        self.steering.push(guidance)

    def chat_step(self, user_input: str) -> str:
        """Interactive REPL single-step response generator."""
        self.turn_engine.working_memory.add_scratchpad_note(f"Operator instruction: {user_input}")
        messages = self.memory.build_llm_messages(
            self.turn_engine.working_memory, self.turn_engine.consolidated_summary
        )
        messages.append({"role": "user", "content": user_input})

        decision = self.provider.complete(
            messages=messages,
            tools=self.tools.get_tool_specs(),
        )

        turn_idx = len(self.turn_engine.working_memory.recent_turns) + 1

        if decision.is_tool_call:
            responses: list[str] = []
            observations: list[ToolObservation] = []
            if decision.reasoning:
                responses.append(f"Thinking: {decision.reasoning}\n")
            for call in decision.tool_calls:
                responses.append(f"-> Calling tool: {call.tool_id}({call.arguments})")
                auth = self.policy.authorize_tool(call.tool_id, call.arguments, self.case_dir)
                if not auth.allowed:
                    obs = ToolObservation(
                        call_id=call.call_id,
                        tool_id=call.tool_id,
                        success=False,
                        error=f"Denied: {auth.reason}",
                    )
                else:
                    obs = self.tools.execute(call)
                observations.append(obs)
                responses.append(
                    f"   Result: {'OK' if obs.success else 'FAILED'} (took {obs.duration_s:.2f}s)"
                )
                if obs.error:
                    responses.append(f"   Error: {obs.error}")

            turn_rec = TurnRecord(
                turn_index=turn_idx,
                decision=decision,
                observations=observations,
            )
            self.turn_engine.working_memory.recent_turns.append(turn_rec)
            self.memory.persist_turn(turn_rec)
            return "\n".join(responses)

        turn_rec = TurnRecord(
            turn_index=turn_idx,
            decision=decision,
        )
        self.turn_engine.working_memory.recent_turns.append(turn_rec)
        self.memory.persist_turn(turn_rec)
        return decision.text or "Acknowledged."
