from __future__ import annotations

import collections
import logging
import time
from collections.abc import Callable
from typing import Any

from lockknife.core.agent.memory import MemoryStore, WorkingMemory
from lockknife.core.agent.models import (
    AgentGoal,
    AgentRunResult,
    DecisionKind,
    GoalStatus,
    ModelDecision,
    ToolObservation,
    TurnRecord,
)
from lockknife.core.agent.policy import ResearcherPolicy
from lockknife.core.agent.provider import LLMProvider
from lockknife.core.agent.tools import AgentToolRegistry

logger = logging.getLogger("lockknife.agent.turn")

_SYSTEM_AGENT_PROMPT = """You are LockKnife Agent, an autonomous Android security research, mobile forensics, and ethical hacking AI.
Your objective is to accomplish the user's mission using the available tools.

Guidelines:
1. Formulate a structured plan and execute tools sequentially or in logical batches.
2. Carefully inspect tool observations. If a command or exploit fails, analyze the error, adjust your hypothesis, and pivot to alternative methods.
3. Use 'device_shell' for raw adb commands when granular terminal checks or getprop/pm inspections are needed.
4. Record key findings, credentials, and package names as persistent facts using 'record_fact'.
5. When the mission objective is achieved, provide a clear, comprehensive final report detailing:
   - Summary of actions executed
   - Evidence & forensic findings discovered
   - Security vulnerabilities identified
   - Recommendations
"""


class TurnEngine:
    """The autonomous reasoning and execution loop engine."""

    def __init__(
        self,
        *,
        goal: AgentGoal,
        provider: LLMProvider,
        tools: AgentToolRegistry,
        memory: MemoryStore,
        policy: ResearcherPolicy,
        on_turn_start: Callable[[int], None] | None = None,
        on_turn_decision: Callable[[TurnRecord], None] | None = None,
        on_tool_execute: Callable[[str, dict[str, Any]], None] | None = None,
        on_tool_result: Callable[[ToolObservation], None] | None = None,
    ) -> None:
        self.goal = goal
        self.provider = provider
        self.tools = tools
        self.memory = memory
        self.policy = policy
        self.working_memory = WorkingMemory(goal=goal)
        self.consolidated_summary: str | None = None

        # Observer hooks for CLI/TUI feedback
        self.on_turn_start = on_turn_start
        self.on_turn_decision = on_turn_decision
        self.on_tool_execute = on_tool_execute
        self.on_tool_result = on_tool_result

        # Stall / Loop detection
        self._recent_tool_signatures: collections.deque[str] = collections.deque(maxlen=6)

    def run_loop(self) -> AgentRunResult:
        """Run the autonomous turn engine until goal satisfaction or termination condition."""
        start_time = time.time()
        self.goal.status = GoalStatus.ACTIVE
        turns: list[TurnRecord] = []
        all_artifacts: list[str] = []
        current_iteration = 0

        logger.info("Starting autonomous turn loop for goal '%s'", self.goal.objective)

        while current_iteration < self.goal.budget_iterations:
            current_iteration += 1
            turn_start = time.time()
            if self.on_turn_start:
                self.on_turn_start(current_iteration)

            # 1. Governance & Context Compaction
            self.working_memory, self.consolidated_summary = self.memory.check_and_compact(
                self.working_memory, self.consolidated_summary
            )

            # 2. Build Context Messages
            messages = self.memory.build_llm_messages(
                self.working_memory, self.consolidated_summary
            )

            # 3. Model Reasoning Call
            tool_specs = self.tools.get_tool_specs()
            decision = self.provider.complete(
                messages=messages,
                tools=tool_specs,
                system_prompt=_SYSTEM_AGENT_PROMPT,
            )

            turn_record = TurnRecord(turn_index=current_iteration, decision=decision)

            if self.on_turn_decision:
                self.on_turn_decision(turn_record)

            # 4. Handle Decision
            if not decision.is_tool_call:
                # Model produced terminal answer or conclusion
                turn_record.duration_s = time.time() - turn_start
                turns.append(turn_record)
                self.working_memory.recent_turns.append(turn_record)
                self.memory.persist_turn(turn_record)

                self.goal.status = GoalStatus.COMPLETED
                return AgentRunResult(
                    goal=self.goal,
                    status=GoalStatus.COMPLETED,
                    final_response=decision.text or "Mission completed successfully.",
                    turns=turns,
                    artifacts_created=all_artifacts,
                    duration_s=time.time() - start_time,
                )

            # 5. Execute Proposed Tool Calls
            observations: list[ToolObservation] = []
            for call in decision.tool_calls:
                sig = f"{call.tool_id}:{sorted(call.arguments.items())}"
                self._recent_tool_signatures.append(sig)

                # Stall prevention: detect repeated identical calls
                if self._recent_tool_signatures.count(sig) >= 3:
                    logger.warning("Repeated tool call detected for %s", call.tool_id)
                    obs = ToolObservation(
                        call_id=call.call_id,
                        tool_id=call.tool_id,
                        success=False,
                        error="Stall detected: repeated identical tool call. Pivot to a different approach.",
                        duration_s=0.0,
                    )
                    observations.append(obs)
                    continue

                if self.on_tool_execute:
                    self.on_tool_execute(call.tool_id, call.arguments)

                # Authorize via policy
                auth = self.policy.authorize_tool(
                    call.tool_id, call.arguments, case_dir=self.memory.case_dir
                )
                if not auth.allowed:
                    obs = ToolObservation(
                        call_id=call.call_id,
                        tool_id=call.tool_id,
                        success=False,
                        error=f"Permission denied: {auth.reason}",
                        duration_s=0.0,
                    )
                else:
                    # Execute tool
                    obs = self.tools.execute(call)
                    # Check for oversized output & truncate if needed
                    preview, artifact_path = self.memory.truncate_observation_payload(
                        obs.tool_id, obs.output
                    )
                    if artifact_path:
                        all_artifacts.append(artifact_path)
                    if obs.artifacts_created:
                        all_artifacts.extend(obs.artifacts_created)

                    obs = ToolObservation(
                        call_id=obs.call_id,
                        tool_id=obs.tool_id,
                        success=obs.success,
                        output=preview,
                        error=obs.error,
                        duration_s=obs.duration_s,
                        artifacts_created=obs.artifacts_created,
                    )

                if self.on_tool_result:
                    self.on_tool_result(obs)
                observations.append(obs)

            turn_record.observations = observations
            turn_record.duration_s = time.time() - turn_start
            turns.append(turn_record)
            self.working_memory.recent_turns.append(turn_record)
            self.memory.persist_turn(turn_record)

        # Budget exhausted: Request one final conclusion synthesis
        self.goal.status = GoalStatus.BUDGET_EXHAUSTED
        summary_messages = self.memory.build_llm_messages(
            self.working_memory, self.consolidated_summary
        )
        summary_messages.append({
            "role": "user",
            "content": "Turn budget reached. Please provide your final forensic summary and conclusions based on all evidence collected so far.",
        })
        final_dec = self.provider.complete(messages=summary_messages, tools=None)

        return AgentRunResult(
            goal=self.goal,
            status=GoalStatus.BUDGET_EXHAUSTED,
            final_response=final_dec.text or "Turn budget exhausted before mission completion.",
            turns=turns,
            artifacts_created=all_artifacts,
            duration_s=time.time() - start_time,
        )
