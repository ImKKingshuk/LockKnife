from __future__ import annotations

import dataclasses
import logging
from typing import Any

from lockknife.core.agent.models import ToolInvocation, ToolObservation
from lockknife.core.agent.planner import GoalPlan, MilestoneStatus

logger = logging.getLogger("lockknife.agent.reflexion")


@dataclasses.dataclass(frozen=True)
class ReflexionCritique:
    """The outcome of evaluative observation critique."""
    has_issues: bool
    critique_notes: list[str]
    suggested_recovery: str | None = None
    milestone_advance: str | None = None

    def format_prompt_block(self) -> str | None:
        if not self.has_issues and not self.milestone_advance:
            return None
        parts = ["=== EVALUATIVE SELF-CRITIQUE (REFLEXION) ==="]
        if self.milestone_advance:
            parts.append(f"✓ Progress Check: {self.milestone_advance}")
        if self.has_issues:
            parts.append("⚠️ Execution Critiques:")
            for note in self.critique_notes:
                parts.append(f"  - {note}")
            if self.suggested_recovery:
                parts.append(f"💡 Strategy Recovery Hint: {self.suggested_recovery}")
        return "\n".join(parts)


class ReflexionEngine:
    """Self-healing evaluative critic analyzing turn observations to prevent dead-ends."""

    def __init__(self, plan: GoalPlan | None = None) -> None:
        self.plan = plan

    def evaluate(
        self,
        calls: list[ToolInvocation],
        observations: list[ToolObservation],
    ) -> ReflexionCritique:
        critique_notes: list[str] = []
        has_issues = False
        suggested_recovery: str | None = None
        milestone_advance: str | None = None

        active_milestone = self.plan.get_active_milestone() if self.plan else None

        for _call, obs in zip(calls, observations):
            tool_id = obs.tool_id
            output_str = str(obs.output or "")
            err_str = str(obs.error or "")

            # 1. Error / Failure detection
            if not obs.success or obs.error:
                has_issues = True
                if "permission denied" in (err_str + output_str).lower():
                    critique_notes.append(
                        f"Action '{tool_id}' encountered permission restriction. Ensure ADB has proper privileges or try unprivileged alternatives."
                    )
                    suggested_recovery = "Pivot to alternative non-root export APIs or content provider queries."
                elif "not found" in (err_str + output_str).lower():
                    critique_notes.append(
                        f"Action '{tool_id}' reported missing target/command: {obs.error}. Verify paths or package names."
                    )
                    suggested_recovery = "List available packages with 'device_shell(command=\"pm list packages\")' to verify exact package name."
                elif "stall detected" in (err_str + output_str).lower():
                    critique_notes.append(
                        f"Action '{tool_id}' was flagged for repeated identical failure. Cease retrying this parameter set."
                    )
                    suggested_recovery = "Explore an alternative tool or vector to progress the active milestone."
                else:
                    critique_notes.append(f"Action '{tool_id}' failed: {obs.error or 'Non-zero return code'}")

            # 2. Progress / Success evaluation
            elif obs.success:
                # Check for milestone advancement clues
                if active_milestone and active_milestone.status == MilestoneStatus.PENDING:
                    active_milestone.start()

                # Triage milestone satisfied
                if active_milestone and "triage" in active_milestone.title.lower() and any(k in tool_id for k in ("health", "device", "info")):
                    milestone_advance = f"Milestone '{active_milestone.title}' validated by {tool_id}."
                    active_milestone.complete(f"Validated by {tool_id}")

        return ReflexionCritique(
            has_issues=has_issues,
            critique_notes=critique_notes,
            suggested_recovery=suggested_recovery,
            milestone_advance=milestone_advance,
        )
