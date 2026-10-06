from __future__ import annotations

import dataclasses
import enum
import time
from typing import Any

from lockknife.core.agent.models import AgentGoal


class MilestoneStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclasses.dataclass
class PlanMilestone:
    """A discrete milestone within an autonomous investigation plan."""
    milestone_id: str
    title: str
    description: str
    status: MilestoneStatus = MilestoneStatus.PENDING
    evidence_found: list[str] = dataclasses.field(default_factory=list)
    started_at: float | None = None
    completed_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "milestone_id": self.milestone_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "evidence_found": self.evidence_found,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    def start(self) -> None:
        self.status = MilestoneStatus.IN_PROGRESS
        self.started_at = time.time()

    def complete(self, evidence: str | None = None) -> None:
        self.status = MilestoneStatus.COMPLETED
        self.completed_at = time.time()
        if evidence:
            self.evidence_found.append(evidence)

    def block(self, reason: str) -> None:
        self.status = MilestoneStatus.BLOCKED
        self.evidence_found.append(f"Blocked: {reason}")


class GoalPlan:
    """Structured hierarchical milestone plan driving agentic goal execution."""

    def __init__(self, goal: AgentGoal, milestones: list[PlanMilestone] | None = None) -> None:
        self.goal = goal
        self.milestones: list[PlanMilestone] = milestones or self._generate_default_milestones(goal)

    @classmethod
    def _generate_default_milestones(cls, goal: AgentGoal) -> list[PlanMilestone]:
        """Synthesize default investigation milestones tailored to the objective."""
        obj_lower = goal.objective.lower()

        if any(w in obj_lower for w in ("apk", "app", "decompile", "manifest")):
            return [
                PlanMilestone(
                    milestone_id="m1",
                    title="Target Identification & Static Analysis",
                    description="Locate package, inspect AndroidManifest.xml, permissions, and exported components.",
                ),
                PlanMilestone(
                    milestone_id="m2",
                    title="Vulnerability Discovery & Code Audit",
                    description="Decompile DEX, scan for hardcoded credentials, API keys, and insecure exported surfaces.",
                ),
                PlanMilestone(
                    milestone_id="m3",
                    title="Evidence Synthesis & Reporting",
                    description="Compile findings into structured risk assessment and actionable mitigations.",
                ),
            ]

        if any(w in obj_lower for w in ("exploit", "cve", "root", "bypass")):
            return [
                PlanMilestone(
                    milestone_id="m1",
                    title="Device Environment Reconnaissance",
                    description="Query device build, kernel version, patch level, and SELinux enforcement status.",
                ),
                PlanMilestone(
                    milestone_id="m2",
                    title="Attack Vector Correlation",
                    description="Match kernel/OS version to viable CVEs and check permission elevation surfaces.",
                ),
                PlanMilestone(
                    milestone_id="m3",
                    title="Verification & Forensic Artifact Collection",
                    description="Validate impact safely, collect exploit telemetry, and log artifacts to case custody.",
                ),
            ]

        # Standard Mobile Forensics & Security Audit default plan
        return [
            PlanMilestone(
                milestone_id="m1",
                title="Target Triage & Connectivity Verification",
                description="Establish device communication, verify authorization, and catalog system baseline.",
            ),
            PlanMilestone(
                milestone_id="m2",
                title="Investigative Extraction & Surface Analysis",
                description="Execute targeted forensic data extraction or vulnerability scanning per objective.",
            ),
            PlanMilestone(
                milestone_id="m3",
                title="Artifact Correlation & Finding Synthesis",
                description="Analyze collected databases, logs, and indicators to fulfill mission objective.",
            ),
        ]

    def get_active_milestone(self) -> PlanMilestone | None:
        """Return the first in-progress or pending milestone."""
        for m in self.milestones:
            if m.status in (MilestoneStatus.IN_PROGRESS, MilestoneStatus.PENDING):
                return m
        return None

    def update_milestone_progress(
        self,
        milestone_id: str,
        status: MilestoneStatus,
        evidence: str | None = None,
    ) -> bool:
        for m in self.milestones:
            if m.milestone_id == milestone_id:
                if status == MilestoneStatus.IN_PROGRESS:
                    m.start()
                elif status == MilestoneStatus.COMPLETED:
                    m.complete(evidence)
                elif status == MilestoneStatus.BLOCKED:
                    m.block(evidence or "Unspecified blocker")
                else:
                    m.status = status
                return True
        return False

    def is_fully_completed(self) -> bool:
        return all(m.status in (MilestoneStatus.COMPLETED, MilestoneStatus.SKIPPED) for m in self.milestones)

    def format_plan_context(self) -> str:
        """Format the plan as a high-density status markdown table for LLM prompt context."""
        lines = ["=== INVESTIGATION MILESTONE PLAN ==="]
        for idx, m in enumerate(self.milestones, 1):
            icon = {
                MilestoneStatus.COMPLETED: "[COMPLETED ✓]",
                MilestoneStatus.IN_PROGRESS: "[IN-PROGRESS ⚡]",
                MilestoneStatus.PENDING: "[PENDING ⏳]",
                MilestoneStatus.BLOCKED: "[BLOCKED ⚠️]",
                MilestoneStatus.SKIPPED: "[SKIPPED -]",
            }.get(m.status, "[PENDING]")

            line = f"{idx}. {icon} {m.title}: {m.description}"
            if m.evidence_found:
                line += f"\n   ↳ Notes: {'; '.join(m.evidence_found[-2:])}"
            lines.append(line)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "milestones": [m.to_dict() for m in self.milestones],
            "all_completed": self.is_fully_completed(),
        }
