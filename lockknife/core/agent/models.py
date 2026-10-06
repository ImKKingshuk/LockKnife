from __future__ import annotations

import dataclasses
import enum
import pathlib
import time
import uuid
from typing import Any


class DecisionKind(str, enum.Enum):
    RESPOND = "respond"
    TOOL_CALL = "tool_call"
    CONTINUE = "continue"
    FINISH = "finish"


class GoalStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERRUPTED = "interrupted"


@dataclasses.dataclass(frozen=True)
class ToolInvocation:
    """A tool call proposed by the model."""
    call_id: str
    tool_id: str
    arguments: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolInvocation:
        return cls(
            call_id=str(data.get("call_id") or str(uuid.uuid4())[:8]),
            tool_id=str(data.get("tool_id") or ""),
            arguments=dict(data.get("arguments") or {}),
        )


@dataclasses.dataclass(frozen=True)
class ToolObservation:
    """The result of executing a tool call."""
    call_id: str
    tool_id: str
    success: bool
    output: Any = None
    error: str | None = None
    duration_s: float = 0.0
    artifacts_created: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "duration_s": self.duration_s,
            "artifacts_created": list(self.artifacts_created),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolObservation:
        return cls(
            call_id=str(data.get("call_id") or ""),
            tool_id=str(data.get("tool_id") or ""),
            success=bool(data.get("success", False)),
            output=data.get("output"),
            error=str(data.get("error")) if data.get("error") is not None else None,
            duration_s=float(data.get("duration_s", 0.0)),
            artifacts_created=list(data.get("artifacts_created") or []),
        )


@dataclasses.dataclass(frozen=True)
class ModelDecision:
    """State transition returned by the LLM Provider."""
    kind: DecisionKind
    text: str = ""
    tool_calls: list[ToolInvocation] = dataclasses.field(default_factory=list)
    reasoning: str | None = None

    @classmethod
    def respond(cls, text: str, reasoning: str | None = None) -> ModelDecision:
        return cls(kind=DecisionKind.RESPOND, text=text, reasoning=reasoning)

    @classmethod
    def call_tools(
        cls, tool_calls: list[ToolInvocation], reasoning: str | None = None
    ) -> ModelDecision:
        return cls(kind=DecisionKind.TOOL_CALL, tool_calls=tool_calls, reasoning=reasoning)

    @classmethod
    def continue_run(cls, reason: str = "") -> ModelDecision:
        return cls(kind=DecisionKind.CONTINUE, text=reason)

    @classmethod
    def finish(cls, outcome: str, reasoning: str | None = None) -> ModelDecision:
        return cls(kind=DecisionKind.FINISH, text=outcome, reasoning=reasoning)

    @property
    def is_tool_call(self) -> bool:
        return self.kind == DecisionKind.TOOL_CALL and len(self.tool_calls) > 0

    @property
    def is_terminal(self) -> bool:
        return self.kind in (DecisionKind.RESPOND, DecisionKind.FINISH)


@dataclasses.dataclass
class AgentGoal:
    """The mission objective and parameters for the autonomous agent."""
    objective: str
    goal_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4())[:8])
    case_dir: pathlib.Path | None = None
    target_device: str | None = None
    budget_iterations: int = 25
    created_at: float = dataclasses.field(default_factory=time.time)
    status: GoalStatus = GoalStatus.PENDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "objective": self.objective,
            "case_dir": str(self.case_dir) if self.case_dir else None,
            "target_device": self.target_device,
            "budget_iterations": self.budget_iterations,
            "created_at": self.created_at,
            "status": self.status.value,
        }


@dataclasses.dataclass
class TurnRecord:
    """A record of a single reasoning/action step."""
    turn_index: int
    decision: ModelDecision
    observations: list[ToolObservation] = dataclasses.field(default_factory=list)
    timestamp: float = dataclasses.field(default_factory=time.time)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_index": self.turn_index,
            "decision": {
                "kind": self.decision.kind.value,
                "text": self.decision.text,
                "reasoning": self.decision.reasoning,
                "tool_calls": [tc.to_dict() for tc in self.decision.tool_calls],
            },
            "observations": [obs.to_dict() for obs in self.observations],
            "timestamp": self.timestamp,
            "duration_s": self.duration_s,
        }


@dataclasses.dataclass
class AgentRunResult:
    """The final outcome of an autonomous agent run."""
    goal: AgentGoal
    status: GoalStatus
    final_response: str
    turns: list[TurnRecord] = dataclasses.field(default_factory=list)
    artifacts_created: list[str] = dataclasses.field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal.to_dict(),
            "status": self.status.value,
            "final_response": self.final_response,
            "turns_count": len(self.turns),
            "artifacts_created": self.artifacts_created,
            "duration_s": round(self.duration_s, 2),
            "error": self.error,
        }
