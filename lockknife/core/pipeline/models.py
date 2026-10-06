from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


class AcquisitionTier(str, Enum):
    DIRECT = "direct"
    ROOT_STAGED = "root_staged"
    PROVIDER_BACKUP = "provider_backup"
    OFFLINE_CARVED = "offline_carved"
    LOCAL_DERIVED = "local_derived"
    NOT_APPLICABLE = "not_applicable"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    PARTIAL = "partial"


class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclasses.dataclass(frozen=True)
class StepDefinition:
    step_id: str
    label: str
    action_id: str
    category: str
    depends_on: tuple[str, ...] = ()
    requires_device: bool = False
    fallback_action_id: str | None = None
    timeout_s: float = 300.0
    params: dict[str, Any] = dataclasses.field(default_factory=dict)
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "label": self.label,
            "action_id": self.action_id,
            "category": self.category,
            "depends_on": list(self.depends_on),
            "requires_device": self.requires_device,
            "fallback_action_id": self.fallback_action_id,
            "timeout_s": self.timeout_s,
            "params": dict(self.params),
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StepDefinition:
        return cls(
            step_id=str(data["step_id"]),
            label=str(data.get("label", data["step_id"])),
            action_id=str(data["action_id"]),
            category=str(data.get("category", "general")),
            depends_on=tuple(str(d) for d in data.get("depends_on", ())),
            requires_device=bool(data.get("requires_device", False)),
            fallback_action_id=data.get("fallback_action_id"),
            timeout_s=float(data.get("timeout_s", 300.0)),
            params=dict(data.get("params", {})),
            optional=bool(data.get("optional", False)),
        )


@dataclasses.dataclass(frozen=True)
class StepExecutionRecord:
    step_id: str
    status: StepStatus
    started_at_utc: str | None = None
    ended_at_utc: str | None = None
    duration_ms: float = 0.0
    tier: AcquisitionTier = AcquisitionTier.NOT_APPLICABLE
    artifact_ids: tuple[str, ...] = ()
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    error_message: str | None = None
    recovery_hint: str | None = None
    attempt_count: int = 1
    used_fallback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "status": self.status.value,
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "duration_ms": self.duration_ms,
            "tier": self.tier.value,
            "artifact_ids": list(self.artifact_ids),
            "summary": dict(self.summary),
            "error_message": self.error_message,
            "recovery_hint": self.recovery_hint,
            "attempt_count": self.attempt_count,
            "used_fallback": self.used_fallback,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StepExecutionRecord:
        tier_raw = data.get("tier", AcquisitionTier.NOT_APPLICABLE.value)
        try:
            tier = AcquisitionTier(tier_raw)
        except ValueError:
            tier = AcquisitionTier.NOT_APPLICABLE

        status_raw = data.get("status", StepStatus.PENDING.value)
        try:
            status = StepStatus(status_raw)
        except ValueError:
            status = StepStatus.PENDING

        return cls(
            step_id=str(data["step_id"]),
            status=status,
            started_at_utc=data.get("started_at_utc"),
            ended_at_utc=data.get("ended_at_utc"),
            duration_ms=float(data.get("duration_ms", 0.0)),
            tier=tier,
            artifact_ids=tuple(str(a) for a in data.get("artifact_ids", ())),
            summary=dict(data.get("summary", {})),
            error_message=data.get("error_message"),
            recovery_hint=data.get("recovery_hint"),
            attempt_count=int(data.get("attempt_count", 1)),
            used_fallback=bool(data.get("used_fallback", False)),
        )


@dataclasses.dataclass(frozen=True)
class PlaybookDefinition:
    name: str
    title: str
    description: str
    category: str
    steps: tuple[StepDefinition, ...]
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "steps": [s.to_dict() for s in self.steps],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlaybookDefinition:
        return cls(
            name=str(data["name"]),
            title=str(data.get("title", data["name"])),
            description=str(data.get("description", "")),
            category=str(data.get("category", "general")),
            steps=tuple(StepDefinition.from_dict(s) for s in data.get("steps", ())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclasses.dataclass(frozen=True)
class PipelineCheckpoint:
    pipeline_id: str
    playbook_name: str
    case_dir: str
    target_serial: str | None
    status: PipelineStatus
    started_at_utc: str
    updated_at_utc: str
    ended_at_utc: str | None = None
    step_records: dict[str, StepExecutionRecord] = dataclasses.field(default_factory=dict)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "playbook_name": self.playbook_name,
            "case_dir": self.case_dir,
            "target_serial": self.target_serial,
            "status": self.status.value,
            "started_at_utc": self.started_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "step_records": {k: v.to_dict() for k, v in self.step_records.items()},
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PipelineCheckpoint:
        status_raw = data.get("status", PipelineStatus.PENDING.value)
        try:
            status = PipelineStatus(status_raw)
        except ValueError:
            status = PipelineStatus.PENDING

        step_records: dict[str, StepExecutionRecord] = {}
        for k, v in data.get("step_records", {}).items():
            if isinstance(v, dict):
                step_records[k] = StepExecutionRecord.from_dict(v)

        return cls(
            pipeline_id=str(data["pipeline_id"]),
            playbook_name=str(data["playbook_name"]),
            case_dir=str(data["case_dir"]),
            target_serial=data.get("target_serial"),
            status=status,
            started_at_utc=str(data["started_at_utc"]),
            updated_at_utc=str(data["updated_at_utc"]),
            ended_at_utc=data.get("ended_at_utc"),
            step_records=step_records,
            metadata=dict(data.get("metadata", {})),
        )


@dataclasses.dataclass(frozen=True)
class PipelineSummary:
    pipeline_id: str
    playbook_name: str
    case_dir: str
    target_serial: str | None
    status: PipelineStatus
    duration_s: float
    total_steps: int
    completed_steps: int
    skipped_steps: int
    failed_steps: int
    artifacts_collected: int
    step_records: tuple[StepExecutionRecord, ...]
    checkpoint_path: str
    report_artifact_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "playbook_name": self.playbook_name,
            "case_dir": self.case_dir,
            "target_serial": self.target_serial,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 2),
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "skipped_steps": self.skipped_steps,
            "failed_steps": self.failed_steps,
            "artifacts_collected": self.artifacts_collected,
            "checkpoint_path": self.checkpoint_path,
            "report_artifact_id": self.report_artifact_id,
            "step_records": [r.to_dict() for r in self.step_records],
        }
