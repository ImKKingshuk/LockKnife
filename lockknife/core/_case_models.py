from __future__ import annotations



import dataclasses

from typing import Any



@dataclasses.dataclass(frozen=True)
class CaseArtifact:
    artifact_id: str
    path: str
    category: str
    source_command: str
    sha256: str
    size_bytes: int
    created_at_utc: str
    device_serial: str | None = None
    input_paths: list[str] = dataclasses.field(default_factory=list)
    parent_artifact_ids: list[str] = dataclasses.field(default_factory=list)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass(frozen=True)
class CaseArtifactRegistration:
    artifact: CaseArtifact
    action: str

@dataclasses.dataclass(frozen=True)
class CaseJobStep:
    step_id: str
    label: str
    status: str
    started_at_utc: str
    ended_at_utc: str | None = None
    message: str | None = None

@dataclasses.dataclass(frozen=True)
class CaseJob:
    job_id: str
    action_id: str
    action_label: str
    workflow_kind: str
    status: str
    resumable: bool
    created_at_utc: str
    updated_at_utc: str
    started_at_utc: str
    ended_at_utc: str | None = None
    device_serial: str | None = None
    attempt_count: int = 1
    params: dict[str, Any] = dataclasses.field(default_factory=dict)
    latest_message: str | None = None
    error_message: str | None = None
    recovery_hint: str | None = None
    logs_path: str | None = None
    result_artifact_ids: list[str] = dataclasses.field(default_factory=list)
    steps: list[CaseJobStep] = dataclasses.field(default_factory=list)

@dataclasses.dataclass(frozen=True)
class CaseRuntimeScript:
    script_id: str
    label: str
    path: str
    sha256: str
    source_command: str
    created_at_utc: str
    source_kind: str = "snapshot"
    source_path: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass(frozen=True)
class CaseRuntimeSession:
    session_id: str
    name: str
    app_id: str
    session_kind: str
    attach_mode: str
    status: str
    created_at_utc: str
    updated_at_utc: str
    started_at_utc: str
    last_connected_at_utc: str | None = None
    ended_at_utc: str | None = None
    device_id: str | None = None
    pid: int | None = None
    connect_count: int = 0
    reload_count: int = 0
    event_count: int = 0
    last_event_at_utc: str | None = None
    active_script_id: str | None = None
    logs_path: str | None = None
    summary_path: str | None = None
    latest_message: str | None = None
    error_message: str | None = None
    recovery_hint: str | None = None
    result_artifact_ids: list[str] = dataclasses.field(default_factory=list)
    script_inventory: list[CaseRuntimeScript] = dataclasses.field(default_factory=list)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class CaseManifest:
    schema_version: int
    case_id: str
    title: str
    examiner: str
    notes: str | None
    created_at_utc: str
    updated_at_utc: str
    workspace_root: str
    target_serials: list[str] = dataclasses.field(default_factory=list)
    artifacts: list[CaseArtifact] = dataclasses.field(default_factory=list)
    jobs: list[CaseJob] = dataclasses.field(default_factory=list)
    runtime_sessions: list[CaseRuntimeSession] = dataclasses.field(default_factory=list)
