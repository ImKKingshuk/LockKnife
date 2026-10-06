from __future__ import annotations

import json

from lockknife.core.pipeline.models import (
    AcquisitionTier,
    PipelineCheckpoint,
    PipelineStatus,
    PipelineSummary,
    PlaybookDefinition,
    StepDefinition,
    StepExecutionRecord,
    StepStatus,
)


def test_step_definition_roundtrip() -> None:
    step = StepDefinition(
        step_id="test.step",
        label="Test Step",
        action_id="security.scan",
        category="security",
        depends_on=("init.step",),
        requires_device=True,
        fallback_action_id="security.fallback",
        timeout_s=120.0,
        params={"depth": "full"},
        optional=True,
    )
    data = step.to_dict()
    restored = StepDefinition.from_dict(data)

    assert restored.step_id == "test.step"
    assert restored.label == "Test Step"
    assert restored.action_id == "security.scan"
    assert restored.category == "security"
    assert restored.depends_on == ("init.step",)
    assert restored.requires_device is True
    assert restored.fallback_action_id == "security.fallback"
    assert restored.timeout_s == 120.0
    assert restored.params == {"depth": "full"}
    assert restored.optional is True


def test_step_execution_record_roundtrip() -> None:
    rec = StepExecutionRecord(
        step_id="step.01",
        status=StepStatus.COMPLETED,
        started_at_utc="2026-10-06T10:00:00Z",
        ended_at_utc="2026-10-06T10:00:05Z",
        duration_ms=5000.0,
        tier=AcquisitionTier.ROOT_STAGED,
        artifact_ids=("art-001", "art-002"),
        summary={"extracted_count": 42},
        error_message=None,
        used_fallback=True,
    )
    data = rec.to_dict()
    restored = StepExecutionRecord.from_dict(data)

    assert restored.step_id == "step.01"
    assert restored.status == StepStatus.COMPLETED
    assert restored.tier == AcquisitionTier.ROOT_STAGED
    assert restored.artifact_ids == ("art-001", "art-002")
    assert restored.used_fallback is True
    assert restored.summary == {"extracted_count": 42}


def test_playbook_definition_roundtrip() -> None:
    step = StepDefinition(
        step_id="s1",
        label="Step 1",
        action_id="act.1",
        category="core",
    )
    pb = PlaybookDefinition(
        name="custom-pb",
        title="Custom Playbook",
        description="A test playbook.",
        category="testing",
        steps=(step,),
        metadata={"author": "Researcher"},
    )
    data = pb.to_dict()
    restored = PlaybookDefinition.from_dict(data)

    assert restored.name == "custom-pb"
    assert restored.title == "Custom Playbook"
    assert len(restored.steps) == 1
    assert restored.steps[0].step_id == "s1"
    assert restored.metadata["author"] == "Researcher"


def test_pipeline_checkpoint_roundtrip() -> None:
    rec = StepExecutionRecord(
        step_id="s1",
        status=StepStatus.COMPLETED,
        tier=AcquisitionTier.DIRECT,
    )
    cp = PipelineCheckpoint(
        pipeline_id="pipe-12345",
        playbook_name="triage",
        case_dir="/tmp/case-123",
        target_serial="SERIAL-001",
        status=PipelineStatus.RUNNING,
        started_at_utc="2026-10-06T10:00:00Z",
        updated_at_utc="2026-10-06T10:05:00Z",
        step_records={"s1": rec},
    )
    data = cp.to_dict()
    json_str = json.dumps(data)
    restored = PipelineCheckpoint.from_dict(json.loads(json_str))

    assert restored.pipeline_id == "pipe-12345"
    assert restored.playbook_name == "triage"
    assert restored.target_serial == "SERIAL-001"
    assert restored.status == PipelineStatus.RUNNING
    assert "s1" in restored.step_records
    assert restored.step_records["s1"].status == StepStatus.COMPLETED


def test_pipeline_summary_to_dict() -> None:
    summary = PipelineSummary(
        pipeline_id="pipe-99",
        playbook_name="triage",
        case_dir="/tmp/case-99",
        target_serial=None,
        status=PipelineStatus.COMPLETED,
        duration_s=12.345,
        total_steps=5,
        completed_steps=5,
        skipped_steps=0,
        failed_steps=0,
        artifacts_collected=3,
        step_records=(),
        checkpoint_path="/tmp/case-99/pipelines/pipe-99.json",
    )
    data = summary.to_dict()
    assert data["pipeline_id"] == "pipe-99"
    assert data["status"] == "completed"
    assert data["duration_s"] == 12.35
    assert data["completed_steps"] == 5
