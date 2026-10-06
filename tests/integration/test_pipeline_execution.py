from __future__ import annotations

import pathlib

from lockknife.core.case import load_case_manifest
from lockknife.core.pipeline import (
    PipelineExecutor,
    PlaybookDefinition,
    StepDefinition,
    list_checkpoints,
    load_checkpoint,
)


def test_end_to_end_pipeline_execution_in_case_workspace(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "CASE-E2E"

    step1 = StepDefinition(
        step_id="report.stage1",
        label="Pre-Report Initialization",
        action_id="report.generate",
        category="reporting",
        params={"template": "technical", "format": "json"},
    )
    step2 = StepDefinition(
        step_id="report.stage2",
        label="Final Report Synthesis",
        action_id="report.generate",
        category="reporting",
        depends_on=("report.stage1",),
        params={"template": "technical", "format": "json"},
    )

    playbook = PlaybookDefinition(
        name="e2e-pipeline",
        title="E2E Pipeline Test",
        description="Verifies full pipeline execution against real case workspace.",
        category="integration",
        steps=(step1, step2),
    )

    executor = PipelineExecutor(case_dir=case_dir, concurrency=2)
    summary = executor.execute(playbook)

    assert summary.status.value in {"completed", "partial"}
    assert summary.total_steps == 2
    assert summary.completed_steps == 2

    # Verify checkpoint on disk
    checkpoints = list_checkpoints(case_dir)
    assert len(checkpoints) == 1
    cp = checkpoints[0]
    assert cp.pipeline_id == summary.pipeline_id
    assert cp.playbook_name == "e2e-pipeline"
    assert "report.stage1" in cp.step_records
    assert "report.stage2" in cp.step_records

    # Verify manifest exists and is valid
    manifest = load_case_manifest(case_dir)
    assert manifest.case_id == "CASE-E2E"
