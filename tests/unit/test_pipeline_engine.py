from __future__ import annotations

import pathlib
from typing import Any

from lockknife.core.pipeline.engine import PipelineExecutor
from lockknife.core.pipeline.models import (
    AcquisitionTier,
    PipelineStatus,
    PlaybookDefinition,
    StepDefinition,
    StepStatus,
)


def test_executor_plan(tmp_path: pathlib.Path) -> None:
    step1 = StepDefinition(step_id="s1", label="Step 1", action_id="act.1", category="core")
    step2 = StepDefinition(step_id="s2", label="Step 2", action_id="act.2", category="core", depends_on=("s1",))
    pb = PlaybookDefinition(
        name="test-plan",
        title="Test Plan",
        description="Description",
        category="core",
        steps=(step1, step2),
    )

    executor = PipelineExecutor(case_dir=tmp_path / "case-plan", target_serial="DEV-001")
    plan = executor.plan(pb)

    assert plan["playbook_name"] == "test-plan"
    assert plan["total_steps"] == 2
    assert plan["tier_count"] == 2
    assert plan["target_serial"] == "DEV-001"


def test_executor_dry_run(tmp_path: pathlib.Path) -> None:
    step1 = StepDefinition(step_id="s1", label="Step 1", action_id="act.1", category="core")
    pb = PlaybookDefinition(
        name="test-dry",
        title="Test Dry",
        description="Description",
        category="core",
        steps=(step1,),
    )

    executor = PipelineExecutor(case_dir=tmp_path / "case-dry")
    summary = executor.execute(pb, dry_run=True)

    assert summary.status == PipelineStatus.COMPLETED
    assert summary.completed_steps == 1
    assert summary.total_steps == 1
    assert pathlib.Path(summary.checkpoint_path).exists()


def test_executor_with_fallback_and_dependency_skip(tmp_path: pathlib.Path) -> None:
    # s1 succeeds
    step1 = StepDefinition(step_id="s1", label="Step 1", action_id="act.1", category="core")
    # s2 fails with primary act.2, but succeeds with fallback act.2.fb
    step2 = StepDefinition(
        step_id="s2",
        label="Step 2",
        action_id="act.2",
        category="core",
        fallback_action_id="act.2.fb",
        requires_device=True,
    )
    # s3 fails fatally
    step3 = StepDefinition(step_id="s3", label="Step 3", action_id="act.3", category="core")
    # s4 depends on s3, so should be skipped!
    step4 = StepDefinition(step_id="s4", label="Step 4", action_id="act.4", category="core", depends_on=("s3",))

    pb = PlaybookDefinition(
        name="test-workflow",
        title="Test Workflow",
        description="Description",
        category="core",
        steps=(step1, step2, step3, step4),
    )

    executor = PipelineExecutor(case_dir=tmp_path / "case-exec", target_serial="DEV-1")

    # Mock dispatch callback
    def mock_dispatch(action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action == "act.1":
            return {"ok": True, "data": "success"}
        if action == "act.2":
            return {"ok": False, "error": "permission denied"}
        if action == "act.2.fb":
            return {"ok": True, "data": "fallback success"}
        if action == "act.3":
            return {"ok": False, "error": "fatal failure"}
        return {"ok": True}

    executor._action_callback = mock_dispatch

    summary = executor.execute(pb)

    assert summary.total_steps == 4
    assert summary.completed_steps == 2  # s1 and s2 (via fallback)
    assert summary.failed_steps == 1     # s3
    assert summary.skipped_steps == 1    # s4
    assert summary.status == PipelineStatus.PARTIAL

    records = {r.step_id: r for r in summary.step_records}
    assert records["s1"].status == StepStatus.COMPLETED
    assert records["s2"].status == StepStatus.COMPLETED
    assert records["s2"].used_fallback is True
    assert records["s3"].status == StepStatus.FAILED
    assert records["s4"].status == StepStatus.SKIPPED


def test_executor_resumption(tmp_path: pathlib.Path) -> None:
    step1 = StepDefinition(step_id="s1", label="Step 1", action_id="act.1", category="core")
    step2 = StepDefinition(step_id="s2", label="Step 2", action_id="act.2", category="core", depends_on=("s1",))

    pb = PlaybookDefinition(
        name="test-resume",
        title="Test Resume",
        description="Description",
        category="core",
        steps=(step1, step2),
    )

    case_dir = tmp_path / "case-resume"
    executor = PipelineExecutor(case_dir=case_dir)

    call_count = {"act.1": 0, "act.2": 0}

    # Pass 1: s1 succeeds, s2 fails
    def mock_dispatch_pass1(action: str, params: dict[str, Any]) -> dict[str, Any]:
        call_count[action] += 1
        if action == "act.1":
            return {"ok": True}
        return {"ok": False, "error": "temporary error"}

    executor._action_callback = mock_dispatch_pass1
    sum1 = executor.execute(pb)
    assert sum1.completed_steps == 1
    assert sum1.failed_steps == 1
    assert call_count["act.1"] == 1
    assert call_count["act.2"] == 1

    # Pass 2: Resume with fixed s2
    def mock_dispatch_pass2(action: str, params: dict[str, Any]) -> dict[str, Any]:
        call_count[action] += 1
        return {"ok": True}

    executor._action_callback = mock_dispatch_pass2
    sum2 = executor.execute(pb, resume=True)

    assert sum2.status == PipelineStatus.COMPLETED
    assert sum2.completed_steps == 2
    # act.1 should NOT be called again during resume!
    assert call_count["act.1"] == 1
    # act.2 was retried and succeeded
    assert call_count["act.2"] == 2
