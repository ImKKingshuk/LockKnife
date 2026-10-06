from __future__ import annotations

import pytest

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.dag import build_dag, resolve_execution_tiers
from lockknife.core.pipeline.models import StepDefinition


def test_build_valid_dag_and_resolve_tiers() -> None:
    s0 = StepDefinition(step_id="step.0", label="Root", action_id="act.0", category="core")
    s1 = StepDefinition(step_id="step.1", label="Branch A", action_id="act.1", category="core", depends_on=("step.0",))
    s2 = StepDefinition(step_id="step.2", label="Branch B", action_id="act.2", category="core", depends_on=("step.0",))
    s3 = StepDefinition(step_id="step.3", label="Join", action_id="act.3", category="core", depends_on=("step.1", "step.2"))

    dag = build_dag([s0, s1, s2, s3])
    assert dag.step_count == 4
    assert dag.dependencies["step.3"] == frozenset({"step.1", "step.2"})

    tiers = resolve_execution_tiers(dag)
    assert len(tiers) == 3
    # Tier 0 has step.0
    assert [s.step_id for s in tiers[0]] == ["step.0"]
    # Tier 1 has step.1 and step.2 (order in tier can vary)
    assert sorted(s.step_id for s in tiers[1]) == ["step.1", "step.2"]
    # Tier 2 has step.3
    assert [s.step_id for s in tiers[2]] == ["step.3"]


def test_duplicate_step_id_raises() -> None:
    s1 = StepDefinition(step_id="step.dup", label="One", action_id="act.1", category="core")
    s2 = StepDefinition(step_id="step.dup", label="Two", action_id="act.2", category="core")

    with pytest.raises(LockKnifeError, match="Duplicate step ID"):
        build_dag([s1, s2])


def test_missing_dependency_raises() -> None:
    s1 = StepDefinition(step_id="step.1", label="One", action_id="act.1", category="core", depends_on=("nonexistent",))

    with pytest.raises(LockKnifeError, match="depends on non-existent step 'nonexistent'"):
        build_dag([s1])


def test_cycle_detection_raises() -> None:
    s1 = StepDefinition(step_id="step.1", label="One", action_id="act.1", category="core", depends_on=("step.2",))
    s2 = StepDefinition(step_id="step.2", label="Two", action_id="act.2", category="core", depends_on=("step.1",))

    with pytest.raises(LockKnifeError, match="Cycle detected"):
        build_dag([s1, s2])


def test_empty_dag() -> None:
    dag = build_dag([])
    assert dag.step_count == 0
    assert resolve_execution_tiers(dag) == []
