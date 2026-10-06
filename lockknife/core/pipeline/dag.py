from __future__ import annotations

import collections
import dataclasses
from collections.abc import Sequence

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.models import StepDefinition


@dataclasses.dataclass(frozen=True)
class PipelineDAG:
    steps: dict[str, StepDefinition]
    dependencies: dict[str, frozenset[str]]
    dependents: dict[str, frozenset[str]]

    def get_step(self, step_id: str) -> StepDefinition | None:
        return self.steps.get(step_id)

    @property
    def step_count(self) -> int:
        return len(self.steps)


def build_dag(steps: Sequence[StepDefinition]) -> PipelineDAG:
    """Build and validate a directed acyclic graph from a list of steps.

    Raises LockKnifeError if duplicate IDs, missing dependencies, or cycles are found.
    """
    step_map: dict[str, StepDefinition] = {}
    for step in steps:
        if step.step_id in step_map:
            raise LockKnifeError(f"Duplicate step ID in pipeline: {step.step_id!r}")
        step_map[step.step_id] = step

    deps: dict[str, set[str]] = {}
    dependents: dict[str, set[str]] = collections.defaultdict(set)

    for step_id, step in step_map.items():
        step_deps = set(step.depends_on)
        for dep in step_deps:
            if dep not in step_map:
                raise LockKnifeError(
                    f"Step {step_id!r} depends on non-existent step {dep!r}"
                )
            dependents[dep].add(step_id)
        deps[step_id] = step_deps

    # Detect cycles via Kahn algorithm
    in_degree = {sid: len(deps[sid]) for sid in step_map}
    zero_in_degree = collections.deque([sid for sid, deg in in_degree.items() if deg == 0])
    visited_count = 0

    while zero_in_degree:
        current = zero_in_degree.popleft()
        visited_count += 1
        for downstream in dependents.get(current, set()):
            in_degree[downstream] -= 1
            if in_degree[downstream] == 0:
                zero_in_degree.append(downstream)

    if visited_count != len(step_map):
        cycle_candidates = [sid for sid, deg in in_degree.items() if deg > 0]
        raise LockKnifeError(
            f"Cycle detected in pipeline dependency graph among steps: {cycle_candidates}"
        )

    return PipelineDAG(
        steps=step_map,
        dependencies={sid: frozenset(d) for sid, d in deps.items()},
        dependents={sid: frozenset(dependents[sid]) for sid in step_map},
    )


def resolve_execution_tiers(dag: PipelineDAG) -> list[list[StepDefinition]]:
    """Partition steps into independent execution tiers.

    Tier 0 contains steps with zero dependencies.
    Tier N contains steps whose dependencies are all satisfied in Tiers < N.
    Within each tier, all steps can execute in parallel.
    """
    if not dag.steps:
        return []

    tiers: list[list[StepDefinition]] = []
    satisfied: set[str] = set()
    remaining = dict(dag.steps)

    while remaining:
        # Find all steps whose dependencies are completely satisfied
        current_tier_ids = [
            sid
            for sid, step in remaining.items()
            if dag.dependencies[sid].issubset(satisfied)
        ]

        if not current_tier_ids:
            # Should not happen if build_dag passed, but guard against infinite loop
            raise LockKnifeError("Unresolvable step dependencies encountered in DAG tiers")

        current_tier = [remaining.pop(sid) for sid in current_tier_ids]
        tiers.append(current_tier)
        satisfied.update(current_tier_ids)

    return tiers
