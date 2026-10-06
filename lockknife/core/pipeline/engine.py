from __future__ import annotations

import concurrent.futures
import pathlib
import sys
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

from lockknife.core._case_common import _utc_now
from lockknife.core._case_store import is_case_workspace
from lockknife.core.case import create_case_workspace, load_case_manifest
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.checkpoint import (
    find_latest_checkpoint,
    load_checkpoint,
    save_checkpoint,
)
from lockknife.core.pipeline.dag import PipelineDAG, build_dag, resolve_execution_tiers
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


class PipelineExecutor:
    """Autonomous DAG-based pipeline execution engine for LockKnife investigations."""

    def __init__(
        self,
        *,
        case_dir: pathlib.Path,
        target_serial: str | None = None,
        concurrency: int = 4,
    ) -> None:
        self.case_dir = pathlib.Path(case_dir).resolve()
        self.target_serial = target_serial
        self.concurrency = max(1, concurrency)
        self._device_lock = threading.Lock()
        self._action_callback: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None

    def _get_action_callback(self) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
        if self._action_callback is None:
            try:
                from lockknife_headless_cli.tui_callback import build_tui_callback

                self._action_callback = build_tui_callback(None)
            except Exception as exc:
                raise LockKnifeError(f"Failed to initialize action callback: {exc}") from exc
        return self._action_callback

    def plan(self, playbook: PlaybookDefinition) -> dict[str, Any]:
        """Preview and validate the execution plan for a playbook without running actions."""
        dag = build_dag(playbook.steps)
        tiers = resolve_execution_tiers(dag)

        plan_tiers: list[list[dict[str, Any]]] = []
        for _tier_idx, tier_steps in enumerate(tiers):
            tier_payload: list[dict[str, Any]] = []
            for step in tier_steps:
                tier_payload.append(
                    {
                        "step_id": step.step_id,
                        "label": step.label,
                        "action_id": step.action_id,
                        "category": step.category,
                        "depends_on": list(step.depends_on),
                        "requires_device": step.requires_device,
                        "fallback_action_id": step.fallback_action_id,
                        "optional": step.optional,
                    }
                )
            plan_tiers.append(tier_payload)

        device_required = any(s.requires_device for s in playbook.steps)

        return {
            "playbook_name": playbook.name,
            "title": playbook.title,
            "description": playbook.description,
            "category": playbook.category,
            "case_dir": str(self.case_dir),
            "target_serial": self.target_serial,
            "requires_device": device_required,
            "total_steps": len(playbook.steps),
            "tier_count": len(tiers),
            "concurrency": self.concurrency,
            "tiers": plan_tiers,
        }

    def execute(
        self,
        playbook: PlaybookDefinition,
        *,
        resume: bool = False,
        dry_run: bool = False,
        pipeline_id: str | None = None,
        on_step_start: Callable[[StepDefinition], None] | None = None,
        on_step_complete: Callable[[StepDefinition, StepExecutionRecord], None] | None = None,
    ) -> PipelineSummary:
        """Execute an autonomous investigation playbook across topological DAG tiers."""
        t_start = time.perf_counter()

        # Ensure case workspace exists
        if not is_case_workspace(self.case_dir):
            create_case_workspace(
                case_dir=self.case_dir,
                case_id=self.case_dir.name or "CASE-AUTO",
                examiner="LockKnife Pipeline",
                title=f"Autonomous Pipeline: {playbook.title}",
            )

        dag = build_dag(playbook.steps)
        tiers = resolve_execution_tiers(dag)

        # Initialize or restore checkpoint
        checkpoint: PipelineCheckpoint
        step_records: dict[str, StepExecutionRecord] = {}

        if resume:
            existing: PipelineCheckpoint | None = None
            if pipeline_id:
                try:
                    existing = load_checkpoint(self.case_dir, pipeline_id)
                except Exception:
                    existing = None
            if existing is None:
                existing = find_latest_checkpoint(self.case_dir, playbook.name)

            if existing is not None:
                checkpoint = existing
                step_records = dict(existing.step_records)
            else:
                resume = False

        if not resume:
            active_id = pipeline_id or f"pipe-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
            now = _utc_now()
            checkpoint = PipelineCheckpoint(
                pipeline_id=active_id,
                playbook_name=playbook.name,
                case_dir=str(self.case_dir),
                target_serial=self.target_serial,
                status=PipelineStatus.RUNNING,
                started_at_utc=now,
                updated_at_utc=now,
                step_records={},
                metadata={"title": playbook.title, "dry_run": dry_run},
            )
            save_checkpoint(checkpoint)

        if dry_run:
            now = _utc_now()
            preview_records: list[StepExecutionRecord] = []
            for step in playbook.steps:
                rec = StepExecutionRecord(
                    step_id=step.step_id,
                    status=StepStatus.COMPLETED,
                    started_at_utc=now,
                    ended_at_utc=now,
                    duration_ms=0.0,
                    tier=AcquisitionTier.LOCAL_DERIVED,
                    summary={"dry_run": True, "action_id": step.action_id},
                )
                preview_records.append(rec)
                step_records[step.step_id] = rec

            summary_cp = PipelineCheckpoint(
                pipeline_id=checkpoint.pipeline_id,
                playbook_name=playbook.name,
                case_dir=str(self.case_dir),
                target_serial=self.target_serial,
                status=PipelineStatus.COMPLETED,
                started_at_utc=checkpoint.started_at_utc,
                updated_at_utc=now,
                ended_at_utc=now,
                step_records=step_records,
                metadata={"dry_run": True},
            )
            cp_path = save_checkpoint(summary_cp)

            return PipelineSummary(
                pipeline_id=checkpoint.pipeline_id,
                playbook_name=playbook.name,
                case_dir=str(self.case_dir),
                target_serial=self.target_serial,
                status=PipelineStatus.COMPLETED,
                duration_s=round(time.perf_counter() - t_start, 2),
                total_steps=len(playbook.steps),
                completed_steps=len(playbook.steps),
                skipped_steps=0,
                failed_steps=0,
                artifacts_collected=0,
                step_records=tuple(preview_records),
                checkpoint_path=str(cp_path),
            )

        dispatch_cb = self._get_action_callback()

        # Execute tiers sequentially, with parallel steps inside each tier
        for tier in tiers:
            # Check dependency satisfaction
            runnable_steps: list[StepDefinition] = []
            for step in tier:
                # If already completed from a resumed checkpoint, keep it
                existing_rec = step_records.get(step.step_id)
                if existing_rec and existing_rec.status == StepStatus.COMPLETED:
                    continue

                # Check if dependencies succeeded
                deps_satisfied = True
                failed_dep = ""
                for dep_id in step.depends_on:
                    dep_rec = step_records.get(dep_id)
                    dep_step = dag.get_step(dep_id)
                    is_dep_optional = dep_step.optional if dep_step else False

                    if not dep_rec or dep_rec.status != StepStatus.COMPLETED:
                        if not is_dep_optional:
                            deps_satisfied = False
                            failed_dep = dep_id
                            break

                if not deps_satisfied:
                    # Mark as skipped
                    now = _utc_now()
                    skip_rec = StepExecutionRecord(
                        step_id=step.step_id,
                        status=StepStatus.SKIPPED,
                        started_at_utc=now,
                        ended_at_utc=now,
                        duration_ms=0.0,
                        error_message=f"Prerequisite step failed: {failed_dep}",
                    )
                    step_records[step.step_id] = skip_rec
                    if on_step_complete:
                        on_step_complete(step, skip_rec)
                    continue

                runnable_steps.append(step)

            if not runnable_steps:
                continue

            # Execute runnable steps
            def _execute_single_step(step_def: StepDefinition) -> StepExecutionRecord:
                if on_step_start:
                    on_step_start(step_def)

                step_start = time.perf_counter()
                now_utc = _utc_now()

                # Build action params
                params: dict[str, Any] = dict(step_def.params)
                params["case_dir"] = str(self.case_dir)
                if self.target_serial:
                    params["serial"] = self.target_serial
                    params["device_id"] = self.target_serial

                used_fallback = False
                res: dict[str, Any] = {}
                tier_used = AcquisitionTier.LOCAL_DERIVED

                # Execute with device mutex if step accesses physical device
                if step_def.requires_device:
                    with self._device_lock:
                        tier_used = AcquisitionTier.DIRECT
                        try:
                            res = dispatch_cb(step_def.action_id, params)
                        except Exception as exc:
                            res = {"ok": False, "error": str(exc)}

                        # If primary action failed and a fallback action exists, attempt fallback
                        if not res.get("ok") and step_def.fallback_action_id:
                            used_fallback = True
                            tier_used = AcquisitionTier.PROVIDER_BACKUP
                            try:
                                res = dispatch_cb(step_def.fallback_action_id, params)
                            except Exception as exc:
                                res = {"ok": False, "error": str(exc)}
                else:
                    # Offline processing runs parallel without holding device mutex
                    try:
                        res = dispatch_cb(step_def.action_id, params)
                    except Exception as exc:
                        res = {"ok": False, "error": str(exc)}

                duration_ms = round((time.perf_counter() - step_start) * 1000.0, 2)
                end_utc = _utc_now()

                ok = bool(res.get("ok", False))
                err_msg = res.get("error") if not ok else None
                recovery_hint = res.get("recovery_hint")

                if ok:
                    step_status = StepStatus.COMPLETED
                elif step_def.optional:
                    step_status = StepStatus.PARTIAL
                else:
                    step_status = StepStatus.FAILED

                record = StepExecutionRecord(
                    step_id=step_def.step_id,
                    status=step_status,
                    started_at_utc=now_utc,
                    ended_at_utc=end_utc,
                    duration_ms=duration_ms,
                    tier=tier_used,
                    summary=res if isinstance(res, dict) else {},
                    error_message=err_msg,
                    recovery_hint=recovery_hint,
                    used_fallback=used_fallback,
                )

                if on_step_complete:
                    on_step_complete(step_def, record)

                return record

            # Run steps within tier using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                future_to_step = {
                    pool.submit(_execute_single_step, s): s for s in runnable_steps
                }
                for future in concurrent.futures.as_completed(future_to_step):
                    step_def = future_to_step[future]
                    try:
                        rec = future.result()
                    except Exception as exc:
                        now = _utc_now()
                        rec = StepExecutionRecord(
                            step_id=step_def.step_id,
                            status=StepStatus.FAILED,
                            started_at_utc=now,
                            ended_at_utc=now,
                            error_message=f"Step execution crashed: {exc}",
                        )
                    step_records[step_def.step_id] = rec

            # Persist checkpoint at completion of each tier
            checkpoint = PipelineCheckpoint(
                pipeline_id=checkpoint.pipeline_id,
                playbook_name=playbook.name,
                case_dir=str(self.case_dir),
                target_serial=self.target_serial,
                status=PipelineStatus.RUNNING,
                started_at_utc=checkpoint.started_at_utc,
                updated_at_utc=_utc_now(),
                step_records=step_records,
                metadata={"title": playbook.title},
            )
            save_checkpoint(checkpoint)

        # Final tally
        completed_count = sum(1 for r in step_records.values() if r.status == StepStatus.COMPLETED)
        skipped_count = sum(1 for r in step_records.values() if r.status == StepStatus.SKIPPED)
        failed_count = sum(1 for r in step_records.values() if r.status == StepStatus.FAILED)

        if failed_count == 0:
            final_status = PipelineStatus.COMPLETED
        elif completed_count > 0:
            final_status = PipelineStatus.PARTIAL
        else:
            final_status = PipelineStatus.FAILED

        ended_utc = _utc_now()
        final_checkpoint = PipelineCheckpoint(
            pipeline_id=checkpoint.pipeline_id,
            playbook_name=playbook.name,
            case_dir=str(self.case_dir),
            target_serial=self.target_serial,
            status=final_status,
            started_at_utc=checkpoint.started_at_utc,
            updated_at_utc=ended_utc,
            ended_at_utc=ended_utc,
            step_records=step_records,
            metadata={"title": playbook.title},
        )
        cp_path = save_checkpoint(final_checkpoint)

        # Count artifacts from case manifest
        artifacts_count = 0
        try:
            m = load_case_manifest(self.case_dir)
            artifacts_count = len(m.artifacts)
        except Exception:
            pass

        duration_total = round(time.perf_counter() - t_start, 2)

        return PipelineSummary(
            pipeline_id=checkpoint.pipeline_id,
            playbook_name=playbook.name,
            case_dir=str(self.case_dir),
            target_serial=self.target_serial,
            status=final_status,
            duration_s=duration_total,
            total_steps=len(playbook.steps),
            completed_steps=completed_count,
            skipped_steps=skipped_count,
            failed_steps=failed_count,
            artifacts_collected=artifacts_count,
            step_records=tuple(step_records.values()),
            checkpoint_path=str(cp_path),
        )
