from __future__ import annotations

import json
import pathlib
from typing import Any

import click


def register(case_group: Any, cli: Any) -> None:
    @case_group.command("jobs")
    @click.option(
        "--case-dir",
        type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path),
        required=True,
    )
    @click.option("--status", "statuses", multiple=True)
    @click.option("--workflow", "workflows", multiple=True)
    @click.option("--action", "actions", multiple=True)
    @click.option("--query")
    @click.option("--limit", type=int)
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["text", "json"], case_sensitive=False),
        default="text",
    )
    def jobs_cmd(
        case_dir: pathlib.Path,
        statuses: tuple[str, ...],
        workflows: tuple[str, ...],
        actions: tuple[str, ...],
        query: str | None,
        limit: int | None,
        out_format: str,
    ) -> None:
        payload = cli.query_case_jobs(
            case_dir,
            statuses=list(statuses) if statuses else None,
            workflow_kinds=list(workflows) if workflows else None,
            action_ids=list(actions) if actions else None,
            query=query,
            limit=limit,
        )
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return

        lines = [
            f"Case Jobs: {payload['case_id']} | title={payload['title']}",
            f"Jobs: {payload['job_count']} of {payload['total_job_count']}",
        ]
        filters = []
        if statuses:
            filters.append(f"status={', '.join(statuses)}")
        if workflows:
            filters.append(f"workflow={', '.join(workflows)}")
        if actions:
            filters.append(f"action={', '.join(actions)}")
        if query:
            filters.append(f"query={query}")
        if limit:
            filters.append(f"limit={limit}")
        if filters:
            lines.append("Filters: " + " | ".join(filters))
        lines.append("")

        if not payload["jobs"]:
            lines.append("- none")
        else:
            for job in payload["jobs"]:
                device_str = f" device={job['device_serial']}" if job.get("device_serial") else ""
                resumable_str = " [resumable]" if job.get("resumable") and job["status"] in ("failed", "partial", "cancelled") else ""
                lines.append(
                    f"- {job['job_id']} | {job['status']}{resumable_str} | {job['action_id']} ({job['action_label']}) | attempts={job['attempt_count']}{device_str}"
                )
                if job.get("latest_message"):
                    lines.append(f"    message: {job['latest_message']}")
                if job.get("error_message"):
                    lines.append(f"    error: {job['error_message']}")
                if job.get("recovery_hint"):
                    lines.append(f"    recovery hint: {job['recovery_hint']}")

        cli.console.print("\n".join(lines), markup=False)

    @case_group.command("job")
    @click.option(
        "--case-dir",
        type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path),
        required=True,
    )
    @click.option("--job-id", required=True)
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["text", "json"], case_sensitive=False),
        default="text",
    )
    def job_cmd(
        case_dir: pathlib.Path,
        job_id: str,
        out_format: str,
    ) -> None:
        payload = cli.case_job_details(case_dir, job_id=job_id)
        if payload is None:
            raise click.ClickException(f"Job {job_id} not found in case {case_dir}")
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return

        job = payload["job"]
        lines = [
            f"Case: {payload['case_id']}",
            f"Job: {job['job_id']} | {job['status']} | {job['action_id']} ({job['action_label']})",
            f"Workflow: {job['workflow_kind']} | attempts={job['attempt_count']} | resumable={job['resumable']}",
            f"Started: {job['started_at_utc']} | Updated: {job['updated_at_utc']} | Ended: {job['ended_at_utc'] or 'running'}",
        ]
        if job.get("device_serial"):
            lines.append(f"Device: {job['device_serial']}")
        if job.get("latest_message"):
            lines.append(f"Message: {job['latest_message']}")
        if job.get("error_message"):
            lines.append(f"Error: {job['error_message']}")
        if job.get("recovery_hint"):
            lines.append(f"Recovery Hint: {job['recovery_hint']}")

        lines.append("")
        lines.append("Parameters:")
        if job.get("params"):
            for k, v in sorted(job["params"].items()):
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  none")

        lines.append("")
        lines.append("Steps:")
        if job.get("steps"):
            for step in job["steps"]:
                step_msg = f" - {step['message']}" if step.get("message") else ""
                lines.append(f"  - [{step['status']}] {step['step_id']}: {step['label']}{step_msg}")
        else:
            lines.append("  none")

        lines.append("")
        lines.append(f"Result Artifacts: {', '.join(job.get('result_artifact_ids', [])) or 'none'}")
        if job.get("logs_path"):
            lines.append(f"Logs Path: {job['logs_path']}")

        if job.get("logs_tail"):
            lines.append("")
            lines.append("Recent Logs:")
            for log_entry in job["logs_tail"]:
                ts = log_entry.get("timestamp_utc", "")
                lvl = log_entry.get("level", "info").upper()
                msg = log_entry.get("message", "")
                lines.append(f"  [{ts}] [{lvl}] {msg}")

        cli.console.print("\n".join(lines), markup=False)

    @case_group.command("resume")
    @click.option(
        "--case-dir",
        type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path),
        required=True,
    )
    @click.option("--job-id", required=True)
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Print the resume execution plan without dispatching.",
    )
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["text", "json"], case_sensitive=False),
        default="text",
    )
    def resume_cmd(
        case_dir: pathlib.Path,
        job_id: str,
        dry_run: bool,
        out_format: str,
    ) -> None:
        try:
            payload = cli.case_job_rerun_context(case_dir, job_id=job_id, mode="resume")
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        if payload is None:
            raise click.ClickException(f"Job {job_id} not found")

        if dry_run:
            if out_format.lower() == "json":
                cli.console.print_json(json.dumps(payload))
                return
            lines = [
                f"Resume Plan for Job: {job_id}",
                f"Action: {payload['action_id']} ({payload['action_label']})",
                f"Case Directory: {case_dir}",
                "Parameters:",
            ]
            for k, v in sorted(payload["params"].items()):
                lines.append(f"  {k}: {v}")
            cli.console.print("\n".join(lines), markup=False)
            return

        from lockknife_headless_cli.tui_callback import build_tui_callback

        execution_params = dict(payload["params"])
        execution_params["case_dir"] = str(case_dir)
        execution_params["resume_job_id"] = payload["job"]["job_id"]

        callback = build_tui_callback()
        result_raw = callback(str(payload["action_id"]), execution_params)
        if out_format.lower() == "json":
            cli.console.print(result_raw, markup=False)
            return

        try:
            parsed = json.loads(result_raw)
            ok = parsed.get("ok", True)
            msg = parsed.get("message", "Completed")
            status_tag = "[OK]" if ok else "[FAILED]"
            cli.console.print(f"{status_tag} Resumed job {job_id} ({payload['action_id']}): {msg}", markup=False)
        except Exception:
            cli.console.print(f"Resumed job {job_id} ({payload['action_id']}):\n{result_raw}", markup=False)

    @case_group.command("retry")
    @click.option(
        "--case-dir",
        type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path),
        required=True,
    )
    @click.option("--job-id", required=True)
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Print the retry execution plan without dispatching.",
    )
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["text", "json"], case_sensitive=False),
        default="text",
    )
    def retry_cmd(
        case_dir: pathlib.Path,
        job_id: str,
        dry_run: bool,
        out_format: str,
    ) -> None:
        try:
            payload = cli.case_job_rerun_context(case_dir, job_id=job_id, mode="retry")
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        if payload is None:
            raise click.ClickException(f"Job {job_id} not found")

        if dry_run:
            if out_format.lower() == "json":
                cli.console.print_json(json.dumps(payload))
                return
            lines = [
                f"Retry Plan for Job: {job_id}",
                f"Action: {payload['action_id']} ({payload['action_label']})",
                f"Attempt Count: {payload['job']['attempt_count'] + 1}",
                f"Case Directory: {case_dir}",
                "Parameters:",
            ]
            for k, v in sorted(payload["params"].items()):
                lines.append(f"  {k}: {v}")
            cli.console.print("\n".join(lines), markup=False)
            return

        from lockknife_headless_cli.tui_callback import build_tui_callback

        execution_params = dict(payload["params"])
        execution_params["case_dir"] = str(case_dir)
        execution_params["retry_job_id"] = payload["job"]["job_id"]

        callback = build_tui_callback()
        result_raw = callback(str(payload["action_id"]), execution_params)
        if out_format.lower() == "json":
            cli.console.print(result_raw, markup=False)
            return

        try:
            parsed = json.loads(result_raw)
            ok = parsed.get("ok", True)
            msg = parsed.get("message", "Completed")
            status_tag = "[OK]" if ok else "[FAILED]"
            cli.console.print(f"{status_tag} Retried job {job_id} ({payload['action_id']}): {msg}", markup=False)
        except Exception:
            cli.console.print(f"Retried job {job_id} ({payload['action_id']}):\n{result_raw}", markup=False)
