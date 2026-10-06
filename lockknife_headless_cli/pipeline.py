from __future__ import annotations

import json
import pathlib
from typing import Any

import click
from rich.table import Table

from lockknife.core.cli_instrumentation import LockKnifeCommand, LockKnifeGroup
from lockknife.core.output import console
from lockknife.core.pipeline import (
    BUILTIN_PLAYBOOKS,
    PipelineExecutor,
    PlaybookDefinition,
    get_playbook,
    list_checkpoints,
    list_playbooks,
    load_checkpoint,
    load_custom_playbook,
)


@click.group("pipeline", cls=LockKnifeGroup, help="Autonomous multi-stage investigation pipeline engine.")
def pipeline_group() -> None:
    pass


@pipeline_group.command("list", cls=LockKnifeCommand, help="List available autonomous investigation playbooks.")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format.",
)
def pipeline_list_cmd(out_format: str) -> None:
    playbooks = list_playbooks()
    if out_format.lower() == "json":
        console.print_json(json.dumps([p.to_dict() for p in playbooks]))
        return

    table = Table(title="LockKnife Autonomous Playbooks")
    table.add_column("Playbook", style="cyan")
    table.add_column("Title", style="bold white")
    table.add_column("Category", style="green")
    table.add_column("Steps", justify="right", style="yellow")
    table.add_column("Description")

    for pb in playbooks:
        table.add_row(
            pb.name,
            pb.title,
            pb.category,
            str(len(pb.steps)),
            pb.description,
        )

    console.print(table)


@pipeline_group.command("plan", cls=LockKnifeCommand, help="Inspect DAG tiers and execution plan for a playbook.")
@click.option("--playbook", "-p", default="triage", help="Playbook name to inspect.")
@click.option("--recipe", type=click.Path(path_type=pathlib.Path), help="Path to custom YAML/JSON playbook recipe.")
@click.option("--case-dir", type=click.Path(path_type=pathlib.Path), default="./cases/CASE-PREVIEW", help="Target case directory.")
@click.option("--serial", "-s", help="Target device serial (optional).")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format.",
)
def pipeline_plan_cmd(
    playbook: str,
    recipe: pathlib.Path | None,
    case_dir: pathlib.Path,
    serial: str | None,
    out_format: str,
) -> None:
    if recipe is not None:
        pb = load_custom_playbook(recipe)
    else:
        pb = get_playbook(playbook)

    executor = PipelineExecutor(case_dir=case_dir, target_serial=serial)
    plan_data = executor.plan(pb)

    if out_format.lower() == "json":
        console.print_json(json.dumps(plan_data))
        return

    console.print(f"[bold cyan]Playbook:[/] [bold white]{pb.title}[/] ({pb.name})")
    console.print(f"[dim]{pb.description}[/]\n")
    console.print(f"• Total Steps: [bold]{plan_data['total_steps']}[/] across [bold]{plan_data['tier_count']}[/] topological tiers")
    console.print(f"• Target Device: [yellow]{serial or 'none (offline)'}[/]")
    console.print(f"• Case Workspace: [dim]{case_dir}[/]\n")

    for idx, tier in enumerate(plan_data["tiers"]):
        table = Table(title=f"Execution Tier {idx} ({len(tier)} concurrent steps)", expand=True)
        table.add_column("Step ID", style="cyan")
        table.add_column("Action", style="green")
        table.add_column("Category", style="magenta")
        table.add_column("Requires Device", justify="center")
        table.add_column("Depends On", style="yellow")
        table.add_column("Fallback Action")

        for step in tier:
            table.add_row(
                step["step_id"],
                step["action_id"],
                step["category"],
                "Yes" if step["requires_device"] else "No",
                ", ".join(step["depends_on"]) or "-",
                step["fallback_action_id"] or "-",
            )
        console.print(table)
        console.print("")


@pipeline_group.command("run", cls=LockKnifeCommand, help="Execute an autonomous investigation pipeline.")
@click.option("--playbook", "-p", default="triage", help="Playbook name to execute.")
@click.option("--recipe", type=click.Path(path_type=pathlib.Path), help="Path to custom YAML/JSON playbook recipe.")
@click.option("--case-dir", "-c", required=True, type=click.Path(path_type=pathlib.Path), help="Case directory for evidence and checkpoint.")
@click.option("--serial", "-s", help="Target device serial.")
@click.option("--concurrency", "-j", default=4, type=int, help="Parallel concurrency for independent steps.")
@click.option("--dry-run", is_flag=True, help="Simulate execution without running underlying actions.")
@click.option("--resume", is_flag=True, help="Resume an existing pipeline from its latest checkpoint.")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format.",
)
def pipeline_run_cmd(
    playbook: str,
    recipe: pathlib.Path | None,
    case_dir: pathlib.Path,
    serial: str | None,
    concurrency: int,
    dry_run: bool,
    resume: bool,
    out_format: str,
) -> None:
    if recipe is not None:
        pb = load_custom_playbook(recipe)
    else:
        pb = get_playbook(playbook)

    executor = PipelineExecutor(
        case_dir=case_dir,
        target_serial=serial,
        concurrency=concurrency,
    )

    if out_format.lower() != "json":
        console.print(f"[bold cyan]Starting Autonomous Pipeline:[/] [bold white]{pb.title}[/]")
        console.print(f"[dim]Case: {case_dir.resolve()} | Concurrency: {concurrency} | Dry-run: {dry_run}[/]\n")

    summary = executor.execute(
        pb,
        resume=resume,
        dry_run=dry_run,
        on_step_start=lambda s: console.print(f"  [cyan]▶ Running:[/] {s.label} ({s.step_id})...") if out_format.lower() != "json" else None,
        on_step_complete=lambda s, r: console.print(
            f"  [{'green' if r.status.value == 'completed' else 'yellow' if r.status.value == 'partial' else 'red'}]"
            f"✓ {s.label}: {r.status.value.upper()}[/] ({r.duration_ms:.1f}ms)"
            + (" [dim](fallback used)[/]" if r.used_fallback else "")
        ) if out_format.lower() != "json" else None,
    )

    if out_format.lower() == "json":
        console.print_json(json.dumps(summary.to_dict()))
        return

    console.print("\n[bold]═══════════════════════════════════════════════════[/]")
    console.print(f"[bold cyan]Pipeline Summary:[/] [bold { 'green' if summary.status.value == 'completed' else 'yellow' }]{summary.status.value.upper()}[/]")
    console.print(f"• Pipeline ID: [white]{summary.pipeline_id}[/]")
    console.print(f"• Completed Steps: [green]{summary.completed_steps}[/] / [white]{summary.total_steps}[/]")
    if summary.skipped_steps:
        console.print(f"• Skipped Steps: [yellow]{summary.skipped_steps}[/]")
    if summary.failed_steps:
        console.print(f"• Failed Steps: [red]{summary.failed_steps}[/]")
    console.print(f"• Duration: [white]{summary.duration_s:.2f}s[/]")
    console.print(f"• Checkpoint: [dim]{summary.checkpoint_path}[/]")
    console.print("[bold]═══════════════════════════════════════════════════[/]\n")


@pipeline_group.command("resume", cls=LockKnifeCommand, help="Resume an interrupted pipeline from checkpoint.")
@click.option("--case-dir", "-c", required=True, type=click.Path(path_type=pathlib.Path), help="Case directory containing checkpoint.")
@click.option("--pipeline-id", help="Specific pipeline ID to resume (defaults to latest).")
@click.option("--serial", "-s", help="Target device serial.")
@click.option("--concurrency", "-j", default=4, type=int, help="Parallel concurrency for independent steps.")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format.",
)
def pipeline_resume_cmd(
    case_dir: pathlib.Path,
    pipeline_id: str | None,
    serial: str | None,
    concurrency: int,
    out_format: str,
) -> None:
    cps = list_checkpoints(case_dir)
    if not cps:
        raise click.ClickException(f"No pipeline checkpoints found in {case_dir}")

    target_cp = None
    if pipeline_id:
        try:
            target_cp = load_checkpoint(case_dir, pipeline_id)
        except Exception as exc:
            raise click.ClickException(f"Failed to load checkpoint {pipeline_id}: {exc}") from exc
    else:
        target_cp = cps[0]

    try:
        pb = get_playbook(target_cp.playbook_name)
    except Exception as exc:
        raise click.ClickException(f"Failed to load playbook for checkpoint: {exc}") from exc

    executor = PipelineExecutor(
        case_dir=case_dir,
        target_serial=serial or target_cp.target_serial,
        concurrency=concurrency,
    )

    if out_format.lower() != "json":
        console.print(f"[bold cyan]Resuming Pipeline:[/] [bold white]{target_cp.pipeline_id}[/] ({pb.title})")

    summary = executor.execute(
        pb,
        resume=True,
        pipeline_id=target_cp.pipeline_id,
        on_step_start=lambda s: console.print(f"  [cyan]▶ Running:[/] {s.label} ({s.step_id})...") if out_format.lower() != "json" else None,
        on_step_complete=lambda s, r: console.print(
            f"  [{'green' if r.status.value == 'completed' else 'yellow' if r.status.value == 'partial' else 'red'}]"
            f"✓ {s.label}: {r.status.value.upper()}[/] ({r.duration_ms:.1f}ms)"
        ) if out_format.lower() != "json" else None,
    )

    if out_format.lower() == "json":
        console.print_json(json.dumps(summary.to_dict()))
        return

    console.print(f"\n[bold green]Resumed Pipeline Finished:[/] {summary.status.value.upper()} ({summary.duration_s:.2f}s)")


@pipeline_group.command("status", cls=LockKnifeCommand, help="Check status of pipelines in a case workspace.")
@click.option("--case-dir", "-c", required=True, type=click.Path(path_type=pathlib.Path), help="Case directory.")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format.",
)
def pipeline_status_cmd(case_dir: pathlib.Path, out_format: str) -> None:
    cps = list_checkpoints(case_dir)
    if out_format.lower() == "json":
        console.print_json(json.dumps([cp.to_dict() for cp in cps]))
        return

    if not cps:
        console.print(f"[yellow]No pipeline checkpoints found in {case_dir}[/]")
        return

    table = Table(title=f"Pipelines in {case_dir}")
    table.add_column("Pipeline ID", style="cyan")
    table.add_column("Playbook", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Steps Done", justify="right")
    table.add_column("Started (UTC)")
    table.add_column("Updated (UTC)")

    for cp in cps:
        completed = sum(1 for r in cp.step_records.values() if r.status.value == "completed")
        total = len(cp.step_records)
        style = "green" if cp.status.value == "completed" else "yellow" if cp.status.value == "running" else "red"
        table.add_row(
            cp.pipeline_id,
            cp.playbook_name,
            f"[{style}]{cp.status.value.upper()}[/]",
            f"{completed}/{total}",
            cp.started_at_utc[:19] if cp.started_at_utc else "-",
            cp.updated_at_utc[:19] if cp.updated_at_utc else "-",
        )

    console.print(table)
