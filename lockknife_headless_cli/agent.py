from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

import click
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from lockknife.core.agent import (
    AgentGoal,
    AgentRunResult,
    AutonomousRuntime,
    DeterministicMockProvider,
    DeviceHeartbeatDaemon,
    GoalStatus,
    ModelDecision,
    OpenAICompatibleProvider,
    ProviderConfig,
    ResearcherPolicy,
    ToolInvocation,
)
from lockknife.core.cli_instrumentation import LockKnifeCommand, LockKnifeGroup
from lockknife.core.output import console


@click.group("agent", cls=LockKnifeGroup, help="Autonomous agent execution kernel for security research and forensics.")
def agent_group() -> None:
    pass


@agent_group.command("goal", cls=LockKnifeCommand, help="Execute an autonomous goal-driven investigation mission.")
@click.argument("objective", type=str)
@click.option("--case-dir", type=click.Path(path_type=pathlib.Path), default=None, help="Case workspace directory (auto-created if omitted).")
@click.option("--target", "target_device", type=str, default=None, help="Target device serial.")
@click.option("--budget", "budget_iterations", type=int, default=25, show_default=True, help="Maximum turn loop budget.")
@click.option("--model", type=str, default=None, help="LLM model name.")
@click.option("--api-base", type=str, default=None, help="LLM API base URL (e.g. http://localhost:11434/v1).")
@click.option("--api-key", type=str, default=None, help="LLM API key.")
@click.option("--mock", is_flag=True, default=False, help="Use deterministic mock provider for testing.")
@click.option("--unrestricted/--restricted", default=True, show_default=True, help="Researcher autonomy mode (bypasses confirmation gates).")
@click.option("--concurrency", type=int, default=4, show_default=True, help="Concurrency limit for parallel tool execution.")
@click.option("--format", "out_format", type=click.Choice(["text", "json", "markdown"], case_sensitive=False), default="text", help="Output format.")
def agent_goal_cmd(
    objective: str,
    case_dir: pathlib.Path | None,
    target_device: str | None,
    budget_iterations: int,
    model: str | None,
    api_base: str | None,
    api_key: str | None,
    mock: bool,
    unrestricted: bool,
    concurrency: int,
    out_format: str,
) -> None:
    goal = AgentGoal(
        objective=objective,
        target_device=target_device,
        budget_iterations=budget_iterations,
    )

    policy = ResearcherPolicy(unrestricted=unrestricted, auto_provision_case=True)

    if mock:
        provider = DeterministicMockProvider([
            ModelDecision.call_tools([
                ToolInvocation(call_id="call_triage", tool_id="core.health", arguments={})
            ], reasoning="Initiating automated triage on target."),
            ModelDecision.finish(
                f"Mission completed: Successfully investigated objective: '{objective}'. Target status verified.",
                reasoning="Verification completed.",
            ),
        ])
    else:
        cfg = ProviderConfig.from_env()
        if model:
            cfg = ProviderConfig(api_base=cfg.api_base, api_key=cfg.api_key, model_name=model)
        if api_base:
            cfg = ProviderConfig(api_base=api_base, api_key=cfg.api_key, model_name=cfg.model_name)
        if api_key:
            cfg = ProviderConfig(api_base=cfg.api_base, api_key=api_key, model_name=cfg.model_name)
        provider = OpenAICompatibleProvider(cfg)

    def on_turn_start(idx: int) -> None:
        if out_format == "text":
            console.print(f"[bold cyan]─── Turn {idx}/{budget_iterations} ───[/bold cyan]")

    def on_tool_execute(tool_id: str, args: dict[str, Any]) -> None:
        if out_format == "text":
            args_snippet = str(args)[:80] + ("..." if len(str(args)) > 80 else "")
            console.print(f"  [bold yellow]⚡ Action:[/bold yellow] [green]{tool_id}[/green]({args_snippet})")

    def on_tool_result(obs: Any) -> None:
        if out_format == "text":
            status_style = "bold green" if obs.success else "bold red"
            status_text = "OK" if obs.success else "FAILED"
            console.print(f"  [{status_style}]↳ Observation [{status_text}][/{status_style}] ({obs.duration_s:.2f}s)")

    runtime = AutonomousRuntime(
        goal=goal,
        case_dir=case_dir,
        target_device=target_device,
        provider=provider,
        policy=policy,
        max_concurrency=concurrency,
        on_turn_start=on_turn_start,
        on_tool_execute=on_tool_execute,
        on_tool_result=on_tool_result,
    )

    if out_format == "text":
        console.print(Panel(
            f"[bold]Objective:[/bold] {objective}\n"
            f"[bold]Case Workspace:[/bold] {runtime.case_dir}\n"
            f"[bold]Target Device:[/bold] {target_device or 'Auto-detect'}\n"
            f"[bold]Autonomy Mode:[/bold] {'Unrestricted Researcher' if unrestricted else 'Restricted'}",
            title="[bold magenta]LockKnife Autonomous Agent Kernel[/bold magenta]",
            border_style="magenta",
        ))

    result: AgentRunResult = runtime.run()

    if out_format == "json":
        console.print_json(json.dumps(result.to_dict()))
        return

    if out_format == "markdown":
        console.print(Markdown(result.final_response))
        return

    # Text / Rich output
    console.print("\n")
    status_color = "green" if result.status == GoalStatus.COMPLETED else "yellow"
    console.print(Panel(
        f"[bold {status_color}]Status:[/bold {status_color}] {result.status.value.upper()}\n"
        f"[bold]Total Turns:[/bold] {len(result.turns)}\n"
        f"[bold]Duration:[/bold] {result.duration_s:.2f}s\n"
        f"[bold]Artifacts Created:[/bold] {len(result.artifacts_created)}\n\n"
        f"[bold white]Final Forensic Summary:[/bold white]\n{result.final_response}",
        title="[bold green]Mission Outcome[/bold green]",
        border_style=status_color,
    ))


@agent_group.command("chat", cls=LockKnifeCommand, help="Interactive terminal REPL session with the autonomous agent.")
@click.option("--case-dir", type=click.Path(path_type=pathlib.Path), default=None, help="Case workspace directory.")
@click.option("--target", "target_device", type=str, default=None, help="Target device serial.")
@click.option("--model", type=str, default=None, help="LLM model name.")
@click.option("--mock", is_flag=True, default=False, help="Use deterministic mock provider.")
def agent_chat_cmd(
    case_dir: pathlib.Path | None,
    target_device: str | None,
    model: str | None,
    mock: bool,
) -> None:
    goal = AgentGoal(
        objective="Interactive security research session",
        target_device=target_device,
        budget_iterations=100,
    )

    if mock:
        provider = DeterministicMockProvider()
    else:
        cfg = ProviderConfig.from_env()
        if model:
            cfg = ProviderConfig(api_base=cfg.api_base, api_key=cfg.api_key, model_name=model)
        provider = OpenAICompatibleProvider(cfg)

    policy = ResearcherPolicy(unrestricted=True, auto_provision_case=True)
    runtime = AutonomousRuntime(
        goal=goal,
        case_dir=case_dir,
        target_device=target_device,
        provider=provider,
        policy=policy,
    )

    console.print(Panel(
        f"[bold green]LockKnife Interactive Research Agent REPL[/bold green]\n"
        f"Case Workspace: {runtime.case_dir}\n"
        f"Target Device: {target_device or 'Auto-detect'}\n\n"
        f"Type your research commands or questions. Available slash commands:\n"
        f"  [cyan]/facts[/cyan]  - Inspect discovered semantic facts\n"
        f"  [cyan]/tools[/cyan]  - List available agent tools\n"
        f"  [cyan]/exit[/cyan]   - Terminate session",
        border_style="green",
    ))

    while True:
        try:
            user_input = click.prompt("researcher", prompt_suffix=" > ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Session ended.[/yellow]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/exit", "/quit", "exit", "quit"):
            console.print("[yellow]Exiting agent REPL.[/yellow]")
            break

        if user_input.lower() == "/facts":
            facts = runtime.memory.get_facts()
            console.print_json(json.dumps(facts))
            continue

        if user_input.lower() == "/plan":
            table = Table(title="Autonomous Investigation Milestone Plan")
            table.add_column("ID", style="cyan")
            table.add_column("Milestone", style="bold white")
            table.add_column("Status", style="green")
            table.add_column("Description")
            for m in runtime.plan.milestones:
                table.add_row(m.milestone_id, m.title, m.status.value.upper(), m.description)
            console.print(table)
            continue

        if user_input.lower().startswith("/steer "):
            guidance = user_input[7:].strip()
            runtime.steer(guidance)
            console.print(f"[bold green]✓ Mid-flight guidance queued:[/bold green] {guidance}")
            continue

        if user_input.lower() == "/sessions":
            sessions = runtime.tools.exec_sessions.list_sessions()
            if not sessions:
                console.print("[yellow]No active background exec sessions.[/yellow]")
            else:
                table = Table(title="Active Stateful Exec Sessions")
                table.add_column("Session ID", style="cyan")
                table.add_column("Command", style="white")
                table.add_column("Running", style="green")
                table.add_column("Elapsed (s)", style="yellow")
                for s in sessions:
                    table.add_row(s["session_id"], s["command"], str(s["is_running"]), str(s["elapsed_s"]))
                console.print(table)
            continue

        if user_input.lower().startswith("/kill "):
            sid = user_input[6:].strip()
            res = runtime.tools.exec_sessions.close_session(sid)
            if res.get("ok"):
                console.print(f"[bold green]✓ Closed session {sid}[/bold green]")
            else:
                console.print(f"[bold red]Failed to close session: {res.get('error')}[/bold red]")
            continue

        if user_input.lower() == "/tools":
            specs = runtime.tools.get_tool_specs()
            table = Table(title="Available Agent Capabilities")
            table.add_column("Tool Name", style="cyan")
            table.add_column("Description")
            for s in specs:
                fn = s.get("function", {})
                table.add_row(fn.get("name", ""), fn.get("description", ""))
            console.print(table)
            continue

        console.print("[dim]Thinking & executing...[/dim]")
        reply = runtime.chat_step(user_input)
        console.print(f"[bold cyan]Agent:[/bold cyan]\n{reply}\n")


@agent_group.command("daemon", cls=LockKnifeCommand, help="Run proactive ADB heartbeat daemon watching for device hotplugs.")
@click.option("--interval", type=float, default=10.0, show_default=True, help="Polling interval in seconds.")
@click.option("--once", is_flag=True, default=False, help="Execute a single check tick and exit.")
@click.option("--auto-triage", is_flag=True, default=False, help="Automatically run triage investigation when a device is attached.")
def agent_daemon_cmd(interval: float, once: bool, auto_triage: bool) -> None:
    console.print(f"[bold cyan]Starting LockKnife Proactive Device Watcher[/bold cyan] (interval: {interval}s)")

    def on_attached(device: Any) -> None:
        console.print(f"[bold green]⚡ Device Attached:[/bold green] {device.serial} (Model: {device.model or 'Unknown'})")
        if auto_triage:
            console.print(f"[cyan]Dispatching autonomous triage for {device.serial}...[/cyan]")
            goal = AgentGoal(
                objective=f"Autonomous intake triage for newly attached device {device.serial}",
                target_device=device.serial,
                budget_iterations=10,
            )
            runtime = AutonomousRuntime(goal=goal, target_device=device.serial)
            res = runtime.run()
            console.print(f"[green]Triage completed:[/green] {res.status.value}")

    def on_detached(serial: str) -> None:
        console.print(f"[bold yellow]Device Detached:[/bold yellow] {serial}")

    daemon = DeviceHeartbeatDaemon(
        interval_s=interval,
        on_device_attached=on_attached,
        on_device_detached=on_detached,
    )

    if once:
        result = daemon.tick()
        console.print_json(json.dumps(result))
        return

    try:
        daemon.run_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Daemon stopped by operator.[/yellow]")


@agent_group.command("memory", cls=LockKnifeCommand, help="Inspect episodic turns and semantic facts for a case workspace.")
@click.option("--case-dir", type=click.Path(exists=True, path_type=pathlib.Path), required=True, help="Case workspace directory.")
def agent_memory_cmd(case_dir: pathlib.Path) -> None:
    from lockknife.core.agent.memory import MemoryStore

    store = MemoryStore(case_dir=case_dir)
    facts = store.get_facts()
    turns = store.load_episodic_turns()

    console.print(Panel(
        f"[bold]Case Workspace:[/bold] {case_dir}\n"
        f"[bold]Episodic Turns Recorded:[/bold] {len(turns)}\n"
        f"[bold]Semantic Facts:[/bold] {len(facts)}",
        title="[bold cyan]Agent Memory State[/bold cyan]",
    ))

    if facts:
        table = Table(title="Discovered Semantic Facts")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")
        for k, v in facts.items():
            table.add_row(k, str(v))
        console.print(table)
