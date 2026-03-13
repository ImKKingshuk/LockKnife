from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click


def register(case_group: Any, cli: Any) -> None:
    @case_group.command("enrich")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--artifact-id")
    @click.option("--category", "categories", multiple=True)
    @click.option("--exclude-category", "exclude_categories", multiple=True)
    @click.option("--source-command", "source_commands", multiple=True)
    @click.option("--device-serial", "device_serials", multiple=True)
    @click.option("--limit", type=int, default=25, show_default=True)
    @click.option("--reputation-limit", type=int, default=10, show_default=True)
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def enrich_cmd(case_dir: pathlib.Path, artifact_id: str | None, categories: tuple[str, ...], exclude_categories: tuple[str, ...], source_commands: tuple[str, ...], device_serials: tuple[str, ...], limit: int, reputation_limit: int, output: pathlib.Path | None, out_format: str) -> None:
        payload = cli.run_case_enrichment(
            case_dir=case_dir,
            artifact_id=artifact_id,
            categories=categories,
            exclude_categories=exclude_categories,
            source_commands=source_commands,
            device_serials=device_serials,
            limit=limit,
            reputation_limit=reputation_limit,
            output=output,
        )
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return
        cli.console.print(cli._render_enrichment_text(payload))

    @case_group.command("register")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--path", "artifact_path", type=click.Path(dir_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--category", required=True)
    @click.option("--source-command", required=True)
    @click.option("--device-serial")
    @click.option("--input-path", "input_paths", multiple=True)
    @click.option("--parent-artifact-id", "parent_artifact_ids", multiple=True)
    @click.option("--on-conflict", type=click.Choice(["auto", "replace", "duplicate", "error"], case_sensitive=False), default="auto")
    def register_cmd(case_dir: pathlib.Path, artifact_path: pathlib.Path, category: str, source_command: str, device_serial: str | None, input_paths: tuple[str, ...], parent_artifact_ids: tuple[str, ...], on_conflict: str) -> None:
        try:
            result = cli.register_case_artifact_with_status(
                case_dir=case_dir,
                path=artifact_path,
                category=category,
                source_command=source_command,
                device_serial=device_serial,
                input_paths=list(input_paths),
                parent_artifact_ids=list(parent_artifact_ids),
                on_conflict=on_conflict.lower(),
            )
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        payload = dataclasses.asdict(result.artifact)
        payload["registration_action"] = result.action
        cli.console.print_json(json.dumps(payload))
