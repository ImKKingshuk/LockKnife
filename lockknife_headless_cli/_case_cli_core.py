from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click


def register(case_group: Any, cli: Any) -> None:
    @case_group.command("init")
    @click.option("--case-id", required=True)
    @click.option("--examiner", required=True)
    @click.option("--title", required=True)
    @click.option("--notes")
    @click.option("--target-serial", "target_serials", multiple=True)
    @click.option("--output", type=click.Path(file_okay=False, path_type=pathlib.Path), required=True)
    def init_cmd(case_id: str, examiner: str, title: str, notes: str | None, target_serials: tuple[str, ...], output: pathlib.Path) -> None:
        cli.create_case_workspace(
            case_dir=output,
            case_id=case_id,
            examiner=examiner,
            title=title,
            notes=notes,
            target_serials=list(target_serials),
        )
        cli.console.print(str(output))

    @case_group.command("manifest")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--format", "out_format", type=click.Choice(["json", "text"], case_sensitive=False), default="json")
    def manifest_cmd(case_dir: pathlib.Path, out_format: str) -> None:
        manifest = dataclasses.asdict(cli.load_case_manifest(case_dir))
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(manifest))
            return
        cli.console.print(f"{manifest['case_id']} | artifacts={len(manifest['artifacts'])} | examiner={manifest['examiner']}")

    @case_group.command("export")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--include-registered-artifacts/--no-include-registered-artifacts", default=False)
    @click.option("--category", "categories", multiple=True)
    @click.option("--exclude-category", "exclude_categories", multiple=True)
    @click.option("--source-command", "source_commands", multiple=True)
    @click.option("--device-serial", "device_serials", multiple=True)
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def export_cmd(case_dir: pathlib.Path, output: pathlib.Path | None, include_registered_artifacts: bool, categories: tuple[str, ...], exclude_categories: tuple[str, ...], source_commands: tuple[str, ...], device_serials: tuple[str, ...], out_format: str) -> None:
        manifest = cli.load_case_manifest(case_dir)
        if output is None:
            output = cli.case_output_path(case_dir, area="exports", filename=f"{manifest.case_id}_bundle.zip")
        payload = cli.export_case_bundle(
            case_dir=case_dir,
            output_path=output,
            include_registered_artifacts=include_registered_artifacts,
            **cli._case_filter_kwargs(
                categories=categories,
                exclude_categories=exclude_categories,
                source_commands=source_commands,
                device_serials=device_serials,
            ),
        )
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return
        cli.console.print(str(output))

    @case_group.command("sync-custody")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    def sync_custody_cmd(case_dir: pathlib.Path) -> None:
        entries = [dataclasses.asdict(entry) for entry in cli.list_entries()]
        out = case_dir / "logs" / "custody_log.json"
        cli.write_json(out, entries)
        cli.register_case_artifact(
            case_dir=case_dir,
            path=out,
            category="custody-log",
            source_command="case sync-custody",
            metadata={"entry_count": len(entries)},
        )
        cli.console.print(str(out))
