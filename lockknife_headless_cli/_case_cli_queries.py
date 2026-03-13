from __future__ import annotations

import json
import pathlib
from typing import Any

import click


def register(case_group: Any, cli: Any) -> None:
    @case_group.command("summary")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--category", "categories", multiple=True)
    @click.option("--exclude-category", "exclude_categories", multiple=True)
    @click.option("--source-command", "source_commands", multiple=True)
    @click.option("--device-serial", "device_serials", multiple=True)
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def summary_cmd(
        case_dir: pathlib.Path,
        categories: tuple[str, ...],
        exclude_categories: tuple[str, ...],
        source_commands: tuple[str, ...],
        device_serials: tuple[str, ...],
        out_format: str,
    ) -> None:
        payload = cli.summarize_case_manifest(
            case_dir,
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

        artifact_label = f"Artifacts: {payload['artifact_count']}"
        if payload["artifact_count"] != payload["total_artifact_count"]:
            artifact_label += f" of {payload['total_artifact_count']}"
        artifact_label += f" | schema={payload['schema_version']}"
        lines = [
            f"Case: {payload['case_id']} | title={payload['title']} | examiner={payload['examiner']}",
            artifact_label,
        ]
        filter_line = cli._render_filter_summary(payload["filters"])
        if filter_line:
            lines.append(filter_line)
        target_serials = payload.get("target_serials") or []
        lines.append(f"Targets: {', '.join(target_serials) if target_serials else 'none'}")
        lineage = payload["lineage"]
        lines.append(
            "Lineage: "
            f"roots={lineage['root_artifacts']} linked={lineage['linked_artifacts']} "
            f"edges={lineage['parent_edges']} external_inputs={lineage['artifacts_with_external_inputs']}"
        )
        lines.append("")
        lines.extend(cli._render_rows("Categories", payload["artifacts_by_category"]))
        lines.append("")
        lines.extend(cli._render_rows("Source Commands", payload["artifacts_by_source_command"]))
        lines.append("")
        lines.extend(cli._render_rows("Devices", payload["artifacts_by_device_serial"]))
        cli.console.print("\n".join(lines))

    @case_group.command("graph")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--category", "categories", multiple=True)
    @click.option("--exclude-category", "exclude_categories", multiple=True)
    @click.option("--source-command", "source_commands", multiple=True)
    @click.option("--device-serial", "device_serials", multiple=True)
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def graph_cmd(
        case_dir: pathlib.Path,
        categories: tuple[str, ...],
        exclude_categories: tuple[str, ...],
        source_commands: tuple[str, ...],
        device_serials: tuple[str, ...],
        out_format: str,
    ) -> None:
        payload = cli.case_lineage_graph(
            case_dir,
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
        graph_text = cli._render_graph_text(payload)
        filter_line = cli._render_filter_summary(payload["filters"])
        if filter_line:
            graph_text = graph_text.replace("Lineage:\n", f"{filter_line}\n\nLineage:\n", 1)
            if payload["artifact_count"] != payload["total_artifact_count"]:
                graph_text = graph_text.replace(
                    f"Artifacts: {payload['artifact_count']} | roots={len(payload['root_artifact_ids'])} | edges={len(payload['edges'])}",
                    f"Artifacts: {payload['artifact_count']} of {payload['total_artifact_count']} | roots={len(payload['root_artifact_ids'])} | edges={len(payload['edges'])}",
                    1,
                )
        cli.console.print(graph_text)

    @case_group.command("artifacts")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--category", "categories", multiple=True)
    @click.option("--exclude-category", "exclude_categories", multiple=True)
    @click.option("--source-command", "source_commands", multiple=True)
    @click.option("--device-serial", "device_serials", multiple=True)
    @click.option("--query")
    @click.option("--path-contains")
    @click.option("--metadata-contains")
    @click.option("--limit", type=int)
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def artifacts_cmd(
        case_dir: pathlib.Path,
        categories: tuple[str, ...],
        exclude_categories: tuple[str, ...],
        source_commands: tuple[str, ...],
        device_serials: tuple[str, ...],
        query: str | None,
        path_contains: str | None,
        metadata_contains: str | None,
        limit: int | None,
        out_format: str,
    ) -> None:
        payload = cli.query_case_artifacts(
            case_dir,
            **cli._case_filter_kwargs(
                categories=categories,
                exclude_categories=exclude_categories,
                source_commands=source_commands,
                device_serials=device_serials,
            ),
            query=query,
            path_contains=path_contains,
            metadata_contains=metadata_contains,
            limit=limit,
        )
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return
        lines = [
            f"Case Artifacts: {payload['case_id']} | title={payload['title']} | examiner={payload['examiner']}",
            f"Artifacts: {payload['artifact_count']} of {payload['total_artifact_count']}",
        ]
        filter_line = cli._render_filter_summary(payload["filters"])
        if filter_line:
            lines.append(filter_line)
        search_line = cli._render_search_summary(payload)
        if search_line:
            lines.append(search_line)
        lines.append("")
        if not payload["artifacts"]:
            lines.append("- none")
        else:
            for artifact in payload["artifacts"]:
                device = artifact["device_serial"] or "unknown"
                lines.append(f"- {artifact['artifact_id']} | {artifact['category']} | {artifact['path']} | cmd={artifact['source_command']} | device={device}")
        cli.console.print("\n".join(lines))

    @case_group.command("artifact")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--artifact-id")
    @click.option("--path", "artifact_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def artifact_cmd(case_dir: pathlib.Path, artifact_id: str | None, artifact_path: pathlib.Path | None, out_format: str) -> None:
        payload = cli.case_artifact_details(case_dir, **cli._artifact_ref_kwargs(artifact_id=artifact_id, artifact_path=artifact_path))
        if payload is None:
            raise click.ClickException("Artifact not found")
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return
        artifact = payload["artifact"]
        lines = [
            f"Artifact: {artifact['artifact_id']} | {artifact['category']} | {artifact['path']}",
            f"Source: {artifact['source_command']} | device={artifact['device_serial'] or 'unknown'}",
            f"Created: {artifact['created_at_utc']} | size={artifact['size_bytes']} | sha256={artifact['sha256']}",
            f"Inputs: {', '.join(artifact['input_paths']) if artifact['input_paths'] else 'none'}",
            f"Parents: {', '.join(artifact['parent_artifact_ids']) if artifact['parent_artifact_ids'] else 'none'}",
            f"Children: {', '.join(child['artifact_id'] for child in payload['children']) if payload['children'] else 'none'}",
            f"Metadata: {json.dumps(artifact['metadata'], sort_keys=True) if artifact['metadata'] else 'none'}",
        ]
        cli.console.print("\n".join(lines))

    @case_group.command("lineage")
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path), required=True)
    @click.option("--artifact-id")
    @click.option("--path", "artifact_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
    def lineage_cmd(case_dir: pathlib.Path, artifact_id: str | None, artifact_path: pathlib.Path | None, out_format: str) -> None:
        payload = cli.case_artifact_lineage(case_dir, **cli._artifact_ref_kwargs(artifact_id=artifact_id, artifact_path=artifact_path))
        if payload is None:
            raise click.ClickException("Artifact not found")
        if out_format.lower() == "json":
            cli.console.print_json(json.dumps(payload))
            return
        artifact = payload["artifact"]
        lines = [
            f"Artifact Lineage: {artifact['artifact_id']} | {artifact['category']} | {artifact['path']}",
            "Parents:",
        ]
        if payload["parents"]:
            for parent in payload["parents"]:
                lines.append(f"- {parent['artifact_id']} | {parent['category']} | {parent['path']}")
        else:
            lines.append("- none")
        if payload["missing_parent_ids"]:
            lines.append("Missing Parents:")
            for parent_id in payload["missing_parent_ids"]:
                lines.append(f"- {parent_id}")
        lines.append("Children:")
        if payload["children"]:
            for child in payload["children"]:
                lines.append(f"- {child['artifact_id']} | {child['category']} | {child['path']}")
        else:
            lines.append("- none")
        cli.console.print("\n".join(lines))