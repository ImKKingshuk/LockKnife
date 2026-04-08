from __future__ import annotations

import pathlib
from typing import Any

import click


def _render_rows(title: str, rows: list[dict[str, object]]) -> list[str]:
    lines = [f"{title}:"]
    if not rows:
        lines.append("- none")
        return lines
    for row in rows:
        lines.append(f"- {row['name']}: {row['count']}")
    return lines


def _case_filter_kwargs(
    *,
    categories: tuple[str, ...],
    exclude_categories: tuple[str, ...],
    source_commands: tuple[str, ...],
    device_serials: tuple[str, ...],
) -> dict[str, tuple[str, ...]]:
    return {
        "categories": categories,
        "exclude_categories": exclude_categories,
        "source_commands": source_commands,
        "device_serials": device_serials,
    }


def _render_filter_summary(filters: dict[str, list[str]]) -> str | None:
    parts: list[str] = []
    if filters.get("categories"):
        parts.append(f"categories={', '.join(filters['categories'])}")
    if filters.get("exclude_categories"):
        parts.append(f"exclude={', '.join(filters['exclude_categories'])}")
    if filters.get("source_commands"):
        parts.append(f"commands={', '.join(filters['source_commands'])}")
    if filters.get("device_serials"):
        parts.append(f"devices={', '.join(filters['device_serials'])}")
    if not parts:
        return None
    return "Filters: " + " | ".join(parts)


def _render_search_summary(payload: dict[str, Any]) -> str | None:
    search = payload.get("search") or {}
    parts: list[str] = []
    if search.get("query"):
        parts.append(f"query={search['query']}")
    if search.get("path_contains"):
        parts.append(f"path~{search['path_contains']}")
    if search.get("metadata_contains"):
        parts.append(f"metadata~{search['metadata_contains']}")
    if search.get("limit") is not None:
        parts.append(f"limit={search['limit']}")
    if not parts:
        return None
    return "Search: " + " | ".join(parts)


def _artifact_ref_kwargs(
    *, artifact_id: str | None, artifact_path: pathlib.Path | None
) -> dict[str, str | pathlib.Path | None]:
    if bool(artifact_id) == bool(artifact_path):
        raise click.ClickException("Provide exactly one of --artifact-id or --path")
    return {"artifact_id": artifact_id, "path": artifact_path}


def _render_graph_node(
    node_id: str,
    *,
    node_map: dict[str, dict[str, Any]],
    depth: int,
    lines: list[str],
    stack: set[str],
    rendered_shared: set[str],
) -> None:
    node = node_map[node_id]
    prefix = "  " * depth
    detail = f"{node['artifact_id']} ({node['category']}) {node['path']}"
    if node.get("device_serial"):
        detail += f" (device={node['device_serial']})"
    if node_id in stack:
        lines.append(f"{prefix}- {detail} [cycle]")
        return
    if depth > 0 and node_id in rendered_shared:
        lines.append(f"{prefix}- {detail} [shared]")
        return

    lines.append(f"{prefix}- {detail}")
    rendered_shared.add(node_id)
    stack.add(node_id)
    for child_id in node.get("child_artifact_ids", []):
        _render_graph_node(
            child_id,
            node_map=node_map,
            depth=depth + 1,
            lines=lines,
            stack=stack,
            rendered_shared=rendered_shared,
        )
    stack.remove(node_id)


def _render_graph_text(payload: dict[str, Any]) -> str:
    lines = [
        f"Case Graph: {payload['case_id']} | title={payload['title']} | examiner={payload['examiner']}",
        f"Artifacts: {payload['artifact_count']} | roots={len(payload['root_artifact_ids'])} | edges={len(payload['edges'])}",
        "",
        "Lineage:",
    ]
    node_map = {node["artifact_id"]: node for node in payload["nodes"]}
    rendered_shared: set[str] = set()
    root_ids = list(payload["root_artifact_ids"])
    for root_id in root_ids:
        _render_graph_node(
            root_id,
            node_map=node_map,
            depth=0,
            lines=lines,
            stack=set(),
            rendered_shared=rendered_shared,
        )

    remaining = [node_id for node_id in node_map if node_id not in rendered_shared]
    if remaining:
        lines.append("")
        lines.append("Remaining:")
        for node_id in remaining:
            _render_graph_node(
                node_id,
                node_map=node_map,
                depth=0,
                lines=lines,
                stack=set(),
                rendered_shared=rendered_shared,
            )
    return "\n".join(lines)


def _render_enrichment_text(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or {}
    providers = payload.get("provider_status") or []
    run_summary = payload.get("run_summary") or {}
    lines = [
        f"Case Enrichment: {payload['case_id']} | title={payload['title']}",
        f"Artifacts selected={summary.get('selected_artifact_count', 0)} | workflows={summary.get('workflow_run_count', 0)} | skipped={summary.get('skipped_artifact_count', 0)}",
        f"Providers: {', '.join(source.get('provider', 'unknown') for source in providers) if providers else 'none'}",
        f"Output: {payload['output']}",
    ]
    if run_summary:
        lines.append(
            f"Run status: ok={run_summary.get('success_count', 0)} | error={run_summary.get('error_count', 0)} | workflows={len(run_summary.get('workflow_status') or [])}"
        )
    if payload.get("artifact_id"):
        lines.append(f"Seed artifact: {payload['artifact_id']}")
    return "\n".join(lines)
