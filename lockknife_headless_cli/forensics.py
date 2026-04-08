from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from lockknife.core.case import case_output_path, find_case_artifact, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.forensics.aleapp_compat import looks_like_aleapp_output
from lockknife.modules.forensics.artifacts import parse_forensics_directory
from lockknife.modules.forensics.carving import carve_deleted_files
from lockknife.modules.forensics.correlation import correlate_artifacts_json_blobs
from lockknife.modules.forensics.parsers import decode_protobuf_file
from lockknife.modules.forensics.recovery import recover_deleted_records
from lockknife.modules.forensics.snapshot import create_snapshot
from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite
from lockknife.modules.forensics.timeline import build_timeline_report


@click.group(
    help="Forensic workflows: snapshotting, SQLite analysis, timeline building.", cls=LockKnifeGroup
)
def forensics() -> None:
    pass


def _register_forensics_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str | None = None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category=category,
        source_command=source_command,
        device_serial=device_serial,
        input_paths=input_paths,
        parent_artifact_ids=parent_artifact_ids,
        metadata=metadata,
    )


def _resolve_forensics_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, area: str, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area=area, filename=filename), True


def _parent_artifact_ids(case_dir: pathlib.Path | None, input_paths: list[str]) -> list[str] | None:
    if case_dir is None:
        return None
    out: list[str] = []
    for input_path in input_paths:
        artifact = find_case_artifact(case_dir, path=pathlib.Path(input_path))
        if artifact is not None and artifact.artifact_id not in out:
            out.append(artifact.artifact_id)
    return out or None


@forensics.command("snapshot")
@click.option("-s", "--serial", required=True)
@click.option("--full", is_flag=True, default=False)
@click.option("--path", "paths", multiple=True)
@click.option("--encrypt", is_flag=True, default=False)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def snapshot_cmd(
    app: Any,
    serial: str,
    full: bool,
    paths: tuple[str, ...],
    encrypt: bool,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    output, _derived = _resolve_forensics_output(
        output, case_dir, area="evidence", filename=f"snapshot_{serial}.tar"
    )
    if output is None:
        raise click.ClickException("Either --output or --case-dir is required")
    with Progress(
        SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), transient=True
    ) as progress:
        task = progress.add_task(description="Creating snapshot", total=None)

        def _on_progress(event: dict[str, Any]) -> None:
            progress.update(task, description=str(event.get("message") or "Creating snapshot"))

        out = create_snapshot(
            app.devices,
            serial,
            output_path=output,
            paths=list(paths),
            full=full,
            encrypt=encrypt,
            progress_callback=_on_progress,
        )
    _register_forensics_output(
        case_dir=case_dir,
        output=out,
        category="forensics-snapshot",
        source_command="forensics snapshot",
        device_serial=serial,
        input_paths=list(paths),
        metadata={"full": full, "encrypt": encrypt},
    )
    snapshot_artifact = find_case_artifact(case_dir, path=out) if case_dir is not None else None
    meta_path = output.with_suffix(output.suffix + ".meta.json")
    if meta_path.exists():
        _register_forensics_output(
            case_dir=case_dir,
            output=meta_path,
            category="forensics-snapshot-meta",
            source_command="forensics snapshot",
            device_serial=serial,
            input_paths=list(paths),
            parent_artifact_ids=[snapshot_artifact.artifact_id] if snapshot_artifact else None,
            metadata={"full": full, "encrypt": encrypt},
        )
    key_path = output.with_suffix(output.suffix + ".key")
    if key_path.exists():
        _register_forensics_output(
            case_dir=case_dir,
            output=key_path,
            category="forensics-snapshot-key",
            source_command="forensics snapshot",
            device_serial=serial,
            input_paths=list(paths),
            parent_artifact_ids=[snapshot_artifact.artifact_id] if snapshot_artifact else None,
            metadata={"full": full, "encrypt": encrypt},
        )
    console.print(str(out))


@forensics.command("sqlite")
@click.argument("path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def sqlite_cmd(
    path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    analysis = analyze_sqlite(path)
    payload = dataclasses.asdict(analysis)
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename=f"sqlite_{path.stem}.json"
    )
    if output:
        write_json(output, payload)
        input_paths = [str(path)]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-sqlite-analysis",
            source_command="forensics sqlite",
            input_paths=input_paths,
            parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
            metadata={"table_count": len(analysis.tables), "object_count": len(analysis.objects)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("timeline")
@click.option("--sms", type=READABLE_FILE)
@click.option("--call-logs", type=READABLE_FILE)
@click.option("--browser", type=READABLE_FILE)
@click.option("--messaging", type=READABLE_FILE)
@click.option("--media", type=READABLE_FILE)
@click.option("--location", type=READABLE_FILE)
@click.option("--parsed-artifacts", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def timeline_cmd(
    sms: pathlib.Path | None,
    call_logs: pathlib.Path | None,
    browser: pathlib.Path | None,
    messaging: pathlib.Path | None,
    media: pathlib.Path | None,
    location: pathlib.Path | None,
    parsed_artifacts: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    payload = build_timeline_report(
        sms_path=sms,
        call_logs_path=call_logs,
        browser_path=browser,
        messaging_path=messaging,
        media_path=media,
        location_path=location,
        parsed_artifacts_path=parsed_artifacts,
        case_dir=case_dir,
    )
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename="timeline.json"
    )
    if output:
        write_json(output, payload)
        inputs = [
            item["path"]
            for item in payload.get("sources", [])
            if isinstance(item, dict) and item.get("path")
        ]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-timeline",
            source_command="forensics timeline",
            input_paths=inputs,
            parent_artifact_ids=_parent_artifact_ids(case_dir, inputs),
            metadata={
                "event_count": payload.get("event_count", 0),
                "source_count": len(payload.get("sources", [])),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("parse")
@click.option(
    "--aleapp",
    "aleapp_dir",
    type=click.Path(file_okay=False, path_type=pathlib.Path),
    required=False,
)
@click.option(
    "--input-dir", type=click.Path(file_okay=False, path_type=pathlib.Path), required=False
)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def parse_cmd(
    aleapp_dir: pathlib.Path | None,
    input_dir: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    source_dir = input_dir or aleapp_dir
    if source_dir is None:
        raise click.ClickException("Either --aleapp or --input-dir is required")
    payload = dataclasses.asdict(parse_forensics_directory(source_dir))
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename="parsed_artifacts.json"
    )
    if output:
        write_json(output, payload)
        inputs = [str(source_dir)] + [
            item["source_file"] for item in payload.get("artifacts", []) if isinstance(item, dict)
        ]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-parse",
            source_command="forensics parse",
            input_paths=inputs,
            parent_artifact_ids=_parent_artifact_ids(case_dir, inputs),
            metadata={
                "artifact_count": payload.get("summary", {}).get("artifact_count", 0),
                "protobuf_count": payload.get("summary", {}).get("protobuf_count", 0),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("import-aleapp")
@click.argument("input_dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def import_aleapp_cmd(
    input_dir: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    if not looks_like_aleapp_output(input_dir):
        raise click.ClickException("Directory does not look like ALEAPP output")
    payload = dataclasses.asdict(parse_forensics_directory(input_dir))
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename="aleapp_import.json"
    )
    if output:
        write_json(output, payload)
        inputs = [str(input_dir)]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-aleapp-import",
            source_command="forensics import-aleapp",
            input_paths=inputs,
            parent_artifact_ids=_parent_artifact_ids(case_dir, inputs),
            metadata={
                "artifact_count": payload.get("summary", {}).get("artifact_count", 0),
                "aleapp_imported_count": payload.get("summary", {}).get("aleapp_imported_count", 0),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("decode-protobuf")
@click.argument("path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def decode_protobuf_cmd(
    path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    payload = decode_protobuf_file(path)
    if payload is None:
        raise click.ClickException("Input does not appear to contain a decodable protobuf message")
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename=f"protobuf_{path.stem}.json"
    )
    if output:
        write_json(output, payload)
        input_paths = [str(path)]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-protobuf",
            source_command="forensics decode-protobuf",
            input_paths=input_paths,
            parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
            metadata={
                "message_count": payload.get("message_count", 0),
                "field_count": payload.get("field_count", 0),
                "nested_message_count": payload.get("nested_message_count", 0),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("correlate")
@click.option("--input", "inputs", multiple=True, type=READABLE_FILE, required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def correlate_cmd(
    inputs: tuple[pathlib.Path, ...], output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    blobs = [p.read_text(encoding="utf-8") for p in inputs]
    payload = correlate_artifacts_json_blobs(blobs)
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename="correlation.json"
    )
    if output:
        write_json(output, payload)
        input_paths = [str(p) for p in inputs]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-correlation",
            source_command="forensics correlate",
            input_paths=input_paths,
            parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
            metadata={"input_count": len(inputs)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("recover")
@click.argument("db_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def recover_cmd(
    db_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    payload = recover_deleted_records(db_path)
    output, derived = _resolve_forensics_output(
        output, case_dir, area="derived", filename=f"recovered_{db_path.stem}.json"
    )
    if output:
        write_json(output, payload)
        input_paths = [str(db_path)]
        _register_forensics_output(
            case_dir=case_dir,
            output=output,
            category="forensics-recovery",
            source_command="forensics recover",
            input_paths=input_paths,
            parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
            metadata={
                "fragment_count": len(payload.get("fragments", [])),
                "high_confidence_count": payload.get("summary", {}).get("high_confidence_count", 0),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@forensics.command("carve")
@click.argument("input_path", type=READABLE_FILE)
@click.option(
    "--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path), required=True
)
@click.option(
    "--source", type=click.Choice(["auto", "image", "sqlite"], case_sensitive=False), default="auto"
)
@click.option("--max-matches", type=int, default=25, show_default=True)
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def carve_cmd(
    input_path: pathlib.Path,
    output_dir: pathlib.Path,
    source: str,
    max_matches: int,
    case_dir: pathlib.Path | None,
) -> None:
    payload = carve_deleted_files(
        input_path, output_dir, source=source.lower(), max_matches=max_matches
    )
    summary_path, derived = _resolve_forensics_output(
        output_dir / f"carve_{input_path.stem}.json",
        case_dir,
        area="derived",
        filename=f"carve_{input_path.stem}.json",
    )
    if summary_path:
        write_json(summary_path, payload)
        input_paths = [str(input_path)]
        _register_forensics_output(
            case_dir=case_dir,
            output=summary_path,
            category="forensics-carve",
            source_command="forensics carve",
            input_paths=input_paths,
            parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
            metadata={"carved_count": payload.get("carved_count", 0), "source": source.lower()},
        )
        if derived:
            console.print(str(summary_path))
        return
    console.print_json(json.dumps(payload))
