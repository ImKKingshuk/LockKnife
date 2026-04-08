from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from lockknife.modules.forensics._artifact_registry import (
    iter_registered_artifacts,
    parse_app_data_artifacts,
)
from lockknife.modules.forensics.aleapp_compat import (
    import_aleapp_artifacts,
    looks_like_aleapp_output,
)


@dataclasses.dataclass(frozen=True)
class AleappArtifact:
    artifact_name: str
    artifact_family: str
    parser_id: str
    source_file: str
    records: list[dict[str, Any]]
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    source_format: str | None = None


@dataclasses.dataclass(frozen=True)
class AppDataArtifact:
    source_file: str
    format: str
    key_count: int
    preview: list[dict[str, str]]
    root_tag: str | None = None


@dataclasses.dataclass(frozen=True)
class ProtobufArtifact:
    source_file: str
    format: str
    message_count: int
    field_count: int
    top_fields: list[dict[str, int]]
    messages: list[dict[str, Any]]
    wire_type_counts: dict[str, int] = dataclasses.field(default_factory=dict)
    nested_message_count: int = 0
    string_field_count: int = 0
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class ForensicsParseReport:
    input_dir: str
    artifacts: list[AleappArtifact]
    app_data: list[AppDataArtifact]
    protobuf_files: list[ProtobufArtifact]
    summary: dict[str, Any]
    aleapp_import: dict[str, Any] = dataclasses.field(default_factory=dict)


def parse_directory_as_aleapp(input_dir: pathlib.Path) -> list[AleappArtifact]:
    imported = (
        import_aleapp_artifacts(input_dir)
        if looks_like_aleapp_output(input_dir)
        else {"artifacts": []}
    )
    rows = imported.get("artifacts") or iter_registered_artifacts(input_dir)
    return [
        AleappArtifact(
            artifact_name=item["artifact_name"],
            artifact_family=item["artifact_family"],
            parser_id=item["parser_id"],
            source_file=item["source_file"],
            records=item["records"],
            summary=item.get("summary") or {},
            source_format=(item.get("summary") or {}).get("source_format"),
        )
        for item in rows
    ]


def parse_forensics_directory(input_dir: pathlib.Path) -> ForensicsParseReport:
    aleapp_import = (
        import_aleapp_artifacts(input_dir) if looks_like_aleapp_output(input_dir) else {}
    )
    artifacts = parse_directory_as_aleapp(input_dir)
    app_data_raw, protobuf_raw = parse_app_data_artifacts(input_dir)
    app_data = [AppDataArtifact(**item) for item in app_data_raw]
    protobuf_files = [ProtobufArtifact(**item) for item in protobuf_raw]
    family_counts: dict[str, int] = {}
    for artifact in artifacts:
        family_counts[artifact.artifact_family] = family_counts.get(artifact.artifact_family, 0) + 1
    summary = {
        "artifact_count": len(artifacts),
        "artifact_family_counts": family_counts,
        "app_data_count": len(app_data),
        "protobuf_count": len(protobuf_files),
        "input_dir": str(input_dir),
        "aleapp_compatible": bool(aleapp_import),
        "aleapp_imported_count": int(
            (aleapp_import.get("summary") or {}).get("artifact_count") or 0
        ),
    }
    return ForensicsParseReport(
        input_dir=str(input_dir),
        artifacts=artifacts,
        app_data=app_data,
        protobuf_files=protobuf_files,
        summary=summary,
        aleapp_import=aleapp_import,
    )
