import dataclasses
import json
import pathlib
from types import SimpleNamespace

from click.testing import CliRunner


def _console() -> SimpleNamespace:
    return SimpleNamespace(print_json=lambda *_a, **_k: None, print=lambda *_a, **_k: None)


def _invoke(cmd, args, obj=None):
    runner = CliRunner()
    result = runner.invoke(cmd, args, obj=obj)
    assert result.exit_code == 0, result.output
    return result


@dataclasses.dataclass
class _Row:
    name: str


@dataclasses.dataclass
class _Analysis:
    path: str
    tables: list[_Row]
    objects: list[dict[str, object]] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class _ParsedReport:
    input_dir: str
    artifacts: list[dict[str, object]]
    app_data: list[dict[str, object]]
    protobuf_files: list[dict[str, object]]
    summary: dict[str, int]


def test_forensics_helper_functions(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import forensics as forensics_cli

    captured: list[dict[str, object]] = []
    monkeypatch.setattr(forensics_cli, "case_output_path", lambda case_dir, area, filename: case_dir / area / filename)
    monkeypatch.setattr(forensics_cli, "register_case_artifact", lambda **kwargs: captured.append(kwargs))

    explicit, derived = forensics_cli._resolve_forensics_output(tmp_path / "x.json", None, area="derived", filename="a.json")
    assert explicit == tmp_path / "x.json"
    assert derived is False

    none_path, none_derived = forensics_cli._resolve_forensics_output(None, None, area="derived", filename="a.json")
    assert none_path is None
    assert none_derived is False

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    derived_path, derived = forensics_cli._resolve_forensics_output(None, case_dir, area="derived", filename="a.json")
    assert derived is True
    assert derived_path == case_dir / "derived" / "a.json"

    forensics_cli._register_forensics_output(case_dir=None, output=tmp_path / "skip.json", category="c", source_command="cmd")
    assert captured == []

    forensics_cli._register_forensics_output(case_dir=case_dir, output=tmp_path / "artifact.json", category="intel", source_command="cmd", input_paths=["a"], metadata={"ok": True})
    assert captured[0]["category"] == "intel"

    monkeypatch.setattr(
        forensics_cli,
        "find_case_artifact",
        lambda _case_dir, path: SimpleNamespace(artifact_id=f"artifact:{path.name}") if path.name != "missing.json" else None,
    )
    parent_ids = forensics_cli._parent_artifact_ids(case_dir, [str(tmp_path / "a.json"), str(tmp_path / "a.json"), str(tmp_path / "missing.json")])
    assert parent_ids == ["artifact:a.json"]


def test_forensics_cli_output_branches(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import forensics as forensics_cli

    monkeypatch.setattr(forensics_cli, "console", _console())
    monkeypatch.setattr(forensics_cli, "case_output_path", lambda case_dir, area, filename: case_dir / area / filename)
    monkeypatch.setattr(forensics_cli, "register_case_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(forensics_cli, "find_case_artifact", lambda *_a, **_k: SimpleNamespace(artifact_id="parent-1"))

    def _snapshot(_devices, _serial, output_path, paths, full, encrypt, progress_callback):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("snapshot", encoding="utf-8")
        output_path.with_suffix(output_path.suffix + ".meta.json").write_text("{}", encoding="utf-8")
        output_path.with_suffix(output_path.suffix + ".key").write_text("key", encoding="utf-8")
        progress_callback({"message": "Done"})
        return output_path

    monkeypatch.setattr(forensics_cli, "create_snapshot", _snapshot)
    monkeypatch.setattr(forensics_cli, "analyze_sqlite", lambda path: _Analysis(path=str(path), tables=[_Row("t1")], objects=[{"kind": "index"}]))
    monkeypatch.setattr(forensics_cli, "build_timeline_report", lambda **_k: {"event_count": 2, "sources": [{"path": str(tmp_path / "src.json")}], "events": [{"ts_ms": 1}]})
    monkeypatch.setattr(
        forensics_cli,
        "parse_forensics_directory",
        lambda source_dir: _ParsedReport(
            input_dir=str(source_dir),
            artifacts=[{"source_file": str(source_dir / "a.bin")}],
            app_data=[],
            protobuf_files=[],
            summary={"artifact_count": 1, "protobuf_count": 0, "aleapp_imported_count": 1},
        ),
    )
    monkeypatch.setattr(forensics_cli, "looks_like_aleapp_output", lambda *_a, **_k: True)
    monkeypatch.setattr(forensics_cli, "decode_protobuf_file", lambda path: {"message_count": 1, "field_count": 2, "nested_message_count": 0, "path": str(path)})
    monkeypatch.setattr(forensics_cli, "correlate_artifacts_json_blobs", lambda blobs: {"input_count": len(blobs)})
    monkeypatch.setattr(forensics_cli, "recover_deleted_records", lambda _path: {"fragments": [{"text": "x"}], "summary": {"high_confidence_count": 1}})
    monkeypatch.setattr(forensics_cli, "carve_deleted_files", lambda input_path, output_dir, **_k: {"carved_count": 1, "input": str(input_path), "output_dir": str(output_dir)})

    app = SimpleNamespace(devices=SimpleNamespace())
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    sample_dir = tmp_path / "forensics"
    sample_dir.mkdir()
    sqlite_path = tmp_path / "sample.sqlite"
    sqlite_path.write_text("db", encoding="utf-8")
    proto_path = tmp_path / "msg.bin"
    proto_path.write_bytes(b"abc")
    json_path = tmp_path / "data.json"
    json_path.write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    out_dir = tmp_path / "carved"

    _invoke(forensics_cli.forensics, ["snapshot", "-s", "S", "--full", "--encrypt", "--path", "/sdcard/demo", "--case-dir", str(case_dir)], obj=app)
    _invoke(forensics_cli.forensics, ["sqlite", str(sqlite_path), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["timeline", "--sms", str(json_path), "--browser", str(json_path), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["parse", "--input-dir", str(sample_dir), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["import-aleapp", str(sample_dir), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["decode-protobuf", str(proto_path), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["correlate", "--input", str(json_path), "--input", str(json_path), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["recover", str(sqlite_path), "--case-dir", str(case_dir)])
    _invoke(forensics_cli.forensics, ["carve", str(sqlite_path), "--output-dir", str(out_dir), "--source", "sqlite", "--max-matches", "3", "--case-dir", str(case_dir)])

    assert (case_dir / "evidence" / "snapshot_S.tar").exists()
    assert json.loads((case_dir / "derived" / "sqlite_sample.json").read_text(encoding="utf-8"))["path"].endswith("sample.sqlite")
    assert json.loads((case_dir / "derived" / "timeline.json").read_text(encoding="utf-8"))["event_count"] == 2
    assert json.loads((case_dir / "derived" / "parsed_artifacts.json").read_text(encoding="utf-8"))["summary"]["artifact_count"] == 1
    assert json.loads((out_dir / "carve_sample.json").read_text(encoding="utf-8"))["carved_count"] == 1


def test_forensics_cli_error_branches(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import forensics as forensics_cli

    monkeypatch.setattr(forensics_cli, "console", _console())
    monkeypatch.setattr(forensics_cli, "looks_like_aleapp_output", lambda *_a, **_k: False)
    monkeypatch.setattr(forensics_cli, "decode_protobuf_file", lambda *_a, **_k: None)
    runner = CliRunner()

    sample_dir = tmp_path / "forensics"
    sample_dir.mkdir()
    proto_path = tmp_path / "msg.bin"
    proto_path.write_bytes(b"abc")

    snapshot = runner.invoke(forensics_cli.forensics, ["snapshot", "-s", "S"])
    assert snapshot.exit_code != 0
    assert "either --output or --case-dir is required" in snapshot.output.lower()

    parse = runner.invoke(forensics_cli.forensics, ["parse"])
    assert parse.exit_code != 0
    assert "either --aleapp or --input-dir is required" in parse.output.lower()

    aleapp = runner.invoke(forensics_cli.forensics, ["import-aleapp", str(sample_dir)])
    assert aleapp.exit_code != 0
    assert "does not look like aleapp output" in aleapp.output.lower()

    proto = runner.invoke(forensics_cli.forensics, ["decode-protobuf", str(proto_path)])
    assert proto.exit_code != 0
    assert "does not appear to contain a decodable protobuf" in proto.output.lower()