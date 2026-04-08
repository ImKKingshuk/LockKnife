import dataclasses
import json
import pathlib
from types import SimpleNamespace

from click.testing import CliRunner


def _console() -> SimpleNamespace:
    return SimpleNamespace(print_json=lambda *_a, **_k: None, print=lambda *_a, **_k: None)


def _invoke(cmd, args):
    runner = CliRunner()
    result = runner.invoke(cmd, args)
    assert result.exit_code == 0, result.output
    return result


@dataclasses.dataclass
class _Indicator:
    ioc: str
    kind: str


def test_intel_helper_functions(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import intel as intel_cli

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        intel_cli, "case_output_path", lambda case_dir, area, filename: case_dir / area / filename
    )
    monkeypatch.setattr(
        intel_cli, "register_case_artifact", lambda **kwargs: captured.update(kwargs)
    )

    assert intel_cli._safe_name("evil / name") == "evil_name"
    explicit, derived = intel_cli._resolve_case_output(
        tmp_path / "out.json", None, filename="x.json"
    )
    assert explicit == tmp_path / "out.json"
    assert derived is False

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    derived_path, derived = intel_cli._resolve_case_output(None, case_dir, filename="x.json")
    assert derived is True
    assert derived_path == case_dir / "derived" / "x.json"

    intel_cli._register_intel_output(
        case_dir=None, output=tmp_path / "skip.json", category="c", source_command="cmd"
    )
    assert captured == {}

    intel_cli._register_intel_output(
        case_dir=case_dir,
        output=tmp_path / "artifact.json",
        category="intel",
        source_command="cmd",
        input_paths=["a"],
        metadata={"ok": True},
    )
    assert captured["category"] == "intel"
    assert captured["source_command"] == "cmd"


def test_intel_cli_output_branches(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import intel as intel_cli

    monkeypatch.setattr(intel_cli, "console", _console())
    monkeypatch.setattr(
        intel_cli, "case_output_path", lambda case_dir, area, filename: case_dir / area / filename
    )
    monkeypatch.setattr(intel_cli, "register_case_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(
        intel_cli,
        "file_report",
        lambda *_a, **_k: {
            "attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1}}
        },
    )
    monkeypatch.setattr(intel_cli, "submit_url_for_analysis", lambda *_a, **_k: {"submitted": True})
    monkeypatch.setattr(intel_cli, "url_report", lambda *_a, **_k: {"url": True})
    monkeypatch.setattr(
        intel_cli,
        "virustotal_payload",
        lambda indicator, report, **_k: {
            "indicator": indicator,
            "report": report,
            "summary": {"ok": True},
        },
    )
    monkeypatch.setattr(intel_cli, "detect_iocs", lambda *_a, **_k: [])
    monkeypatch.setattr(
        intel_cli,
        "ioc_payload",
        lambda matches, **_k: {"matches": matches, "summary": {"match_count": len(matches)}},
    )
    monkeypatch.setattr(
        intel_cli,
        "cve_payload",
        lambda package, data, **_k: {"package": package, "data": data, "summary": {"count": 1}},
    )
    monkeypatch.setattr(
        intel_cli, "correlate_cves_for_apk_package", lambda package: {"package": package}
    )
    monkeypatch.setattr(intel_cli, "android_cve_risk_score", lambda sdk: {"score": sdk})
    monkeypatch.setattr(
        intel_cli,
        "correlate_cves_for_kernel_version",
        lambda version: {"score": 7, "version": version},
    )
    monkeypatch.setattr(
        intel_cli,
        "stix_payload",
        lambda url, matches, **_k: {
            "url": url,
            "matches": matches,
            "summary": {"match_count": len(matches)},
        },
    )
    monkeypatch.setattr(
        intel_cli,
        "taxii_payload",
        lambda url, matches, **_k: {
            "url": url,
            "matches": matches,
            "summary": {"match_count": len(matches)},
        },
    )
    monkeypatch.setattr(
        intel_cli,
        "load_stix_indicators_from_url",
        lambda *_a, **_k: [_Indicator(ioc="x", kind="domain")],
    )
    monkeypatch.setattr(
        intel_cli, "load_taxii_indicators", lambda *_a, **_k: [_Indicator(ioc="y", kind="ipv4")]
    )
    monkeypatch.setattr(intel_cli, "add_iocs", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        intel_cli, "indicator_reputation", lambda indicator: {"indicator": indicator}
    )

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    input_json = tmp_path / "rows.json"
    input_json.write_text(json.dumps([{"value": "x"}]), encoding="utf-8")
    rules = tmp_path / "rules.json"
    rules.write_text("[]", encoding="utf-8")

    _invoke(
        intel_cli.intel,
        ["virustotal", "--submit-url", "https://submit.example", "--case-dir", str(case_dir)],
    )
    _invoke(
        intel_cli.intel,
        ["virustotal", "--url", "https://example.com", "--output", str(tmp_path / "vt.json")],
    )
    _invoke(
        intel_cli.intel,
        [
            "ioc",
            "--input",
            str(input_json),
            "--composite-rules",
            str(rules),
            "--case-dir",
            str(case_dir),
        ],
    )
    _invoke(intel_cli.intel, ["cve", "--package", "com.example.app", "--case-dir", str(case_dir)])
    _invoke(
        intel_cli.intel,
        ["cve-risk", "--sdk", "33", "--kernel-version", "5.10.1", "--case-dir", str(case_dir)],
    )
    _invoke(
        intel_cli.intel,
        [
            "stix",
            "--url",
            "https://example.com/stix.json",
            "--db",
            str(tmp_path / "iocs.db"),
            "--case-dir",
            str(case_dir),
        ],
    )
    _invoke(
        intel_cli.intel,
        [
            "taxii",
            "--api-root-url",
            "https://example.com/api",
            "--collection-id",
            "demo",
            "--db",
            str(tmp_path / "iocs.db"),
            "--case-dir",
            str(case_dir),
        ],
    )
    _invoke(
        intel_cli.intel,
        [
            "reputation",
            "--hash",
            "a" * 64,
            "--domain",
            "example.com",
            "--ip",
            "192.0.2.5",
            "--package",
            "com.example.app",
            "--case-dir",
            str(case_dir),
        ],
    )

    assert (case_dir / "derived").exists()
    assert any(
        path.name.startswith("intel_virustotal_") for path in (case_dir / "derived").iterdir()
    )
    rep_files = [
        path
        for path in (case_dir / "derived").iterdir()
        if path.name.startswith("intel_reputation_")
    ]
    assert rep_files, "expected reputation output"
    rep_payload = json.loads(rep_files[0].read_text(encoding="utf-8"))
    assert rep_payload["combined_score"] == 25


def test_intel_cli_error_branches(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import intel as intel_cli

    monkeypatch.setattr(intel_cli, "console", _console())
    monkeypatch.setattr(
        intel_cli, "file_report", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("vt boom"))
    )
    monkeypatch.setattr(
        intel_cli,
        "indicator_reputation",
        lambda *_a, **_k: (_ for _ in ()).throw(intel_cli.OtxError("otx boom")),
    )
    monkeypatch.setattr(
        intel_cli,
        "correlate_cves_for_apk_package",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("osv boom")),
    )

    runner = CliRunner()
    none_selected = runner.invoke(intel_cli.intel, ["virustotal"])
    assert none_selected.exit_code != 0
    assert "provide exactly one" in none_selected.output.lower()

    invalid_submit = runner.invoke(
        intel_cli.intel, ["virustotal", "--submit-url", "https://x", "--domain", "example.com"]
    )
    assert invalid_submit.exit_code != 0
    assert "by itself" in invalid_submit.output.lower()

    invalid_input = tmp_path / "invalid.json"
    invalid_input.write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    invalid_rules = tmp_path / "rules.json"
    invalid_rules.write_text("{", encoding="utf-8")
    invalid_rules_result = runner.invoke(
        intel_cli.intel,
        ["ioc", "--input", str(invalid_input), "--composite-rules", str(invalid_rules)],
    )
    assert invalid_rules_result.exit_code != 0
    assert "invalid composite rules json" in invalid_rules_result.output.lower()

    risk = runner.invoke(intel_cli.intel, ["cve-risk"])
    assert risk.exit_code != 0
    assert "provide --sdk and/or --kernel-version" in risk.output.lower()

    out = tmp_path / "reputation.json"
    result = runner.invoke(
        intel_cli.intel,
        [
            "reputation",
            "--hash",
            "a" * 64,
            "--domain",
            "example.com",
            "--ip",
            "192.0.2.5",
            "--package",
            "com.example.app",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["virustotal_error"] == "vt boom"
    assert payload["otx_hash_error"] == "otx boom"
    assert payload["otx_domain_error"] == "otx boom"
    assert payload["otx_ip_error"] == "otx boom"
    assert payload["osv_error"] == "osv boom"
