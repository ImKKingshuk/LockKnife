import dataclasses
import json
import pathlib
import sqlite3
from types import SimpleNamespace

from click.testing import CliRunner


@dataclasses.dataclass
class _Row:
    value: str


@dataclasses.dataclass
class _LocSnap:
    lat: float = 0.0
    lon: float = 0.0


@dataclasses.dataclass
class _LocEntry:
    name: str = "x"


@dataclasses.dataclass
class _LocArtifacts:
    snapshot: _LocSnap
    wifi: list[_LocEntry]
    cell: list[_LocEntry]
    location_raw: str
    wifi_raw: str
    telephony_raw: str


@dataclasses.dataclass
class _Boot:
    unlocked: bool


@dataclasses.dataclass
class _Hardware:
    ok: bool


@dataclasses.dataclass
class _Event:
    event: str


@dataclasses.dataclass
class _Vuln:
    package: str
    version_name: str
    version_code: int
    manifest_flags: object
    components: object
    uses_libraries: list[str]
    findings: list[object] = dataclasses.field(default_factory=list)
    permission_risk: dict[str, object] = dataclasses.field(default_factory=dict)
    mastg: dict[str, object] = dataclasses.field(default_factory=dict)
    cve: object = dataclasses.field(default_factory=list)
    cve_by_component: dict[str, object] = dataclasses.field(default_factory=dict)
    cve_summary: dict[str, object] = dataclasses.field(default_factory=dict)
    risk_summary: dict[str, object] = dataclasses.field(default_factory=dict)
    string_analysis: dict[str, object] = dataclasses.field(default_factory=dict)
    signing: dict[str, object] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class _Capture:
    path: str


class _App:
    def __init__(self) -> None:
        self.devices = SimpleNamespace()


def _console():
    return SimpleNamespace(print_json=lambda *_a, **_k: None, print=lambda *_a, **_k: None)


def _invoke(cmd, args, obj=None):
    runner = CliRunner()
    result = runner.invoke(cmd, args, obj=obj)
    assert result.exit_code == 0, result.output


def test_cli_device_commands(monkeypatch) -> None:
    from lockknife_headless_cli import device as dev_cli

    app = _App()
    app.devices.list_handles = lambda: []
    app.devices.info = lambda _s: SimpleNamespace(props={"a": "b"})
    app.devices.connect_device = lambda _h: "ok"
    app.devices.authorized_serials = lambda: ["S"]
    app.devices.map_devices = lambda func, serials: {s: func(s) for s in serials}
    app.adb = SimpleNamespace(shell=lambda *_a, **_k: "ok")
    monkeypatch.setattr(dev_cli, "console", _console())

    _invoke(dev_cli.device, ["list", "--format", "json"], obj=app)
    _invoke(dev_cli.device, ["info", "-s", "S", "--format", "json"], obj=app)
    _invoke(dev_cli.device, ["info", "-s", "S", "--all", "--format", "json"], obj=app)
    _invoke(dev_cli.device, ["connect", "192.0.2.1:5555"], obj=app)
    _invoke(dev_cli.device, ["shell", "-s", "S", "echo", "hi"], obj=app)
    _invoke(dev_cli.device, ["shell", "-s", "S", "--all", "echo", "hi"], obj=app)


def test_cli_extract_commands(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import extract as extract_cli

    app = _App()
    monkeypatch.setattr(extract_cli, "console", _console())
    monkeypatch.setattr(extract_cli, "extract_sms", lambda *_a, **_k: [_Row("sms")])
    monkeypatch.setattr(extract_cli, "extract_contacts", lambda *_a, **_k: [_Row("contact")])
    monkeypatch.setattr(extract_cli, "extract_call_logs", lambda *_a, **_k: [_Row("call")])
    monkeypatch.setattr(extract_cli, "extract_chrome_history", lambda *_a, **_k: [_Row("h")])
    monkeypatch.setattr(extract_cli, "extract_chrome_bookmarks", lambda *_a, **_k: [_Row("b")])
    monkeypatch.setattr(extract_cli, "extract_chrome_downloads", lambda *_a, **_k: [_Row("d")])
    monkeypatch.setattr(extract_cli, "extract_chrome_cookies", lambda *_a, **_k: [_Row("c")])
    monkeypatch.setattr(extract_cli, "extract_chrome_saved_logins", lambda *_a, **_k: [_Row("p")])
    monkeypatch.setattr(extract_cli, "extract_firefox_history", lambda *_a, **_k: [_Row("h2")])
    monkeypatch.setattr(extract_cli, "extract_firefox_bookmarks", lambda *_a, **_k: [_Row("b2")])
    monkeypatch.setattr(extract_cli, "extract_firefox_saved_logins", lambda *_a, **_k: [_Row("p2")])
    monkeypatch.setattr(extract_cli, "extract_whatsapp_messages", lambda *_a, **_k: [_Row("wa")])
    monkeypatch.setattr(extract_cli, "extract_telegram_messages", lambda *_a, **_k: [_Row("tg")])
    monkeypatch.setattr(extract_cli, "extract_signal_messages", lambda *_a, **_k: [_Row("sig")])
    monkeypatch.setattr(extract_cli, "extract_signal_artifacts", lambda *_a, **_k: _Row("sig-a"))
    monkeypatch.setattr(extract_cli, "extract_telegram_artifacts", lambda *_a, **_k: _Row("tg-a"))
    monkeypatch.setattr(extract_cli, "extract_whatsapp_artifacts", lambda *_a, **_k: _Row("wa-a"))
    monkeypatch.setattr(extract_cli, "extract_media_with_exif", lambda *_a, **_k: [_Row("media")])

    def _loc(_dev, _serial):
        return _LocArtifacts(
            snapshot=_LocSnap(),
            wifi=[_LocEntry()],
            cell=[_LocEntry()],
            location_raw="loc",
            wifi_raw="wifi",
            telephony_raw="tel",
        )

    monkeypatch.setattr(extract_cli, "extract_location_artifacts", _loc)
    monkeypatch.setattr(extract_cli, "extract_location_snapshot", lambda *_a, **_k: _LocSnap())

    _invoke(extract_cli.extract, ["sms", "-s", "S", "--limit", "1", "--format", "json"], obj=app)
    _invoke(
        extract_cli.extract,
        ["sms", "-s", "S", "--limit", "1", "--format", "csv", "--output", str(tmp_path / "sms.csv")],
        obj=app,
    )
    _invoke(extract_cli.extract, ["contacts", "-s", "S", "--limit", "1", "--format", "json"], obj=app)
    _invoke(
        extract_cli.extract,
        ["contacts", "-s", "S", "--limit", "1", "--format", "csv", "--output", str(tmp_path / "contacts.csv")],
        obj=app,
    )
    _invoke(extract_cli.extract, ["call-logs", "-s", "S", "--limit", "1", "--format", "json"], obj=app)
    _invoke(
        extract_cli.extract,
        ["call-logs", "-s", "S", "--limit", "1", "--format", "csv", "--output", str(tmp_path / "calls.csv")],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["browser", "-s", "S", "--app", "chrome", "--kind", "history", "--limit", "1", "--format", "json"],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["browser", "-s", "S", "--app", "chrome", "--kind", "all", "--limit", "1", "--format", "json"],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["messaging", "-s", "S", "--app", "signal", "--mode", "messages", "--limit", "1", "--format", "json"],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["messaging", "-s", "S", "--app", "signal", "--mode", "artifacts", "--limit", "1", "--format", "json"],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["browser", "-s", "S", "--app", "firefox", "--kind", "all", "--limit", "1", "--format", "json"],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["browser", "-s", "S", "--app", "firefox", "--kind", "all", "--limit", "1", "--format", "json", "--output", str(tmp_path / "firefox.json")],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["browser", "-s", "S", "--app", "edge", "--kind", "passwords", "--limit", "1", "--format", "csv", "--output", str(tmp_path / "edge.csv")],
        obj=app,
    )
    _invoke(extract_cli.extract, ["media", "-s", "S", "--limit", "1", "--format", "json"], obj=app)
    _invoke(
        extract_cli.extract,
        ["media", "-s", "S", "--limit", "1", "--format", "csv", "--output", str(tmp_path / "media.csv")],
        obj=app,
    )
    _invoke(extract_cli.extract, ["location", "-s", "S", "--mode", "snapshot"], obj=app)
    _invoke(
        extract_cli.extract,
        ["location", "-s", "S", "--mode", "artifacts", "--output", str(tmp_path / "location.json")],
        obj=app,
    )
    _invoke(
        extract_cli.extract,
        ["all", "-s", "S", "--limit", "1", "--format", "json", "--output-dir", str(tmp_path)],
        obj=app,
    )


def test_cli_extract_browser_rejects_csv_for_all(monkeypatch) -> None:
    from lockknife_headless_cli import extract as extract_cli

    app = _App()
    monkeypatch.setattr(extract_cli, "console", _console())
    monkeypatch.setattr(extract_cli, "extract_chrome_history", lambda *_a, **_k: [_Row("h")])
    runner = CliRunner()
    result = runner.invoke(extract_cli.extract, ["browser", "-s", "S", "--app", "chrome", "--kind", "all", "--format", "csv"], obj=app)
    assert result.exit_code != 0
    assert "not supported" in result.output.lower()


def test_cli_forensics_and_network(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import forensics as forensics_cli
    from lockknife_headless_cli import network as network_cli

    @dataclasses.dataclass
    class _Analysis:
        path: str
        tables: list[_Row]
        objects: list[dict] = dataclasses.field(default_factory=list)

    @dataclasses.dataclass
    class _ParsedReport:
        input_dir: str
        artifacts: list[dict]
        app_data: list[dict]
        protobuf_files: list[dict]
        summary: dict[str, int]

    app = _App()
    monkeypatch.setattr(forensics_cli, "console", _console())
    monkeypatch.setattr(network_cli, "console", _console())

    monkeypatch.setattr(forensics_cli, "create_snapshot", lambda *_a, **_k: tmp_path / "snap.tar")
    monkeypatch.setattr(
        forensics_cli,
        "analyze_sqlite",
        lambda *_a, **_k: _Analysis(path=str(sqlite_path), tables=[_Row("t")]),
    )
    monkeypatch.setattr(forensics_cli, "correlate_artifacts_json_blobs", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(forensics_cli, "recover_deleted_records", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(forensics_cli, "carve_deleted_files", lambda *_a, **_k: {"ok": True, "carved_count": 0})
    monkeypatch.setattr(
        forensics_cli,
        "build_timeline_report",
        lambda *_a, **_k: {"event_count": 1, "sources": [{"path": str(json_path)}], "events": [{"ts_ms": 1}]},
    )
    monkeypatch.setattr(
        forensics_cli,
        "parse_forensics_directory",
        lambda *_a, **_k: _ParsedReport(input_dir=str(tmp_path), artifacts=[], app_data=[], protobuf_files=[], summary={"artifact_count": 0, "protobuf_count": 0}),
    )

    sqlite_path = tmp_path / "db.sqlite"
    con = sqlite3.connect(str(sqlite_path))
    try:
        con.execute("CREATE TABLE t (id INTEGER)")
        con.commit()
    finally:
        con.close()
    json_path = tmp_path / "x.json"
    json_path.write_text(json.dumps([{"a": 1}]), encoding="utf-8")

    _invoke(
        forensics_cli.forensics,
        ["snapshot", "-s", "S", "--output", str(tmp_path / "snap.tar")],
        obj=app,
    )
    _invoke(forensics_cli.forensics, ["sqlite", str(sqlite_path)], obj=app)
    _invoke(
        forensics_cli.forensics,
        ["timeline", "--sms", str(json_path), "--call-logs", str(json_path), "--output", str(tmp_path / "timeline.json")],
        obj=app,
    )
    _invoke(
        forensics_cli.forensics,
        ["correlate", "--input", str(json_path), "--input", str(json_path)],
        obj=app,
    )
    _invoke(forensics_cli.forensics, ["recover", str(sqlite_path)], obj=app)

    monkeypatch.setattr(network_cli, "capture_pcap", lambda *_a, **_k: _Capture(str(tmp_path / "cap.pcap")))
    monkeypatch.setattr(network_cli, "summarize_pcap", lambda *_a, **_k: {"summary": "ok"})
    monkeypatch.setattr(network_cli, "extract_api_endpoints_from_pcap", lambda *_a, **_k: {"endpoints": []})

    pcap = tmp_path / "cap.pcap"
    pcap.write_text("pcap", encoding="utf-8")
    _invoke(
        network_cli.network,
        ["capture", "-s", "S", "--duration", "1", "--iface", "any", "--snaplen", "64", "--output", str(pcap)],
        obj=app,
    )
    _invoke(network_cli.network, ["analyze", str(pcap)], obj=app)
    _invoke(network_cli.network, ["api-discovery", str(pcap)], obj=app)
    _invoke(network_cli.network, ["parse-ipv4", "4500001400000000400600007f00000108080808"], obj=app)


def test_cli_apk_security_intel(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import apk as apk_cli
    from lockknife_headless_cli import intel as intel_cli
    from lockknife_headless_cli import security as sec_cli

    app = _App()
    monkeypatch.setattr(apk_cli, "console", _console())
    monkeypatch.setattr(sec_cli, "console", _console())
    monkeypatch.setattr(intel_cli, "console", _console())

    monkeypatch.setattr(apk_cli, "parse_apk_manifest", lambda *_a, **_k: {"permissions": []})
    monkeypatch.setattr(apk_cli, "score_permissions", lambda *_a, **_k: (1, [_Row("risk")]))
    monkeypatch.setattr(
        apk_cli,
        "analyze_apk",
        lambda *_a, **_k: SimpleNamespace(
            package="pkg",
            manifest={"package": "pkg", "permissions": []},
            findings=[_Row("finding")],
            permission_risk={"score": 1, "risks": []},
            risk_summary={"score": 12, "level": "low"},
            mastg={"mastg_ids": []},
        ),
    )
    monkeypatch.setattr(apk_cli, "scan_with_yara", lambda *_a, **_k: [_Row("hit")])
    monkeypatch.setattr(apk_cli, "extract_dex_headers", lambda *_a, **_k: [])
    monkeypatch.setattr(
        apk_cli,
        "vulnerability_report",
        lambda *_a, **_k: _Vuln(
            package="pkg",
            version_name="1.0",
            version_code=1,
            manifest_flags=[],
            components=[],
            uses_libraries=[],
            cve=[],
            cve_by_component={},
        ),
    )
    monkeypatch.setattr(
        apk_cli,
        "decompile_apk_report",
        lambda *_a, **_k: {
            "output_dir": str(tmp_path),
            "manifest_path": str(tmp_path / "manifest.json"),
            "report_path": str(tmp_path / "decompile_report.json"),
            "selected_mode": "unpack",
        },
    )

    apk_path = tmp_path / "a.apk"
    apk_path.write_text("apk", encoding="utf-8")
    rule_path = tmp_path / "r.yar"
    rule_path.write_text("rule", encoding="utf-8")

    _invoke(apk_cli.apk, ["permissions", str(apk_path)], obj=app)
    _invoke(apk_cli.apk, ["analyze", str(apk_path)], obj=app)
    _invoke(apk_cli.apk, ["scan", "--yara", str(rule_path), "--apk", str(apk_path)], obj=app)
    _invoke(apk_cli.apk, ["vulnerability", str(apk_path)], obj=app)
    _invoke(apk_cli.apk, ["decompile", str(apk_path), "--output", str(tmp_path / "out")], obj=app)

    monkeypatch.setattr(sec_cli, "run_device_audit", lambda *_a, **_k: [_Row("r")])
    monkeypatch.setattr(sec_cli, "get_selinux_status", lambda *_a, **_k: _Row("Enforcing"))
    monkeypatch.setattr(sec_cli, "scan_with_yara", lambda *_a, **_k: [_Row("hit")])
    monkeypatch.setattr(sec_cli, "scan_network", lambda *_a, **_k: SimpleNamespace(dns=[], dns_cache=[], listening=[], raw=""))
    monkeypatch.setattr(sec_cli, "analyze_bootloader", lambda *_a, **_k: _Boot(False))
    monkeypatch.setattr(sec_cli, "analyze_hardware_security", lambda *_a, **_k: _Hardware(True))
    monkeypatch.setattr(sec_cli, "assess_attack_surface", lambda *_a, **_k: {"package": "pkg", "findings": [], "probe_results": {"attempted": False}})
    monkeypatch.setattr(sec_cli, "mastg_summary", lambda *_a, **_k: {"items": []})

    _invoke(sec_cli.security, ["scan", "-s", "S"], obj=app)
    _invoke(sec_cli.security, ["selinux", "-s", "S"], obj=app)
    _invoke(sec_cli.security, ["malware", "--yara", str(rule_path), "--target", str(apk_path)], obj=app)
    _invoke(sec_cli.security, ["network-scan", "-s", "S"], obj=app)
    _invoke(sec_cli.security, ["bootloader", "-s", "S"], obj=app)
    _invoke(sec_cli.security, ["hardware", "-s", "S"], obj=app)
    artifacts = tmp_path / "a.json"
    artifacts.write_text(json.dumps([{"id": "x"}]), encoding="utf-8")
    _invoke(sec_cli.security, ["attack-surface", "--artifacts", str(artifacts)], obj=app)
    _invoke(sec_cli.security, ["owasp", "--artifacts", str(artifacts)], obj=app)

    monkeypatch.setattr(intel_cli, "detect_iocs", lambda *_a, **_k: [_Row("ioc")])
    monkeypatch.setattr(intel_cli, "correlate_cves_for_apk_package", lambda *_a, **_k: {"cves": []})
    monkeypatch.setattr(intel_cli, "file_report", lambda *_a, **_k: {"report": "ok"})
    monkeypatch.setattr(intel_cli, "indicator_reputation", lambda *_a, **_k: {"indicator": "ok"})
    monkeypatch.setattr(intel_cli, "load_stix_indicators_from_url", lambda *_a, **_k: [_Row("ioc")])
    monkeypatch.setattr(intel_cli, "load_taxii_indicators", lambda *_a, **_k: [_Row("ioc")])
    monkeypatch.setattr(intel_cli, "list_iocs", lambda *_a, **_k: [_Row("ioc")])
    monkeypatch.setattr(intel_cli, "load_feed_config", lambda *_a, **_k: [{"name": "demo"}])
    monkeypatch.setattr(intel_cli, "sync_ioc_feeds", lambda *_a, **_k: {"feeds": [{"status": "updated"}], "total_added": 1})
    monkeypatch.setattr(intel_cli, "android_cve_risk_score", lambda *_a, **_k: {"score": 1})

    json_path = tmp_path / "iocs.json"
    json_path.write_text(json.dumps([{"ioc": "x"}]), encoding="utf-8")

    _invoke(intel_cli.intel, ["ioc", "--input", str(json_path)], obj=app)
    _invoke(intel_cli.intel, ["cve", "--package", "com.example.app"], obj=app)
    _invoke(intel_cli.intel, ["cve-risk", "--sdk", "33"], obj=app)
    _invoke(intel_cli.intel, ["virustotal", "--hash", "0" * 64], obj=app)
    _invoke(intel_cli.intel, ["reputation", "--domain", "example.com"], obj=app)
    _invoke(intel_cli.intel, ["stix", "--url", "https://example.com/stix.json"], obj=app)
    _invoke(intel_cli.intel, ["taxii", "--api-root-url", "https://example.com/api"], obj=app)
    _invoke(intel_cli.intel, ["ioc-db-list", "--db", str(tmp_path / "iocs.db"), "--limit", "1"], obj=app)
    cfg = tmp_path / "feeds.json"
    cfg.write_text("[]", encoding="utf-8")
    _invoke(intel_cli.intel, ["ioc-db-sync", "--db", str(tmp_path / "iocs.db"), "--config", str(cfg), "--force"], obj=app)


def test_cli_intel_error_paths(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import intel as intel_cli

    monkeypatch.setattr(intel_cli, "console", _console())
    runner = CliRunner()

    invalid_json = tmp_path / "broken.json"
    invalid_json.write_text("{", encoding="utf-8")
    result = runner.invoke(intel_cli.intel, ["ioc", "--input", str(invalid_json)])
    assert result.exit_code != 0
    assert "invalid json input" in result.output.lower()

    stix = runner.invoke(intel_cli.intel, ["stix", "--url", "http://example.com/stix.json"])
    assert stix.exit_code != 0
    assert "only https:// urls are supported" in stix.output.lower()

    taxii = runner.invoke(intel_cli.intel, ["taxii", "--api-root-url", "http://example.com/api"])
    assert taxii.exit_code != 0
    assert "only https:// urls are supported" in taxii.output.lower()


def test_cli_ai_crypto_runtime_report(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import ai as ai_cli
    from lockknife_headless_cli import crypto_wallet as crypto_cli
    from lockknife_headless_cli import report as report_cli
    from lockknife_headless_cli import runtime as runtime_cli

    app = _App()
    monkeypatch.setattr(ai_cli, "console", _console())
    monkeypatch.setattr(crypto_cli, "console", _console())
    monkeypatch.setattr(report_cli, "console", _console())
    monkeypatch.setattr(runtime_cli, "console", _console())

    monkeypatch.setattr(ai_cli, "anomaly_scores", lambda *_a, **_k: [{"row": {"a": 1}, "anomaly_score": 0.5}])
    monkeypatch.setattr(ai_cli, "PasswordPredictor", SimpleNamespace(train_from_wordlist=lambda *_a, **_k: SimpleNamespace(generate=lambda *_a, **_k: ["pw"])))
    def _train(rows, features, label, model_path):
        model_path.write_text("model", encoding="utf-8")
        return model_path

    monkeypatch.setattr(ai_cli, "train_classifier", _train)
    monkeypatch.setattr(ai_cli, "predict_classifier", lambda *_a, **_k: [{"row": {"a": 1}, "risk": 0.1}])

    json_path = tmp_path / "rows.json"
    json_path.write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    wl = tmp_path / "wl.txt"
    wl.write_text("alpha", encoding="utf-8")

    _invoke(ai_cli.ai, ["anomaly", "--input", str(json_path), "--feature", "a"], obj=app)
    _invoke(
        ai_cli.ai,
        ["train-malware", "--input", str(json_path), "--feature", "a", "--label", "a", "--model", str(tmp_path / "model.json")],
        obj=app,
    )
    _invoke(ai_cli.ai, ["classify-malware", "--input", str(json_path), "--model", str(tmp_path / "model.json")], obj=app)
    _invoke(ai_cli.ai, ["predict-password", "--corpus", str(wl), "--count", "1", "--min-len", "4", "--max-len", "8"], obj=app)

    monkeypatch.setattr(crypto_cli, "extract_wallet_addresses_from_sqlite", lambda *_a, **_k: [_Row("addr")])
    monkeypatch.setattr(crypto_cli, "enrich_wallet_addresses", lambda *_a, **_k: [{"address": "addr"}])

    db = tmp_path / "db.sqlite"
    db.write_text("x", encoding="utf-8")
    _invoke(crypto_cli.crypto_wallet, ["wallet", str(db)], obj=app)

    monkeypatch.setattr(report_cli, "write_html_report", lambda *_a, **_k: None)
    monkeypatch.setattr(report_cli, "write_pdf_report", lambda *_a, **_k: None)
    monkeypatch.setattr(report_cli, "export_json", lambda *_a, **_k: None)
    monkeypatch.setattr(report_cli, "export_csv", lambda *_a, **_k: None)

    artifacts = tmp_path / "artifacts.json"
    artifacts.write_text(json.dumps({"case_id": "CASE"}), encoding="utf-8")
    _invoke(
        report_cli.report,
        ["generate", "--case-id", "CASE", "--template", "technical", "--artifacts", str(artifacts), "--format", "html", "--output", str(tmp_path / "r.html")],
        obj=app,
    )
    _invoke(
        report_cli.report,
        ["chain-of-custody", "--case-id", "CASE", "--examiner", "Examiner", "--evidence", "item", "--output", str(tmp_path / "coc.json")],
        obj=app,
    )

    class _Script:
        def on(self, _event: str, _handler):
            return None

    class _Mgr:
        def __init__(self, device_id=None) -> None:
            _ = device_id

        def spawn_and_attach(self, _app_id: str):
            return 0, object()

        def load_script(self, _session, _script: str):
            return _Script()

    monkeypatch.setattr(runtime_cli, "FridaManager", _Mgr)
    monkeypatch.setattr(
        runtime_cli,
        "get_builtin_runtime_script",
        lambda name: {"name": name, "category": "test", "path": str(wl), "source": f"send('{name}')"},
    )
    monkeypatch.setattr(runtime_cli, "method_tracer_script", lambda *_a, **_k: "m")
    monkeypatch.setattr(runtime_cli, "memory_search", lambda *_a, **_k: json.dumps({"hits": []}))
    monkeypatch.setattr(runtime_cli, "heap_dump", lambda *_a, **_k: json.dumps({"path": "/tmp/heap"}))

    monkeypatch.setattr(runtime_cli.time, "sleep", lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()))
    _invoke(runtime_cli.runtime, ["hook", "app", "--script", str(wl)], obj=app)
    _invoke(runtime_cli.runtime, ["bypass-ssl", "app"], obj=app)
    _invoke(runtime_cli.runtime, ["bypass-root", "app"], obj=app)
    _invoke(runtime_cli.runtime, ["builtin-script", "app", "--name", "debug_bypass"], obj=app)
    _invoke(runtime_cli.runtime, ["trace", "app", "--class", "C", "--method", "m"], obj=app)
    _invoke(runtime_cli.runtime, ["memory-search", "app", "--pattern", "abc", "--timeout", "1.0"], obj=app)
    _invoke(runtime_cli.runtime, ["heap-dump", "app", "--output-path", "/tmp/heap.hprof", "--timeout", "1.0"], obj=app)
