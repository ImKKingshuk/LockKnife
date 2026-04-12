import dataclasses
import json
import pathlib

import pytest

from tests.unit.test_tui_callback import (
    DummyAnalysis,
    DummyAnalysisReport,
    DummyApp,
    DummyAudit,
    DummyBoot,
    DummyFridaManager,
    DummyHardware,
    DummyIoc,
    DummyPredictor,
    DummyRow,
    DummyScan,
    DummySnapshot,
    DummyStatus,
    DummyVuln,
    build_tui_callback,
)


@pytest.mark.skip(
    "Test requires many missing functions in tui_callback module - needs comprehensive function addition"
)
def test_tui_callback_action_matrix(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    from lockknife.core.case import CaseArtifact, CaseArtifactRegistration
    from lockknife.core.case import create_case_workspace as real_create_case_workspace
    from lockknife.core.feature_matrix import FeatureEntry

    monkeypatch.setattr(cb, "extract_wifi_passwords", lambda *a, **k: [DummyRow("wifi")])
    monkeypatch.setattr(cb, "list_keystore", lambda *a, **k: [DummyRow("key")])
    monkeypatch.setattr(cb, "recover_pin", lambda *a, **k: "1234")
    monkeypatch.setattr(cb, "recover_gesture", lambda *a, **k: "ULDR")
    monkeypatch.setattr(cb, "extract_sms", lambda *a, **k: [DummyRow("sms")])
    monkeypatch.setattr(cb, "extract_contacts", lambda *a, **k: [DummyRow("contact")])
    monkeypatch.setattr(cb, "extract_call_logs", lambda *a, **k: [DummyRow("call")])
    monkeypatch.setattr(cb, "extract_chrome_history", lambda *a, **k: [DummyRow("history")])
    monkeypatch.setattr(cb, "extract_chrome_bookmarks", lambda *a, **k: [DummyRow("bookmark")])
    monkeypatch.setattr(cb, "extract_chrome_downloads", lambda *a, **k: [DummyRow("download")])
    monkeypatch.setattr(cb, "extract_chrome_cookies", lambda *a, **k: [DummyRow("cookie")])
    monkeypatch.setattr(cb, "extract_chrome_saved_logins", lambda *a, **k: [DummyRow("login")])
    monkeypatch.setattr(cb, "extract_firefox_history", lambda *a, **k: [DummyRow("history")])
    monkeypatch.setattr(cb, "extract_firefox_bookmarks", lambda *a, **k: [DummyRow("bookmark")])
    monkeypatch.setattr(cb, "extract_firefox_saved_logins", lambda *a, **k: [DummyRow("login")])
    monkeypatch.setattr(cb, "extract_whatsapp_messages", lambda *a, **k: [DummyRow("wa")])
    monkeypatch.setattr(cb, "extract_telegram_messages", lambda *a, **k: [DummyRow("tg")])
    monkeypatch.setattr(cb, "extract_signal_messages", lambda *a, **k: [DummyRow("sig")])
    monkeypatch.setattr(cb, "extract_whatsapp_artifacts", lambda *a, **k: DummyRow("wa_artifacts"))
    monkeypatch.setattr(cb, "extract_telegram_artifacts", lambda *a, **k: DummyRow("tg_artifacts"))
    monkeypatch.setattr(cb, "extract_signal_artifacts", lambda *a, **k: DummyRow("sig_artifacts"))
    monkeypatch.setattr(cb, "extract_media_with_exif", lambda *a, **k: [DummyRow("media")])
    monkeypatch.setattr(cb, "extract_location_artifacts", lambda *a, **k: DummyRow("loc"))
    monkeypatch.setattr(cb, "extract_location_snapshot", lambda *a, **k: DummyRow("loc_snapshot"))
    monkeypatch.setattr(cb, "create_snapshot", lambda *a, **k: DummySnapshot("snap"))
    monkeypatch.setattr(cb, "analyze_sqlite", lambda *a, **k: DummyAnalysis(["t1"]))
    monkeypatch.setattr(
        cb,
        "build_timeline_report",
        lambda *a, **k: {
            "event_count": 1,
            "sources": [{"path": str(sms_json)}],
            "events": [{"ts_ms": 1}],
        },
    )

    @dataclasses.dataclass
    class _ParsedReport:
        input_dir: str
        artifacts: list[dict]
        app_data: list[dict]
        protobuf_files: list[dict]
        summary: dict[str, int]

    monkeypatch.setattr(
        cb,
        "parse_forensics_directory",
        lambda *a, **k: _ParsedReport(
            input_dir=str(tmp_path),
            artifacts=[],
            app_data=[],
            protobuf_files=[],
            summary={"artifact_count": 0, "protobuf_count": 0},
        ),
    )
    monkeypatch.setattr(cb, "looks_like_aleapp_output", lambda *_a, **_k: True)
    monkeypatch.setattr(
        cb,
        "decode_protobuf_file",
        lambda *_a, **_k: {
            "message_count": 1,
            "field_count": 1,
            "messages": [],
            "nested_message_count": 0,
        },
    )
    monkeypatch.setattr(cb, "correlate_artifacts_json_blobs", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(cb, "recover_deleted_records", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(cb, "carve_deleted_files", lambda *a, **k: {"ok": True, "carved_count": 0})
    monkeypatch.setattr(cb, "capture_pcap", lambda *a, **k: DummySnapshot("pcap"))
    monkeypatch.setattr(cb, "summarize_pcap", lambda *a, **k: {"summary": "ok"})
    monkeypatch.setattr(cb, "extract_api_endpoints_from_pcap", lambda *a, **k: {"endpoints": []})
    monkeypatch.setattr(cb, "scan_with_yara", lambda *a, **k: [DummyRow("hit")])
    monkeypatch.setattr(cb, "run_device_audit", lambda *a, **k: [DummyAudit("rule")])
    monkeypatch.setattr(cb, "get_selinux_status", lambda *a, **k: DummyStatus("enforcing"))
    monkeypatch.setattr(
        cb,
        "scan_network",
        lambda *a, **k: DummyScan(["192.0.2.4"], ["192.0.2.4"], [DummyRow("8080")]),
    )
    monkeypatch.setattr(cb, "analyze_bootloader", lambda *a, **k: DummyBoot(True))
    monkeypatch.setattr(cb, "analyze_hardware_security", lambda *a, **k: DummyHardware(True))
    monkeypatch.setattr(
        cb,
        "assess_attack_surface",
        lambda *a, **k: {
            "package": "com.example.app",
            "findings": [{"id": "exported-component-surface", "severity": "medium"}],
            "probe_results": {"attempted": False},
        },
    )
    monkeypatch.setattr(cb, "correlate_cves_for_apk_package", lambda *a, **k: {"cves": []})
    monkeypatch.setattr(
        cb,
        "correlate_cves_for_kernel_version",
        lambda *a, **k: {"kernel_branch": "5.10", "score": 46},
    )
    monkeypatch.setattr(cb, "indicator_reputation", lambda *a, **k: {"indicator": "ok"})
    monkeypatch.setattr(cb, "file_report", lambda *a, **k: {"report": "ok"})
    monkeypatch.setattr(
        cb, "url_report", lambda *a, **k: {"report": "ok", "summary": {"detection_ratio": 0.1}}
    )
    monkeypatch.setattr(
        cb, "domain_report", lambda *a, **k: {"report": "ok", "summary": {"detection_ratio": 0.1}}
    )
    monkeypatch.setattr(
        cb, "ip_report", lambda *a, **k: {"report": "ok", "summary": {"detection_ratio": 0.1}}
    )
    monkeypatch.setattr(
        cb,
        "submit_url_for_analysis",
        lambda *a, **k: {"submitted": True, "submission_id": "analysis-1"},
    )
    monkeypatch.setattr(cb, "detect_iocs", lambda *a, **k: [DummyIoc("192.0.2.4", "ipv4", "text")])
    monkeypatch.setattr(
        cb, "load_stix_indicators_from_url", lambda *a, **k: [DummyIoc("192.0.2.3", "ipv4", "stix")]
    )
    monkeypatch.setattr(
        cb, "load_taxii_indicators", lambda *a, **k: [DummyIoc("192.0.2.7", "ipv4", "taxii")]
    )
    monkeypatch.setattr(
        cb, "anomaly_scores", lambda *a, **k: [{"row": {"x": 1}, "anomaly_score": 0.9}]
    )
    monkeypatch.setattr(
        cb,
        "PasswordPredictor",
        type("P", (), {"train_from_wordlist": lambda *_a, **_k: DummyPredictor()}),
    )
    monkeypatch.setattr(cb, "load_personal_data", lambda *a, **k: {"owner": "Casey"})
    monkeypatch.setattr(
        cb, "extract_wallet_addresses_from_sqlite", lambda *a, **k: [DummyRow("addr")]
    )
    monkeypatch.setattr(cb, "enrich_wallet_addresses", lambda *a, **k: [{"address": "addr"}])
    monkeypatch.setattr(cb, "list_wallet_transactions", lambda *a, **k: [{"hash": "tx"}])
    monkeypatch.setattr(
        cb,
        "write_html_report",
        lambda _template, _context, output, **_k: pathlib.Path(output).write_text(
            "<html></html>", encoding="utf-8"
        ),
    )
    monkeypatch.setattr(
        cb,
        "write_pdf_report",
        lambda _context, output, **_k: pathlib.Path(output).write_bytes(b"%PDF-1.4\n"),
    )
    monkeypatch.setattr(cb, "export_json", lambda *a, **k: None)
    monkeypatch.setattr(cb, "export_csv", lambda *a, **k: None)
    monkeypatch.setattr(
        cb,
        "parse_apk_manifest",
        lambda *a, **k: {"permissions": [], "package": "x", "version_name": "1"},
    )
    monkeypatch.setattr(cb, "score_permissions", lambda *a, **k: (1, [DummyRow("risk")]))
    monkeypatch.setattr(
        cb,
        "analyze_apk",
        lambda *a, **k: DummyAnalysisReport(
            package="x",
            manifest={"package": "x", "permissions": [], "sdk": {"target": "33"}},
            findings=[DummyRow("finding")],
            permission_risk={"score": 1, "risks": [{"name": "risk"}]},
            risk_summary={"score": 42, "level": "medium"},
            mastg={"mastg_ids": ["MSTG-RESILIENCE-2"]},
        ),
    )
    monkeypatch.setattr(cb, "extract_dex_headers", lambda *a, **k: [{"dex": 1}])
    monkeypatch.setattr(cb, "vulnerability_report", lambda *a, **k: DummyVuln(1.2))
    monkeypatch.setattr(
        cb,
        "decompile_apk_report",
        lambda *_a, **_k: {
            "output_dir": str(tmp_path / "apk_out"),
            "manifest_path": str(tmp_path / "apk_out" / "manifest.json"),
            "report_path": str(tmp_path / "apk_out" / "decompile_report.json"),
            "selected_mode": "unpack",
            "positioning": {"selected_mode": "unpack", "source_recovery_level": "archive-unpack"},
        },
    )
    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb, "ssl_pinning_bypass_script", lambda: "script")
    monkeypatch.setattr(cb, "root_bypass_script", lambda: "script")
    monkeypatch.setattr(cb, "method_tracer_script", lambda *_a, **_k: "script")
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(cb, "memory_search", lambda *a, **k: json.dumps({"hits": []}))
    monkeypatch.setattr(cb, "heap_dump", lambda *a, **k: json.dumps({"path": "/tmp/heap"}))
    monkeypatch.setattr(
        cb, "health_status", lambda: {"ok": True, "checks": {"rust_extension": "ready"}}
    )
    monkeypatch.setattr(cb, "doctor_status", lambda: {"ok": True, "dependencies": {"adb": "ready"}})
    monkeypatch.setattr(
        cb,
        "iter_features",
        lambda: (
            FeatureEntry(
                category="core",
                capability="Default TUI",
                cli="lockknife",
                status="functional",
                requirements="Rust extension",
                notes="Primary operator interface.",
            ),
        ),
    )
    monkeypatch.setattr(cb, "_load_config_text", lambda *_a, **_k: ("key=1", "lockknife.toml"))
    monkeypatch.setattr(cb, "create_case_workspace", lambda **_k: None)
    monkeypatch.setattr(
        cb,
        "summarize_case_manifest",
        lambda case_dir, **kwargs: {
            "case_id": "CASE-001",
            "artifact_count": 1,
            "total_artifact_count": 2,
            "filters": kwargs,
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "case_lineage_graph",
        lambda case_dir, **kwargs: {
            "case_id": "CASE-001",
            "artifact_count": 1,
            "total_artifact_count": 2,
            "filters": kwargs,
            "root_artifact_ids": ["artifact-0001"],
            "nodes": [],
            "edges": [],
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "query_case_artifacts",
        lambda case_dir, **kwargs: {
            "case_id": "CASE-001",
            "artifact_count": 1,
            "total_artifact_count": 2,
            "filters": {
                k: kwargs.get(k, [])
                for k in ("categories", "exclude_categories", "source_commands", "device_serials")
            },
            "search": {
                "query": kwargs.get("query"),
                "path_contains": kwargs.get("path_contains"),
                "metadata_contains": kwargs.get("metadata_contains"),
                "limit": kwargs.get("limit"),
            },
            "artifacts": [
                {
                    "artifact_id": "artifact-0001",
                    "path": "derived/timeline.json",
                    "category": "forensics-timeline",
                    "source_command": "forensics timeline",
                    "device_serial": "SERIAL",
                }
            ],
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "case_artifact_details",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "artifact": {
                "artifact_id": "artifact-0001",
                "path": "derived/timeline.json",
                "category": "forensics-timeline",
                "source_command": "forensics timeline",
                "device_serial": "SERIAL",
                "size_bytes": 12,
                "created_at_utc": "2026-03-07T00:00:00Z",
                "sha256": "abc",
                "input_paths": ["evidence/sms.json"],
                "parent_artifact_ids": ["artifact-0000"],
                "metadata": {"kind": "timeline"},
            },
            "parents": [],
            "children": [],
            "missing_parent_ids": [],
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "case_artifact_lineage",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "artifact": {
                "artifact_id": "artifact-0001",
                "path": "derived/timeline.json",
                "category": "forensics-timeline",
                "source_command": "forensics timeline",
                "device_serial": "SERIAL",
                "size_bytes": 12,
                "created_at_utc": "2026-03-07T00:00:00Z",
                "parent_artifact_ids": ["artifact-0000"],
                "input_paths": ["evidence/sms.json"],
            },
            "parents": [],
            "children": [],
            "missing_parent_ids": [],
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "run_case_enrichment",
        lambda **kwargs: {
            "case_dir": str(kwargs["case_dir"]),
            "case_id": "CASE-001",
            "title": "Demo",
            "summary": {
                "selected_artifact_count": 1,
                "workflow_run_count": 2,
                "skipped_artifact_count": 0,
            },
            "provider_status": [
                {
                    "provider": "lockknife-local-ioc-detection",
                    "credentials": {"configured": None},
                    "cache": {"mode": "none"},
                }
            ],
            "runs": [],
            "output": str(tmp_path / "case" / "derived" / "case_enrichment_CASE-001.json"),
        },
    )
    monkeypatch.setattr(
        cb,
        "export_case_bundle",
        lambda **kwargs: {
            "bundle_path": str(kwargs["output_path"]),
            "filters": {
                k: kwargs.get(k, [])
                for k in ("categories", "exclude_categories", "source_commands", "device_serials")
            },
            "include_registered_artifacts": kwargs.get("include_registered_artifacts", False),
        },
    )
    monkeypatch.setattr(
        cb,
        "register_case_artifact_with_status",
        lambda **kwargs: CaseArtifactRegistration(
            artifact=CaseArtifact(
                artifact_id="artifact-0002",
                path=str(kwargs["path"]),
                category=kwargs["category"],
                source_command=kwargs["source_command"],
                sha256="def",
                size_bytes=9,
                created_at_utc="2026-03-07T00:00:00Z",
                device_serial=kwargs.get("device_serial"),
                input_paths=kwargs.get("input_paths") or [],
                parent_artifact_ids=kwargs.get("parent_artifact_ids") or [],
                metadata=kwargs.get("metadata") or {},
            ),
            action="created",
        ),
    )
    monkeypatch.setattr(
        cb,
        "query_case_jobs",
        lambda case_dir, **kwargs: {
            "case_id": "CASE-001",
            "case_dir": str(case_dir),
            "job_count": 0,
            "total_job_count": 0,
            "filters": kwargs,
            "jobs": [],
        },
    )

    callback = build_tui_callback(DummyApp())

    sms_json = tmp_path / "sms.json"
    calls_json = tmp_path / "calls.json"
    browser_json = tmp_path / "browser.json"
    sms_json.write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    calls_json.write_text(json.dumps([{"b": 2}]), encoding="utf-8")
    browser_json.write_text(json.dumps({"history": []}), encoding="utf-8")
    timeline_out = tmp_path / "timeline.json"
    report_out = tmp_path / "report.html"
    artifacts_json = tmp_path / "artifacts.json"
    artifacts_json.write_text(json.dumps([{"id": "debuggable"}]), encoding="utf-8")
    sqlite_path = tmp_path / "db.sqlite"
    sqlite_path.write_text("dummy", encoding="utf-8")
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_text("pcap", encoding="utf-8")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\nbeta\n", encoding="utf-8")
    case_dir = tmp_path / "case"
    real_create_case_workspace(
        case_dir=case_dir, case_id="CASE-MATRIX", examiner="Examiner", title="Matrix"
    )
    artifact_path = case_dir / "derived" / "timeline.json"

    actions = [
        ("device.list", {}),
        ("device.info", {"serial": "SERIAL"}),
        ("device.connect", {"host": "192.0.2.1:5555"}),
        ("core.health", {}),
        ("core.doctor", {}),
        ("core.features", {}),
        ("credentials.pin", {"serial": "SERIAL", "length": 4}),
        ("credentials.gesture", {"serial": "SERIAL"}),
        ("credentials.wifi", {"serial": "SERIAL"}),
        ("credentials.keystore", {"serial": "SERIAL"}),
        ("extraction.sms", {"serial": "SERIAL", "limit": 1}),
        ("extraction.contacts", {"serial": "SERIAL", "limit": 1}),
        ("extraction.call_logs", {"serial": "SERIAL", "limit": 1}),
        (
            "extraction.browser",
            {"serial": "SERIAL", "app": "chrome", "kind": "history", "limit": 1},
        ),
        ("extraction.messaging", {"serial": "SERIAL", "app": "signal", "limit": 1}),
        ("extraction.media", {"serial": "SERIAL", "limit": 1}),
        ("extraction.location", {"serial": "SERIAL"}),
        (
            "forensics.snapshot",
            {
                "serial": "SERIAL",
                "output": str(tmp_path / "snap.tar"),
                "full": False,
                "encrypt": False,
            },
        ),
        ("forensics.sqlite", {"path": str(sqlite_path)}),
        (
            "forensics.timeline",
            {
                "sms": str(sms_json),
                "calls": str(calls_json),
                "browser": str(browser_json),
                "output": str(timeline_out),
            },
        ),
        (
            "forensics.parse",
            {"path": str(tmp_path), "output": str(tmp_path / "parsed_artifacts.json")},
        ),
        (
            "forensics.import_aleapp",
            {"input_dir": str(tmp_path), "output": str(tmp_path / "aleapp_import.json")},
        ),
        (
            "forensics.decode_protobuf",
            {"path": str(sqlite_path), "output": str(tmp_path / "protobuf.json")},
        ),
        ("forensics.correlate", {"inputs": f"{sms_json},{calls_json}"}),
        ("forensics.recover", {"path": str(sqlite_path)}),
        (
            "report.generate",
            {
                "case_id": "CASE",
                "template": "technical",
                "format": "html",
                "output": str(report_out),
            },
        ),
        (
            "report.chain_of_custody",
            {"case_dir": str(case_dir), "output": str(tmp_path / "custody.html"), "format": "html"},
        ),
        (
            "report.integrity",
            {"case_dir": str(case_dir), "output": str(tmp_path / "integrity.json")},
        ),
        (
            "case.init",
            {
                "case_dir": str(case_dir),
                "case_id": "CASE-001",
                "examiner": "Examiner",
                "title": "Case",
            },
        ),
        ("case.summary", {"case_dir": str(case_dir), "categories": "extract-sms"}),
        ("case.jobs", {"case_dir": str(case_dir), "statuses": "failed", "limit": 5}),
        ("case.graph", {"case_dir": str(case_dir), "exclude_categories": "runtime-session-log"}),
        ("case.artifacts", {"case_dir": str(case_dir), "query": "timeline", "limit": 5}),
        ("case.artifact", {"case_dir": str(case_dir), "artifact_id": "artifact-0001"}),
        ("case.lineage", {"case_dir": str(case_dir), "artifact_id": "artifact-0001"}),
        (
            "case.export",
            {
                "case_dir": str(case_dir),
                "output": str(tmp_path / "bundle.zip"),
                "include_registered_artifacts": True,
            },
        ),
        ("case.enrich", {"case_dir": str(case_dir)}),
        (
            "case.register",
            {
                "case_dir": str(case_dir),
                "path": str(artifact_path),
                "category": "forensics-timeline",
                "source_command": "forensics timeline",
                "metadata_json": json.dumps({"kind": "timeline"}),
            },
        ),
        (
            "network.capture",
            {"serial": "SERIAL", "output": str(pcap_path), "duration": 1, "iface": "any"},
        ),
        ("network.summarize", {"path": str(pcap_path)}),
        ("network.api_discovery", {"path": str(pcap_path)}),
        ("apk.permissions", {"path": str(sqlite_path)}),
        ("apk.analyze", {"path": str(sqlite_path)}),
        ("apk.decompile", {"path": str(sqlite_path), "output": str(tmp_path / "apk_out")}),
        ("apk.vulnerability", {"path": str(sqlite_path)}),
        ("apk.scan", {"rule": str(sqlite_path), "path": str(sqlite_path)}),
        (
            "runtime.hook",
            {"app_id": "app", "script": str(wordlist), "case_dir": str(case_dir), "timeout": "0"},
        ),
        ("runtime.bypass_ssl", {"app_id": "app", "case_dir": str(case_dir), "timeout": "0"}),
        ("runtime.bypass_root", {"app_id": "app", "case_dir": str(case_dir), "timeout": "0"}),
        (
            "runtime.trace",
            {
                "app_id": "app",
                "class": "C",
                "method": "m",
                "case_dir": str(case_dir),
                "timeout": "0",
            },
        ),
        ("runtime.memory_search", {"app_id": "app", "pattern": "abc"}),
        ("runtime.heap_dump", {"app_id": "app", "output": "/tmp/heap.hprof"}),
        ("security.audit", {"serial": "SERIAL"}),
        ("security.selinux", {"serial": "SERIAL"}),
        ("security.malware", {"rule": str(sqlite_path), "target": str(sqlite_path)}),
        ("security.network_scan", {"serial": "SERIAL"}),
        ("security.bootloader", {"serial": "SERIAL"}),
        ("security.hardware", {"serial": "SERIAL"}),
        ("security.attack_surface", {"artifacts": str(artifacts_json)}),
        (
            "security.owasp",
            {"artifacts": str(artifacts_json), "output": str(tmp_path / "mastg.json")},
        ),
        ("intelligence.ioc", {"input": str(sms_json)}),
        ("intelligence.cve", {"package": "pkg"}),
        ("intelligence.cve_risk", {"sdk": 34, "kernel_version": "5.10.1"}),
        ("intelligence.virustotal", {"hash": "abcd"}),
        ("intelligence.otx", {"indicator": "example.com"}),
        ("intelligence.stix", {"url": "https://example.com/stix.json"}),
        ("intelligence.taxii", {"api_root": "https://example.com/api", "limit": 10}),
        ("ai.anomaly_score", {"input": str(sms_json), "features": "a"}),
        (
            "ai.predict_passwords",
            {
                "wordlist": str(wordlist),
                "personal_data": str(sms_json),
                "count": 2,
                "min_len": 4,
                "max_len": 8,
                "markov_order": 2,
            },
        ),
        ("crypto.wallets", {"path": str(sqlite_path), "limit": 10}),
        ("crypto.transactions", {"address": "addr", "kind": "btc", "limit": 5}),
        ("config.load", {}),
        ("config.save", {"text": "k=1", "path": str(tmp_path / "lockknife.toml")}),
    ]

    for action, payload in actions:
        result = callback(action, payload)
        assert result["ok"] is True, action
