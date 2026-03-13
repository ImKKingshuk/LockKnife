import json
import pathlib
import types

import pytest

from tests.unit.test_tui_callback import DummyApp, DummyFridaManager, DummyIoc, DummyPredictor, DummyRow, build_tui_callback

def test_tui_callback_case_actions_require_artifact_reference(tmp_path: pathlib.Path) -> None:
    callback = build_tui_callback(DummyApp())
    result = callback("case.artifact", {"case_dir": str(tmp_path / "case")})
    assert result["ok"] is False
    assert "artifact_id or path" in result["error"]

def test_tui_callback_case_aware_actions_route_outputs_into_case_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    import lockknife_headless_cli._tui_callback_helpers as cb_helpers

    registered: list[dict[str, object]] = []

    monkeypatch.setattr(
        cb,
        "build_timeline_report",
        lambda **_k: {"event_count": 1, "sources": [{"path": str(sms_json)}], "events": [{"ts_ms": 1}]},
    )
    monkeypatch.setattr(cb, "summarize_pcap", lambda _path: {"packets": 3})
    monkeypatch.setattr(cb, "run_device_audit", lambda *_a, **_k: [DummyRow("finding")])
    monkeypatch.setattr(
        cb,
        "assess_attack_surface",
        lambda *_a, **_k: {
            "package": "com.example.app",
            "findings": [],
            "probe_results": {"attempted": False},
        },
    )
    monkeypatch.setattr(cb, "register_case_artifact", lambda **kwargs: registered.append(kwargs))
    monkeypatch.setattr(cb_helpers, "register_case_artifact", lambda **kwargs: registered.append(kwargs))
    monkeypatch.setattr(
        cb,
        "find_case_artifact",
        lambda *_a, **_k: types.SimpleNamespace(artifact_id="artifact-0001"),
    )
    monkeypatch.setattr(cb, "_template_path", lambda *_a, **_k: tmp_path / "report.html.j2")
    monkeypatch.setattr(
        cb,
        "write_html_report",
        lambda _template, _context, output: output.write_text("<html></html>", encoding="utf-8"),
    )

    callback = build_tui_callback(DummyApp())

    case_dir = tmp_path / "case"
    cb.create_case_workspace(case_dir=case_dir, case_id="CASE-001", examiner="Examiner", title="TUI")
    sms_json = tmp_path / "sms.json"
    sms_json.write_text("[]", encoding="utf-8")
    calls_json = tmp_path / "calls.json"
    calls_json.write_text("[]", encoding="utf-8")
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_text("pcap", encoding="utf-8")
    artifacts_json = tmp_path / "artifacts.json"
    artifacts_json.write_text(json.dumps({"manifest": {"package": "com.example.app"}}), encoding="utf-8")

    result = callback(
        "forensics.timeline",
        {"sms": str(sms_json), "calls": str(calls_json), "case_dir": str(case_dir), "output": ""},
    )
    assert result["ok"] is True

    result = callback(
        "network.summarize",
        {"path": str(pcap_path), "case_dir": str(case_dir), "output": ""},
    )
    assert result["ok"] is True

    result = callback(
        "security.audit",
        {"serial": "SERIAL", "case_dir": str(case_dir), "output": ""},
    )
    assert result["ok"] is True

    result = callback(
        "security.attack_surface",
        {"artifacts": str(artifacts_json), "case_dir": str(case_dir), "output": ""},
    )
    assert result["ok"] is True

    result = callback(
        "report.generate",
        {
            "case_id": "CASE-001",
            "template": "technical",
            "format": "html",
            "case_dir": str(case_dir),
            "output": "",
            "data_json": json.dumps({"summary": "ok"}),
        },
    )
    assert result["ok"] is True

    registered_by_category = {entry["category"]: pathlib.Path(entry["path"]) for entry in registered}
    assert registered_by_category["forensics-timeline"] == case_dir / "derived" / "timeline.json"
    assert registered_by_category["network-analysis"] == case_dir / "derived" / "network_analyze_capture.json"
    assert registered_by_category["security-scan"] == case_dir / "derived" / "security_scan_SERIAL.json"
    assert registered_by_category["security-attack-surface"] == case_dir / "derived" / "security_attack_surface_com_example_app.json"
    assert registered_by_category["report-html"] == case_dir / "reports" / "report_CASE-001.html"


def test_tui_callback_passkeys_register_case_artifacts(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    from lockknife.modules.credentials.fido2 import PasskeyArtifact

    case_dir = tmp_path / "case"
    cb.create_case_workspace(case_dir=case_dir, case_id="CASE-777", examiner="Examiner", title="TUI")

    def _pull(_devices, _serial: str, *, output_dir: pathlib.Path, limit: int):
        _ = limit
        output_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = output_dir / "credential.bin"
        artifact_path.write_text("secret", encoding="utf-8")
        return [PasskeyArtifact(remote_path="/data/cred.bin", local_path=str(artifact_path), size=artifact_path.stat().st_size)]

    monkeypatch.setattr(cb, "pull_passkey_artifacts", _pull)

    callback = build_tui_callback(DummyApp())
    result = callback("credentials.passkeys", {"case_dir": str(case_dir), "limit": 5})
    assert result["ok"] is True
    payload = json.loads(result["data_json"])
    assert payload["case_dir"] == str(case_dir)
    assert payload["artifact_count"] == 1
    assert payload["success_count"] == 1

    manifest = cb.load_case_manifest(case_dir)
    categories = {artifact.category for artifact in manifest.artifacts}
    assert "crack-passkey-artifact" in categories
    assert "crack-passkeys-manifest" in categories

def test_tui_callback_report_generation_can_summarize_case_context_on_demand(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb

    captured: dict[str, object] = {}

    case_dir = tmp_path / "case"
    cb.create_case_workspace(case_dir=case_dir, case_id="CASE-010", examiner="Examiner", title="Case")
    monkeypatch.setattr(
        cb,
        "build_report_context",
        lambda **kwargs: {"artifacts": {"artifact_count": 7}, "case_dir": str(kwargs["case_dir"])},
    )
    monkeypatch.setattr(
        cb,
        "write_html_report",
        lambda template_path, context, output: captured.update(
            {
                "template_path": pathlib.Path(template_path),
                "context": context,
                "output": pathlib.Path(output),
            }
        ),
    )
    monkeypatch.setattr(cb, "_register_case_output", lambda *args, **kwargs: None)

    callback = build_tui_callback(types.SimpleNamespace())

    result = callback(
        "report.generate",
        {
            "case_id": "CASE-010",
            "template": "technical",
            "format": "html",
            "case_dir": str(case_dir),
            "output": "",
        },
    )

    assert result["ok"] is True
    assert captured["output"] == case_dir / "reports" / "technical_CASE-010.html"
    assert captured["context"]["artifacts"]["artifact_count"] == 7

def test_tui_callback_case_first_reporting_support_actions_write_into_case_dir(
    tmp_path: pathlib.Path,
) -> None:
    from lockknife.core.case import create_case_workspace, register_case_artifact

    callback = build_tui_callback(types.SimpleNamespace())
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-777", examiner="Examiner", title="Case")
    evidence_path = case_dir / "evidence" / "sms.json"
    evidence_path.write_text("[]", encoding="utf-8")
    register_case_artifact(
        case_dir=case_dir,
        path=evidence_path,
        category="extract-sms",
        source_command="extract sms",
        device_serial="SER-1",
    )

    custody = callback("report.chain_of_custody", {"case_dir": str(case_dir), "output": ""})
    integrity = callback("report.integrity", {"case_dir": str(case_dir), "output": "", "format": "json"})

    assert custody["ok"] is True
    assert integrity["ok"] is True
    assert (case_dir / "reports" / "chain_of_custody_CASE-777.txt").exists()
    assert (case_dir / "reports" / "integrity_CASE-777.json").exists()

def test_tui_callback_additional_case_aware_actions_route_outputs_into_case_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    import lockknife_headless_cli._tui_callback_helpers as cb_helpers

    registered: list[dict[str, object]] = []

    monkeypatch.setattr(cb, "extract_sms", lambda *_a, **_k: [DummyRow("sms")])
    monkeypatch.setattr(
        cb,
        "parse_apk_manifest",
        lambda *_a, **_k: {"permissions": ["android.permission.CAMERA"], "package": "pkg", "version_name": "1", "version_code": "1"},
    )
    monkeypatch.setattr(cb, "score_permissions", lambda *_a, **_k: (7, [DummyRow("risk")]))
    monkeypatch.setattr(cb, "memory_search", lambda *_a, **_k: json.dumps({"hits": ["deadbeef"]}))
    monkeypatch.setattr(cb, "heap_dump", lambda *_a, **_k: json.dumps({"path": "/sdcard/lockknife.hprof"}))
    monkeypatch.setattr(cb, "detect_iocs", lambda *_a, **_k: [DummyIoc("1.1.1.1", "ipv4", "body")])
    monkeypatch.setattr(cb, "anomaly_scores", lambda *_a, **_k: [{"row": {"x": 1}, "anomaly_score": 0.9}])
    monkeypatch.setattr(cb, "PasswordPredictor", type("P", (), {"train_from_wordlist": lambda *_a, **_k: DummyPredictor()}))
    monkeypatch.setattr(cb, "extract_wallet_addresses_from_sqlite", lambda *_a, **_k: [DummyRow("addr")])
    monkeypatch.setattr(cb, "enrich_wallet_addresses", lambda *_a, **_k: [{"address": "addr"}])
    monkeypatch.setattr(cb, "register_case_artifact", lambda **kwargs: registered.append(kwargs))
    monkeypatch.setattr(cb_helpers, "register_case_artifact", lambda **kwargs: registered.append(kwargs))

    callback = build_tui_callback(DummyApp())

    case_dir = tmp_path / "case"
    cb.create_case_workspace(case_dir=case_dir, case_id="CASE-001", examiner="Examiner", title="TUI")
    apk_path = tmp_path / "sample.apk"
    apk_path.write_text("apk", encoding="utf-8")
    anomaly_input = tmp_path / "rows.json"
    anomaly_input.write_text(json.dumps([{"x": 1}]), encoding="utf-8")
    ioc_input = tmp_path / "iocs.json"
    ioc_input.write_text(json.dumps({"note": "connect to 1.1.1.1"}), encoding="utf-8")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\nbeta\n", encoding="utf-8")
    wallet_db = tmp_path / "wallets.sqlite"
    wallet_db.write_text("sqlite", encoding="utf-8")

    assert callback(
        "extraction.sms",
        {"serial": "SERIAL", "limit": "10", "format": "json", "case_dir": str(case_dir), "output": ""},
    )["ok"] is True
    assert callback(
        "apk.permissions",
        {"path": str(apk_path), "case_dir": str(case_dir), "output": ""},
    )["ok"] is True
    assert callback(
        "runtime.memory_search",
        {
            "app_id": "com.example.app",
            "pattern": "deadbeef",
            "hex": "true",
            "case_dir": str(case_dir),
            "output": "",
        },
    )["ok"] is True
    assert callback(
        "runtime.heap_dump",
        {
            "app_id": "com.example.app",
            "output": "/sdcard/lockknife.hprof",
            "case_dir": str(case_dir),
            "result_output": "",
        },
    )["ok"] is True
    intel_result = callback(
        "intelligence.ioc",
        {"input": str(ioc_input), "case_dir": str(case_dir), "output": ""},
    )
    assert intel_result["ok"] is True
    intel_payload = json.loads(intel_result["data_json"])
    assert intel_payload["source_attribution"][0]["provider"] == "lockknife-local-ioc-detection"
    assert intel_payload["summary"]["match_count"] == 1
    anomaly_payload = json.loads(
        callback(
            "ai.anomaly_score",
            {"input": str(anomaly_input), "features": "x", "case_dir": str(case_dir), "output": ""},
        )["data_json"]
    )
    assert anomaly_payload["advisory"].startswith("AI anomaly scoring")
    assert anomaly_payload["explainability"]["feature_keys"] == ["x"]
    password_result = callback(
        "ai.predict_passwords",
        {"wordlist": str(wordlist), "count": "2", "case_dir": str(case_dir), "output": ""},
    )
    assert password_result["ok"] is True
    password_payload = json.loads(password_result["data_json"])
    assert password_payload["summary"]["generated_count"] == 2
    assert password_payload["explainability"]["sample_predictions"][:2] == ["pwd0", "pwd1"]
    assert callback(
        "crypto.wallets",
        {"path": str(wallet_db), "limit": "10", "lookup": "true", "case_dir": str(case_dir), "output": ""},
    )["ok"] is True

    registered_by_category = {entry["category"]: pathlib.Path(entry["path"]) for entry in registered}
    assert registered_by_category["extract-sms"] == case_dir / "evidence" / "sms.json"
    assert registered_by_category["apk-permissions"] == case_dir / "derived" / "apk_permissions_sample.json"
    assert registered_by_category["runtime-memory-search"] == case_dir / "derived" / "runtime_memory_search_com_example_app.json"
    assert registered_by_category["runtime-heap-dump"] == case_dir / "derived" / "runtime_heap_dump_com_example_app.json"
    assert registered_by_category["intel-ioc"] == case_dir / "derived" / "intel_ioc_iocs.json"
    assert registered_by_category["ai-anomaly"] == case_dir / "derived" / "ai_anomaly_rows.json"
    assert registered_by_category["ai-password-predictions"] == case_dir / "derived" / "ai_predict_password_words.json"
    assert registered_by_category["crypto-wallet"] == case_dir / "derived" / "crypto_wallet_wallets.json"

def test_tui_callback_case_action_messages_match_tui_labels(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb

    monkeypatch.setattr(
        cb,
        "query_case_artifacts",
        lambda case_dir, **_kwargs: {"case_id": "CASE-001", "artifacts": [], "case_dir": str(case_dir)},
    )
    monkeypatch.setattr(
        cb,
        "case_artifact_details",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "artifact": {"artifact_id": "artifact-0001", "path": "derived/timeline.json"},
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "case_artifact_lineage",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "artifact": {"artifact_id": "artifact-0001", "path": "derived/timeline.json"},
            "parents": [],
            "children": [],
            "missing_parent_ids": [],
            "case_dir": str(case_dir),
        },
    )
    monkeypatch.setattr(
        cb,
        "export_case_bundle",
        lambda **kwargs: {"bundle_path": str(kwargs["output_path"]), "case_id": "CASE-001"},
    )
    monkeypatch.setattr(
        cb,
        "run_case_enrichment",
        lambda **kwargs: {
            "case_dir": str(kwargs["case_dir"]),
            "case_id": "CASE-001",
            "title": "Case",
            "summary": {"selected_artifact_count": 1, "workflow_run_count": 3, "skipped_artifact_count": 0},
            "provider_status": [{"provider": "osv.dev", "credentials": {"configured": None}, "cache": {"mode": "http-ttl"}}],
            "runs": [{"workflow": "intelligence.cve"}],
            "output": str(kwargs.get("output") or (kwargs["case_dir"] / "derived" / "case_enrichment_CASE-001.json")),
        },
    )

    callback = build_tui_callback(DummyApp())
    case_dir = tmp_path / "case"
    bundle_path = tmp_path / "case-bundle.zip"

    assert callback("case.artifacts", {"case_dir": str(case_dir)})["message"] == (
        f"Artifact search ready for {case_dir}"
    )
    assert callback(
        "case.artifact",
        {"case_dir": str(case_dir), "artifact_id": "artifact-0001"},
    )["message"] == "Artifact detail ready for artifact-0001"
    assert callback(
        "case.lineage",
        {"case_dir": str(case_dir), "artifact_id": "artifact-0001"},
    )["message"] == "Artifact lineage ready for artifact-0001"
    assert callback(
        "case.export",
        {"case_dir": str(case_dir), "output": str(bundle_path)},
    )["message"] == f"Export bundle saved to {bundle_path}"
    enrich = callback("case.enrich", {"case_dir": str(case_dir)})
    assert enrich["message"].endswith("case_enrichment_CASE-001.json")
    enrich_payload = json.loads(enrich["data_json"])
    assert enrich_payload["summary"]["workflow_run_count"] == 3

def test_tui_callback_case_job_actions_surface_job_history_and_rerun_context(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb

    case_dir = tmp_path / "case"
    rerun_params: list[dict[str, object]] = []

    monkeypatch.setattr(
        cb,
        "query_case_jobs",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "case_dir": str(case_dir),
            "jobs": [{"job_id": "job-0007", "status": "failed"}],
        },
    )
    monkeypatch.setattr(
        cb,
        "case_job_details",
        lambda case_dir, **_kwargs: {
            "case_id": "CASE-001",
            "case_dir": str(case_dir),
            "job": {"job_id": "job-0007", "status": "failed"},
        },
    )
    monkeypatch.setattr(
        cb,
        "case_job_rerun_context",
        lambda case_dir, **kwargs: {
            "case_id": "CASE-001",
            "case_dir": str(case_dir),
            "action_id": "case.summary",
            "params": {"categories": "runtime-session"},
            "job": {"job_id": kwargs["job_id"]},
        },
    )
    monkeypatch.setattr(
        cb,
        "summarize_case_manifest",
        lambda case_dir, **kwargs: rerun_params.append(kwargs) or {"case_dir": str(case_dir), "case_id": "CASE-001"},
    )

    callback = build_tui_callback(DummyApp())

    assert callback("case.jobs", {"case_dir": str(case_dir)})["message"] == f"Job history ready for {case_dir}"
    assert callback("case.job", {"case_dir": str(case_dir), "job_id": "job-0007"})["message"] == "Job detail ready for job-0007"
    assert callback("case.resume_job", {"case_dir": str(case_dir), "job_id": "job-0007"})["message"] == (
        f"Case summary ready for {case_dir}"
    )
    assert callback("case.retry_job", {"case_dir": str(case_dir), "job_id": "job-0007"})["message"] == (
        f"Case summary ready for {case_dir}"
    )
    assert rerun_params == [
        {
            "categories": ["runtime-session"],
            "exclude_categories": [],
            "source_commands": [],
            "device_serials": [],
        },
        {
            "categories": ["runtime-session"],
            "exclude_categories": [],
            "source_commands": [],
            "device_serials": [],
        },
    ]

def test_tui_callback_case_managed_runtime_jobs_persist_job_json(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lockknife_headless_cli.tui_callback as cb
    from lockknife.core.case import create_case_workspace, load_case_manifest

    monkeypatch.setattr(cb, "FridaManager", DummyFridaManager)
    monkeypatch.setattr(cb, "ssl_pinning_bypass_script", lambda: "ssl-script")
    monkeypatch.setattr(cb, "root_bypass_script", lambda: "root-script")
    monkeypatch.setattr(cb, "method_tracer_script", lambda *_a, **_k: "trace-script")
    monkeypatch.setattr(cb.time, "sleep", lambda *_a, **_k: None)

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-200", examiner="Examiner", title="Jobs")
    script_path = tmp_path / "hook.js"
    script_path.write_text("send('hook');", encoding="utf-8")
    callback = build_tui_callback(DummyApp())

    result = callback(
        "runtime.hook",
        {"app_id": "app", "script": str(script_path), "timeout": "0", "case_dir": str(case_dir), "output": ""},
    )

    assert result["ok"] is True
    assert "job_json" in result
    job_payload = json.loads(result["job_json"])
    assert job_payload["status"] == "succeeded"
    manifest = load_case_manifest(case_dir)
    assert len(manifest.jobs) == 1
    assert manifest.jobs[0].job_id == job_payload["job_id"]
    assert pathlib.Path(manifest.jobs[0].logs_path).exists()
