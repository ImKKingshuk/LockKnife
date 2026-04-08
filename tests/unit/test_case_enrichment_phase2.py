import dataclasses
import json
import pathlib
import types

from lockknife.core._case_models import CaseManifest
from lockknife.modules._case_enrichment_common import (
    _base_payload,
    _float_or_none,
    _hash_prefix,
    _looks_like_sha256,
    _safe_package,
    _secret_status,
    _source,
    _summarize_matches,
)
from lockknife.modules._case_enrichment_helpers import (
    _artifact_path,
    _extract_package,
    _infer_numeric_feature_keys,
    _load_artifact_data,
    _selected_artifacts,
    _structured_rows,
    _unique_provider_status,
)
from lockknife.modules._case_enrichment_orchestrator import run_case_enrichment
from lockknife.modules._case_enrichment_runs import _error_run_entry, _pcap_runs, _reputation_runs, _run_entry
from lockknife.modules._case_enrichment_summary import summarize_case_enrichment_runs
from lockknife.modules.intelligence.ioc import IocMatch


def test_case_enrichment_common_and_helper_functions(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules._case_enrichment_common as common
    import lockknife.modules._case_enrichment_helpers as helpers

    monkeypatch.setattr(common, "load_secrets", lambda: types.SimpleNamespace(OTX_API_KEY="secret"))
    configured, source = _secret_status("OTX_API_KEY")
    assert configured is True
    assert source == "env:OTX_API_KEY"

    payload = _base_payload(case_dir=tmp_path, output=tmp_path / "out.json", input_paths=["a"], category="cat", source_command="cmd")
    assert payload["category"] == "cat"
    assert _source("provider", mode="remote", description="desc", rate_limit_hint="slow")["rate_limit_hint"] == "slow"
    assert _hash_prefix("abcdef") == "abcdef"
    assert _looks_like_sha256("a" * 64) is True
    assert _safe_package("com/example app") == "com_example_app"
    summary = _summarize_matches([
        {"ioc": "192.0.2.4", "kind": "ipv4", "confidence": 0.9},
        {"ioc": "rule", "kind": "composite_and", "confidence": 0.5},
    ])
    assert summary["composite_count"] == 1
    assert _float_or_none("1.25") == 1.25
    assert _float_or_none({}) is None

    artifact = {"artifact_id": "A1", "path": "a.json"}
    monkeypatch.setattr(helpers, "case_artifact_details", lambda *_a, **_k: {"artifact": artifact})
    assert _selected_artifacts(tmp_path, artifact_id="A1", categories=None, exclude_categories=None, source_commands=None, device_serials=None, limit=None) == [artifact]
    monkeypatch.setattr(helpers, "query_case_artifacts", lambda *_a, **_k: {"artifacts": [artifact, {"artifact_id": "A2"}]})
    assert len(_selected_artifacts(tmp_path, artifact_id=None, categories=None, exclude_categories=None, source_commands=None, device_serials=None, limit=2)) == 2

    json_path = tmp_path / "sample.json"
    json_path.write_text('{"package": "com.example", "manifest": {"package": "fallback"}}', encoding="utf-8")
    csv_path = tmp_path / "rows.csv"
    csv_path.write_text("score,count\n1,2\n2,3\n3,4\n", encoding="utf-8")
    txt_path = tmp_path / "note.txt"
    txt_path.write_text("hello", encoding="utf-8")
    big_path = tmp_path / "big.txt"
    big_path.write_text("x" * 2_100_000, encoding="utf-8")

    assert _artifact_path(tmp_path, "a.json") == tmp_path / "a.json"
    assert _load_artifact_data(json_path)["package"] == "com.example"
    assert len(_load_artifact_data(csv_path)) == 3
    assert _load_artifact_data(txt_path) == "hello"
    assert _load_artifact_data(big_path) is None
    assert _extract_package({"manifest": {"package": "pkg"}}) == "pkg"
    assert len(_structured_rows(_load_artifact_data(csv_path))) == 3
    assert _infer_numeric_feature_keys(_load_artifact_data(csv_path)) == ["score", "count"][:2]
    providers = _unique_provider_status([
        {"payload": {"source_attribution": [{"provider": "otx"}, {"provider": "otx"}, {"provider": "vt"}]}},
        {"payload": {"source_attribution": "ignore"}},
    ])
    assert [item["provider"] for item in providers] == ["otx", "vt"]


def test_case_enrichment_runs_and_summary(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules._case_enrichment_runs as runs_mod

    artifact = {"artifact_id": "A1", "path": "capture.pcap", "category": "network-capture"}
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"pcap")

    monkeypatch.setattr(runs_mod, "summarize_pcap", lambda _path: {"packets": 3})
    monkeypatch.setattr(runs_mod, "extract_api_endpoints_from_pcap", lambda _path: [{"url": "https://api.example"}])
    monkeypatch.setattr(runs_mod, "network_summary_payload", lambda data, input_path: {"summary": data, "source_attribution": [{"provider": "pcap"}]})
    monkeypatch.setattr(runs_mod, "api_discovery_payload", lambda data, input_path: {"summary": {"count": len(data)}, "source_attribution": [{"provider": "api"}]})
    monkeypatch.setattr(runs_mod, "indicator_reputation", lambda indicator: {"indicator": indicator})
    monkeypatch.setattr(runs_mod, "file_report", lambda indicator: (_ for _ in ()).throw(RuntimeError("vt down")))
    monkeypatch.setattr(runs_mod, "otx_payload", lambda indicator, data, input_paths: {"summary": data, "provider": indicator, "source_attribution": [{"provider": "otx"}]})
    monkeypatch.setattr(runs_mod, "virustotal_payload", lambda indicator, data, input_paths: {"summary": data, "provider": indicator})

    assert _run_entry("wf", artifact, {"ok": True})["workflow"] == "wf"
    assert _error_run_entry("wf", artifact, "boom", input_path=str(path))["payload"]["error"] == "boom"
    pcap_runs = _pcap_runs(artifact, path)
    assert len(pcap_runs) == 2

    rep_runs = _reputation_runs(
        artifact,
        path,
        [
            {"ioc": "evil.example", "kind": "domain"},
            {"ioc": "a" * 64, "kind": "sha256"},
            {"ioc": "evil.example", "kind": "domain"},
        ],
        limit=4,
    )
    assert any(run["workflow"] == "intelligence.otx" for run in rep_runs)
    assert any(run["payload"].get("error") == "vt down" for run in rep_runs)

    run_summary = summarize_case_enrichment_runs(
        [{"workflow": "a", "status": "ok", "provider": "otx"}, {"workflow": "b", "status": "error", "provider": "vt"}],
        [{"reason": "missing"}, {"reason": "missing"}],
    )
    assert run_summary["success_count"] == 1
    assert run_summary["error_count"] == 1
    assert run_summary["skipped_reasons"][0]["name"] == "missing"


def test_run_case_enrichment_success_and_error_paths(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules._case_enrichment_orchestrator as orch

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "derived").mkdir()
    good_json = case_dir / "good.json"
    good_json.write_text('{"package": "com.example.app", "ioc": "evil.example"}', encoding="utf-8")
    rows_csv = case_dir / "rows.csv"
    rows_csv.write_text("score\n1\n2\n3\n", encoding="utf-8")
    missing = case_dir / "missing.json"
    broken = case_dir / "broken.json"
    broken.write_text("{", encoding="utf-8")
    pcap = case_dir / "capture.pcap"
    pcap.write_bytes(b"pcap")

    manifest = CaseManifest(
        schema_version=4,
        case_id="CASE-ENRICH",
        title="Enrichment",
        examiner="Examiner",
        notes=None,
        created_at_utc="now",
        updated_at_utc="now",
        workspace_root=str(case_dir),
    )
    selected = [
        {"artifact_id": "a1", "path": good_json.name, "category": "apk-analyze"},
        {"artifact_id": "a2", "path": rows_csv.name, "category": "extract-browser"},
        {"artifact_id": "a3", "path": pcap.name, "category": "network-capture"},
        {"artifact_id": "a4", "path": missing.name, "category": "misc"},
        {"artifact_id": "a5", "path": broken.name, "category": "misc"},
    ]
    captured: list[dict[str, object]] = []

    monkeypatch.setattr(orch, "load_case_manifest", lambda _case_dir: manifest)
    monkeypatch.setattr(orch, "_selected_artifacts", lambda *_a, **_k: selected)
    monkeypatch.setattr(orch, "_pcap_runs", lambda artifact, path: [{"workflow": "network.case", "payload": {"source_attribution": [{"provider": "pcap"}]}}] if path.suffix == ".pcap" else (_ for _ in ()).throw(RuntimeError("pcap boom")) if artifact["artifact_id"] == "a1" else [])
    monkeypatch.setattr(orch, "detect_iocs", lambda raw: [IocMatch(ioc="evil.example", kind="domain", location="loc", confidence=0.9)] if isinstance(raw, dict) else [])
    monkeypatch.setattr(orch, "ioc_payload", lambda matches, input_path: {"matches": matches, "source_attribution": [{"provider": "ioc"}]})
    monkeypatch.setattr(orch, "_reputation_runs", lambda artifact, path, matches, limit: [{"workflow": "intel.otx", "payload": {"source_attribution": [{"provider": "otx"}]}}])
    monkeypatch.setattr(orch, "correlate_cves_for_apk_package", lambda package: {"package": package})
    monkeypatch.setattr(orch, "cve_payload", lambda package, data, input_paths: {"package": package, "source_attribution": [{"provider": "osv"}]})
    monkeypatch.setattr(orch, "anomaly_scores", lambda rows, feature_keys: [{"index": 0, "score": 0.5}] if rows else [])
    monkeypatch.setattr(orch, "anomaly_payload", lambda rows, feature_keys, scores, input_path: {"rows": len(rows), "source_attribution": [{"provider": "ai"}]})
    monkeypatch.setattr(orch, "register_case_artifact", lambda **kwargs: captured.append(kwargs))

    out = run_case_enrichment(case_dir=case_dir, reputation_limit=2)
    assert out["case_id"] == "CASE-ENRICH"
    assert out["summary"]["selected_artifact_count"] == 5
    assert out["summary"]["skipped_artifact_count"] == 3
    assert any(item["reason"] == "missing" for item in out["skipped_artifacts"])
    assert any(item["reason"].startswith("read-error:") for item in out["skipped_artifacts"])
    assert any(item["reason"] == "unsupported" for item in out["skipped_artifacts"])
    assert any(run["payload"].get("error") == "pcap boom" for run in out["runs"])
    assert {item["provider"] for item in out["provider_status"]} >= {"otx", "osv", "ai", "pcap", "ioc"}
    assert pathlib.Path(out["output"]).exists()
    assert captured and captured[0]["category"] == "case-enrichment"
