import pathlib


def test_score_permissions() -> None:
    from lockknife.modules.apk.permissions import score_permissions

    total, risks = score_permissions(
        [
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
            "nope",
        ]
    )
    assert total > 0
    assert risks[0].score >= risks[-1].score


def test_analyze_apk_builds_combined_risk_summary(monkeypatch) -> None:
    from lockknife.modules.apk import static_analysis as static_mod

    monkeypatch.setattr(
        static_mod,
        "parse_apk_manifest",
        lambda _path: {
            "package": "com.example",
            "permissions": ["android.permission.READ_SMS"],
            "debuggable": True,
            "allow_backup": True,
            "uses_cleartext_traffic": True,
            "sdk": {"min": "21", "target": "27"},
            "network_security_config": "@xml/netsec",
            "component_summary": {
                "exported_total": 4,
                "browsable_deeplink_total": 2,
                "provider_weak_permission_total": 1,
                "intent_filter_overlap_total": 1,
                "component_permission_gap_total": 1,
            },
            "components": {
                "interaction_analysis": {
                    "overlaps": [
                        {"type": "custom-scheme", "scheme": "example", "components": ["A", "B"]}
                    ],
                    "permission_gaps": [
                        {"component": "com.example.OpenActivity", "bucket": "activities"}
                    ],
                    "custom_scheme_overlaps": [{"scheme": "example", "components": ["A", "B"]}],
                },
                "providers": [{"name": "com.example.Provider", "exported": True}],
            },
            "deeplinks": ["https://example.com/open"],
            "string_analysis": {
                "stats": {
                    "secret_indicator_count": 2,
                    "tracker_count": 1,
                    "code_signal_count": 5,
                    "native_library_count": 1,
                    "jni_entry_point_count": 2,
                },
                "hardcoded_secret_indicators": [
                    {"file": "classes.dex", "preview": "api_ke…123456"}
                ],
                "trackers": [{"id": "appsflyer", "label": "AppsFlyer"}],
                "code_signals": [
                    {
                        "id": "dynamic-code-loading",
                        "label": "Dynamic code loading APIs",
                        "severity": "medium",
                    },
                    {
                        "id": "webview-js-bridge",
                        "label": "WebView JavaScript bridge",
                        "severity": "medium",
                    },
                    {
                        "id": "insecure-storage-world-readable",
                        "label": "World-readable storage APIs",
                        "severity": "high",
                    },
                    {"id": "crypto-ecb-mode", "label": "ECB cryptography mode", "severity": "high"},
                    {
                        "id": "crypto-static-iv",
                        "label": "Static IV cryptography",
                        "severity": "high",
                    },
                ],
                "native_libraries": [
                    {"file": "lib/arm64-v8a/libnative.so", "jni_entry_point_count": 2}
                ],
            },
            "signing": {
                "has_debug_or_test_certificate": True,
                "certificates": [],
                "strict_verification": {
                    "status": "warn",
                    "findings": [
                        {
                            "id": "legacy-v1-only-signing",
                            "severity": "warn",
                            "title": "Legacy signing",
                        }
                    ],
                },
            },
        },
    )

    report = static_mod.analyze_apk(pathlib.Path("sample.apk"))
    finding_ids = {finding.id for finding in report.findings}

    assert report.package == "com.example"
    assert "debuggable" in finding_ids
    assert "exported_components" in finding_ids
    assert "weak_exported_provider" in finding_ids
    assert "tracker_sdk_present" in finding_ids
    assert "dynamic_code_loading" in finding_ids
    assert "webview_js_bridge" in finding_ids
    assert "intent_filter_overlap" in finding_ids
    assert "component_permission_gap" in finding_ids
    assert "custom_scheme_collision" in finding_ids
    assert "insecure_storage_world_readable" in finding_ids
    assert "crypto_ecb_mode" in finding_ids
    assert "crypto_static_iv" in finding_ids
    assert "native_library_surface" in finding_ids
    assert "legacy_v1_only_signing" in finding_ids
    assert report.permission_risk["score"] > 0
    assert report.risk_summary["score"] >= 50
    assert report.risk_summary["score_breakdown"]
    assert report.risk_summary["evidence_traces"]
    assert report.risk_summary["tracker_count"] == 1
    assert report.risk_summary["code_signal_count"] == 5
    assert report.mastg["mastg_ids"]


def test_vulnerability_report_merges_static_and_cve_signals(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import static_analysis as static_mod
    from lockknife.modules.apk import vulnerability as vuln_mod

    analysis = static_mod.ApkAnalysisReport(
        package="com.example",
        manifest={
            "package": "com.example",
            "version_name": "1.0",
            "version_code": "1",
            "debuggable": True,
            "allow_backup": False,
            "uses_cleartext_traffic": True,
            "network_security_config": None,
            "uses_libraries": ["libssl"],
            "component_summary": {"exported_total": 1},
            "component_interactions": {
                "permission_gaps": [{"component": "A"}],
                "overlaps": [{"scheme": "example"}],
            },
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "string_analysis": {
                "stats": {"secret_indicator_count": 0, "jni_entry_point_count": 1},
                "code_signals": [
                    {
                        "id": "insecure-storage-world-readable",
                        "label": "World-readable storage APIs",
                        "severity": "high",
                    },
                ],
                "native_libraries": [
                    {"file": "lib/arm64-v8a/libnative.so", "jni_entry_point_count": 1}
                ],
            },
            "signing": {"has_debug_or_test_certificate": False},
        },
        findings=[
            static_mod.Finding(
                id="debuggable",
                severity="high",
                title="App is debuggable",
                details={},
            )
        ],
        permission_risk={"score": 7, "risks": [{"name": "READ_SMS"}]},
        risk_summary={"score": 40, "level": "medium"},
        mastg={"mastg_ids": ["MSTG-RESILIENCE-2"]},
    )
    monkeypatch.setattr(vuln_mod, "analyze_apk", lambda _path: analysis)
    monkeypatch.setattr(
        vuln_mod,
        "correlate_cves_for_apk_package",
        lambda query: {"query": query, "results": [{"id": f"CVE-for-{query}"}]},
    )

    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    rep = vuln_mod.vulnerability_report(apk)

    assert rep.package == "com.example"
    assert rep.uses_libraries == ["libssl"]
    assert rep.cve["query"].startswith("com.example")
    assert rep.cve_summary["cve_count"] == 1
    assert rep.cve_summary["component_cve_count"] == 1
    assert rep.risk_summary["score"] > analysis.risk_summary["score"]
    assert rep.findings[0]["id"] == "debuggable"
    assert {item["id"] for item in rep.findings} >= {
        "insecure_storage_world_readable",
        "jni_native_surface",
        "component_permission_gap",
        "intent_filter_overlap",
    }
    assert rep.manifest["package"] == "com.example"
