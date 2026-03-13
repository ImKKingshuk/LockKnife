use super::*;

#[test]
fn extract_result_paths_collects_case_relevant_paths() {
    let data_json = serde_json::json!({
        "output": "./cases/CASE-001/reports/report_CASE-001.html",
        "script_snapshot_path": "./cases/CASE-001/derived/runtime_rt-0001_hook.js.js",
        "session": {
            "summary_path": "./cases/CASE-001/derived/runtime/rt-0001.json",
            "logs_path": "./cases/CASE-001/logs/runtime/rt-0001.jsonl"
        }
    })
    .to_string();

    let paths = extract_result_paths(
        Some("Report saved to ./cases/CASE-001/reports/report_CASE-001.html"),
        Some(&data_json),
    );

    let mut actual = paths
        .into_iter()
        .map(|path| (path.label, path.value))
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = vec![
        (
            "Output".to_string(),
            "./cases/CASE-001/reports/report_CASE-001.html".to_string(),
        ),
        (
            "Script snapshot".to_string(),
            "./cases/CASE-001/derived/runtime_rt-0001_hook.js.js".to_string(),
        ),
        (
            "Session log".to_string(),
            "./cases/CASE-001/logs/runtime/rt-0001.jsonl".to_string(),
        ),
        (
            "Session summary".to_string(),
            "./cases/CASE-001/derived/runtime/rt-0001.json".to_string(),
        ),
    ];
    expected.sort();

    assert_eq!(actual, expected);
}

#[test]
fn build_result_view_content_includes_summary_key_paths_and_pretty_json() {
    let content = build_result_view_content(
        Some("Managed runtime session saved to ./cases/CASE-001/derived/runtime/rt-0001.json"),
        &[
            ResultPath {
                label: "Session summary".to_string(),
                value: "./cases/CASE-001/derived/runtime/rt-0001.json".to_string(),
            },
            ResultPath {
                label: "Session log".to_string(),
                value: "./cases/CASE-001/logs/runtime/rt-0001.jsonl".to_string(),
            },
        ],
        &serde_json::json!({
            "session": {
                "session_id": "rt-0001",
                "status": "active",
                "session_kind": "hook",
                "attach_mode": "spawn",
                "event_count": 3,
                "connect_count": 1,
                "reload_count": 0,
                "preflight": {"status": "warn", "readiness": {"ready": true}},
                "compatibility": {"status": "warn", "finding_count": 1},
                "script_inventory_summary": {
                    "count": 1,
                    "active_label": "hook.js",
                    "items": [{"label": "hook.js", "preview": "send('hook');"}]
                },
                "event_summary": {
                    "recent": [{"event_type": "lifecycle", "level": "info", "message": "Runtime session created."}]
                }
            },
            "live": true,
            "runtime_dashboard": {
                "mode": "session-detail",
                "recommended_next_action": "Inspect recent runtime events and keep reload/reconnect controls ready while the session stays live."
            }
        })
        .to_string(),
        Some("./cases/CASE-001"),
    );

    assert!(content.contains("Summary"));
    assert!(content.contains("Case context"));
    assert!(content.contains("- Active case: ./cases/CASE-001"));
    assert!(content.contains("- Managed outputs detected: 2"));
    assert!(content.contains("Follow-up actions"));
    assert!(content.contains("Runtime context"));
    assert!(content.contains("- Session: rt-0001 · active · live yes · kind hook · attach spawn"));
    assert!(content.contains("- [s] Case summary: ready for active case ./cases/CASE-001."));
    assert!(content.contains(
        "- [f] Artifact search: ready for active case ./cases/CASE-001 · path hint ./cases/CASE-001/derived/runtime."
    ));
    assert!(content.contains(
        "- [r] Register artifact: ready for ./cases/CASE-001/derived/runtime/rt-0001.json."
    ));
    assert!(content.contains("- [g] Integrity report: ready for active case ./cases/CASE-001."));
    assert!(content.contains("- [v] Chain of custody: ready for active case ./cases/CASE-001."));
    assert!(content.contains("- [m] Runtime sessions: ready for active case ./cases/CASE-001."));
    assert!(content
        .contains("- [i] Runtime session: ready for rt-0001 in active case ./cases/CASE-001."));
    assert!(content.contains("Key paths"));
    assert!(content.contains("- Session summary: ./cases/CASE-001/derived/runtime/rt-0001.json"));
    assert!(content.contains("\"session_id\": \"rt-0001\""));
}

#[test]
fn build_result_view_content_includes_runtime_preflight_context() {
    let content = build_result_view_content(
        Some("Runtime preflight finished with status warn"),
        &[],
        &serde_json::json!({
            "app_id": "app",
            "attach_mode": "attach",
            "session_kind": "bypass_ssl",
            "status": "warn",
            "target": {
                "application_available": true,
                "running_pid": 4242,
                "device": {"id": "usb", "name": "Demo", "type": "usb"}
            },
            "readiness": {
                "ready": true,
                "blocked_checks": [],
                "warned_checks": ["abi"],
                "recommended_action": "Review the compatibility findings before reconnecting."
            },
            "compatibility": {
                "status": "warn",
                "finding_count": 1,
                "findings": [{"title": "Attach mode can miss early TLS hooks"}]
            },
            "runtime_dashboard": {"mode": "preflight"}
        })
        .to_string(),
        None,
    );

    assert!(content.contains("Runtime context"));
    assert!(content.contains("- Preflight: warn · attach attach · kind bypass_ssl"));
    assert!(content.contains("- Readiness: yes · blocked 0 · warnings 1"));
    assert!(content.contains("- Compatibility: warn · findings 1"));
}

#[test]
fn build_result_view_content_includes_artifact_registration_context() {
    let content = build_result_view_content(
        Some("Artifact created: artifact-0002"),
        &[],
        &serde_json::json!({
            "artifact_id": "artifact-0002",
            "path": "./cases/CASE-001/derived/timeline.json",
            "category": "forensics-timeline",
            "source_command": "forensics timeline",
            "registration_action": "created",
            "input_paths": ["./cases/CASE-001/evidence/sms.json"],
            "parent_artifact_ids": ["artifact-0001"]
        })
        .to_string(),
        Some("./cases/CASE-001"),
    );

    assert!(content.contains("Artifact context"));
    assert!(content.contains("Playbook guide"));
    assert!(content.contains("Case enrichment"));
    assert!(content.contains("Evidence-to-report"));
    assert!(content.contains("- Next: [s] Case summary — ready for active case ./cases/CASE-001."));
    assert!(content.contains(
        "- Next: [r] Register artifact — ready for ./cases/CASE-001/derived/timeline.json in active case ./cases/CASE-001."
    ));
    assert!(content.contains("- Artifact: artifact-0002 · registration created"));
    assert!(content.contains("- Artifact path: ./cases/CASE-001/derived/timeline.json"));
    assert!(content.contains("- Classification: forensics-timeline · Source: forensics timeline"));
    assert!(content.contains("- Inputs: 1 · parent artifact IDs: 1"));
    assert!(content
        .contains("- Next: open Case Management → Artifact detail or Lineage with artifact-0002."));
    assert!(content.contains("Follow-up actions"));
    assert!(content.contains(
        "- [a] Artifact detail: ready for artifact-0002 in active case ./cases/CASE-001."
    ));
    assert!(
        content.contains("- [l] Lineage: ready for artifact-0002 in active case ./cases/CASE-001.")
    );
}

#[test]
fn build_result_view_content_includes_apk_context_and_followups() {
    let content = build_result_view_content(
        Some("APK analysis saved to ./cases/CASE-222/derived/apk_analysis_demo.json"),
        &[ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-222/derived/apk_analysis_demo.json".to_string(),
        }],
        &serde_json::json!({
            "case_dir": "./cases/CASE-222",
            "package": "com.example.app",
            "manifest": {
                "package": "com.example.app",
                "app_name": "Example",
                "main_activity": "com.example.app.MainActivity",
                "sdk": {"min": "24", "target": "33"},
                "manifest_flags": {
                    "debuggable": true,
                    "allow_backup": true,
                    "uses_cleartext_traffic": false,
                    "network_security_config": "@xml/netsec"
                },
                "components": {
                    "activities": [{
                        "name": "com.example.app.MainActivity",
                        "exported": true,
                        "risk_flags": ["exported-without-permission", "browsable-deeplink"]
                    }],
                    "providers": [{
                        "name": "com.example.app.Provider",
                        "exported": true,
                        "risk_flags": ["exported-without-permission", "content-provider-authority"]
                    }],
                    "deeplinks": [{
                        "component": "com.example.app.MainActivity",
                        "uri": "https://example.com/open"
                    }]
                },
                "component_summary": {
                    "exported_total": 3,
                    "browsable_deeplink_total": 1,
                    "provider_weak_permission_total": 1,
                    "implicit_export_total": 1
                },
                "signing": {
                    "schemes": {"v1": true, "v2": false, "v3": false, "v4": false},
                    "lineage_count": 1,
                    "has_debug_or_test_certificate": true,
                    "strict_verification": {
                        "status": "warn",
                        "findings": [{"title": "Only legacy JAR signing is visible"}]
                    }
                },
                "string_analysis": {
                    "stats": {
                        "secret_indicator_count": 2,
                        "url_count": 4,
                        "tracker_count": 1,
                        "library_count": 2,
                        "code_signal_count": 1
                    },
                    "trackers": [{"label": "AppsFlyer"}],
                    "libraries": [{"label": "OkHttp"}],
                    "code_signals": [{"label": "Dynamic code loading APIs"}]
                }
            },
            "permission_risk": {
                "score": 9,
                "risks": [{"permission": "android.permission.READ_SMS"}]
            },
            "risk_summary": {
                "score": 72,
                "level": "high",
                "exploitability": "high",
                "evidence_strength": "strong",
                "finding_count": 4,
                "top_findings": [{"title": "App is debuggable", "severity": "high"}],
                "score_breakdown": [
                    {"factor": "finding-severity", "points": 16},
                    {"factor": "component-surface", "points": 12}
                ],
                "evidence_traces": [
                    {"source": "finding", "title": "App is debuggable"},
                    {"source": "tracker", "title": "AppsFlyer"}
                ]
            }
        })
        .to_string(),
        Some("./cases/CASE-222"),
    );

    assert!(content.contains("APK context"));
    assert!(content.contains("Playbook guide"));
    assert!(content.contains("APK triage"));
    assert!(content.contains("Runtime triage"));
    assert!(content.contains("Attack-surface review"));
    assert!(content.contains("Evidence-to-report"));
    assert!(content.contains(
        "- Next: [d] Attack-surface assessment — ready for APK package com.example.app using ./cases/CASE-222/derived/apk_analysis_demo.json in ./cases/CASE-222."
    ));
    assert!(content.contains(
        "- 2. [b]/[t] Live session — ready for APK package com.example.app in ./cases/CASE-222."
    ));
    assert!(content.contains("- Package: com.example.app · App: Example"));
    assert!(content
        .contains("- Risk: 72 / 100 · high · exploitability high · evidence strong · findings 4"));
    assert!(content.contains("- Manifest flags: debuggable yes · backup yes · cleartext no · network security @xml/netsec"));
    assert!(content.contains("- Surface: 3 exported components · 1 browsable deep links · 1 weak providers · 1 implicit exports"));
    assert!(content.contains("- Component drill-down: com.example.app.MainActivity [exported-without-permission, browsable-deeplink]"));
    assert!(
        content.contains("- Deep links: com.example.app.MainActivity → https://example.com/open")
    );
    assert!(content.contains("- Permissions: score 9 · android.permission.READ_SMS"));
    assert!(content.contains("- Signing: v1 · strict warn · lineage 1 · debug/test yes"));
    assert!(content
        .contains("- Code signals: 2 libraries · 1 trackers · 1 signals · 2 secrets · 4 URLs"));
    assert!(content.contains(
        "- Signal preview: tracker AppsFlyer · library OkHttp · signal Dynamic code loading APIs"
    ));
    assert!(content.contains("- [d] Attack-surface assessment: ready for APK package com.example.app using ./cases/CASE-222/derived/apk_analysis_demo.json in ./cases/CASE-222."));
    assert!(content.contains("- [p] Runtime preflight: ready for APK package com.example.app."));
    assert!(content.contains(
        "- [b] SSL bypass session: ready for APK package com.example.app in ./cases/CASE-222."
    ));
    assert!(content.contains("- [e] CVE correlation: ready for APK package com.example.app."));
    assert!(content.contains(
        "- [z] OWASP mapping: ready for ./cases/CASE-222/derived/apk_analysis_demo.json."
    ));
}

#[test]
fn build_result_view_content_includes_forensics_context() {
    let content = build_result_view_content(
        Some("Timeline saved to ./cases/CASE-333/derived/timeline.json"),
        &[ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-333/derived/timeline.json".to_string(),
        }],
        &serde_json::json!({
            "case_dir": "./cases/CASE-333",
            "event_count": 3,
            "sources": [{"path": "./cases/CASE-333/evidence/browser.json"}],
            "events": [{"ts_ms": 1}],
            "summary": {
                "source_counts": {"browser": 2, "messaging": 1},
                "kind_counts": {"visit": 2, "message": 1}
            }
        })
        .to_string(),
        Some("./cases/CASE-333"),
    );

    assert!(content.contains("Forensics context"));
    assert!(content.contains("- Timeline events: 3"));
    assert!(content.contains("- Sources: browser=2, messaging=1"));
}

#[test]
fn build_result_view_content_includes_security_context() {
    let content = build_result_view_content(
        Some("Attack-surface assessment saved to ./cases/CASE-444/derived/attack_surface.json"),
        &[ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-444/derived/attack_surface.json".to_string(),
        }],
        &serde_json::json!({
            "package": "com.example.app",
            "surface": {
                "summary": {
                    "exported_total": 4,
                    "provider_weak_permission_total": 1,
                    "browsable_deeplink_total": 2
                }
            },
            "probe_results": {
                "summary": {
                    "deeplink_resolved_total": 1,
                    "provider_resolved_total": 1,
                    "component_resolved_total": 1
                }
            },
            "risk_summary": {
                "score": 78,
                "level": "high",
                "exploitability": "high",
                "evidence_strength": "strong",
                "finding_count": 5,
                "attack_paths": ["Exported provider path", "Browsable deep-link path"],
                "next_steps": ["Inspect providers", "Run OWASP mapping"]
            },
            "mastg_ids": ["MSTG-PLATFORM-8"],
            "owasp_categories": ["M1: Improper Platform Usage"]
        })
        .to_string(),
        Some("./cases/CASE-444"),
    );

    assert!(content.contains("Security context"));
    assert!(content
        .contains("- Risk: 78 / 100 · high · exploitability high · evidence strong · findings 5"));
    assert!(content.contains(
        "- Static surface: 4 exported components · 1 weak providers · 2 browsable deep links"
    ));
    assert!(content.contains("- Live probes: 1 deep links · 1 providers · 1 components resolved"));
    assert!(content.contains("- OWASP/MASTG: 1 MASTG IDs · M1: Improper Platform Usage"));
}

#[test]
fn build_result_view_content_blocks_followups_without_case_context() {
    let content = build_result_view_content(
        Some("Dependency doctor ready"),
        &[],
        &serde_json::json!({
            "ok": true,
            "checks": {
                "adb": {"ok": true},
                "rust_extension": {"ok": true}
            }
        })
        .to_string(),
        None,
    );

    assert!(content.contains("Follow-up actions"));
    assert!(content.contains(
        "- [s] Case summary: blocked — latest result does not expose a case directory yet."
    ));
    assert!(content.contains(
        "- [r] Register artifact: blocked — latest result does not expose a case directory yet."
    ));
}

#[test]
fn build_result_view_content_includes_diagnostics_summary_and_recovery_hints() {
    let content = build_result_view_content(
        Some("Dependency doctor ready"),
        &[],
        &serde_json::json!({
            "ok": true,
            "full_ok": false,
            "python": "3.11.8",
            "checks": {
                "adb": {"ok": true},
                "rust_extension": {"ok": true}
            },
            "optional": {
                "runtime_frida": {
                    "ok": false,
                    "hint": "Install runtime extras: uv sync --extra frida"
                },
                "virustotal": {
                    "ok": false,
                    "installed": false,
                    "configured": false,
                    "hint": "Requires vt-py plus VT_API_KEY."
                }
            }
        })
        .to_string(),
        None,
    );

    assert!(content.contains("Diagnostics"));
    assert!(content.contains("- Core baseline ready: yes · Optional coverage ready: no"));
    assert!(content.contains("- Checks passing: core 2/2 · optional 0/2"));
    assert!(content.contains("- Optional blockers: runtime frida, virustotal"));
    assert!(content.contains("Recovery hints"));
    assert!(content.contains("- Install runtime extras: uv sync --extra frida"));
    assert!(content.contains("- Requires vt-py plus VT_API_KEY."));
}

#[test]
fn build_result_view_content_includes_feature_matrix_summary() {
    let content = build_result_view_content(
        Some("Feature matrix ready"),
        &[],
        &serde_json::json!({
            "summary": {
                "production-ready": 1,
                "functional": 2,
                "dependency-gated": 1
            },
            "features": [
                {"capability": "CLI + orchestration", "status": "production-ready"},
                {"capability": "Default TUI", "status": "functional"},
                {"capability": "APK analysis", "status": "dependency-gated"},
                {"capability": "Case management", "status": "functional"}
            ]
        })
        .to_string(),
        None,
    );

    assert!(content.contains("Diagnostics"));
    assert!(content.contains("- Features tracked: 4"));
    assert!(
        content.contains("- Status mix: 1 production-ready · 2 functional · 1 dependency-gated")
    );
    assert!(content
        .contains("- Next: open Dependency doctor before relying on dependency-gated workflows."));
}

#[test]
fn build_result_view_content_includes_analysis_and_report_preview_context() {
    let content = build_result_view_content(
        Some("Report saved to ./cases/CASE-777/reports/report.html"),
        &[],
        &serde_json::json!({
            "summary": {
                "endpoint_count": 3,
                "host_count": 2,
                "http_request_count": 1
            },
            "endpoint_groups": [{"host": "api.example.com", "count": 2}],
            "http": {"request_count": 1},
            "dns": {"domains": ["auth.example.com"]},
            "coverage": {"subject": "api.example.com", "confidence": "moderate", "evidence_count": 2},
            "explainability": {"top_rows": [{"anomaly_score": 0.9}]},
            "evidence_summary": {"artifact_payload_rows": 4, "top_categories": [{"name": "report-html", "count": 1}]},
            "report_preview": {
                "template_readiness": "complete",
                "pdf_backend_status": {"preferred": null}
            },
            "report_sections": [{"title": "PDF readiness", "summary": "PDF backend unavailable; HTML fallback may be required."}]
        })
        .to_string(),
        Some("./cases/CASE-777"),
    );

    assert!(content.contains("Analysis context"));
    assert!(
        content.contains("- Network summary: 3 endpoint(s) · 2 host(s) · 1 HTTP request hint(s)")
    );
    assert!(content.contains("- Coverage: api.example.com · confidence moderate · evidence 2"));
    assert!(content.contains("Reporting context"));
    assert!(content.contains("- Report preview: readiness complete · PDF backend unavailable"));
    assert!(content.contains("- [w] Report preview: PDF backend unavailable · confirm readiness before exporting reviewer-facing bundles."));
}

#[test]
fn apply_result_surfaces_result_paths_in_logs_and_result_view() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);

    app.apply_result(
        "runtime.hook",
        CallbackResult {
            ok: true,
            message: Some("Managed hook session rt-0001 is active".to_string()),
            data_json: Some(
                serde_json::json!({
                    "case_dir": "./cases/CASE-001",
                    "script_snapshot_path": "./cases/CASE-001/derived/runtime_rt-0001_hook.js.js",
                    "live": true,
                    "runtime_dashboard": {"mode": "session-detail"},
                    "session": {
                        "session_id": "rt-0001",
                        "status": "active",
                        "session_kind": "hook",
                        "attach_mode": "spawn",
                        "summary_path": "./cases/CASE-001/derived/runtime/rt-0001.json",
                        "logs_path": "./cases/CASE-001/logs/runtime/rt-0001.jsonl",
                        "script_inventory": [
                            {"path": "./cases/CASE-001/derived/runtime_rt-0001_hook.js.js"}
                        ]
                    }
                })
                .to_string(),
            ),
            job_json: None,
            logs: None,
            error: None,
        },
    );

    assert!(app.logs.iter().any(|entry| {
        entry.message == "↳ Session log: ./cases/CASE-001/logs/runtime/rt-0001.jsonl"
    }));
    assert_eq!(app.last_result_paths.len(), 4);

    app.start_result_view();
    let Overlay::ResultView(state) = &app.overlay else {
        panic!("expected result view overlay");
    };

    assert!(state.title.contains("4 key paths"));
    assert!(state.content.contains("Script snapshot"));
    assert!(state.content.contains("JSON"));
    assert_eq!(state.line_count, state.content.lines().count() as u16);
    let expected_sections = state
        .content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| match line.trim() {
            "Summary" | "Diagnostics" | "Recovery hints" | "Case context" | "Job context"
            | "Artifact context" | "APK context" | "Enrichment context" | "Reporting context"
            | "Runtime context" | "Follow-up actions" | "Playbook guide" | "Key paths" | "JSON" => {
                Some(idx as u16)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(state.section_starts, expected_sections);
}

#[test]
fn start_result_view_includes_case_context_when_active_case_is_known() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-777".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "output": "./cases/CASE-777/reports/report_CASE-777.html"
        })
        .to_string(),
    );
    app.last_result_paths = vec![ResultPath {
        label: "Output".to_string(),
        value: "./cases/CASE-777/reports/report_CASE-777.html".to_string(),
    }];

    assert!(app.start_result_view());
    let Overlay::ResultView(state) = &app.overlay else {
        panic!("expected result view overlay");
    };

    assert!(state.content.contains("Case context"));
    assert!(state.content.contains("- Active case: ./cases/CASE-777"));
    assert!(state.content.contains("- Managed outputs detected: 1"));
}

#[test]
fn start_result_view_includes_artifact_lineage_context_when_available() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-888".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-888",
            "artifact": {
                "artifact_id": "artifact-0001",
                "path": "./cases/CASE-888/derived/timeline.json",
                "category": "forensics-timeline",
                "source_command": "forensics timeline",
                "parent_artifact_ids": ["artifact-0000"],
                "input_paths": ["./cases/CASE-888/evidence/sms.json"]
            },
            "parents": [{"artifact_id": "artifact-0000"}],
            "children": [{"artifact_id": "artifact-0002"}, {"artifact_id": "artifact-0003"}],
            "missing_parent_ids": ["artifact-9999"]
        })
        .to_string(),
    );

    assert!(app.start_result_view());
    let Overlay::ResultView(state) = &app.overlay else {
        panic!("expected result view overlay");
    };

    assert!(state.content.contains("Artifact context"));
    assert!(state.content.contains("- Artifact: artifact-0001"));
    assert!(state
        .content
        .contains("- Lineage: parents 1 · children 2 · missing parents 1"));
    assert!(state
        .content
        .contains("- Next: open Case Management → Artifact detail or Lineage with artifact-0001."));
    assert!(state.section_starts.iter().any(|idx| {
        state
            .content
            .lines()
            .nth(*idx as usize)
            .map(|line| line.trim() == "Artifact context")
            .unwrap_or(false)
    }));
}

#[test]
fn apply_result_promotes_active_case_from_case_paths() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.pending_case_dir = Some("./cases/CASE-001".to_string());

    app.apply_result(
        "runtime.hook",
        CallbackResult {
            ok: true,
            message: Some("Managed hook session rt-0001 is active".to_string()),
            data_json: Some(
                serde_json::json!({
                    "case_dir": "./cases/CASE-001",
                    "session": {
                        "session_id": "rt-0001",
                        "summary_path": "./cases/CASE-001/derived/runtime/rt-0001.json"
                    }
                })
                .to_string(),
            ),
            job_json: None,
            logs: None,
            error: None,
        },
    );

    assert_eq!(app.active_case_dir(), Some("./cases/CASE-001"));
    assert_eq!(
        app.recent_case_dirs.first().map(String::as_str),
        Some("./cases/CASE-001")
    );
    assert!(app.pending_case_dir.is_none());
}
