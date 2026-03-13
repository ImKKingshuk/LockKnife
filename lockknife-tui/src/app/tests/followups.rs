use super::*;

#[test]
fn build_result_followup_prompt_prefills_summary_from_latest_case() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-321".to_string());

    let prompt = app
        .build_result_followup_prompt("case.summary")
        .expect("case.summary follow-up should be available");

    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(case_dir.value, "./cases/CASE-321");
    assert!(prompt.help_lines[0].contains("Opened from Result view for case summary"));
}

#[test]
fn build_result_followup_prompt_prefills_artifact_detail_from_latest_result() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-654".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-654",
            "artifact": {
                "artifact_id": "artifact-0042",
                "path": "./cases/CASE-654/derived/timeline.json"
            }
        })
        .to_string(),
    );

    let prompt = app
        .build_result_followup_prompt("case.artifact")
        .expect("case.artifact follow-up should be available");

    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    let artifact_id = prompt
        .fields
        .iter()
        .find(|field| field.key == "artifact_id")
        .expect("artifact_id field should exist");
    let path = prompt
        .fields
        .iter()
        .find(|field| field.key == "path")
        .expect("path field should exist");

    assert_eq!(case_dir.value, "./cases/CASE-654");
    assert_eq!(artifact_id.value, "artifact-0042");
    assert_eq!(path.value, "./cases/CASE-654/derived/timeline.json");
    assert!(prompt.help_lines[0].contains("Opened from Result view with latest artifact context"));
}

#[test]
fn build_result_followup_prompt_prefills_register_from_result_paths_and_metadata() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-777".to_string());
    app.last_result_paths = vec![
        ResultPath {
            label: "Case directory".to_string(),
            value: "./cases/CASE-777".to_string(),
        },
        ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-777/reports/timeline.json".to_string(),
        },
    ];
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-777",
            "category": "forensics-timeline",
            "source_command": "forensics timeline",
            "device_serial": "emulator-5554",
            "input_paths": ["./cases/CASE-777/evidence/sms.json"],
            "parent_artifact_ids": ["artifact-0001"]
        })
        .to_string(),
    );

    let prompt = app
        .build_result_followup_prompt("case.register")
        .expect("case.register follow-up should be available");

    let field_value = |key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value("case_dir"), "./cases/CASE-777");
    assert_eq!(
        field_value("path"),
        "./cases/CASE-777/reports/timeline.json"
    );
    assert_eq!(field_value("category"), "forensics-timeline");
    assert_eq!(field_value("source_command"), "forensics timeline");
    assert_eq!(field_value("device_serial"), "emulator-5554");
    assert_eq!(
        field_value("input_paths"),
        "./cases/CASE-777/evidence/sms.json"
    );
    assert_eq!(field_value("parent_artifact_ids"), "artifact-0001");
    assert!(
        prompt.help_lines[0].contains("Opened from Result view with latest registration context")
    );
}

#[test]
fn build_result_followup_prompt_prefills_artifact_search_from_latest_result_context() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-778".to_string());
    app.last_result_paths = vec![
        ResultPath {
            label: "Case directory".to_string(),
            value: "./cases/CASE-778".to_string(),
        },
        ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-778/derived/report.json".to_string(),
        },
    ];
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-778",
            "artifact": {
                "category": "report-json",
                "source_command": "report generate",
                "device_serial": "emulator-5554"
            }
        })
        .to_string(),
    );

    let prompt = app
        .build_result_followup_prompt("case.artifacts")
        .expect("case.artifacts follow-up should be available");

    let field_value = |key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value("case_dir"), "./cases/CASE-778");
    assert_eq!(field_value("path_contains"), "./cases/CASE-778/derived");
    assert_eq!(field_value("categories"), "report-json");
    assert_eq!(field_value("source_commands"), "report generate");
    assert_eq!(field_value("device_serials"), "emulator-5554");
    assert_eq!(field_value("query"), "");
    assert!(prompt.help_lines[0]
        .contains("Opened from Result view with latest artifact-search context"));
}

#[test]
fn build_result_followup_prompt_uses_artifact_id_as_search_fallback() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-779".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-779",
            "artifact_id": "artifact-1111"
        })
        .to_string(),
    );

    let prompt = app
        .build_result_followup_prompt("case.artifacts")
        .expect("case.artifacts follow-up should be available");

    let query = prompt
        .fields
        .iter()
        .find(|field| field.key == "query")
        .expect("query field should exist");
    assert_eq!(query.value, "artifact-1111");
}

#[test]
fn build_result_followup_prompt_supports_case_export_and_reporting_followups() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-880".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-880",
            "case_id": "CASE-880",
            "artifact": {
                "artifact_id": "artifact-0088",
                "path": "./cases/CASE-880/derived/summary.json"
            }
        })
        .to_string(),
    );

    let export_prompt = app
        .build_result_followup_prompt("case.export")
        .expect("case.export follow-up should be available");
    let enrich_prompt = app
        .build_result_followup_prompt("case.enrich")
        .expect("case.enrich follow-up should be available");
    let report_prompt = app
        .build_result_followup_prompt("report.generate")
        .expect("report.generate follow-up should be available");
    let custody_prompt = app
        .build_result_followup_prompt("report.chain_of_custody")
        .expect("report.chain_of_custody follow-up should be available");
    let integrity_prompt = app
        .build_result_followup_prompt("report.integrity")
        .expect("report.integrity follow-up should be available");

    let export_case_dir = export_prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(export_case_dir.value, "./cases/CASE-880");
    assert!(export_prompt.help_lines[0].contains("export the case workspace"));

    let report_field = |key: &str| {
        report_prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(report_field("case_dir"), "./cases/CASE-880");
    assert_eq!(report_field("case_id"), "CASE-880");
    assert_eq!(report_field("output"), "");
    assert!(report_prompt.help_lines[0].contains("report on ./cases/CASE-880"));

    let custody_field = |key: &str| {
        custody_prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(custody_field("case_dir"), "./cases/CASE-880");
    assert_eq!(custody_field("case_id"), "CASE-880");
    assert_eq!(custody_field("output"), "");
    assert!(custody_prompt.help_lines[0].contains("chain-of-custody output"));

    let integrity_field = |key: &str| {
        integrity_prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(integrity_field("case_dir"), "./cases/CASE-880");
    assert_eq!(integrity_field("output"), "");
    assert!(integrity_prompt.help_lines[0].contains("operator-ready integrity report"));

    let enrich_field = |key: &str| {
        enrich_prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(enrich_field("case_dir"), "./cases/CASE-880");
    assert_eq!(enrich_field("artifact_id"), "artifact-0088");
    assert!(enrich_prompt.help_lines[0].contains("case enrichment bundle"));
}

#[test]
fn build_result_followup_prompt_prefills_apk_runtime_and_security_actions() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-990".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-990",
            "package": "com.example.app",
            "output": "./cases/CASE-990/derived/apk_analysis_demo.json"
        })
        .to_string(),
    );
    app.last_result_paths = extract_result_paths(
        Some("APK analysis saved to ./cases/CASE-990/derived/apk_analysis_demo.json"),
        app.last_result_json.as_deref(),
    );

    let preflight = app
        .build_result_followup_prompt("runtime.preflight")
        .expect("runtime.preflight should be available from APK results");
    let ssl = app
        .build_result_followup_prompt("runtime.bypass_ssl")
        .expect("runtime.bypass_ssl should be available from APK results");
    let cve = app
        .build_result_followup_prompt("intelligence.cve")
        .expect("intelligence.cve should be available from APK results");
    let attack_surface = app
        .build_result_followup_prompt("security.attack_surface")
        .expect("security.attack_surface should be available from APK results");
    let owasp = app
        .build_result_followup_prompt("security.owasp")
        .expect("security.owasp should be available from APK results");

    let field_value = |prompt: &crate::app::PromptState, key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value(&preflight, "app_id"), "com.example.app");
    assert_eq!(field_value(&ssl, "app_id"), "com.example.app");
    assert_eq!(field_value(&ssl, "case_dir"), "./cases/CASE-990");
    assert_eq!(field_value(&cve, "package"), "com.example.app");
    assert_eq!(field_value(&attack_surface, "package"), "com.example.app");
    assert_eq!(
        field_value(&attack_surface, "artifacts"),
        "./cases/CASE-990/derived/apk_analysis_demo.json"
    );
    assert_eq!(field_value(&attack_surface, "case_dir"), "./cases/CASE-990");
    assert_eq!(
        field_value(&owasp, "artifacts"),
        "./cases/CASE-990/derived/apk_analysis_demo.json"
    );
    assert!(preflight.help_lines[0].contains("preflight runtime access"));
    assert!(attack_surface.help_lines[0].contains(
        "assess APK package com.example.app using ./cases/CASE-990/derived/apk_analysis_demo.json"
    ));
    assert!(owasp.help_lines[0].contains("OWASP MASTG references"));
}

#[test]
fn apk_decompile_action_exposes_mode_selector_and_updated_guidance() {
    let modules = default_modules();
    let action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "apk.decompile")
        .expect("apk.decompile should exist");

    let mode_field = action
        .fields
        .iter()
        .find(|field| field.key == "mode")
        .expect("apk.decompile should expose a mode selector");
    assert_eq!(mode_field.value, "auto");
    assert_eq!(
        mode_field.options,
        vec!["auto", "unpack", "apktool", "jadx", "hybrid"]
    );
    assert!(action
        .description()
        .expect("description should exist")
        .contains("apktool/jadx"));
}

#[test]
fn build_result_followup_prompt_supports_case_job_actions() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-882".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-882",
            "recent_jobs": [
                {
                    "job_id": "job-0007",
                    "status": "failed",
                    "action_id": "runtime.hook"
                }
            ]
        })
        .to_string(),
    );
    app.last_job_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-882",
            "job_id": "job-0007",
            "status": "failed",
            "action_id": "runtime.hook"
        })
        .to_string(),
    );

    let jobs_prompt = app
        .build_result_followup_prompt("case.jobs")
        .expect("case.jobs follow-up should be available");
    let job_prompt = app
        .build_result_followup_prompt("case.job")
        .expect("case.job follow-up should be available");
    let resume_prompt = app
        .build_result_followup_prompt("case.resume_job")
        .expect("case.resume_job follow-up should be available");
    let retry_prompt = app
        .build_result_followup_prompt("case.retry_job")
        .expect("case.retry_job follow-up should be available");

    let field_value = |prompt: &crate::app::PromptState, key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value(&jobs_prompt, "case_dir"), "./cases/CASE-882");
    assert_eq!(field_value(&job_prompt, "job_id"), "job-0007");
    assert_eq!(field_value(&resume_prompt, "job_id"), "job-0007");
    assert_eq!(field_value(&retry_prompt, "job_id"), "job-0007");
    assert!(resume_prompt.help_lines[0].contains("resume the latest resumable job"));
    assert!(retry_prompt.help_lines[0].contains("retry the latest finished job"));
}
