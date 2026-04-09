use super::*;

#[test]
fn apply_action_prompt_context_prefills_active_case_for_case_aware_actions() {
    let modules = default_modules();
    let action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "report.generate")
        .expect("report.generate should exist")
        .clone();

    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-007".to_string());

    let mut fields = action.fields.clone();
    let mut help_lines = action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(&action, &mut fields, &mut help_lines);

    let case_dir = fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(case_dir.value, "./cases/CASE-007");
    assert!(help_lines[0].contains("Active case in this TUI session"));
}

#[test]
fn apply_action_prompt_context_prefills_selected_device_for_case_init() {
    let modules = default_modules();
    let action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "case.init")
        .expect("case.init should exist")
        .clone();

    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::from_loaded_config(callback, None);
    app.devices = vec![DeviceItem {
        serial: "emulator-5554".to_string(),
        adb_state: "device".to_string(),
        state: "available".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    }];

    let mut fields = action.fields.clone();
    let mut help_lines = action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(&action, &mut fields, &mut help_lines);

    let target_serials = fields
        .iter()
        .find(|field| field.key == "target_serials")
        .expect("target_serials field should exist");
    assert_eq!(target_serials.value, "emulator-5554");
}

#[test]
fn apply_action_prompt_context_prefills_runtime_device_and_preflight_lines() {
    let modules = default_modules();
    let action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "runtime.hook")
        .expect("runtime.hook should exist")
        .clone();

    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-008".to_string());
    app.devices = vec![DeviceItem {
        serial: "emulator-5554".to_string(),
        adb_state: "device".to_string(),
        state: "available".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    }];

    let mut fields = action.fields.clone();
    let mut help_lines = action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(&action, &mut fields, &mut help_lines);

    let device_id = fields
        .iter()
        .find(|field| field.key == "device_id")
        .expect("device_id field should exist");
    assert_eq!(device_id.value, "emulator-5554");
    assert!(help_lines[0].contains("Active case in this TUI session"));
    assert!(help_lines.iter().any(|line| {
        line.contains(
            "Preflight: dependency-gated [gated] · requires lockknife[frida] + Frida server.",
        )
    }));
    assert!(help_lines
        .iter()
        .any(|line| line.contains("Playbook: Runtime triage step 2/4")));
    assert!(help_lines
        .iter()
        .any(|line| line.contains("Device target in this TUI session: emulator-5554.")));
    assert!(help_lines
        .iter()
        .any(|line| { line.contains("Recovery: open Diagnostics → Dependency doctor") }));
    assert!(help_lines.iter().any(|line| {
        line.contains("Recommended next: inspect [i] Runtime session, then keep [h]/[c]/[o] ready")
    }));
}

#[test]
fn build_case_dashboard_prompt_prefills_case_first_reporting() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-515".to_string());

    let prompt = app
        .build_case_dashboard_prompt("report.generate")
        .expect("case-dashboard report prompt should be available");

    let field_value = |key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value("case_dir"), "./cases/CASE-515");
    assert_eq!(field_value("case_id"), "CASE-515");
    assert_eq!(field_value("output"), "");
    assert!(prompt.help_lines.iter().any(|line| {
        line.contains("generate a report directly from the active case workspace")
    }));
    assert!(prompt
        .help_lines
        .iter()
        .any(|line| { line.contains("Case-first reporting: leave Artifacts JSON blank") }));
}

#[test]
fn build_case_dashboard_prompt_prefills_case_first_reporting_support_actions() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-616".to_string());

    let custody_prompt = app
        .build_case_dashboard_prompt("report.chain_of_custody")
        .expect("custody prompt should be available");
    let integrity_prompt = app
        .build_case_dashboard_prompt("report.integrity")
        .expect("integrity prompt should be available");

    let custody_case_id = custody_prompt
        .fields
        .iter()
        .find(|field| field.key == "case_id")
        .map(|field| field.value.clone())
        .unwrap_or_default();
    let integrity_case_dir = integrity_prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .map(|field| field.value.clone())
        .unwrap_or_default();

    assert_eq!(custody_case_id, "CASE-616");
    assert_eq!(integrity_case_dir, "./cases/CASE-616");
}

#[test]
fn build_case_dashboard_prompt_prefills_case_job_actions_from_latest_job() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-516".to_string());
    app.last_job_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-516",
            "job_id": "job-0012",
            "status": "failed",
            "action_id": "runtime.hook"
        })
        .to_string(),
    );

    let resume_prompt = app
        .build_case_dashboard_prompt("case.resume_job")
        .expect("resume prompt should exist");
    let retry_prompt = app
        .build_case_dashboard_prompt("case.retry_job")
        .expect("retry prompt should exist");

    let field_value = |prompt: &crate::app::PromptState, key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value(&resume_prompt, "case_dir"), "./cases/CASE-516");
    assert_eq!(field_value(&resume_prompt, "job_id"), "job-0012");
    assert_eq!(field_value(&retry_prompt, "job_id"), "job-0012");
}

#[test]
fn apply_action_prompt_context_prefills_case_filters_from_latest_result() {
    let modules = default_modules();
    let action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "case.summary")
        .expect("case.summary should exist")
        .clone();

    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::from_loaded_config(callback, None);
    app.last_result_json = Some(
        serde_json::json!({
            "artifact": {
                "category": "forensics-timeline",
                "source_command": "forensics timeline",
                "device_serial": "emulator-5554"
            }
        })
        .to_string(),
    );

    let mut fields = action.fields.clone();
    let mut help_lines = action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(&action, &mut fields, &mut help_lines);

    let categories = fields
        .iter()
        .find(|field| field.key == "categories")
        .expect("categories field should exist");
    let source_commands = fields
        .iter()
        .find(|field| field.key == "source_commands")
        .expect("source_commands field should exist");
    let device_serials = fields
        .iter()
        .find(|field| field.key == "device_serials")
        .expect("device_serials field should exist");

    assert_eq!(categories.value, "forensics-timeline");
    assert_eq!(source_commands.value, "forensics timeline");
    assert_eq!(device_serials.value, "emulator-5554");
}

#[test]
fn build_action_prompt_prefills_register_metadata_from_general_context() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::from_loaded_config(callback, None);
    app.active_case_dir = Some("./cases/CASE-042".to_string());
    app.devices = vec![DeviceItem {
        serial: "emulator-5554".to_string(),
        adb_state: "device".to_string(),
        state: "available".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    }];
    app.last_result_json = Some(
        serde_json::json!({
            "artifact": {
                "category": "forensics-timeline",
                "source_command": "forensics timeline"
            }
        })
        .to_string(),
    );

    let prompt = app
        .build_action_prompt_by_id("case.register")
        .expect("case.register prompt should be available");

    let field_value = |key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value("case_dir"), "./cases/CASE-042");
    assert_eq!(field_value("category"), "forensics-timeline");
    assert_eq!(field_value("source_command"), "forensics timeline");
    assert_eq!(field_value("device_serial"), "emulator-5554");
}

#[test]
fn apply_action_prompt_context_prefills_case_metadata_from_persisted_defaults() {
    let modules = default_modules();
    let init_action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "case.init")
        .expect("case.init should exist")
        .clone();
    let register_action = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "case.register")
        .expect("case.register should exist")
        .clone();

    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(
        callback,
        Some(TuiConfig {
            theme: "dark".to_string(),
            top_height: 9,
            recent_case_dirs: vec![],
            prompt_defaults: PersistedPromptDefaults {
                examiner: "Analyst One".to_string(),
                title: "Device Intake".to_string(),
                target_serials: "emulator-5554".to_string(),
                categories: "timeline".to_string(),
                exclude_categories: "trash".to_string(),
                source_commands: "forensics timeline".to_string(),
                device_serials: "emulator-5554".to_string(),
                category: "derived-report".to_string(),
                source_command: "report generate".to_string(),
                device_serial: "emulator-5554".to_string(),
            },
            artifact_filter_history: PersistedArtifactFilterHistory::default(),
        }),
    );

    let mut init_fields = init_action.fields.clone();
    let mut init_help_lines = init_action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(&init_action, &mut init_fields, &mut init_help_lines);

    let init_value = |key: &str| {
        init_fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(init_value("examiner"), "Analyst One");
    assert_eq!(init_value("title"), "Device Intake");
    assert_eq!(init_value("target_serials"), "emulator-5554");

    let mut register_fields = register_action.fields.clone();
    let mut register_help_lines = register_action
        .help_lines()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    app.apply_action_prompt_context(
        &register_action,
        &mut register_fields,
        &mut register_help_lines,
    );

    let register_value = |key: &str| {
        register_fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(register_value("category"), "derived-report");
    assert_eq!(register_value("source_command"), "report generate");
    assert_eq!(register_value("device_serial"), "emulator-5554");
}
