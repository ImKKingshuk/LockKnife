use super::*;

#[test]
fn confirm_lines_include_case_routing_and_destination_context() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-222".to_string());

    let module_index = app
        .modules
        .iter()
        .position(|module| {
            module
                .actions
                .iter()
                .any(|action| action.id == "report.generate")
        })
        .expect("report.generate action should be reachable from a module");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "report.generate")
        .expect("report.generate should exist");
    let state = ConfirmState {
        title: "Confirm Generate report?".to_string(),
        target: PromptTarget::Action {
            module_index,
            action_index,
        },
        params: serde_json::json!({"case_dir": "./cases/CASE-333", "output": "./cases/CASE-333/reports/report.html"}),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    };

    let rendered = confirm_lines(&app, &state, Rect::new(0, 0, 68, 12))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Case routing: ./cases/CASE-333 (overrides active case)"));
    assert!(rendered.contains("Destination: ./cases/CASE-333/reports/report.html"));
}

#[test]
fn confirm_lines_include_device_context_for_device_actions() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.devices.push(DeviceItem {
        serial: "SERIAL-9".to_string(),
        adb_state: "device".to_string(),
        state: "connected".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("9".to_string()),
    });

    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "credentials")
        .expect("credentials module should exist");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "credentials.pin")
        .expect("credentials.pin should exist");
    let state = ConfirmState {
        title: "Confirm PIN recovery?".to_string(),
        target: PromptTarget::Action {
            module_index,
            action_index,
        },
        params: serde_json::json!({}),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    };

    let rendered = confirm_lines(&app, &state, Rect::new(0, 0, 68, 12))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Device: SERIAL-9"));
}

#[test]
fn confirm_lines_surface_runtime_preflight_blockers_and_remediation() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let app = App::new(callback);

    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "runtime")
        .expect("runtime module should exist");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "runtime.hook")
        .expect("runtime.hook should exist");
    let state = ConfirmState {
        title: "Confirm hook preview?".to_string(),
        target: PromptTarget::Action {
            module_index,
            action_index,
        },
        params: serde_json::json!({"case_dir": "./cases/CASE-444"}),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    };

    let rendered = confirm_lines(&app, &state, Rect::new(0, 0, 76, 14))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains(
        "Preflight: dependency-gated [gated] · requires lockknife[frida] + Frida server."
    ));
    assert!(rendered.contains(
        "Device target: none yet · choose one in Devices or enter Device ID before confirming."
    ));
    assert!(rendered.contains("Case routing: ./cases/CASE-444"));
    assert!(rendered.contains("Recovery: open Diagnostics → Dependency doctor"));
}

#[test]
fn confirm_lines_surface_dependency_gated_remediation_for_threat_intel_actions() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let app = App::new(callback);

    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "intelligence")
        .expect("intelligence module should exist");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "intelligence.virustotal")
        .expect("intelligence.virustotal should exist");
    let state = ConfirmState {
        title: "Confirm VT lookup?".to_string(),
        target: PromptTarget::Action {
            module_index,
            action_index,
        },
        params: serde_json::json!({"hash": "abc123"}),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    };

    let rendered = confirm_lines(&app, &state, Rect::new(0, 0, 80, 14))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains(
        "Preflight: dependency-gated [gated] · requires lockknife[threat-intel] + API keys."
    ));
    assert!(rendered.contains(
        "Recovery: open Diagnostics → Dependency doctor, install `uv sync --extra threat-intel`, and set the required API keys."
    ));
}
