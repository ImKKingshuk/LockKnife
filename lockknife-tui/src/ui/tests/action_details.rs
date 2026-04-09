use super::*;

#[test]
fn action_menu_detail_lines_include_description_and_traits() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let action = crate::app::ModuleAction {
        id: "runtime.hook".to_string(),
        label: "Start hook session".to_string(),
        fields: vec![
            PromptField {
                key: "script".to_string(),
                label: "Script path".to_string(),
                value: "".to_string(),
                kind: FieldKind::Text,
                options: vec![],
            },
            PromptField {
                key: "output".to_string(),
                label: "Session summary output path (optional)".to_string(),
                value: "".to_string(),
                kind: FieldKind::Text,
                options: vec![],
            },
            PromptField {
                key: "case_dir".to_string(),
                label: "Case directory".to_string(),
                value: "./cases/CASE-001".to_string(),
                kind: FieldKind::Text,
                options: vec![],
            },
        ],
        requires_device: false,
        confirm: true,
    };

    let rendered = action_menu_detail_lines(&app, &action, Rect::new(0, 0, 72, 18))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Start a named managed hook session"));
    assert!(rendered.contains("case-aware"));
    assert!(rendered.contains("writes output"));
    assert!(rendered.contains("Flow: 3 inputs · Enter opens inputs"));
    assert!(rendered.contains("managed sessions"));
    assert!(rendered.contains("Playbook: Runtime triage step 2/4"));
    assert!(rendered.contains(
        "Preflight: dependency-gated [gated] · requires lockknife[frida] + Frida server."
    ));
    assert!(rendered.contains("Recovery: open Diagnostics → Dependency doctor"));
    assert!(rendered
        .contains("Recommended next: inspect [i] Runtime session, then keep [h]/[c]/[o] ready"));
    assert!(rendered.contains("Enter open/run"));
}

#[test]
fn action_menu_detail_lines_surface_standardized_preflight_for_optional_modules() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let action = app
        .modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "network.summarize")
        .expect("network.summarize should exist");

    let rendered = action_menu_detail_lines(&app, action, Rect::new(0, 0, 84, 18))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Preflight: dependency-gated [gated] · requires lockknife[network]."));
    assert!(rendered.contains(
        "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra network` to unlock PCAP analysis workflows."
    ));
}

#[test]
fn module_detail_lines_include_description_counts_and_help() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let module = crate::app::ModuleEntry {
        id: "runtime".to_string(),
        label: "Runtime".to_string(),
        actions: vec![
            crate::app::ModuleAction {
                id: "runtime.hook".to_string(),
                label: "Start hook session".to_string(),
                fields: vec![
                    PromptField {
                        key: "output".to_string(),
                        label: "Session summary output path (optional)".to_string(),
                        value: "".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                    PromptField {
                        key: "case_dir".to_string(),
                        label: "Case directory".to_string(),
                        value: "./cases/CASE-001".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                ],
                requires_device: false,
                confirm: true,
            },
            crate::app::ModuleAction {
                id: "runtime.heap_dump".to_string(),
                label: "Heap dump".to_string(),
                fields: vec![
                    PromptField {
                        key: "result_output".to_string(),
                        label: "Result output path (optional)".to_string(),
                        value: "".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                    PromptField {
                        key: "case_dir".to_string(),
                        label: "Case directory".to_string(),
                        value: "./cases/CASE-001".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                ],
                requires_device: false,
                confirm: true,
            },
        ],
    };

    let rendered = module_detail_lines(&app, &module)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Launch and manage Frida-backed runtime sessions"));
    assert!(rendered.contains("Actions: 2 · device-backed: 0 · case-aware: 2 · outputs: 2"));
    assert!(rendered.contains(
        "Case: no active case yet · press n to init one or set Case directory so 2 managed-output workflows stay in one workspace."
    ));
    assert!(rendered.contains("Playbooks: Runtime triage"));
    assert!(rendered.contains("Recovery: open Diagnostics → Dependency doctor"));
    assert!(rendered
        .contains("Recommended next: start with Preflight, then launch Hook/SSL bypass/Trace"));
    assert!(rendered.contains("First action: Start hook session · Enter opens actions"));
    assert!(rendered.contains("Managed runtime sessions require Case directory"));
}

#[test]
fn module_detail_lines_surface_device_blockers_when_no_device_is_selected() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let module = app
        .modules
        .iter()
        .find(|module| module.id == "credentials")
        .expect("credentials module should exist");

    let rendered = module_detail_lines(&app, module)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Blocked: this module needs a selected device"));
}

#[test]
fn action_menu_detail_lines_surface_ready_device_context() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.devices.push(DeviceItem {
        serial: "SERIAL-1".to_string(),
        adb_state: "device".to_string(),
        state: "connected".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    });

    let action = app
        .modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "credentials.pin")
        .expect("credentials.pin should exist");

    let rendered = action_menu_detail_lines(&app, action, Rect::new(0, 0, 80, 18))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Ready: device-backed action will use SERIAL-1."));
}

#[test]
fn module_detail_lines_surface_active_case_context_for_case_aware_modules() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-011".to_string());
    let module = app
        .modules
        .iter()
        .find(|module| module.id == "case")
        .expect("case module should exist");

    let rendered = module_detail_lines(&app, module)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Case: ./cases/CASE-011"));
    assert!(rendered.contains("can reuse"));
}

#[test]
fn module_detail_lines_quantify_case_reuse_and_auto_routing() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-777".to_string());
    let module = crate::app::ModuleEntry {
        id: "runtime".to_string(),
        label: "Runtime".to_string(),
        actions: vec![
            crate::app::ModuleAction {
                id: "runtime.hook".to_string(),
                label: "Hook script".to_string(),
                fields: vec![
                    PromptField {
                        key: "output".to_string(),
                        label: "Preview output path (optional)".to_string(),
                        value: "".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                    PromptField {
                        key: "case_dir".to_string(),
                        label: "Case directory".to_string(),
                        value: "./cases/CASE-777".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                ],
                requires_device: false,
                confirm: true,
            },
            crate::app::ModuleAction {
                id: "runtime.heap_dump".to_string(),
                label: "Heap dump".to_string(),
                fields: vec![
                    PromptField {
                        key: "result_output".to_string(),
                        label: "Result output path (optional)".to_string(),
                        value: "".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                    PromptField {
                        key: "case_dir".to_string(),
                        label: "Case directory".to_string(),
                        value: "./cases/CASE-777".to_string(),
                        kind: FieldKind::Text,
                        options: vec![],
                    },
                ],
                requires_device: false,
                confirm: true,
            },
        ],
    };

    let rendered = module_detail_lines(&app, &module)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains(
        "Case: ./cases/CASE-777 · 2 case-aware actions can reuse it, 2 can auto-route managed outputs."
    ));
}

#[test]
fn action_menu_detail_lines_surface_active_case_routing_guidance() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-012".to_string());
    let action = app
        .modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "report.generate")
        .expect("report.generate should exist");

    let rendered = action_menu_detail_lines(&app, action, Rect::new(0, 0, 84, 20))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains(
        "Case: ./cases/CASE-012 · leave Output blank to auto-route managed artifacts into this case."
    ));
}
