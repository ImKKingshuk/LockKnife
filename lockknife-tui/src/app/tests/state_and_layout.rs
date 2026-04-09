use super::*;

#[test]
fn build_result_followup_prompt_uses_first_artifact_from_search_results_for_lineage() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-881".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-881",
            "artifacts": [
                {
                    "artifact_id": "artifact-1001",
                    "path": "./cases/CASE-881/derived/timeline.json"
                }
            ]
        })
        .to_string(),
    );

    let prompt = app
        .build_result_followup_prompt("case.lineage")
        .expect("case.lineage follow-up should use first artifact from search results");

    let artifact_id = prompt
        .fields
        .iter()
        .find(|field| field.key == "artifact_id")
        .expect("artifact_id field should exist");
    assert_eq!(artifact_id.value, "artifact-1001");
}

#[test]
fn build_result_followup_prompt_requires_artifact_context_for_lineage() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-900".to_string());
    app.last_result_json = Some(serde_json::json!({"case_dir": "./cases/CASE-900"}).to_string());

    let error = app
        .build_result_followup_prompt("case.lineage")
        .expect_err("case.lineage follow-up should require artifact context");

    assert_eq!(
        error,
        "Latest result does not expose an artifact ID or artifact path yet"
    );
}

#[test]
fn build_result_followup_prompt_requires_registerable_path_for_registration() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-901".to_string());
    app.last_result_json = Some(serde_json::json!({"case_dir": "./cases/CASE-901"}).to_string());

    let error = app
        .build_result_followup_prompt("case.register")
        .expect_err("case.register follow-up should require a path");

    assert_eq!(
        error,
        "Latest result does not expose a registerable artifact path yet"
    );
}

#[test]
fn apply_result_records_case_investigation_history_for_partial_and_failed_steps() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.pending_case_dir = Some("./cases/CASE-902".to_string());

    app.apply_result(
        "case.graph",
        CallbackResult {
            ok: true,
            message: Some("Graph built".to_string()),
            data_json: Some(
                serde_json::json!({
                    "case_dir": "./cases/CASE-902",
                    "missing_parent_ids": ["artifact-missing"]
                })
                .to_string(),
            ),
            job_json: None,
            logs: None,
            error: None,
        },
    );
    app.apply_result(
        "runtime.hook",
        CallbackResult {
            ok: false,
            message: None,
            data_json: Some(serde_json::json!({"case_dir": "./cases/CASE-902"}).to_string()),
            job_json: None,
            logs: None,
            error: Some("Frida attach failed".to_string()),
        },
    );

    assert_eq!(app.investigation_history.len(), 2);
    assert!(matches!(
        app.investigation_history[0].outcome,
        crate::app::InvestigationOutcome::Partial
    ));
    assert_eq!(app.investigation_history[0].summary, "1 missing parent id");
    assert!(matches!(
        app.investigation_history[1].outcome,
        crate::app::InvestigationOutcome::Failure
    ));
    assert_eq!(app.investigation_history[1].case_dir, "./cases/CASE-902");
    assert_eq!(app.active_case_history_totals(), Some((0, 1, 1)));
}

#[test]
fn start_result_view_without_result_logs_guidance() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    assert!(!app.start_result_view());
    assert!(matches!(app.overlay, Overlay::None));
    assert!(app.logs.iter().any(|entry| {
        entry
            .message
            .contains("No result available yet — run an action first")
    }));
}

#[test]
fn cycle_theme_emits_feedback() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.theme = Theme::Dark;

    app.cycle_theme();

    assert!(matches!(app.theme, Theme::Light));
    assert!(app.logs.iter().any(|entry| entry.message == "Theme: light"));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Theme: light"));
}

#[test]
fn apply_search_query_reports_apply_and_clear() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.module_scroll = 7;

    app.apply_search_query(
        SearchTarget::Modules,
        "certificate pinning flow".to_string(),
    );

    let search = app.search.as_ref().expect("search should be active");
    assert!(matches!(search.target, SearchTarget::Modules));
    assert_eq!(search.query, "certificate pinning flow");
    assert_eq!(app.module_scroll, 0);
    assert!(app.toasts.iter().any(|toast| toast
        .message
        .contains("Filtering modules by \"certificate pinning flow\"")));

    app.apply_search_query(SearchTarget::Modules, "   ".to_string());

    assert!(app.search.is_none());
    assert!(app
        .logs
        .iter()
        .any(|entry| entry.message == "Cleared modules filter"));
}

#[test]
fn apply_result_device_list_without_message_reports_refresh_summary() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    app.apply_result(
            "device.list",
            CallbackResult {
                ok: true,
                message: None,
                data_json: Some(
                    serde_json::json!([
                        {"serial": "emulator-5554", "state": "device", "adb_state": "device", "model": "Pixel"},
                        {"serial": "ZX1G22", "state": "device", "adb_state": "device", "model": "Moto"}
                    ])
                    .to_string(),
                ),
                job_json: None,
                logs: None,
                error: None,
            },
        );

    assert_eq!(app.devices.len(), 2);
    assert!(app
        .logs
        .iter()
        .any(|entry| entry.message == "Device refresh complete — 2 devices detected."));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Device refresh complete — 2 devices detected."));
}

#[test]
fn apply_result_surfaces_recovery_guidance_for_failed_actions() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    app.apply_result(
        "runtime.hook",
        CallbackResult {
            ok: false,
            message: None,
            data_json: None,
            job_json: None,
            logs: Some(vec![crate::bridge::CallbackLog {
                level: "error".to_string(),
                message: "Frida attach failed".to_string(),
            }]),
            error: Some("Frida attach failed".to_string()),
        },
    );

    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Frida attach failed"));
    assert!(app.toasts.iter().any(|toast| {
        toast
            .message
            .contains("Recovery: open Diagnostics → Dependency doctor")
    }));
    assert!(app
        .logs
        .iter()
        .any(|entry| entry.message.contains("uv sync --extra frida")));
}

#[test]
fn apply_result_config_save_without_message_reports_saved_config() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_path = Some("./lockknife.toml".to_string());
    app.config_text = "theme = 'light'\n".to_string();
    app.config_saved_text = "theme = 'dark'\n".to_string();

    app.apply_result(
        "config.save",
        CallbackResult {
            ok: true,
            message: None,
            data_json: None,
            job_json: None,
            logs: None,
            error: None,
        },
    );

    assert!(app
        .logs
        .iter()
        .any(|entry| entry.message == "Saved config: ./lockknife.toml"));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Saved config: ./lockknife.toml"));
    assert!(!app.config_is_dirty());
}

#[test]
fn config_edit_helpers_track_dirty_state_and_utf8_boundaries() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_text = "héllo\nworld".to_string();
    app.config_saved_text = app.config_text.clone();
    app.config_cursor = app.config_text.len();

    app.config_move_cursor_left();
    assert_eq!(app.config_cursor, "héllo\nworl".len());

    app.config_move_cursor_home();
    assert_eq!(app.config_cursor, "héllo\n".len());

    app.config_insert_char('!');
    assert_eq!(app.config_text, "héllo\n!world");
    assert!(app.config_is_dirty());

    app.config_backspace();
    assert_eq!(app.config_text, "héllo\nworld");
    assert!(!app.config_is_dirty());

    app.config_move_cursor_end();
    assert_eq!(app.config_cursor, app.config_text.len());
}

#[test]
fn config_vertical_movement_and_scroll_follow_cursor() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_text = "alpha\nb\ngamma\ndelta".to_string();
    app.config_saved_text = app.config_text.clone();
    app.set_config_viewport_height(2);
    app.config_cursor = "alp".len();

    app.config_move_cursor_down();
    assert_eq!(app.config_cursor, "alpha\nb".len());
    assert_eq!(app.config_scroll, 0);

    app.config_move_cursor_down();
    assert_eq!(app.config_cursor, "alpha\nb\ngam".len());
    assert_eq!(app.config_scroll, 1);

    app.config_move_cursor_up();
    assert_eq!(app.config_cursor, "alpha\nb".len());
    assert_eq!(app.config_scroll, 1);

    app.config_move_cursor_up();
    assert_eq!(app.config_cursor, "alp".len());
    assert_eq!(app.config_scroll, 0);
}

#[test]
fn execute_action_without_device_surfaces_toast() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    let (module_index, action_index) = app
        .modules
        .iter()
        .enumerate()
        .find_map(|(module_index, module)| {
            module
                .actions
                .iter()
                .enumerate()
                .find(|(_, action)| action.requires_device)
                .map(|(action_index, _)| (module_index, action_index))
        })
        .expect("expected at least one device-backed action");

    app.execute_action(
        module_index,
        action_index,
        Value::Object(serde_json::Map::new()),
    );

    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "No device selected"));
}

#[test]
fn main_body_height_budget_preserves_output_space_on_short_terminals() {
    assert_eq!(main_body_height_budget(12, 12), (7, 5));
    assert_eq!(main_body_height_budget(12, 8), (5, 3));
    assert_eq!(main_body_height_budget(12, 5), (3, 2));
}

#[test]
fn update_layout_clamps_top_row_for_short_terminals() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.top_height = 20;

    app.update_layout(Rect::new(0, 0, 80, 18));

    assert_eq!(app.layout.header.height, 3);
    assert_eq!(app.layout.status.height, 3);
    assert_eq!(app.layout.devices.height, 7);
    assert_eq!(app.layout.modules.height, 7);
    assert_eq!(app.layout.output.height, 5);
    assert!(app.is_compact_main_layout());
}

#[test]
fn update_layout_keeps_regular_top_row_when_space_allows() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    app.update_layout(Rect::new(0, 0, 80, 24));

    assert_eq!(app.layout.devices.height, 9);
    assert_eq!(app.layout.output.height, 9);
    assert!(!app.is_compact_main_layout());
}
