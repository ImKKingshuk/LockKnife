use super::*;

#[test]
fn handle_action_menu_prefills_case_aware_prompt_from_active_case() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-021".to_string());

    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "case")
        .expect("case module should exist");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "case.summary")
        .expect("case.summary should exist");

    let (_, overlay) = handle_action_menu(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        crate::app::ActionMenuState {
            module_index,
            action_index,
        },
    );

    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(case_dir.value, "./cases/CASE-021");
    assert!(prompt
        .help_lines
        .iter()
        .any(|line| line.contains("Active case in this TUI session")));
}

#[test]
fn handle_main_case_panel_shortcuts_open_case_dashboard_workflows() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_panel = Panel::Case;
    app.active_case_dir = Some("./cases/CASE-303".to_string());

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Summary");

    app.overlay = Overlay::None;
    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Generate report");
    assert!(prompt.help_lines[0].contains("Case dashboard quick action"));

    app.overlay = Overlay::None;
    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Chain of custody");

    app.overlay = Overlay::None;
    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Integrity report");

    app.overlay = Overlay::None;
    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Job history");
}

#[test]
fn handle_result_view_opens_case_job_followups() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-444".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-444",
            "recent_jobs": [{"job_id": "job-0003", "status": "failed"}]
        })
        .to_string(),
    );
    app.last_job_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-444",
            "job_id": "job-0003",
            "status": "failed"
        })
        .to_string(),
    );
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Job context\n- Latest job: job-0003".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE)),
        state.clone(),
    );
    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Resume job");

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)),
        state,
    );
    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    assert_eq!(prompt.title, "Retry job");
}

#[test]
fn handle_action_menu_prefills_general_case_metadata_defaults() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-022".to_string());
    app.devices = vec![crate::app::DeviceItem {
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
                "category": "report-json",
                "source_command": "report generate"
            }
        })
        .to_string(),
    );

    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "case")
        .expect("case module should exist");
    let action_index = app.modules[module_index]
        .actions
        .iter()
        .position(|action| action.id == "case.register")
        .expect("case.register should exist");

    let (_, overlay) = handle_action_menu(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        crate::app::ActionMenuState {
            module_index,
            action_index,
        },
    );

    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    let field_value = |key: &str| {
        prompt
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };

    assert_eq!(field_value("case_dir"), "./cases/CASE-022");
    assert_eq!(field_value("category"), "report-json");
    assert_eq!(field_value("source_command"), "report generate");
    assert_eq!(field_value("device_serial"), "emulator-5554");
}
