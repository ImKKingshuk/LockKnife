use super::*;

#[test]
fn build_search_prompt_reflects_output_target_and_existing_query() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Output,
        query: "certificate".to_string(),
    });

    let prompt = build_search_prompt(&app, SearchTarget::Output);

    assert_eq!(prompt.title, "Search Output");
    assert_eq!(prompt.fields[0].value, "certificate");
    assert!(prompt
        .description
        .as_deref()
        .unwrap_or_default()
        .contains("output logs"));
    assert!(prompt
        .help_lines
        .iter()
        .any(|line| line.contains("Output panel")));
    assert!(prompt
        .help_lines
        .iter()
        .any(|line| line.contains("empty query to clear the current output filter")));
}

#[test]
fn handle_main_opens_case_summary_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-123".to_string());

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(prompt.title, "Summary");
    assert_eq!(case_dir.value, "./cases/CASE-123");
    assert!(prompt.help_lines[0].contains("Quick case access from the main TUI"));
}

#[test]
fn handle_main_opens_diagnostics_menu_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::ActionMenu(state) = &app.overlay else {
        panic!("expected diagnostics action menu");
    };
    let module = app
        .modules
        .get(state.module_index)
        .expect("diagnostics module should exist");
    let action = module
        .actions
        .get(state.action_index)
        .expect("dependency doctor action should exist");
    assert_eq!(module.id, "core");
    assert_eq!(action.id, "core.doctor");
}

#[test]
fn handle_main_opens_recent_case_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-123".to_string());
    app.recent_case_dirs = vec![
        "./cases/CASE-123".to_string(),
        "./cases/CASE-045".to_string(),
    ];

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(prompt.title, "Summary");
    assert!(matches!(case_dir.kind, FieldKind::Choice));
    assert_eq!(case_dir.options.len(), 2);
    assert!(prompt.help_lines[0].contains("Recent case recall from the main TUI"));
}

#[test]
fn handle_main_opens_recent_artifact_filter_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.artifact_filter_history = crate::app::PersistedArtifactFilterHistory {
        queries: vec!["report-json".to_string(), "timeline".to_string()],
        path_contains: vec!["derived/report".to_string()],
        metadata_contains: vec![],
        categories: vec!["report-json".to_string()],
        exclude_categories: vec![],
        source_commands: vec!["report generate".to_string()],
        device_serials: vec!["emulator-5554".to_string()],
        limits: vec!["100".to_string()],
    };

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    let query = prompt
        .fields
        .iter()
        .find(|field| field.key == "query")
        .expect("query field should exist");
    let limit = prompt
        .fields
        .iter()
        .find(|field| field.key == "limit")
        .expect("limit field should exist");
    assert_eq!(prompt.title, "Artifact search");
    assert!(matches!(query.kind, FieldKind::Choice));
    assert_eq!(query.options.len(), 2);
    assert_eq!(limit.value, "100");
    assert!(prompt.help_lines[0].contains("Artifact recall from the main TUI"));
}

#[test]
fn handle_main_reports_when_recent_case_history_is_missing() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.recent_case_dirs.clear();

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    assert!(matches!(app.overlay, Overlay::None));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "No recent cases in this TUI session yet"));
}

#[test]
fn handle_main_reports_when_artifact_filter_history_is_missing() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.artifact_filter_history = crate::app::PersistedArtifactFilterHistory::default();

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    assert!(matches!(app.overlay, Overlay::None));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "No recent artifact filters saved yet"));
}

#[test]
fn handle_main_opens_case_init_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-123".to_string());

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(prompt.title, "Init workspace");
    assert_eq!(case_dir.value, "./cases/CASE-001");
    assert!(prompt.help_lines[0].contains("Quick case init from the main TUI"));
}

#[test]
fn handle_main_opens_case_summary_prompt_even_without_active_case() {
    let callback = none_callback();
    let mut app = App::new(callback);

    let should_quit = handle_main(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)),
    );

    assert!(!should_quit);
    let Overlay::Prompt(prompt) = &app.overlay else {
        panic!("expected prompt overlay");
    };
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");
    assert_eq!(case_dir.value, "./cases/CASE-001");
    assert!(prompt.help_lines[0].contains("set Case directory to open or resume a workspace"));
}

#[test]
fn build_search_prompt_does_not_reuse_other_target_query() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Output,
        query: "certificate".to_string(),
    });

    let prompt = build_search_prompt(&app, SearchTarget::Modules);

    assert_eq!(prompt.title, "Search Modules");
    assert!(prompt.fields[0].value.is_empty());
    assert!(prompt
        .description
        .as_deref()
        .unwrap_or_default()
        .contains("module names"));
}
