use super::*;

#[test]
fn build_recent_case_prompt_uses_choice_field_for_session_history() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-003".to_string());
    app.recent_case_dirs = vec![
        "./cases/CASE-003".to_string(),
        "./cases/CASE-002".to_string(),
        "./cases/CASE-001".to_string(),
    ];

    let prompt = app
        .build_recent_case_prompt()
        .expect("recent case prompt should be available");

    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");

    assert_eq!(prompt.title, "Summary");
    assert!(matches!(case_dir.kind, FieldKind::Choice));
    assert_eq!(case_dir.value, "./cases/CASE-003");
    assert_eq!(
        case_dir.options,
        vec![
            "./cases/CASE-003".to_string(),
            "./cases/CASE-002".to_string(),
            "./cases/CASE-001".to_string()
        ]
    );
    assert!(prompt.help_lines[0].contains("Recent case recall from the main TUI"));
}

#[test]
fn build_recent_case_prompt_reports_when_session_has_no_case_history() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(callback, None);

    let error = app
        .build_recent_case_prompt()
        .expect_err("recent case prompt should require case history");

    assert_eq!(error, "No recent cases in this TUI session yet");
}

#[test]
fn build_recent_artifact_filter_prompt_uses_choice_fields_for_saved_history() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(
        callback,
        Some(TuiConfig {
            theme: "dark".to_string(),
            top_height: 9,
            recent_case_dirs: vec![],
            prompt_defaults: PersistedPromptDefaults::default(),
            artifact_filter_history: PersistedArtifactFilterHistory {
                queries: vec!["report-json".to_string(), "timeline".to_string()],
                path_contains: vec!["derived/report".to_string()],
                metadata_contains: vec![],
                categories: vec!["report-json".to_string(), "timeline".to_string()],
                exclude_categories: vec![],
                source_commands: vec!["report generate".to_string()],
                device_serials: vec!["emulator-5554".to_string()],
                limits: vec![],
            },
        }),
    );

    let prompt = app
        .build_recent_artifact_filter_prompt()
        .expect("artifact recall prompt should be available");

    let query = prompt
        .fields
        .iter()
        .find(|field| field.key == "query")
        .expect("query field should exist");
    let categories = prompt
        .fields
        .iter()
        .find(|field| field.key == "categories")
        .expect("categories field should exist");
    let limit = prompt
        .fields
        .iter()
        .find(|field| field.key == "limit")
        .expect("limit field should exist");

    assert_eq!(prompt.title, "Artifact search");
    assert!(matches!(query.kind, FieldKind::Choice));
    assert_eq!(
        query.options,
        vec!["report-json".to_string(), "timeline".to_string()]
    );
    assert!(matches!(categories.kind, FieldKind::Choice));
    assert_eq!(categories.value, "report-json");
    assert!(matches!(limit.kind, FieldKind::Number));
    assert_eq!(limit.value, "100");
    assert!(prompt.help_lines[0].contains("Artifact recall from the main TUI"));
}

#[test]
fn build_recent_artifact_filter_prompt_reports_when_history_is_missing() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(callback, None);

    let error = app
        .build_recent_artifact_filter_prompt()
        .expect_err("artifact recall prompt should require saved history");

    assert_eq!(error, "No recent artifact filters saved yet");
}

#[test]
fn load_tui_config_from_path_defaults_recent_cases_for_legacy_files() {
    let path = temp_tui_config_path("legacy-config");
    std::fs::write(&path, "theme = 'light'\ntop_height = 11\n")
        .expect("legacy config should be writable");

    let config = load_tui_config_from_path(&path).expect("legacy config should load");

    assert_eq!(config.theme, "light");
    assert_eq!(config.top_height, 11);
    assert!(config.recent_case_dirs.is_empty());
    assert_eq!(config.prompt_defaults, PersistedPromptDefaults::default());
    assert_eq!(
        config.artifact_filter_history,
        PersistedArtifactFilterHistory::default()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn default_config_path_is_disabled_for_unit_tests() {
    assert!(config_path().is_none());
}

#[test]
fn app_from_loaded_config_restores_sanitized_recent_case_history() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(
        callback,
        Some(TuiConfig {
            theme: "hacker".to_string(),
            top_height: 12,
            recent_case_dirs: vec![
                "./cases/CASE-006".to_string(),
                " ".to_string(),
                "./cases/CASE-006".to_string(),
                "./cases/CASE-005".to_string(),
                "./cases/CASE-004".to_string(),
                "./cases/CASE-003".to_string(),
                "./cases/CASE-002".to_string(),
                "./cases/CASE-001".to_string(),
                "./cases/CASE-000".to_string(),
            ],
            prompt_defaults: PersistedPromptDefaults::default(),
            artifact_filter_history: PersistedArtifactFilterHistory::default(),
        }),
    );

    assert!(matches!(app.theme, Theme::Hacker));
    assert_eq!(app.top_height, 12);
    assert_eq!(
        app.recent_case_dirs,
        vec![
            "./cases/CASE-006".to_string(),
            "./cases/CASE-005".to_string(),
            "./cases/CASE-004".to_string(),
            "./cases/CASE-003".to_string(),
            "./cases/CASE-002".to_string(),
            "./cases/CASE-001".to_string(),
        ]
    );
}

#[test]
fn current_tui_config_persists_recent_case_history_roundtrip() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::from_loaded_config(callback, None);
    app.theme = Theme::Light;
    app.top_height = 13;
    app.recent_case_dirs = vec![
        "./cases/CASE-020".to_string(),
        "./cases/CASE-019".to_string(),
        "./cases/CASE-020".to_string(),
        " ".to_string(),
        "./cases/CASE-018".to_string(),
    ];
    app.prompt_defaults = PersistedPromptDefaults {
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
    };
    app.artifact_filter_history = PersistedArtifactFilterHistory {
        queries: vec!["report-json".to_string(), "timeline".to_string()],
        path_contains: vec!["derived/report".to_string(), "derived/report".to_string()],
        metadata_contains: vec!["imei".to_string()],
        categories: vec!["report-json".to_string()],
        exclude_categories: vec!["trash".to_string()],
        source_commands: vec!["report generate".to_string()],
        device_serials: vec!["emulator-5554".to_string()],
        limits: vec!["100".to_string()],
    };

    let path = temp_tui_config_path("recent-roundtrip");
    save_tui_config_to_path(&app.current_tui_config(), &path);
    let loaded = load_tui_config_from_path(&path).expect("saved config should roundtrip");

    assert_eq!(loaded.theme, "light");
    assert_eq!(loaded.top_height, 13);
    assert_eq!(
        loaded.recent_case_dirs,
        vec![
            "./cases/CASE-020".to_string(),
            "./cases/CASE-019".to_string(),
            "./cases/CASE-018".to_string(),
        ]
    );
    assert_eq!(loaded.prompt_defaults.examiner, "Analyst One");
    assert_eq!(loaded.prompt_defaults.title, "Device Intake");
    assert_eq!(loaded.prompt_defaults.target_serials, "emulator-5554");
    assert_eq!(loaded.prompt_defaults.categories, "timeline");
    assert_eq!(loaded.prompt_defaults.exclude_categories, "trash");
    assert_eq!(loaded.prompt_defaults.source_commands, "forensics timeline");
    assert_eq!(loaded.prompt_defaults.device_serials, "emulator-5554");
    assert_eq!(loaded.prompt_defaults.category, "derived-report");
    assert_eq!(loaded.prompt_defaults.source_command, "report generate");
    assert_eq!(loaded.prompt_defaults.device_serial, "emulator-5554");
    assert_eq!(
        loaded.artifact_filter_history.queries,
        vec!["report-json".to_string(), "timeline".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.path_contains,
        vec!["derived/report".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.metadata_contains,
        vec!["imei".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.categories,
        vec!["report-json".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.exclude_categories,
        vec!["trash".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.source_commands,
        vec!["report generate".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.device_serials,
        vec!["emulator-5554".to_string()]
    );
    assert_eq!(
        loaded.artifact_filter_history.limits,
        vec!["100".to_string()]
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn app_from_loaded_config_restores_sanitized_prompt_defaults() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(
        callback,
        Some(TuiConfig {
            theme: "dark".to_string(),
            top_height: 9,
            recent_case_dirs: vec![],
            prompt_defaults: PersistedPromptDefaults {
                examiner: " Examiner ".to_string(),
                title: "Investigation".to_string(),
                target_serials: " emulator-5554 ".to_string(),
                categories: " timeline ".to_string(),
                exclude_categories: " trash ".to_string(),
                source_commands: " forensics timeline ".to_string(),
                device_serials: " emulator-5554 ".to_string(),
                category: "derived".to_string(),
                source_command: "case register".to_string(),
                device_serial: " emulator-5554 ".to_string(),
            },
            artifact_filter_history: PersistedArtifactFilterHistory::default(),
        }),
    );

    assert_eq!(app.prompt_defaults.examiner, "");
    assert_eq!(app.prompt_defaults.title, "");
    assert_eq!(app.prompt_defaults.target_serials, "emulator-5554");
    assert_eq!(app.prompt_defaults.categories, "timeline");
    assert_eq!(app.prompt_defaults.exclude_categories, "trash");
    assert_eq!(app.prompt_defaults.source_commands, "forensics timeline");
    assert_eq!(app.prompt_defaults.device_serials, "emulator-5554");
    assert_eq!(app.prompt_defaults.category, "");
    assert_eq!(app.prompt_defaults.source_command, "");
    assert_eq!(app.prompt_defaults.device_serial, "emulator-5554");
}

#[test]
fn app_from_loaded_config_restores_sanitized_artifact_filter_history() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::from_loaded_config(
        callback,
        Some(TuiConfig {
            theme: "dark".to_string(),
            top_height: 9,
            recent_case_dirs: vec![],
            prompt_defaults: PersistedPromptDefaults::default(),
            artifact_filter_history: PersistedArtifactFilterHistory {
                queries: vec![
                    " report-json ".to_string(),
                    " ".to_string(),
                    "report-json".to_string(),
                    "timeline".to_string(),
                ],
                path_contains: vec![" derived/report ".to_string()],
                metadata_contains: vec![" imei ".to_string()],
                categories: vec![" report-json ".to_string()],
                exclude_categories: vec![" trash ".to_string()],
                source_commands: vec![" report generate ".to_string()],
                device_serials: vec![" emulator-5554 ".to_string()],
                limits: vec![" 100 ".to_string(), "100".to_string()],
            },
        }),
    );

    assert_eq!(
        app.artifact_filter_history.queries,
        vec!["report-json".to_string(), "timeline".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.path_contains,
        vec!["derived/report".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.metadata_contains,
        vec!["imei".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.categories,
        vec!["report-json".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.exclude_categories,
        vec!["trash".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.source_commands,
        vec!["report generate".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.device_serials,
        vec!["emulator-5554".to_string()]
    );
    assert_eq!(app.artifact_filter_history.limits, vec!["100".to_string()]);
}
