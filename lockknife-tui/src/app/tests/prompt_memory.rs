use super::*;

#[test]
fn remember_prompt_defaults_from_params_captures_sanitized_metadata() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::from_loaded_config(callback, None);

    app.remember_prompt_defaults_from_params(&serde_json::json!({
        "examiner": "Analyst One",
        "title": "Device Intake",
        "target_serials": "emulator-5554",
        "categories": "timeline",
        "exclude_categories": "trash",
        "source_commands": "forensics timeline",
        "device_serials": "emulator-5554",
        "category": "derived-report",
        "source_command": "report generate",
        "device_serial": "emulator-5554"
    }));

    assert_eq!(app.prompt_defaults.examiner, "Analyst One");
    assert_eq!(app.prompt_defaults.title, "Device Intake");
    assert_eq!(app.prompt_defaults.target_serials, "emulator-5554");
    assert_eq!(app.prompt_defaults.categories, "timeline");
    assert_eq!(app.prompt_defaults.exclude_categories, "trash");
    assert_eq!(app.prompt_defaults.source_commands, "forensics timeline");
    assert_eq!(app.prompt_defaults.device_serials, "emulator-5554");
    assert_eq!(app.prompt_defaults.category, "derived-report");
    assert_eq!(app.prompt_defaults.source_command, "report generate");
    assert_eq!(app.prompt_defaults.device_serial, "emulator-5554");

    app.remember_prompt_defaults_from_params(&serde_json::json!({
        "examiner": "Examiner",
        "title": "Investigation",
        "category": "derived",
        "source_command": "case register"
    }));

    assert_eq!(app.prompt_defaults.examiner, "Analyst One");
    assert_eq!(app.prompt_defaults.title, "Device Intake");
    assert_eq!(app.prompt_defaults.category, "derived-report");
    assert_eq!(app.prompt_defaults.source_command, "report generate");
}

#[test]
fn remember_artifact_filter_history_from_params_captures_recent_filters() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::from_loaded_config(callback, None);

    app.remember_artifact_filter_history_from_params(&serde_json::json!({
        "query": "report-json",
        "path_contains": "derived/report",
        "metadata_contains": "imei",
        "categories": "report-json",
        "exclude_categories": "trash",
        "source_commands": "report generate",
        "device_serials": "emulator-5554",
        "limit": 100
    }));

    assert_eq!(
        app.artifact_filter_history.queries,
        vec!["report-json".to_string()]
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

    app.remember_artifact_filter_history_from_params(&serde_json::json!({
        "query": "timeline",
        "path_contains": "derived/report",
        "categories": "timeline",
        "limit": 50
    }));

    assert_eq!(
        app.artifact_filter_history.queries,
        vec!["timeline".to_string(), "report-json".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.path_contains,
        vec!["derived/report".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.categories,
        vec!["timeline".to_string(), "report-json".to_string()]
    );
    assert_eq!(
        app.artifact_filter_history.limits,
        vec!["50".to_string(), "100".to_string()]
    );
}
