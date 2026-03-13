use super::*;

#[test]
fn handle_result_view_supports_home_end_and_section_jumps() {
    let callback = none_callback();
    let mut app = App::new(callback);
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Summary\nok\n\nKey paths\n- Output: ./out.json\n\nJSON\n{}".to_string(),
        scroll: 0,
        line_count: 8,
        section_starts: vec![0, 3, 6],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE)),
        state.clone(),
    );
    let Overlay::ResultView(state) = overlay else {
        panic!("expected result view overlay");
    };
    assert_eq!(state.scroll, 3);

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE)),
        ResultViewState {
            scroll: 6,
            ..state.clone()
        },
    );
    let Overlay::ResultView(state) = overlay else {
        panic!("expected result view overlay");
    };
    assert_eq!(state.scroll, 3);

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
        state.clone(),
    );
    let Overlay::ResultView(state) = overlay else {
        panic!("expected result view overlay");
    };
    assert_eq!(state.scroll, 7);

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE)),
        ResultViewState { scroll: 7, ..state },
    );
    let Overlay::ResultView(state) = overlay else {
        panic!("expected result view overlay");
    };
    assert_eq!(state.scroll, 0);
}

#[test]
fn handle_result_view_opens_artifact_followup_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-777".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-777",
            "artifact": {
                "artifact_id": "artifact-9000",
                "path": "./cases/CASE-777/derived/report.json"
            }
        })
        .to_string(),
    );
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Artifact context\n- Artifact: artifact-9000".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)),
        state,
    );

    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    let artifact_id = prompt
        .fields
        .iter()
        .find(|field| field.key == "artifact_id")
        .expect("artifact_id field should exist");
    let case_dir = prompt
        .fields
        .iter()
        .find(|field| field.key == "case_dir")
        .expect("case_dir field should exist");

    assert_eq!(prompt.title, "Artifact detail");
    assert_eq!(artifact_id.value, "artifact-9000");
    assert_eq!(case_dir.value, "./cases/CASE-777");
}

#[test]
fn handle_result_view_opens_artifact_search_followup_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-781".to_string());
    app.last_result_paths = vec![
        crate::app::ResultPath {
            label: "Case directory".to_string(),
            value: "./cases/CASE-781".to_string(),
        },
        crate::app::ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-781/derived/timeline.json".to_string(),
        },
    ];
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-781",
            "category": "forensics-timeline",
            "source_command": "forensics timeline"
        })
        .to_string(),
    );
    let state = ResultViewState {
        title: "Result".to_string(),
        content:
            "Artifact context\n- Classification: forensics-timeline · Source: forensics timeline"
                .to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE)),
        state,
    );

    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    let category = prompt
        .fields
        .iter()
        .find(|field| field.key == "categories")
        .expect("categories field should exist");
    let path_contains = prompt
        .fields
        .iter()
        .find(|field| field.key == "path_contains")
        .expect("path_contains field should exist");

    assert_eq!(prompt.title, "Artifact search");
    assert_eq!(category.value, "forensics-timeline");
    assert_eq!(path_contains.value, "./cases/CASE-781/derived");
}

#[test]
fn handle_result_view_opens_register_followup_prompt_from_shortcut() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-779".to_string());
    app.last_result_paths = vec![
        crate::app::ResultPath {
            label: "Case directory".to_string(),
            value: "./cases/CASE-779".to_string(),
        },
        crate::app::ResultPath {
            label: "Output".to_string(),
            value: "./cases/CASE-779/derived/report.json".to_string(),
        },
    ];
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-779",
            "source_command": "report generate",
            "category": "report-json"
        })
        .to_string(),
    );
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Key paths\n- Output: ./cases/CASE-779/derived/report.json".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
        state,
    );

    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected prompt overlay");
    };
    let path = prompt
        .fields
        .iter()
        .find(|field| field.key == "path")
        .expect("path field should exist");
    let category = prompt
        .fields
        .iter()
        .find(|field| field.key == "category")
        .expect("category field should exist");

    assert_eq!(prompt.title, "Register artifact");
    assert_eq!(path.value, "./cases/CASE-779/derived/report.json");
    assert_eq!(category.value, "report-json");
}

#[test]
fn handle_result_view_opens_export_and_report_followup_prompts_from_shortcuts() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-782".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-782",
            "case_id": "CASE-782"
        })
        .to_string(),
    );
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Case context\n- Active case: ./cases/CASE-782".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
        state.clone(),
    );
    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected export prompt overlay");
    };
    assert_eq!(prompt.title, "Export bundle");

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
        state.clone(),
    );
    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected enrichment prompt overlay");
    };
    assert_eq!(prompt.title, "Enrichment bundle");

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE)),
        state,
    );
    let Overlay::Prompt(prompt) = overlay else {
        panic!("expected report prompt overlay");
    };
    assert_eq!(prompt.title, "Generate report");
}

#[test]
fn handle_result_view_keeps_overlay_open_when_followup_context_is_missing() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-778".to_string());
    app.last_result_json = Some(serde_json::json!({"case_dir": "./cases/CASE-778"}).to_string());
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Case context\n- Active case: ./cases/CASE-778".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE)),
        state,
    );

    assert!(matches!(overlay, Overlay::ResultView(_)));
    assert!(app.toasts.iter().any(|toast| {
        toast.message == "Latest result does not expose an artifact ID or artifact path yet"
    }));
}

#[test]
fn handle_result_view_keeps_overlay_open_when_register_path_is_missing() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-780".to_string());
    app.last_result_json = Some(serde_json::json!({"case_dir": "./cases/CASE-780"}).to_string());
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Case context\n- Active case: ./cases/CASE-780".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
        state,
    );

    assert!(matches!(overlay, Overlay::ResultView(_)));
    assert!(app.toasts.iter().any(|toast| {
        toast.message == "Latest result does not expose a registerable artifact path yet"
    }));
}

#[test]
fn handle_result_view_keeps_overlay_open_for_artifact_search_without_case_context() {
    let callback = none_callback();
    let mut app = App::new(callback);
    let state = ResultViewState {
        title: "Result".to_string(),
        content: "Summary\nNo case context".to_string(),
        scroll: 0,
        line_count: 2,
        section_starts: vec![0],
    };

    let (_, overlay) = handle_result_view(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE)),
        state,
    );

    assert!(matches!(overlay, Overlay::ResultView(_)));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Latest result does not expose a case directory yet"));
}
