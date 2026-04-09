use super::*;

#[test]
fn config_hint_lines_show_controls_and_cursor_position() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_text = "[ui]\ntheme='dark'\n".to_string();
    app.config_saved_text = app.config_text.clone();
    app.config_cursor = 12;
    app.config_scroll = 3;

    let rendered = config_hint_lines(&app, Rect::new(0, 0, 80, 2))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Ctrl+S save"));
    assert!(rendered.contains("Ctrl+R revert"));
    assert!(rendered.contains("Home/End line"));
    assert!(rendered.contains("Saved · Cursor: Ln 2 · Col 8 · Scroll 3"));
}

#[test]
fn config_cursor_line_col_tracks_line_breaks() {
    assert_eq!(config_cursor_line_col("abc", 0), (1, 1));
    assert_eq!(config_cursor_line_col("abc\ndef", 4), (2, 1));
    assert_eq!(config_cursor_line_col("abc\ndef", 6), (2, 3));
}

#[test]
fn prompt_hint_lines_explain_case_aware_runtime_session_behavior() {
    let state = PromptState {
        title: "Runtime Hook".to_string(),
        description: None,
        help_lines: vec![],
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
        index: 0,
        target: PromptTarget::Export,
    };

    let rendered = prompt_hint_lines(&state, Rect::new(0, 0, 72, 18))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("case-managed path"));
    assert!(rendered.contains("script snapshots, JSONL event logs"));
    assert!(rendered.contains("Enter next/submit"));
}

#[test]
fn prompt_hint_lines_explain_result_output_for_heap_dump_style_actions() {
    let state = PromptState {
        title: "Heap dump".to_string(),
        description: None,
        help_lines: vec![],
        fields: vec![
            PromptField {
                key: "output".to_string(),
                label: "Remote output path".to_string(),
                value: "/sdcard/lockknife.hprof".to_string(),
                kind: FieldKind::Text,
                options: vec![],
            },
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
        index: 0,
        target: PromptTarget::Export,
    };

    let rendered = prompt_hint_lines(&state, Rect::new(0, 0, 72, 18))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("case-managed path"));
    assert!(rendered.contains("Remote output stays on-device"));
    assert!(rendered.contains("Enter next/submit"));
}

#[test]
fn prompt_intro_lines_include_description_and_help() {
    let state = PromptState {
        title: "Generate report".to_string(),
        description: Some("Render a case report from structured artifacts.".to_string()),
        help_lines: vec![
            "Leave Output blank to auto-derive a report path.".to_string(),
            "Use Case directory to register the report in the manifest.".to_string(),
        ],
        fields: vec![PromptField {
            key: "case_id".to_string(),
            label: "Case ID".to_string(),
            value: "CASE-001".to_string(),
            kind: FieldKind::Text,
            options: vec![],
        }],
        index: 0,
        target: PromptTarget::Export,
    };

    let rendered = prompt_intro_lines(&state)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Render a case report"));
    assert!(rendered.contains("auto-derive a report path"));
    assert!(rendered.contains("register the report in the manifest"));
}
