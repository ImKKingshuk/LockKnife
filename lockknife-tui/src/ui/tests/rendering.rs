use super::*;

#[test]
fn renders_header_and_panels() {
    init_python();
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    assert!(text.contains("LockKnife"));
    assert!(text.contains("Devices"));
    assert!(text.contains("Modules"));
    assert!(text.contains("Case"));
    assert!(text.contains("Output"));
    assert!(text.contains("No active case yet"));
}

#[test]
fn renders_overlays() {
    init_python();
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    app.overlay = Overlay::Help;
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::Config;
    app.config_text = "test=true".to_string();
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::Prompt(PromptState {
        title: "Prompt".to_string(),
        description: Some("Prompt description".to_string()),
        help_lines: vec!["Prompt help".to_string()],
        fields: vec![PromptField {
            key: "path".to_string(),
            label: "Path".to_string(),
            value: "/tmp".to_string(),
            kind: FieldKind::Text,
            options: vec![],
        }],
        index: 0,
        target: PromptTarget::Export,
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::Confirm(ConfirmState {
        title: "Confirm".to_string(),
        target: PromptTarget::Export,
        params: serde_json::Value::Object(serde_json::Map::new()),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::ActionMenu(ActionMenuState {
        module_index: 0,
        action_index: 0,
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::ResultView(ResultViewState {
        title: "Result".to_string(),
        content: "{\"ok\":true}".to_string(),
        scroll: 0,
        line_count: 1,
        section_starts: vec![0],
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();
}

#[test]
fn renders_overlays_on_small_terminal() {
    init_python();
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);

    app.overlay = Overlay::Help;
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::Prompt(PromptState {
        title: "Search Output".to_string(),
        description: Some("Filter output logs with a case-insensitive query.".to_string()),
        help_lines: vec!["Submit an empty query to clear the current output filter.".to_string()],
        fields: vec![PromptField {
            key: "query".to_string(),
            label: "Query".to_string(),
            value: "hook".to_string(),
            kind: FieldKind::Text,
            options: vec![],
        }],
        index: 0,
        target: PromptTarget::Export,
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    app.overlay = Overlay::Confirm(ConfirmState {
        title: "Delete generated preview bundle?".to_string(),
        target: PromptTarget::Export,
        params: serde_json::Value::Object(serde_json::Map::new()),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    });
    terminal.draw(|f| draw(f, &mut app)).unwrap();
}
