use super::*;

#[test]
fn submit_prompt_search_reports_apply_and_clear() {
    let callback = none_callback();
    let mut app = App::new(callback);

    submit_prompt(
        &mut app,
        PromptTarget::Search {
            target: SearchTarget::Output,
        },
        serde_json::json!({"query": "hook payload"}),
    );

    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Filtering output by \"hook payload\""));

    submit_prompt(
        &mut app,
        PromptTarget::Search {
            target: SearchTarget::Output,
        },
        serde_json::json!({"query": "   "}),
    );

    assert!(app.search.is_none());
    assert!(app
        .logs
        .iter()
        .any(|entry| entry.message == "Cleared output filter"));
}

#[test]
fn submit_prompt_export_without_result_shows_toast() {
    let callback = none_callback();
    let mut app = App::new(callback);

    submit_prompt(
        &mut app,
        PromptTarget::Export,
        serde_json::json!({"format": "json", "output": "export.json"}),
    );

    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "No result available to export"));
}
