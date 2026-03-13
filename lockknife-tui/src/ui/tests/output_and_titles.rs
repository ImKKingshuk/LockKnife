use super::*;

#[test]
fn output_empty_lines_explain_next_step_without_logs() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let app = App::new(callback);

    let rendered = output_empty_lines(&app)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("No output yet."));
    assert!(rendered.contains("Run an action"));
    assert!(rendered.contains("press v"));
    assert!(rendered.contains("Use Tab to switch panels"));
    assert!(rendered.contains(
        "Tip: no active case yet · use n to init one or set Case directory on supported prompts."
    ));
}

#[test]
fn output_empty_lines_surface_active_case_guidance_after_result() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-314".to_string());
    app.last_result_json = Some("{}".to_string());

    let rendered = output_empty_lines(&app)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("No output logs are available for the latest result."));
    assert!(rendered.contains(
        "Active case: ./cases/CASE-314 · key paths in Result view show where artifacts landed."
    ));
    assert!(rendered.contains("Result view follow-up actions stay scoped to the active case."));
}

#[test]
fn output_empty_lines_surface_active_target_guidance() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.devices.push(DeviceItem {
        serial: "SERIAL-42".to_string(),
        adb_state: "device".to_string(),
        state: "authorized".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    });

    let rendered = output_empty_lines(&app)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Active target: SERIAL-42"));
}

#[test]
fn prompt_controls_hint_compacts_for_small_prompts() {
    let state = PromptState {
        title: "Search Output".to_string(),
        description: None,
        help_lines: vec![],
        fields: vec![PromptField {
            key: "query".to_string(),
            label: "Query".to_string(),
            value: "hook".to_string(),
            kind: FieldKind::Text,
            options: vec![],
        }],
        index: 0,
        target: PromptTarget::Export,
    };

    assert_eq!(
        prompt_controls_hint(&state, Rect::new(0, 0, 40, 10)),
        "Keys: ↑/↓ field · Enter next · Esc close"
    );
}

#[test]
fn result_view_controls_hint_includes_followup_shortcuts_on_roomy_layouts() {
    assert_eq!(
        result_view_controls_hint(Rect::new(0, 0, 72, 20)).as_deref(),
        Some(
            "Keys: ↑/↓ scroll · PgUp/PgDn jump · Home/End ends · [] sections · s/f/a/l/r/x/w/j/u/k follow-up · y copy"
        )
    );
    assert_eq!(
        result_view_controls_hint(Rect::new(0, 0, 60, 12)).as_deref(),
        Some("Keys: ↑/↓ scroll · PgUp/PgDn jump · s/f/a/l/r/x/w/j/u/k follow-up · y copy")
    );
    assert_eq!(
        result_view_controls_hint(Rect::new(0, 0, 40, 10)).as_deref(),
        Some("Keys: ↑/↓ scroll · y copy · Esc close")
    );
}

#[test]
fn case_detail_lines_surface_history_and_quick_actions() {
    init_python();
    let callback = Python::with_gil(|py| py.None().into_py(py));
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-222".to_string());
    app.last_result_json = Some(
        serde_json::json!({
            "case_dir": "./cases/CASE-222",
            "artifact_count": 4,
            "total_artifact_count": 9,
            "jobs": {
                "total": 3,
                "running": 1,
                "succeeded": 1,
                "partial": 0,
                "failed": 1,
                "resumable": 1
            },
            "recent_jobs": [
                {"job_id": "job-0003", "action_label": "Runtime Hook", "status": "failed"}
            ],
            "artifacts_by_category": [{"label": "timeline", "count": 2}],
            "artifacts_by_device_serial": [{"label": "emulator-5554", "count": 4}],
            "artifact": {
                "artifact_id": "artifact-0009",
                "path": "./cases/CASE-222/derived/timeline.json"
            }
        })
        .to_string(),
    );
    app.investigation_history
        .push(crate::app::InvestigationEntry {
            timestamp: "12:00:00".to_string(),
            action_id: "case.summary".to_string(),
            action_label: "Case summary".to_string(),
            case_dir: "./cases/CASE-222".to_string(),
            outcome: crate::app::InvestigationOutcome::Partial,
            summary: "1 missing parent id".to_string(),
        });

    let rendered = case_detail_lines(&app, 56)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Active workspace: ./cases/CASE-222"));
    assert!(rendered.contains("Inventory: 4 visible · 9 total · 1 categories · 1 devices"));
    assert!(rendered.contains("Latest artifact: artifact-0009"));
    assert!(rendered.contains("History: 0 ok · 1 partial · 0 failed"));
    assert!(
        rendered.contains("Jobs: 3 total · 1 running · 1 ok · 0 partial · 1 failed · 1 resumable")
    );
    assert!(rendered.contains(
        "Quick actions: Enter summary · j jobs · f artifact inventory · g graph · x export bundle · w report · u resume · k retry"
    ));
}

#[test]
fn result_view_title_includes_scroll_position() {
    let state = ResultViewState {
        title: "Result · 2 key paths".to_string(),
        content: "Summary\nok\n\nKey paths\n- Output: ./out.json\n\nJSON\n{}".to_string(),
        scroll: 3,
        line_count: 8,
        section_starts: vec![0, 3, 6],
    };

    assert_eq!(result_view_title(&state), "Result · 2 key paths · line 4/8");
}
