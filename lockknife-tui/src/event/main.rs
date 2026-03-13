use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
use ratatui::layout::Rect;

use crate::app::{
    ActionMenuState, App, FieldKind, Overlay, Panel, PromptField, PromptState, PromptTarget,
    SearchTarget,
};

use super::helpers::{
    clamp_module_scroll, ensure_module_visible, handle_mouse_click, module_rows,
    move_module_selection,
};

pub(super) fn handle_main(app: &mut App, event: Event) -> bool {
    match event {
        Event::Key(KeyEvent {
            code, modifiers, ..
        }) => {
            match (code, modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Char('Q'), _) => return true,
                (KeyCode::Tab, _) => app.select_next_panel(),
                (KeyCode::Char('?'), _) => app.overlay = Overlay::Help,
                (KeyCode::Char('t'), _) | (KeyCode::Char('T'), _) => app.cycle_theme(),
                (KeyCode::Char('c'), _) | (KeyCode::Char('C'), _) => app.open_config(),
                (KeyCode::Char('d'), _) | (KeyCode::Char('D'), _) => {
                    if !app.open_diagnostics_menu() {
                        app.push_toast("error", "Diagnostics shortcuts are unavailable right now");
                    }
                }
                (KeyCode::Char('o'), _) | (KeyCode::Char('O'), _) => {
                    match app.build_main_case_prompt("case.summary") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("error", message),
                    }
                }
                (KeyCode::Char('p'), _) | (KeyCode::Char('P'), _) => {
                    match app.build_recent_case_prompt() {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('a'), _) | (KeyCode::Char('A'), _) => {
                    match app.build_recent_artifact_filter_prompt() {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('n'), _) | (KeyCode::Char('N'), _) => {
                    match app.build_main_case_prompt("case.init") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("error", message),
                    }
                }
                (KeyCode::Char('f'), _) | (KeyCode::Char('F'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.artifacts") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('g'), _) | (KeyCode::Char('G'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.graph") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('x'), _) | (KeyCode::Char('X'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.export") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('w'), _) | (KeyCode::Char('W'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("report.generate") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('h'), _) | (KeyCode::Char('H'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("report.chain_of_custody") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('i'), _) | (KeyCode::Char('I'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("report.integrity") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('j'), _) | (KeyCode::Char('J'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.jobs") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('u'), _) | (KeyCode::Char('U'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.resume_job") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('k'), _) | (KeyCode::Char('K'), _)
                    if matches!(app.active_panel, Panel::Case) =>
                {
                    match app.build_case_dashboard_prompt("case.retry_job") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    }
                }
                (KeyCode::Char('r'), _) | (KeyCode::Char('R'), _) => app.refresh_devices(),
                (KeyCode::Char('v'), _) | (KeyCode::Char('V'), _) => {
                    app.start_result_view();
                }
                (KeyCode::Up, KeyModifiers::CONTROL) => app.adjust_top_height(-1),
                (KeyCode::Down, KeyModifiers::CONTROL) => app.adjust_top_height(1),
                (KeyCode::Char('/'), _) => {
                    let target = if matches!(app.active_panel, Panel::Output) {
                        SearchTarget::Output
                    } else {
                        SearchTarget::Modules
                    };
                    let prompt = build_search_prompt(app, target);
                    app.start_prompt(prompt);
                }
                (KeyCode::Char('e'), _) | (KeyCode::Char('E'), _) => {
                    let prompt = PromptState {
                    title: "Export".to_string(),
                    description: Some("Export the last JSON result into a new output format.".to_string()),
                    help_lines: vec!["Run an action first, then export the result when you need another format.".to_string()],
                    fields: vec![
                        PromptField {
                            key: "format".to_string(),
                            label: "Format".to_string(),
                            value: "json".to_string(),
                            kind: FieldKind::Choice,
                            options: vec![
                                "json".to_string(),
                                "csv".to_string(),
                                "html".to_string(),
                            ],
                        },
                        PromptField {
                            key: "output".to_string(),
                            label: "Output path".to_string(),
                            value: "export.json".to_string(),
                            kind: FieldKind::Text,
                            options: vec![],
                        },
                    ],
                    index: 0,
                    target: PromptTarget::Export,
                };
                    app.start_prompt(prompt);
                }
                (KeyCode::PageUp, _) => {
                    if matches!(app.active_panel, Panel::Modules) {
                        let rows = module_rows(app);
                        app.module_scroll = app.module_scroll.saturating_sub(rows * 2);
                        clamp_module_scroll(app);
                    }
                }
                (KeyCode::PageDown, _) => {
                    if matches!(app.active_panel, Panel::Modules) {
                        let rows = module_rows(app);
                        app.module_scroll = app.module_scroll.saturating_add(rows * 2);
                        clamp_module_scroll(app);
                    }
                }
                (KeyCode::Enter, _) => match app.active_panel {
                    Panel::Modules => {
                        app.overlay = Overlay::ActionMenu(ActionMenuState {
                            module_index: app.selected_module,
                            action_index: 0,
                        });
                    }
                    Panel::Case => match app.build_case_dashboard_prompt("case.summary") {
                        Ok(prompt) => app.start_prompt(prompt),
                        Err(message) => app.push_toast("info", message),
                    },
                    _ => {}
                },
                (KeyCode::Up, _) => match app.active_panel {
                    Panel::Devices => {
                        if app.selected_device > 0 {
                            app.selected_device -= 1;
                        }
                    }
                    Panel::Modules => {
                        move_module_selection(app, -1, 0);
                    }
                    Panel::Case => {}
                    Panel::Output => {
                        app.output_scroll = app.output_scroll.saturating_sub(1);
                    }
                },
                (KeyCode::Down, _) => match app.active_panel {
                    Panel::Devices => {
                        if app.selected_device + 1 < app.devices.len() {
                            app.selected_device += 1;
                        }
                    }
                    Panel::Modules => {
                        move_module_selection(app, 1, 0);
                    }
                    Panel::Case => {}
                    Panel::Output => {
                        app.output_scroll = app.output_scroll.saturating_add(1);
                    }
                },
                (KeyCode::Left, _) => {
                    if matches!(app.active_panel, Panel::Modules) {
                        move_module_selection(app, 0, -1);
                    }
                }
                (KeyCode::Right, _) => {
                    if matches!(app.active_panel, Panel::Modules) {
                        move_module_selection(app, 0, 1);
                    }
                }
                (KeyCode::Char(ch), _) if ch.is_ascii_digit() => {
                    let idx = ch.to_digit(10).unwrap_or(0) as usize;
                    if idx > 0 && idx - 1 < app.modules.len() {
                        app.selected_module = idx - 1;
                        app.active_panel = Panel::Modules;
                        ensure_module_visible(app, app.visible_modules().len());
                    }
                }
                _ => {}
            }
        }
        Event::Resize(width, height) => {
            app.update_layout(Rect {
                x: 0,
                y: 0,
                width,
                height,
            });
            clamp_module_scroll(app);
            ensure_module_visible(app, app.visible_modules().len());
        }
        Event::Mouse(mouse) => {
            if let MouseEventKind::Down(_) = mouse.kind {
                let x = mouse.column;
                let y = mouse.row;
                handle_mouse_click(app, x, y);
            }
        }
        _ => {}
    }
    false
}

pub(super) fn build_search_prompt(app: &App, target: SearchTarget) -> PromptState {
    let current_query = app
        .search
        .as_ref()
        .filter(|state| {
            matches!(
                (&state.target, &target),
                (SearchTarget::Modules, SearchTarget::Modules)
                    | (SearchTarget::Output, SearchTarget::Output)
            )
        })
        .map(|state| state.query.clone())
        .unwrap_or_default();

    let description = match target {
        SearchTarget::Modules => "Filter module names with a case-insensitive query.".to_string(),
        SearchTarget::Output => "Filter output logs with a case-insensitive query.".to_string(),
    };

    let help_lines = match target {
        SearchTarget::Modules => vec![
            "Current target: Modules panel.".to_string(),
            "Submit an empty query to clear the current module filter.".to_string(),
        ],
        SearchTarget::Output => vec![
            "Current target: Output panel.".to_string(),
            "Submit an empty query to clear the current output filter.".to_string(),
        ],
    };

    PromptState {
        title: format!("Search {}", target.title_label()),
        description: Some(description),
        help_lines,
        fields: vec![PromptField {
            key: "query".to_string(),
            label: "Query".to_string(),
            value: current_query,
            kind: FieldKind::Text,
            options: vec![],
        }],
        index: 0,
        target: PromptTarget::Search { target },
    }
}
