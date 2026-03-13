use crossterm::event::{Event, KeyCode, KeyEvent};

use crate::app::{App, Overlay, ResultViewState};

pub(in crate::event) fn handle_result_view(
    app: &mut App,
    event: Event,
    mut state: ResultViewState,
) -> (bool, Overlay) {
    if let Event::Key(KeyEvent { code, .. }) = event {
        match code {
            KeyCode::Esc => return (false, Overlay::None),
            KeyCode::Home => state.scroll = 0,
            KeyCode::End => state.scroll = state.line_count.saturating_sub(1),
            KeyCode::Up => state.scroll = state.scroll.saturating_sub(1),
            KeyCode::Down => state.scroll = state.scroll.saturating_add(1),
            KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(10),
            KeyCode::PageDown => state.scroll = state.scroll.saturating_add(10),
            KeyCode::Char('[') => {
                if let Some(previous) = state
                    .section_starts
                    .iter()
                    .copied()
                    .rfind(|line| *line < state.scroll)
                {
                    state.scroll = previous;
                }
            }
            KeyCode::Char(']') => {
                if let Some(next) = state
                    .section_starts
                    .iter()
                    .copied()
                    .find(|line| *line > state.scroll)
                {
                    state.scroll = next;
                }
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => copy_result(app),
            KeyCode::Char(ch) => {
                if let Some(next_overlay) = result_followup_overlay(app, ch) {
                    return (false, next_overlay);
                }
            }
            _ => {}
        }
        state.scroll = state.scroll.min(state.line_count.saturating_sub(1));
    }
    (false, Overlay::ResultView(state))
}

fn copy_result(app: &mut App) {
    if app.copy_last_result() {
        app.push_toast("info", "Copied result to clipboard");
    } else {
        app.push_toast("error", "Clipboard copy failed");
    }
}

fn result_followup_overlay(app: &mut App, ch: char) -> Option<Overlay> {
    let action_id = match ch.to_ascii_lowercase() {
        's' => Some("case.summary"),
        'f' => Some("case.artifacts"),
        'a' => Some("case.artifact"),
        'l' => Some("case.lineage"),
        'r' => Some("case.register"),
        'x' => Some("case.export"),
        'n' => Some("case.enrich"),
        'w' => Some("report.generate"),
        'g' => Some("report.integrity"),
        'v' => Some("report.chain_of_custody"),
        'j' => Some("case.jobs"),
        'm' => Some("runtime.sessions"),
        'i' => Some("runtime.session"),
        'h' => Some("runtime.session_reload"),
        'c' => Some("runtime.session_reconnect"),
        'o' => Some("runtime.session_stop"),
        'p' => Some("runtime.preflight"),
        'b' => Some("runtime.bypass_ssl"),
        't' => Some("runtime.trace"),
        'e' => Some("intelligence.cve"),
        'd' => Some("security.attack_surface"),
        'z' => Some("security.owasp"),
        'u' => Some("case.resume_job"),
        'k' => Some("case.retry_job"),
        _ => None,
    }?;
    match app.build_result_followup_prompt(action_id) {
        Ok(prompt) => Some(Overlay::Prompt(prompt)),
        Err(message) => {
            app.push_toast("info", message);
            None
        }
    }
}
