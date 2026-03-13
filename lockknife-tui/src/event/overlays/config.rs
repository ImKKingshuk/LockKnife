use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Map, Value};

use crate::app::{App, ConfirmState, Overlay, PromptTarget};

const CONFIG_SCROLL_STEP: u16 = 8;

pub(in crate::event) fn handle_help(_app: &mut App, event: Event) -> (bool, Overlay) {
    if let Event::Key(key) = event {
        if matches!(
            key.code,
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
        ) {
            return (false, Overlay::None);
        }
    }
    (false, Overlay::Help)
}

pub(in crate::event) fn handle_config(app: &mut App, event: Event) -> (bool, Overlay) {
    if let Event::Key(KeyEvent {
        code, modifiers, ..
    }) = event
    {
        match (code, modifiers) {
            (KeyCode::Esc, _) => {
                if app.config_is_dirty() {
                    return (false, Overlay::Confirm(discard_config_confirm()));
                }
                return (false, Overlay::None);
            }
            (KeyCode::Char('s'), KeyModifiers::CONTROL)
            | (KeyCode::Char('S'), KeyModifiers::CONTROL) => app.save_config(),
            (KeyCode::Char('r'), KeyModifiers::CONTROL)
            | (KeyCode::Char('R'), KeyModifiers::CONTROL) => {
                if app.config_is_dirty() {
                    return (false, Overlay::Confirm(revert_config_confirm()));
                }
                app.push_toast("info", "Config already matches the last saved state");
            }
            (KeyCode::Up, _) => app.config_move_cursor_up(),
            (KeyCode::Down, _) => app.config_move_cursor_down(),
            (KeyCode::PageUp, _) => {
                app.config_scroll = app.config_scroll.saturating_sub(CONFIG_SCROLL_STEP)
            }
            (KeyCode::PageDown, _) => {
                app.config_scroll = app.config_scroll.saturating_add(CONFIG_SCROLL_STEP)
            }
            (KeyCode::Home, _) => app.config_move_cursor_home(),
            (KeyCode::End, _) => app.config_move_cursor_end(),
            (KeyCode::Left, _) => app.config_move_cursor_left(),
            (KeyCode::Right, _) => app.config_move_cursor_right(),
            (KeyCode::Backspace, _) => app.config_backspace(),
            (KeyCode::Enter, _) => app.config_insert_newline(),
            (KeyCode::Char(ch), _) => app.config_insert_char(ch),
            _ => {}
        }
    }
    (false, Overlay::Config)
}

fn discard_config_confirm() -> ConfirmState {
    ConfirmState {
        title: "Discard unsaved config changes?".to_string(),
        target: PromptTarget::DiscardConfig,
        params: Value::Object(Map::new()),
        resume_config_on_cancel: true,
        resume_config_on_submit: false,
    }
}

fn revert_config_confirm() -> ConfirmState {
    ConfirmState {
        title: "Revert config to last saved state?".to_string(),
        target: PromptTarget::RevertConfig,
        params: Value::Object(Map::new()),
        resume_config_on_cancel: true,
        resume_config_on_submit: true,
    }
}
