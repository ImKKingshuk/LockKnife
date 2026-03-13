use crossterm::event::{Event, KeyCode, KeyEvent};

use crate::app::{App, ConfirmState, Overlay};

use super::prompt::submit_prompt;

pub(in crate::event) fn handle_confirm(
    app: &mut App,
    event: Event,
    state: ConfirmState,
) -> (bool, Overlay) {
    if let Event::Key(KeyEvent { code, .. }) = event {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let target = state.target.clone();
                let params = state.params.clone();
                submit_prompt(app, target, params);
                return (
                    false,
                    if state.resume_config_on_submit {
                        Overlay::Config
                    } else {
                        Overlay::None
                    },
                );
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                return (
                    false,
                    if state.resume_config_on_cancel {
                        Overlay::Config
                    } else {
                        Overlay::None
                    },
                );
            }
            _ => {}
        }
    }
    (false, Overlay::Confirm(state))
}
