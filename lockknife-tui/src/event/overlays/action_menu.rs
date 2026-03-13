use crossterm::event::{Event, KeyCode, KeyEvent};
use serde_json::{Map, Value};

use crate::app::{ActionMenuState, App, ConfirmState, Overlay, PromptTarget};

pub(in crate::event) fn handle_action_menu(
    app: &mut App,
    event: Event,
    mut state: ActionMenuState,
) -> (bool, Overlay) {
    if let Event::Key(KeyEvent { code, .. }) = event {
        match code {
            KeyCode::Esc => return (false, Overlay::None),
            KeyCode::Up => {
                if state.action_index > 0 {
                    state.action_index -= 1;
                }
            }
            KeyCode::Down => {
                if let Some(module) = app.modules.get(state.module_index) {
                    if state.action_index + 1 < module.actions.len() {
                        state.action_index += 1;
                    }
                }
            }
            KeyCode::Enter => return open_or_run_action(app, state),
            _ => {}
        }
    }
    (false, Overlay::ActionMenu(state))
}

fn open_or_run_action(app: &mut App, state: ActionMenuState) -> (bool, Overlay) {
    if let Some(module) = app.modules.get(state.module_index) {
        if let Some(action) = module.actions.get(state.action_index) {
            if !action.fields.is_empty() {
                if let Some(prompt) =
                    app.build_action_prompt(state.module_index, state.action_index)
                {
                    return (false, Overlay::Prompt(prompt));
                }
            }
            if action.confirm {
                return (
                    false,
                    Overlay::Confirm(ConfirmState {
                        title: format!("Confirm {}?", action.label),
                        target: PromptTarget::Action {
                            module_index: state.module_index,
                            action_index: state.action_index,
                        },
                        params: Value::Object(Map::new()),
                        resume_config_on_cancel: false,
                        resume_config_on_submit: false,
                    }),
                );
            }
            app.execute_action(
                state.module_index,
                state.action_index,
                Value::Object(Map::new()),
            );
            return (false, Overlay::None);
        }
    }
    (false, Overlay::ActionMenu(state))
}
