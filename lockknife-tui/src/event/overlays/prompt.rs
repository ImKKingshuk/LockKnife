use crossterm::event::{Event, KeyCode, KeyEvent};
use serde_json::Value;

use crate::app::{App, ConfirmState, FieldKind, Overlay, PromptState, PromptTarget};

use super::super::helpers::{complete_path, fields_to_params, handle_choice};

pub(in crate::event) fn handle_prompt(
    app: &mut App,
    event: Event,
    mut state: PromptState,
) -> (bool, Overlay) {
    if let Event::Key(KeyEvent {
        code, modifiers, ..
    }) = event
    {
        match (code, modifiers) {
            (KeyCode::Esc, _) => return (false, Overlay::None),
            (KeyCode::Up, _) => {
                if state.index > 0 {
                    state.index -= 1;
                }
            }
            (KeyCode::Down, _) => {
                if state.index + 1 < state.fields.len() {
                    state.index += 1;
                }
            }
            (KeyCode::Enter, _) => {
                if state.index + 1 < state.fields.len() {
                    state.index += 1;
                } else {
                    let params = fields_to_params(&state.fields);
                    let target = state.target.clone();
                    submit_prompt(app, target, params);
                    return (false, Overlay::None);
                }
            }
            (KeyCode::Left, _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    handle_choice(field, -1);
                }
            }
            (KeyCode::Right, _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    handle_choice(field, 1);
                }
            }
            (KeyCode::Backspace, _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    if matches!(field.kind, FieldKind::Text | FieldKind::Number)
                        && !field.value.is_empty()
                    {
                        field.value.pop();
                    }
                }
            }
            (KeyCode::Tab, _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    if matches!(field.kind, FieldKind::Text) {
                        if let Some(next) = complete_path(&field.value) {
                            field.value = next;
                        }
                    }
                }
            }
            (KeyCode::Char(' '), _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    if matches!(field.kind, FieldKind::Bool) {
                        field.value = if field.value.to_lowercase() == "true" {
                            "false"
                        } else {
                            "true"
                        }
                        .to_string();
                    }
                }
            }
            (KeyCode::Char(ch), _) => {
                if let Some(field) = state.fields.get_mut(state.index) {
                    if matches!(field.kind, FieldKind::Text | FieldKind::Number) {
                        field.value.push(ch);
                    }
                }
            }
            _ => {}
        }
    }
    (false, Overlay::Prompt(state))
}

pub(in crate::event) fn submit_prompt(app: &mut App, target: PromptTarget, params: Value) {
    match target {
        PromptTarget::Action {
            module_index,
            action_index,
        } => submit_action_prompt(app, module_index, action_index, params),
        PromptTarget::Search { target } => {
            let query = params
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            app.apply_search_query(target, query);
        }
        PromptTarget::Export => export_last_result(app, params),
        PromptTarget::ConfigSave => app.save_config(),
        PromptTarget::DiscardConfig => {
            app.discard_config_changes();
            app.push_toast("info", "Discarded unsaved config changes");
        }
        PromptTarget::RevertConfig => {
            app.discard_config_changes();
            app.push_toast("info", "Reverted config to last saved state");
        }
    }
}

fn submit_action_prompt(app: &mut App, module_index: usize, action_index: usize, params: Value) {
    if let Some(action) = app
        .modules
        .get(module_index)
        .and_then(|m| m.actions.get(action_index))
    {
        if action.confirm {
            app.start_confirm(ConfirmState {
                title: format!("Confirm {}?", action.label),
                target: PromptTarget::Action {
                    module_index,
                    action_index,
                },
                params,
                resume_config_on_cancel: false,
                resume_config_on_submit: false,
            });
        } else {
            app.execute_action(module_index, action_index, params);
        }
    }
}

fn export_last_result(app: &mut App, params: Value) {
    if let Some(data_json) = app.last_result_json.clone() {
        let mut map = params.as_object().cloned().unwrap_or_default();
        map.insert("data_json".to_string(), Value::String(data_json));
        app.execute_custom("export.result", Value::Object(map));
    } else {
        app.push_log("error", "No result available to export");
        app.push_toast("error", "No result available to export");
    }
}
