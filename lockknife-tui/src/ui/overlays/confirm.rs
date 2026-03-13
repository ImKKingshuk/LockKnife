use ratatui::layout::Alignment;
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use serde_json::Value;

use crate::app::{App, ConfirmState, ModuleAction, PromptTarget};

use super::common::{action_needs_preflight, action_preflight_summary, dialog_title};
use crate::ui::adaptive_centered_rect;
use crate::ui::ThemeStyles;

pub(in crate::ui) fn render_confirm(
    frame: &mut Frame,
    app: &App,
    state: &ConfirmState,
    styles: &ThemeStyles,
) {
    let area = adaptive_centered_rect(50, 30, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(dialog_title("Confirm", area.width.saturating_sub(2), None))
        .style(styles.border);
    let lines = confirm_lines(app, state, area);
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .alignment(if area.width < 38 {
            Alignment::Left
        } else {
            Alignment::Center
        });
    frame.render_widget(paragraph, area);
}

pub(in crate::ui) fn confirm_lines(
    app: &App,
    state: &ConfirmState,
    area: Rect,
) -> Vec<Line<'static>> {
    let title = state.title.clone();
    let context = confirm_context_lines(app, state);

    if area.width < 38 || area.height < 8 {
        let mut lines = vec![Line::from(title)];
        if area.height >= 7 {
            if let Some(line) = context.first() {
                lines.push(Line::from(line.clone()));
            }
        }
        lines.push(Line::from("y confirm · n/Esc cancel"));
        return lines;
    }

    let mut lines = vec![Line::from(title), Line::from("")];
    for line in context {
        lines.push(Line::from(line));
    }
    if area.height >= 10 {
        lines.push(Line::from(""));
    }
    lines.push(Line::from("Press y to confirm, n or Esc to cancel."));
    lines
}

fn confirm_context_lines(app: &App, state: &ConfirmState) -> Vec<String> {
    let Some(action) = confirm_action(app, &state.target) else {
        return Vec::new();
    };

    let mut lines = Vec::new();
    if let Some(preflight) = action_preflight_summary(action) {
        lines.push(preflight);
    }

    let uses_explicit_device_field = action.fields.iter().any(|field| {
        matches!(
            field.key.as_str(),
            "device_id" | "device_serial" | "device_serials" | "target_serials"
        )
    });

    if action.targets_device() {
        let device_target = confirm_param_string(&state.params, "device_id")
            .or_else(|| confirm_param_string(&state.params, "device_serial"))
            .or_else(|| confirm_param_string(&state.params, "target_serials"))
            .or_else(|| confirm_param_string(&state.params, "device_serials"))
            .or_else(|| app.selected_device_serial());
        lines.push(match device_target {
            Some(serial) if action.requires_device && !uses_explicit_device_field => {
                format!("Device: {}", serial)
            }
            Some(serial) => format!("Device target: {}", serial),
            None if action.id.starts_with("runtime.") => {
                "Device target: none yet · choose one in Devices or enter Device ID before confirming."
                    .to_string()
            }
            None if action.requires_device => "Device: no selected target yet".to_string(),
            None => "Device target: none yet".to_string(),
        });
    }

    if action.is_case_aware() {
        let case_dir = confirm_param_string(&state.params, "case_dir")
            .or_else(|| app.active_case_dir().map(str::to_string));
        if let Some(case_dir) = case_dir {
            let routing = match app.active_case_dir() {
                Some(active_case) if active_case != case_dir => {
                    format!("Case routing: {} (overrides active case)", case_dir)
                }
                _ => format!("Case routing: {}", case_dir),
            };
            lines.push(routing);
        } else {
            lines.push("Case routing: none yet".to_string());
        }

        if action.has_output_field() {
            if let Some(output) = confirm_param_string(&state.params, "output")
                .or_else(|| confirm_param_string(&state.params, "result_output"))
            {
                lines.push(format!("Destination: {}", output));
            } else if confirm_param_string(&state.params, "case_dir").is_some()
                || app.active_case_dir().is_some()
            {
                lines.push(
                    "Destination: auto-derived managed path under the case workspace".to_string(),
                );
            }
        }
    }

    if let Some(recovery_hint) = action
        .recovery_hint()
        .filter(|_| action_needs_preflight(action))
    {
        lines.push(recovery_hint.to_string());
    }
    lines
}

fn confirm_action<'a>(app: &'a App, target: &PromptTarget) -> Option<&'a ModuleAction> {
    match target {
        PromptTarget::Action {
            module_index,
            action_index,
        } => app
            .modules
            .get(*module_index)
            .and_then(|module| module.actions.get(*action_index)),
        _ => None,
    }
}

fn confirm_param_string(params: &Value, key: &str) -> Option<String> {
    params
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
