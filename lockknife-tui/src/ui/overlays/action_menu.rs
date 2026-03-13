use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    action_next_step_hint, action_playbook_summary, module_playbook_summary,
    module_recommended_next_hint, ActionMenuState, App, ModuleAction, ModuleEntry,
};

use super::common::{action_preflight_summary, dialog_title, status_badge};
use crate::ui::adaptive_centered_rect;
use crate::ui::ThemeStyles;

pub(in crate::ui) fn render_action_menu(
    frame: &mut Frame,
    app: &App,
    state: &ActionMenuState,
    styles: &ThemeStyles,
) {
    let area = adaptive_centered_rect(60, 60, frame.area());
    frame.render_widget(Clear, area);
    let module = app.modules.get(state.module_index);
    let title = module
        .map(|m| m.label.clone())
        .unwrap_or_else(|| "Actions".to_string());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(dialog_title(
            &title,
            area.width.saturating_sub(2),
            Some("Esc"),
        ))
        .style(styles.border);
    let mut lines = Vec::new();
    if let Some(m) = module {
        for (i, action) in m.actions.iter().enumerate() {
            let marker = if i == state.action_index { "›" } else { " " };
            let status = action
                .capability_metadata()
                .map(|metadata| format!(" [{}]", status_badge(metadata.status)))
                .unwrap_or_default();
            lines.push(Line::from(format!("{} {}{}", marker, action.label, status)));
        }
        if let Some(action) = m.actions.get(state.action_index) {
            lines.extend(action_menu_detail_lines(app, action, area));
        }
    } else {
        lines.push(Line::from("No actions available for this module yet."));
    }
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

pub(in crate::ui) fn action_menu_detail_lines(
    app: &App,
    action: &ModuleAction,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    if let Some(description) = action.description() {
        lines.push(Line::from(description.to_string()));
    }

    let mut traits = Vec::new();
    if action.requires_device {
        traits.push("requires device".to_string());
    }
    if action.is_case_aware() {
        traits.push("case-aware".to_string());
    }
    if action.has_output_field() {
        traits.push("writes output".to_string());
    }
    if !traits.is_empty() {
        lines.push(Line::from(format!("Traits: {}", traits.join(" · "))));
    }

    if let Some(metadata) = action.capability_metadata() {
        lines.push(Line::from(format!(
            "Status: {} [{}] · Requires: {}",
            metadata.status,
            status_badge(metadata.status),
            metadata.requirements
        )));
        lines.push(Line::from(format!("Truth: {}", metadata.notes)));
    }
    if let Some(playbook) = action_playbook_summary(&action.id) {
        lines.push(Line::from(playbook));
    }

    if let Some(preflight) = action_preflight_summary(action) {
        lines.push(Line::from(preflight));
    }
    if let Some(readiness) = action_device_guidance(app, action) {
        lines.push(Line::from(readiness));
    }
    if let Some(case_context) = action_case_guidance(app, action) {
        lines.push(Line::from(case_context));
    }
    if let Some(recovery) = action.recovery_hint() {
        lines.push(Line::from(recovery));
    }
    if let Some(next_step) = action_next_step_hint(&action.id) {
        lines.push(Line::from(next_step));
    }

    let input_count = action.fields.len();
    let input_label = match input_count {
        0 => "no inputs".to_string(),
        1 => "1 input".to_string(),
        count => format!("{} inputs", count),
    };
    let flow_label = if action.fields.is_empty() {
        if action.confirm {
            "Enter opens confirm"
        } else {
            "Enter runs now"
        }
    } else {
        "Enter opens inputs"
    };
    lines.push(Line::from(format!(
        "Flow: {} · {}",
        input_label, flow_label
    )));

    for help in action.help_lines().into_iter().take(2) {
        lines.push(Line::from(format!("• {}", help)));
    }
    lines.push(Line::from(action_menu_controls_hint(area)));
    lines
}

pub(in crate::ui) fn module_detail_lines(app: &App, module: &ModuleEntry) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(description) = module.description() {
        lines.push(Line::from(description.to_string()));
    } else {
        lines.push(Line::from(format!("{} module", module.label)));
    }

    lines.push(Line::from(format!(
        "Actions: {} · device-backed: {} · case-aware: {} · outputs: {}",
        module.actions.len(),
        module.device_action_count(),
        module.case_aware_action_count(),
        module.output_action_count()
    )));

    if let Some(metadata) = module.capability_metadata() {
        lines.push(Line::from(format!(
            "Posture: {} [{}] · Requires: {}",
            metadata.status,
            status_badge(metadata.status),
            metadata.requirements
        )));
    }
    if let Some(playbooks) = module_playbook_summary(&module.id) {
        lines.push(Line::from(playbooks));
    }
    if let Some(readiness) = module_device_guidance(app, module) {
        lines.push(Line::from(readiness));
    }
    if let Some(case_context) = module_case_guidance(app, module) {
        lines.push(Line::from(case_context));
    }

    if let Some(metadata) = module.capability_metadata() {
        if let Some(recovery) = module.recovery_hint() {
            lines.push(Line::from(format!(
                "Truth: {} · {}",
                metadata.notes, recovery
            )));
        } else {
            lines.push(Line::from(format!("Truth: {}", metadata.notes)));
        }
    } else if let Some(recovery) = module.recovery_hint() {
        lines.push(Line::from(recovery));
    }
    if let Some(next_step) = module_recommended_next_hint(&module.id) {
        lines.push(Line::from(next_step));
    }

    if let Some(action) = module.actions.first() {
        lines.push(Line::from(format!(
            "First action: {} · Enter opens actions",
            action.label
        )));
    }

    if let Some(help) = module.help_lines().into_iter().next() {
        lines.push(Line::from(format!("• {}", help)));
    } else {
        lines.push(Line::from("Tip: Press 1-9 to jump modules or / to filter."));
    }

    lines
}

pub(in crate::ui) fn module_empty_detail_lines(app: &App) -> Vec<Line<'static>> {
    if let Some(query) = super::status::active_module_search_query(app) {
        vec![
            Line::from("No modules match the current search."),
            Line::from(format!("Search query: {}", query)),
            Line::from("Press / and submit an empty query to clear the module filter."),
        ]
    } else {
        vec![
            Line::from("No modules are available."),
            Line::from("Restart the TUI or review the current configuration if this persists."),
        ]
    }
}

fn action_device_guidance(app: &App, action: &ModuleAction) -> Option<String> {
    if !action.requires_device {
        return None;
    }

    Some(match app.selected_device_serial() {
        Some(serial) => format!("Ready: device-backed action will use {}.", serial),
        None => "Blocked: no device selected · Tab to Devices, press r, then choose a target."
            .to_string(),
    })
}

fn action_case_guidance(app: &App, action: &ModuleAction) -> Option<String> {
    if !action.is_case_aware() {
        return None;
    }

    match app.active_case_summary(52) {
        Some(case_summary) if action.has_output_field() => Some(format!(
            "Case: {} · leave Output blank to auto-route managed artifacts into this case.",
            case_summary
        )),
        Some(case_summary) => Some(format!(
            "Case: {} · this action can read or register artifacts in the active case.",
            case_summary
        )),
        None if action.has_output_field() => Some(
            "Case: no active case yet · set Case directory to route managed outputs into a case workspace."
                .to_string(),
        ),
        None => Some(
            "Case: no active case yet · set Case directory when you want this action tied to a case workspace."
                .to_string(),
        ),
    }
}

fn module_device_guidance(app: &App, module: &ModuleEntry) -> Option<String> {
    if module.device_action_count() == 0 {
        return None;
    }

    Some(match app.selected_device_serial() {
        Some(serial) => format!("Ready: device-backed actions will use {} when needed.", serial),
        None => {
            "Blocked: this module needs a selected device for some actions · Tab to Devices and press r."
                .to_string()
        }
    })
}

fn module_case_guidance(app: &App, module: &ModuleEntry) -> Option<String> {
    let case_aware_actions = module.case_aware_action_count();
    if case_aware_actions == 0 {
        return None;
    }

    let managed_output_actions = module.case_managed_output_count();
    match app.active_case_summary(52) {
        Some(case_summary) if managed_output_actions > 0 => Some(format!(
            "Case: {} · {} case-aware actions can reuse it, {} can auto-route managed outputs.",
            case_summary, case_aware_actions, managed_output_actions
        )),
        Some(case_summary) => Some(format!(
            "Case: {} · {} case-aware actions in this module can reuse that workspace.",
            case_summary, case_aware_actions
        )),
        None if managed_output_actions > 0 => Some(format!(
            "Case: no active case yet · press n to init one or set Case directory so {} managed-output workflows stay in one workspace.",
            managed_output_actions
        )),
        None => Some(format!(
            "Case: no active case yet · press n to init one or set Case directory for {} case-aware actions.",
            case_aware_actions
        )),
    }
}

fn action_menu_controls_hint(area: Rect) -> String {
    if area.width < 48 || area.height < 12 {
        "Keys: ↑/↓ select · Enter open · Esc close".to_string()
    } else {
        "Keys: ↑/↓ select · Enter open/run · Esc close".to_string()
    }
}
