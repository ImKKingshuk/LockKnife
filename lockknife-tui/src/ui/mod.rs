use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Overlay, Panel, Theme};

pub mod exploit;
mod overlays;
mod panels;
#[cfg(test)]
mod tests;

use self::exploit::{
    render_evidence_viewer_panel, render_exploit_panel, render_exploit_status_panel,
    render_scan_results_panel,
};
#[cfg(test)]
use self::overlays::{
    action_menu_detail_lines, config_controls_hint, config_cursor_line_col, config_cursor_position,
    config_hint_lines, config_title, confirm_lines, help_lines, prompt_controls_hint,
    prompt_hint_lines, prompt_intro_lines, result_view_controls_hint, result_view_title,
};
use self::overlays::{
    active_case_status, active_module_search_query, active_output_search_query,
    active_panel_status, active_search_status, active_target_status, case_detail_lines,
    case_panel_title, device_empty_hint, module_detail_lines, module_empty_detail_lines,
    output_empty_lines, panel_title, progress_label_for_width, render_action_menu, render_config,
    render_confirm, render_help, render_prompt, render_result_view, render_toasts,
    running_status_label, status_badge, status_spans,
};
use self::panels::{render_case, render_devices, render_modules, render_output, render_status};

#[derive(Clone)]
#[allow(dead_code)]
pub struct ThemeStyles {
    pub border: Style,
    pub highlight: Style,
    pub title: Style,
    pub text: Style,
    pub header: Style,
    pub status: Style,
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    app.update_layout(area);
    let header_area = app.layout.header;

    let styles = theme_styles(&app.theme);
    let header_line = if area.width < 24 {
        Line::from(vec![
            Span::styled("LK ", styles.title),
            Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), styles.text),
        ])
    } else {
        Line::from(vec![
            Span::styled("LockKnife ", styles.title),
            Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), styles.text),
        ])
    };

    let header = Paragraph::new(Text::from(header_line))
        .block(Block::default().borders(Borders::ALL).style(styles.border))
        .alignment(if area.width < 24 {
            Alignment::Left
        } else {
            Alignment::Center
        });
    frame.render_widget(header, header_area);

    render_devices(frame, app, &styles);
    render_modules(frame, app, &styles);
    render_case(frame, app, &styles);
    render_output(frame, app, &styles);
    render_status(frame, app, &styles);

    // Render exploitation panels if active
    if matches!(app.active_panel, Panel::Exploit) {
        render_exploit_panel(frame, app, &styles);
    }
    if matches!(app.active_panel, Panel::ExploitStatus) {
        render_exploit_status_panel(frame, app, &styles);
    }
    if matches!(app.active_panel, Panel::Evidence) {
        render_evidence_viewer_panel(frame, app, &styles);
    }
    if matches!(app.active_panel, Panel::ScanResults) {
        render_scan_results_panel(frame, app, &styles);
    }

    match &app.overlay {
        Overlay::Help => render_help(frame, app, &styles),
        Overlay::Config => render_config(frame, app, &styles),
        Overlay::Prompt(state) => render_prompt(frame, app, state, &styles),
        Overlay::Confirm(state) => render_confirm(frame, app, state, &styles),
        Overlay::ActionMenu(state) => render_action_menu(frame, app, state, &styles),
        Overlay::ResultView(state) => render_result_view(frame, app, state, &styles),
        Overlay::None => {}
    }
    render_toasts(frame, app, &styles);
}

fn theme_styles(theme: &Theme) -> ThemeStyles {
    match theme {
        Theme::Dark => ThemeStyles {
            border: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            highlight: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            title: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::White),
            header: Style::default().fg(Color::White),
            status: Style::default().fg(Color::White),
        },
        Theme::Light => ThemeStyles {
            border: Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
            highlight: Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::Black),
            header: Style::default().fg(Color::Black),
            status: Style::default().fg(Color::Black),
        },
        Theme::Hacker => ThemeStyles {
            border: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            highlight: Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::Green),
            header: Style::default().fg(Color::Green),
            status: Style::default().fg(Color::Green),
        },
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    let vertical = popup_layout[1];
    let popup_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);
    popup_layout[1]
}

fn adaptive_centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let adjusted_x = if r.width < 44 {
        percent_x.max(94)
    } else if r.width < 72 {
        percent_x.max(84)
    } else {
        percent_x
    }
    .min(98);

    let adjusted_y = if r.height < 14 {
        percent_y.max(94)
    } else if r.height < 22 {
        percent_y.max(84)
    } else {
        percent_y
    }
    .min(98);

    centered_rect(adjusted_x, adjusted_y, r)
}
