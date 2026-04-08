use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, PromptState};

use super::common::{dialog_title, summarize_plain_text};
use crate::ui::adaptive_centered_rect;
use crate::ui::ThemeStyles;

pub(in crate::ui) fn render_help(frame: &mut Frame, app: &App, styles: &ThemeStyles) {
    let area = adaptive_centered_rect(70, 70, frame.area());
    let lines = help_lines(area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(dialog_title(
            "Help",
            area.width.saturating_sub(2),
            Some("Esc"),
        ))
        .style(styles.border);
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
    let _ = app;
}

pub(in crate::ui) fn render_config(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let area = adaptive_centered_rect(80, 80, frame.area());
    frame.render_widget(Clear, area);
    let title = config_title(app, area.width.saturating_sub(2));
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(styles.border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let hint_height = if inner.height >= 7 {
        2
    } else if inner.height >= 4 {
        1
    } else {
        0
    };
    let (hint_area, editor_area) = if hint_height > 0 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(hint_height), Constraint::Min(1)])
            .split(inner);
        (Some(chunks[0]), chunks[1])
    } else {
        (None, inner)
    };

    if let Some(hint_area) = hint_area {
        let hint =
            Paragraph::new(Text::from(config_hint_lines(app, hint_area))).wrap(Wrap { trim: true });
        frame.render_widget(hint, hint_area);
    }

    app.set_config_viewport_height(editor_area.height);

    let text = Text::from(app.config_text.clone());
    let para = Paragraph::new(text)
        .scroll((app.config_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, editor_area);
    if let Some((cursor_x, cursor_y)) = config_cursor_position(app, editor_area) {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

pub(in crate::ui) fn render_prompt(
    frame: &mut Frame,
    _app: &App,
    state: &PromptState,
    styles: &ThemeStyles,
) {
    let area = adaptive_centered_rect(70, 60, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(dialog_title(
            &state.title,
            area.width.saturating_sub(2),
            Some("Esc"),
        ))
        .style(styles.border);
    let mut lines = prompt_intro_lines(state);
    for (i, f) in state.fields.iter().enumerate() {
        let marker = if i == state.index { "›" } else { " " };
        let val = if matches!(f.kind, crate::app::FieldKind::Bool) {
            if f.value.to_lowercase() == "true" {
                "true"
            } else {
                "false"
            }
        } else {
            f.value.as_str()
        };
        lines.push(Line::from(format!("{} {}: {}", marker, f.label, val)));
    }
    if state.fields.is_empty() {
        lines.push(Line::from("No parameters — press Enter to continue."));
    }
    lines.extend(prompt_hint_lines(state, area));
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

pub(in crate::ui) fn prompt_intro_lines(state: &PromptState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(description) = &state.description {
        let trimmed = description.trim();
        if !trimmed.is_empty() {
            lines.push(Line::from(trimmed.to_string()));
        }
    }
    for help in &state.help_lines {
        let trimmed = help.trim();
        if !trimmed.is_empty() {
            lines.push(Line::from(format!("• {}", trimmed)));
        }
    }
    if !lines.is_empty() && !state.fields.is_empty() {
        lines.push(Line::from(""));
    }
    lines
}

pub(in crate::ui) fn prompt_hint_lines(state: &PromptState, area: Rect) -> Vec<Line<'static>> {
    let has_case_dir = state.fields.iter().any(|f| f.key == "case_dir");
    let mut lines = Vec::new();
    if has_case_dir {
        let has_output = state
            .fields
            .iter()
            .any(|f| f.key == "output" || f.key == "result_output");
        let has_session_output = state.fields.iter().any(|f| {
            f.label
                .to_ascii_lowercase()
                .contains("session summary output")
        });
        let has_result_output = state.fields.iter().any(|f| f.key == "result_output");

        lines.push(Line::from(""));
        if has_output {
            lines.push(Line::from(
                "Tip: leave output blank to auto-derive a case-managed path.",
            ));
        } else {
            lines.push(Line::from(
                "Tip: set Case directory to register supported outputs in the case manifest.",
            ));
        }
        if has_session_output {
            lines.push(Line::from(
                "Managed runtime sessions also save script snapshots, JSONL event logs, and session summary JSON in the case.",
            ));
        }
        if has_result_output {
            lines.push(Line::from(
                "Remote output stays on-device; result output stores the local summary JSON.",
            ));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(prompt_controls_hint(state, area)));
    lines
}

pub(in crate::ui) fn config_hint_lines(app: &App, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(config_controls_hint(area))];
    if area.height >= 2 {
        let (line, column) = config_cursor_line_col(&app.config_text, app.config_cursor);
        let dirty = if app.config_is_dirty() {
            "Modified"
        } else {
            "Saved"
        };
        let status = if area.width < 46 {
            format!("{} · Ln {} · Col {}", dirty, line, column)
        } else {
            format!(
                "{} · Cursor: Ln {} · Col {} · Scroll {}",
                dirty, line, column, app.config_scroll
            )
        };
        lines.push(Line::from(status));
    }
    lines
}

pub(in crate::ui) fn config_controls_hint(area: Rect) -> String {
    if area.width < 42 {
        "Ctrl+S save · Esc close".to_string()
    } else if area.width < 68 {
        "Keys: Ctrl+S save · Ctrl+R revert · Esc close".to_string()
    } else {
        "Keys: Ctrl+S save · Ctrl+R revert · Esc close · ↑/↓ line · ←/→ move · Home/End line · PgUp/PgDn jump".to_string()
    }
}

pub(in crate::ui) fn config_cursor_line_col(text: &str, cursor: usize) -> (usize, usize) {
    let safe_cursor = cursor.min(text.len());
    let mut line = 1usize;
    let mut column = 1usize;
    for ch in text[..safe_cursor].chars() {
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

pub(in crate::ui) fn config_cursor_position(app: &App, editor_area: Rect) -> Option<(u16, u16)> {
    if editor_area.width == 0 || editor_area.height == 0 {
        return None;
    }

    let (line, column) = config_cursor_line_col(&app.config_text, app.config_cursor);
    let visible_row = line
        .saturating_sub(1)
        .saturating_sub(app.config_scroll as usize);
    if visible_row >= editor_area.height as usize {
        return None;
    }

    let visible_col = column.saturating_sub(1);
    if visible_col >= editor_area.width as usize {
        return None;
    }

    Some((
        editor_area.x + visible_col as u16,
        editor_area.y + visible_row as u16,
    ))
}

pub(in crate::ui) fn prompt_controls_hint(state: &PromptState, area: Rect) -> String {
    if state.fields.is_empty() {
        if area.width < 44 {
            "Enter continue · Esc close".to_string()
        } else {
            "Keys: Enter continue · Esc close".to_string()
        }
    } else if area.width < 52 || area.height < 12 {
        "Keys: ↑/↓ field · Enter next · Esc close".to_string()
    } else {
        "Keys: ↑/↓ field · Enter next/submit · ←/→ choice · Esc close".to_string()
    }
}

pub(in crate::ui) fn help_lines(area: Rect) -> Vec<Line<'static>> {
    if area.width < 56 || area.height < 16 {
        vec![
            Line::from("LockKnife TUI Help"),
            Line::from(""),
            Line::from("Nav: Tab panels · arrows move · Enter select"),
            Line::from("Tools: / search · d diag · o case · p recent · a art · n init · v view"),
            Line::from("Case: Enter summary · j jobs · f inventory · g graph · x export · w report · u/k job reruns"),
            Line::from("Session: r refresh · t theme · q quit · Esc close"),
            Line::from(""),
            Line::from("Case: set Case directory to route supported outputs into a case."),
            Line::from("Leave Output blank to auto-derive case-managed paths."),
        ]
    } else {
        vec![
            Line::from("LockKnife TUI Help"),
            Line::from(""),
            Line::from("Navigation"),
            Line::from("  Tab: cycle panels"),
            Line::from("  Arrow keys: move selection"),
            Line::from("  Enter: select module/action or open active case summary"),
            Line::from("  /: search modules or output"),
            Line::from("  ?: toggle help"),
            Line::from(""),
            Line::from("Actions"),
            Line::from("  d: open Diagnostics quickly (starts on Dependency doctor)"),
            Line::from("  o: open case summary quickly (edit Case directory to switch workspaces)"),
            Line::from("  p: reopen a recent case summary with ←/→ recall"),
            Line::from("  a: reopen recent artifact-search filters with ←/→ recall"),
            Line::from("  n: init a new case workspace quickly"),
            Line::from("  Case panel: j jobs · f artifact inventory · g graph · x export bundle · w report · h custody · i integrity · u resume job · k retry job"),
            Line::from("  c: open config editor"),
            Line::from("  e: export last result"),
            Line::from("  t: cycle theme"),
            Line::from("  r: refresh devices"),
            Line::from("  q: quit"),
            Line::from(""),
            Line::from("Exploitation"),
            Line::from("  e: enter exploitation panel (from Devices/Modules/Case/Output)"),
            Line::from("  Exploit panel: s scan · r run exploit · v view evidence · x stop"),
            Line::from("  Tab cycles through: Exploit → ExploitStatus → Evidence → ScanResults"),
            Line::from(""),
            Line::from("Case-aware prompts"),
            Line::from("  Set Case directory to route supported actions into a case workspace"),
            Line::from("  Leave Output blank to auto-derive evidence/derived/reports paths"),
            Line::from("  Runtime sessions can also save script snapshots, JSONL event logs, and summary JSON"),
            Line::from(""),
            Line::from("Diagnostics"),
            Line::from("  Open the Diagnostics module for Core health, Dependency doctor, and Feature matrix"),
            Line::from("  Use the CLI only for headless quick tasks or automation"),
        ]
    }
}

pub(in crate::ui) fn config_title(app: &App, width: u16) -> String {
    match &app.config_path {
        Some(_path) if width < 34 => "Config".to_string(),
        Some(path) if width < 56 => format!("Config ({})", summarize_plain_text(path, 20)),
        Some(path) => format!("Config ({})", path),
        None if width < 34 => "Config".to_string(),
        None => "Config (lockknife.toml)".to_string(),
    }
}
