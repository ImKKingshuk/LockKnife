use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, ResultViewState};

use super::common::dialog_title;
use crate::ui::adaptive_centered_rect;
use crate::ui::ThemeStyles;

pub(in crate::ui) fn result_view_controls_hint(area: Rect) -> Option<String> {
    if area.height < 8 {
        None
    } else if area.width < 52 {
        Some("Keys: ↑/↓ scroll · y copy · Esc close".to_string())
    } else if area.width < 72 {
        Some(
            "Keys: ↑/↓ scroll · PgUp/PgDn jump · s/f/a/l/r/x/w/j/u/k follow-up · y copy"
                .to_string(),
        )
    } else {
        Some(
            "Keys: ↑/↓ scroll · PgUp/PgDn jump · Home/End ends · [] sections · s/f/a/l/r/x/w/j/u/k follow-up · y copy"
                .to_string(),
        )
    }
}

pub(in crate::ui) fn result_view_title(state: &ResultViewState) -> String {
    let line_count = state.line_count.max(1);
    let current_line = state.scroll.saturating_add(1).min(line_count);
    format!("{} · line {}/{}", state.title, current_line, line_count)
}

pub(in crate::ui) fn render_result_view(
    frame: &mut Frame,
    _app: &App,
    state: &ResultViewState,
    styles: &ThemeStyles,
) {
    let area = adaptive_centered_rect(80, 80, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(dialog_title(
            &result_view_title(state),
            area.width.saturating_sub(2),
            Some("Esc"),
        ))
        .style(styles.border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let (hint_area, content_area) =
        if result_view_controls_hint(area).is_some() && inner.height >= 3 {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(1)])
                .split(inner);
            (Some(chunks[0]), chunks[1])
        } else {
            (None, inner)
        };

    if let Some(hint_area) = hint_area {
        let hint = Paragraph::new(Text::from(Line::from(
            result_view_controls_hint(area).unwrap_or_default(),
        )))
        .wrap(Wrap { trim: true });
        frame.render_widget(hint, hint_area);
    }

    let text = Text::from(state.content.clone());
    let paragraph = Paragraph::new(text)
        .scroll((state.scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, content_area);
}

fn toast_width(area: Rect) -> u16 {
    if area.width < 30 {
        area.width.saturating_sub(2)
    } else if area.width < 52 {
        area.width.saturating_sub(4)
    } else {
        42u16.min(area.width.saturating_sub(2))
    }
}

fn toast_height(width: u16, area_height: u16) -> u16 {
    if area_height < 10 || width < 26 {
        4
    } else {
        3
    }
}

pub(in crate::ui) fn render_toasts(frame: &mut Frame, app: &App, styles: &ThemeStyles) {
    if app.toasts.is_empty() {
        return;
    }
    let area = frame.area();
    let width = toast_width(area);
    let start_x = area.x + area.width.saturating_sub(width + 1);
    let mut y = area.y + 1;
    for toast in app.toasts.iter().rev() {
        let height = toast_height(width, area.height);
        let rect = Rect {
            x: start_x,
            y,
            width,
            height,
        };
        let style = if toast.level == "error" {
            styles.highlight
        } else {
            styles.text
        };
        frame.render_widget(Clear, rect);
        let block = Block::default().borders(Borders::ALL).style(styles.border);
        let paragraph = Paragraph::new(Text::from(Line::from(Span::styled(
            toast.message.clone(),
            style,
        ))))
        .block(block)
        .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, rect);
        y = y.saturating_add(height);
        if y + height > area.height {
            break;
        }
    }
}
