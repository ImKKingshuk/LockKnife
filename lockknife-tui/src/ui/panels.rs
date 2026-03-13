use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::app::{App, Panel};

use super::{
    active_case_status, active_module_search_query, active_output_search_query,
    active_panel_status, active_search_status, active_target_status, case_detail_lines,
    case_panel_title, device_empty_hint, module_detail_lines, module_empty_detail_lines,
    output_empty_lines, panel_title, progress_label_for_width, running_status_label, status_badge,
    status_spans, ThemeStyles,
};

pub(super) fn render_devices(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let mut rows = Vec::new();
    for (i, d) in app.devices.iter().enumerate() {
        let bullet = if i == app.selected_device {
            "●"
        } else {
            "○"
        };
        let label = format!(
            "{} {} {} {}",
            bullet,
            d.model.clone().unwrap_or_else(|| "Device".to_string()),
            d.serial,
            d.state
        );
        rows.push(
            Row::new(vec![Cell::from(label)]).style(if i == app.selected_device {
                styles.highlight
            } else {
                styles.text
            }),
        );
    }
    if rows.is_empty() {
        rows.push(Row::new(vec![Cell::from("No devices detected yet")]).style(styles.text));
        if let Some(hint) = device_empty_hint(
            app.layout.devices.width.saturating_sub(2),
            app.layout.devices.height.saturating_sub(2),
        ) {
            rows.push(Row::new(vec![Cell::from(hint)]).style(styles.text));
        }
    }
    let title = app
        .selected_device_serial()
        .map(|serial| format!("Devices · target {}", serial))
        .unwrap_or_else(|| "Devices".to_string());
    let table = Table::new(rows, [Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title(title).style(
            if matches!(app.active_panel, Panel::Devices) {
                styles.border
            } else {
                styles.text
            },
        ))
        .column_spacing(1);
    frame.render_widget(table, app.layout.devices);
}

pub(super) fn render_modules(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let title = panel_title(
        "Modules",
        active_module_search_query(app),
        app.layout.modules.width.saturating_sub(2),
    );
    let block = Block::default().borders(Borders::ALL).title(title).style(
        if matches!(app.active_panel, Panel::Modules) {
            styles.border
        } else {
            styles.text
        },
    );
    let inner = block.inner(app.layout.modules);
    frame.render_widget(block, app.layout.modules);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let detail_height = if inner.height >= 9 {
        4
    } else if inner.height >= 7 {
        3
    } else {
        0
    };
    let (table_area, detail_area) = if detail_height > 0 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(detail_height)])
            .split(inner);
        (chunks[0], Some(chunks[1]))
    } else {
        (inner, None)
    };

    let visible = app.visible_modules();
    let rows_visible = table_area.height.max(1) as usize;
    let start = app.module_scroll.min(visible.len());
    let window = visible
        .into_iter()
        .skip(start)
        .take(rows_visible * 2)
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    let mut idx = 0;
    for _ in 0..rows_visible {
        let left = window.get(idx).copied();
        let right = window.get(idx + 1).copied();
        idx += 2;
        let mut cells = Vec::new();
        if let Some(i) = left {
            let badge = app.modules[i]
                .capability_metadata()
                .map(|metadata| format!(" [{}]", status_badge(metadata.status)))
                .unwrap_or_default();
            let label = format!("[{}] {}{}", i + 1, app.modules[i].label, badge);
            let style = if i == app.selected_module {
                styles.highlight
            } else {
                styles.text
            };
            cells.push(Cell::from(label).style(style));
        } else {
            cells.push(Cell::from(""));
        }
        if let Some(i) = right {
            let badge = app.modules[i]
                .capability_metadata()
                .map(|metadata| format!(" [{}]", status_badge(metadata.status)))
                .unwrap_or_default();
            let label = format!("[{}] {}{}", i + 1, app.modules[i].label, badge);
            let style = if i == app.selected_module {
                styles.highlight
            } else {
                styles.text
            };
            cells.push(Cell::from(label).style(style));
        } else {
            cells.push(Cell::from(""));
        }
        rows.push(Row::new(cells));
    }
    if rows.is_empty() {
        let label = if active_module_search_query(app).is_some() {
            "No modules match the current search"
        } else {
            "No modules available"
        };
        rows.push(Row::new(vec![Cell::from(label)]));
    }
    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .column_spacing(2);
    frame.render_widget(table, table_area);

    let detail_lines = if window.is_empty() {
        module_empty_detail_lines(app)
    } else {
        let module_index = if window.contains(&app.selected_module) {
            Some(app.selected_module)
        } else {
            window.first().copied()
        };
        module_index
            .and_then(|index| app.modules.get(index))
            .map(|module| module_detail_lines(app, module))
            .unwrap_or_else(|| module_empty_detail_lines(app))
    };

    if let Some(area) = detail_area {
        let paragraph = Paragraph::new(Text::from(detail_lines)).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}

pub(super) fn render_output(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let title = panel_title(
        "Output",
        active_output_search_query(app),
        app.layout.output.width.saturating_sub(2),
    );
    let visible = app.visible_logs();
    let mut lines = Vec::new();
    for i in visible {
        if let Some(l) = app.logs.get(i) {
            let line = Line::from(vec![
                Span::styled(format!("[{}] ", l.timestamp), styles.text),
                Span::styled(l.message.clone(), styles.text),
            ]);
            lines.push(line);
        }
    }
    if lines.is_empty() {
        lines.extend(output_empty_lines(app));
    }
    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(title).style(
            if matches!(app.active_panel, Panel::Output) {
                styles.border
            } else {
                styles.text
            },
        ))
        .scroll((app.output_scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, app.layout.output);
}

pub(super) fn render_case(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let title = case_panel_title(app, app.layout.case.width.saturating_sub(2));
    let lines = case_detail_lines(app, app.layout.case.width.saturating_sub(2));
    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(title).style(
            if matches!(app.active_panel, Panel::Case) {
                styles.border
            } else {
                styles.text
            },
        ))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, app.layout.case);
}

pub(super) fn render_status(frame: &mut Frame, app: &mut App, styles: &ThemeStyles) {
    let status_width = app.layout.status.width.saturating_sub(2);
    let compact_layout = app.is_compact_main_layout();
    let mut spans = status_spans(styles, status_width, compact_layout);
    if let Some(panel_hint) = active_panel_status(app, status_width, compact_layout) {
        spans.push(Span::styled(format!("  {}", panel_hint), styles.status));
    }
    if let Some(case_hint) = active_case_status(app, status_width, compact_layout) {
        spans.push(Span::styled(format!("  {}", case_hint), styles.status));
    }
    if let Some(target_hint) = active_target_status(app, status_width, compact_layout) {
        spans.push(Span::styled(format!("  {}", target_hint), styles.status));
    }
    if app.busy {
        let spinner = ["|", "/", "-", "\\"];
        let spin = spinner[app.spinner_index % spinner.len()];
        spans.push(Span::styled(
            format!("  {}", running_status_label(status_width, spin)),
            styles.status,
        ));
    }
    if let Some(search_summary) = active_search_status(app, status_width) {
        spans.push(Span::styled(format!("  {}", search_summary), styles.status));
    }
    let para = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL).style(styles.border))
        .alignment(Alignment::Left);
    frame.render_widget(para, app.layout.status);
    if app.busy {
        let gauge_area = Rect {
            x: app.layout.status.x + 1,
            y: app.layout.status.y,
            width: app.layout.status.width.saturating_sub(2),
            height: 1,
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::NONE))
            .gauge_style(styles.highlight)
            .ratio(app.progress as f64 / 100.0)
            .label(progress_label_for_width(
                &app.progress_label,
                status_width.saturating_sub(10),
            ));
        frame.render_widget(gauge, gauge_area);
    }
}
