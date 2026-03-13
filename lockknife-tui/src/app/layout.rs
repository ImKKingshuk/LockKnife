use ratatui::layout::{Constraint, Direction, Layout, Rect};

use super::*;

impl App {
    pub fn update_layout(&mut self, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);

        let header_area = layout[0];
        let body_area = layout[1];
        let status_area = layout[2];
        let (top_height, minimum_output_height) =
            main_body_height_budget(self.top_height, body_area.height);

        let body_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(top_height),
                Constraint::Min(minimum_output_height),
            ])
            .split(body_area);
        let top_row = body_chunks[0];
        let output_area = body_chunks[1];
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(42),
                Constraint::Percentage(30),
            ])
            .split(top_row);
        let devices_area = top[0];
        let modules_area = top[1];
        let case_area = top[2];

        self.layout = UiLayout {
            header: header_area,
            devices: devices_area,
            modules: modules_area,
            case: case_area,
            output: output_area,
            status: status_area,
        };
    }

    pub fn is_compact_main_layout(&self) -> bool {
        self.layout.case.height < 6 || self.layout.output.height < 6
    }

    pub fn visible_modules(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let query = self.search.as_ref().and_then(|s| {
            if matches!(s.target, SearchTarget::Modules) && !s.query.is_empty() {
                Some(s.query.to_lowercase())
            } else {
                None
            }
        });
        for (i, m) in self.modules.iter().enumerate() {
            if let Some(q) = &query {
                if m.label.to_lowercase().contains(q) {
                    out.push(i);
                }
            } else {
                out.push(i);
            }
        }
        out
    }

    pub fn visible_logs(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let query = self.search.as_ref().and_then(|s| {
            if matches!(s.target, SearchTarget::Output) && !s.query.is_empty() {
                Some(s.query.to_lowercase())
            } else {
                None
            }
        });
        for (i, l) in self.logs.iter().enumerate() {
            if let Some(q) = &query {
                if l.message.to_lowercase().contains(q) {
                    out.push(i);
                }
            } else {
                out.push(i);
            }
        }
        out
    }

    pub fn select_next_panel(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::Devices => Panel::Modules,
            Panel::Modules => Panel::Case,
            Panel::Case => Panel::Output,
            Panel::Output => Panel::Devices,
        };
    }

    pub fn adjust_top_height(&mut self, delta: i16) {
        let next = if delta.is_negative() {
            self.top_height.saturating_sub(delta.unsigned_abs())
        } else {
            self.top_height.saturating_add(delta as u16)
        };
        self.top_height = next.clamp(6, 20);
        save_tui_config(&self.current_tui_config());
    }
}

pub(crate) fn main_body_height_budget(preferred_top_height: u16, body_height: u16) -> (u16, u16) {
    if body_height == 0 {
        return (0, 0);
    }

    let minimum_output_height = match body_height {
        0 => 0,
        1..=3 => 1,
        4..=6 => 2,
        7..=9 => 3,
        10..=11 => 4,
        _ => 5,
    };
    let top_height = preferred_top_height.min(body_height.saturating_sub(minimum_output_height));

    (top_height, minimum_output_height)
}
