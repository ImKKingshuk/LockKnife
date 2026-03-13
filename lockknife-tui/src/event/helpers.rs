use serde_json::{Map, Value};

use crate::app::{App, FieldKind, Panel, PromptField};

pub(super) fn handle_mouse_click(app: &mut App, x: u16, y: u16) {
    let devices = app.layout.devices;
    let modules = app.layout.modules;
    let case_panel = app.layout.case;
    let output = app.layout.output;

    if in_rect(x, y, devices) {
        app.active_panel = Panel::Devices;
        let rel = y.saturating_sub(devices.y + 1) as usize;
        if rel < app.devices.len() {
            app.selected_device = rel;
        }
        return;
    }
    if in_rect(x, y, modules) {
        app.active_panel = Panel::Modules;
        let inner_x = x.saturating_sub(modules.x + 1);
        let inner_y = y.saturating_sub(modules.y + 1);
        let col = if inner_x > modules.width / 2 { 1 } else { 0 };
        let row = inner_y as usize;
        let idx = app.module_scroll + row * 2 + col as usize;
        if idx < app.modules.len() {
            app.selected_module = idx;
        }
        return;
    }
    if in_rect(x, y, case_panel) {
        app.active_panel = Panel::Case;
        return;
    }
    if in_rect(x, y, output) {
        app.active_panel = Panel::Output;
    }
}

fn in_rect(x: u16, y: u16, rect: ratatui::layout::Rect) -> bool {
    x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height
}

pub(super) fn move_module_selection(app: &mut App, delta_row: i32, delta_col: i32) {
    let visible = app.visible_modules();
    if visible.is_empty() {
        return;
    }
    let pos = visible
        .iter()
        .position(|v| *v == app.selected_module)
        .unwrap_or(0);
    let row = (pos / 2) as i32;
    let col = (pos % 2) as i32;
    let mut new_row = row + delta_row;
    let mut new_col = col + delta_col;
    if new_row < 0 {
        new_row = 0;
    }
    if new_col < 0 {
        new_col = 0;
    }
    let idx = (new_row * 2 + new_col) as usize;
    if idx < visible.len() {
        app.selected_module = visible[idx];
    }
    ensure_module_visible(app, visible.len());
}

pub(super) fn handle_choice(field: &mut PromptField, delta: i32) {
    if !matches!(field.kind, FieldKind::Choice) {
        return;
    }
    if field.options.is_empty() {
        return;
    }
    let pos = field
        .options
        .iter()
        .position(|v| v == &field.value)
        .unwrap_or(0);
    let mut new_pos = pos as i32 + delta;
    if new_pos < 0 {
        new_pos = (field.options.len() as i32) - 1;
    }
    if new_pos >= field.options.len() as i32 {
        new_pos = 0;
    }
    field.value = field.options[new_pos as usize].clone();
}

pub(super) fn fields_to_params(fields: &[PromptField]) -> Value {
    let mut map = Map::new();
    for f in fields {
        let val = match f.kind {
            FieldKind::Number => {
                if let Ok(i) = f.value.trim().parse::<i64>() {
                    Value::Number(i.into())
                } else if let Ok(fv) = f.value.trim().parse::<f64>() {
                    Value::Number(serde_json::Number::from_f64(fv).unwrap_or_else(|| 0.into()))
                } else {
                    Value::String(f.value.clone())
                }
            }
            FieldKind::Bool => Value::Bool(f.value.to_lowercase() == "true"),
            _ => Value::String(f.value.clone()),
        };
        map.insert(f.key.clone(), val);
    }
    Value::Object(map)
}

pub(super) fn module_rows(app: &App) -> usize {
    app.layout.modules.height.saturating_sub(2).max(1) as usize
}

pub(super) fn clamp_module_scroll(app: &mut App) {
    let rows = module_rows(app);
    let visible_len = app.visible_modules().len();
    let max_scroll = visible_len.saturating_sub(rows * 2);
    if app.module_scroll > max_scroll {
        app.module_scroll = max_scroll;
    }
}

pub(super) fn ensure_module_visible(app: &mut App, visible_len: usize) {
    if visible_len == 0 {
        return;
    }
    let pos = app
        .visible_modules()
        .iter()
        .position(|v| *v == app.selected_module)
        .unwrap_or(0);
    let row = pos / 2;
    let rows = module_rows(app);
    let start_row = app.module_scroll / 2;
    if row < start_row {
        app.module_scroll = row.saturating_mul(2);
    } else if row >= start_row + rows {
        app.module_scroll = (row + 1 - rows).saturating_mul(2);
    }
    let max_scroll = visible_len.saturating_sub(rows * 2);
    if app.module_scroll > max_scroll {
        app.module_scroll = max_scroll;
    }
}

pub(super) fn complete_path(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let expanded = if trimmed.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            trimmed.replacen('~', &home, 1)
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };
    let (dir, prefix) = if expanded.ends_with(std::path::MAIN_SEPARATOR) {
        (expanded.clone(), "".to_string())
    } else {
        let path = std::path::Path::new(&expanded);
        let parent = path.parent().unwrap_or(std::path::Path::new(""));
        let pref = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        (parent.to_string_lossy().to_string(), pref)
    };
    let read_dir = std::fs::read_dir(if dir.is_empty() { "." } else { &dir }).ok()?;
    let mut matches = Vec::new();
    for entry in read_dir.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(&prefix) {
                let mut candidate = if dir.is_empty() || dir == "." {
                    name.to_string()
                } else {
                    format!("{}{}{}", dir, std::path::MAIN_SEPARATOR, name)
                };
                if entry.path().is_dir() {
                    candidate.push(std::path::MAIN_SEPARATOR);
                }
                matches.push(candidate);
            }
        }
    }
    matches.sort();
    matches.into_iter().next()
}
