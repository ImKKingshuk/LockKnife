use serde_json::Value;

use crate::bridge;

use super::*;

impl App {
    pub fn open_config(&mut self) {
        let params = Value::Object(serde_json::Map::new());
        let result = bridge::call(&self.callback, "config.load", &params);
        if result.ok {
            if let Some(data) = result.data_json.clone() {
                if let Ok(value) = serde_json::from_str::<Value>(&data) {
                    if let Some(text) = value.get("text").and_then(|v| v.as_str()) {
                        self.config_text = text.to_string();
                        self.config_saved_text = self.config_text.clone();
                        self.config_cursor = 0;
                        self.config_scroll = 0;
                        self.config_goal_column = None;
                    }
                    if let Some(path) = value.get("path").and_then(|v| v.as_str()) {
                        self.config_path = Some(path.to_string());
                    }
                }
            }
            let message = result
                .message
                .clone()
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| config_open_feedback(self.config_path.as_deref()));
            self.push_feedback("info", message);
        } else {
            self.push_feedback("error", result.error_message());
        }
        self.overlay = Overlay::Config;
    }

    pub fn save_config(&mut self) {
        let mut map = serde_json::Map::new();
        map.insert("text".to_string(), Value::String(self.config_text.clone()));
        if let Some(path) = &self.config_path {
            map.insert("path".to_string(), Value::String(path.clone()));
        }
        let params = Value::Object(map);
        let result = bridge::call(&self.callback, "config.save", &params);
        self.apply_result("config.save", result);
    }

    pub fn discard_config_changes(&mut self) {
        self.config_text = self.config_saved_text.clone();
        self.config_cursor = 0;
        self.config_scroll = 0;
        self.config_goal_column = None;
    }

    pub fn config_is_dirty(&self) -> bool {
        self.config_text != self.config_saved_text
    }

    pub fn set_config_viewport_height(&mut self, height: u16) {
        self.config_viewport_height = height;
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_left(&mut self) {
        self.config_cursor = prev_char_boundary(&self.config_text, self.config_cursor);
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_right(&mut self) {
        self.config_cursor = next_char_boundary(&self.config_text, self.config_cursor);
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_up(&mut self) {
        let safe_cursor = clamp_char_boundary(&self.config_text, self.config_cursor);
        let current_column = self
            .config_goal_column
            .unwrap_or_else(|| current_line_column(&self.config_text, safe_cursor));
        if let Some((line_start, line_end)) = previous_line_bounds(&self.config_text, safe_cursor) {
            self.config_cursor =
                line_column_to_index(&self.config_text, line_start, line_end, current_column);
        } else {
            self.config_cursor = 0;
        }
        self.config_goal_column = Some(current_column);
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_down(&mut self) {
        let safe_cursor = clamp_char_boundary(&self.config_text, self.config_cursor);
        let current_column = self
            .config_goal_column
            .unwrap_or_else(|| current_line_column(&self.config_text, safe_cursor));
        if let Some((line_start, line_end)) = next_line_bounds(&self.config_text, safe_cursor) {
            self.config_cursor =
                line_column_to_index(&self.config_text, line_start, line_end, current_column);
        } else {
            self.config_cursor = self.config_text.len();
        }
        self.config_goal_column = Some(current_column);
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_home(&mut self) {
        let (line_start, _) = current_line_bounds(&self.config_text, self.config_cursor);
        self.config_cursor = line_start;
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_move_cursor_end(&mut self) {
        let (_, line_end) = current_line_bounds(&self.config_text, self.config_cursor);
        self.config_cursor = line_end;
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_backspace(&mut self) {
        let safe_cursor = clamp_char_boundary(&self.config_text, self.config_cursor);
        if safe_cursor == 0 {
            self.config_cursor = 0;
            return;
        }

        let previous = prev_char_boundary(&self.config_text, safe_cursor);
        self.config_text.drain(previous..safe_cursor);
        self.config_cursor = previous;
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    pub fn config_insert_newline(&mut self) {
        self.config_insert_char('\n');
    }

    pub fn config_insert_char(&mut self, ch: char) {
        let idx = clamp_char_boundary(&self.config_text, self.config_cursor);
        self.config_text.insert(idx, ch);
        self.config_cursor = idx + ch.len_utf8();
        self.config_capture_goal_column();
        self.config_sync_scroll_to_cursor();
    }

    fn config_capture_goal_column(&mut self) {
        self.config_goal_column = Some(current_line_column(&self.config_text, self.config_cursor));
    }

    fn config_sync_scroll_to_cursor(&mut self) {
        if self.config_viewport_height == 0 {
            return;
        }

        let cursor_line =
            current_line_number(&self.config_text, self.config_cursor).saturating_sub(1);
        let viewport_height = self.config_viewport_height as usize;
        let scroll = self.config_scroll as usize;

        if cursor_line < scroll {
            self.config_scroll = cursor_line as u16;
        } else if cursor_line >= scroll + viewport_height {
            self.config_scroll =
                cursor_line.saturating_sub(viewport_height.saturating_sub(1)) as u16;
        }
    }
}

fn clamp_char_boundary(text: &str, cursor: usize) -> usize {
    let mut safe = cursor.min(text.len());
    while safe > 0 && !text.is_char_boundary(safe) {
        safe -= 1;
    }
    safe
}

fn prev_char_boundary(text: &str, cursor: usize) -> usize {
    let safe = clamp_char_boundary(text, cursor);
    if safe == 0 {
        0
    } else {
        let mut previous = safe.saturating_sub(1);
        while previous > 0 && !text.is_char_boundary(previous) {
            previous -= 1;
        }
        previous
    }
}

fn next_char_boundary(text: &str, cursor: usize) -> usize {
    let safe = clamp_char_boundary(text, cursor);
    if safe >= text.len() {
        text.len()
    } else {
        let mut next = safe.saturating_add(1);
        while next < text.len() && !text.is_char_boundary(next) {
            next += 1;
        }
        next.min(text.len())
    }
}

fn current_line_bounds(text: &str, cursor: usize) -> (usize, usize) {
    let safe = clamp_char_boundary(text, cursor);
    let line_start = text[..safe].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let line_end = text[safe..]
        .find('\n')
        .map(|idx| safe + idx)
        .unwrap_or(text.len());
    (line_start, line_end)
}

fn previous_line_bounds(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let (line_start, _) = current_line_bounds(text, cursor);
    if line_start == 0 {
        return None;
    }

    let previous_line_end = line_start.saturating_sub(1);
    let previous_line_start = text[..previous_line_end]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    Some((previous_line_start, previous_line_end))
}

fn next_line_bounds(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let (_, line_end) = current_line_bounds(text, cursor);
    if line_end >= text.len() {
        return None;
    }

    let next_line_start = line_end + 1;
    let next_line_end = text[next_line_start..]
        .find('\n')
        .map(|idx| next_line_start + idx)
        .unwrap_or(text.len());
    Some((next_line_start, next_line_end))
}

fn current_line_number(text: &str, cursor: usize) -> usize {
    let safe = clamp_char_boundary(text, cursor);
    text[..safe].bytes().filter(|byte| *byte == b'\n').count() + 1
}

fn current_line_column(text: &str, cursor: usize) -> usize {
    let safe = clamp_char_boundary(text, cursor);
    let (line_start, _) = current_line_bounds(text, safe);
    text[line_start..safe].chars().count()
}

fn line_column_to_index(text: &str, line_start: usize, line_end: usize, column: usize) -> usize {
    text[line_start..line_end]
        .char_indices()
        .nth(column)
        .map(|(idx, _)| line_start + idx)
        .unwrap_or(line_end)
}
