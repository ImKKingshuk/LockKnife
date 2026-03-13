use std::path::PathBuf;
use std::time::Instant;

use pyo3::prelude::*;
use ratatui::layout::Rect;
use serde_json::Value;

use super::catalog::default_modules;
use super::*;

impl App {
    pub fn new(callback: Py<PyAny>) -> Self {
        Self::from_loaded_config(callback, load_tui_config())
    }

    pub(crate) fn from_loaded_config(callback: Py<PyAny>, cfg: Option<TuiConfig>) -> Self {
        let modules = default_modules();
        let layout = UiLayout {
            header: Rect::default(),
            devices: Rect::default(),
            modules: Rect::default(),
            case: Rect::default(),
            output: Rect::default(),
            status: Rect::default(),
        };
        let theme = cfg
            .as_ref()
            .and_then(|c| c.theme.parse().ok())
            .unwrap_or(Theme::Dark);
        let top_height = cfg.as_ref().map(|c| c.top_height).unwrap_or(9);
        let recent_case_dirs = cfg
            .as_ref()
            .map(|c| sanitize_recent_case_dirs(&c.recent_case_dirs))
            .unwrap_or_default();
        let prompt_defaults = cfg
            .as_ref()
            .map(|c| sanitize_prompt_defaults(&c.prompt_defaults))
            .unwrap_or_default();
        let artifact_filter_history = cfg
            .as_ref()
            .map(|c| sanitize_artifact_filter_history(&c.artifact_filter_history))
            .unwrap_or_default();
        Self {
            callback,
            devices: Vec::new(),
            modules,
            logs: Vec::new(),
            toasts: Vec::new(),
            selected_device: 0,
            selected_module: 0,
            selected_action: 0,
            module_scroll: 0,
            active_panel: Panel::Modules,
            overlay: Overlay::None,
            search: None,
            theme,
            layout,
            top_height,
            busy: false,
            progress: 0,
            progress_label: String::new(),
            spinner_index: 0,
            last_tick: Instant::now(),
            async_rx: None,
            cancel_tx: None,
            active_case_dir: None,
            recent_case_dirs,
            prompt_defaults,
            artifact_filter_history,
            pending_case_dir: None,
            last_result_json: None,
            last_job_json: None,
            last_result_message: None,
            last_result_paths: Vec::new(),
            investigation_history: Vec::new(),
            config_text: String::new(),
            config_saved_text: String::new(),
            config_path: None,
            config_scroll: 0,
            config_cursor: 0,
            config_viewport_height: 0,
            config_goal_column: None,
            output_scroll: 0,
        }
    }

    pub(crate) fn remember_case_dir(&mut self, case_dir: &str) {
        let trimmed = case_dir.trim();
        if trimmed.is_empty() {
            return;
        }

        let before = self.recent_case_dirs.clone();
        self.recent_case_dirs.retain(|existing| existing != trimmed);
        self.recent_case_dirs.insert(0, trimmed.to_string());
        self.recent_case_dirs.truncate(MAX_RECENT_CASES);
        if self.recent_case_dirs != before {
            save_tui_config(&self.current_tui_config());
        }
    }

    pub(crate) fn current_tui_config(&self) -> TuiConfig {
        TuiConfig {
            theme: self.theme.as_str().to_string(),
            top_height: self.top_height,
            recent_case_dirs: sanitize_recent_case_dirs(&self.recent_case_dirs),
            prompt_defaults: sanitize_prompt_defaults(&self.prompt_defaults),
            artifact_filter_history: sanitize_artifact_filter_history(
                &self.artifact_filter_history,
            ),
        }
    }

    pub(crate) fn apply_persisted_prompt_defaults(&self, fields: &mut [PromptField]) {
        prefill_prompt_field_if_matches(
            fields,
            "examiner",
            &self.prompt_defaults.examiner,
            &["Examiner"],
        );
        prefill_prompt_field_if_matches(
            fields,
            "title",
            &self.prompt_defaults.title,
            &["Investigation"],
        );
        prefill_prompt_field_if_empty(
            fields,
            "target_serials",
            &self.prompt_defaults.target_serials,
        );
        prefill_prompt_field_if_empty(fields, "categories", &self.prompt_defaults.categories);
        prefill_prompt_field_if_empty(
            fields,
            "exclude_categories",
            &self.prompt_defaults.exclude_categories,
        );
        prefill_prompt_field_if_empty(
            fields,
            "source_commands",
            &self.prompt_defaults.source_commands,
        );
        prefill_prompt_field_if_empty(
            fields,
            "device_serials",
            &self.prompt_defaults.device_serials,
        );
        prefill_prompt_field_if_matches(
            fields,
            "category",
            &self.prompt_defaults.category,
            &["derived"],
        );
        prefill_prompt_field_if_matches(
            fields,
            "source_command",
            &self.prompt_defaults.source_command,
            &["case register"],
        );
        prefill_prompt_field_if_empty(fields, "device_serial", &self.prompt_defaults.device_serial);
    }

    pub(crate) fn remember_prompt_defaults_from_params(&mut self, params: &Value) {
        let mut next = self.prompt_defaults.clone();
        remember_prompt_string(params, "examiner", &mut next.examiner, &["Examiner"]);
        remember_prompt_string(params, "title", &mut next.title, &["Investigation"]);
        remember_prompt_string(params, "target_serials", &mut next.target_serials, &[]);
        remember_prompt_string(params, "categories", &mut next.categories, &[]);
        remember_prompt_string(
            params,
            "exclude_categories",
            &mut next.exclude_categories,
            &[],
        );
        remember_prompt_string(params, "source_commands", &mut next.source_commands, &[]);
        remember_prompt_string(params, "device_serials", &mut next.device_serials, &[]);
        remember_prompt_string(params, "category", &mut next.category, &["derived"]);
        remember_prompt_string(
            params,
            "source_command",
            &mut next.source_command,
            &["case register"],
        );
        remember_prompt_string(params, "device_serial", &mut next.device_serial, &[]);

        let next = sanitize_prompt_defaults(&next);
        if next != self.prompt_defaults {
            self.prompt_defaults = next;
            save_tui_config(&self.current_tui_config());
        }
    }

    pub(crate) fn remember_artifact_filter_history_from_params(&mut self, params: &Value) {
        let mut next = self.artifact_filter_history.clone();
        remember_history_value(params, "query", &mut next.queries);
        remember_history_value(params, "path_contains", &mut next.path_contains);
        remember_history_value(params, "metadata_contains", &mut next.metadata_contains);
        remember_history_value(params, "categories", &mut next.categories);
        remember_history_value(params, "exclude_categories", &mut next.exclude_categories);
        remember_history_value(params, "source_commands", &mut next.source_commands);
        remember_history_value(params, "device_serials", &mut next.device_serials);
        remember_history_value(params, "limit", &mut next.limits);

        let next = sanitize_artifact_filter_history(&next);
        if next != self.artifact_filter_history {
            self.artifact_filter_history = next;
            save_tui_config(&self.current_tui_config());
        }
    }

    pub fn cycle_theme(&mut self) {
        self.theme = match self.theme {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Hacker,
            Theme::Hacker => Theme::Dark,
        };
        save_tui_config(&self.current_tui_config());
        self.push_feedback("info", format!("Theme: {}", self.theme.as_str()));
    }
}

pub(crate) fn config_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    let home = std::env::var("HOME").ok()?;
    let mut path = PathBuf::from(home);
    path.push(".config");
    path.push("lockknife");
    path.push("tui.toml");
    Some(path)
}

pub(crate) fn load_tui_config() -> Option<TuiConfig> {
    let path = config_path()?;
    load_tui_config_from_path(&path)
}

pub(crate) fn save_tui_config(cfg: &TuiConfig) {
    let Some(path) = config_path() else {
        return;
    };
    save_tui_config_to_path(cfg, &path);
}

pub(crate) fn load_tui_config_from_path(path: &std::path::Path) -> Option<TuiConfig> {
    let data = std::fs::read_to_string(path).ok()?;
    toml::from_str(&data).ok()
}

pub(crate) fn save_tui_config_to_path(cfg: &TuiConfig, path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(data) = toml::to_string(cfg) {
        let _ = std::fs::write(path, data);
    }
}

pub(crate) fn sanitize_recent_case_dirs(values: &[String]) -> Vec<String> {
    let mut recent_cases = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || recent_cases.iter().any(|existing| existing == trimmed) {
            continue;
        }
        recent_cases.push(trimmed.to_string());
        if recent_cases.len() == MAX_RECENT_CASES {
            break;
        }
    }
    recent_cases
}

pub(crate) fn sanitize_artifact_filter_history(
    history: &PersistedArtifactFilterHistory,
) -> PersistedArtifactFilterHistory {
    PersistedArtifactFilterHistory {
        queries: sanitize_history_values(&history.queries),
        path_contains: sanitize_history_values(&history.path_contains),
        metadata_contains: sanitize_history_values(&history.metadata_contains),
        categories: sanitize_history_values(&history.categories),
        exclude_categories: sanitize_history_values(&history.exclude_categories),
        source_commands: sanitize_history_values(&history.source_commands),
        device_serials: sanitize_history_values(&history.device_serials),
        limits: sanitize_history_values(&history.limits),
    }
}

pub(crate) fn sanitize_history_values(values: &[String]) -> Vec<String> {
    let mut history = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || history.iter().any(|existing| existing == trimmed) {
            continue;
        }
        history.push(trimmed.to_string());
        if history.len() == MAX_RECENT_FILTER_VALUES {
            break;
        }
    }
    history
}

pub(crate) fn artifact_filter_history_is_empty(history: &PersistedArtifactFilterHistory) -> bool {
    history.queries.is_empty()
        && history.path_contains.is_empty()
        && history.metadata_contains.is_empty()
        && history.categories.is_empty()
        && history.exclude_categories.is_empty()
        && history.source_commands.is_empty()
        && history.device_serials.is_empty()
        && history.limits.is_empty()
}

pub(crate) fn history_choice_options(current_value: &str, history: &[String]) -> Vec<String> {
    let sanitized_history = sanitize_history_values(history);
    if sanitized_history.is_empty() {
        return Vec::new();
    }

    let mut options = Vec::new();
    let trimmed_current = current_value.trim();
    if !trimmed_current.is_empty() {
        options.push(trimmed_current.to_string());
    }
    for value in sanitized_history {
        if !options.iter().any(|existing| existing == &value) {
            options.push(value);
        }
    }
    options
}

pub(crate) fn sanitize_prompt_defaults(
    defaults: &PersistedPromptDefaults,
) -> PersistedPromptDefaults {
    PersistedPromptDefaults {
        examiner: sanitize_prompt_default_value(&defaults.examiner, &["Examiner"]),
        title: sanitize_prompt_default_value(&defaults.title, &["Investigation"]),
        target_serials: sanitize_prompt_default_value(&defaults.target_serials, &[]),
        categories: sanitize_prompt_default_value(&defaults.categories, &[]),
        exclude_categories: sanitize_prompt_default_value(&defaults.exclude_categories, &[]),
        source_commands: sanitize_prompt_default_value(&defaults.source_commands, &[]),
        device_serials: sanitize_prompt_default_value(&defaults.device_serials, &[]),
        category: sanitize_prompt_default_value(&defaults.category, &["derived"]),
        source_command: sanitize_prompt_default_value(&defaults.source_command, &["case register"]),
        device_serial: sanitize_prompt_default_value(&defaults.device_serial, &[]),
    }
}

pub(crate) fn sanitize_prompt_default_value(value: &str, placeholders: &[&str]) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || placeholders
            .iter()
            .any(|placeholder| trimmed == placeholder.trim())
    {
        String::new()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn remember_prompt_string(
    params: &Value,
    key: &str,
    slot: &mut String,
    placeholders: &[&str],
) {
    let Some(value) = params.get(key).and_then(Value::as_str) else {
        return;
    };
    let trimmed = sanitize_prompt_default_value(value, placeholders);
    if !trimmed.is_empty() {
        *slot = trimmed;
    }
}

pub(crate) fn remember_history_value(params: &Value, key: &str, values: &mut Vec<String>) {
    let Some(value) = params.get(key) else {
        return;
    };
    let Some(raw) = prompt_param_value_string(value) else {
        return;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    values.retain(|existing| existing != trimmed);
    values.insert(0, trimmed.to_string());
    values.truncate(MAX_RECENT_FILTER_VALUES);
}

pub(crate) fn prompt_param_value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(crate) fn config_open_feedback(path: Option<&str>) -> String {
    match path {
        Some(path) => format!("Opened config editor for {}", path),
        None => "Opened config editor".to_string(),
    }
}

pub(crate) fn success_feedback_message(action: &str, config_path: Option<&str>) -> Option<String> {
    match action {
        "config.save" => Some(match config_path {
            Some(path) => format!("Saved config: {}", path),
            None => "Saved config".to_string(),
        }),
        _ => None,
    }
}
