use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use pyo3::prelude::*;
use ratatui::layout::Rect;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridge::CallbackResult;

use super::catalog::{
    action_capability_metadata, action_description, action_help_lines, action_recovery_hint,
    module_capability_metadata, module_description, module_help_lines, module_recovery_hint,
};

pub(crate) const MAX_RECENT_CASES: usize = 6;
pub(crate) const MAX_RECENT_FILTER_VALUES: usize = 6;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DeviceItem {
    pub serial: String,
    pub adb_state: String,
    pub state: String,
    pub model: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Toast {
    pub created_at: Instant,
    pub level: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityMetadata {
    pub status: &'static str,
    pub requirements: &'static str,
    pub notes: &'static str,
}

#[derive(Clone, Debug)]
pub struct ModuleAction {
    pub id: String,
    pub label: String,
    pub fields: Vec<PromptField>,
    pub requires_device: bool,
    pub confirm: bool,
}

impl ModuleAction {
    pub fn description(&self) -> Option<&'static str> {
        action_description(&self.id)
    }

    pub fn help_lines(&self) -> Vec<&'static str> {
        action_help_lines(&self.id)
    }

    pub fn capability_metadata(&self) -> Option<CapabilityMetadata> {
        action_capability_metadata(&self.id)
    }

    pub fn recovery_hint(&self) -> Option<&'static str> {
        action_recovery_hint(&self.id)
    }

    pub fn is_case_aware(&self) -> bool {
        self.fields.iter().any(|field| field.key == "case_dir")
    }

    pub fn has_output_field(&self) -> bool {
        self.fields
            .iter()
            .any(|field| matches!(field.key.as_str(), "output" | "result_output"))
    }

    pub fn targets_device(&self) -> bool {
        self.requires_device
            || self.fields.iter().any(|field| {
                matches!(
                    field.key.as_str(),
                    "device_id" | "device_serial" | "device_serials" | "target_serials"
                )
            })
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ModuleEntry {
    pub id: String,
    pub label: String,
    pub actions: Vec<ModuleAction>,
}

impl ModuleEntry {
    pub fn description(&self) -> Option<&'static str> {
        module_description(&self.id)
    }

    pub fn help_lines(&self) -> Vec<&'static str> {
        module_help_lines(&self.id)
    }

    pub fn capability_metadata(&self) -> Option<CapabilityMetadata> {
        module_capability_metadata(&self.id)
    }

    pub fn recovery_hint(&self) -> Option<&'static str> {
        module_recovery_hint(&self.id)
    }

    pub fn device_action_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.requires_device)
            .count()
    }

    pub fn case_aware_action_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.is_case_aware())
            .count()
    }

    pub fn output_action_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.has_output_field())
            .count()
    }

    pub fn case_managed_output_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.is_case_aware() && action.has_output_field())
            .count()
    }
}

#[derive(Clone, Debug)]
pub struct PromptField {
    pub key: String,
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
    pub options: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum FieldKind {
    Text,
    Number,
    Bool,
    Choice,
}

#[derive(Clone, Debug)]
pub struct PromptState {
    pub title: String,
    pub description: Option<String>,
    pub help_lines: Vec<String>,
    pub fields: Vec<PromptField>,
    pub index: usize,
    pub target: PromptTarget,
}

#[derive(Clone, Debug)]
pub struct ActionMenuState {
    pub module_index: usize,
    pub action_index: usize,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum PromptTarget {
    Action {
        module_index: usize,
        action_index: usize,
    },
    Search {
        target: SearchTarget,
    },
    Export,
    ConfigSave,
    DiscardConfig,
    RevertConfig,
}

#[derive(Clone, Debug)]
pub struct ConfirmState {
    pub title: String,
    pub target: PromptTarget,
    pub params: Value,
    pub resume_config_on_cancel: bool,
    pub resume_config_on_submit: bool,
}

#[derive(Clone, Debug)]
pub struct ResultViewState {
    pub title: String,
    pub content: String,
    pub scroll: u16,
    pub line_count: u16,
    pub section_starts: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultPath {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvestigationOutcome {
    Success,
    Partial,
    Failure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvestigationEntry {
    pub timestamp: String,
    pub action_id: String,
    pub action_label: String,
    pub case_dir: String,
    pub outcome: InvestigationOutcome,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub enum Overlay {
    None,
    Help,
    Config,
    Prompt(PromptState),
    Confirm(ConfirmState),
    ActionMenu(ActionMenuState),
    ResultView(ResultViewState),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Panel {
    Devices,
    Modules,
    Case,
    Output,
}

#[derive(Clone, Debug)]
pub enum SearchTarget {
    Modules,
    Output,
}

impl SearchTarget {
    pub fn title_label(&self) -> &'static str {
        match self {
            Self::Modules => "Modules",
            Self::Output => "Output",
        }
    }

    pub fn summary_label(&self) -> &'static str {
        match self {
            Self::Modules => "modules",
            Self::Output => "output",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchState {
    pub target: SearchTarget,
    pub query: String,
}

#[derive(Clone, Debug)]
pub enum Theme {
    Dark,
    Light,
    Hacker,
}

impl Theme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
            Theme::Hacker => "hacker",
        }
    }
}

impl FromStr for Theme {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "dark" => Ok(Theme::Dark),
            "light" => Ok(Theme::Light),
            "hacker" => Ok(Theme::Hacker),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UiLayout {
    pub header: Rect,
    pub devices: Rect,
    pub modules: Rect,
    pub case: Rect,
    pub output: Rect,
    pub status: Rect,
}

#[derive(Clone, Debug)]
pub struct AsyncResult {
    pub action: String,
    pub result: CallbackResult,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TuiConfig {
    pub theme: String,
    pub top_height: u16,
    #[serde(default)]
    pub recent_case_dirs: Vec<String>,
    #[serde(default)]
    pub prompt_defaults: PersistedPromptDefaults,
    #[serde(default)]
    pub artifact_filter_history: PersistedArtifactFilterHistory,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPromptDefaults {
    #[serde(default)]
    pub examiner: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub target_serials: String,
    #[serde(default)]
    pub categories: String,
    #[serde(default)]
    pub exclude_categories: String,
    #[serde(default)]
    pub source_commands: String,
    #[serde(default)]
    pub device_serials: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub source_command: String,
    #[serde(default)]
    pub device_serial: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedArtifactFilterHistory {
    #[serde(default)]
    pub queries: Vec<String>,
    #[serde(default)]
    pub path_contains: Vec<String>,
    #[serde(default)]
    pub metadata_contains: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub exclude_categories: Vec<String>,
    #[serde(default)]
    pub source_commands: Vec<String>,
    #[serde(default)]
    pub device_serials: Vec<String>,
    #[serde(default)]
    pub limits: Vec<String>,
}

#[derive(Debug)]
pub struct App {
    pub callback: Py<PyAny>,
    pub devices: Vec<DeviceItem>,
    pub modules: Vec<ModuleEntry>,
    pub logs: Vec<LogEntry>,
    pub toasts: Vec<Toast>,
    pub selected_device: usize,
    pub selected_module: usize,
    #[allow(dead_code)]
    pub selected_action: usize,
    pub module_scroll: usize,
    pub active_panel: Panel,
    pub overlay: Overlay,
    pub search: Option<SearchState>,
    pub theme: Theme,
    pub layout: UiLayout,
    pub top_height: u16,
    pub busy: bool,
    pub progress: u16,
    pub progress_label: String,
    pub spinner_index: usize,
    pub last_tick: Instant,
    pub async_rx: Option<Receiver<AsyncResult>>,
    pub cancel_tx: Option<Sender<()>>,
    pub active_case_dir: Option<String>,
    pub recent_case_dirs: Vec<String>,
    pub prompt_defaults: PersistedPromptDefaults,
    pub artifact_filter_history: PersistedArtifactFilterHistory,
    pub pending_case_dir: Option<String>,
    pub last_result_json: Option<String>,
    pub last_job_json: Option<String>,
    pub last_result_message: Option<String>,
    pub last_result_paths: Vec<ResultPath>,
    pub investigation_history: Vec<InvestigationEntry>,
    pub config_text: String,
    pub config_saved_text: String,
    pub config_path: Option<String>,
    pub config_scroll: u16,
    pub config_cursor: usize,
    pub config_viewport_height: u16,
    pub config_goal_column: Option<usize>,
    pub output_scroll: u16,
}
