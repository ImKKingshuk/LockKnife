use super::*;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use crate::app::{
    ActionMenuState, App, ConfirmState, DeviceItem, FieldKind, Overlay, Panel, PromptField,
    PromptState, PromptTarget, ResultViewState, SearchState, SearchTarget,
};
use std::sync::Once;
use std::time::Instant;

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

mod action_details;
mod compact_status;
mod confirm;
mod output_and_titles;
mod prompts;
mod rendering;
