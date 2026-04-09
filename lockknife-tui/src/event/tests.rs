use super::main::handle_main;
use super::{
    build_search_prompt, handle_action_menu, handle_config, handle_confirm, handle_result_view,
    submit_prompt,
};
use crate::app::{
    App, ConfirmState, FieldKind, Overlay, Panel, PromptTarget, ResultViewState, SearchState,
    SearchTarget,
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Map, Value};
use std::sync::Once;

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

fn none_callback() -> pyo3::Py<pyo3::PyAny> {
    init_python();
    pyo3::Python::attach(|py| py.None())
}

mod action_menu;
mod config;
mod main_shortcuts;
mod prompt_submit;
mod result_view;
