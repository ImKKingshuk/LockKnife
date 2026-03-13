use super::*;
use pyo3::{IntoPy, Python};
use std::path::PathBuf;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
    });
}

fn temp_tui_config_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "lockknife-tui-{}-{}-{}.toml",
        std::process::id(),
        nonce,
        name
    ))
}

mod action_prompts;
mod catalog;
mod config_history;
mod followups;
mod prompt_memory;
mod result_view;
mod state_and_layout;
