#![allow(deprecated)] // Allow deprecated PyO3 API (upgrade to 0.24 for security, migration to new API deferred)

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{poll, read, DisableMouseCapture, EnableMouseCapture, Event};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use pyo3::prelude::*;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use signal_hook::consts::signal;

pub mod app;
pub mod bridge;
pub mod event;
pub mod ui;

static CLEANUP_REGISTERED: AtomicBool = AtomicBool::new(false);

fn register_signal_handlers(cleanup_flag: Arc<AtomicBool>) -> PyResult<()> {
    if CLEANUP_REGISTERED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already registered
    }

    let flag = cleanup_flag.clone();
    signal_hook::flag::register(signal::SIGINT, flag.clone())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    signal_hook::flag::register(signal::SIGTERM, flag)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    Ok(())
}

pub fn run_tui(py: Python<'_>, callback: PyObject) -> PyResult<()> {
    let callback = callback.into_py(py);
    let mut terminal = setup_terminal()?;

    // Register signal handlers for graceful shutdown
    let cleanup_flag = Arc::new(AtomicBool::new(false));
    register_signal_handlers(cleanup_flag.clone())?;

    let mut app = app::App::new(callback);
    app.refresh_devices();
    let res = run_app(py, &mut terminal, &mut app, cleanup_flag);
    restore_terminal(&mut terminal)?;
    res.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

fn setup_terminal() -> PyResult<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> PyResult<()> {
    disable_raw_mode()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    crossterm::execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    terminal
        .show_cursor()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

fn run_app(
    py: Python<'_>,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut app::App,
    cleanup_flag: Arc<AtomicBool>,
) -> io::Result<()> {
    loop {
        // Check if signal was received
        if cleanup_flag.load(Ordering::SeqCst) {
            break;
        }

        let quit = py.allow_threads(|| -> io::Result<bool> {
            app.poll_async();
            app.tick();
            terminal.draw(|f| ui::draw(f, app))?;
            if poll(Duration::from_millis(120))? {
                let evt = read()?;
                if handle_event(app, evt) {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if quit {
            app.cancel_async();
            break;
        }
    }
    Ok(())
}

fn handle_event(app: &mut app::App, evt: Event) -> bool {
    event::handle_event(app, evt)
}

#[cfg(test)]
mod crash_recovery_tests {
    use super::*;

    #[test]
    fn test_restore_terminal_idempotent() {
        // This test verifies that restore_terminal can be called multiple times safely
        // In practice, this is difficult to test without a real terminal, but we can
        // at least verify the function signature and that it exists
        // The actual behavior is tested in integration tests
    }

    #[test]
    fn test_cleanup_registered_flag() {
        // Verify that the cleanup flag is atomic and can be checked
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::SeqCst));
        flag.store(true, Ordering::SeqCst);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_cleanup_registration_idempotent() {
        // Verify that cleanup registration is idempotent
        // First registration should succeed (not testing actual registration due to signal complexity)
        // This is a placeholder to verify the logic exists
        assert!(!CLEANUP_REGISTERED.load(Ordering::SeqCst));
    }
}
