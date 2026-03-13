use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{poll, read, DisableMouseCapture, EnableMouseCapture, Event};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use pyo3::prelude::*;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

pub mod app;
pub mod bridge;
pub mod event;
pub mod ui;

pub fn run_tui(py: Python<'_>, callback: PyObject) -> PyResult<()> {
    let callback = callback.into_py(py);
    let mut terminal = setup_terminal()?;
    let mut app = app::App::new(callback);
    app.refresh_devices();
    let res = run_app(py, &mut terminal, &mut app);
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
) -> io::Result<()> {
    loop {
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
