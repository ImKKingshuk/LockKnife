use ratatui::text::{Line, Span};

use crate::app::{App, Panel};

use super::common::{summarize_plain_text, summarize_query};
use crate::ui::ThemeStyles;

pub(in crate::ui) fn output_empty_lines(app: &App) -> Vec<Line<'static>> {
    if let Some(query) = active_output_search_query(app) {
        return vec![
            Line::from("No output matches the current search."),
            Line::from(format!("Search query: {}", query)),
            Line::from("Press / and submit an empty query to clear the output filter."),
        ];
    }

    if app.busy {
        let mut lines = vec![Line::from("Waiting for output from the running action...")];
        if !app.progress_label.trim().is_empty() {
            lines.push(Line::from(format!(
                "Current action: {}",
                app.progress_label.trim()
            )));
        }
        if let Some(case_summary) = app.active_case_summary(48) {
            lines.push(Line::from(format!(
                "Active case: {} · case-aware actions can route outputs here.",
                case_summary
            )));
        }
        if let Some(serial) = app.selected_device_serial() {
            lines.push(Line::from(format!(
                "Active target: {} · refresh Devices if the cable, transport, or authorization state changed.",
                serial
            )));
        }
        return lines;
    }

    if app.last_result_json.is_some() {
        let mut lines = vec![
            Line::from("No output logs are available for the latest result."),
            Line::from(
                "Press v to inspect the latest JSON result, or run another action for more output.",
            ),
        ];
        if let Some(case_summary) = app.active_case_summary(48) {
            lines.push(Line::from(format!(
                "Active case: {} · key paths in Result view show where artifacts landed.",
                case_summary
            )));
            lines.push(Line::from(
                "Result view follow-up actions stay scoped to the active case.",
            ));
        } else {
            lines.push(Line::from(
                "Tip: no active case yet · use n to init one or set Case directory on the next supported action.",
            ));
        }
        if let Some(serial) = app.selected_device_serial() {
            lines.push(Line::from(format!(
                "Active target: {} · credential prompts inherit this device unless you override the serial.",
                serial
            )));
        }
        return lines;
    }

    let mut lines = vec![
        Line::from("No output yet."),
        Line::from("Run an action to populate logs, then press v to inspect the latest result."),
        Line::from("Use Tab to switch panels and Enter on a module to open its actions."),
    ];
    if let Some(case_summary) = app.active_case_summary(48) {
        lines.push(Line::from(format!(
            "Active case: {} · leave Output blank in case-aware prompts for managed paths.",
            case_summary
        )));
    } else {
        lines.push(Line::from(
            "Tip: no active case yet · use n to init one or set Case directory on supported prompts.",
        ));
    }
    if let Some(serial) = app.selected_device_serial() {
        lines.push(Line::from(format!(
            "Active target: {} · use the Devices panel to avoid running fragile workflows on the wrong handset.",
            serial
        )));
    }
    lines
}

pub(in crate::ui) fn active_module_search_query(app: &App) -> Option<&str> {
    app.search.as_ref().and_then(|state| {
        if matches!(state.target, crate::app::SearchTarget::Modules) && !state.query.is_empty() {
            Some(state.query.as_str())
        } else {
            None
        }
    })
}

pub(in crate::ui) fn active_output_search_query(app: &App) -> Option<&str> {
    app.search.as_ref().and_then(|state| {
        if matches!(state.target, crate::app::SearchTarget::Output) && !state.query.is_empty() {
            Some(state.query.as_str())
        } else {
            None
        }
    })
}

pub(in crate::ui) fn active_search_status(app: &App, width: u16) -> Option<String> {
    let state = app.search.as_ref()?;
    let query = state.query.trim();
    if query.is_empty() || width < 38 {
        return None;
    }

    Some(if width < 64 {
        format!(
            "f:{}={}",
            state.target.summary_label(),
            summarize_query(query, 8)
        )
    } else if width < 84 {
        format!(
            "Filter {}={}",
            state.target.summary_label(),
            summarize_query(query, 12)
        )
    } else {
        format!(
            "Filter: {}={} · clear with / then empty",
            state.target.summary_label(),
            summarize_query(query, 18)
        )
    })
}

pub(in crate::ui) fn panel_title(base: &str, query: Option<&str>, width: u16) -> String {
    match query {
        Some(_) if width < 18 => base.to_string(),
        Some(query) if width < 28 => format!("{} · {}", base, summarize_query(query, 6)),
        Some(query) if width < 40 => format!("{} · f:{}", base, summarize_query(query, 10)),
        Some(query) => format!("{} · filter: {}", base, summarize_query(query, 14)),
        None => base.to_string(),
    }
}

pub(in crate::ui) fn device_empty_hint(width: u16, height: u16) -> Option<&'static str> {
    if height < 3 {
        None
    } else if height < 5 || width < 34 {
        Some("Press r to refresh.")
    } else if width < 56 {
        Some("Press r to refresh or connect a device.")
    } else {
        Some("Press r to refresh or connect a device before running device-backed actions.")
    }
}

pub(in crate::ui) fn status_spans(
    styles: &ThemeStyles,
    width: u16,
    compact_layout: bool,
) -> Vec<Span<'static>> {
    let items: &[&str] = if width < 56 || compact_layout {
        &[
            "[q] Quit  ",
            "[Tab]  ",
            "[Enter]  ",
            "[/]  ",
            "[v]  ",
            "[?]",
        ]
    } else if width < 88 {
        &[
            "[q] Quit  ",
            "[Tab] Nav  ",
            "[Enter] Select  ",
            "[d] Diag  ",
            "[o] Case  ",
            "[p] Recent  ",
            "[a] Art  ",
            "[v] View  ",
            "[/] Search  ",
            "[?] Help  ",
            "[e] Export  ",
            "[n] New",
        ]
    } else {
        &[
            "[q] Quit  ",
            "[Tab] Navigate  ",
            "[Enter] Select  ",
            "[d] Diagnostics  ",
            "[o] Open case  ",
            "[p] Recent case  ",
            "[a] Art recall  ",
            "[v] View  ",
            "[/] Search  ",
            "[?] Help  ",
            "[n] Init case  ",
            "[t] Theme  ",
            "[c] Config  ",
            "[e] Export",
        ]
    };

    items
        .iter()
        .map(|item| Span::styled((*item).to_string(), styles.status))
        .collect()
}

pub(in crate::ui) fn active_panel_status(
    app: &App,
    width: u16,
    compact_layout: bool,
) -> Option<String> {
    if compact_layout || width < 64 {
        return None;
    }

    Some(match app.active_panel {
        Panel::Devices if width < 92 => "Panel: Devices · r refresh".to_string(),
        Panel::Devices => "Panel: Devices · ↑/↓ choose device · r refresh".to_string(),
        Panel::Modules if width < 92 => {
            "Panel: Modules · d diagnostics · Enter actions · 1-9 jump".to_string()
        }
        Panel::Modules => {
            "Panel: Modules · ↑/↓/←/→ choose · d diagnostics · Enter actions · 1-9 jump"
                .to_string()
        }
        Panel::Case if width < 92 => "Panel: Case · Enter/j summary · f/g/x/w · u/k jobs".to_string(),
        Panel::Case => {
            "Panel: Case · Enter summary · j jobs · f artifacts · g graph · x export · w report · u resume · k retry".to_string()
        }
        Panel::Output if width < 92 => "Panel: Output · ↑/↓ scroll · / filter".to_string(),
        Panel::Output => {
            "Panel: Output · ↑/↓ scroll · / filter logs · v latest result".to_string()
        }
        Panel::Exploit => "Panel: Exploit · s scan · r run · v evidence · x stop".to_string(),
        Panel::ExploitStatus => "Panel: Exploit Status · ↑/↓ scroll".to_string(),
        Panel::Evidence => "Panel: Evidence · ↑/↓ scroll · f filter".to_string(),
        Panel::ScanResults => "Panel: Scan Results · ↑/↓ scroll".to_string(),
    })
}

pub(in crate::ui) fn active_case_status(
    app: &App,
    width: u16,
    compact_layout: bool,
) -> Option<String> {
    if compact_layout {
        return None;
    }

    if let Some(summary) = app.active_case_summary(if width < 112 { 18 } else { 28 }) {
        if width < 86 {
            None
        } else {
            Some(format!("Case: {}", summary))
        }
    } else if width >= 112 {
        Some("Case: no active case yet · n init or set Case directory".to_string())
    } else {
        None
    }
}

pub(in crate::ui) fn active_target_status(
    app: &App,
    width: u16,
    compact_layout: bool,
) -> Option<String> {
    if compact_layout || width < 98 {
        return None;
    }
    app.selected_device_serial().map(|serial| {
        format!(
            "Target: {}",
            summarize_query(&serial, if width < 118 { 14 } else { 22 })
        )
    })
}

pub(in crate::ui) fn running_status_label(width: u16, spinner: &str) -> String {
    if width < 56 {
        format!("{} Busy", spinner)
    } else {
        format!("{} Running...", spinner)
    }
}

pub(in crate::ui) fn progress_label_for_width(label: &str, width: u16) -> String {
    let max_chars = usize::from(width.max(8));
    summarize_plain_text(label, max_chars)
}
