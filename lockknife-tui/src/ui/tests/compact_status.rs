use super::*;

#[test]
fn config_controls_hint_compacts_with_width() {
    assert_eq!(
        config_controls_hint(Rect::new(0, 0, 36, 1)),
        "Ctrl+S save · Esc close"
    );
    let wide = config_controls_hint(Rect::new(0, 0, 72, 1));
    assert!(wide.contains("Ctrl+R revert"));
    assert!(wide.contains("PgUp/PgDn jump"));
    assert!(wide.contains("Home/End line"));
    assert!(wide.contains("↑/↓ line"));
}

#[test]
fn config_hint_lines_show_modified_state() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_text = "[ui]\ntheme='light'\n".to_string();
    app.config_saved_text = "[ui]\ntheme='dark'\n".to_string();
    app.config_cursor = 5;

    let rendered = config_hint_lines(&app, Rect::new(0, 0, 80, 2))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Modified · Cursor"));
}

#[test]
fn config_cursor_position_respects_scroll_and_width() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_text = "alpha\nbeta\ngamma".to_string();
    app.config_cursor = "alpha\nbe".len();
    app.config_scroll = 1;

    assert_eq!(
        config_cursor_position(&app, Rect::new(10, 5, 20, 4)),
        Some((12, 5))
    );

    app.config_cursor = "alpha\nbeta\ngamma".len();
    assert_eq!(config_cursor_position(&app, Rect::new(10, 5, 3, 1)), None);
}

#[test]
fn output_empty_lines_explain_how_to_clear_output_search() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Output,
        query: "hook".to_string(),
    });

    let rendered = output_empty_lines(&app)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("No output matches the current search."));
    assert!(rendered.contains("Search query: hook"));
    assert!(rendered.contains("empty query to clear the output filter"));
}

#[test]
fn active_search_status_summarizes_target_and_query() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Output,
        query: "hook response payload".to_string(),
    });

    let rendered = active_search_status(&app, 120).expect("search status should exist");

    assert!(rendered.contains("Filter: output"));
    assert!(rendered.contains("hook response payl"));
    assert!(rendered.contains("clear with / then empty"));
}

#[test]
fn panel_title_includes_active_filter_summary() {
    assert_eq!(panel_title("Modules", None, 20), "Modules");
    assert_eq!(
        panel_title("Output", Some("certificate pinning flow"), 60),
        "Output · filter: \"certificate pi…\""
    );
}

#[test]
fn panel_title_compacts_on_narrow_width() {
    assert_eq!(
        panel_title("Output", Some("certificate pinning flow"), 24),
        "Output · \"certif…\""
    );
    assert_eq!(
        panel_title("Output", Some("certificate pinning flow"), 34),
        "Output · f:\"certificat…\""
    );
}

#[test]
fn active_search_status_compacts_on_narrow_width() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Modules,
        query: "case workspace reuse".to_string(),
    });

    let rendered = active_search_status(&app, 56).expect("search status should exist");

    assert_eq!(rendered, "f:modules=\"case wor…\"");
}

#[test]
fn status_spans_compact_on_small_widths() {
    let styles = theme_styles(&Theme::Dark);
    let rendered = status_spans(&styles, 48, false)
        .into_iter()
        .map(|span| span.content.to_string())
        .collect::<String>();

    assert!(rendered.contains("[q] Quit"));
    assert!(rendered.contains("[Tab]"));
    assert!(!rendered.contains("Navigate"));
    assert!(!rendered.contains("[c] Config"));
}

#[test]
fn status_spans_surface_case_shortcuts_on_wide_layouts() {
    let styles = theme_styles(&Theme::Dark);
    let rendered = status_spans(&styles, 96, false)
        .into_iter()
        .map(|span| span.content.to_string())
        .collect::<String>();

    assert!(rendered.contains("[d] Diagnostics"));
    assert!(rendered.contains("[o] Open case"));
    assert!(rendered.contains("[p] Recent case"));
    assert!(rendered.contains("[a] Art recall"));
    assert!(rendered.contains("[n] Init case"));
}

#[test]
fn module_detail_lines_surface_truth_alignment_metadata() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let runtime = app
        .modules
        .iter()
        .find(|module| module.id == "runtime")
        .expect("runtime module should exist");

    let rendered = module_detail_lines(&app, runtime)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered
        .contains("Posture: dependency-gated [gated] · Requires: lockknife[frida] + Frida server"));
    assert!(rendered.contains("Recovery: open Diagnostics → Dependency doctor"));
}

#[test]
fn action_menu_detail_lines_surface_status_and_requirements() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let action = app
        .modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "core.doctor")
        .expect("core.doctor should exist");

    let rendered = action_menu_detail_lines(&app, action, Rect::new(0, 0, 80, 20))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Status: functional [func] · Requires: base install"));
    assert!(rendered.contains("Truth: Dependency doctor exposes optional extras"));
}

#[test]
fn renders_action_menu_with_truth_alignment_badges() {
    init_python();
    let backend = TestBackend::new(90, 26);
    let mut terminal = Terminal::new(backend).unwrap();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    let module_index = app
        .modules
        .iter()
        .position(|module| module.id == "core")
        .expect("core module should exist");
    app.overlay = Overlay::ActionMenu(ActionMenuState {
        module_index,
        action_index: 0,
    });

    terminal.draw(|f| draw(f, &mut app)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }

    assert!(text.contains("Core health [func]"));
    assert!(text.contains("Dependency doctor [func]"));
}

#[test]
fn active_panel_status_describes_current_modules_focus() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);

    assert_eq!(
        active_panel_status(&app, 96, false).as_deref(),
        Some("Panel: Modules · ↑/↓/←/→ choose · d diagnostics · Enter actions · 1-9 jump")
    );
}

#[test]
fn active_panel_status_describes_case_dashboard_focus() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_panel = Panel::Case;

    assert_eq!(
        active_panel_status(&app, 96, false).as_deref(),
        Some("Panel: Case · Enter summary · j jobs · f artifacts · g graph · x export · w report · u resume · k retry")
    );
}

#[test]
fn active_panel_status_adapts_to_devices_and_output_panels() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_panel = Panel::Devices;
    assert_eq!(
        active_panel_status(&app, 80, false).as_deref(),
        Some("Panel: Devices · r refresh")
    );

    app.active_panel = Panel::Output;
    assert_eq!(
        active_panel_status(&app, 96, false).as_deref(),
        Some("Panel: Output · ↑/↓ scroll · / filter logs · v latest result")
    );
}

#[test]
fn active_panel_status_hides_on_compact_layouts() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);

    assert!(active_panel_status(&app, 56, false).is_none());
    assert!(active_panel_status(&app, 96, true).is_none());
}

#[test]
fn active_case_status_reflects_current_case_on_wide_layouts() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.active_case_dir = Some("./cases/CASE-099".to_string());

    assert_eq!(
        active_case_status(&app, 112, false).as_deref(),
        Some("Case: ./cases/CASE-099")
    );
    assert!(active_case_status(&app, 72, false).is_none());
    assert!(active_case_status(&app, 112, true).is_none());
}

#[test]
fn active_case_status_surfaces_missing_case_state_on_roomy_layouts() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);

    assert_eq!(
        active_case_status(&app, 112, false).as_deref(),
        Some("Case: no active case yet · n init or set Case directory")
    );
    assert!(active_case_status(&app, 96, false).is_none());
}

#[test]
fn active_target_status_reflects_selected_device_on_roomy_layouts() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.devices.push(DeviceItem {
        serial: "SERIAL-77".to_string(),
        adb_state: "device".to_string(),
        state: "authorized".to_string(),
        model: Some("Pixel".to_string()),
        device: Some("pixel".to_string()),
        transport_id: Some("1".to_string()),
    });

    assert_eq!(
        active_target_status(&app, 112, false).as_deref(),
        Some("Target: \"SERIAL-77\"")
    );
    assert!(active_target_status(&app, 88, false).is_none());
}

#[test]
fn device_empty_hint_compacts_for_narrow_layouts() {
    assert_eq!(device_empty_hint(24, 6), Some("Press r to refresh."));
    assert_eq!(
        device_empty_hint(40, 6),
        Some("Press r to refresh or connect a device.")
    );
}

#[test]
fn device_empty_hint_hides_extra_copy_for_short_panes() {
    assert_eq!(device_empty_hint(60, 2), None);
    assert_eq!(device_empty_hint(60, 4), Some("Press r to refresh."));
}

#[test]
fn status_spans_compact_for_short_main_layouts() {
    let styles = theme_styles(&Theme::Dark);
    let rendered = status_spans(&styles, 100, true)
        .into_iter()
        .map(|span| span.content.to_string())
        .collect::<String>();

    assert!(rendered.contains("[q] Quit"));
    assert!(!rendered.contains("[c] Config"));
    assert!(!rendered.contains("Navigate"));
}

#[test]
fn help_lines_compact_for_small_overlays() {
    let rendered = help_lines(Rect::new(0, 0, 40, 12))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("Nav: Tab panels"));
    assert!(
        rendered.contains("Tools: / search · d diag · o case · p recent · a art · n init · v view")
    );
    assert!(rendered.contains("Case: set Case directory"));
    assert!(!rendered.contains("Diagnostics"));
}

#[test]
fn help_lines_promote_tui_first_diagnostics_on_wide_overlays() {
    let rendered = help_lines(Rect::new(0, 0, 90, 24))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains(
        "Open the Diagnostics module for Core health, Dependency doctor, and Feature matrix"
    ));
    assert!(rendered.contains("d: open Diagnostics quickly (starts on Dependency doctor)"));
    assert!(rendered
        .contains("o: open case summary quickly (edit Case directory to switch workspaces)"));
    assert!(rendered.contains("p: reopen a recent case summary with ←/→ recall"));
    assert!(rendered.contains("a: reopen recent artifact-search filters with ←/→ recall"));
    assert!(rendered.contains("n: init a new case workspace quickly"));
    assert!(rendered
        .contains("Case panel: j jobs · f artifact inventory · g graph · x export bundle · w report · h custody · i integrity · u resume job · k retry job"));
    assert!(rendered.contains("Use the CLI only for headless quick tasks or automation"));
}

#[test]
fn config_title_compacts_for_small_widths() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.config_path = Some("/very/long/path/to/configs/lockknife.toml".to_string());

    assert_eq!(config_title(&app, 20), "Config");
    assert!(config_title(&app, 48).starts_with("Config ("));
    assert!(config_title(&app, 48).contains('…'));
}

#[test]
fn adaptive_centered_rect_expands_on_small_terminals() {
    let compact = adaptive_centered_rect(70, 70, Rect::new(0, 0, 40, 12));

    assert!(compact.width >= 36);
    assert!(compact.height >= 11);
}

#[test]
fn confirm_lines_compact_for_small_overlays() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let app = App::new(callback);
    let state = ConfirmState {
        title: "Delete bundle?".to_string(),
        target: PromptTarget::Export,
        params: serde_json::json!({}),
        resume_config_on_cancel: false,
        resume_config_on_submit: false,
    };

    let rendered = confirm_lines(&app, &state, Rect::new(0, 0, 30, 7))
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert_eq!(rendered[1], "y confirm · n/Esc cancel");
}

#[test]
fn module_empty_detail_lines_explain_how_to_clear_module_search() {
    init_python();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    app.search = Some(SearchState {
        target: SearchTarget::Modules,
        query: "nonexistent".to_string(),
    });

    let rendered = module_empty_detail_lines(&app)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("No modules match the current search."));
    assert!(rendered.contains("Search query: nonexistent"));
    assert!(rendered.contains("empty query to clear the module filter"));
}

#[test]
fn tui_first_render_under_100ms() {
    init_python();
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let callback = pyo3::Python::attach(|py| py.None());
    let mut app = App::new(callback);
    let start = Instant::now();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    assert!(start.elapsed().as_millis() < 100);
}
