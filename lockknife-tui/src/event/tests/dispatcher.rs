use super::*;
use crate::event::handle_event;
use crossterm::event::{KeyEventKind, MouseButton, MouseEvent, MouseEventKind};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::time::{Duration, Instant};

fn press(app: &mut App, code: KeyCode) -> bool {
    handle_event(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
}

fn recording_callback() -> Py<PyAny> {
    init_python();
    Python::attach(|py| {
        PyModule::from_code(
            py,
            pyo3::ffi::c_str!("import json\ndef callback(action, params):\n    return {'ok': True, 'data_json': json.dumps({'action': action, 'params': params})}\n"),
            pyo3::ffi::c_str!("dispatcher_tests.py"),
            pyo3::ffi::c_str!("dispatcher_tests"),
        )
        .unwrap()
        .getattr("callback")
        .unwrap()
        .unbind()
    })
}

fn catalog_app(callback: Py<PyAny>) -> App {
    match std::env::var("LOCKKNIFE_TEST_CATALOG_FILE") {
        Ok(path) => {
            let json = std::fs::read_to_string(path).expect("generated action catalog");
            App::new_with_catalog_json(callback, Some(&json))
        }
        Err(_) => App::new(callback),
    }
}

fn wait_for_result(app: &mut App) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.busy && Instant::now() < deadline {
        app.poll_async();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!app.busy, "callback did not finish");
    serde_json::from_str(app.last_result_json.as_deref().expect("callback result")).unwrap()
}

#[test]
fn main_shortcuts_keep_new_overlays() {
    for key in ['n', 'o', '/', 'd', '?', 'v', 'e'] {
        let mut app = App::new(recording_callback());
        app.last_result_json = Some("{}".to_string());
        assert!(!press(&mut app, KeyCode::Char(key)));
        assert!(!matches!(app.overlay, Overlay::None), "lost {key} overlay");
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(matches!(app.overlay, Overlay::None));
    }
}

#[test]
fn export_shortcut_is_not_shadowed_by_exploit_navigation() {
    for panel in [Panel::Devices, Panel::Modules, Panel::Case, Panel::Output] {
        let mut app = App::new(none_callback());
        app.active_panel = panel.clone();
        press(&mut app, KeyCode::Char('e'));
        let Overlay::Prompt(prompt) = app.overlay else {
            panic!("export prompt missing")
        };
        assert!(matches!(prompt.target, PromptTarget::Export));
        assert_eq!(app.active_panel, panel);
    }
}

#[test]
fn case_dashboard_shortcuts_keep_new_prompts() {
    for key in ['f', 'g', 'x', 'w', 'h', 'i', 'j', 'u', 'k'] {
        let mut app = App::new(recording_callback());
        app.active_panel = Panel::Case;
        app.active_case_dir = Some("./cases/test-case".to_string());
        assert!(!press(&mut app, KeyCode::Char(key)));
        assert!(
            matches!(app.overlay, Overlay::Prompt(_)),
            "lost {key} prompt"
        );
    }
}

#[test]
fn every_catalog_action_is_reachable_and_dispatches_through_the_event_loop() {
    let modules = catalog_app(none_callback()).modules;
    let defaults = App::new(none_callback()).modules;
    let mut tested = 0;
    for (module_index, module) in modules.iter().enumerate() {
        for (action_index, action) in module.actions.iter().enumerate() {
            if let Some(default) = defaults
                .iter()
                .flat_map(|module| &module.actions)
                .find(|default| default.id == action.id)
            {
                assert_eq!(
                    action.fields.len(),
                    default.fields.len(),
                    "{}: lost fields",
                    action.id
                );
                assert_eq!(
                    action.requires_device, default.requires_device,
                    "{}: lost device requirement",
                    action.id
                );
                assert_eq!(
                    action.confirm, default.confirm,
                    "{}: lost confirmation",
                    action.id
                );
            }
            let mut app = catalog_app(recording_callback());
            app.devices = vec![crate::app::DeviceItem {
                serial: "test-device".to_string(),
                adb_state: "device".to_string(),
                state: "available".to_string(),
                model: None,
                device: None,
                transport_id: None,
            }];
            app.active_panel = Panel::Modules;
            app.selected_module = module_index;
            press(&mut app, KeyCode::Enter);
            let Overlay::ActionMenu(menu) = &mut app.overlay else {
                panic!("{}: module menu not opened", action.id);
            };
            menu.action_index = action_index;
            press(&mut app, KeyCode::Enter);
            if !action.fields.is_empty() {
                assert!(
                    matches!(app.overlay, Overlay::Prompt(_)),
                    "{}: no form",
                    action.id
                );
                for _ in 0..action.fields.len() {
                    press(&mut app, KeyCode::Enter);
                }
            }
            if action.confirm {
                assert!(
                    matches!(app.overlay, Overlay::Confirm(_)),
                    "{}: no confirmation",
                    action.id
                );
                assert!(!app.busy, "{} ran before confirmation", action.id);
                press(&mut app, KeyCode::Char('y'));
            }
            assert!(
                matches!(app.overlay, Overlay::None),
                "{}: dialog not closed",
                action.id
            );
            assert!(app.busy, "{}: callback was not dispatched", action.id);
            let result = wait_for_result(&mut app);
            assert_eq!(result["action"], action.id);
            if action.requires_device {
                assert_eq!(result["params"]["serial"], "test-device");
            }
            tested += 1;
        }
    }
    assert!(tested > 0);
    println!("Checked {tested} catalog actions through the dispatcher");
}

#[test]
fn release_and_repeat_events_do_not_open_close_or_submit_dialogs() {
    let mut app = App::new(recording_callback());
    for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
        assert!(!handle_event(
            &mut app,
            Event::Key(KeyEvent::new_with_kind(
                KeyCode::Char('q'),
                KeyModifiers::NONE,
                kind,
            )),
        ));
        assert!(matches!(app.overlay, Overlay::None));
        press(&mut app, KeyCode::Char('/'));
        handle_event(
            &mut app,
            Event::Key(KeyEvent::new_with_kind(
                KeyCode::Enter,
                KeyModifiers::NONE,
                kind,
            )),
        );
        assert!(matches!(app.overlay, Overlay::Prompt(_)));
        handle_event(
            &mut app,
            Event::Key(KeyEvent::new_with_kind(
                KeyCode::Char('x'),
                KeyModifiers::NONE,
                kind,
            )),
        );
        let Overlay::Prompt(prompt) = &app.overlay else {
            panic!("lost prompt")
        };
        assert!(prompt.fields[0].value.is_empty());
        press(&mut app, KeyCode::Esc);
    }
}

#[test]
fn search_form_accepts_spaces_and_applies_the_whole_query() {
    let mut app = App::new(none_callback());
    app.active_panel = Panel::Output;
    press(&mut app, KeyCode::Char('/'));
    for character in "hook payload".chars() {
        press(&mut app, KeyCode::Char(character));
    }
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.overlay, Overlay::None));
    assert_eq!(app.search.as_ref().unwrap().query, "hook payload");
}

#[test]
fn confirmation_cancel_never_dispatches_the_action() {
    for key in [KeyCode::Esc, KeyCode::Char('n')] {
        let mut app = App::new(recording_callback());
        let (module_index, action_index) = app.find_action_indices("case.init").unwrap();
        app.overlay = Overlay::Confirm(ConfirmState {
            title: "Cancel test".to_string(),
            target: PromptTarget::Action {
                module_index,
                action_index,
            },
            params: serde_json::json!({}),
            resume_config_on_cancel: false,
            resume_config_on_submit: false,
        });
        press(&mut app, key);
        assert!(!app.busy);
        assert!(app.last_result_json.is_none());
        assert!(matches!(app.overlay, Overlay::None));
    }
}

#[test]
fn unfinished_exploit_shortcuts_do_not_claim_execution() {
    let mut app = App::new(none_callback());
    app.active_panel = Panel::Exploit;
    for key in ['s', 'x', 'f'] {
        press(&mut app, KeyCode::Char(key));
        assert!(!app.busy);
        let message = &app.toasts.last().unwrap().message;
        assert!(message.contains("not implemented"));
    }
}

#[test]
fn filtered_module_click_selects_the_displayed_module() {
    let mut app = App::new(none_callback());
    app.layout.modules = ratatui::layout::Rect::new(0, 0, 40, 6);
    app.apply_search_query(SearchTarget::Modules, "case".to_string());
    let expected = app.visible_modules()[0];
    assert_ne!(expected, 0, "fixture must exercise a filtered index");
    handle_event(
        &mut app,
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        }),
    );
    assert_eq!(app.selected_module, expected);
    press(&mut app, KeyCode::Enter);
    let Overlay::ActionMenu(menu) = app.overlay else {
        panic!("menu missing")
    };
    assert_eq!(menu.module_index, expected);
}

#[test]
fn resize_keeps_prompt_and_config_controls_work_through_dispatcher() {
    let mut app = App::new(none_callback());
    press(&mut app, KeyCode::Char('n'));
    handle_event(&mut app, Event::Resize(80, 24));
    assert!(matches!(app.overlay, Overlay::Prompt(_)));
    press(&mut app, KeyCode::Esc);
    app.overlay = Overlay::Config;
    app.config_saved_text = app.config_text.clone();
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Esc);
    assert!(matches!(app.overlay, Overlay::Confirm(_)));
    press(&mut app, KeyCode::Char('n'));
    assert!(matches!(app.overlay, Overlay::Config));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('y'));
    assert!(matches!(app.overlay, Overlay::None));
    assert_eq!(app.config_text, app.config_saved_text);
}

#[test]
fn recent_history_and_result_followups_open_through_dispatcher() {
    let mut app = App::new(none_callback());
    app.active_case_dir = Some("./cases/test-case".to_string());
    app.last_result_json = Some("{}".to_string());
    press(&mut app, KeyCode::Char('p'));
    assert!(matches!(app.overlay, Overlay::Prompt(_)));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('v'));
    assert!(matches!(app.overlay, Overlay::ResultView(_)));
    press(&mut app, KeyCode::Char('s'));
    assert!(matches!(app.overlay, Overlay::Prompt(_)));
    press(&mut app, KeyCode::Esc);
    assert!(press(&mut app, KeyCode::Char('q')));
}
