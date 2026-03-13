use super::*;

#[test]
fn handle_config_page_keys_fast_scroll() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_scroll = 10;

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_scroll, 2);
    assert!(matches!(overlay, Overlay::Config));

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_scroll, 10);
    assert!(matches!(overlay, Overlay::Config));
}

#[test]
fn handle_config_up_down_move_cursor_and_follow_scroll() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "alpha\nb\ngamma\ndelta".to_string();
    app.config_saved_text = app.config_text.clone();
    app.config_viewport_height = 2;
    app.config_cursor = "alp".len();

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, "alpha\nb".len());
    assert_eq!(app.config_scroll, 0);

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, "alpha\nb\ngam".len());
    assert_eq!(app.config_scroll, 1);

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, "alpha\nb".len());
    assert_eq!(app.config_scroll, 1);
}

#[test]
fn handle_config_home_end_and_editing_use_app_helpers() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "héllo\nworld".to_string();
    app.config_saved_text = app.config_text.clone();
    app.config_cursor = app.config_text.len();

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, "héllo\n".len());
    assert!(matches!(overlay, Overlay::Config));

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, app.config_text.len());

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)),
    );
    let before_insert = app.config_cursor;

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('!'), KeyModifiers::NONE)),
    );
    assert_eq!(app.config_cursor, before_insert + '!'.len_utf8());
    assert!(app.config_is_dirty());

    let _ = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)),
    );
    assert_eq!(app.config_text, "héllo\nworld");
}

#[test]
fn handle_config_esc_prompts_before_discarding_dirty_changes() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "theme = 'light'\n".to_string();
    app.config_saved_text = "theme = 'dark'\n".to_string();

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
    );

    match overlay {
        Overlay::Confirm(state) => {
            assert_eq!(state.title, "Discard unsaved config changes?");
            assert!(matches!(state.target, PromptTarget::DiscardConfig));
            assert!(state.resume_config_on_cancel);
            assert!(!state.resume_config_on_submit);
        }
        other => panic!("expected confirm overlay, got {other:?}"),
    }
}

#[test]
fn handle_config_ctrl_r_prompts_before_reverting_dirty_changes() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "theme = 'light'\n".to_string();
    app.config_saved_text = "theme = 'dark'\n".to_string();

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
    );

    match overlay {
        Overlay::Confirm(state) => {
            assert_eq!(state.title, "Revert config to last saved state?");
            assert!(matches!(state.target, PromptTarget::RevertConfig));
            assert!(state.resume_config_on_cancel);
            assert!(state.resume_config_on_submit);
        }
        other => panic!("expected confirm overlay, got {other:?}"),
    }
}

#[test]
fn handle_config_ctrl_r_reports_when_buffer_is_already_saved() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "theme = 'dark'\n".to_string();
    app.config_saved_text = app.config_text.clone();

    let (_, overlay) = handle_config(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
    );

    assert!(matches!(overlay, Overlay::Config));
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Config already matches the last saved state"));
}

#[test]
fn handle_confirm_can_resume_or_discard_config_editor() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "theme = 'light'\n".to_string();
    app.config_saved_text = "theme = 'dark'\n".to_string();

    let confirm = ConfirmState {
        title: "Discard unsaved config changes?".to_string(),
        target: PromptTarget::DiscardConfig,
        params: Value::Object(Map::new()),
        resume_config_on_cancel: true,
        resume_config_on_submit: false,
    };

    let (_, overlay) = handle_confirm(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
        confirm.clone(),
    );
    assert!(matches!(overlay, Overlay::Config));
    assert_eq!(app.config_text, "theme = 'light'\n");

    let (_, overlay) = handle_confirm(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
        confirm,
    );
    assert!(matches!(overlay, Overlay::None));
    assert_eq!(app.config_text, "theme = 'dark'\n");
    assert!(!app.config_is_dirty());
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Discarded unsaved config changes"));
}

#[test]
fn handle_confirm_can_resume_after_reverting_config_editor() {
    let callback = none_callback();
    let mut app = App::new(callback);
    app.config_text = "theme = 'light'\n".to_string();
    app.config_saved_text = "theme = 'dark'\n".to_string();

    let confirm = ConfirmState {
        title: "Revert config to last saved state?".to_string(),
        target: PromptTarget::RevertConfig,
        params: Value::Object(Map::new()),
        resume_config_on_cancel: true,
        resume_config_on_submit: true,
    };

    let (_, overlay) = handle_confirm(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
        confirm,
    );

    assert!(matches!(overlay, Overlay::Config));
    assert_eq!(app.config_text, "theme = 'dark'\n");
    assert!(!app.config_is_dirty());
    assert!(app
        .toasts
        .iter()
        .any(|toast| toast.message == "Reverted config to last saved state"));
}
