use crossterm::event::{Event, KeyEventKind};

use crate::app::{App, Overlay};

mod helpers;
mod main;
mod overlays;
#[cfg(test)]
mod tests;

#[cfg(test)]
use self::main::build_search_prompt;
use self::main::handle_main;
#[cfg(test)]
use self::overlays::submit_prompt;
use self::overlays::{
    handle_action_menu, handle_config, handle_confirm, handle_help, handle_prompt,
    handle_result_view,
};

pub fn handle_event(app: &mut App, event: Event) -> bool {
    // Windows emits releases as well as presses; never submit an action twice.
    if matches!(&event, Event::Key(key) if key.kind != KeyEventKind::Press) {
        return false;
    }
    let overlay = std::mem::replace(&mut app.overlay, Overlay::None);
    let (quit, next_overlay) = match overlay {
        Overlay::Help => handle_help(app, event),
        Overlay::Config => handle_config(app, event),
        Overlay::Prompt(state) => handle_prompt(app, event, state),
        Overlay::Confirm(state) => handle_confirm(app, event, state),
        Overlay::ActionMenu(state) => handle_action_menu(app, event, state),
        Overlay::ResultView(state) => handle_result_view(app, event, state),
        Overlay::None => {
            let quit = handle_main(app, event);
            (quit, std::mem::replace(&mut app.overlay, Overlay::None))
        }
    };
    app.overlay = next_overlay;
    quit
}
