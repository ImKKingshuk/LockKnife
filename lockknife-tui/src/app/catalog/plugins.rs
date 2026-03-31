use super::super::ModuleEntry;
use super::fields::{action, bool_field, choice_field, module, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "plugins",
        "Plugins",
        vec![action(
            "plugins.list",
            "List plugins",
            vec![
                choice_field("format", "Format", "text", &["text", "json"]),
                bool_field("reload", "Reload before listing", false),
            ],
            false,
            false,
        )],
    )
}
