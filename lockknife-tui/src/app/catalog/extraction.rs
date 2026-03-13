use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, choice_field, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "extraction",
        "Extraction",
        vec![
            action(
                "extraction.sms",
                "SMS",
                vec![
                    number_field("limit", "Limit", "200"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.contacts",
                "Contacts",
                vec![
                    number_field("limit", "Limit", "200"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.call_logs",
                "Call logs",
                vec![
                    number_field("limit", "Limit", "200"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.browser",
                "Browser",
                vec![
                    choice_field(
                        "app",
                        "App",
                        "chrome",
                        &["chrome", "edge", "brave", "opera", "firefox"],
                    ),
                    choice_field(
                        "kind",
                        "Kind",
                        "history",
                        &[
                            "history",
                            "bookmarks",
                            "downloads",
                            "cookies",
                            "passwords",
                            "all",
                        ],
                    ),
                    number_field("limit", "Limit", "200"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.messaging",
                "Messaging",
                vec![
                    choice_field(
                        "app",
                        "App",
                        "whatsapp",
                        &["whatsapp", "telegram", "signal"],
                    ),
                    choice_field("mode", "Mode", "messages", &["messages", "artifacts"]),
                    number_field("limit", "Limit", "200"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.media",
                "Media + EXIF",
                vec![
                    number_field("limit", "Limit", "20"),
                    choice_field("format", "Format", "json", &["json", "csv"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "extraction.location",
                "Location artifacts",
                vec![
                    choice_field("mode", "Mode", "artifacts", &["artifacts", "snapshot"]),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
        ],
    )
}
