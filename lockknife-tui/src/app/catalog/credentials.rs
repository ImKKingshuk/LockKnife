use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "credentials",
        "Credentials",
        vec![
            action(
                "credentials.pin",
                "PIN brute-force",
                vec![
                    number_field("length", "PIN length", "6"),
                    text_field("output_dir", "Output directory", ""),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "credentials.gesture",
                "Gesture recovery",
                vec![
                    text_field("output_dir", "Output directory", ""),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "credentials.wifi",
                "WiFi passwords",
                vec![
                    text_field("output_dir", "Output directory", ""),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "credentials.keystore",
                "Keystore listing",
                vec![
                    text_field("output_dir", "Output directory", ""),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "credentials.passkeys",
                "Passkey export",
                vec![
                    number_field("limit", "Artifact limit", "200"),
                    text_field("output_dir", "Output directory", ""),
                    case_dir_field(),
                ],
                true,
                true,
            ),
        ],
    )
}
