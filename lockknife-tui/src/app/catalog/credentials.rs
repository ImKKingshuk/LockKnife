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
            action(
                "credentials.offline_pin",
                "Offline PIN brute-force",
                vec![
                    text_field("hash", "Target hash (hex)", ""),
                    choice_field("algo", "Algorithm", "sha256", &["sha1", "sha256"]),
                    number_field("length", "PIN length", "6"),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "credentials.offline_password",
                "Offline password crack",
                vec![
                    text_field("hash", "Target hash (hex)", ""),
                    choice_field("algo", "Algorithm", "sha256", &["sha1", "sha256", "sha512"]),
                    text_field("wordlist", "Wordlist path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "credentials.offline_password_rules",
                "Offline password with rules",
                vec![
                    text_field("hash", "Target hash (hex)", ""),
                    choice_field("algo", "Algorithm", "sha256", &["sha1", "sha256", "sha512"]),
                    text_field("wordlist", "Wordlist path", ""),
                    number_field("max_suffix", "Max suffix", "100"),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
