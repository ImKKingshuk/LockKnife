use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, choice_field, module, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "apk",
        "APK Analysis",
        vec![
            action(
                "apk.dex",
                "DEX headers",
                vec![
                    text_field("path", "APK or DEX path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "apk.permissions",
                "Permissions",
                vec![
                    text_field("path", "APK path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "apk.analyze",
                "Analyze",
                vec![
                    text_field("path", "APK path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "apk.decompile",
                "Decompile",
                vec![
                    text_field("path", "APK path", ""),
                    text_field(
                        "output",
                        "Output dir (optional if case dir set)",
                        "./apk_out",
                    ),
                    choice_field(
                        "mode",
                        "Decompile mode",
                        "auto",
                        &["auto", "unpack", "apktool", "jadx", "hybrid"],
                    ),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "apk.vulnerability",
                "Vulnerability",
                vec![
                    text_field("path", "APK path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "apk.scan",
                "YARA scan",
                vec![
                    text_field("rule", "YARA rule", ""),
                    text_field("path", "Target APK", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
