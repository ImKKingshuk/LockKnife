use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "security",
        "Security Audit",
        vec![
            action(
                "security.audit",
                "Device audit",
                vec![
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "security.selinux",
                "SELinux status",
                vec![
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "security.malware",
                "Malware scan",
                vec![
                    text_field("rule", "YARA rule", ""),
                    text_field("target", "Target path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                true,
            ),
            action(
                "security.network_scan",
                "Network scan",
                vec![
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "security.bootloader",
                "Bootloader",
                vec![
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "security.hardware",
                "Hardware security",
                vec![
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                true,
                false,
            ),
            action(
                "security.attack_surface",
                "Attack surface",
                vec![
                    text_field("package", "Package name for live probes (optional)", ""),
                    text_field("serial", "Device serial for safe probes (optional)", ""),
                    text_field("apk", "APK path (optional)", ""),
                    text_field(
                        "artifacts",
                        "APK analysis or attack-surface JSON path (optional)",
                        "",
                    ),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "security.owasp",
                "OWASP MASTG mapping",
                vec![
                    text_field("artifacts", "Artifacts JSON path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
