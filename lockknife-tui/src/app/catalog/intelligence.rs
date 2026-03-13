use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "intelligence",
        "Intelligence",
        vec![
            action(
                "intelligence.ioc",
                "IOC detection",
                vec![
                    text_field("input", "Input JSON path", ""),
                    text_field(
                        "composite_rules",
                        "Composite rules JSON path (optional)",
                        "",
                    ),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.cve",
                "CVE correlation",
                vec![
                    text_field("package", "Package name", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.virustotal",
                "VirusTotal lookup",
                vec![
                    text_field("hash", "SHA256 (optional)", ""),
                    text_field("url", "URL (optional)", ""),
                    text_field("domain", "Domain (optional)", ""),
                    text_field("ip", "IPv4 address (optional)", ""),
                    text_field("submit_url", "Submit URL for analysis (optional)", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.cve_risk",
                "Android/kernel CVE risk",
                vec![
                    text_field("sdk", "Android SDK level (optional)", "34"),
                    text_field("kernel_version", "Kernel version (optional)", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.otx",
                "OTX reputation",
                vec![
                    text_field("indicator", "Indicator", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.stix",
                "STIX feed",
                vec![
                    text_field("url", "STIX URL", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "intelligence.taxii",
                "TAXII feed",
                vec![
                    text_field("api_root", "API root URL", ""),
                    text_field("collection_id", "Collection ID", ""),
                    text_field("token", "Bearer token", ""),
                    text_field("username", "Username", ""),
                    text_field("password", "Password", ""),
                    text_field("added_after", "Added after (ISO)", ""),
                    number_field("limit", "Limit", "2000"),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
