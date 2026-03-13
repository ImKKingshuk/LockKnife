use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "network",
        "Network",
        vec![
            action(
                "network.capture",
                "Capture PCAP",
                vec![
                    text_field(
                        "output",
                        "Output path (optional if case dir set)",
                        "capture.pcap",
                    ),
                    number_field("duration", "Duration (s)", "30"),
                    text_field("iface", "Interface", "any"),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "network.summarize",
                "Summarize PCAP",
                vec![
                    text_field("path", "PCAP path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "network.api_discovery",
                "API discovery",
                vec![
                    text_field("path", "PCAP path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
