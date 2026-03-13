use super::super::ModuleEntry;
use super::fields::{
    action, bool_field, case_dir_field, choice_field, module, number_field, text_field,
};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "forensics",
        "Forensics",
        vec![
            action(
                "forensics.snapshot",
                "Snapshot",
                vec![
                    text_field(
                        "output",
                        "Output path (optional if case dir set)",
                        "snapshot.tar",
                    ),
                    bool_field("full", "Full snapshot", false),
                    bool_field("encrypt", "Encrypt", false),
                    case_dir_field(),
                ],
                true,
                true,
            ),
            action(
                "forensics.sqlite",
                "SQLite analyzer",
                vec![
                    text_field("path", "SQLite path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.timeline",
                "Timeline",
                vec![
                    text_field("sms", "SMS JSON path (optional)", ""),
                    text_field("calls", "Call logs JSON path (optional)", ""),
                    text_field("browser", "Browser JSON path (optional)", ""),
                    text_field("messaging", "Messaging JSON path (optional)", ""),
                    text_field("media", "Media JSON path (optional)", ""),
                    text_field("location", "Location JSON path (optional)", ""),
                    text_field(
                        "parsed_artifacts",
                        "Parsed artifacts JSON path (optional)",
                        "",
                    ),
                    text_field(
                        "output",
                        "Output JSON path (optional if case dir set)",
                        "timeline.json",
                    ),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.parse",
                "Parse artifact directory",
                vec![
                    text_field("path", "Artifact or app-data directory", ""),
                    text_field(
                        "output",
                        "Output JSON path (optional if case dir set)",
                        "parsed_artifacts.json",
                    ),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.import_aleapp",
                "Import ALEAPP artifacts",
                vec![
                    text_field("input_dir", "ALEAPP output directory", ""),
                    text_field(
                        "output",
                        "Output JSON path (optional if case dir set)",
                        "aleapp_import.json",
                    ),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.decode_protobuf",
                "Decode protobuf blob",
                vec![
                    text_field("path", "Protobuf blob path", ""),
                    text_field(
                        "output",
                        "Output JSON path (optional if case dir set)",
                        "protobuf.json",
                    ),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.correlate",
                "Correlate artifacts",
                vec![
                    text_field("inputs", "JSON paths (comma)", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "forensics.recover",
                "Recover deleted",
                vec![
                    text_field("path", "SQLite path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                true,
            ),
            action(
                "forensics.carve",
                "Carve deleted files",
                vec![
                    text_field("path", "Image or SQLite path", ""),
                    text_field("output_dir", "Output directory", "carved-output"),
                    choice_field("source", "Source", "auto", &["auto", "image", "sqlite"]),
                    number_field("max_matches", "Max matches", "25"),
                    case_dir_field(),
                ],
                false,
                true,
            ),
            action(
                "report.generate",
                "Generate report",
                vec![
                    text_field("case_id", "Case ID", "CASE123"),
                    choice_field(
                        "template",
                        "Template",
                        "technical",
                        &["executive", "technical"],
                    ),
                    choice_field("format", "Format", "html", &["html", "pdf", "json", "csv"]),
                    text_field(
                        "output",
                        "Output path (optional if case dir set)",
                        "report.html",
                    ),
                    case_dir_field(),
                    text_field("artifacts", "Artifacts JSON path", ""),
                ],
                false,
                false,
            ),
            action(
                "report.chain_of_custody",
                "Chain of custody",
                vec![
                    text_field("case_id", "Case ID (optional if case dir set)", "CASE123"),
                    text_field(
                        "examiner",
                        "Examiner (optional if case dir set)",
                        "Investigator",
                    ),
                    text_field(
                        "evidence",
                        "Evidence paths CSV (optional if case dir set)",
                        "",
                    ),
                    text_field("notes", "Notes", ""),
                    text_field(
                        "output",
                        "Output path (optional if case dir set)",
                        "chain_of_custody.txt",
                    ),
                    choice_field("format", "Format", "text", &["text", "html"]),
                    bool_field("sign", "Detached-sign with GPG if available", false),
                    text_field("gpg_key_id", "GPG key ID (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "report.integrity",
                "Integrity report",
                vec![
                    case_dir_field(),
                    choice_field("format", "Format", "json", &["json", "text"]),
                    text_field(
                        "output",
                        "Output path (optional if case dir set)",
                        "integrity.json",
                    ),
                ],
                false,
                false,
            ),
        ],
    )
}
