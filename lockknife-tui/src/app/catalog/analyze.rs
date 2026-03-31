use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "analyze",
        "Analysis",
        vec![action(
            "analyze.evidence",
            "Analyze evidence directory",
            vec![
                text_field("input_dir", "Input directory", ""),
                text_field("patterns", "Patterns (comma, optional)", ""),
                text_field("output", "Output path (optional)", ""),
                case_dir_field(),
            ],
            false,
            false,
        )],
    )
}
