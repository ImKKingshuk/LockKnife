use super::super::{ModuleAction, ModuleEntry};
use super::fields::{
    action, bool_field, case_dir_field, choice_field, module, number_field, text_field,
};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "case",
        "Case Management",
        vec![
            init_action(),
            summary_action(),
            graph_action(),
            artifacts_action(),
            artifact_action(),
            lineage_action(),
            export_action(),
            enrich_action(),
            register_action(),
            jobs_action(),
            job_action(),
            resume_job_action(),
            retry_job_action(),
            runtime_sessions_action(),
            chain_of_custody_action(),
            integrity_action(),
        ],
    )
}

fn init_action() -> ModuleAction {
    action(
        "case.init",
        "Init workspace",
        vec![
            case_dir_field(),
            text_field("case_id", "Case ID", "CASE-001"),
            text_field("examiner", "Examiner", "Examiner"),
            text_field("title", "Title", "Investigation"),
            text_field("notes", "Notes", ""),
            text_field("target_serials", "Target serials (comma)", ""),
        ],
        false,
        false,
    )
}

fn summary_action() -> ModuleAction {
    action(
        "case.summary",
        "Summary",
        vec![
            case_dir_field(),
            text_field("categories", "Categories (comma)", ""),
            text_field("exclude_categories", "Exclude categories (comma)", ""),
            text_field("source_commands", "Source commands (comma)", ""),
            text_field("device_serials", "Device serials (comma)", ""),
        ],
        false,
        false,
    )
}

fn graph_action() -> ModuleAction {
    action(
        "case.graph",
        "Lineage graph",
        vec![
            case_dir_field(),
            text_field("categories", "Categories (comma)", ""),
            text_field("exclude_categories", "Exclude categories (comma)", ""),
            text_field("source_commands", "Source commands (comma)", ""),
            text_field("device_serials", "Device serials (comma)", ""),
        ],
        false,
        false,
    )
}

fn artifacts_action() -> ModuleAction {
    action(
        "case.artifacts",
        "Artifact search",
        vec![
            case_dir_field(),
            text_field("query", "Query", ""),
            text_field("path_contains", "Path contains", ""),
            text_field("metadata_contains", "Metadata contains", ""),
            text_field("categories", "Categories (comma)", ""),
            text_field("exclude_categories", "Exclude categories (comma)", ""),
            text_field("source_commands", "Source commands (comma)", ""),
            text_field("device_serials", "Device serials (comma)", ""),
            number_field("limit", "Limit", "100"),
        ],
        false,
        false,
    )
}

fn artifact_action() -> ModuleAction {
    action(
        "case.artifact",
        "Artifact detail",
        vec![
            case_dir_field(),
            text_field("artifact_id", "Artifact ID", ""),
            text_field("path", "Artifact path", ""),
        ],
        false,
        false,
    )
}

fn lineage_action() -> ModuleAction {
    action(
        "case.lineage",
        "Artifact lineage",
        vec![
            case_dir_field(),
            text_field("artifact_id", "Artifact ID", ""),
            text_field("path", "Artifact path", ""),
        ],
        false,
        false,
    )
}

fn export_action() -> ModuleAction {
    action(
        "case.export",
        "Export bundle",
        vec![
            case_dir_field(),
            text_field("output", "Output archive", ""),
            bool_field(
                "include_registered_artifacts",
                "Include registered artifacts",
                true,
            ),
            text_field("categories", "Categories (comma)", ""),
            text_field("exclude_categories", "Exclude categories (comma)", ""),
            text_field("source_commands", "Source commands (comma)", ""),
            text_field("device_serials", "Device serials (comma)", ""),
        ],
        false,
        false,
    )
}

fn enrich_action() -> ModuleAction {
    action(
        "case.enrich",
        "Enrichment bundle",
        vec![
            case_dir_field(),
            text_field("artifact_id", "Seed artifact ID (optional)", ""),
            text_field("categories", "Categories (comma)", ""),
            text_field("exclude_categories", "Exclude categories (comma)", ""),
            text_field("source_commands", "Source commands (comma)", ""),
            text_field("device_serials", "Device serials (comma)", ""),
            number_field("limit", "Artifact limit", "25"),
            number_field("reputation_limit", "Reputation lookup limit", "10"),
            text_field("output", "Output path (optional)", ""),
        ],
        false,
        false,
    )
}

fn register_action() -> ModuleAction {
    action(
        "case.register",
        "Register artifact",
        vec![
            case_dir_field(),
            text_field("path", "Artifact path", ""),
            text_field("category", "Category", "derived"),
            text_field("source_command", "Source command", "case register"),
            text_field("device_serial", "Device serial", ""),
            text_field("input_paths", "Input paths (comma)", ""),
            text_field("parent_artifact_ids", "Parent artifact IDs (comma)", ""),
            text_field("metadata_json", "Metadata JSON", ""),
            choice_field(
                "on_conflict",
                "On conflict",
                "auto",
                &["auto", "replace", "duplicate", "error"],
            ),
        ],
        false,
        false,
    )
}

fn jobs_action() -> ModuleAction {
    action(
        "case.jobs",
        "Job history",
        vec![
            case_dir_field(),
            text_field("statuses", "Statuses (comma)", ""),
            text_field("workflow_kinds", "Workflow kinds (comma)", ""),
            text_field("action_ids", "Action IDs (comma)", ""),
            text_field("query", "Search query", ""),
            number_field("limit", "Limit", "25"),
        ],
        false,
        false,
    )
}

fn job_action() -> ModuleAction {
    action(
        "case.job",
        "Job detail",
        vec![case_dir_field(), text_field("job_id", "Job ID", "")],
        false,
        false,
    )
}

fn resume_job_action() -> ModuleAction {
    action(
        "case.resume_job",
        "Resume job",
        vec![case_dir_field(), text_field("job_id", "Job ID", "")],
        false,
        true,
    )
}

fn retry_job_action() -> ModuleAction {
    action(
        "case.retry_job",
        "Retry job",
        vec![case_dir_field(), text_field("job_id", "Job ID", "")],
        false,
        true,
    )
}

fn runtime_sessions_action() -> ModuleAction {
    action(
        "case.runtime_sessions",
        "Runtime sessions",
        vec![
            case_dir_field(),
            text_field("session_id", "Session ID (optional)", ""),
            number_field("limit", "Limit", "50"),
        ],
        false,
        false,
    )
}

fn chain_of_custody_action() -> ModuleAction {
    action(
        "case.chain_of_custody",
        "Chain of custody",
        vec![
            case_dir_field(),
            text_field("output", "Output path (optional)", ""),
            choice_field("format", "Format", "json", &["json", "txt", "md"]),
        ],
        false,
        false,
    )
}

fn integrity_action() -> ModuleAction {
    action(
        "case.integrity",
        "Integrity report",
        vec![
            case_dir_field(),
            text_field("output", "Output path (optional)", ""),
            choice_field("format", "Format", "json", &["json", "txt", "md"]),
        ],
        false,
        false,
    )
}
