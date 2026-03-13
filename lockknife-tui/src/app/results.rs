use serde_json::Value;

use super::ResultPath;

mod analysis_context;
mod apk_context;
mod case_context;
mod common;
mod diagnostics;
mod enrichment_context;
mod followups;
mod forensics_context;
mod paths;
mod playbook_context;
mod reporting_context;
mod runtime_context;
mod security_context;

use self::analysis_context::build_analysis_context_section;
use self::apk_context::build_apk_context_section;
use self::case_context::{
    build_artifact_context_section, build_case_context_section, build_job_context_section,
};
use self::diagnostics::{build_diagnostics_summary_section, build_recovery_hints_section};
use self::enrichment_context::build_enrichment_context_section;
use self::followups::build_follow_up_actions_section;
use self::forensics_context::build_forensics_context_section;
use self::playbook_context::build_playbook_context_section;
use self::reporting_context::build_reporting_context_section;
use self::runtime_context::build_runtime_context_section;
use self::security_context::build_security_context_section;

pub(crate) fn build_result_view_content(
    message: Option<&str>,
    paths: &[ResultPath],
    json: &str,
    active_case_dir: Option<&str>,
) -> String {
    let parsed = serde_json::from_str::<Value>(json).ok();
    let mut sections = Vec::new();
    if let Some(message) = message {
        let trimmed = message.trim();
        if !trimmed.is_empty() {
            sections.push(format!("Summary\n{}", trimmed));
        }
    }
    if let Some(diagnostics) = build_diagnostics_summary_section(parsed.as_ref()) {
        sections.push(format!("Diagnostics\n{}", diagnostics));
    }
    if let Some(hints) = build_recovery_hints_section(parsed.as_ref()) {
        sections.push(format!("Recovery hints\n{}", hints));
    }
    if let Some(case_context) = build_case_context_section(paths, parsed.as_ref(), active_case_dir)
    {
        sections.push(format!("Case context\n{}", case_context));
    }
    if let Some(job_context) = build_job_context_section(parsed.as_ref()) {
        sections.push(format!("Job context\n{}", job_context));
    }
    if let Some(artifact_context) = build_artifact_context_section(parsed.as_ref()) {
        sections.push(format!("Artifact context\n{}", artifact_context));
    }
    if let Some(apk_context) = build_apk_context_section(parsed.as_ref()) {
        sections.push(format!("APK context\n{}", apk_context));
    }
    if let Some(enrichment_context) = build_enrichment_context_section(parsed.as_ref()) {
        sections.push(format!("Enrichment context\n{}", enrichment_context));
    }
    if let Some(analysis_context) = build_analysis_context_section(parsed.as_ref()) {
        sections.push(format!("Analysis context\n{}", analysis_context));
    }
    if let Some(forensics_context) = build_forensics_context_section(parsed.as_ref()) {
        sections.push(format!("Forensics context\n{}", forensics_context));
    }
    if let Some(security_context) = build_security_context_section(parsed.as_ref()) {
        sections.push(format!("Security context\n{}", security_context));
    }
    if let Some(reporting_context) = build_reporting_context_section(parsed.as_ref()) {
        sections.push(format!("Reporting context\n{}", reporting_context));
    }
    if let Some(runtime_context) = build_runtime_context_section(parsed.as_ref()) {
        sections.push(format!("Runtime context\n{}", runtime_context));
    }
    if let Some(follow_up_actions) =
        build_follow_up_actions_section(paths, parsed.as_ref(), active_case_dir)
    {
        sections.push(format!("Follow-up actions\n{}", follow_up_actions));
    }
    if let Some(playbook_context) =
        build_playbook_context_section(paths, parsed.as_ref(), active_case_dir)
    {
        sections.push(format!("Playbook guide\n{}", playbook_context));
    }
    if !paths.is_empty() {
        let lines = paths
            .iter()
            .map(|path| format!("- {}: {}", path.label, path.value))
            .collect::<Vec<_>>()
            .join("\n");
        sections.push(format!("Key paths\n{}", lines));
    }
    sections.push(format!("JSON\n{}", pretty_result_json(json)));
    sections.join("\n\n")
}

pub(crate) fn extract_result_paths(
    message: Option<&str>,
    data_json: Option<&str>,
) -> Vec<ResultPath> {
    self::paths::extract_result_paths(message, data_json)
}

fn pretty_result_json(json: &str) -> String {
    serde_json::from_str::<Value>(json)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| json.to_string())
}
