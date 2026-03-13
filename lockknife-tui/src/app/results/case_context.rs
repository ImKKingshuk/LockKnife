use serde_json::Value;

use super::common::{looks_like_path, nested_or_root_array_len, nested_or_root_string};
use super::paths::{extract_case_dir_from_value, first_job_object};
use super::ResultPath;

pub(super) fn build_case_context_section(
    paths: &[ResultPath],
    parsed: Option<&Value>,
    active_case_dir: Option<&str>,
) -> Option<String> {
    let result_case_dir = paths
        .iter()
        .find(|path| path.label == "Case directory")
        .map(|path| path.value.clone())
        .or_else(|| extract_case_dir_from_value(parsed));

    let managed_root = result_case_dir.as_deref().or(active_case_dir);
    let managed_outputs = managed_root
        .map(|root| {
            paths
                .iter()
                .filter(|path| path.label != "Case directory" && path.value.starts_with(root))
                .count()
        })
        .unwrap_or(0);

    let mut lines = Vec::new();
    if let Some(active_case_dir) = active_case_dir.filter(|value| !value.trim().is_empty()) {
        lines.push(format!("- Active case: {}", active_case_dir));
    }
    if let Some(result_case_dir) = result_case_dir.as_deref() {
        if active_case_dir != Some(result_case_dir) {
            lines.push(format!("- Result case directory: {}", result_case_dir));
        }
    }
    if managed_outputs > 0 {
        lines.push(format!("- Managed outputs detected: {}", managed_outputs));
    }
    if result_case_dir.is_some() || active_case_dir.is_some() {
        lines.push(
            "- Next: open Case Management → Summary or Artifact search to inspect the workspace."
                .to_string(),
        );
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

pub(super) fn build_job_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if let Some(jobs) = root.get("jobs").and_then(Value::as_object) {
        let total = jobs.get("total").and_then(Value::as_u64).unwrap_or(0);
        if total > 0 {
            lines.push(format!(
                "- Persisted jobs: {} total · {} running · {} ok · {} partial · {} failed · {} resumable",
                total,
                jobs.get("running").and_then(Value::as_u64).unwrap_or(0),
                jobs.get("succeeded").and_then(Value::as_u64).unwrap_or(0),
                jobs.get("partial").and_then(Value::as_u64).unwrap_or(0),
                jobs.get("failed").and_then(Value::as_u64).unwrap_or(0),
                jobs.get("resumable").and_then(Value::as_u64).unwrap_or(0),
            ));
        }
    }

    if let Some(job) = root.get("job").and_then(Value::as_object) {
        if let Some(job_id) = job.get("job_id").and_then(Value::as_str) {
            let action = job
                .get("action_label")
                .or_else(|| job.get("action_id"))
                .and_then(Value::as_str)
                .unwrap_or("job");
            let status = job
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let attempts = job
                .get("attempt_count")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            lines.push(format!(
                "- Latest job: {} · {} · status {} · {} attempt(s)",
                job_id, action, status, attempts
            ));
            if let Some(recovery) = job
                .get("recovery_hint")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                lines.push(format!("- Recovery: {}", recovery));
            }
        }
    } else if let Some(job) = first_job_object(root.get("recent_jobs")) {
        if let Some(job_id) = job.get("job_id").and_then(Value::as_str) {
            let action = job
                .get("action_label")
                .or_else(|| job.get("action_id"))
                .and_then(Value::as_str)
                .unwrap_or("job");
            let status = job
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            lines.push(format!(
                "- Recent job: {} · {} · status {}",
                job_id, action, status
            ));
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

pub(super) fn build_artifact_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let artifact = root.get("artifact").and_then(Value::as_object);
    let artifact_id = nested_or_root_string(root, artifact, "artifact_id");
    let artifact_path =
        nested_or_root_string(root, artifact, "path").filter(|path| looks_like_path(path));
    let category = nested_or_root_string(root, artifact, "category");
    let source_command = nested_or_root_string(root, artifact, "source_command");
    let registration_action = root
        .get("registration_action")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let input_count = nested_or_root_array_len(root, artifact, "input_paths");
    let parent_id_count = nested_or_root_array_len(root, artifact, "parent_artifact_ids");
    let parent_count = root
        .get("parents")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let child_count = root
        .get("children")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let missing_parent_count = root
        .get("missing_parent_ids")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let artifact_count = root
        .get("artifact_count")
        .and_then(Value::as_u64)
        .map(|value| value.min(usize::MAX as u64) as usize);
    let total_artifact_count = root
        .get("total_artifact_count")
        .and_then(Value::as_u64)
        .map(|value| value.min(usize::MAX as u64) as usize);
    let root_artifact_count = root
        .get("root_artifact_ids")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let node_count = root
        .get("nodes")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let edge_count = root
        .get("edges")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let has_search_results = artifact_count.is_some();

    let mut lines = Vec::new();
    match (artifact_id.as_deref(), registration_action.as_deref()) {
        (Some(artifact_id), Some(action)) => {
            lines.push(format!(
                "- Artifact: {} · registration {}",
                artifact_id, action
            ));
        }
        (Some(artifact_id), None) => lines.push(format!("- Artifact: {}", artifact_id)),
        (None, Some(action)) => lines.push(format!("- Registration action: {}", action)),
        (None, None) => {}
    }
    if let Some(path) = artifact_path {
        lines.push(format!("- Artifact path: {}", path));
    }
    if category.is_some() || source_command.is_some() {
        lines.push(format!(
            "- Classification: {} · Source: {}",
            category.unwrap_or_else(|| "unknown".to_string()),
            source_command.unwrap_or_else(|| "unknown".to_string())
        ));
    }
    if input_count > 0 || parent_id_count > 0 {
        lines.push(format!(
            "- Inputs: {} · parent artifact IDs: {}",
            input_count, parent_id_count
        ));
    }
    if parent_count.is_some() || child_count.is_some() || missing_parent_count.is_some() {
        lines.push(format!(
            "- Lineage: parents {} · children {} · missing parents {}",
            parent_count.unwrap_or(0),
            child_count.unwrap_or(0),
            missing_parent_count.unwrap_or(0)
        ));
    }
    if let Some(artifact_count) = artifact_count {
        lines.push(format!(
            "- Search results: {} of {} artifacts",
            artifact_count,
            total_artifact_count.unwrap_or(artifact_count)
        ));
    }
    if root_artifact_count.is_some() || node_count.is_some() || edge_count.is_some() {
        lines.push(format!(
            "- Graph: roots {} · nodes {} · edges {}",
            root_artifact_count.unwrap_or(0),
            node_count.unwrap_or(0),
            edge_count.unwrap_or(0)
        ));
    }
    if let Some(artifact_id) = artifact_id {
        lines.push(format!(
            "- Next: open Case Management → Artifact detail or Lineage with {}.",
            artifact_id
        ));
    } else if has_search_results {
        lines.push(
            "- Next: open Case Management → Artifact detail on a returned artifact ID.".to_string(),
        );
    } else if root_artifact_count.is_some() || node_count.is_some() || edge_count.is_some() {
        lines.push(
            "- Next: open Case Management → Artifact detail or Lineage to inspect graph nodes."
                .to_string(),
        );
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
