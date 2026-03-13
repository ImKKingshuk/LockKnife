use serde_json::Value;

use super::common::{first_nested_array_string, looks_like_path, nested_or_root_string};
use super::ResultPath;

pub(super) fn extract_case_dir_from_value(parsed: Option<&Value>) -> Option<String> {
    parsed
        .and_then(Value::as_object)
        .and_then(|map| map.get("case_dir"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn extract_runtime_session_id(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    root.get("session_id")
        .and_then(Value::as_str)
        .or_else(|| {
            root.get("session")
                .and_then(Value::as_object)
                .and_then(|session| session.get("session_id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            ["sessions", "recent_runtime_sessions"]
                .into_iter()
                .filter_map(|key| root.get(key))
                .find_map(|value| {
                    value
                        .as_array()
                        .and_then(|items| items.first())
                        .and_then(Value::as_object)
                        .and_then(|session| session.get("session_id"))
                        .and_then(Value::as_str)
                })
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn extract_apk_package(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    nested_or_root_string(
        root,
        root.get("manifest").and_then(Value::as_object),
        "package",
    )
}

pub(super) fn extract_artifact_string(parsed: Option<&Value>, key: &str) -> Option<String> {
    let root = parsed?.as_object()?;
    let artifact = root.get("artifact").and_then(Value::as_object);
    nested_or_root_string(root, artifact, key)
        .or_else(|| first_nested_array_string(root.get("artifacts"), key))
        .or_else(|| first_nested_array_string(root.get("nodes"), key))
}

pub(super) fn first_job_object(value: Option<&Value>) -> Option<&serde_json::Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
}

pub(super) fn first_job_id(parsed: Option<&Value>, statuses: &[&str]) -> Option<String> {
    let root = parsed?.as_object()?;
    if let Some(job) = root.get("job").and_then(Value::as_object) {
        let status = job.get("status").and_then(Value::as_str).map(str::trim);
        if statuses.is_empty()
            || status
                .map(|status| statuses.iter().any(|wanted| wanted == &status))
                .unwrap_or(false)
        {
            return job
                .get("job_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }
    }

    for key in ["recent_jobs", "jobs"] {
        if let Some(job_id) = root.get(key).and_then(Value::as_array).and_then(|jobs| {
            jobs.iter().find_map(|item| {
                let job = item.as_object()?;
                if !statuses.is_empty() {
                    let status = job.get("status").and_then(Value::as_str).map(str::trim)?;
                    if !statuses.iter().any(|wanted| wanted == &status) {
                        return None;
                    }
                }
                job.get("job_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
        }) {
            return Some(job_id);
        }
    }
    None
}

pub(super) fn latest_register_path(paths: &[ResultPath]) -> Option<String> {
    for label in [
        "Decompile report",
        "Manifest",
        "Output",
        "Output directory",
        "Session summary",
        "Session log",
        "Preview log",
        "Script snapshot",
        "Remote output",
    ] {
        if let Some(path) = paths
            .iter()
            .find(|path| path.label == label && looks_like_path(&path.value))
            .map(|path| path.value.clone())
        {
            return Some(path);
        }
    }

    paths
        .iter()
        .find(|path| path.label != "Case directory" && looks_like_path(&path.value))
        .map(|path| path.value.clone())
}

pub(super) fn parent_path_hint(path: &str) -> String {
    let separator_index = path.rfind('/').or_else(|| path.rfind('\\'));
    separator_index
        .map(|idx| &path[..idx])
        .unwrap_or(path)
        .trim()
        .to_string()
}

pub(super) fn extract_result_paths(
    message: Option<&str>,
    data_json: Option<&str>,
) -> Vec<ResultPath> {
    let mut paths = Vec::new();
    if let Some(data_json) = data_json {
        if let Ok(value) = serde_json::from_str::<Value>(data_json) {
            collect_result_paths_from_value(&value, &mut paths);
        }
    }
    if let Some(message) = message {
        if let Some(path) = extract_path_from_message(message) {
            push_result_path(&mut paths, path);
        }
    }
    paths
}

fn collect_result_paths_from_value(value: &Value, out: &mut Vec<ResultPath>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if let Some(label) = result_path_label(key) {
                    if let Some(path) = value.as_str() {
                        if looks_like_path(path) {
                            push_result_path(
                                out,
                                ResultPath {
                                    label: label.to_string(),
                                    value: path.to_string(),
                                },
                            );
                        }
                    }
                }
                collect_result_paths_from_value(value, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_result_paths_from_value(item, out);
            }
        }
        _ => {}
    }
}

fn result_path_label(key: &str) -> Option<&'static str> {
    match key {
        "output" => Some("Output"),
        "output_dir" => Some("Output directory"),
        "case_dir" => Some("Case directory"),
        "message_log_path" => Some("Preview log"),
        "logs_path" => Some("Session log"),
        "summary_path" => Some("Session summary"),
        "script_snapshot_path" => Some("Script snapshot"),
        "manifest_path" => Some("Manifest"),
        "report_path" => Some("Decompile report"),
        "remote_output_path" => Some("Remote output"),
        _ => None,
    }
}

fn extract_path_from_message(message: &str) -> Option<ResultPath> {
    for (marker, label) in [
        (" saved to ", "Output"),
        (" written to ", "Output"),
        (" ready at ", "Case directory"),
        (" ready for ", "Case directory"),
        (" to ", "Output"),
    ] {
        if let Some(path) = extract_path_after_marker(message, marker) {
            return Some(ResultPath {
                label: label.to_string(),
                value: path,
            });
        }
    }
    None
}

fn extract_path_after_marker(message: &str, marker: &str) -> Option<String> {
    let (_, tail) = message.rsplit_once(marker)?;
    let candidate = tail
        .trim()
        .trim_start_matches(['"', '\''])
        .trim_end_matches(['"', '\'', '.', ',', ';']);
    if looks_like_path(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn push_result_path(paths: &mut Vec<ResultPath>, path: ResultPath) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}
