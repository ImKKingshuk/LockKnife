use std::path::PathBuf;

use serde_json::Value;

use super::results::build_result_view_content;
use super::*;

impl App {
    pub(crate) fn last_result_case_dir(&self) -> Option<String> {
        self.last_result_paths
            .iter()
            .find(|path| path.label == "Case directory")
            .map(|path| path.value.clone())
            .or_else(|| extract_case_dir_from_json(self.last_result_json.as_deref()))
    }

    pub(crate) fn latest_result_artifact_id(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(&value, &["artifact_id"], &["artifact", "artifact_id"])
                    .or_else(|| first_artifact_list_string(&value, "artifact_id"))
                    .or_else(|| first_graph_node_string(&value, "artifact_id"))
            })
    }

    pub(crate) fn latest_result_artifact_path(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(&value, &["path"], &["artifact", "path"])
                    .or_else(|| first_artifact_list_string(&value, "path"))
                    .or_else(|| first_graph_node_string(&value, "path"))
            })
            .filter(|value| looks_like_path(value))
    }

    pub(crate) fn latest_result_case_id(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                value
                    .as_object()
                    .and_then(|map| map.get("case_id"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
    }

    pub(crate) fn latest_result_apk_package(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(&value, &["package"], &["manifest", "package"])
            })
    }

    pub(crate) fn latest_case_job_id(&self) -> Option<String> {
        self.latest_case_job_id_by_status(&[])
    }

    pub(crate) fn latest_case_job_id_by_status(&self, statuses: &[&str]) -> Option<String> {
        self.last_job_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| job_id_from_value(&value, statuses))
            .or_else(|| {
                self.last_result_json
                    .as_deref()
                    .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                    .and_then(|value| first_job_id_from_value(&value, statuses))
            })
    }

    pub(crate) fn latest_runtime_session_id(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| runtime_session_id_from_value(&value))
    }

    pub(crate) fn latest_result_register_path(&self) -> Option<String> {
        self.latest_result_artifact_path().or_else(|| {
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
                if let Some(path) = self
                    .last_result_paths
                    .iter()
                    .find(|path| path.label == label && looks_like_path(&path.value))
                    .map(|path| path.value.clone())
                {
                    return Some(path);
                }
            }
            self.last_result_paths
                .iter()
                .find(|path| path.label != "Case directory" && looks_like_path(&path.value))
                .map(|path| path.value.clone())
        })
    }

    pub(crate) fn latest_result_search_path_hint(&self) -> Option<String> {
        self.latest_result_register_path()
            .map(|path| parent_path_hint(&path))
            .filter(|value| !value.trim().is_empty())
    }

    pub(crate) fn latest_result_artifact_category(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(&value, &["category"], &["artifact", "category"])
            })
    }

    pub(crate) fn latest_result_source_command(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(
                    &value,
                    &["source_command"],
                    &["artifact", "source_command"],
                )
            })
    }

    pub(crate) fn latest_result_device_serial(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_from_value(&value, &["device_serial"], &["artifact", "device_serial"])
            })
    }

    pub(crate) fn latest_result_input_paths_csv(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_array_from_value(
                    &value,
                    &["input_paths"],
                    &["artifact", "input_paths"],
                )
            })
    }

    pub(crate) fn latest_result_parent_artifact_ids_csv(&self) -> Option<String> {
        self.last_result_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| {
                nested_string_array_from_value(
                    &value,
                    &["parent_artifact_ids"],
                    &["artifact", "parent_artifact_ids"],
                )
            })
    }

    pub fn start_result_view(&mut self) -> bool {
        if let Some(json) = self.last_result_json.clone() {
            let path_count = self.last_result_paths.len();
            let title = if path_count == 0 {
                "Result".to_string()
            } else {
                format!(
                    "Result · {} key path{}",
                    path_count,
                    if path_count == 1 { "" } else { "s" }
                )
            };
            let content = build_result_view_content(
                self.last_result_message.as_deref(),
                &self.last_result_paths,
                &json,
                self.active_case_dir(),
            );
            let line_count = content.lines().count().max(1).min(u16::MAX as usize) as u16;
            let section_starts = content
                .lines()
                .enumerate()
                .filter_map(|(idx, line)| match line.trim() {
                    "Summary" | "Diagnostics" | "Recovery hints" | "Case context"
                    | "Job context" | "Artifact context" | "APK context" | "Enrichment context"
                    | "Reporting context" | "Runtime context" | "Follow-up actions"
                    | "Playbook guide" | "Key paths" | "JSON" => {
                        Some(idx.min(u16::MAX as usize) as u16)
                    }
                    _ => None,
                })
                .collect();
            self.overlay = Overlay::ResultView(ResultViewState {
                title,
                content,
                scroll: 0,
                line_count,
                section_starts,
            });
            true
        } else {
            let message = "No result available yet — run an action first, then press v.";
            self.push_log("info", message);
            self.push_toast("info", message);
            false
        }
    }

    pub fn copy_last_result(&self) -> bool {
        let Some(content) = self.last_result_json.clone() else {
            return false;
        };
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            return clipboard.set_text(content).is_ok();
        }
        false
    }
}

pub(crate) fn case_dir_from_value(value: &Value) -> Option<String> {
    value
        .as_object()
        .and_then(|map| map.get("case_dir"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn extract_case_dir_from_json(data: Option<&str>) -> Option<String> {
    let raw = data?;
    let value = serde_json::from_str::<Value>(raw).ok()?;
    value
        .as_object()
        .and_then(|map| map.get("case_dir"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn derive_case_id_from_dir(case_dir: &str) -> String {
    PathBuf::from(case_dir)
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("CASE")
        .to_string()
}

pub(crate) fn nested_string_from_value(
    value: &Value,
    root_path: &[&str],
    nested_path: &[&str],
) -> Option<String> {
    value_at_path(value, nested_path)
        .or_else(|| value_at_path(value, root_path))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn first_artifact_list_string(value: &Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|map| map.get("artifacts"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|artifact| artifact.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn first_graph_node_string(value: &Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|map| map.get("nodes"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|node| node.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn job_id_from_value(value: &Value, statuses: &[&str]) -> Option<String> {
    let status_matches = |job: &serde_json::Map<String, Value>| {
        if statuses.is_empty() {
            return true;
        }
        job.get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .map(|status| statuses.iter().any(|wanted| wanted == &status))
            .unwrap_or(false)
    };

    if let Some(job) = value.as_object() {
        if job.contains_key("job_id") && status_matches(job) {
            return job
                .get("job_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }
    }

    value
        .as_object()
        .and_then(|map| map.get("job"))
        .and_then(Value::as_object)
        .filter(|job| status_matches(job))
        .and_then(|job| job.get("job_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn first_job_id_from_value(value: &Value, statuses: &[&str]) -> Option<String> {
    job_id_from_value(value, statuses).or_else(|| {
        value
            .as_object()
            .into_iter()
            .flat_map(|map| [map.get("recent_jobs"), map.get("jobs")])
            .flatten()
            .find_map(|jobs| first_job_list_id(jobs, statuses))
    })
}

pub(crate) fn first_job_list_id(value: &Value, statuses: &[&str]) -> Option<String> {
    value.as_array().into_iter().flatten().find_map(|item| {
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
}

pub(crate) fn runtime_session_id_from_value(value: &Value) -> Option<String> {
    nested_string_from_value(value, &["session_id"], &["session", "session_id"])
        .or_else(|| first_runtime_session_id_from_lists(value))
}

pub(crate) fn first_runtime_session_id_from_lists(value: &Value) -> Option<String> {
    value
        .as_object()
        .and_then(|map| {
            ["sessions", "recent_runtime_sessions"]
                .into_iter()
                .filter_map(|key| map.get(key))
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

pub(crate) fn nested_string_array_from_value(
    value: &Value,
    root_path: &[&str],
    nested_path: &[&str],
) -> Option<String> {
    value_at_path(value, nested_path)
        .or_else(|| value_at_path(value, root_path))
        .and_then(Value::as_array)
        .map(|values| array_string_values(values))
        .filter(|value| !value.is_empty())
}

pub(crate) fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.as_object()?.get(*key)?;
    }
    Some(current)
}

pub(crate) fn device_refresh_feedback(device_count: usize) -> String {
    match device_count {
        0 => "Device refresh complete — no devices detected.".to_string(),
        1 => "Device refresh complete — 1 device detected.".to_string(),
        count => format!("Device refresh complete — {} devices detected.", count),
    }
}
