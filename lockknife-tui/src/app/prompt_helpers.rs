use serde_json::Value;

use super::*;

pub(crate) fn summarize_feedback_text(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}…", shortened)
    } else {
        shortened
    }
}

pub(crate) fn set_prompt_field(fields: &mut [PromptField], key: &str, value: &str) {
    for field in fields.iter_mut() {
        if field.key == key {
            field.value = value.to_string();
        }
    }
}

pub(crate) fn fields_have_key(fields: &[PromptField], key: &str) -> bool {
    fields.iter().any(|field| field.key == key)
}

pub(crate) fn field_value<'a>(fields: &'a [PromptField], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.trim())
}

pub(crate) fn prefill_prompt_field_if_empty(fields: &mut [PromptField], key: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }

    for field in fields.iter_mut() {
        if field.key == key && field.value.trim().is_empty() {
            field.value = trimmed.to_string();
        }
    }
}

pub(crate) fn prefill_prompt_field_if_matches(
    fields: &mut [PromptField],
    key: &str,
    value: &str,
    matches: &[&str],
) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }

    for field in fields.iter_mut() {
        if field.key == key
            && matches
                .iter()
                .any(|candidate| field.value.trim() == candidate.trim())
        {
            field.value = trimmed.to_string();
        }
    }
}

pub(crate) fn insert_prompt_preflight_lines(
    action: &ModuleAction,
    preferred_device_serial: Option<&str>,
    help_lines: &mut Vec<String>,
) {
    let mut preflight_lines = Vec::new();

    if let Some(metadata) = action.capability_metadata().filter(|metadata| {
        matches!(
            metadata.status,
            "dependency-gated" | "best-effort" | "experimental"
        )
    }) {
        preflight_lines.push(format!(
            "Preflight: {} [{}] · requires {}.",
            metadata.status,
            capability_status_badge(metadata.status),
            metadata.requirements
        ));
    }

    if action.targets_device() {
        let device_line = match preferred_device_serial.filter(|value| !value.trim().is_empty()) {
            Some(device_serial) => {
                format!("Device target in this TUI session: {}.", device_serial)
            }
            None if action.id.starts_with("runtime.") => {
                "Device target: none selected yet — choose one in Devices or enter Device ID before running this runtime workflow."
                    .to_string()
            }
            None if action.requires_device => {
                "Device target: none selected yet — choose one in Devices before running this action."
                    .to_string()
            }
            None => {
                "Device target: none selected yet — choose one in Devices or fill the device field manually."
                    .to_string()
            }
        };
        preflight_lines.push(device_line);
    }

    if let Some(recovery_hint) = action.recovery_hint() {
        preflight_lines.push(recovery_hint.to_string());
    }

    let insert_index = if action.is_case_aware() && !help_lines.is_empty() {
        1
    } else {
        0
    };

    for (offset, line) in preflight_lines.into_iter().enumerate() {
        help_lines.insert(insert_index + offset, line);
    }
}

pub(crate) fn capability_status_badge(status: &str) -> &'static str {
    match status {
        "production-ready" => "ready",
        "functional" => "func",
        "best-effort" => "best",
        "experimental" => "exp",
        "dependency-gated" => "gated",
        "mixed" => "mixed",
        _ => "info",
    }
}

pub(crate) fn array_string_values(values: &[Value]) -> String {
    values
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn parent_path_hint(path: &str) -> String {
    path.rfind(['/', '\\'])
        .map(|idx| path[..idx].trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| path.trim().to_string())
}

pub(crate) fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || value.starts_with('.') || value.starts_with('~')
}

pub(crate) fn summarize_path(path: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let trimmed = path.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}…", shortened)
    } else {
        shortened
    }
}

pub(crate) fn summarize_feedback_query(query: &str, max_chars: usize) -> String {
    let trimmed = query.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("\"{}…\"", shortened)
    } else {
        format!("\"{}\"", shortened)
    }
}
