use serde_json::Value;

pub(super) fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub(super) fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || value.starts_with('.') || value.starts_with('~')
}

pub(super) fn nested_or_root_string(
    root: &serde_json::Map<String, Value>,
    nested: Option<&serde_json::Map<String, Value>>,
    key: &str,
) -> Option<String> {
    nested
        .and_then(|map| map.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn nested_or_root_array_len(
    root: &serde_json::Map<String, Value>,
    nested: Option<&serde_json::Map<String, Value>>,
    key: &str,
) -> usize {
    nested
        .and_then(|map| map.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0)
}

pub(super) fn first_nested_array_string(value: Option<&Value>, key: &str) -> Option<String> {
    value
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|item| item.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
