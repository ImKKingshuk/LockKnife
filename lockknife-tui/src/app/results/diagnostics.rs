use std::collections::BTreeSet;

use serde_json::Value;

use super::common::yes_no;

pub(super) fn build_diagnostics_summary_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    if let Some(checks) = root.get("checks").and_then(Value::as_object) {
        let total_checks = checks.len();
        let passing_checks = checks.values().filter(|value| value_is_ok(value)).count();
        let failing_checks = failing_entry_names(checks);
        let mut lines = Vec::new();

        if let Some(full_ok) = root.get("full_ok").and_then(Value::as_bool) {
            lines.push(format!(
                "- Core baseline ready: {} · Optional coverage ready: {}",
                yes_no(root.get("ok").and_then(Value::as_bool).unwrap_or(false)),
                yes_no(full_ok)
            ));
            if let Some(python) = root
                .get("python")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                lines.push(format!("- Python: {}", python));
            }
            if let Some(optional) = root.get("optional").and_then(Value::as_object) {
                let total_optional = optional.len();
                let passing_optional = optional.values().filter(|value| value_is_ok(value)).count();
                lines.push(format!(
                    "- Checks passing: core {}/{} · optional {}/{}",
                    passing_checks, total_checks, passing_optional, total_optional
                ));
                let blockers = failing_entry_names(optional);
                if !blockers.is_empty() {
                    lines.push(format!(
                        "- Optional blockers: {}",
                        blockers.into_iter().take(4).collect::<Vec<_>>().join(", ")
                    ));
                }
            } else {
                lines.push(format!(
                    "- Core checks passing: {}/{}",
                    passing_checks, total_checks
                ));
            }
        } else {
            lines.push(format!(
                "- Baseline ready: {}",
                yes_no(root.get("ok").and_then(Value::as_bool).unwrap_or(false))
            ));
            lines.push(format!(
                "- Checks passing: {}/{}",
                passing_checks, total_checks
            ));
            if !failing_checks.is_empty() {
                lines.push(format!(
                    "- Failing checks: {}",
                    failing_checks
                        .into_iter()
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }

        return Some(lines.join("\n"));
    }

    let features = root.get("features").and_then(Value::as_array)?;
    let summary = root.get("summary").and_then(Value::as_object);
    let mut lines = vec![format!("- Features tracked: {}", features.len())];
    let statuses = [
        "production-ready",
        "functional",
        "best-effort",
        "experimental",
        "dependency-gated",
    ];
    let mix = statuses
        .iter()
        .filter_map(|status| {
            summary
                .and_then(|rows| rows.get(*status))
                .and_then(Value::as_u64)
                .map(|count| format!("{} {}", count, status))
        })
        .collect::<Vec<_>>();
    if !mix.is_empty() {
        lines.push(format!("- Status mix: {}", mix.join(" · ")));
    }
    if summary
        .and_then(|rows| rows.get("dependency-gated"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        lines.push(
            "- Next: open Dependency doctor before relying on dependency-gated workflows."
                .to_string(),
        );
    }
    Some(lines.join("\n"))
}

pub(super) fn build_recovery_hints_section(parsed: Option<&Value>) -> Option<String> {
    let mut hints = BTreeSet::new();
    collect_failure_hints(parsed?, &mut hints);
    if hints.is_empty() {
        None
    } else {
        Some(
            hints
                .into_iter()
                .take(6)
                .map(|hint| format!("- {}", hint))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

fn collect_failure_hints(value: &Value, hints: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            let failed = map.get("ok").and_then(Value::as_bool) == Some(false)
                || map.get("configured").and_then(Value::as_bool) == Some(false)
                || map.get("installed").and_then(Value::as_bool) == Some(false);
            if failed {
                if let Some(hint) = map
                    .get("hint")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    hints.insert(hint.to_string());
                }
            }
            for child in map.values() {
                collect_failure_hints(child, hints);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_failure_hints(item, hints);
            }
        }
        _ => {}
    }
}

fn value_is_ok(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|map| {
            map.get("ok")
                .and_then(Value::as_bool)
                .or_else(|| map.get("configured").and_then(Value::as_bool))
        })
        .unwrap_or(false)
}

fn failing_entry_names(entries: &serde_json::Map<String, Value>) -> Vec<String> {
    entries
        .iter()
        .filter_map(|(name, value)| {
            if value_is_ok(value) {
                None
            } else {
                Some(name.replace('_', " "))
            }
        })
        .collect()
}
