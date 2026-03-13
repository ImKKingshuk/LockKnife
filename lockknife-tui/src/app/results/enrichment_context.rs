use serde_json::Value;

use super::common::yes_no;

pub(super) fn build_enrichment_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if let Some(summary) = root.get("summary").and_then(Value::as_object) {
        let selected = summary
            .get("selected_artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let workflows = summary
            .get("workflow_run_count")
            .or_else(|| summary.get("completed_workflows"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let skipped = summary
            .get("skipped_artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if selected > 0 || workflows > 0 || skipped > 0 {
            lines.push(format!(
                "- Bundle summary: {} artifact(s) selected · {} workflow run(s) · {} skipped",
                selected, workflows, skipped
            ));
        }
        if let Some(features) = summary.get("feature_keys").and_then(Value::as_array) {
            let labels = features
                .iter()
                .filter_map(Value::as_str)
                .take(5)
                .collect::<Vec<_>>();
            if !labels.is_empty() {
                lines.push(format!("- AI features: {}", labels.join(", ")));
            }
        }
    }

    if let Some(providers) = root
        .get("provider_status")
        .or_else(|| root.get("source_attribution"))
        .and_then(Value::as_array)
    {
        let details = providers
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|provider| {
                let name = provider.get("provider").and_then(Value::as_str)?;
                let credentials = provider.get("credentials").and_then(Value::as_object);
                let cache = provider.get("cache").and_then(Value::as_object);
                let configured = credentials
                    .and_then(|value| value.get("configured"))
                    .and_then(Value::as_bool)
                    .map(yes_no)
                    .unwrap_or("n/a");
                let cache_mode = cache
                    .and_then(|value| value.get("mode"))
                    .and_then(Value::as_str)
                    .unwrap_or("none");
                Some(format!(
                    "{} (creds {} · cache {})",
                    name, configured, cache_mode
                ))
            })
            .take(4)
            .collect::<Vec<_>>();
        if !details.is_empty() {
            lines.push(format!("- Providers: {}", details.join(" · ")));
        }
    }

    if let Some(explainability) = root.get("explainability").and_then(Value::as_object) {
        if let Some(top_rows) = explainability.get("top_rows").and_then(Value::as_array) {
            if let Some(first) = top_rows.first().and_then(Value::as_object) {
                let score = first
                    .get("anomaly_score")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                let drivers = first
                    .get("top_contributors")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_object)
                            .filter_map(|item| item.get("feature").and_then(Value::as_str))
                            .take(3)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if !drivers.is_empty() {
                    lines.push(format!(
                        "- Anomaly explainability: top score {:.3} driven by {}",
                        score,
                        drivers.join(", ")
                    ));
                }
            }
        }
        if let Some(prefixes) = explainability.get("top_prefixes").and_then(Value::as_array) {
            let values = prefixes
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| item.get("token").and_then(Value::as_str))
                .take(3)
                .collect::<Vec<_>>();
            if !values.is_empty() {
                lines.push(format!(
                    "- Password model hints: common prefixes {}",
                    values.join(", ")
                ));
            }
        }
    }

    if let Some(runs) = root.get("runs").and_then(Value::as_array) {
        let count = runs.len();
        if count > 0 {
            lines.push(format!(
                "- Workflow details captured: {} run entries",
                count
            ));
        }
    }

    if let Some(advisory) = root.get("advisory").and_then(Value::as_str) {
        let trimmed = advisory.trim();
        if !trimmed.is_empty() {
            lines.push(format!("- Advisory: {}", trimmed));
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
