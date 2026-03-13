use serde_json::Value;

pub(crate) fn build_forensics_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if let Some(summary) = root.get("summary").and_then(Value::as_object) {
        if root.get("tables").and_then(Value::as_array).is_some() {
            if let Some(table_count) = summary.get("table_count").and_then(Value::as_u64) {
                lines.push(format!("- SQLite tables: {}", table_count));
            }
            if let Some(index_count) = summary.get("index_count").and_then(Value::as_u64) {
                lines.push(format!("- Indexes: {}", index_count));
            }
            if let Some(wal) = root.get("wal").and_then(Value::as_object) {
                let exists = wal.get("exists").and_then(Value::as_bool).unwrap_or(false);
                lines.push(format!(
                    "- WAL present: {}",
                    if exists { "yes" } else { "no" }
                ));
            }
        }

        if root.get("events").and_then(Value::as_array).is_some() {
            if let Some(event_count) = root.get("event_count").and_then(Value::as_u64) {
                lines.push(format!("- Timeline events: {}", event_count));
            }
            if let Some(source_counts) = summary.get("source_counts").and_then(Value::as_object) {
                let preview = source_counts
                    .iter()
                    .take(4)
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect::<Vec<_>>()
                    .join(", ");
                if !preview.is_empty() {
                    lines.push(format!("- Sources: {}", preview));
                }
            }
        }

        if root.get("fragments").and_then(Value::as_array).is_some() {
            if let Some(fragment_count) = summary.get("fragment_count").and_then(Value::as_u64) {
                lines.push(format!("- Recovered fragments: {}", fragment_count));
            }
            if let Some(high_confidence) =
                summary.get("high_confidence_count").and_then(Value::as_u64)
            {
                lines.push(format!("- High-confidence fragments: {}", high_confidence));
            }
        }

        if root.get("artifacts").and_then(Value::as_array).is_some() {
            if let Some(artifact_count) = summary.get("artifact_count").and_then(Value::as_u64) {
                lines.push(format!("- Parsed artifact groups: {}", artifact_count));
            }
            if let Some(protobuf_count) = summary.get("protobuf_count").and_then(Value::as_u64) {
                lines.push(format!("- Protobuf/app blobs: {}", protobuf_count));
            }
            if let Some(app_data_count) = summary.get("app_data_count").and_then(Value::as_u64) {
                lines.push(format!("- App-data config files: {}", app_data_count));
            }
        }
    }

    if root.get("matches").and_then(Value::as_array).is_some() {
        let match_count = root
            .get("matches")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        lines.push(format!("- Correlation matches: {}", match_count));
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
