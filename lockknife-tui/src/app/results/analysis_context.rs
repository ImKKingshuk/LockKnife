use serde_json::Value;

pub(super) fn build_analysis_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if root.contains_key("http") || root.contains_key("dns") || root.contains_key("tls") {
        let summary = root.get("summary").and_then(Value::as_object);
        let endpoints = summary
            .and_then(|value| value.get("endpoint_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let hosts = summary
            .and_then(|value| value.get("host_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let http_requests = summary
            .and_then(|value| value.get("http_request_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Network summary: {} endpoint(s) · {} host(s) · {} HTTP request hint(s)",
            endpoints, hosts, http_requests
        ));
        if let Some(groups) = root.get("endpoint_groups").and_then(Value::as_array) {
            if let Some(group) = groups.first().and_then(Value::as_object) {
                let host = group
                    .get("host")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let count = group.get("count").and_then(Value::as_u64).unwrap_or(0);
                lines.push(format!(
                    "- Top endpoint cluster: {} · {} observation(s)",
                    host, count
                ));
            }
        }
    }

    if let Some(coverage) = root.get("coverage").and_then(Value::as_object) {
        let subject = coverage
            .get("subject")
            .and_then(Value::as_str)
            .unwrap_or("query");
        let confidence = coverage
            .get("confidence")
            .and_then(Value::as_str)
            .unwrap_or("limited");
        let evidence = coverage
            .get("evidence_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Coverage: {} · confidence {} · evidence {}",
            subject, confidence, evidence
        ));
    }

    if let Some(explainability) = root.get("explainability").and_then(Value::as_object) {
        if let Some(top_rows) = explainability.get("top_rows").and_then(Value::as_array) {
            if !top_rows.is_empty() {
                lines.push(format!(
                    "- AI explainability: {} row(s) include top contributing features for review",
                    top_rows.len()
                ));
            }
        }
        if let Some(samples) = explainability
            .get("sample_predictions")
            .and_then(Value::as_array)
        {
            if !samples.is_empty() {
                lines.push(format!(
                    "- Password model: {} sample candidate(s) retained for operator review",
                    samples.len()
                ));
            }
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
