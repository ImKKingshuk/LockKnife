use serde_json::Value;

pub(super) fn build_reporting_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if let Some(case_summary) = root.get("case_summary").and_then(Value::as_object) {
        let total_artifacts = case_summary
            .get("total_artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let jobs = case_summary
            .get("jobs")
            .and_then(Value::as_object)
            .and_then(|jobs| jobs.get("total"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let runtime_sessions = case_summary
            .get("runtime_sessions")
            .and_then(Value::as_object)
            .and_then(|sessions| sessions.get("total"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if total_artifacts > 0 || jobs > 0 || runtime_sessions > 0 {
            lines.push(format!(
                "- Case workspace: {} artifact(s) tracked · {} job(s) · {} runtime session(s)",
                total_artifacts, jobs, runtime_sessions
            ));
        }
    }

    let integrity = root
        .get("integrity")
        .and_then(Value::as_object)
        .or_else(|| {
            if root.contains_key("verified_at_utc") && root.contains_key("summary") {
                Some(root)
            } else {
                None
            }
        });
    if let Some(integrity) = integrity {
        if let Some(summary) = integrity.get("summary").and_then(Value::as_object) {
            let verified = summary
                .get("verified_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let modified = summary
                .get("modified_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let missing = summary
                .get("missing_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            lines.push(format!(
                "- Integrity: {} verified · {} modified · {} missing",
                verified, modified, missing
            ));
        }
        if let Some(advisory) = integrity.get("advisory").and_then(Value::as_str) {
            let trimmed = advisory.trim();
            if !trimmed.is_empty() {
                lines.push(format!("- Integrity advisory: {}", trimmed));
            }
        }
    }

    if let Some(custody) = root.get("custody_preview").and_then(Value::as_object) {
        let count = custody
            .get("artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if count > 0 {
            lines.push(format!(
                "- Chain of custody: {} artifact-backed evidence item(s) ready from the case manifest",
                count
            ));
        }
    } else if let Some(count) = root.get("evidence_count").and_then(Value::as_u64) {
        lines.push(format!(
            "- Chain of custody: {} evidence item(s) included in the generated ledger",
            count
        ));
    }

    if let Some(items) = root.get("evidence_inventory").and_then(Value::as_array) {
        if !items.is_empty() {
            lines.push(format!(
                "- Evidence inventory: {} artifact record(s) available for report rendering",
                items.len()
            ));
        }
    }

    if let Some(summary) = root.get("evidence_summary").and_then(Value::as_object) {
        let categories = summary
            .get("top_categories")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        let payload_rows = summary
            .get("artifact_payload_rows")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Evidence summary: {} visible category bucket(s) · {} top-level payload row(s)",
            categories, payload_rows
        ));
    }

    if let Some(preview) = root.get("report_preview").and_then(Value::as_object) {
        let readiness = preview
            .get("template_readiness")
            .and_then(Value::as_str)
            .unwrap_or("partial");
        let backend = preview
            .get("pdf_backend_status")
            .and_then(Value::as_object)
            .and_then(|status| status.get("preferred"))
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        lines.push(format!(
            "- Report preview: readiness {} · PDF backend {}",
            readiness, backend
        ));
    }

    if let Some(sections) = root.get("report_sections").and_then(Value::as_array) {
        if let Some(section) = sections.first().and_then(Value::as_object) {
            let title = section
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("section");
            let summary = section.get("summary").and_then(Value::as_str).unwrap_or("");
            if !summary.trim().is_empty() {
                lines.push(format!("- {}: {}", title, summary));
            }
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
