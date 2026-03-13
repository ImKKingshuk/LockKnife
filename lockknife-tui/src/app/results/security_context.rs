use serde_json::Value;

pub(crate) fn build_security_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let mut lines = Vec::new();

    if let Some(risk) = root.get("risk_summary").and_then(Value::as_object) {
        let score = risk.get("score").and_then(Value::as_u64).unwrap_or(0);
        let level = risk
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let exploitability = risk
            .get("exploitability")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let evidence_strength = risk
            .get("evidence_strength")
            .and_then(Value::as_str)
            .unwrap_or("limited");
        let finding_count = risk
            .get("finding_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Risk: {} / 100 · {} · exploitability {} · evidence {} · findings {}",
            score, level, exploitability, evidence_strength, finding_count
        ));

        if let Some(summary) = root
            .get("static_analysis")
            .or_else(|| root.get("surface"))
            .and_then(|value| value.get("summary"))
            .and_then(Value::as_object)
        {
            let exported = summary
                .get("exported_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let providers = summary
                .get("provider_weak_permission_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let deeplinks = summary
                .get("browsable_deeplink_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            lines.push(format!(
                "- Static surface: {} exported components · {} weak providers · {} browsable deep links",
                exported, providers, deeplinks
            ));
        }

        if let Some(summary) = root
            .get("live_analysis")
            .or_else(|| root.get("probe_results"))
            .and_then(|value| value.get("summary"))
            .and_then(Value::as_object)
        {
            let deeplink_hits = summary
                .get("deeplink_resolved_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let provider_hits = summary
                .get("provider_resolved_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let component_hits = summary
                .get("component_resolved_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            lines.push(format!(
                "- Live probes: {} deep links · {} providers · {} components resolved",
                deeplink_hits, provider_hits, component_hits
            ));
        }

        if let Some(paths) = risk.get("attack_paths").and_then(Value::as_array) {
            let preview = paths
                .iter()
                .filter_map(Value::as_str)
                .take(2)
                .collect::<Vec<_>>()
                .join(" | ");
            if !preview.is_empty() {
                lines.push(format!("- Attack paths: {}", preview));
            }
        }
        if let Some(steps) = risk.get("next_steps").and_then(Value::as_array) {
            let preview = steps
                .iter()
                .filter_map(Value::as_str)
                .take(2)
                .collect::<Vec<_>>()
                .join(" | ");
            if !preview.is_empty() {
                lines.push(format!("- Next inspect: {}", preview));
            }
        }
    }

    if let Some(mastg_ids) = root.get("mastg_ids").and_then(Value::as_array) {
        let mastg_total = mastg_ids.len();
        let owasp_preview = root
            .get("owasp_categories")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        lines.push(format!(
            "- OWASP/MASTG: {} MASTG IDs{}",
            mastg_total,
            if owasp_preview.is_empty() {
                String::new()
            } else {
                format!(" · {}", owasp_preview)
            }
        ));
    }

    if root.get("mode").is_some() || root.get("status").is_some() {
        let mode = root
            .get("mode")
            .or_else(|| root.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        let posture = root
            .get("posture")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let risk_level = posture
            .get("risk_level")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let domain_count = posture
            .get("domain_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let denial_count = posture
            .get("denial_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                root.get("denial_summary")
                    .and_then(|value| value.get("count"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            });
        lines.push(format!(
            "- SELinux: {} · posture {} · {} domains · {} AVC denials",
            mode, risk_level, domain_count, denial_count
        ));
        if let Some(hints) = root.get("remediation_hints").and_then(Value::as_array) {
            let preview = hints
                .iter()
                .filter_map(Value::as_str)
                .take(2)
                .collect::<Vec<_>>()
                .join(" | ");
            if !preview.is_empty() {
                lines.push(format!("- Remediation: {}", preview));
            }
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
