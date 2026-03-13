use serde_json::{Map, Value};

use super::common::{nested_or_root_string, yes_no};

pub(super) fn build_apk_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let manifest = root.get("manifest").and_then(Value::as_object);
    let components_root = manifest
        .and_then(|item| item.get("components"))
        .or_else(|| root.get("components"))
        .and_then(Value::as_object);
    let component_summary = manifest
        .and_then(|item| item.get("component_summary"))
        .or_else(|| components_root.and_then(|item| item.get("summary")))
        .and_then(Value::as_object);
    let signing = manifest
        .and_then(|item| item.get("signing"))
        .or_else(|| root.get("signing"))
        .and_then(Value::as_object);
    let strings = manifest
        .and_then(|item| item.get("string_analysis"))
        .or_else(|| root.get("string_analysis"))
        .and_then(Value::as_object);
    let risk_summary = root.get("risk_summary").and_then(Value::as_object);
    let permission_risk = root.get("permission_risk").and_then(Value::as_object);
    let findings = root.get("findings").and_then(Value::as_array);
    let positioning = root.get("positioning").and_then(Value::as_object);
    let pipelines = root.get("pipelines").and_then(Value::as_array);
    let decompile_outputs = root.get("decompile_outputs").and_then(Value::as_object);
    let sdk = manifest
        .and_then(|item| item.get("sdk"))
        .and_then(Value::as_object);
    let package = nested_or_root_string(root, manifest, "package");
    let app_name = nested_or_root_string(root, manifest, "app_name");
    let main_activity = nested_or_root_string(root, manifest, "main_activity");

    if package.is_none()
        && risk_summary.is_none()
        && positioning.is_none()
        && strings.is_none()
        && component_summary.is_none()
    {
        return None;
    }

    let mut lines = Vec::new();
    match (package.as_deref(), app_name.as_deref()) {
        (Some(package), Some(app_name)) => {
            lines.push(format!("- Package: {} · App: {}", package, app_name))
        }
        (Some(package), None) => lines.push(format!("- Package: {}", package)),
        (None, Some(app_name)) => lines.push(format!("- App: {}", app_name)),
        (None, None) => {}
    }
    if let Some(main_activity) = main_activity {
        lines.push(format!("- Entry point: {}", main_activity));
    }
    if let Some(sdk) = sdk {
        let min_sdk = string_or_number_at(sdk, "min").unwrap_or_else(|| "?".to_string());
        let target_sdk = string_or_number_at(sdk, "target").unwrap_or_else(|| "?".to_string());
        lines.push(format!("- SDK: min {} · target {}", min_sdk, target_sdk));
    }
    if let Some(risk) = risk_summary {
        let score = risk.get("score").and_then(Value::as_u64).unwrap_or(0);
        let level = string_at(risk, "level").unwrap_or_else(|| "unknown".to_string());
        let exploitability =
            string_at(risk, "exploitability").unwrap_or_else(|| "unknown".to_string());
        let evidence =
            string_at(risk, "evidence_strength").unwrap_or_else(|| "unknown".to_string());
        let findings_count = risk
            .get("finding_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Risk: {} / 100 · {} · exploitability {} · evidence {} · findings {}",
            score, level, exploitability, evidence, findings_count
        ));
        if let Some(top) = risk.get("top_findings").and_then(Value::as_array) {
            let preview = top
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| {
                    let title = string_at(item, "title")?;
                    let severity =
                        string_at(item, "severity").unwrap_or_else(|| "info".to_string());
                    Some(format!("{} ({})", title, severity))
                })
                .take(3)
                .collect::<Vec<_>>();
            if !preview.is_empty() {
                lines.push(format!("- Top findings: {}", preview.join(" · ")));
            }
        }
        if let Some(breakdown) = risk.get("score_breakdown").and_then(Value::as_array) {
            let preview = breakdown
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| {
                    let factor = string_at(item, "factor")?;
                    let points = item.get("points").and_then(Value::as_u64).unwrap_or(0);
                    Some(format!("{} +{}", factor, points))
                })
                .take(4)
                .collect::<Vec<_>>();
            if !preview.is_empty() {
                lines.push(format!("- Score breakdown: {}", preview.join(" · ")));
            }
        }
        if let Some(evidence_traces) = risk.get("evidence_traces").and_then(Value::as_array) {
            let preview = evidence_traces
                .iter()
                .filter_map(Value::as_object)
                .map(trace_preview)
                .take(3)
                .collect::<Vec<_>>();
            if !preview.is_empty() {
                lines.push(format!("- Evidence: {}", preview.join(" · ")));
            }
        }
    }
    if let Some(manifest_flags) = manifest
        .and_then(|item| item.get("manifest_flags"))
        .or_else(|| root.get("manifest_flags"))
        .and_then(Value::as_object)
    {
        let debuggable = yes_no(
            manifest_flags
                .get("debuggable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        let backup = yes_no(
            manifest_flags
                .get("allow_backup")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        let cleartext = yes_no(
            manifest_flags
                .get("uses_cleartext_traffic")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        let network_security = string_at(manifest_flags, "network_security_config")
            .unwrap_or_else(|| "not declared".to_string());
        lines.push(format!(
            "- Manifest flags: debuggable {} · backup {} · cleartext {} · network security {}",
            debuggable, backup, cleartext, network_security
        ));
    }
    if let Some(summary) = component_summary {
        let exported = summary
            .get("exported_total")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let deeplinks = summary
            .get("browsable_deeplink_total")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let weak_providers = summary
            .get("provider_weak_permission_total")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let implicit_exports = summary
            .get("implicit_export_total")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Surface: {} exported components · {} browsable deep links · {} weak providers · {} implicit exports",
            exported, deeplinks, weak_providers, implicit_exports
        ));
    }
    if let Some(components) = components_root {
        let preview = risky_component_preview(components);
        if !preview.is_empty() {
            lines.push(format!("- Component drill-down: {}", preview.join(" · ")));
        }
        if let Some(deeplinks) = components.get("deeplinks").and_then(Value::as_array) {
            let preview = deeplinks
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| {
                    let uri = string_at(item, "uri")?;
                    let component =
                        string_at(item, "component").unwrap_or_else(|| "component".to_string());
                    Some(format!("{} → {}", component, uri))
                })
                .take(2)
                .collect::<Vec<_>>();
            if !preview.is_empty() {
                lines.push(format!("- Deep links: {}", preview.join(" · ")));
            }
        }
    }
    if let Some(permission_risk) = permission_risk {
        let score = permission_risk
            .get("score")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let preview = permission_risk
            .get("risks")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_object)
                    .filter_map(|item| string_at(item, "permission"))
                    .take(3)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut line = format!("- Permissions: score {}", score);
        if !preview.is_empty() {
            line.push_str(&format!(" · {}", preview.join(" · ")));
        }
        lines.push(line);
    }
    if let Some(signing) = signing {
        let schemes = enabled_schemes(signing);
        let schemes_display = if schemes.is_empty() {
            "none".to_string()
        } else {
            schemes.join("/")
        };
        let strict = signing
            .get("strict_verification")
            .and_then(Value::as_object);
        let strict_status = strict
            .and_then(|item| string_at(item, "status"))
            .unwrap_or_else(|| "unknown".to_string());
        let lineage_count = signing
            .get("lineage_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let debug_keys = signing
            .get("has_debug_or_test_certificate")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        lines.push(format!(
            "- Signing: {} · strict {} · lineage {} · debug/test {}",
            schemes_display,
            strict_status,
            lineage_count,
            yes_no(debug_keys)
        ));
        if let Some(findings) = strict
            .and_then(|item| item.get("findings"))
            .and_then(Value::as_array)
        {
            let preview = findings
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| string_at(item, "title"))
                .take(2)
                .collect::<Vec<_>>();
            if !preview.is_empty() {
                lines.push(format!("- Signing notes: {}", preview.join(" · ")));
            }
        }
    }
    if let Some(strings) = strings {
        if let Some(stats) = strings.get("stats").and_then(Value::as_object) {
            let secrets = stats
                .get("secret_indicator_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let trackers = stats
                .get("tracker_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let libraries = stats
                .get("library_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let signals = stats
                .get("code_signal_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let urls = stats.get("url_count").and_then(Value::as_u64).unwrap_or(0);
            if secrets > 0 || trackers > 0 || libraries > 0 || signals > 0 || urls > 0 {
                lines.push(format!(
                    "- Code signals: {} libraries · {} trackers · {} signals · {} secrets · {} URLs",
                    libraries, trackers, signals, secrets, urls
                ));
            }
        }
        let preview = signal_preview(strings);
        if !preview.is_empty() {
            lines.push(format!("- Signal preview: {}", preview.join(" · ")));
        }
    }
    if let Some(findings) = findings {
        let preview = findings
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|item| {
                let title = string_at(item, "title")?;
                let severity = string_at(item, "severity").unwrap_or_else(|| "info".to_string());
                Some(format!("{} ({})", title, severity))
            })
            .take(3)
            .collect::<Vec<_>>();
        if !preview.is_empty() {
            lines.push(format!("- Findings: {}", preview.join(" · ")));
        }
    }
    if let Some(positioning) = positioning {
        let selected_mode =
            string_at(positioning, "selected_mode").unwrap_or_else(|| "unknown".to_string());
        let level = string_at(positioning, "source_recovery_level")
            .unwrap_or_else(|| "unknown".to_string());
        let confidence =
            string_at(positioning, "operator_confidence").unwrap_or_else(|| "unknown".to_string());
        lines.push(format!(
            "- Decompile posture: {} · {} · confidence {}",
            selected_mode, level, confidence
        ));
        if let Some(next) = string_at(positioning, "recommended_next") {
            lines.push(format!("- Decompile next: {}", next));
        }
    }
    if let Some(pipelines) = pipelines {
        let preview = pipelines
            .iter()
            .filter_map(Value::as_object)
            .map(|item| {
                let name = string_at(item, "name").unwrap_or_else(|| "stage".to_string());
                let status = string_at(item, "status").unwrap_or_else(|| "unknown".to_string());
                let files = item.get("file_count").and_then(Value::as_u64).unwrap_or(0);
                format!("{} {} {} files", name, status, files)
            })
            .take(3)
            .collect::<Vec<_>>();
        if !preview.is_empty() {
            lines.push(format!("- Decompile stages: {}", preview.join(" · ")));
        }
    }
    if let Some(outputs) = decompile_outputs {
        let preview = outputs
            .iter()
            .take(3)
            .filter_map(|(name, value)| value.as_str().map(|path| format!("{} → {}", name, path)))
            .collect::<Vec<_>>();
        if !preview.is_empty() {
            lines.push(format!("- Decompile outputs: {}", preview.join(" · ")));
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn risky_component_preview(components: &Map<String, Value>) -> Vec<String> {
    let mut items = Vec::new();
    for bucket in ["activities", "services", "receivers", "providers"] {
        if let Some(entries) = components.get(bucket).and_then(Value::as_array) {
            for entry in entries.iter().filter_map(Value::as_object) {
                let exported = entry
                    .get("exported")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let risk_flags = entry.get("risk_flags").and_then(Value::as_array);
                if !exported && risk_flags.is_none() {
                    continue;
                }
                let name = string_at(entry, "name").unwrap_or_else(|| bucket.to_string());
                let flags = risk_flags
                    .map(|flags| {
                        flags
                            .iter()
                            .filter_map(Value::as_str)
                            .take(2)
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if flags.is_empty() {
                    items.push(name);
                } else {
                    items.push(format!("{} [{}]", name, flags.join(", ")));
                }
                if items.len() >= 3 {
                    return items;
                }
            }
        }
    }
    items
}

fn signal_preview(strings: &Map<String, Value>) -> Vec<String> {
    let mut items = Vec::new();
    if let Some(trackers) = strings.get("trackers").and_then(Value::as_array) {
        for tracker in trackers.iter().filter_map(Value::as_object).take(2) {
            if let Some(label) = string_at(tracker, "label") {
                items.push(format!("tracker {}", label));
            }
        }
    }
    if let Some(libraries) = strings.get("libraries").and_then(Value::as_array) {
        for library in libraries.iter().filter_map(Value::as_object).take(2) {
            if let Some(label) = string_at(library, "label") {
                items.push(format!("library {}", label));
            }
            if items.len() >= 3 {
                return items;
            }
        }
    }
    if let Some(signals) = strings.get("code_signals").and_then(Value::as_array) {
        for signal in signals.iter().filter_map(Value::as_object).take(2) {
            if let Some(label) = string_at(signal, "label") {
                items.push(format!("signal {}", label));
            }
            if items.len() >= 3 {
                return items;
            }
        }
    }
    items
}

fn enabled_schemes(signing: &Map<String, Value>) -> Vec<&'static str> {
    signing
        .get("schemes")
        .and_then(Value::as_object)
        .map(|schemes| {
            [
                (
                    "v1",
                    schemes.get("v1").and_then(Value::as_bool).unwrap_or(false),
                ),
                (
                    "v2",
                    schemes.get("v2").and_then(Value::as_bool).unwrap_or(false),
                ),
                (
                    "v3",
                    schemes.get("v3").and_then(Value::as_bool).unwrap_or(false),
                ),
                (
                    "v4",
                    schemes.get("v4").and_then(Value::as_bool).unwrap_or(false),
                ),
            ]
            .into_iter()
            .filter_map(|(label, enabled)| if enabled { Some(label) } else { None })
            .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn trace_preview(trace: &Map<String, Value>) -> String {
    let source = string_at(trace, "source").unwrap_or_else(|| "trace".to_string());
    let title = string_at(trace, "title")
        .or_else(|| string_at(trace, "preview"))
        .or_else(|| string_at(trace, "id"))
        .unwrap_or_else(|| "evidence".to_string());
    format!("{} {}", source, title)
}

fn string_at(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_or_number_at(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.trim().to_string()).filter(|value| !value.is_empty()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}
