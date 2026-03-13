use serde_json::{Map, Value};

use super::common::yes_no;

pub(super) fn build_runtime_context_section(parsed: Option<&Value>) -> Option<String> {
    let root = parsed?.as_object()?;
    let dashboard = root.get("runtime_dashboard").and_then(Value::as_object);
    let dashboard_mode = dashboard.and_then(|item| item.get("mode").and_then(Value::as_str));

    if let Some(session) = root
        .get("session")
        .and_then(Value::as_object)
        .filter(|item| item.get("session_kind").is_some() || item.get("logs_path").is_some())
    {
        return Some(build_session_context(root, session, dashboard));
    }
    if dashboard_mode == Some("inventory")
        || root
            .get("live_session_ids")
            .and_then(Value::as_array)
            .is_some()
    {
        return Some(build_inventory_context(root, dashboard));
    }
    if dashboard_mode == Some("memory-search") {
        return Some(build_memory_search_context(root, dashboard));
    }
    if dashboard_mode == Some("heap-dump") {
        return Some(build_heap_dump_context(root, dashboard));
    }
    if dashboard_mode == Some("preflight")
        || ((root.get("attach_mode").is_some() || root.get("target").is_some())
            && (root.get("checks").and_then(Value::as_array).is_some()
                || root.get("readiness").is_some()))
    {
        return Some(build_preflight_context(root, dashboard));
    }
    None
}

fn build_preflight_context(
    root: &Map<String, Value>,
    dashboard: Option<&Map<String, Value>>,
) -> String {
    let mut lines = Vec::new();
    let status = string_at(root, "status").unwrap_or_else(|| "unknown".to_string());
    let attach_mode = string_at(root, "attach_mode").unwrap_or_else(|| "spawn".to_string());
    let session_kind = string_at(root, "session_kind");
    lines.push(format!(
        "- Preflight: {} · attach {}{}",
        status,
        attach_mode,
        session_kind
            .as_ref()
            .map(|value| format!(" · kind {}", value))
            .unwrap_or_default()
    ));

    if let Some(target) = root.get("target").and_then(Value::as_object) {
        let app_visible = target
            .get("application_available")
            .and_then(Value::as_bool)
            .map(yes_no)
            .unwrap_or("no");
        let running_pid = target
            .get("running_pid")
            .and_then(Value::as_i64)
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "not found".to_string());
        lines.push(format!(
            "- Target visibility: {} · Running pid: {}",
            app_visible, running_pid
        ));
        if let Some(device) = target.get("device").and_then(Value::as_object) {
            let label = string_at(device, "name")
                .or_else(|| string_at(device, "id"))
                .unwrap_or_else(|| "device".to_string());
            let device_type = string_at(device, "type").unwrap_or_else(|| "unknown".to_string());
            lines.push(format!("- Device: {} · type {}", label, device_type));
        }
    }

    if let Some(readiness) = root.get("readiness").and_then(Value::as_object) {
        let blocked = readiness
            .get("blocked_checks")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        let warned = readiness
            .get("warned_checks")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        lines.push(format!(
            "- Readiness: {} · blocked {} · warnings {}",
            yes_no(
                readiness
                    .get("ready")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            ),
            blocked,
            warned
        ));
        if let Some(next) = string_at(readiness, "recommended_action") {
            lines.push(format!("- Next: {}", next));
        }
    }

    if let Some(compatibility) = root.get("compatibility").and_then(Value::as_object) {
        let status = string_at(compatibility, "status").unwrap_or_else(|| "pass".to_string());
        let findings = compatibility
            .get("finding_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Compatibility: {} · findings {}",
            status, findings
        ));
        if let Some(finding_titles) = compatibility
            .get("findings")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_object)
                    .filter_map(|item| string_at(item, "title"))
                    .take(3)
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
        {
            lines.push(format!("- Warnings: {}", finding_titles.join(" · ")));
        }
    } else if let Some(dashboard) = dashboard {
        if let Some(next) = string_at(dashboard, "recommended_next_action") {
            lines.push(format!("- Next: {}", next));
        }
    }

    lines.join("\n")
}

fn build_session_context(
    root: &Map<String, Value>,
    session: &Map<String, Value>,
    dashboard: Option<&Map<String, Value>>,
) -> String {
    let mut lines = Vec::new();
    let session_id =
        string_at(session, "session_id").unwrap_or_else(|| "runtime-session".to_string());
    let status = string_at(session, "status").unwrap_or_else(|| "unknown".to_string());
    let live = root.get("live").and_then(Value::as_bool).unwrap_or(false);
    let session_kind = string_at(session, "session_kind").unwrap_or_else(|| "hook".to_string());
    let attach_mode = string_at(session, "attach_mode").unwrap_or_else(|| "spawn".to_string());
    lines.push(format!(
        "- Session: {} · {} · live {} · kind {} · attach {}",
        session_id,
        status,
        yes_no(live),
        session_kind,
        attach_mode
    ));
    lines.push(format!(
        "- Activity: connects {} · reloads {} · events {}",
        u64_at(session, "connect_count"),
        u64_at(session, "reload_count"),
        u64_at(session, "event_count")
    ));

    if let Some(preflight) = session.get("preflight").and_then(Value::as_object) {
        let preflight_status =
            string_at(preflight, "status").unwrap_or_else(|| "unknown".to_string());
        let readiness = preflight
            .get("readiness")
            .and_then(Value::as_object)
            .and_then(|item| item.get("ready"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        lines.push(format!(
            "- Preflight: {} · ready {}",
            preflight_status,
            yes_no(readiness)
        ));
    }

    if let Some(compatibility) = session.get("compatibility").and_then(Value::as_object) {
        let status = string_at(compatibility, "status").unwrap_or_else(|| "pass".to_string());
        let findings = compatibility
            .get("finding_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Compatibility: {} · findings {}",
            status, findings
        ));
    }

    if let Some(summary) = session
        .get("script_inventory_summary")
        .and_then(Value::as_object)
    {
        let count = summary.get("count").and_then(Value::as_u64).unwrap_or(0);
        let active = string_at(summary, "active_label").unwrap_or_else(|| "n/a".to_string());
        lines.push(format!("- Saved scripts: {} · active {}", count, active));
        if let Some(items) = summary.get("items").and_then(Value::as_array) {
            let previews = items
                .iter()
                .filter_map(Value::as_object)
                .map(|item| {
                    let label = string_at(item, "label").unwrap_or_else(|| "script".to_string());
                    let preview = string_at(item, "preview").unwrap_or_default();
                    if preview.is_empty() {
                        label
                    } else {
                        format!("{} ({})", label, preview)
                    }
                })
                .take(3)
                .collect::<Vec<_>>();
            if !previews.is_empty() {
                lines.push(format!("- Script previews: {}", previews.join(" · ")));
            }
        }
    }

    if let Some(events) = session
        .get("event_summary")
        .and_then(Value::as_object)
        .and_then(|summary| summary.get("recent"))
        .and_then(Value::as_array)
    {
        let recent = events
            .iter()
            .filter_map(Value::as_object)
            .map(|item| {
                let event_type =
                    string_at(item, "event_type").unwrap_or_else(|| "event".to_string());
                let level = string_at(item, "level").unwrap_or_else(|| "info".to_string());
                let message =
                    string_at(item, "message").unwrap_or_else(|| "runtime event".to_string());
                format!("{}/{} {}", event_type, level, message)
            })
            .take(3)
            .collect::<Vec<_>>();
        if !recent.is_empty() {
            lines.push(format!("- Recent events: {}", recent.join(" · ")));
        }
    }

    if let Some(failure) = session.get("failure_context").and_then(Value::as_object) {
        if let Some(error) = string_at(failure, "error_message") {
            lines.push(format!("- Failure: {}", error));
        }
    }

    if let Some(next) = dashboard.and_then(|item| string_at(item, "recommended_next_action")) {
        lines.push(format!("- Next: {}", next));
    }
    lines.join("\n")
}

fn build_inventory_context(
    root: &Map<String, Value>,
    dashboard: Option<&Map<String, Value>>,
) -> String {
    let mut lines = Vec::new();
    let session_count = root
        .get("session_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_session_count = root
        .get("total_session_count")
        .and_then(Value::as_u64)
        .unwrap_or(session_count);
    let live_session_count = dashboard
        .and_then(|item| item.get("live_session_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let failed_session_count = dashboard
        .and_then(|item| item.get("failed_session_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    lines.push(format!(
        "- Sessions: {} shown / {} total · live {} · failed {}",
        session_count, total_session_count, live_session_count, failed_session_count
    ));

    if let Some(dashboard) = dashboard {
        let warnings = dashboard
            .get("compatibility_warning_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let script_count = dashboard
            .get("script_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- Saved scripts: {} · compatibility warnings {}",
            script_count, warnings
        ));
        if let Some(previews) = dashboard.get("session_previews").and_then(Value::as_array) {
            let items = previews
                .iter()
                .filter_map(Value::as_object)
                .map(|item| {
                    let session_id =
                        string_at(item, "session_id").unwrap_or_else(|| "rt".to_string());
                    let status = string_at(item, "status").unwrap_or_else(|| "unknown".to_string());
                    let kind =
                        string_at(item, "session_kind").unwrap_or_else(|| "hook".to_string());
                    let latest = string_at(item, "latest_message").unwrap_or_default();
                    if latest.is_empty() {
                        format!("{} {} {}", session_id, status, kind)
                    } else {
                        format!("{} {} {} — {}", session_id, status, kind, latest)
                    }
                })
                .take(3)
                .collect::<Vec<_>>();
            if !items.is_empty() {
                lines.push(format!("- Session previews: {}", items.join(" · ")));
            }
        }
        if let Some(next) = string_at(dashboard, "recommended_next_action") {
            lines.push(format!("- Next: {}", next));
        }
    }

    lines.join("\n")
}

fn build_memory_search_context(
    root: &Map<String, Value>,
    dashboard: Option<&Map<String, Value>>,
) -> String {
    let mut lines = Vec::new();
    let status = string_at(root, "status").unwrap_or_else(|| "unknown".to_string());
    let hit_count = root.get("hit_count").and_then(Value::as_u64).unwrap_or(0);
    let timed_out = root
        .get("timed_out")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let protection = dashboard
        .and_then(|item| string_at(item, "protection"))
        .unwrap_or_else(|| "r--".to_string());
    lines.push(format!(
        "- Memory search: {} · hits {} · timed out {} · scope {}",
        status,
        hit_count,
        yes_no(timed_out),
        protection
    ));
    if let Some(pattern) = dashboard.and_then(|item| string_at(item, "pattern")) {
        let pattern_type = dashboard
            .and_then(|item| string_at(item, "pattern_type"))
            .unwrap_or_else(|| "string".to_string());
        lines.push(format!("- Pattern: {} · type {}", pattern, pattern_type));
    }
    if let Some(hit) = root
        .get("sample_hits")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
    {
        lines.push(format!("- Sample hit: {}", hit));
    }
    if let Some(next) = dashboard.and_then(|item| string_at(item, "recommended_next_action")) {
        lines.push(format!("- Next: {}", next));
    }
    lines.join("\n")
}

fn build_heap_dump_context(
    root: &Map<String, Value>,
    dashboard: Option<&Map<String, Value>>,
) -> String {
    let mut lines = Vec::new();
    let status = string_at(root, "status").unwrap_or_else(|| "unknown".to_string());
    let timed_out = root
        .get("timed_out")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let remote = string_at(root, "remote_output_path")
        .or_else(|| dashboard.and_then(|item| string_at(item, "remote_output_path")))
        .unwrap_or_else(|| "(not provided)".to_string());
    lines.push(format!(
        "- Heap dump: {} · timed out {}",
        status,
        yes_no(timed_out)
    ));
    lines.push(format!("- Remote output: {}", remote));
    if let Some(next) = dashboard.and_then(|item| string_at(item, "recommended_next_action")) {
        lines.push(format!("- Next: {}", next));
    }
    lines.join("\n")
}

fn string_at(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn u64_at(map: &Map<String, Value>, key: &str) -> u64 {
    map.get(key).and_then(Value::as_u64).unwrap_or(0)
}
