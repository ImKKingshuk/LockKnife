use ratatui::text::Line;
use serde_json::Value;

use crate::app::{App, InvestigationOutcome};

use super::common::{looks_like_path, summarize_case_path};

pub(in crate::ui) fn case_panel_title(app: &App, width: u16) -> String {
    match app.active_case_summary(if width < 28 { 16 } else { 24 }) {
        Some(summary) if width >= 24 => format!("Case · {}", summary),
        _ => "Case".to_string(),
    }
}

pub(in crate::ui) fn case_detail_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    match app.active_case_summary(if width < 34 { 20 } else { 44 }) {
        Some(summary) => lines.push(Line::from(format!("Active workspace: {}", summary))),
        None => {
            lines.push(Line::from("No active case yet."));
            lines.push(Line::from(
                "Press n to init a workspace or o/p to reopen an existing case.",
            ));
            if let Some(recent_cases) = recent_case_hint(app, width) {
                lines.push(Line::from(recent_cases));
            }
            lines.push(Line::from(case_quick_actions(width)));
            return lines;
        }
    }

    if let Some(inventory_line) = case_inventory_line(app) {
        lines.push(Line::from(inventory_line));
    }
    if let Some(lineage_line) = case_lineage_line(app) {
        lines.push(Line::from(lineage_line));
    }
    if let Some(artifact_line) = case_latest_artifact_line(app, width) {
        lines.push(Line::from(artifact_line));
    }
    if let Some((ok, partial, failed)) = app.active_case_history_totals() {
        lines.push(Line::from(format!(
            "History: {} ok · {} partial · {} failed",
            ok, partial, failed
        )));
    } else {
        lines.push(Line::from(
            "History: no investigation steps recorded for this case yet.",
        ));
    }
    if let Some(job_summary) = case_job_summary_line(app) {
        lines.push(Line::from(job_summary));
    }
    if let Some(issue_line) = latest_case_issue_line(app, width) {
        lines.push(Line::from(issue_line));
    }
    for job_line in case_recent_job_lines(app, width) {
        lines.push(Line::from(job_line));
    }
    for entry in app.active_case_history(if width < 42 { 1 } else { 2 }) {
        lines.push(Line::from(format!(
            "• [{}] {} · {}",
            case_outcome_badge(&entry.outcome),
            entry.action_label,
            entry.summary
        )));
    }
    lines.push(Line::from(case_quick_actions(width)));
    lines
}

fn recent_case_hint(app: &App, width: u16) -> Option<String> {
    let recent = app
        .recent_case_dirs
        .iter()
        .take(if width < 42 { 1 } else { 2 })
        .map(|case_dir| summarize_case_path(case_dir, if width < 42 { 18 } else { 24 }))
        .collect::<Vec<_>>();
    if recent.is_empty() {
        None
    } else {
        Some(format!("Recent cases: {}", recent.join(" · ")))
    }
}

fn case_inventory_line(app: &App) -> Option<String> {
    let root = current_case_result_root(app)?;
    let visible = current_case_numeric(&root, &["artifact_count"]);
    let total = current_case_numeric(&root, &["total_artifact_count"]);
    let categories = current_case_row_count(&root, "artifacts_by_category");
    let devices = current_case_row_count(&root, "artifacts_by_device_serial");
    if visible.is_none() && total.is_none() && categories.is_none() && devices.is_none() {
        return None;
    }

    let mut parts = Vec::new();
    if let Some(visible) = visible {
        parts.push(format!("{} visible", visible));
    }
    if let Some(total) = total {
        parts.push(format!("{} total", total));
    }
    if let Some(categories) = categories {
        parts.push(format!("{} categories", categories));
    }
    if let Some(devices) = devices {
        parts.push(format!("{} devices", devices));
    }

    Some(format!("Inventory: {}", parts.join(" · ")))
}

fn case_lineage_line(app: &App) -> Option<String> {
    let root = current_case_result_root(app)?;
    let roots = current_case_numeric(&root, &["root_artifact_count"]);
    let nodes = current_case_numeric(&root, &["node_count", "artifact_count"]);
    let edges = current_case_numeric(&root, &["edge_count"]);
    if roots.is_none() && edges.is_none() {
        return None;
    }

    let mut parts = Vec::new();
    if let Some(roots) = roots {
        parts.push(format!("{} roots", roots));
    }
    if let Some(nodes) = nodes {
        parts.push(format!("{} nodes", nodes));
    }
    if let Some(edges) = edges {
        parts.push(format!("{} edges", edges));
    }
    Some(format!("Lineage: {}", parts.join(" · ")))
}

fn case_latest_artifact_line(app: &App, width: u16) -> Option<String> {
    let artifact_id = latest_case_artifact_string(app, "artifact_id")?;
    let path = latest_case_artifact_string(app, "path")
        .filter(|value| looks_like_path(value))
        .map(|path| summarize_case_path(&path, if width < 42 { 18 } else { 28 }));

    match path {
        Some(path) => Some(format!(
            "Latest artifact: {} · {} · l lineage / f inventory",
            artifact_id, path
        )),
        None => Some(format!(
            "Latest artifact: {} · l lineage / f inventory",
            artifact_id
        )),
    }
}

fn latest_case_issue_line(app: &App, width: u16) -> Option<String> {
    let issue = app.active_case_history(4).into_iter().find_map(|entry| {
        if matches!(entry.outcome, InvestigationOutcome::Success) {
            None
        } else {
            Some(entry.summary.clone())
        }
    })?;
    Some(format!(
        "Attention: {}",
        summarize_case_path(&issue, if width < 42 { 26 } else { 48 })
    ))
}

fn case_quick_actions(width: u16) -> String {
    if width < 42 {
        "Enter/j summary · f/g/x/w case · u resume · k retry".to_string()
    } else {
        "Quick actions: Enter summary · j jobs · f artifact inventory · g graph · x export bundle · w report · u resume · k retry"
            .to_string()
    }
}

fn case_outcome_badge(outcome: &InvestigationOutcome) -> &'static str {
    match outcome {
        InvestigationOutcome::Success => "ok",
        InvestigationOutcome::Partial => "partial",
        InvestigationOutcome::Failure => "fail",
    }
}

fn current_case_result_root(app: &App) -> Option<Value> {
    let value = app
        .last_result_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())?;
    let active_case = app.active_case_dir().map(str::trim);
    let result_case = value
        .as_object()
        .and_then(|map| map.get("case_dir"))
        .and_then(Value::as_str)
        .map(str::trim);
    if active_case.is_some() && result_case.is_some() && active_case != result_case {
        return None;
    }
    Some(value)
}

fn current_case_job_root(app: &App) -> Option<Value> {
    let value = app
        .last_job_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())?;
    let active_case = app.active_case_dir().map(str::trim);
    let result_case = value
        .as_object()
        .and_then(|map| map.get("case_dir"))
        .and_then(Value::as_str)
        .map(str::trim);
    if active_case.is_some() && result_case.is_some() && active_case != result_case {
        return None;
    }
    Some(value)
}

fn current_case_numeric(root: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        root.as_object()
            .and_then(|map| map.get(*key))
            .and_then(Value::as_u64)
    })
}

fn current_case_row_count(root: &Value, key: &str) -> Option<usize> {
    root.as_object()
        .and_then(|map| map.get(key))
        .and_then(Value::as_array)
        .map(Vec::len)
}

fn case_job_summary_line(app: &App) -> Option<String> {
    let root = current_case_result_root(app)?;
    let jobs = root.as_object()?.get("jobs")?.as_object()?;
    let total = jobs.get("total").and_then(Value::as_u64).unwrap_or(0);
    if total == 0 {
        return None;
    }
    Some(format!(
        "Jobs: {} total · {} running · {} ok · {} partial · {} failed · {} resumable",
        total,
        jobs.get("running").and_then(Value::as_u64).unwrap_or(0),
        jobs.get("succeeded").and_then(Value::as_u64).unwrap_or(0),
        jobs.get("partial").and_then(Value::as_u64).unwrap_or(0),
        jobs.get("failed").and_then(Value::as_u64).unwrap_or(0),
        jobs.get("resumable").and_then(Value::as_u64).unwrap_or(0),
    ))
}

fn case_recent_job_lines(app: &App, width: u16) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(root) = current_case_job_root(app) {
        if let Some(job) = root.as_object() {
            if let Some(job_id) = job.get("job_id").and_then(Value::as_str) {
                let action = job
                    .get("action_label")
                    .or_else(|| job.get("action_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("job");
                let status = job
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                lines.push(format!(
                    "Job: {} · {} · {}",
                    job_id,
                    summarize_case_path(action, if width < 42 { 12 } else { 18 }),
                    status
                ));
                if let Some(recovery) = job
                    .get("recovery_hint")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    lines.push(format!(
                        "Recovery: {}",
                        summarize_case_path(recovery, if width < 42 { 22 } else { 40 })
                    ));
                }
                return lines;
            }
        }
    }

    if let Some(root) = current_case_result_root(app) {
        if let Some(recent_jobs) = root
            .as_object()
            .and_then(|map| map.get("recent_jobs"))
            .and_then(Value::as_array)
        {
            for job in recent_jobs.iter().take(if width < 42 { 1 } else { 2 }) {
                let Some(job) = job.as_object() else { continue };
                let Some(job_id) = job.get("job_id").and_then(Value::as_str) else {
                    continue;
                };
                let action = job
                    .get("action_label")
                    .or_else(|| job.get("action_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("job");
                let status = job
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                lines.push(format!(
                    "Job: {} · {} · {}",
                    job_id,
                    summarize_case_path(action, if width < 42 { 12 } else { 18 }),
                    status
                ));
            }
        }
    }
    lines
}

fn latest_case_artifact_string(app: &App, key: &str) -> Option<String> {
    let root = current_case_result_root(app)?;
    root.as_object()
        .and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| first_case_array_string(&root, "artifact", key))
        .or_else(|| first_case_array_string(&root, "artifacts", key))
        .or_else(|| first_case_array_string(&root, "nodes", key))
}

fn first_case_array_string(root: &Value, field: &str, key: &str) -> Option<String> {
    if field == "artifact" {
        return root
            .as_object()
            .and_then(|map| map.get(field))
            .and_then(Value::as_object)
            .and_then(|artifact| artifact.get(key))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
    }

    root.as_object()
        .and_then(|map| map.get(field))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|item| item.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
