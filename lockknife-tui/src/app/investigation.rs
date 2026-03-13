use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::*;

impl App {
    pub fn active_case_history(&self, limit: usize) -> Vec<&InvestigationEntry> {
        let Some(case_dir) = self.active_case_dir() else {
            return Vec::new();
        };

        self.investigation_history
            .iter()
            .rev()
            .filter(|entry| entry.case_dir == case_dir)
            .take(limit)
            .collect()
    }

    pub fn active_case_history_totals(&self) -> Option<(usize, usize, usize)> {
        let case_dir = self.active_case_dir()?;
        let mut ok = 0usize;
        let mut partial = 0usize;
        let mut failed = 0usize;

        for entry in self
            .investigation_history
            .iter()
            .filter(|entry| entry.case_dir == case_dir)
        {
            match entry.outcome {
                InvestigationOutcome::Success => ok += 1,
                InvestigationOutcome::Partial => partial += 1,
                InvestigationOutcome::Failure => failed += 1,
            }
        }

        if ok + partial + failed == 0 {
            None
        } else {
            Some((ok, partial, failed))
        }
    }

    pub(crate) fn promote_case_context(&mut self, action: &str, result_data: Option<&str>) {
        let discovered = self
            .last_result_paths
            .iter()
            .find(|path| path.label == "Case directory")
            .map(|path| path.value.clone())
            .or_else(|| extract_case_dir_from_json(result_data))
            .or_else(|| {
                if action.starts_with("case.") {
                    self.pending_case_dir.clone()
                } else {
                    None
                }
            })
            .or_else(|| self.pending_case_dir.clone());

        if let Some(case_dir) = discovered.filter(|value| !value.trim().is_empty()) {
            self.remember_case_dir(&case_dir);
            self.active_case_dir = Some(case_dir);
        }
    }

    pub(crate) fn record_investigation_result(
        &mut self,
        action: &str,
        ok: bool,
        result_message: Option<&str>,
        result_data: Option<&str>,
        error_message: Option<&str>,
    ) {
        let case_dir = self
            .last_result_case_dir()
            .or_else(|| extract_case_dir_from_json(result_data))
            .or_else(|| self.pending_case_dir.clone())
            .or_else(|| self.active_case_dir.clone());
        let Some(case_dir) = case_dir.filter(|value| !value.trim().is_empty()) else {
            return;
        };

        let action_label = self.action_label_for_id(action);
        let (outcome, summary) = if ok {
            if let Some(issue) = partial_issue_summary(result_data) {
                (InvestigationOutcome::Partial, issue)
            } else if let Some(message) = result_message
                .map(str::trim)
                .filter(|message| !message.is_empty())
            {
                (InvestigationOutcome::Success, message.to_string())
            } else {
                let fallback = success_feedback_message(action, self.config_path.as_deref())
                    .unwrap_or_else(|| format!("{} completed", action_label));
                (InvestigationOutcome::Success, fallback)
            }
        } else {
            (
                InvestigationOutcome::Failure,
                error_message
                    .map(str::trim)
                    .filter(|message| !message.is_empty())
                    .unwrap_or("Action failed")
                    .to_string(),
            )
        };

        self.investigation_history.push(InvestigationEntry {
            timestamp: now_hms(),
            action_id: action.to_string(),
            action_label,
            case_dir,
            outcome,
            summary: summarize_feedback_text(&summary, 72),
        });
        if self.investigation_history.len() > 32 {
            self.investigation_history
                .drain(0..self.investigation_history.len().saturating_sub(32));
        }
    }

    fn action_label_for_id(&self, action_id: &str) -> String {
        self.modules
            .iter()
            .flat_map(|module| module.actions.iter())
            .find(|action| action.id == action_id)
            .map(|action| action.label.clone())
            .unwrap_or_else(|| action_id.to_string())
    }
}

pub(crate) fn partial_issue_summary(data: Option<&str>) -> Option<String> {
    let raw = data?;
    let value = serde_json::from_str::<Value>(raw).ok()?;
    let mut issues = Vec::new();
    collect_partial_issue_summaries(&value, &mut issues);
    issues.into_iter().next()
}

pub(crate) fn collect_partial_issue_summaries(value: &Value, issues: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(items) = map.get("missing_parent_ids").and_then(Value::as_array) {
                push_unique_issue(
                    issues,
                    format!(
                        "{} missing parent id{}",
                        items.len(),
                        if items.len() == 1 { "" } else { "s" }
                    ),
                );
            }
            for key in ["warnings", "errors"] {
                if let Some(items) = map
                    .get(key)
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty())
                {
                    push_unique_issue(
                        issues,
                        format!(
                            "{} {}",
                            items.len(),
                            if key == "warnings" {
                                "warning(s)"
                            } else {
                                "error(s)"
                            }
                        ),
                    );
                }
            }
            for (key, label) in [
                ("failed", "failed item(s)"),
                ("failed_count", "failed item(s)"),
                ("failure_count", "failure(s)"),
                ("skipped", "skipped item(s)"),
                ("skipped_count", "skipped item(s)"),
            ] {
                if let Some(count) = map
                    .get(key)
                    .and_then(Value::as_u64)
                    .filter(|count| *count > 0)
                {
                    push_unique_issue(issues, format!("{} {}", count, label));
                }
            }
            let degraded = map.get("ok").and_then(Value::as_bool) == Some(false)
                || map.get("configured").and_then(Value::as_bool) == Some(false)
                || map.get("installed").and_then(Value::as_bool) == Some(false);
            if degraded {
                if let Some(hint) = map
                    .get("hint")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    push_unique_issue(issues, hint.to_string());
                } else if let Some(name) = map
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    push_unique_issue(issues, format!("{} needs attention", name));
                }
            }
            for child in map.values() {
                collect_partial_issue_summaries(child, issues);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_partial_issue_summaries(item, issues);
            }
        }
        _ => {}
    }
}

pub(crate) fn push_unique_issue(issues: &mut Vec<String>, issue: String) {
    if !issues.iter().any(|existing| existing == &issue) {
        issues.push(issue);
    }
}

pub(crate) fn now_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs % 86400;
    let h = day / 3600;
    let m = (day % 3600) / 60;
    let s = day % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}
