use serde_json::Value;

use super::common::looks_like_path;
use super::paths::{
    extract_apk_package, extract_artifact_string, extract_case_dir_from_value,
    extract_runtime_session_id, first_job_id, latest_register_path, parent_path_hint,
};
use super::ResultPath;

pub(super) fn build_follow_up_actions_section(
    paths: &[ResultPath],
    parsed: Option<&Value>,
    active_case_dir: Option<&str>,
) -> Option<String> {
    let active_case_dir = active_case_dir
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let result_case_dir = paths
        .iter()
        .find(|path| path.label == "Case directory")
        .map(|path| path.value.clone())
        .or_else(|| extract_case_dir_from_value(parsed));
    let case_target = result_case_dir
        .as_deref()
        .map(|case_dir| case_dir.to_string())
        .or_else(|| active_case_dir.map(|case_dir| format!("active case {}", case_dir)));
    let artifact_id = extract_artifact_string(parsed, "artifact_id");
    let artifact_path =
        extract_artifact_string(parsed, "path").filter(|path| looks_like_path(path));
    let runtime_session_id = extract_runtime_session_id(parsed);
    let apk_package = extract_apk_package(parsed);
    let register_path = artifact_path
        .clone()
        .or_else(|| latest_register_path(paths));
    let search_hint = register_path
        .as_deref()
        .map(parent_path_hint)
        .filter(|value| !value.trim().is_empty());
    let mut lines = Vec::new();

    match case_target.as_deref() {
        Some(case_target) => {
            lines.push(format!("- [s] Case summary: ready for {}.", case_target));
            if let Some(path_hint) = search_hint.as_deref() {
                lines.push(format!(
                    "- [f] Artifact search: ready for {} · path hint {}.",
                    case_target, path_hint
                ));
            } else {
                lines.push(format!("- [f] Artifact search: ready for {}.", case_target));
            }

            if let Some(artifact_id) = artifact_id.as_deref() {
                lines.push(format!(
                    "- [a] Artifact detail: ready for {} in {}.",
                    artifact_id, case_target
                ));
                lines.push(format!(
                    "- [l] Lineage: ready for {} in {}.",
                    artifact_id, case_target
                ));
            } else if let Some(path) = artifact_path.as_deref() {
                lines.push(format!(
                    "- [a] Artifact detail: ready from artifact path {}.",
                    path
                ));
                lines.push(format!("- [l] Lineage: ready from artifact path {}.", path));
            } else {
                lines.push(
                    "- [a] Artifact detail: blocked — latest result does not expose an artifact ID or artifact path yet."
                        .to_string(),
                );
                lines.push(
                    "- [l] Lineage: blocked — latest result does not expose an artifact ID or artifact path yet."
                        .to_string(),
                );
            }

            if let Some(path) = register_path.as_deref() {
                lines.push(format!("- [r] Register artifact: ready for {}.", path));
            } else {
                lines.push(
                    "- [r] Register artifact: blocked — latest result does not expose a registerable artifact path yet."
                        .to_string(),
                );
            }
            lines.push(format!("- [x] Export bundle: ready for {}.", case_target));
            if let Some(artifact_id) = artifact_id.as_deref() {
                lines.push(format!(
                    "- [n] Enrichment bundle: ready for {} in {}.",
                    artifact_id, case_target
                ));
            } else {
                lines.push(format!(
                    "- [n] Enrichment bundle: ready for {}.",
                    case_target
                ));
            }
            lines.push(format!(
                "- [w] Generate report: ready for {} · uses latest case context or an on-demand case summary.",
                case_target
            ));
            if let Some(preview) = parsed
                .and_then(|value| value.get("report_preview"))
                .and_then(Value::as_object)
            {
                let backend = preview
                    .get("pdf_backend_status")
                    .and_then(Value::as_object)
                    .and_then(|status| status.get("preferred"))
                    .and_then(Value::as_str)
                    .unwrap_or("unavailable");
                lines.push(format!(
                    "- [w] Report preview: PDF backend {} · confirm readiness before exporting reviewer-facing bundles.",
                    backend
                ));
            }
            lines.push(format!(
                "- [g] Integrity report: ready for {}.",
                case_target
            ));
            lines.push(format!(
                "- [v] Chain of custody: ready for {}.",
                case_target
            ));
            lines.push(format!("- [j] Job history: ready for {}.", case_target));
            lines.push(format!(
                "- [m] Runtime sessions: ready for {}.",
                case_target
            ));
            if let Some(session_id) = runtime_session_id.as_deref() {
                lines.push(format!(
                    "- [i] Runtime session: ready for {} in {}.",
                    session_id, case_target
                ));
                lines.push(format!(
                    "- [h] Hot-reload session: ready for {} in {}.",
                    session_id, case_target
                ));
                lines.push(format!(
                    "- [c] Reconnect session: ready for {} in {}.",
                    session_id, case_target
                ));
                lines.push(format!(
                    "- [o] Stop session: ready for {} in {}.",
                    session_id, case_target
                ));
            } else {
                lines.push(
                    "- [i] Runtime session: blocked — latest result does not expose a runtime session ID yet."
                        .to_string(),
                );
                lines.push(
                    "- [h] Hot-reload session: blocked — latest result does not expose a runtime session ID yet."
                        .to_string(),
                );
                lines.push(
                    "- [c] Reconnect session: blocked — latest result does not expose a runtime session ID yet."
                        .to_string(),
                );
                lines.push(
                    "- [o] Stop session: blocked — latest result does not expose a runtime session ID yet."
                        .to_string(),
                );
            }
        }
        None => {
            lines.push(
                "- [s] Case summary: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [f] Artifact search: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [a] Artifact detail: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [l] Lineage: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [r] Register artifact: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [x] Export bundle: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [n] Enrichment bundle: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [w] Generate report: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [g] Integrity report: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [v] Chain of custody: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [j] Job history: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [m] Runtime sessions: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [i] Runtime session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [h] Hot-reload session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [c] Reconnect session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [o] Stop session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
        }
    }

    if let Some(package) = apk_package.as_deref() {
        lines.push(format!(
            "- [p] Runtime preflight: ready for APK package {}.",
            package
        ));
        if let Some(case_target) = case_target.as_deref() {
            lines.push(format!(
                "- [b] SSL bypass session: ready for APK package {} in {}.",
                package, case_target
            ));
            lines.push(format!(
                "- [t] Trace session: ready for APK package {} in {}.",
                package, case_target
            ));
        } else {
            lines.push(
                "- [b] SSL bypass session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- [t] Trace session: blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
        }
        lines.push(format!(
            "- [e] CVE correlation: ready for APK package {}.",
            package
        ));
        match (register_path.as_deref(), case_target.as_deref()) {
            (Some(path), Some(case_target)) => lines.push(format!(
                "- [d] Attack-surface assessment: ready for APK package {} using {} in {}.",
                package, path, case_target
            )),
            (Some(path), None) => lines.push(format!(
                "- [d] Attack-surface assessment: ready for APK package {} using {}.",
                package, path
            )),
            (None, Some(case_target)) => lines.push(format!(
                "- [d] Attack-surface assessment: ready for APK package {} in {}.",
                package, case_target
            )),
            (None, None) => lines.push(format!(
                "- [d] Attack-surface assessment: ready for APK package {}.",
                package
            )),
        }
    } else {
        lines.push(
            "- [p] Runtime preflight: blocked — latest result does not expose an APK package name yet."
                .to_string(),
        );
        lines.push(
            "- [b] SSL bypass session: blocked — latest result does not expose an APK package name yet."
                .to_string(),
        );
        lines.push(
            "- [t] Trace session: blocked — latest result does not expose an APK package name yet."
                .to_string(),
        );
        lines.push(
            "- [e] CVE correlation: blocked — latest result does not expose an APK package name yet."
                .to_string(),
        );
        if let Some(path) = register_path.as_deref() {
            lines.push(format!(
                "- [d] Attack-surface assessment: ready for {}.",
                path
            ));
        } else {
            lines.push(
                "- [d] Attack-surface assessment: blocked — latest result does not expose an APK package name or JSON artifact path yet."
                    .to_string(),
            );
        }
    }

    if let Some(path) = register_path.as_deref() {
        lines.push(format!("- [z] OWASP mapping: ready for {}.", path));
    } else {
        lines.push(
            "- [z] OWASP mapping: blocked — latest result does not expose a JSON artifact path yet."
                .to_string(),
        );
    }

    if let Some(job_id) = first_job_id(parsed, &["failed", "partial", "cancelled"]) {
        lines.push(format!("- [u] Resume job: ready for {}.", job_id));
    } else {
        lines.push(
            "- [u] Resume job: blocked — no resumable persisted job is visible in the latest result yet."
                .to_string(),
        );
    }
    if let Some(job_id) = first_job_id(parsed, &["failed", "partial", "cancelled", "succeeded"]) {
        lines.push(format!("- [k] Retry job: ready for {}.", job_id));
    } else {
        lines.push(
            "- [k] Retry job: blocked — no finished persisted job is visible in the latest result yet."
                .to_string(),
        );
    }

    Some(lines.join("\n"))
}
