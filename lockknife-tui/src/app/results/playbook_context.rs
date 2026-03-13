use serde_json::Value;

use super::paths::{
    extract_apk_package, extract_artifact_string, extract_case_dir_from_value,
    extract_runtime_session_id, latest_register_path,
};
use super::ResultPath;
use crate::app::{playbook_summary, playbook_title, PlaybookId};

struct ResultPlaybookContext {
    case_target: Option<String>,
    register_path: Option<String>,
    artifact_id: Option<String>,
    runtime_session_id: Option<String>,
    apk_package: Option<String>,
    has_attack_surface: bool,
    has_owasp: bool,
    has_selinux: bool,
}

pub(super) fn build_playbook_context_section(
    paths: &[ResultPath],
    parsed: Option<&Value>,
    active_case_dir: Option<&str>,
) -> Option<String> {
    let context = ResultPlaybookContext::from_result(paths, parsed, active_case_dir);
    let mut sections = Vec::new();

    if context.apk_package.is_some() {
        sections.push(render_apk_triage(&context));
        sections.push(render_runtime_triage(&context));
        sections.push(render_attack_surface_review(&context));
        sections.push(render_evidence_to_report(&context));
    } else if context.has_security_review() {
        sections.push(render_security_review(&context));
        if context.case_target.is_some() {
            sections.push(render_evidence_to_report(&context));
        }
    } else if context.case_target.is_some() {
        sections.push(render_case_enrichment(&context));
        sections.push(render_evidence_to_report(&context));
    }

    if sections.is_empty() {
        None
    } else {
        Some(sections.join("\n\n"))
    }
}

impl ResultPlaybookContext {
    fn from_result(
        paths: &[ResultPath],
        parsed: Option<&Value>,
        active_case_dir: Option<&str>,
    ) -> Self {
        let active_case_dir = active_case_dir
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let result_case_dir = paths
            .iter()
            .find(|path| path.label == "Case directory")
            .map(|path| path.value.clone())
            .or_else(|| extract_case_dir_from_value(parsed));
        let case_target = result_case_dir
            .map(|case_dir| case_dir.to_string())
            .or_else(|| active_case_dir.map(|case_dir| format!("active case {}", case_dir)));

        Self {
            case_target,
            register_path: extract_artifact_string(parsed, "path")
                .or_else(|| latest_register_path(paths)),
            artifact_id: extract_artifact_string(parsed, "artifact_id"),
            runtime_session_id: extract_runtime_session_id(parsed),
            apk_package: extract_apk_package(parsed),
            has_attack_surface: parsed.and_then(|value| value.get("risk_summary")).is_some(),
            has_owasp: parsed.and_then(|value| value.get("mastg_ids")).is_some(),
            has_selinux: parsed
                .and_then(|value| value.get("mode").or_else(|| value.get("status")))
                .is_some()
                && parsed.and_then(|value| value.get("posture")).is_some(),
        }
    }

    fn has_security_review(&self) -> bool {
        self.has_attack_surface || self.has_owasp || self.has_selinux
    }
}

fn render_apk_triage(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::ApkTriage);
    match context.apk_package.as_deref() {
        Some(package) => {
            lines.push(format!(
                "- Next: [d] Attack-surface assessment — ready for APK package {}{}.",
                package,
                package_detail(context)
            ));
            lines.push(format!(
                "- 2. [p] Runtime preflight — ready for APK package {}.",
                package
            ));
            lines.push(format!(
                "- 3. [e] CVE correlation — ready for APK package {}.",
                package
            ));
        }
        None => {
            lines.push(
                "- Next: [d] Attack-surface assessment — blocked — latest result does not expose an APK package or reviewable artifact yet."
                    .to_string(),
            );
            lines.push(
                "- 2. [p] Runtime preflight — blocked — recover package context from APK analysis or decompile output first."
                    .to_string(),
            );
            lines.push(
                "- 3. [e] CVE correlation — blocked — package context is still missing."
                    .to_string(),
            );
        }
    }
    lines.join("\n")
}

fn render_runtime_triage(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::RuntimeTriage);
    match context.apk_package.as_deref() {
        Some(package) => lines.push(format!(
            "- Next: [p] Runtime preflight — ready for APK package {}.",
            package
        )),
        None => lines.push(
            "- Next: [p] Runtime preflight — blocked — latest result does not expose an APK package name yet."
                .to_string(),
        ),
    }

    match (context.case_target.as_deref(), context.apk_package.as_deref()) {
        (Some(case_target), Some(package)) => {
            lines.push(format!(
                "- 2. [b]/[t] Live session — ready for APK package {} in {}.",
                package, case_target
            ));
        }
        (None, Some(_)) => lines.push(
            "- 2. [b]/[t] Live session — blocked — recover or set a case directory before opening managed runtime evidence."
                .to_string(),
        ),
        _ => lines.push(
            "- 2. [b]/[t] Live session — blocked — runtime pivots need package context first."
                .to_string(),
        ),
    }

    match (
        context.case_target.as_deref(),
        context.runtime_session_id.as_deref(),
    ) {
        (Some(case_target), Some(session_id)) => {
            lines.push(format!(
                "- 3. [i] Runtime session — ready for {} in {}.",
                session_id, case_target
            ));
            lines.push(format!(
                "- 4. [h]/[c]/[o] Session recovery — ready for {} in {}.",
                session_id, case_target
            ));
        }
        (Some(_), None) => {
            lines.push(
                "- 3. [i] Runtime session — blocked — latest result does not expose a managed session ID yet."
                    .to_string(),
            );
            lines.push(
                "- 4. [h]/[c]/[o] Session recovery — blocked — inspect or launch a managed session first."
                    .to_string(),
            );
        }
        _ => {
            lines.push(
                "- 3. [i] Runtime session — blocked — managed session review needs both case context and a session ID."
                    .to_string(),
            );
            lines.push(
                "- 4. [h]/[c]/[o] Session recovery — blocked — managed session context is still missing."
                    .to_string(),
            );
        }
    }

    lines.join("\n")
}

fn render_case_enrichment(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::CaseEnrichment);
    match context.case_target.as_deref() {
        Some(case_target) => {
            lines.push(format!(
                "- Next: [s] Case summary — ready for {}.",
                case_target
            ));
            lines.push(format!(
                "- 2. [f]/[a]/[l] Evidence review — ready for {}.",
                case_target
            ));
            lines.push(format!(
                "- 3. [n] Enrichment bundle — ready for {}{}.",
                case_target,
                artifact_detail(context)
            ));
            lines.push(format!(
                "- 4. [j]/[u]/[k] Persisted jobs — ready for {}.",
                case_target
            ));
        }
        None => {
            lines.push(
                "- Next: [s] Case summary — blocked — latest result does not expose a case directory yet."
                    .to_string(),
            );
            lines.push(
                "- 2. [f]/[a]/[l] Evidence review — blocked — set or recover a case workspace first."
                    .to_string(),
            );
            lines.push(
                "- 3. [n] Enrichment bundle — blocked — no case-scoped evidence target is available yet."
                    .to_string(),
            );
            lines.push(
                "- 4. [j]/[u]/[k] Persisted jobs — blocked — job history becomes meaningful once the case workflow starts."
                    .to_string(),
            );
        }
    }
    lines.join("\n")
}

fn render_attack_surface_review(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::AttackSurfaceReview);
    match context.apk_package.as_deref() {
        Some(package) => {
            lines.push(format!(
                "- Next: [d] Attack-surface assessment — ready for APK package {}{}.",
                package,
                package_detail(context)
            ));
            if let Some(path) = context.register_path.as_deref() {
                lines.push(format!("- 2. [z] OWASP mapping — ready for {}.", path));
            } else {
                lines.push(
                    "- 2. [z] OWASP mapping — blocked — latest result does not expose a JSON artifact path yet."
                        .to_string(),
                );
            }
            lines.push(format!(
                "- 3. [e] CVE correlation — ready for APK package {}.",
                package
            ));
            lines.push(report_line(context.case_target.as_deref()));
        }
        None => {
            lines.push(
                "- Next: [d] Attack-surface assessment — blocked — package context is missing from the latest result."
                    .to_string(),
            );
            lines.push(
                "- 2. [z] OWASP mapping — blocked — no reviewable JSON artifact is visible yet."
                    .to_string(),
            );
            lines.push(
                "- 3. [e] CVE correlation — blocked — package context is missing from the latest result."
                    .to_string(),
            );
            lines.push(report_line(context.case_target.as_deref()));
        }
    }
    lines.join("\n")
}

fn render_security_review(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::AttackSurfaceReview);
    if context.has_attack_surface {
        lines.push(
            "- Next: review the Security context score breakdown and confirm the highest-signal exported/provider/deep-link path first."
                .to_string(),
        );
    } else {
        lines.push(
            "- Next: use the current security result as a review anchor before pivoting into reporting or enrichment."
                .to_string(),
        );
    }
    if let Some(path) = context.register_path.as_deref() {
        lines.push(format!("- 2. [z] OWASP mapping — ready for {}.", path));
    } else {
        lines.push(
            "- 2. [z] OWASP mapping — blocked — latest result does not expose a reviewable JSON artifact path yet."
                .to_string(),
        );
    }
    if context.has_selinux {
        lines.push(
            "- 3. Inspect recent AVC denials and posture hints, then decide whether enforcement state affects your trust in later runtime evidence."
                .to_string(),
        );
    } else if let Some(package) = context.apk_package.as_deref() {
        lines.push(format!(
            "- 3. [e] CVE correlation — ready for APK package {}.",
            package
        ));
    } else {
        lines.push(
            "- 3. If package context becomes available, pivot into CVE correlation after triaging the reachable attack paths."
                .to_string(),
        );
    }
    if context.has_attack_surface {
        lines.push(report_line(context.case_target.as_deref()));
    }
    lines.join("\n")
}

fn render_evidence_to_report(context: &ResultPlaybookContext) -> String {
    let mut lines = playbook_header(PlaybookId::EvidenceToReport);
    match (
        context.case_target.as_deref(),
        context.register_path.as_deref(),
    ) {
        (Some(case_target), Some(path)) => {
            lines.push(format!(
                "- Next: [r] Register artifact — ready for {} in {}.",
                path, case_target
            ));
            lines.push(format!(
                "- 2. [n] Enrichment bundle — ready for {}{}.",
                case_target,
                artifact_detail(context)
            ));
            lines.push(format!(
                "- 3. [w] Generate report — ready for {}.",
                case_target
            ));
            lines.push(format!(
                "- 4. [g]/[v] Integrity + custody — ready for {}.",
                case_target
            ));
        }
        (Some(case_target), None) => {
            lines.push(
                "- Next: [r] Register artifact — blocked — latest result does not expose a registerable path yet."
                    .to_string(),
            );
            lines.push(format!(
                "- 2. [n] Enrichment bundle — ready for {}{}.",
                case_target,
                artifact_detail(context)
            ));
            lines.push(format!(
                "- 3. [w] Generate report — ready for {}.",
                case_target
            ));
            lines.push(format!(
                "- 4. [g]/[v] Integrity + custody — ready for {}.",
                case_target
            ));
        }
        (None, _) => {
            lines.push(
                "- Next: [r] Register artifact — blocked — recover or set a case directory before reviewer-facing outputs."
                    .to_string(),
            );
            lines.push(
                "- 2. [n] Enrichment bundle — blocked — a case-scoped evidence target is still missing."
                    .to_string(),
            );
            lines.push(
                "- 3. [w] Generate report — blocked — case-first reporting needs a case directory first."
                    .to_string(),
            );
            lines.push(
                "- 4. [g]/[v] Integrity + custody — blocked — case context is still missing."
                    .to_string(),
            );
        }
    }
    lines.join("\n")
}

fn playbook_header(playbook: PlaybookId) -> Vec<String> {
    vec![
        playbook_title(playbook).to_string(),
        format!("- Scope: {}", playbook_summary(playbook)),
    ]
}

fn package_detail(context: &ResultPlaybookContext) -> String {
    match (
        context.register_path.as_deref(),
        context.case_target.as_deref(),
    ) {
        (Some(path), Some(case_target)) => format!(" using {} in {}", path, case_target),
        (Some(path), None) => format!(" using {}", path),
        (None, Some(case_target)) => format!(" in {}", case_target),
        (None, None) => String::new(),
    }
}

fn artifact_detail(context: &ResultPlaybookContext) -> String {
    context
        .artifact_id
        .as_deref()
        .map(|artifact_id| format!(" using {}", artifact_id))
        .unwrap_or_default()
}

fn report_line(case_target: Option<&str>) -> String {
    match case_target {
        Some(case_target) => format!("- 4. [w] Generate report — ready for {}.", case_target),
        None => {
            "- 4. [w] Generate report — blocked — recover or set a case directory before case-first reporting."
                .to_string()
        }
    }
}
