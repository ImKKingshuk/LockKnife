#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaybookId {
    ApkTriage,
    RuntimeTriage,
    CaseEnrichment,
    AttackSurfaceReview,
    EvidenceToReport,
}

pub(crate) fn playbook_title(playbook: PlaybookId) -> &'static str {
    match playbook {
        PlaybookId::ApkTriage => "APK triage",
        PlaybookId::RuntimeTriage => "Runtime triage",
        PlaybookId::CaseEnrichment => "Case enrichment",
        PlaybookId::AttackSurfaceReview => "Attack-surface review",
        PlaybookId::EvidenceToReport => "Evidence-to-report",
    }
}

pub(crate) fn playbook_summary(playbook: PlaybookId) -> &'static str {
    match playbook {
        PlaybookId::ApkTriage => {
            "Use one APK result to pivot into static security review, runtime readiness, and reportable findings."
        }
        PlaybookId::RuntimeTriage => {
            "Confirm target readiness, launch or reconnect a managed session, then inspect persisted runtime evidence."
        }
        PlaybookId::CaseEnrichment => {
            "Turn the latest result into a case-scoped evidence review, enrichment pass, and persisted job trail."
        }
        PlaybookId::AttackSurfaceReview => {
            "Assess exported surfaces, map them to guidance, and capture the resulting evidence in a reportable form."
        }
        PlaybookId::EvidenceToReport => {
            "Register or reuse structured evidence, enrich it, then generate reviewer-facing outputs with integrity context."
        }
    }
}

pub(crate) fn module_playbook_summary(module_id: &str) -> Option<String> {
    let titles = module_playbooks(module_id)
        .iter()
        .map(|playbook| playbook_title(*playbook))
        .collect::<Vec<_>>();
    if titles.is_empty() {
        None
    } else {
        Some(format!("Playbooks: {}", titles.join(" · ")))
    }
}

pub(crate) fn module_recommended_next_hint(module_id: &str) -> Option<String> {
    match module_id {
        "apk" => Some(
            "Recommended next: start with Analyze or Decompile, then chain into [d] attack surface, [p] runtime preflight, and [e] CVE correlation from Result view."
                .to_string(),
        ),
        "runtime" => Some(
            "Recommended next: start with Preflight, then launch Hook/SSL bypass/Trace once device targeting and case routing are ready."
                .to_string(),
        ),
        "security" => Some(
            "Recommended next: start with Attack surface or Audit, then add OWASP mapping and reporting while the evidence is still fresh."
                .to_string(),
        ),
        "case" => Some(
            "Recommended next: open Summary, pivot into Artifact search or Lineage, then run Enrichment or reporting from the same case workspace."
                .to_string(),
        ),
        "forensics" => Some(
            "Recommended next: produce structured timeline/SQLite outputs, then route them into the evidence-to-report flow from Result view."
                .to_string(),
        ),
        _ => None,
    }
}

pub(crate) fn action_playbook_summary(action_id: &str) -> Option<String> {
    let (playbook, step, total, focus) = action_step(action_id)?;
    Some(format!(
        "Playbook: {} step {}/{} · {}",
        playbook_title(playbook),
        step,
        total,
        focus
    ))
}

pub(crate) fn action_next_step_hint(action_id: &str) -> Option<String> {
    match action_id {
        "apk.analyze" | "apk.decompile" | "apk.permissions" | "apk.vulnerability" | "apk.scan" => Some(
            "Recommended next: use Result view follow-ups to pivot into [d] Attack-surface assessment, [p] Runtime preflight, or [e] CVE correlation once package context is present."
                .to_string(),
        ),
        "runtime.preflight" => Some(
            "Recommended next: launch a managed Hook session or use [b]/[t] live follow-ups when the latest result already exposes package and case context."
                .to_string(),
        ),
        "runtime.hook" | "runtime.bypass_ssl" | "runtime.trace" => Some(
            "Recommended next: inspect [i] Runtime session, then keep [h]/[c]/[o] ready for hot-reload, reconnect, or controlled stop."
                .to_string(),
        ),
        "runtime.sessions" | "runtime.session" | "runtime.session_reload" | "runtime.session_reconnect" | "runtime.session_stop" => Some(
            "Recommended next: preserve the session JSON/JSONL outputs in the active case so later reporting and evidence review stay reproducible."
                .to_string(),
        ),
        "case.summary" | "case.artifacts" | "case.artifact" | "case.lineage" => Some(
            "Recommended next: narrow the case scope, then run [n] Enrichment bundle or open [j]/[u]/[k] job controls when you are ready to scale the workflow."
                .to_string(),
        ),
        "case.enrich" => Some(
            "Recommended next: inspect persisted jobs, then close the loop with [w] Generate report and integrity outputs from the same case context."
                .to_string(),
        ),
        "case.register" => Some(
            "Recommended next: once evidence is registered, chain into [n] Enrichment bundle or [w] Generate report without leaving the active case."
                .to_string(),
        ),
        "security.attack_surface" => Some(
            "Recommended next: add [z] OWASP mapping or [e] CVE correlation, then capture the assessment in [w] reporting once the findings are scoped."
                .to_string(),
        ),
        "security.owasp" => Some(
            "Recommended next: pair this guidance with [d] Attack-surface assessment findings and then move directly into [w] Generate report."
                .to_string(),
        ),
        "intelligence.cve" => Some(
            "Recommended next: merge package intelligence with attack-surface evidence, then keep the report/integrity chain in the same case workspace."
                .to_string(),
        ),
        "report.generate" | "report.integrity" | "report.chain_of_custody" => Some(
            "Recommended next: keep report, integrity, and custody outputs together so the reviewer-facing package stays case-consistent."
                .to_string(),
        ),
        _ => None,
    }
}

fn module_playbooks(module_id: &str) -> &'static [PlaybookId] {
    const APK_PLAYBOOKS: &[PlaybookId] = &[
        PlaybookId::ApkTriage,
        PlaybookId::AttackSurfaceReview,
        PlaybookId::EvidenceToReport,
    ];
    const RUNTIME_PLAYBOOKS: &[PlaybookId] = &[PlaybookId::RuntimeTriage];
    const CASE_PLAYBOOKS: &[PlaybookId] =
        &[PlaybookId::CaseEnrichment, PlaybookId::EvidenceToReport];
    const FORENSICS_PLAYBOOKS: &[PlaybookId] = &[PlaybookId::EvidenceToReport];
    const SECURITY_PLAYBOOKS: &[PlaybookId] = &[PlaybookId::AttackSurfaceReview];
    const EMPTY: &[PlaybookId] = &[];

    match module_id {
        "apk" => APK_PLAYBOOKS,
        "runtime" => RUNTIME_PLAYBOOKS,
        "case" => CASE_PLAYBOOKS,
        "forensics" => FORENSICS_PLAYBOOKS,
        "security" => SECURITY_PLAYBOOKS,
        _ => EMPTY,
    }
}

fn action_step(action_id: &str) -> Option<(PlaybookId, usize, usize, &'static str)> {
    match action_id {
        "apk.analyze" | "apk.decompile" | "apk.permissions" | "apk.vulnerability" | "apk.scan" => {
            Some((
                PlaybookId::ApkTriage,
                1,
                3,
                "capture manifest, component, and decompile context before deeper pivots",
            ))
        }
        "runtime.preflight" => Some((
            PlaybookId::RuntimeTriage,
            1,
            4,
            "confirm Frida, target visibility, and session readiness before live interaction",
        )),
        "runtime.hook" | "runtime.bypass_ssl" | "runtime.trace" => Some((
            PlaybookId::RuntimeTriage,
            2,
            4,
            "launch the right managed live session once preflight and case routing are set",
        )),
        "runtime.sessions" | "runtime.session" => Some((
            PlaybookId::RuntimeTriage,
            3,
            4,
            "inspect persisted runtime state and keep the current session grounded in case context",
        )),
        "runtime.session_reload" | "runtime.session_reconnect" | "runtime.session_stop" => Some((
            PlaybookId::RuntimeTriage,
            4,
            4,
            "recover, refresh, or close the managed session without losing operator state",
        )),
        "case.summary" => Some((
            PlaybookId::CaseEnrichment,
            1,
            4,
            "confirm the active case scope before widening search or enrichment",
        )),
        "case.artifacts" | "case.artifact" | "case.lineage" => Some((
            PlaybookId::CaseEnrichment,
            2,
            4,
            "locate and inspect the exact artifact or lineage branch you want to enrich",
        )),
        "case.enrich" => Some((
            PlaybookId::CaseEnrichment,
            3,
            4,
            "bundle network, intelligence, and AI enrichment over the narrowed case evidence",
        )),
        "case.jobs" | "case.job" | "case.resume_job" | "case.retry_job" => Some((
            PlaybookId::CaseEnrichment,
            4,
            4,
            "inspect or recover persisted execution once enrichment is underway",
        )),
        "security.attack_surface" => Some((
            PlaybookId::AttackSurfaceReview,
            1,
            3,
            "measure exported or reachable surfaces before mapping findings to guidance",
        )),
        "security.owasp" => Some((
            PlaybookId::AttackSurfaceReview,
            2,
            3,
            "translate attack-surface evidence into OWASP/MASTG-oriented review notes",
        )),
        "intelligence.cve" => Some((
            PlaybookId::AttackSurfaceReview,
            3,
            3,
            "pair local attack-surface evidence with package intelligence before reporting",
        )),
        "case.register" => Some((
            PlaybookId::EvidenceToReport,
            1,
            4,
            "turn the latest output into managed evidence before broader review or reporting",
        )),
        "report.generate" => Some((
            PlaybookId::EvidenceToReport,
            3,
            4,
            "package the current evidence state into a reviewer-facing report from the active case",
        )),
        "report.integrity" | "report.chain_of_custody" => Some((
            PlaybookId::EvidenceToReport,
            4,
            4,
            "close the evidence loop with integrity and custody outputs tied to the same case",
        )),
        _ => None,
    }
}
