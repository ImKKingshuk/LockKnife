use super::*;

#[test]
fn default_modules_include_case_management_actions() {
    let modules = default_modules();
    let case_module = modules
        .iter()
        .find(|module| module.id == "case")
        .expect("case module should be present");

    let action_ids: Vec<&str> = case_module
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    assert!(action_ids.contains(&"case.init"));
    assert!(action_ids.contains(&"case.summary"));
    assert!(action_ids.contains(&"case.graph"));
    assert!(action_ids.contains(&"case.artifacts"));
    assert!(action_ids.contains(&"case.artifact"));
    assert!(action_ids.contains(&"case.lineage"));
    assert!(action_ids.contains(&"case.export"));
    assert!(action_ids.contains(&"case.enrich"));
    assert!(action_ids.contains(&"case.register"));
}

#[test]
fn default_modules_include_diagnostics_actions() {
    let modules = default_modules();
    let diagnostics = modules
        .iter()
        .find(|module| module.id == "core")
        .expect("diagnostics module should be present");

    let action_ids: Vec<&str> = diagnostics
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    assert!(action_ids.contains(&"core.health"));
    assert!(action_ids.contains(&"core.doctor"));
    assert!(action_ids.contains(&"core.features"));
}

#[test]
fn default_modules_expose_module_descriptions_and_help_text() {
    let modules = default_modules();

    for module in &modules {
        assert!(
            module.description().is_some(),
            "module {} should have a description",
            module.id
        );
        assert!(
            !module.help_lines().is_empty(),
            "module {} should have help text",
            module.id
        );
    }

    let runtime = modules
        .iter()
        .find(|module| module.id == "runtime")
        .expect("runtime module should exist");
    assert_eq!(runtime.device_action_count(), 0);
    assert_eq!(runtime.case_aware_action_count(), 12);
    assert_eq!(runtime.output_action_count(), 7);
}

#[test]
fn default_modules_expose_case_dir_for_case_aware_actions() {
    let modules = default_modules();
    let expected_actions = [
        "extraction.sms",
        "extraction.contacts",
        "extraction.call_logs",
        "extraction.browser",
        "extraction.messaging",
        "extraction.media",
        "extraction.location",
        "forensics.snapshot",
        "forensics.sqlite",
        "forensics.timeline",
        "forensics.import_aleapp",
        "forensics.decode_protobuf",
        "forensics.correlate",
        "forensics.recover",
        "apk.permissions",
        "apk.analyze",
        "apk.decompile",
        "apk.vulnerability",
        "apk.scan",
        "runtime.hook",
        "runtime.bypass_ssl",
        "runtime.bypass_root",
        "runtime.trace",
        "runtime.sessions",
        "runtime.session",
        "runtime.session_reload",
        "runtime.session_reconnect",
        "runtime.session_stop",
        "runtime.memory_search",
        "runtime.heap_dump",
        "intelligence.ioc",
        "intelligence.cve",
        "intelligence.cve_risk",
        "intelligence.virustotal",
        "intelligence.otx",
        "intelligence.stix",
        "intelligence.taxii",
        "ai.anomaly_score",
        "ai.predict_passwords",
        "crypto.wallets",
        "case.enrich",
        "report.generate",
        "report.chain_of_custody",
        "report.integrity",
        "credentials.pin",
        "credentials.gesture",
        "credentials.wifi",
        "credentials.keystore",
        "credentials.passkeys",
        "network.capture",
        "network.summarize",
        "network.api_discovery",
        "security.audit",
        "security.selinux",
        "security.malware",
        "security.network_scan",
        "security.bootloader",
        "security.hardware",
        "security.attack_surface",
        "security.owasp",
    ];

    for action_id in expected_actions {
        let action = modules
            .iter()
            .flat_map(|module| module.actions.iter())
            .find(|action| action.id == action_id)
            .unwrap_or_else(|| panic!("missing action {action_id}"));

        assert!(
            action.fields.iter().any(|field| field.key == "case_dir"),
            "action {action_id} should expose a case_dir field"
        );
    }
}

#[test]
fn key_case_aware_actions_expose_descriptions_and_help_text() {
    let modules = default_modules();
    let expected_actions = [
        "case.init",
        "extraction.sms",
        "forensics.snapshot",
        "forensics.import_aleapp",
        "report.generate",
        "report.chain_of_custody",
        "report.integrity",
        "network.capture",
        "apk.analyze",
        "runtime.hook",
        "runtime.heap_dump",
        "security.attack_surface",
        "security.audit",
        "ai.anomaly_score",
        "case.enrich",
        "crypto.wallets",
        "credentials.passkeys",
    ];

    for action_id in expected_actions {
        let action = modules
            .iter()
            .flat_map(|module| module.actions.iter())
            .find(|action| action.id == action_id)
            .unwrap_or_else(|| panic!("action {action_id} should exist"));

        assert!(
            action.description().is_some(),
            "action {action_id} should have a description"
        );
        assert!(
            !action.help_lines().is_empty(),
            "action {action_id} should have help text"
        );
    }
}

#[test]
fn modules_and_actions_expose_truth_alignment_metadata() {
    let modules = default_modules();
    let runtime = modules
        .iter()
        .find(|module| module.id == "runtime")
        .expect("runtime module should exist");
    let runtime_meta = runtime
        .capability_metadata()
        .expect("runtime module should expose capability metadata");
    assert_eq!(runtime_meta.status, "dependency-gated");
    assert!(runtime_meta.requirements.contains("Frida"));

    let doctor = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "core.doctor")
        .expect("core.doctor should exist");
    let doctor_meta = doctor
        .capability_metadata()
        .expect("core.doctor should expose capability metadata");
    assert_eq!(doctor_meta.status, "functional");
    assert!(doctor_meta.notes.contains("remediation hints"));

    let report = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "report.generate")
        .expect("report.generate should exist");
    let report_meta = report
        .capability_metadata()
        .expect("report.generate should expose capability metadata");
    assert_eq!(report_meta.status, "functional");
    assert!(report_meta.notes.contains("PDF"));

    let integrity = modules
        .iter()
        .flat_map(|module| module.actions.iter())
        .find(|action| action.id == "report.integrity")
        .expect("report.integrity should exist");
    let integrity_meta = integrity
        .capability_metadata()
        .expect("report.integrity should expose capability metadata");
    assert_eq!(integrity_meta.status, "functional");
    assert!(integrity_meta.notes.contains("case-manifest"));
}
