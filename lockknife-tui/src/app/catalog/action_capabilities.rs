use super::super::CapabilityMetadata;

pub(super) fn action_capability_metadata(action_id: &str) -> Option<CapabilityMetadata> {
    match action_id {
        "core.health" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + Rust extension",
            notes: "Baseline config, ADB, and native-extension checks should pass before treating later failures as workflow issues.",
        }),
        "core.doctor" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Dependency doctor exposes optional extras, missing binaries, and missing secrets with remediation hints.",
        }),
        "core.features" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Use the feature matrix to verify maturity claims before relying on a workflow in the TUI.",
        }),
        "device.list" | "device.info" | "device.connect" | "device.shell" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb",
            notes: "Device management requires adb binaries in PATH or lockknife[adb] extras. Connection and shell actions may require device authorization.",
        }),
        "credentials.pin" | "credentials.gesture" | "credentials.wifi" | "credentials.keystore" => {
            Some(CapabilityMetadata {
                status: "best-effort",
                requirements: "adb + device access",
                notes: "Results depend on Android version, OEM paths, privilege level, and target state.",
            })
        }
        "extraction.messaging" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "adb + app access",
            notes: "Coverage varies by app, encryption scheme, and artifact location.",
        }),
        "extraction.sms"
        | "extraction.contacts"
        | "extraction.call_logs"
        | "extraction.browser"
        | "extraction.media"
        | "extraction.location" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb + device access",
            notes: "Broad coverage exists today, but some outputs remain device- and app-specific.",
        }),
        "forensics.snapshot" | "forensics.recover" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "adb + device/root for deeper coverage",
            notes: "These paths are long-running and more sensitive to privileges, scale, and device behavior.",
        }),
        "forensics.sqlite" | "forensics.timeline" | "forensics.parse" | "forensics.correlate" => {
            Some(CapabilityMetadata {
                status: "production-ready",
                requirements: "local files",
                notes: "These offline investigation flows are among the most stable capabilities in LockKnife today, especially in case-aware file-based workflows.",
            })
        }
        "report.generate" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install; PDF also needs weasyprint or xhtml2pdf",
            notes: "Case-aware reporting now folds in workspace inventory, integrity verification, and evidence summaries; PDF output remains dependency-gated.",
        }),
        "report.chain_of_custody" | "report.integrity" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install; integrity requires a managed case workspace",
            notes: "These reporting support flows are case-manifest aware and help operators package evidence with clearer provenance and drift signals.",
        }),
        "case.init"
        | "case.summary"
        | "case.graph"
        | "case.artifacts"
        | "case.artifact"
        | "case.lineage"
        | "case.export"
        | "case.enrich"
        | "case.register" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Case workspace and artifact-manifest flows are live, though resumable execution still needs another pass.",
        }),
        "network.capture" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "lockknife[network] + root + tcpdump",
            notes: "Device capture depends heavily on device privileges, shell tooling, and traffic visibility.",
        }),
        "network.summarize" | "network.api_discovery" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[network]",
            notes: "These workflows are useful once the network extras are installed, but they are not available on a base install.",
        }),
        "apk.permissions" | "apk.analyze" | "apk.vulnerability" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[apk]",
            notes: "Static APK triage is now materially stronger with components, signing, code signals, and transparent risk scoring, but it still sits below full replacement parity for dedicated APK suites.",
        }),
        "apk.decompile" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "lockknife[apk]",
            notes: "Structured unpack/apktool/jadx stage reporting now exists, but deeper source-recovery ergonomics still depend on external tooling.",
        }),
        "apk.scan" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "Rust extension; optional yara fallback",
            notes: "Local scanning is available today even when optional Python YARA support is absent.",
        }),
        "runtime.hook" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[frida] + Frida server",
            notes: "Managed hook sessions save scripts, logs, and reconnect state when Case directory is set.",
        }),
        "runtime.bypass_ssl"
        | "runtime.bypass_root"
        | "runtime.trace"
        | "runtime.preflight"
        | "runtime.sessions"
        | "runtime.session"
        | "runtime.session_reload"
        | "runtime.session_reconnect"
        | "runtime.session_stop"
        | "runtime.memory_search"
        | "runtime.heap_dump" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "lockknife[frida] + compatible target",
            notes: "These workflows are highly target- and environment-dependent even after runtime extras are installed and preflight passes.",
        }),
        "security.attack_surface" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "APK analysis JSON or APK path; adb optional for live probes",
            notes: "Static assessment works offline, while safe package-manager probes enrich exported component, provider, and deep-link reachability when a device and package are available.",
        }),
        "security.audit"
        | "security.selinux"
        | "security.network_scan"
        | "security.bootloader"
        | "security.hardware"
        | "security.owasp" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb + device access",
            notes: "Security findings are generally available today, but artifact quality and device privilege still shape how much evidence the workflow can surface.",
        }),
        "security.malware" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "Rust extension; optional yara fallback",
            notes: "Pattern-based malware scanning is available locally even without optional yara-python.",
        }),
        "intelligence.virustotal" | "intelligence.otx" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[threat-intel] + API keys",
            notes: "External-intelligence lookups need both the package extras and configured service credentials.",
        }),
        "intelligence.ioc" | "intelligence.cve" | "intelligence.stix" | "intelligence.taxii" => {
            Some(CapabilityMetadata {
                status: "functional",
                requirements: "some commands also need threat-intel extras",
                notes: "Coverage is broad, but certain feeds and queries still depend on external services or extras.",
            })
        }
        "ai.anomaly_score" | "ai.predict_passwords" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[ml]",
            notes: "These workflows are assistive triage helpers rather than authoritative conclusions.",
        }),
        "crypto.wallets" | "crypto.transactions" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "local wallet DB or address input",
            notes: "Current support is practical, but not as deep as specialized crypto-investigation suites.",
        }),
        "credentials.offline_pin" => Some(CapabilityMetadata {
            status: "production-ready",
            requirements: "Rust extension",
            notes: "High-speed offline PIN brute-force powered by the Rust native core. No device needed.",
        }),
        "credentials.offline_password" => Some(CapabilityMetadata {
            status: "production-ready",
            requirements: "Rust extension + wordlist",
            notes: "Rust-accelerated dictionary attack. Runs entirely offline against a password hash.",
        }),
        "credentials.offline_password_rules" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + wordlist",
            notes: "Rule-based password mutation with suffix generation. Broader coverage than plain dictionary.",
        }),
        "extraction.all" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb + device access",
            notes: "Bulk extraction across all primary categories. Individual failures don't block the overall run.",
        }),
        "case.runtime_sessions" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + case workspace",
            notes: "Lists Frida/runtime sessions tracked within a case workspace.",
        }),
        "case.chain_of_custody" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + case workspace",
            notes: "Case-aware chain-of-custody derived from the managed artifact manifest.",
        }),
        "case.integrity" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + case workspace",
            notes: "Verifies artifact hashes against the case manifest to detect tampering or drift.",
        }),
        "apk.dex" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "Rust extension",
            notes: "Rust-powered DEX header parsing works on both standalone DEX files and APK archives.",
        }),
        "ai.train_malware" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[ml]",
            notes: "ML classifier training on labeled feature data. Requires scikit-learn via the ml extra.",
        }),
        "ai.classify_malware" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[ml]",
            notes: "Classification using a previously trained model. Requires the same ml extras.",
        }),
        "analyze.evidence" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Composite analysis combining artifact parsing, IOC detection, and DEX pattern scanning.",
        }),
        "plugins.list" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Discovers plugins from entry points and environment modules.",
        }),
        _ => None,
    }
}
