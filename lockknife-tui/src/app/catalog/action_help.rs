pub(super) fn action_help_lines(action_id: &str) -> Vec<&'static str> {
    match action_id {
        "core.health" => vec![
            "Use this before blaming a workflow failure on evidence or target behavior.",
            "The result highlights baseline configuration, ADB visibility, and Rust-extension readiness.",
        ],
        "core.doctor" => vec![
            "This is the fastest TUI path for figuring out which extras, binaries, or secrets are still missing.",
            "Hints point to the exact uv sync extra or credential that unlocks a gated workflow.",
        ],
        "core.features" => vec![
            "Read this before promising replacement-level coverage to an operator or stakeholder.",
            "Use the matrix to separate production-ready workflows from best-effort or dependency-gated ones.",
        ],
        "device.list" => vec![
            "Run this before any device-specific workflow to confirm the target is visible and authorized.",
            "The serial shown here is used in most other device actions that require a serial parameter.",
        ],
        "device.info" => vec![
            "Provide the device serial from the list output to get detailed properties.",
            "Useful for verifying Android version, build fingerprint, and device capabilities before forensic work.",
        ],
        "device.connect" => vec![
            "Connect to a device over the network using host:port format (e.g., 192.168.1.100:5555).",
            "The device must have ADB over WiFi enabled (usually via USB debugging + 'adb tcpip 5555').",
        ],
        "device.shell" => vec![
            "Execute arbitrary shell commands on the device for inspection or debugging.",
            "Requires an authorized device serial. Commands run with shell user privileges (not root unless su is available).",
            "Output is truncated after large responses; use specific grep patterns for large file listings.",
        ],
        "case.init" => vec![
            "Use a stable case path so later actions can register into the same manifest.",
            "Set examiner and description early to make later bundles and reports clearer.",
        ],
        "case.export" => vec![
            "Export bundles preserve the registered artifacts and manifest metadata together.",
        ],
        "case.enrich" => vec![
            "Use a seed artifact ID to scope enrichment to one registered item or leave it blank to sweep matching artifacts.",
            "The bundle records provider attribution, credential visibility, and explainability hints alongside saved outputs.",
        ],
        id if id.starts_with("credentials.") => vec![
            "Refresh Devices first and confirm the active target is the device you intend to interrogate before running lock-screen or credential workflows.",
            "Case directory auto-registers manifests and exported source files; leave Output blank to let LockKnife derive a case-managed evidence folder.",
            "If root or device access looks uncertain, run Diagnostics → Core health or doctor before expensive recovery attempts.",
        ],
        id if id.starts_with("extraction.") => vec![
            "Set Case directory to auto-register the extracted evidence in the manifest.",
            "Leave Output blank to let LockKnife derive a case-managed evidence path when supported.",
        ],
        id if id.starts_with("forensics.") => vec![
            "Use Case directory to persist derived forensic outputs under evidence or derived folders.",
            "Structured outputs work best as inputs to timeline, correlation, and reporting workflows.",
        ],
        "report.generate" => vec![
            "Reports can be generated from a case-aware artifacts JSON input or inline data_json.",
            "Leave Output blank with Case directory set to derive a report path automatically.",
            "If PDF backends are unavailable, Result view now calls that out and the CLI can degrade to an HTML fallback path.",
        ],
        "report.chain_of_custody" => vec![
            "Leave Evidence blank with Case directory set to derive the ledger directly from registered artifacts.",
            "Use this before bundle export when you need a reviewer-ready custody summary without leaving the TUI.",
        ],
        "report.integrity" => vec![
            "Integrity verification compares the current workspace files against hashes already recorded in the case manifest.",
            "Use JSON output for automation or text output for operator-facing review and export packets.",
        ],
        id if id.starts_with("network.") => vec![
            "Capture actions preserve raw evidence while summarize and API discovery write derived analysis.",
            "Case directory keeps the resulting PCAPs and summaries tied to the same investigation.",
            "Summaries now surface HTTP, DNS, TLS, and endpoint-cluster hints, but operators should still validate important conclusions against packet-level evidence.",
        ],
        id if id.starts_with("intelligence.") => vec![
            "Source attribution now includes credential/cache visibility and confidence hints so operators can judge coverage gaps quickly.",
            "Local IOC/CVE-style helpers complement — not replace — external reputation services and primary evidence review.",
            "VirusTotal now accepts hashes, URLs, domains, IPs, and URL submissions; IOC detection can optionally layer composite-rule logic.",
        ],
        id if id.starts_with("apk.") => vec![
            "APK analysis outputs are saved as derived artifacts when Case directory is set.",
            "Analyze and Vulnerability now surface exported components, deep links, signing hints, string intel, and combined risk summaries.",
            "Decompile keeps a directory output and records whether the result is raw unpacking, apktool-decoded resources, jadx Java-like source, or hybrid source-recovery output.",
        ],
        "runtime.hook" | "runtime.bypass_ssl" | "runtime.bypass_root" | "runtime.trace" => {
            vec![
                "These launch managed sessions instead of one-shot previews, so Case directory is required for persistence.",
                "Each run saves a script snapshot, JSONL event stream, summary JSON, and reconnectable session metadata.",
            ]
        }
        "runtime.preflight" => vec![
            "Use this before launch when you need a quick signal on Frida bindings, target visibility, and attach-vs-spawn readiness.",
            "Optional Session kind adds compatibility guidance for trace, SSL bypass, root bypass, and similar runtime workflows.",
            "Preflight is diagnostic only; it does not create or mutate a managed session.",
        ],
        "runtime.sessions" | "runtime.session" => vec![
            "Session inventory and detail stay scoped to the active case workspace.",
            "Detail output includes recent event lines plus the saved script inventory for hot-reload workflows.",
        ],
        "runtime.session_reload" | "runtime.session_reconnect" | "runtime.session_stop" => {
            vec![
                "These controls operate on a previously saved managed runtime session in the active case.",
                "Reload saves a new script snapshot; reconnect restores the saved target/script pair; stop finalizes the session state.",
            ]
        }
        "runtime.memory_search" => vec![
            "Enable Hex pattern when the search input should be treated as a hex byte sequence.",
            "Case directory stores the search results as a derived artifact for later review.",
        ],
        "runtime.heap_dump" => vec![
            "Remote output stays on-device; Result output stores the local summary JSON.",
            "Case directory auto-derives the local result path when Result output is left blank.",
        ],
        "security.attack_surface" => vec![
            "Provide APK analysis JSON when you want richer component/deep-link/provider context without re-running APK analysis.",
            "Add Package + Serial only when you want safe live package-manager probes layered onto the static report.",
        ],
        "security.owasp" => vec![
            "This works best on APK-analysis or attack-surface JSON so evidence links survive into the mapping output.",
            "Use the result to decide which MASTG families deserve deeper manual validation before reporting.",
        ],
        "security.selinux" => vec![
            "Use this when device posture matters to later runtime or forensic conclusions, not just as a one-line getenforce check.",
            "Recent AVC denials are most useful when paired with the exact workflow you were exercising on-device.",
        ],
        id if id.starts_with("security.") => vec![
            "Use Case directory to persist scan outputs as derived security artifacts.",
            "Structured JSON results are easier to feed into reports or later case review.",
        ],
        id if id.starts_with("ai.") => vec![
            "These helpers work best on structured JSON inputs that came from earlier extraction or analysis steps.",
            "Case directory keeps the generated AI output tied to the investigation timeline.",
            "Result view now keeps lightweight explainability context so reviewers can see why a row or candidate was surfaced.",
            "Password prediction can mix Markov generation with personal/device data tokens when you provide a personalization JSON file.",
        ],
        "crypto.wallets" => vec![
            "Disable enrichment when you only want extracted addresses without lookup metadata.",
            "Case directory stores the wallet extraction output as a derived artifact.",
        ],
        _ => Vec::new(),
    }
}
