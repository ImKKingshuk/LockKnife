pub(super) fn action_description(action_id: &str) -> Option<&'static str> {
    match action_id {
        "core.health" => Some(
            "Run the baseline environment checks the TUI depends on before deeper operator workflows.",
        ),
        "core.doctor" => Some(
            "Inspect optional dependencies, API-key readiness, and install hints without leaving the TUI.",
        ),
        "core.features" => Some(
            "Review the current feature matrix so the TUI shows which workflows are stable, best-effort, or dependency-gated.",
        ),
        "device.list" => Some(
            "List all connected ADB devices with their serial numbers, states, and model information.",
        ),
        "device.info" => Some(
            "Retrieve detailed device properties and getprop values for a specific device by serial.",
        ),
        "device.connect" => Some(
            "Connect to a remote device via host:port (e.g., 127.0.0.1:5555) for wireless debugging.",
        ),
        "device.shell" => Some(
            "Execute a shell command on the device and return the output. Useful for device inspection and debugging.",
        ),
        "case.init" => Some("Create a structured case workspace and seed its manifest metadata."),
        "case.summary" => Some("Summarize the current case manifest, metadata, and artifact counts."),
        "case.artifacts" => Some("Search or filter artifacts already registered in a case workspace."),
        "case.artifact" => Some("Inspect a registered artifact by ID or path."),
        "case.lineage" => Some(
            "Inspect parent-child lineage for a registered artifact by ID or path.",
        ),
        "case.export" => Some("Bundle a case workspace for sharing, archival, or offline review."),
        "case.enrich" => Some(
            "Run bundled network, intelligence, and AI enrichment over matching case artifacts.",
        ),
        "credentials.passkeys" => Some(
            "Export passkey-related artifacts into a managed evidence directory and case-linked manifest.",
        ),
        "extraction.sms" => {
            Some("Extract SMS messages into structured evidence for review or correlation.")
        }
        "extraction.contacts" => {
            Some("Collect contacts from the device into reusable structured evidence.")
        }
        "extraction.call_logs" => {
            Some("Pull call history into case-ready evidence files for timeline work.")
        }
        "extraction.browser" => Some(
            "Extract browser history, bookmarks, cookies, downloads, or passwords.",
        ),
        "extraction.messaging" => Some(
            "Extract messaging records or app artifacts from WhatsApp, Signal, or Telegram.",
        ),
        "extraction.media" => {
            Some("Collect media records with EXIF metadata for location and activity review.")
        }
        "extraction.location" => {
            Some("Capture location artifacts or a current location snapshot from the device.")
        }
        "forensics.snapshot" => {
            Some("Create a device snapshot suitable for later forensic preservation and review.")
        }
        "forensics.sqlite" => {
            Some("Analyze a SQLite database with schema, pragma, sidecar, and sample-row context.")
        }
        "forensics.timeline" => {
            Some("Normalize SMS, calls, browser, messaging, media, location, and parsed artifacts into a timeline report.")
        }
        "forensics.parse" => {
            Some("Parse artifact directories into structured families plus protobuf and app-data previews.")
        }
        "forensics.import_aleapp" => Some(
            "Import ALEAPP output into normalized artifact families so timeline and reporting workflows can consume it directly.",
        ),
        "forensics.decode_protobuf" => Some(
            "Decode protobuf blobs into nested field summaries for triage, correlation, and artifact review.",
        ),
        "forensics.correlate" => {
            Some("Correlate multiple JSON artifacts into a combined investigative view.")
        }
        "forensics.recover" => {
            Some("Attempt recovery of deleted fragments from SQLite, WAL, and rollback-journal data.")
        }
        "report.generate" => Some(
            "Render case artifacts into an HTML, PDF, JSON, or CSV report with case-aware evidence and integrity context.",
        ),
        "report.chain_of_custody" => Some(
            "Generate a chain-of-custody ledger from explicit evidence paths or the active case manifest.",
        ),
        "report.integrity" => Some(
            "Verify registered case artifacts against their recorded hashes and emit an operator-facing integrity report.",
        ),
        "network.capture" => {
            Some("Capture network traffic from the device into a PCAP evidence file.")
        }
        "network.summarize" => {
            Some("Summarize a PCAP into a structured network activity overview.")
        }
        "network.api_discovery" => {
            Some("Identify likely API endpoints and hosts from captured network traffic.")
        }
        "apk.permissions" => Some(
            "Score manifest permissions and highlight risky APK permission combinations.",
        ),
        "apk.analyze" => Some(
            "Perform deeper APK analysis with component/export/deeplink/provider, string, signing, and combined risk output.",
        ),
        "apk.decompile" => Some(
            "Extract APK contents and optionally drive apktool/jadx pipelines when those tools are available.",
        ),
        "apk.vulnerability" => Some(
            "Generate a combined APK vulnerability summary with findings, OWASP mapping, library CVE correlation, and risk scoring.",
        ),
        "apk.scan" => Some("Run YARA rules against an APK and persist the resulting matches."),
        "runtime.hook" => Some(
            "Start a named managed hook session, persist the script snapshot, and keep lifecycle controls available.",
        ),
        "runtime.bypass_ssl" => Some(
            "Launch a managed SSL-bypass runtime session with reconnectable Frida state and saved artifacts.",
        ),
        "runtime.bypass_root" => Some(
            "Launch a managed root-bypass runtime session and persist its script, log, and summary artifacts.",
        ),
        "runtime.trace" => Some(
            "Start a managed trace session for a class or method and keep reload/reconnect controls available.",
        ),
        "runtime.preflight" => Some(
            "Run a Frida/operator preflight before starting or reconnecting a managed runtime session.",
        ),
        "runtime.sessions" => Some("Query the saved runtime session inventory for the active case."),
        "runtime.session" => Some(
            "Inspect one managed runtime session, including its recent event tail and saved scripts.",
        ),
        "runtime.session_reload" => Some(
            "Hot-reload the active script for a managed runtime session and save a new script snapshot.",
        ),
        "runtime.session_reconnect" => Some(
            "Reconnect a managed runtime session using its saved app, script, and attach-mode context.",
        ),
        "runtime.session_stop" => {
            Some("Stop a managed runtime session and persist the final stopped state.")
        }
        "runtime.memory_search" => {
            Some("Search process memory for a string or hex pattern and save the hits.")
        }
        "runtime.heap_dump" => Some(
            "Trigger a heap dump on-device and optionally save a local summary JSON.",
        ),
        "security.audit" => {
            Some("Run a high-level device security audit and preserve the findings.")
        }
        "security.selinux" => Some(
            "Collect SELinux enforcement, domain, AVC-denial, and remediation posture details from the device.",
        ),
        "security.malware" => {
            Some("Run a YARA-backed malware scan against a target file or artifact.")
        }
        "security.network_scan" => {
            Some("Inspect DNS, cache, and listening sockets for device network exposure.")
        }
        "security.bootloader" => {
            Some("Review bootloader state and related device security posture.")
        }
        "security.hardware" => Some("Inspect TEE and hardware-backed security characteristics."),
        "security.attack_surface" => Some(
            "Assess exported components, deep links, and providers from APK evidence with optional safe live-device probes.",
        ),
        "security.owasp" => Some(
            "Map extracted findings to OWASP Mobile and MASTG categories with evidence-aware coverage details.",
        ),
        "ai.anomaly_score" => {
            Some("Score structured rows for anomalies using selected feature keys.")
        }
        "ai.predict_passwords" => {
            Some("Generate likely password candidates from a training wordlist with optional device-personalization hints.")
        }
        "crypto.wallets" => Some(
            "Extract wallet-related addresses from a SQLite database and optionally enrich them.",
        ),
        _ => match action_id.split_once('.') {
            Some(("credentials", "offline_pin")) => {
                Some("Brute-force numeric PIN offline using Rust-accelerated search against a password hash.")
            }
            Some(("credentials", "offline_password")) => {
                Some("Dictionary attack against a password hash using a wordlist file.")
            }
            Some(("credentials", "offline_password_rules")) => {
                Some("Rule-based password cracking with suffix mutations for broader coverage.")
            }
            Some(("extraction", "all")) => {
                Some("Bulk extract all primary artifacts (SMS, contacts, call logs, browser, media, location) in a single operation.")
            }
            Some(("credentials", _)) => {
                Some("Run a focused credential or lock-screen recovery workflow.")
            }
            Some(("intelligence", _)) => {
                Some("Correlate findings against threat or vulnerability intelligence sources.")
            }
            _ => None,
        },
    }
}
