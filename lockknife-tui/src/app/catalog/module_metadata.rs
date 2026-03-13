use super::super::CapabilityMetadata;

pub(super) fn module_description(module_id: &str) -> Option<&'static str> {
    match module_id {
        "credentials" => Some(
            "Recover or inspect lock-screen, Wi-Fi, and keystore secrets from the device.",
        ),
        "extraction" => Some(
            "Collect primary device evidence like messages, media, browser, and location artifacts.",
        ),
        "forensics" => Some(
            "Turn raw evidence into snapshots, correlations, timelines, and investigator-ready reports.",
        ),
        "network" => Some(
            "Capture and summarize device network traffic for communications and API analysis.",
        ),
        "apk" => Some(
            "Inspect APKs for permissions, vulnerabilities, decompilation output, and YARA findings.",
        ),
        "runtime" => Some(
            "Launch and manage Frida-backed runtime sessions, saved scripts, and memory workflows against an app.",
        ),
        "security" => Some(
            "Assess device posture, malware indicators, and hardening signals from collected artifacts.",
        ),
        "intelligence" => Some(
            "Correlate artifacts and identifiers against IOC, CVE, VirusTotal, OTX, STIX, and TAXII sources.",
        ),
        "case" => Some(
            "Create, inspect, search, and export case workspaces that track evidence lineage.",
        ),
        "core" => Some(
            "Verify environment readiness, dependency health, and capability maturity before running deeper workflows.",
        ),
        "ai" => Some(
            "Apply lightweight anomaly scoring and password-prediction helpers to structured inputs.",
        ),
        "crypto" => Some(
            "Extract wallet artifacts and inspect blockchain transaction history from recovered data.",
        ),
        _ => None,
    }
}

pub(super) fn module_help_lines(module_id: &str) -> Vec<&'static str> {
    match module_id {
        "credentials" => vec![
            "These actions are device-backed and are best run with the correct device already selected.",
            "Use them early when credential recovery may unlock richer later extraction steps.",
        ],
        "extraction" => vec![
            "Populate Case directory to auto-register evidence files in the case manifest.",
            "These outputs are good upstream inputs for forensics, security, AI, and reporting workflows.",
        ],
        "forensics" => vec![
            "Use case-aware outputs to keep derived artifacts tied to their original evidence.",
            "Timeline and parse now accept broader evidence families, so one case workspace can move from extraction to investigator review without leaving the TUI.",
            "Generate report, integrity verification, and chain-of-custody can all reuse managed case inventory or the TUI's latest JSON result.",
        ],
        "network" => vec![
            "Capture PCAP first when you need raw evidence, then summarize or discover APIs from it.",
            "Case-aware outputs keep PCAPs and derived summaries in the same investigation workspace.",
        ],
        "apk" => vec![
            "Analyze, permissions, and vulnerability now expose richer manifest, signing, code-signal, and risk drill-down data in Result View.",
            "Decompile is directory-oriented while still emitting structured stage/posture metadata for the generated outputs.",
            "Set Case directory to keep APK findings under derived artifacts for later reporting.",
        ],
        "runtime" => vec![
            "Managed runtime sessions require Case directory so LockKnife can persist script snapshots, JSONL event streams, and reconnect state.",
            "Use Preflight before launch when you need an operator check for Frida readiness, attach mode, and target visibility.",
        ],
        "security" => vec![
            "Most actions emit structured JSON findings that are easy to fold into reports or later review.",
            "Use Case directory to persist security outputs as derived artifacts in the manifest.",
        ],
        "intelligence" => vec![
            "These lookups are best used after extraction or forensics has produced stable indicators to enrich.",
            "Some actions are external-intelligence oriented, so expect them to complement rather than replace local evidence.",
        ],
        "case" => vec![
            "Init workspace first, then reuse the same Case directory across later case-aware actions.",
            "Summary, Artifact search, Lineage graph, and Export bundle help review the case without leaving the TUI.",
        ],
        "core" => vec![
            "Run Core health or Dependency doctor whenever a workstation or virtual environment changes.",
            "Feature matrix keeps the TUI honest about which workflows are stable, gated, or environment-sensitive.",
        ],
        "ai" => vec![
            "AI helpers work best on structured JSON emitted by earlier extraction or analysis steps.",
            "Case-aware outputs keep scored rows and generated candidates attached to the investigation timeline.",
        ],
        "crypto" => vec![
            "Wallet extraction is case-aware and produces structured outputs that can feed later reporting.",
            "Transaction lookup is a follow-on enrichment step once you have candidate addresses.",
        ],
        _ => Vec::new(),
    }
}

pub(super) fn module_capability_metadata(module_id: &str) -> Option<CapabilityMetadata> {
    match module_id {
        "credentials" => Some(CapabilityMetadata {
            status: "best-effort",
            requirements: "adb + device access",
            notes: "TUI credential recovery actions are device-side and can vary by Android version, OEM paths, and privileges.",
        }),
        "extraction" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb + device access",
            notes: "Primary extraction coverage is broad, but some app- and version-specific artifacts still vary in availability.",
        }),
        "forensics" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "local files; some workflows also need adb/device access",
            notes: "Offline SQLite, parse, timeline, and correlation flows are stronger than snapshot-style operations; recovery remains best-effort but now inspects WAL/journal sidecars too.",
        }),
        "network" => Some(CapabilityMetadata {
            status: "mixed",
            requirements: "lockknife[network]; capture also needs root + tcpdump",
            notes: "Derived PCAP analysis is gated by extras, while capture additionally depends on device privileges and tooling.",
        }),
        "apk" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[apk]",
            notes: "Useful today for real static triage and decompile orchestration, but still below full MobSF/Androguard replacement depth.",
        }),
        "runtime" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[frida] + Frida server",
            notes: "Managed session workflows now exist, but success still depends on Frida target compatibility and device/server readiness.",
        }),
        "security" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "adb + device access",
            notes: "Security review flows are now better structured for exported-surface triage, OWASP/MASTG mapping, and SELinux posture review, but they still reflect target-device access and privilege levels.",
        }),
        "intelligence" => Some(CapabilityMetadata {
            status: "mixed",
            requirements: "base install; some sources also need extras or API keys",
            notes: "Local IOC/CVE-style helpers are broader than the external-intelligence lookups that require services and credentials.",
        }),
        "case" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install",
            notes: "Case workspace primitives are real today, but resumable jobs and deeper persistent execution are still ahead.",
        }),
        "core" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "base install + Rust extension",
            notes: "Use these diagnostics to keep the TUI truthful about environment readiness before deeper investigation work.",
        }),
        "ai" => Some(CapabilityMetadata {
            status: "dependency-gated",
            requirements: "lockknife[ml]",
            notes: "AI helpers are optional triage accelerators, not authoritative findings.",
        }),
        "crypto" => Some(CapabilityMetadata {
            status: "functional",
            requirements: "local wallet DB",
            notes: "Useful wallet parsing exists now, but coverage is narrower than specialized crypto-forensics suites.",
        }),
        _ => None,
    }
}

pub(super) fn module_recovery_hint(module_id: &str) -> Option<&'static str> {
    match module_id {
        "runtime" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra frida` and verify the target Frida server.",
        ),
        "apk" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra apk` before running APK workflows.",
        ),
        "network" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra network`; live capture also needs root + tcpdump.",
        ),
        "intelligence" => Some(
            "Recovery: use Diagnostics → Dependency doctor to verify extras and API keys before external intel lookups.",
        ),
        "ai" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra ml` to unlock the optional AI helpers.",
        ),
        _ => None,
    }
}
