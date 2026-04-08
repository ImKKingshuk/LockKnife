from __future__ import annotations

import dataclasses

FEATURE_STATUSES = (
    "production-ready",
    "functional",
    "best-effort",
    "experimental",
    "dependency-gated",
)


@dataclasses.dataclass(frozen=True)
class FeatureEntry:
    category: str
    capability: str
    cli: str
    status: str
    requirements: str
    notes: str


FEATURE_MATRIX: tuple[FeatureEntry, ...] = (
    FeatureEntry(
        "core",
        "CLI + orchestration",
        "lockknife --cli",
        "production-ready",
        "base install",
        "Stable automation and scripting surface.",
    ),
    FeatureEntry(
        "core",
        "Default TUI",
        "lockknife",
        "functional",
        "Rust extension",
        "Primary operator interface; requires the native extension.",
    ),
    FeatureEntry(
        "device",
        "ADB management",
        "lockknife device ...",
        "functional",
        "adb",
        "Device visibility depends on host ADB and device authorization.",
    ),
    FeatureEntry(
        "credentials",
        "Offline PIN/password cracking",
        "lockknife crack pin|password|password-rules",
        "production-ready",
        "Rust extension",
        "Rust-powered offline workflows.",
    ),
    FeatureEntry(
        "credentials",
        "Device-side credential recovery",
        "lockknife crack pin-device|gesture|wifi",
        "best-effort",
        "adb + device access",
        "Results depend on Android version, OEM paths, and privileges.",
    ),
    FeatureEntry(
        "credentials",
        "Keystore / passkey artifact export",
        "lockknife crack keystore|passkeys",
        "best-effort",
        "adb + device access",
        "Often root- or version-dependent.",
    ),
    FeatureEntry(
        "extraction",
        "Primary artifacts",
        "lockknife extract sms|contacts|call-logs|browser|media|location",
        "functional",
        "adb + device access",
        "Broad coverage with device/app-specific constraints.",
    ),
    FeatureEntry(
        "extraction",
        "Messaging artifacts",
        "lockknife extract messaging",
        "best-effort",
        "adb + app access",
        "Coverage varies by app, encryption, and artifact location.",
    ),
    FeatureEntry(
        "forensics",
        "SQLite analysis / timeline / correlation",
        "lockknife forensics sqlite|timeline|correlate",
        "production-ready",
        "local files",
        "Core offline investigation flows are solid.",
    ),
    FeatureEntry(
        "forensics",
        "Snapshots / recovery",
        "lockknife forensics snapshot|recover",
        "best-effort",
        "adb + device/root for deeper coverage",
        "Long-running and privilege-sensitive workflows.",
    ),
    FeatureEntry(
        "forensics",
        "ALEAPP-style parsing",
        "lockknife forensics parse",
        "functional",
        "local evidence directory",
        "Useful normalization layer, but not full ALEAPP parity yet.",
    ),
    FeatureEntry(
        "reporting",
        "HTML/JSON/CSV reporting",
        "lockknife report generate",
        "functional",
        "base install",
        "Case-aware reports now surface workspace inventory, integrity status, and evidence summaries.",
    ),
    FeatureEntry(
        "reporting",
        "PDF reporting",
        "lockknife report generate --format pdf",
        "dependency-gated",
        "weasyprint or xhtml2pdf",
        "Requires an installed PDF backend.",
    ),
    FeatureEntry(
        "reporting",
        "Chain of custody",
        "lockknife report chain-of-custody",
        "functional",
        "base install",
        "Can now derive richer evidence records directly from managed case manifests.",
    ),
    FeatureEntry(
        "reporting",
        "Case integrity verification",
        "lockknife report integrity",
        "functional",
        "base install",
        "Verifies recorded artifact hashes inside managed case workspaces and emits operator-facing summaries.",
    ),
    FeatureEntry(
        "apk",
        "APK permissions / manifest / heuristics",
        "lockknife apk permissions|analyze|vulnerability",
        "dependency-gated",
        "lockknife[apk]",
        "Static triage is now materially stronger with component, signing, code-signal, and transparent risk outputs, but it is still below full MobSF/Androguard replacement depth.",
    ),
    FeatureEntry(
        "apk",
        "APK unpack / decompile workflow",
        "lockknife apk decompile",
        "best-effort",
        "lockknife[apk]",
        "Structured stage reporting and better decompile posture now exist, but full source-recovery depth still depends on external tooling.",
    ),
    FeatureEntry(
        "apk",
        "YARA / pattern scanning",
        "lockknife apk scan",
        "functional",
        "Rust extension; optional yara fallback",
        "Local scanning is available today.",
    ),
    FeatureEntry(
        "runtime",
        "Frida runtime instrumentation",
        "lockknife runtime ...",
        "dependency-gated",
        "lockknife[frida] + Frida server",
        "Useful helpers exist, but session ergonomics need more work.",
    ),
    FeatureEntry(
        "runtime",
        "Bypass / trace / memory workflows",
        "lockknife runtime bypass-ssl|bypass-root|trace|memory-search|heap-dump",
        "best-effort",
        "lockknife[frida] + compatible target",
        "Highly target- and environment-dependent.",
    ),
    FeatureEntry(
        "security",
        "Device posture / SELinux / bootloader / hardware",
        "lockknife security scan|selinux|bootloader|hardware",
        "functional",
        "adb + device access",
        "Good audit surface with device-dependent findings.",
    ),
    FeatureEntry(
        "security",
        "Malware scanning",
        "lockknife security malware",
        "functional",
        "Rust extension; optional yara fallback",
        "Pattern scanning is available without optional YARA extras.",
    ),
    FeatureEntry(
        "security",
        "OWASP mapping",
        "lockknife security owasp",
        "functional",
        "input artifacts",
        "Good helper for mapping existing findings to MASTG categories.",
    ),
    FeatureEntry(
        "intel",
        "VirusTotal / OTX reputation",
        "lockknife intel virustotal|reputation",
        "dependency-gated",
        "lockknife[threat-intel] + API keys",
        "Installed package and configured credentials both required.",
    ),
    FeatureEntry(
        "intel",
        "IOC / CVE / STIX / TAXII",
        "lockknife intel ioc|cve|stix|taxii",
        "functional",
        "some commands require threat-intel extras",
        "Coverage is broad, with some feeds/queries gated by external services.",
    ),
    FeatureEntry(
        "network",
        "PCAP analysis / API discovery",
        "lockknife network analyze|api-discovery",
        "dependency-gated",
        "lockknife[network]",
        "Useful workflow once scapy is installed.",
    ),
    FeatureEntry(
        "network",
        "Device capture",
        "lockknife network capture",
        "best-effort",
        "lockknife[network] + root + tcpdump",
        "Capture depends heavily on device privileges and tooling.",
    ),
    FeatureEntry(
        "ai",
        "Anomaly / classifier workflows",
        "lockknife ai anomaly|train-malware|classify-malware",
        "dependency-gated",
        "lockknife[ml]",
        "Optional triage workflows, not authoritative findings.",
    ),
    FeatureEntry(
        "ai",
        "Password prediction",
        "lockknife ai predict-password",
        "dependency-gated",
        "lockknife[ml]",
        "Useful assistive workflow, not guaranteed recovery.",
    ),
    FeatureEntry(
        "crypto-wallet",
        "Wallet artifact parsing",
        "lockknife crypto-wallet wallet",
        "functional",
        "local wallet DB",
        "Current support is practical but narrower than specialized wallet suites.",
    ),
)


def iter_features() -> tuple[FeatureEntry, ...]:
    return FEATURE_MATRIX


def filter_features(
    *, status: str | None = None, category: str | None = None
) -> list[FeatureEntry]:
    rows = list(FEATURE_MATRIX)
    if status is not None:
        rows = [row for row in rows if row.status == status]
    if category is not None:
        rows = [row for row in rows if row.category == category]
    return rows
