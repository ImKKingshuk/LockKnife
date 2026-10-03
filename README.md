<div align="center">

<img src="https://lockknife.vercel.app/icon.png" width="80" alt="LockKnife"/>

# LockKnife

### Android Security Research & Digital Forensics

A case-first investigation workspace. Interactive TUI. Scriptable CLI. Rust-accelerated analysis.

[![Release](https://img.shields.io/github/v/release/ImKKingshuk/LockKnife?style=flat-square)](https://github.com/ImKKingshuk/LockKnife/releases)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-22863A?style=flat-square)](#installation)
[![License](https://img.shields.io/badge/License-GPL--3.0--only-blue?style=flat-square)](LICENSE)

**[Website](https://lockknife.vercel.app) · [Download](https://github.com/ImKKingshuk/LockKnife/releases) · [Documentation](#documentation) · [Changelog](CHANGELOG.md)**

</div>

---

LockKnife brings Android artifact extraction, offline forensics, APK inspection,
runtime instrumentation, threat intelligence, and reporting into one terminal
workspace. Organize evidence around a case, inspect results interactively, and
use the same toolkit from scripts.

Python handles orchestration and integrations. Rust powers the TUI and
performance-critical hashing, credential recovery, parsing, and pattern matching.

**Collect evidence. Trace artifact lineage. Analyze applications. Verify integrity. Generate reports.**

## Explore

[Quick Start](#quick-start) · [Installation](#installation) · [Features](#features) ·
[Case Workflow](#case-workflow) · [APK Decompilation](#apk-decompilation) ·
[Configuration](#configuration) · [Documentation](#documentation)

## Quick Start

```bash
# Check your installation and available dependencies
lockknife --version
lockknife --cli doctor

# List connected, authorized devices
lockknife --cli device list

# Open the investigation workspace
lockknife
```

| Interface | Command | Use |
|-----------|---------|-----|
| Interactive TUI | `lockknife` | Case workflows, guided actions, result review |
| Headless CLI | `lockknife --cli <command>` | Scripting, automation, remote terminals |
| Headless alias | `lockknife --headless <command>` | The same CLI without the TUI |
| Classic menu | `lockknife interactive` | Menu-based navigation |

Inspect commands and capability requirements without running an operation:

```bash
lockknife --cli --help
lockknife --cli actions --format json
lockknife --cli features
lockknife --cli extract --help
```

## Installation

### Install Script

For macOS and Linux with Bash:

```bash
curl -fsSL https://lockknife.vercel.app/install | bash
```

Review the script before running it in a sensitive environment.

### Homebrew

On macOS:

```bash
brew install ImKKingshuk/tap/lockknife
```

### Release Wheels

Download the matching wheel from [Releases](https://github.com/ImKKingshuk/LockKnife/releases)
and install it with Python 3.12 or newer:

Use a dedicated Python virtual environment for wheel and source installations.

```bash
python -m pip install /path/to/downloaded-wheel.whl
```

Replace the example path with the actual downloaded filename.

| Platform | Release Build Targets |
|----------|-----------------------|
| Linux | x86-64, ARM64 |
| macOS | Apple Silicon |
| Windows | x86-64 |

Linux-only wireless tools require a suitable Linux environment. Windows users
can use WSL for workflows that depend on those tools.

### From Source

Install Python 3.12+, Rust, and a platform C/C++ build toolchain. From the repository root:

```bash
python -m pip install .
```

ADB operations require Android platform-tools (`adb`) on PATH or a configured
`adb_path`. Root, userdebug, or app-specific access may be needed for protected
artifacts.

<details>
<summary><strong>Optional integrations and external tools</strong></summary>

Install extras from a source checkout, selecting only the integrations you need:

```bash
python -m pip install '.[apk,network]'
```

| Extra | Integration | Additional Requirements |
|-------|-------------|-------------------------|
| `apk` | APK manifest and metadata analysis | JADX / apktool for source and resource recovery |
| `frida` | Runtime instrumentation | Compatible Frida server or gadget |
| `network` | Scapy-backed packet analysis | Root + device-side tcpdump for capture |
| `yara` | YARA rules | Platform-compatible YARA installation |
| `threat-intel` | VirusTotal and OTX | Service credentials and connectivity |
| `ml` | Machine-learning backends | Suitable models and input data |
| `full` | All packaged extras | External requirements still apply |

PDF generation requires a working `weasyprint` or `xhtml2pdf` installation.
When a PDF backend is unavailable, report generation can produce an HTML fallback.

</details>

---

## Features

**Local** features work with supplied files. **Device-dependent** features require
appropriate target access. **Dependency-gated** features need optional packages,
tools, or service credentials. **Experimental** results are not proof of live
exploit capability.

### Case Management & Evidence Integrity

- SQLite-backed cases with artifact inventories, job history, and runtime-session records.
- Artifact hashes, source commands, input provenance, and parent/child lineage.
- Searchable artifact views, case summaries, lineage graphs, and enrichment workflows.
- Append-only, hash-chained audit events and integrity verification.
- Consistent SQLite backups in export bundles, with optional original artifacts.
- JSON compatibility manifests and migration from existing case manifests.
- Custody records and explicit-key artifact sealing.

`case init` · `case artifacts` · `case artifact` · `case lineage` · `case graph` · `case enrich` · `case export`

### Device Management & Extraction

- ADB device listing, connection, information, and shell operations.
- SMS, contacts, and call logs.
- Chrome/Firefox history, bookmarks, downloads, cookies, and saved-login artifacts.
- WhatsApp, Telegram, and Signal artifact workflows.
- Media extraction with EXIF metadata.
- Location artifacts and dumpsys snapshot analysis.
- Aggregate extraction with per-dataset error reporting.
- Multi-device execution for supported operations.

`device` · `extract sms` · `extract contacts` · `extract call-logs` · `extract browser` · `extract messaging` · `extract media` · `extract location` · `extract all`

**Access limits:** Android version, OEM paths, root status, and app encryption
affect coverage. SQLCipher-protected messages require suitable keys; inaccessible
data is not guaranteed to be recoverable.

### Credentials & Recovery

- Rust-accelerated offline PIN and dictionary recovery.
- Rule-based password candidate mutations.
- Device-side PIN and gesture recovery from available artifacts.
- WiFi credential extraction and keystore inspection.
- Passkey artifact export on supported devices.

`crack pin` · `crack password` · `crack password-rules` · `crack pin-device` · `crack gesture` · `crack wifi` · `crack keystore` · `crack passkeys`

**Access limits:** Protected credentials remain subject to device encryption and
hardware-backed security. Exporting passkey artifacts does not bypass those protections.

### Offline Forensics

- SQLite inspection and Rust-assisted bulk extraction.
- Timelines across supported artifact types.
- Cross-artifact correlation and evidence analysis.
- ALEAPP-compatible import and normalized artifact export.
- Protobuf decoding, file carving, and deleted-record recovery heuristics.
- Device snapshots, with deeper acquisition where privileges allow.

`forensics sqlite` · `forensics timeline` · `forensics correlate` · `forensics parse` · `forensics import-aleapp` · `forensics decode-protobuf` · `forensics carve` · `forensics recover` · `forensics snapshot` · `analyze evidence`

**Interpretation limits:** Recovery fragments are leads, not proof that a record
was deleted. Neither recovery nor snapshotting guarantees a complete device image.

### APK Analysis & Decompilation

- Manifest, component, deep-link, permission, and SDK inspection.
- Signing metadata, library indicators, string/code signals, and heuristic risk summaries.
- Native DEX header extraction.
- JADX source reconstruction, apktool resource/smali decoding, and archive extraction.
- Automatic decompiler fallback with failed-stage reporting and per-stage timeouts.
- Built-in pattern scanning and optional YARA rules.
- Bounded archive extraction with path/type checks and evidence-overwrite protection.

`apk permissions` · `apk analyze` · `apk vulnerability` · `apk decompile` · `apk scan`

Manifest analysis requires the `apk` extra. Heuristic findings require review;
reconstructed source is not guaranteed to be complete or buildable.

### Runtime Instrumentation

- Frida attach/spawn and script loading.
- Managed session history and script inventory in case workspaces.
- Session reload, reconnect, and stop actions in the TUI.
- Built-in script discovery, method tracing, root/SSL-pinning hook workflows.
- Memory-search and heap-dump helpers.
- Preflight diagnostics and policy-gated, checksum-verified Frida remediation.

`runtime hook` · `runtime builtin-script` · `runtime trace` · `runtime bypass-root` · `runtime bypass-ssl` · `runtime memory-search` · `runtime heap-dump`

Requires compatible Frida deployment and an accessible, authorized target.
Hook behavior depends on the application's implementation and Android environment.

### Network & Security Assessment

- PCAP summaries and API endpoint discovery.
- Bounded native packet analysis with conservative Python/Scapy fallback.
- IPv4 parsing and device-side traffic capture.
- Device posture, SELinux, bootloader, and hardware-security checks.
- Attack-surface assessment and network-scan helpers.
- Pattern/YARA malware scanning and OWASP MASTG mapping.

`network analyze` · `network api-discovery` · `network capture` · `security scan` · `security selinux` · `security bootloader` · `security hardware` · `security attack-surface` · `security malware` · `security owasp`

Capture generally requires root and tcpdump. Encrypted traffic limits endpoint
visibility. Heuristic checks and MASTG mappings are not a complete security audit.

### Threat Intelligence, AI & Wallet Analysis

- Local IOC extraction and matching.
- CVE correlation and Android risk scoring.
- STIX/TAXII indicator workflows and IOC database management.
- VirusTotal and OTX reputation lookups.
- Anomaly scoring, password candidate helpers, and optional malware-model workflows.
- Wallet-address discovery, enrichment, and transaction analysis.

`intel` · `ai` · `crypto-wallet wallet`

External lookups require connectivity and may transmit submitted indicators.
Optional services and models have their own credentials, coverage, and input requirements.

### Reporting

- Technical and executive HTML reports.
- JSON and CSV exports.
- PDF generation with explicit HTML fallback.
- Evidence previews, case summaries, provenance, and integrity sections.
- Chain-of-custody reports and optional report signing.
- Verification of artifact hashes and case audit history.

`report generate` · `report chain-of-custody` · `report integrity`

Reports summarize preserved evidence. Review original artifacts and integrity
results before using reports as the basis for conclusions.

### Authorized Lab Research

The `exploit` command group provides discovery, authorized device interaction,
protocol helpers, and experimental interfaces across ADB-TCP, Bluetooth, WiFi,
USB, hotspot, and CVE/zero-click research.

Active research requires authorization and target scope. Policy-managed lab
execution additionally requires an operator, confirmation, and a case workspace.
A preview, simulation, or PoC result is not evidence of successful exploitation.

<details>
<summary><strong>Capability boundaries</strong></summary>

- Native raw SYN/UDP scanning is unavailable in the retained APIs.
- Active native WPS/Pixie Dust attacks are unavailable.
- Native WPA handshake verification/cracking is unavailable; packet and PSK derivation helpers do not provide it.
- Placeholder zero-click payloads and exploit-chain interfaces are not verified device-compromise capabilities.
- Android lock screens, encryption, and hardware-backed credentials are not generally bypassed by this toolkit.
- Platform-specific discovery tools and lab integrations may need external packages not included in the base installation.

Inspect command help and capability status before relying on a research workflow.

</details>

---

## Case Workflow

### 1. Create a Workspace

```bash
lockknife --cli case init \
  --case-id CASE-001 \
  --examiner "Examiner" \
  --title "Android investigation" \
  --case-dir ./cases/CASE-001
```

Initialization rejects an existing case inventory rather than replacing it.

### 2. Analyze and Report

```bash
lockknife --cli forensics sqlite ./evidence/messages.db --case-dir ./cases/CASE-001
lockknife --cli report integrity --case-dir ./cases/CASE-001
lockknife --cli report generate --case-dir ./cases/CASE-001 --format html
```

SQLite is the case source of truth; `case_manifest.json` is a compatibility snapshot.
Audit hashes provide tamper evidence, not an independent signature against someone
who can replace the entire database. Retain an external trusted copy of the chain
head when stronger verification is needed.

### 3. Export Evidence

```bash
lockknife --cli case export \
  --case-dir ./cases/CASE-001 \
  --include-registered-artifacts \
  --output ./case-bundle.zip
```

Bundles contain a consistent SQLite backup, manifest, logs, reports, custody
information, and integrity summaries. Original artifacts are included when requested.

**Before sharing:** bundles may contain credentials, personal data, and host paths.
Artifact filters do not produce an anonymized database or redacted bundle.

## APK Decompilation

```bash
lockknife --cli apk decompile ./sample.apk \
  --mode auto \
  --timeout 300 \
  --output ./apk-analysis
```

| Mode | Output |
|------|--------|
| `auto` | JADX, then apktool, then archive extraction; records failed stages |
| `jadx` | Java-like source reconstructed with installed JADX |
| `apktool` | Decoded resources, manifest, and smali |
| `unpack` | Raw archive contents and inspection metadata |
| `hybrid` | Archive contents plus JADX and apktool outputs; requires both tools |

Use a new or empty output directory. Each external stage has a configurable
timeout; a successful exit without output files is reported as a failure.

## TUI Controls

| Action | Key |
|--------|-----|
| Navigate panels / move selection | Tab / arrow keys |
| Open an action menu | Enter |
| Search modules or output | `/` |
| Initialize / open a case | `n` / `o` |
| Export / view the last result | `e` / `v` |
| Configuration / help | `c` / `?` |
| Cycle theme | `t` |
| Close a dialog / quit | Escape / `q` |

Controls depend on the active panel. The TUI and action registry share form
metadata, defaults, device requirements, and confirmation flags. Confirming a
form does not grant device access or enable unavailable capabilities.

## Configuration

Configuration files are checked in this order:

1. `./lockknife.toml`
2. `$HOME/.config/lockknife/lockknife.toml`
3. `$HOME/.lockknife.toml`
4. `/etc/lockknife.toml`

```toml
[lockknife]
log_level = "INFO"
log_format = "console"
adb_path = "adb"
```

Legacy `lockknife.conf` is supported for compatible keys. Keep credentials,
signing keys, device data, and case workspaces outside public repositories.
Explicit custody sealing requires a configured signing secret; no shared default key is supplied.

## Documentation

| Guide | Contents |
|-------|----------|
| [TUI Walkthrough](docs/tui-walkthrough.md) | Interactive investigation workflows |
| [Headless CLI Walkthrough](docs/headless-cli-walkthrough.md) | Commands and scripted usage |
| [Classic Interactive Walkthrough](docs/legacy-interactive-walkthrough.md) | Classic menu interface |
| [Changelog](CHANGELOG.md) | Release-specific changes |
| [Contributing](CONTRIBUTING.md) | Development and contribution guidelines |
| [Security Policy](SECURITY.md) | Vulnerability reporting |

For [issue reports](https://github.com/ImKKingshuk/LockKnife/issues), include the
version, operating system, command, and sanitized diagnostic output. Do not post
credentials, device identifiers, evidence files, or private case paths.

## Responsible Use

Use LockKnife only with authorization to examine the devices, applications,
networks, and evidence involved. Follow applicable law and preserve chain of custody.

Licensed under [GPL-3.0-only](LICENSE).
