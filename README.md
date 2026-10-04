<div align="center">

<img src="https://lockknife.vercel.app/icon.png" width="96" height="96" alt="LockKnife logo"/>

# LockKnife

**Android security research, digital forensics, and APK analysis in one terminal toolkit.**

Collect evidence. Investigate applications. Turn findings into clear reports.

[![Release](https://img.shields.io/github/v/release/ImKKingshuk/LockKnife?style=flat-square&color=blue)](https://github.com/ImKKingshuk/LockKnife/releases)
[![Platforms](https://img.shields.io/badge/macOS%20%7C%20Linux%20%7C%20Windows-supported-22863A?style=flat-square)](#installation)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#installation)
[![License](https://img.shields.io/badge/License-GPL--3.0--only-blue?style=flat-square)](LICENSE)

**[Website](https://lockknife.vercel.app) · [Install](#installation) · [Quick Start](#quick-start) · [Features](#features) · [User Guides](#documentation)**

</div>

---

## Android Investigations, From Evidence to Report

**LockKnife** is an open-source Android security research and digital forensics toolkit for security researchers, forensic analysts, and mobile application penetration testers. It brings device data extraction, offline evidence analysis, APK reverse engineering, Frida runtime instrumentation, network forensics, and reporting into one workspace.

Explore a device through the interactive terminal interface, or run focused investigations with the command-line interface. Organize related outputs in a case, follow evidence back to its inputs, and share findings through technical or executive reports.

### Why LockKnife?

- **One investigation workspace.** Keep collected artifacts, analysis results, runtime session records, and reports together.
- **Interactive or command-line.** Choose a full-screen terminal interface for guided work or the CLI for repeatable tasks.
- **Device and offline analysis.** Examine accessible Android data or work with existing databases, APKs, and network captures.
- **Fast where it matters.** Rust-powered hashing, supported credential recovery, and native analysis helpers support demanding tasks.
- **Evidence you can follow.** Review registered artifact hashes, lineage, and case audit records before reporting your findings.

## Features

| Investigation Area | What You Can Do |
|--------------------|-----------------|
| **Android data extraction** | Collect SMS, contacts, call logs, browser records, messaging artifacts, media, and location data |
| **Digital forensics** | Inspect SQLite databases, reconstruct timelines, correlate artifacts, and review recovery candidates |
| **APK reverse engineering** | Analyze manifests and permissions, decompile applications, and scan with YARA rules |
| **Frida instrumentation** | Run hooks, trace methods, test supported security bypasses, and inspect process memory |
| **Network forensics** | Capture device traffic, inspect PCAP files, and discover visible API endpoints |
| **Credential analysis** | Recover supported legacy PIN/password hashes and inspect accessible credential artifacts |
| **Threat intelligence** | Check indicators with VirusTotal and OTX, and score unusual log activity |
| **Wallet forensics** | Inspect supported wallet databases and collect accessible device wallet artifacts |
| **Wireless research** | Use discovery, protocol inspection, and supported Bluetooth, Wi-Fi, and TCP scanning tools |
| **Cases and reports** | Track evidence provenance, verify integrity, generate reports, and export case bundles |

### Android Data Extraction

Bring accessible device evidence into your investigation: communications, browser history, messaging app databases, media metadata, and system or location artifacts. Browser support includes Chrome and Firefox; messaging workflows cover supported WhatsApp, Telegram, and Signal artifacts.

Access depends on device permissions, app versions, and encryption. Protected data may require root; collecting an encrypted database does not automatically decrypt its messages.

```bash
lockknife --cli extract browser --serial DEVICE_SERIAL --app chrome --kind history --case-dir ./cases/CASE-001
lockknife --cli extract messaging --serial DEVICE_SERIAL --app whatsapp --case-dir ./cases/CASE-001
```

### Offline Digital Forensics

Inspect SQLite evidence, build cross-artifact timelines, correlate identifiers, import ALEAPP results, and decode supported protobuf data. Review SQLite carving and recovery candidates alongside their source evidence rather than treating every candidate as a deleted record.

```bash
lockknife --cli forensics sqlite ./evidence/messages.db --case-dir ./cases/CASE-001
lockknife --cli forensics correlate --input ./evidence/artifacts.json --case-dir ./cases/CASE-001
```

### APK Analysis and Reverse Engineering

Review Android manifests, permissions, exported components, and security signals. Decompile APKs with JADX or apktool, inspect DEX metadata, and scan application contents using your YARA rules. Automated findings are leads for review, not confirmed vulnerabilities.

| Decompilation Mode | Result |
|--------------------|--------|
| `auto` | Tries JADX, then apktool, then archive unpacking |
| `jadx` | Reconstructed Java-like source |
| `apktool` | Decoded resources, manifest, and Smali |
| `unpack` | Raw application files |
| `hybrid` | Combined JADX and apktool output |

```bash
lockknife --cli apk decompile ./target.apk --mode auto --output ./decompiled
lockknife --cli apk scan --apk ./target.apk --yara ./rules/secrets.yar
```

### Frida Runtime Instrumentation

Observe applications while they run: attach or spawn a process, load scripts, trace methods, search memory, and manage case-linked sessions. Built-in SSL-pinning and root-detection hooks support authorized mobile application security testing where the target implementation is compatible.

Frida workflows require a compatible target server and sufficient permissions. Hooks can change application behavior; explicitly stop active sessions when your work is complete.

```bash
lockknife --cli runtime bypass-ssl com.example.app --device-id DEVICE_SERIAL --case-dir ./cases/CASE-001
lockknife --cli runtime memory-search com.example.app --device-id DEVICE_SERIAL --pattern "bearer"
```

### Network Forensics and Device Security

Inspect packet captures for visible DNS, HTTP, and endpoint information, or collect traffic using on-device `tcpdump`. Review device security indicators such as SELinux enforcement, reported bootloader state, and USB configuration. Encrypted traffic and reported device properties have limits; they do not independently prove application or hardware security.

```bash
lockknife --cli network api-discovery ./evidence/capture.pcap --case-dir ./cases/CASE-001
lockknife --cli security scan --serial DEVICE_SERIAL
```

### Credential and Wallet Analysis

Use offline PIN and wordlist recovery for supported hashes, inspect legacy gesture artifacts and saved Wi-Fi credentials, or inventory accessible Keystore and passkey artifacts. Wallet workflows inspect supported local databases and device artifacts.

These tools do not guarantee recovery of modern Android screen locks or hardware-backed private keys.

```bash
lockknife --cli crack pin --hash 7110eda4d09e062aa5e4a390b0a572ac0d2c0220 --algo sha1 --length 4
lockknife --cli crypto-wallet scan-device --serial DEVICE_SERIAL --case-dir ./cases/CASE-001
```

The PIN example uses the SHA-1 hash of the sample PIN `1234`.

### Threat Intelligence and Wireless Research

Enrich selected indicators through VirusTotal or OTX, inspect unusual log activity with optional anomaly scoring, and explore supported Bluetooth, Wi-Fi, and network discovery tools. External lookups send selected indicators to their providers; use them only when your investigation permits it.

Capability status distinguishes available operations from dependency-gated, PoC, simulated, or unavailable functions. An exploit name or dry-run preview is not proof of a working live exploit.

### Case Management and Reporting

Keep registered evidence and derived outputs organized, inspect artifact lineage, and verify hashes and case audit records. Create technical or executive reports in HTML, export structured JSON/CSV, or generate PDF with an optional renderer.

Export a case bundle for handoff or archival. Reports and ZIP bundles are not encrypted by default: review their contents and protect sensitive evidence before sharing.

## Installation

Choose Homebrew, Scoop, the one-line installer, or a prebuilt Python wheel for your platform.

### macOS: Homebrew

```bash
brew install ImKKingshuk/tap/lockknife
```

### macOS and Linux: One-Line Installer

```bash
curl -fsSL https://lockknife.vercel.app/install | bash
```

### Windows: Scoop

With Scoop installed:

```powershell
scoop bucket add imkkingshuk https://github.com/ImKKingshuk/scoop-bucket
scoop install imkkingshuk/lockknife
```

### Python: Prebuilt Wheel

Download the matching wheel from [GitHub Releases](https://github.com/ImKKingshuk/LockKnife/releases) and install it in a Python 3.12+ environment:

```bash
python -m pip install /path/to/downloaded-wheel.whl
```

| Operating System | Prebuilt Architecture |
|------------------|-----------------------|
| macOS | Apple Silicon / ARM64 |
| Linux | x86-64, ARM64 |
| Windows | x86-64 |

Device commands also require Android platform-tools (`adb`) and device authorization. Offline analysis can run without a connected Android device.

### Optional Features

For wheel installations, choose the dependencies you need:

```bash
python -m pip install '/path/to/downloaded-wheel.whl[apk,network]'
python -m pip install '/path/to/downloaded-wheel.whl[full]'
```

| Extra | Enables |
|-------|---------|
| `apk` | APK analysis |
| `frida` | Runtime instrumentation |
| `network` | Extended PCAP analysis |
| `yara` | YARA rule scanning |
| `threat-intel` | VirusTotal and OTX clients |
| `ml` | Machine-learning analysis helpers |
| `full` | All the investigation extras above |

External tools still apply: JADX/apktool for decompilation, a target Frida server for instrumentation, and device `tcpdump` for capture. PDF rendering and Bleak are separate optional dependencies, not included in `full`.

See [Installation and Troubleshooting](docs/installation-and-troubleshooting.md) for updates, optional dependency setup, and connection problems.

## Quick Start

### Open the Interactive Workspace

```bash
lockknife
```

Use the device and module panels to choose a target and action. Press `?` for help. Follow the [TUI investigation guide](docs/tui-walkthrough.md) for a complete walkthrough.

### Run Your First CLI Investigation

**1. Check your installation and device.**

```bash
lockknife --version
lockknife --cli doctor
lockknife --cli device list
```

Replace `DEVICE_SERIAL` in the examples with a serial returned by `device list`. Choose a private directory for real case data; the examples use `./cases/CASE-001`.

**2. Create a case and collect accessible evidence.**

```bash
lockknife --cli case init --case-id CASE-001 --examiner "Analyst" --title "Android Assessment" --output ./cases/CASE-001
lockknife --cli device info --serial DEVICE_SERIAL
lockknife --cli extract sms --serial DEVICE_SERIAL --format json --case-dir ./cases/CASE-001
lockknife --cli extract call-logs --serial DEVICE_SERIAL --format json --case-dir ./cases/CASE-001
```

**3. Review the case, verify integrity, and generate a report.**

```bash
lockknife --cli case summary --case-dir ./cases/CASE-001
lockknife --cli report integrity --case-dir ./cases/CASE-001 --format json
lockknife --cli report generate --case-dir ./cases/CASE-001 --template technical --format html
lockknife --cli case export --case-dir ./cases/CASE-001 --include-registered-artifacts --output ./case-001-bundle.zip
```

Use the output paths printed by each command. For local analysis examples, replace the sample input paths with your evidence files. Follow the [CLI investigation guide](docs/headless-cli-walkthrough.md) for timelines, correlation, capture, and custody reports.

### Find the Right Command

```bash
lockknife --cli --help
lockknife --cli features
lockknife --cli actions --format json
```

Use `--help` on a command for its options. Prefer numbered menus? Start `lockknife --cli interactive` and follow the [classic menu guide](docs/legacy-interactive-walkthrough.md).

## Frequently Asked Questions

### Does LockKnife Require Root?

Not for every workflow. Offline analysis and case review do not require root. Device acquisition depends on the data being collected; protected app and system paths often require elevated access.

### Can I Analyze Evidence Without a Device?

Yes. Work with local SQLite databases, APKs, PCAP files, and supported exported artifacts. A connected device is only needed for device-backed operations.

### Does LockKnife Unlock Every Android Device?

No. Credential recovery supports specific hashes and accessible artifacts. Modern hardware-backed credentials, encryption, and device protections cannot be assumed recoverable or bypassable.

### Does Every Feature Work Immediately After Installation?

Some features need optional dependencies, external tools, service credentials, or target permissions. Run `lockknife --cli doctor` and `lockknife --cli features` to check requirements before starting.

### Is Evidence Uploaded Automatically?

Local analysis does not require threat intelligence services. Explicit external lookups send selected indicators to their providers. Review your data-sharing policy and the [case privacy guide](docs/case-integrity-and-privacy.md) before using those integrations.

## Documentation

| Guide | Start Here When You Want To... |
|-------|-------------------------------|
| [Installation and Troubleshooting](docs/installation-and-troubleshooting.md) | Install, update, connect a device, or resolve setup problems |
| [Interactive TUI Walkthrough](docs/tui-walkthrough.md) | Investigate through the full-screen terminal interface |
| [CLI Investigation Walkthrough](docs/headless-cli-walkthrough.md) | Collect, analyze, verify, and report from the command line |
| [Classic Menu Guide](docs/legacy-interactive-walkthrough.md) | Use numbered menus for simple tasks |
| [Case Integrity and Privacy](docs/case-integrity-and-privacy.md) | Protect evidence, verify case records, and share results safely |
| [Changelog](CHANGELOG.md) | See what's changed between versions |
| [Security and Privacy](SECURITY.md) | Handle credentials safely or report a vulnerability privately |

## Responsible Use

Use LockKnife only for authorized Android security testing, digital forensics, research, and education. Obtain permission for the devices, applications, and networks you examine, comply with applicable laws, and protect the personal data you collect.

## License

LockKnife is open source under the [GNU General Public License v3.0 (GPL-3.0-only)](LICENSE).
