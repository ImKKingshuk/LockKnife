<div align="center">

<img src="https://lockknife.vercel.app/icon.png" width="75" alt="LockKnife Icon"/>

# LockKnife

### The Ultimate Android Security Research Tool

### Unified Android Security Research Platform

### ⚛ Python First ⚛ Rust Accelerated ⚛

#### Forensics, Analysis, Recovery, Runtime, and Intelligence in One Framework

LockKnife is a unified Android security research and forensic investigation toolkit built with Python orchestration and Rust-accelerated core. It provides a case-driven TUI workspace alongside a powerful headless CLI, enabling investigators and researchers to perform extraction, credential recovery, artifact analysis, runtime instrumentation, and reporting from a single modular framework.
The platform integrates advanced capabilities including AI-assisted analysis, cryptocurrency wallet forensics, threat intelligence enrichment, APK inspection, runtime instrumentation, and multi-device investigation workflows. LockKnife supports modern Android ecosystems, including passkey artifacts (Android 14+), Private Space analysis (Android 15+), and evolving device security models.
With a growing ecosystem of specialized modules covering device forensics, credential recovery, APK analysis, runtime inspection, network analysis, and security auditing, LockKnife enables security researchers to orchestrate complex Android investigations and generate professional forensic reports within one unified research environment.

Connect your device and begin advanced Android security research.

<br>

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-brightgreen)]()
[![Version](https://img.shields.io/badge/Release-v1.0.1-red)]()
[![License](https://img.shields.io/badge/License-GPLv3-blue)]()

<a href="https://lockknife.vercel.app">
    <img width="180" src="https://img.shields.io/badge/Website-LockKnife-blue?logo=google-chrome&style=square" alt="Website"/>
</a>

<br>

<!-- <p>
 <img height="30" src="https://img.shields.io/badge/Desktop_Apps_Coming_Soon-Under_Development-8A2BE2?style=for-the-badge&logo=tux&logoColor=white&style=square"/>
 <br/>
 <img height="25" src="https://img.shields.io/badge/macOS-101010?style=for-the-badge&logo=apple&logoColor=white&style=square"/>
 <img height="25" src="https://img.shields.io/badge/Linux-101010?style=for-the-badge&logo=linux&logoColor=white&style=square"/>
 <img height="25" src="https://img.shields.io/badge/Windows-101010?style=for-the-badge&logo=microsoft&logoColor=white&style=square"/>

</p> -->
</div>

## New Era: Python + Rust Rewrite (v1.x)

- Python orchestrates CLI, device I/O, modules, reporting, and integrations.
- Rust powers performance-critical primitives (hashing/crypto, bruteforce, bulk parsing).
- The legacy Bash-only edition ended at **v0.4.x** (see [CHANGELOG.md]).

## Installation

### Curl (macOS, Linux, Windows)

```bash
curl -fsSL https://lockknife.vercel.app/install | bash
```

### Homebrew (macOS)

```bash
brew install ImKKingshuk/tap/lockknife
```

## Quick Start

### TUI (Default)

```bash

lockknife
```

### CLI (Headless)

```bash
lockknife --cli
```

OR

```bash
lockknife --headless
```

### Old Classic Interactive Mode

```bash
lockknife interactive
```

## Product Priority

- **TUI is the main product and default experience.** Use `lockknife` for day-to-day investigations, case-driven workflows, result review, and operator-guided execution.
- **Headless CLI is the secondary surface.** Use `lockknife --cli ...` or `lockknife --headless` for quick one-off tasks, scripting, CI, and remote/headless environments.
- **Classic interactive mode is legacy convenience.** Use `lockknife interactive` only when you specifically want the older menu flow.

### TUI (Default)

#### Keybindings

| Action | Keys |
|--------|------|
| Quit | q |
| Navigate panels | Tab |
| Move selection | Arrow keys |
| Open action menu | Enter |
| Search modules/output | / |
| Help | ? |
| Theme cycle | t |
| Config editor | c |
| Export last result | e |
| Result viewer | v |
| Page scroll modules | PageUp / PageDown |
| Adjust panel height | Ctrl + Up / Ctrl + Down |
| Copy result in viewer | y |

### TUI vs CLI

| Mode | Best for | Command |
|------|----------|---------|
| TUI (primary) | Interactive investigation, multi-step workflows, live output, case-first operations | `lockknife` |
| CLI / headless (secondary) | Quick tasks, automation, scripting, CI, headless servers | `lockknife --cli` or `lockknife --headless` |

### TUI positioning vs ALEAPP, MobSF, drozer, objection, and Frida CLI

LockKnife is designed as a **case-first operator workspace** that spans extraction, runtime, APK review, reporting, and enrichment. The tools below are still valuable, but they solve narrower slices of the Android investigation workflow.

| Tool | Primary strength | Main surface | Best at | Gaps relative to LockKnife |
|------|------------------|--------------|---------|--------------------------------|
| **LockKnife** | Unified case-driven Android investigations | Terminal TUI + CLI | Coordinating extraction, forensics, runtime, APK review, reporting, and enrichment from one workspace | N/A |
| **ALEAPP** | Artifact parsing and report generation from device dumps/backups | CLI/report pipeline | Normalizing mobile artifacts into investigator-friendly reports | No integrated runtime instrumentation, APK review, live case workspace, or operator TUI |
| **MobSF** | Mobile app static/dynamic analysis | Web UI | APK/IPA-focused security review and sandbox analysis | Not a case-first device forensics workspace; weaker on extraction/runtime/operator orchestration |
| **drozer** | Android attack-surface assessment | CLI shell | IPC exposure, exported components, and app security probing | Not a reporting/forensics/timeline platform; no integrated case workflow |
| **objection** | Frida-assisted runtime exploration | Interactive CLI | Runtime hooks, method browsing, and rapid app introspection | Not a full evidence, reporting, or case-management surface |
| **Frida CLI** | Low-level instrumentation primitives | CLI | Raw attach/spawn/script workflows and custom tracing | No case model, extraction/reporting pipeline, or investigator-friendly orchestration layer |

### Capability comparison: LockKnife vs specialist Android tools

| Capability | LockKnife | ALEAPP | MobSF | drozer | objection | Frida |
|------------|:---------:|:------:|:-----:|:------:|:---------:|:---------:|
| Case workspace, artifact lineage, integrity | ✅ Native | ⚠️ Report-centric | ❌ | ❌ | ❌ | ❌ |
| Device artifact extraction / acquisition helpers | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Timeline + cross-artifact investigation workflow | ✅ | ⚠️ Artifact-focused | ❌ | ❌ | ❌ | ❌ |
| APK static review | ✅ | ❌ | ✅ | ⚠️ Limited | ❌ | ❌ |
| Runtime instrumentation | ✅ | ❌ | ⚠️ Sandbox-centric | ✅ | ✅ | ✅ |
| Chain-of-custody / executive + technical reporting | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Guided operator workspace (TUI-first) | ✅ Primary | ❌ | ❌ Web UI instead | ❌ | ❌ | ❌ |
| Headless automation / scripting | ✅ | ✅ | ⚠️ Server workflow | ✅ | ✅ | ✅ |

Use LockKnife when you want one operator surface for the broader investigation lifecycle, and pair it with ALEAPP/MobSF/drozer/objection when you need their specialist depth.

## Features Status Legend

| Icon | Status | Meaning |
|------|--------|---------|
| ✅ | `production-ready` | Stable core workflow with strong local/offline behavior |
| 🔧 | `functional` | Useful and working, with practical constraints |
| 🔬 | `best-effort` | Works in some environments, but highly device/app/version dependent |
| 🚧 | `experimental` | Early workflow with notable limitations |
| 🔑 | `dependency-gated` | Requires optional extras, external tools, or credentials |

---

## Current Capabilities (v1.0.1)

### Core Platform

- ✅ Python CLI with subcommands: `device`, `crack`, `extract`, `forensics`, `apk`, `report`, `security`, `intel`, `ai`, `network`, `crypto-wallet`, `exploit`
- 🔧 Full-screen TUI by default (`lockknife`) as the primary product surface; headless CLI via `--cli` / `--headless` for quick/headless tasks
- ✅ Classic menu UI via `lockknife interactive`
- ✅ Config loading via `lockknife.toml` (with legacy `lockknife.conf` mapping)
- ✅ Structured logging (console/JSON) and consistent output formatting
- ✅ Shell completion via `lockknife completion <shell>`
- ✅ Structured error hierarchy with unique error codes (LK-0001 through LK-7001) for precise troubleshooting
- ✅ Rate limiter module for API call throttling
- ✅ Code quality enforcement with ruff, ty (Python) and clippy, rustfmt (Rust)
- ✅ Fuzz testing for critical Rust parsers (correlate, parse_dex_header, sqlite_table)
- ✅ TUI exploit management panel with evidence analysis, scan results, and navigation controls
- ✅ Graceful TUI shutdown with signal handling and terminal state restoration
- ✅ Reorganized TUI callback modules for better maintainability and performance

### Rust Core (Native)

- ✅ Hashing/HMAC + AES-GCM helpers
- ✅ High-speed PIN bruteforce and dictionary attacks
- ✅ Binary helpers (DEX/ELF headers), pattern scanning, IPv4 parsing
- ✅ SQLite bulk table extraction to JSON and artifact correlation primitives
- ✅ MD5-based YARA rule caching with Arc shared ownership and FIFO eviction policy
- ✅ Rust exploitation primitives: packet crafting/parsing for WiFi/Bluetooth, WPS utilities, parallel network port scanner, WPA handshake cracking with Rayon

### Device & Orchestration

- 🔧 ADB management: list/connect/info/shell (`lockknife device ...`)
- 🔧 Multi-device parallel execution for supported operations
- 🔧 Feature coverage depends on device access level (userdebug/root), OEM paths, and Android version

---

## Feature Matrix

### Credentials & Recovery

- ✅ Offline PIN bruteforce (`lockknife crack pin`) (Rust)
- ✅ Offline dictionary attack (`lockknife crack password`) (Rust)
- ✅ Rule-based password mutations (`lockknife crack password-rules`)
- 🔬 Device-side PIN recovery pipeline (`lockknife crack pin-device`) (device-dependent)
- 🔬 Gesture recovery (`lockknife crack gesture`) (device-dependent)
- 🔬 WiFi password extraction (`lockknife crack wifi`) (often requires root)
- 🔬 Keystore listing (`lockknife crack keystore`) (often requires root)
- 🔬 Passkey artifact export (`lockknife crack passkeys`) (Android 14+, device-dependent)

### Extraction

- 🔧 SMS / Contacts / Call logs (`lockknife extract sms|contacts|call-logs`)
- 🔧 Browser artifacts (Chrome/Firefox history/bookmarks/downloads/cookies/saved logins)
- 🔬 Messaging artifacts (WhatsApp/Telegram), with device constraints
- 🔬 Signal message extraction (limited by SQLCipher encryption and key availability)
- 🔧 Media extraction with EXIF
- 🔧 Location artifacts and dumpsys snapshot parsing
- 🔬 `lockknife extract all` evidence directory (best-effort; produces errors manifest when datasets fail)

### Forensics

- 🔬 Device snapshotting (`lockknife forensics snapshot`) (full coverage may require root)
- ✅ SQLite inspection + bulk extraction (`lockknife forensics sqlite`) (Rust-accelerated)
- ✅ Timeline building (`lockknife forensics timeline`)
- 🔧 ALEAPP-style artifact normalization/export (`lockknife forensics parse`)
- ✅ Cross-artifact correlation (`lockknife forensics correlate`) (Rust-assisted)
- 🔬 Deleted record recovery heuristics (`lockknife forensics recover`) (best-effort)

### Reporting

- 🔧 HTML/JSON/CSV reporting (`lockknife report generate`)
- 🔑 PDF reporting (`lockknife report generate --format pdf`) (requires weasyprint or xhtml2pdf)
- 🔧 Chain of custody (`lockknife report chain-of-custody`)
- 🔧 Case integrity verification (`lockknife report integrity`)

### APK Analysis

- 🔑 Manifest parsing and metadata extraction (requires `lockknife[apk]`)
- 🔑 Permission risk scoring and heuristic vulnerability checks
- ✅ DEX header extraction from APK (Rust)
- 🔬 "Decompile" (APK unpack + manifest.json; not full source decompilation)
- 🔧 YARA / pattern scanning (`lockknife apk scan`)

### Runtime Instrumentation

- 🔑 Frida session management and script loading (requires `lockknife[frida]` + Frida server)
- 🔬 Bypass and tracing workflows (device/app dependent)
- 🔬 Memory/heap utilities (device/app dependent)

### Network

- 🔬 Device capture (`lockknife network capture`) (root + tcpdump)
- 🔑 PCAP analysis and API endpoint discovery (requires `lockknife[network]`)
- ✅ Rust helpers for parsing primitives (IPv4)

### Security

- 🔧 Device posture audit and checks (`lockknife security scan`)
- 🔧 SELinux and bootloader/hardware checks (device dependent)
- 🔧 Malware scanning (Rust pattern engine)
- 🔧 OWASP MASTG mapping helpers (`lockknife security owasp`)

### Exploitation Framework

- 🔑 **Wireless Device Exploitation** (`lockknife exploit ...`) (requires `lockknife[exploitation]`)
  - **ADB over TCP**: Network scanning, connection, shell access, logical/physical data extraction
  - **Bluetooth**: Classic + BLE discovery, fingerprinting, GATT client, pairing manager, RFCOMM service discovery, BlueBorne/KNOB/Blurtooth PoCs
  - **WiFi**: Network scanning, WPS attacks, WPA handshake capture and cracking (Rayon-accelerated), rogue AP deployment using hostapd/dnsmasq, P2P exploitation, MITM attacks
  - **Zero-Click**: CVE intelligence management, payload generation, exploit chain automation, vulnerability fingerprinting
  - **USB Debugging**: Lock screen bypass, ADB backup creation/extraction/analysis, content provider access, intent injection
  - **Hotspot Exploitation**: Android tethering detection using iwlist, gateway exploitation, MITM traffic interception
- 🔑 **Authorization Framework**: Exploit authorization controls, lab mode, case tracking, audit trails
- 🔑 **Auto-Exploitation**: Automatic vector selection, multi-vector orchestration, exploit chain automation

---

## Integrations (Optional Extras)

- 🔑 Threat intelligence (`lockknife intel ...`) (requires `lockknife[threat-intel]` + API keys)
- 🔑 AI/ML workflows (`lockknife ai ...`) (requires `lockknife[ml]`)
- 🔧 Crypto wallet forensics (`lockknife crypto-wallet ...`) (data/network dependent)

## Requirements

- **OS**: macOS, Linux, Windows (WSL)
- **Python**: 3.11+
- **ADB**: Android platform-tools (`adb`)
- **Rust**: required to build the native extension from source
- **Device constraints**: some features require root/userdebug builds or app-specific DB access

## Configuration

LockKnife looks for configuration files in the following locations (in order):

1. `./lockknife.toml`
2. `$HOME/.config/lockknife/lockknife.toml`
3. `$HOME/.lockknife.toml`
4. `/etc/lockknife.toml`

Legacy `lockknife.conf` is also supported and auto-mapped for a small set of keys.

Example `lockknife.toml`:

```toml
[lockknife]
log_level = "INFO"
log_format = "console"
adb_path = "adb"
```

## Disclaimer

**LockKnife : The Ultimate Android Security Research Tool** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-only License.

<h3 align="center">Happy Android Security Research with LockKnife! 🔒💫</h3>
