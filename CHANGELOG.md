# Changelog

All notable changes to `LockKnife : The Ultimate Android Security Research Tool` will be documented in this file.

## [v1.0.0] - 2026-03-15

### Full Rewrite: Python + Rust (New Era)

This release marks the transition from a Bash-only tool to a modular, TUI + headless CLI with a Rust native core. LockKnife is now a unified Android security research platform combining forensics, analysis, recovery, runtime instrumentation, and intelligence in one framework.

### 🎯 Product Architecture

- **TUI (Primary)**: Full-screen terminal UI as the default experience (`lockknife`) - case-driven workflows, live output, result viewer, and operator-guided execution
- **CLI (Secondary)**: Headless command-line interface (`lockknife --cli` or `lockknife --headless`) for quick tasks, automation, scripting, and CI/CD integration
- **Interactive (Legacy)**: Old classic menu-driven interface (`lockknife interactive`) for backward compatibility

### 🏗️ Core Platform

#### Python + Rust Hybrid Architecture

- **Python Orchestration Layer**: CLI, device I/O, modules, reporting, and integrations under `lockknife/core/`, `lockknife_headless_cli/`, and `lockknife/modules/`
- **Rust Native** (`lockknife.lockknife_core`) for performance-critical operations:
  - Cryptographic primitives: hashing/HMAC, AES-GCM encryption/decryption
  - High-speed PIN bruteforce (production-ready, Rust-accelerated)
  - Dictionary attacks with rule-based password mutations
  - SQLite bulk table extraction to JSON with correlation primitives
  - Binary helpers: DEX/ELF header parsing, pattern scanning
  - Network primitives: IPv4 parsing and packet analysis helpers

#### Configuration & Logging

- TOML-based configuration (`lockknife.toml`) with multi-location support:
  - `./lockknife.toml`
  - `$HOME/.config/lockknife/lockknife.toml`
  - `$HOME/.lockknife.toml`
  - `/etc/lockknife.toml`
- Legacy `lockknife.conf` auto-mapping for backward compatibility
- Structured logging with console and JSON formats
- Environment variable override support
- Shell completion for bash, zsh, and fish

### 📱 Device & Orchestration

- **ADB Management**: Device listing, connection, info, shell access (`lockknife device ...`)
- **Multi-Device Support**: Parallel execution for supported operations across multiple devices
- **Device Targeting**: Smart device selection and targeting system
- **Feature Matrix**: Runtime feature availability detection based on device access level (userdebug/root), OEM paths, and Android version
- **Health Monitoring**: Device health checks and diagnostics

### 🔐 Credentials & Recovery

#### Production-Ready (Rust-Accelerated)

- **Offline PIN Bruteforce** (`lockknife crack pin`): High-speed 4/6/8-digit PIN cracking
- **Dictionary Attack** (`lockknife crack password`): Wordlist-based password recovery
- **Rule-Based Mutations** (`lockknife crack password-rules`): Advanced password transformation rules

#### Best-Effort (Device-Dependent)

- **Device-Side PIN Recovery** (`lockknife crack pin-device`): On-device PIN extraction pipeline
- **Gesture Recovery** (`lockknife crack gesture`): Pattern lock analysis with visual representation
- **WiFi Password Extraction** (`lockknife crack wifi`): WiFi credential recovery (often requires root)
- **Keystore Listing** (`lockknife crack keystore`): Android keystore inventory
- **Passkey Export** (`lockknife crack passkeys`): FIDO2/WebAuthn credential extraction (Android 14+)

### 📤 Extraction & Forensics

#### Data Extraction (Functional)

- **SMS/Contacts/Call Logs** (`lockknife extract sms|contacts|call-logs`)
- **Browser Artifacts**: Chrome/Firefox history, bookmarks, downloads, cookies, saved logins
- **Media Extraction**: Photos, videos with EXIF metadata preservation
- **Location Artifacts**: GPS data, location history, dumpsys snapshots
- **Messaging Apps** (best-effort): WhatsApp, Telegram, Signal (encryption/key dependent)

#### Forensic Analysis (Production-Ready)

- **SQLite Analysis** (`lockknife forensics sqlite`): Rust-accelerated bulk extraction and inspection
- **Timeline Building** (`lockknife forensics timeline`): Cross-artifact timeline reconstruction
- **Correlation Engine** (`lockknife forensics correlate`): Rust-assisted artifact correlation
- **ALEAPP Compatibility** (`lockknife forensics parse`): Artifact normalization and export
- **Device Snapshots** (`lockknife forensics snapshot`): Full device state capture (best-effort)
- **Recovery Heuristics** (`lockknife forensics recover`): Deleted record recovery (best-effort)
- **Artifact Registry**: Extensible artifact parser system with protobuf, accounts, app usage, Bluetooth, notifications, WiFi history

### 📦 APK Analysis (Dependency-Gated: `lockknife[apk]`)

- **Manifest Parsing**: Component extraction, permission analysis, metadata inspection
- **Permission Risk Scoring**: Heuristic vulnerability assessment
- **Signing Analysis**: Certificate verification, signature validation
- **Code Signal Detection**: Suspicious code pattern identification
- **DEX Header Extraction**: Rust-powered DEX file analysis
- **Decompile Workflow**: APK unpack, manifest.json generation (structured stage reporting)
- **YARA/Pattern Scanning** (`lockknife apk scan`): Malware detection with Rust pattern engine

### 🧪 Runtime Instrumentation (Dependency-Gated: `lockknife[runtime]`)

- **Frida Session Management**: Attach, spawn, script loading
- **SSL Pinning Bypass** (`lockknife runtime bypass-ssl`)
- **Root Detection Bypass** (`lockknife runtime bypass-root`)
- **Method Tracing** (`lockknife runtime trace`)
- **Memory Search** (`lockknife runtime memory-search`)
- **Heap Dump** (`lockknife runtime heap-dump`)
- **Session Orchestration**: Multi-target session management with helper families

### 🌐 Network Analysis (Dependency-Gated: `lockknife[network]`)

- **Device Capture** (`lockknife network capture`): tcpdump-based packet capture (requires root)
- **PCAP Analysis** (`lockknife network analyze`): Traffic inspection and protocol analysis
- **API Discovery** (`lockknife network api-discovery`): Endpoint extraction and mapping
- **Rust Primitives**: IPv4 parsing and network data structure helpers

### 🛡️ Security Assessment (Functional)

- **Device Posture Audit** (`lockknife security scan`): Comprehensive security checks
- **SELinux Analysis** (`lockknife security selinux`): Policy inspection and enforcement status
- **Bootloader Status** (`lockknife security bootloader`): Lock status and vulnerability assessment
- **Hardware Security** (`lockknife security hardware`): TEE, secure element, biometric hardware analysis
- **Malware Scanning** (`lockknife security malware`): Rust pattern engine with optional YARA fallback
- **OWASP MASTG Mapping** (`lockknife security owasp`): Finding categorization and compliance reporting

### 📊 Reporting & Case Management (Functional)

#### Report Generation

- **Multi-Format Export**: HTML, JSON, CSV (functional), PDF (dependency-gated: weasyprint/xhtml2pdf)
- **Report Types**:
  - Executive summaries for stakeholders
  - Technical analysis reports with detailed findings
  - Timeline reports with event reconstruction
  - Security assessment reports with risk scoring
- **Chain of Custody** (`lockknife report chain-of-custody`): Evidence tracking and lineage
- **Integrity Verification** (`lockknife report integrity`): Artifact hash verification and tamper detection

#### Case Workspace Management

- **Case-First Architecture**: Unified workspace for extraction, forensics, runtime, APK review, and reporting
- **Artifact Lineage**: Complete evidence tracking with integrity hashes
- **Manifest System**: Case metadata, artifact inventory, and custody records
- **Enrichment Pipeline**: Automated case enrichment with orchestrator, payloads, runs, and summary generation

### 🔍 Intelligence & AI (Dependency-Gated)

#### Threat Intelligence (`lockknife[threat-intel]`)

- **VirusTotal Integration** (`lockknife intel virustotal`): File/URL reputation checks
- **AlienVault OTX** (`lockknife intel reputation`): Threat intelligence feeds
- **IOC Detection** (`lockknife intel ioc`): Indicator of Compromise identification
- **CVE Lookup** (`lockknife intel cve`): Vulnerability database queries
- **STIX/TAXII** (`lockknife intel stix|taxii`): Structured threat information exchange

#### AI/ML Workflows (`lockknife[ml]`)

- **Anomaly Detection** (`lockknife ai anomaly`): Behavioral anomaly scoring
- **Malware Classification** (`lockknife ai train-malware|classify-malware`): Neural network-based detection
- **Password Prediction** (`lockknife ai predict-password`): ML-assisted password recovery

### 💰 Crypto Wallet Forensics (Functional)

- **Wallet Detection** (`lockknife crypto-wallet wallet`): Multi-chain wallet identification
- **Address Extraction**: Bitcoin, Ethereum, and 20+ cryptocurrency support
- **Transaction Analysis**: Blockchain transaction tracking (data/network dependent)

### 🎨 TUI Features (Primary Product Surface)

- **Full-Screen Interface**: Async operations with overlays and panels
- **Module Catalog**: Searchable feature browser with capability badges
- **Result Viewer**: Export, copy, and review operation outputs
- **Action Matrix**: Feature status and requirement visibility
- **Search & Navigation**: Keyboard-driven workflow with `/` search, tab navigation
- **Theme Support**: Cycle themes with `t` key
- **Config Editor**: In-TUI configuration management with `c` key
- **Keybindings**:
  - `q`: Quit
  - `Tab`: Navigate panels
  - `Arrow keys`: Move selection
  - `Enter`: Open action menu
  - `/`: Search modules/output
  - `?`: Help
  - `t`: Theme cycle
  - `c`: Config editor
  - `e`: Export last result
  - `v`: Result viewer
  - `PageUp/PageDown`: Scroll modules
  - `Ctrl+Up/Down`: Adjust panel height
  - `y`: Copy result in viewer

### 📦 Optional Extras (Dependency-Gated Features)

Install additional capabilities via pip extras:

- `lockknife[apk]`: APK analysis, manifest parsing, decompilation
- `lockknife[frida]`: Runtime instrumentation, bypass workflows
- `lockknife[ml]`: AI/ML analysis, anomaly detection, password prediction
- `lockknife[threat-intel]`: Threat intelligence feeds, IOC detection
- `lockknife[network]`: PCAP analysis, API discovery (requires scapy)
- `lockknife[yara]`: YARA-backed malware scanning (optional fallback)

### 🔄 Migration from v0.4.x

#### Breaking Changes

- **Bash-only bootstrap removed**: `LockKnife.sh` / curl-pipe-bash install no longer primary entrypoint
- **Configuration format**: Primary config is now `lockknife.toml` (legacy `lockknife.conf` auto-mapped)
- **CLI interface**: Menu-driven Bash workflow replaced with Click-based CLI
  - Use `lockknife` for TUI (new default)
  - Use `lockknife --cli` for headless commands
  - Use `lockknife interactive` for classic menu experience
- **Dependency management**: Advanced features gated behind optional extras
- **Output structure**: Reorganized for case-first workflows

#### Compatibility

- **Python 3.11+** required
- **Rust toolchain** required for building from source
- **ADB** (Android platform-tools) required for device operations
- **Platform support**: macOS, Linux, Windows (WSL)

### 🎯 Design Philosophy

- **Case-First**: Unified workspace for the full investigation lifecycle
- **Operator-Centric**: TUI as primary surface with guided workflows
- **Modular**: Importable APIs, not just CLI commands
- **Testable**: Comprehensive test coverage with clear boundaries
- **Transparent**: Feature status visibility and realistic expectations
- **Extensible**: Plugin system and artifact registry for custom workflows

## [v0.4.0] - 2025-11-06

### Last Version with Bash

#### Android Version Support

- **Android 16 (API 36) Full Support**: Complete compatibility with Android 16 and latest security features
- **Android 15 Private Space**: Dedicated module for Private Space detection, extraction, and analysis
- **Android 14 Credential Manager**: Passkey and modern credential analysis with WebAuthn/FIDO2 support
- **Automatic Version Detection**: Smart adaptation to device Android version with feature availability indicators
- **Version-Specific Optimization**: Tailored extraction and analysis methods based on Android API level

#### AI-Powered Analysis (New Module)

- **Password Pattern Prediction**: Machine learning-based password guessing with statistical analysis
- **Behavioral Anomaly Detection**: AI-driven detection of suspicious device activities
- **ML Malware Classification**: Neural network-based malware identification and classification
- **Activity Pattern Analysis**: User behavior pattern recognition and timeline correlation
- **Smart Data Correlation**: AI-powered evidence correlation across multiple data sources
- **Threat Detection**: Automated threat identification using AI algorithms
- **Neural Code Analysis**: Deep code pattern analysis for vulnerability detection

#### Cryptocurrency Wallet Forensics (New Module)

- **Multi-Chain Wallet Detection**: Support for Bitcoin, Ethereum, and 20+ cryptocurrency wallets
- **Transaction History Analysis**: Blockchain transaction tracking and analysis
- **Seed Phrase Recovery**: Advanced techniques for recovering wallet seed phrases
- **Private Key Extraction**: Secure extraction of cryptocurrency private keys
- **Exchange App Forensics**: Specialized analysis for Coinbase, Binance, Kraken, and other exchanges
- **NFT Analysis**: Non-fungible token holdings and transaction analysis
- **DeFi Protocol Analysis**: Decentralized finance application forensics
- **Blockchain Address Analysis**: Address clustering and ownership analysis

#### Threat Intelligence Integration (New Module)

- **Real-Time CTI Feeds**: Integration with VirusTotal, AlienVault OTX, Abuse.ch, and MISP
- **IOC Detection**: Comprehensive Indicators of Compromise identification
- **App Reputation Analysis**: Cloud-based application reputation checking
- **URL/Domain Analysis**: Malicious domain and phishing detection
- **File Hash Lookup**: Instant malware identification via hash databases
- **IP Reputation Checks**: Network threat intelligence for connections
- **CVE Vulnerability Checks**: Automated vulnerability assessment against CVE databases
- **Threat Actor Attribution**: Advanced threat analysis and actor identification

#### Private Space Analysis (New Module - Android 15+)

- **Private Space Detection**: Automatic identification of Private Space usage
- **Multi-Profile Analysis**: Complete analysis of all user profiles
- **Isolated Data Extraction**: Extract data from Private Space applications
- **Security Assessment**: Evaluate Private Space implementation security
- **Isolation Boundary Testing**: Test app isolation and sandbox effectiveness
- **Access Control Analysis**: Analyze authentication and permission boundaries
- **Data Leak Detection**: Identify potential cross-profile data leaks

#### Passkey & Credential Manager Analysis (New Module - Android 14+)

- **Credential Manager Detection**: Identify Android 14+ credential storage
- **Passkey Extraction**: Extract and analyze passkey data
- **WebAuthn Credential Analysis**: Analyze web authentication credentials
- **FIDO2 Security Key Support**: External authenticator forensics
- **Biometric Binding Analysis**: Passkey-biometric association analysis
- **Credential Provider Analysis**: Third-party password manager analysis
- **Usage Statistics**: Passkey usage patterns and timeline

#### Multi-Device Orchestration (New Module)

- **Parallel Device Analysis**: Analyze multiple devices simultaneously
- **Synchronized Extraction**: Coordinated data extraction across devices
- **Cross-Device Correlation**: Find relationships and connections between devices
- **Comparative Analysis**: Compare security postures across devices
- **Multi-Device Timeline**: Unified timeline reconstruction from all devices
- **Network Topology Mapping**: Map device network relationships
- **Scalable Architecture**: Support for analyzing 5+ devices concurrently

#### Advanced Report Generator (New Module)

- **Executive Summary Reports**: High-level reports for stakeholders and management
- **Technical Analysis Reports**: Detailed technical findings and evidence
- **Timeline Reports**: Comprehensive event timeline reconstruction
- **Security Assessment Reports**: Risk scoring and vulnerability analysis
- **Evidence Collection Reports**: Chain of custody and forensic documentation
- **Compliance Reports**: GDPR, HIPAA, and regulatory compliance reporting
- **Multiple Export Formats**: PDF, HTML, JSON, XML, and CSV export
- **Custom Report Builder**: Build reports with selected sections and data
- **Report Templates**: Pre-built templates for common use cases

### 📱 Platform Support

#### New Android Versions

- Full support for Android 16 (API 36) with quantum-resistant crypto analysis
- Complete Android 15 (API 35) support with Private Space features
- Enhanced Android 14 (API 34) support with Credential Manager
- Backward compatibility maintained for Android 5+ through Android 13

#### Platform Improvements

- macOS Apple Silicon (M1/M2/M3) optimization
- Windows WSL 2 full compatibility
- Linux ARM64 support
- Improved ADB connection handling
- Better USB debugging detection

### 🐛 Bug Fixes

- Fixed bash compatibility issues with older versions
- Improved error handling in module loading
- Better handling of disconnected devices
- Fixed memory leaks in long-running operations
- Corrected file permission issues on Windows
- Improved config file parsing
- Fixed Unicode handling in output files
- Better handling of special characters in filenames

### ⚠️ Breaking Changes

- Configuration file format updated (auto-migration supported)
- Some menu option numbers changed (expanded from 20 to 30)
- Output directory structure reorganized for better organization
- Log format enhanced (backward compatible)

### 🔮 Experimental Features

- Plugin system (disabled by default)
- Real-time monitoring dashboard (under development)
- IoT device analysis (under development)
- API access (disabled by default)
- Cloud-based collaborative analysis (planned)

---

## [v0.3.5] - 2025-09-30

### Added

- **Modular Architecture**: Complete rewrite with modular components for better maintainability and extensibility
- **Advanced Memory Analysis**: Comprehensive memory dumping, analysis, and leak detection capabilities
- **Kernel & SELinux Analysis**: Deep kernel module analysis, SELinux policy inspection, and security feature assessment
- **Cloud Backup Extraction**: Extract data from Google Drive, Samsung Cloud, and other cloud services
- **Malware Analysis**: Built-in malware detection and analysis capabilities with YARA integration
- **Vulnerability Scanning**: Automated vulnerability assessment and security auditing
- **Biometric Data Analysis**: Extract and analyze fingerprint and facial recognition data
- **System Service Analysis**: Monitor and analyze Android system services and frameworks
- **Firmware Analysis**: Extract and analyze device firmware and bootloader information
- **Enhanced Security Features**: Improved encryption, secure deletion, and anonymous operation modes
- **Performance Optimizations**: Multi-threaded processing and optimized algorithms
- **Extended App Support**: Analysis for 15+ popular applications with specialized extraction tools
- **Configuration Enhancements**: Expanded configuration options for all new features
- **Advanced Logging**: Multi-format logging (txt, json, csv) with performance metrics
- **Dependency Management**: Improved dependency checking and installation
- **Runtime Analysis Module**: Comprehensive runtime monitoring with process analysis, dynamic behavior tracking, system call tracing, Frida integration, and anti-debugging detection
- **SSL Pinning Bypass Module**: Complete SSL pinning bypass capabilities with Frida scripts, certificate management, proxy configuration, and network interception tools
- **Advanced APK Analysis Module**: Static and dynamic APK analysis including manifest parsing, permission analysis, code decompilation, vulnerability scanning, malware detection, and signature verification
- **Hardware Security Analysis Module**: Deep hardware security assessment covering TEE analysis, hardware-backed keystores, secure elements, biometric hardware, cryptographic acceleration, and attack surface analysis
- **Bootloader & Firmware Security Module**: Bootloader status checking, vulnerability assessment, OEM unlock analysis, boot/recovery image analysis, and comprehensive security reporting
- **Enhanced Menu System**: Reorganized 20-option main menu with categorized features for better usability
- **Modular Architecture Improvements**: Better module loading system and renamed config.sh to config_manager.sh for clarity
- **Advanced Frida Integration**: Runtime instrumentation capabilities with SSL bypass, method hooking, and memory dumping
- **System Integrity Verification**: Rootkit detection, system integrity checks, and comprehensive security assessments

### Enhanced

- **User Interface**: Improved menu layout with categorized options and emoji indicators
- **Configuration System**: Enhanced config file management with better organization
- **Update System**: Improved auto-update mechanism with better error handling
- **Logging System**: Enhanced logging with better compatibility across bash versions

### Changed

- **Code Architecture**: Migrated from monolithic script to modular component system
- **Configuration System**: Enhanced with validation and more comprehensive options
- **Security Improvements**: Implemented secure memory handling and improved file operations
- **User Interface**: Updated menu system to accommodate new features
- **Performance**: Optimized algorithms and added parallel processing where applicable

### Technical Improvements

- **Cross-Platform Compatibility**: Fixed bash compatibility issues for older versions
- **Memory Management**: Better memory handling and cleanup procedures
- **Error Handling**: Improved error detection and recovery mechanisms
- **Performance**: Optimized module loading and function execution
- **Modular Design**: Separated concerns into core/, modules/, and utils/ directories
- **Error Handling**: Enhanced error handling and recovery mechanisms
- **Memory Management**: Secure memory clearing and leak detection
- **File Security**: Improved secure file handling and encryption capabilities
- **Cross-Platform**: Better Windows compatibility and environment detection

## [v0.3.1] - 2025-07-23

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v0.3.0] - 2025-05-30

### Added

- **Configuration System**: Customize tool behavior via config files in multiple locations or command-line options.
- **App-Specific Extraction**: Added specialized extraction for WhatsApp, Telegram, Signal, and browsers.
- **Bluetooth Pairing Keys**: Added extraction and analysis of Bluetooth pairing keys.
- **Keystore Access Monitoring**: Added monitoring of keystore access attempts.
- **Gatekeeper HAL Analysis**: Added advanced credential recovery via Gatekeeper HAL analysis.
- **Gesture Pattern Recognition**: Implemented precomputed gesture pattern hash mapping with visual representation.
- **Network Traffic Analysis**: New capability to capture and analyze network traffic with tcpdump and tshark.
- **Forensic Analysis Tools**: Added tools for analyzing app data, searching snapshots, and extracting sensitive information.
- **Output Directory**: All outputs are now organized in a dedicated directory with timestamps.
- **Modern Credential Recovery**: Support for extracting and analyzing modern Android credential storage.

### Changed

- **Improved User Interface**: Enhanced menu system with more options and better organization.
- **Enhanced Security**: All sensitive files are now stored with proper permissions and securely deleted.
- **Better File Handling**: Improved file transfer and management between device and host.

## [v0.2.7] - 2025-04-15

### Added

- **Parallel Processing**: Optimized brute-force and dictionary attacks with multi-core support using GNU Parallel.
- **Secure File Handling**: Implemented secure file operations with shred for data security.
- **Enhanced Error Handling**: Added retry logic for more reliable device operations.
- **Improved Device Selection**: Added IP-based device connection and better device information.
- **Debug Mode**: Added `--debug` flag for detailed logging of operations.
- **Temporary Directory**: Created a secure temporary directory for all sensitive file operations.
- **Extensive Logging**: Added comprehensive logging with timestamps for better tracking.

### Changed

- **Security Improvements**: Now using secure deletion for all sensitive files.
- **Code Structure**: Reorganized code for better maintainability.
- **User Interface**: Enhanced progress tracking for long-running operations.
- **File Permissions**: Setting secure permissions (chmod 600) on all extracted files.

## [v0.2.6] - 2025-02-26

### Added

- Variable-Length PIN Cracking: Now supports 4, 6, or 8-digit PINs for more flexible brute-force attacks.
- Alphanumeric Password Support: Added the ability to recover alphanumeric passwords using custom wordlists for dictionary attacks.
- Security Assessment: Check device's Android version, security patch level, and root status with a new security check feature.
- Enhanced Data Extraction: Recover SMS messages, call logs, and Wi-Fi passwords.

### Changed

- Improved Dependency Management: Checks for missing dependencies and attempts to install them via common package managers like apt, brew, or dnf.
- Minor Optimizations: General improvements for better performance and usability.

## [v0.2.5] - 2024-11-28

### Added

- Dictionary Attack: Added the ability to recover screen lock passwords using a wordlist-based dictionary attack.
- Brute Force Attack: Implemented a brute force method to try all possible 4-digit PIN combinations for screen lock recovery.

### Changed

- Improved Dependency Management: Checks for missing dependencies and assists in installing them via common package managers like apt, brew, or dnf.
- Minor Optimizations: General improvements and optimizations.

## [v0.2.4] - 2024-08-15

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v0.2.3] - 2024-06-16

### Added

- Updater: Automatically checks for the latest version of LockKnife and updates itself.

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v0.2.2] - 2024-06-05

### Added

- Enhanced User Interface with Main Menu and Submenus.
- Added Support for Android 10 and Newer Versions (Android 14).
- Improved Wi-Fi Password Recovery.
- Integrated Locksettings Analysis for Android 10+.
- Support for Multiple Android Versions:
  - Android 5 and Older.
  - Android 6 to 9.
  - Android 10+ and Newer.

## [v0.2.1] - 2024-06-02

### Added

- Android 14 Support.
- Multiple types of Password Recovery:
  - Wi-Fi Password Recovery.
  - Gesture Password Recovery.
  - PIN Recovery.
  - Password Recovery.
  - Privacy Protection Password Recovery.

## [v0.1.1] - 2023-12-23

### Added

- Multiple types of Password Recovery:
  - Wi-Fi Password Recovery.
  - Gesture Password Recovery.

## [v0.1.0] - 2023-07-20

### Added

- Convenient terminal-based tool to recover Android lock screen passwords.
- Easy-to-use with interactive prompts.
- Supports Android devices with USB debugging enabled.
- Automatically connects to the device using ADB.
- Auto Decrypts the password file (assuming default encryption) and displays the recovered password.
