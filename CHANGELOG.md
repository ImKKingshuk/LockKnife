# Changelog

All notable changes to `LockKnife : The Ultimate Android Security Research Tool` will be documented in this file.

## [v3.5.0] - 2025-11-06

### 🚀 Major New Features

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

## [v3.0.0] - 2025-09-30

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

## [v2.0.1] - 2025-07-23

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v2.0.0] - 2025-05-30

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

## [v1.9.0] - 2025-04-15

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

## [v1.8.5] - 2025-02-26

### Added

- Variable-Length PIN Cracking: Now supports 4, 6, or 8-digit PINs for more flexible brute-force attacks.
- Alphanumeric Password Support: Added the ability to recover alphanumeric passwords using custom wordlists for dictionary attacks.
- Security Assessment: Check device's Android version, security patch level, and root status with a new security check feature.
- Enhanced Data Extraction: Recover SMS messages, call logs, and Wi-Fi passwords.

### Changed

- Improved Dependency Management: Checks for missing dependencies and attempts to install them via common package managers like apt, brew, or dnf.
- Minor Optimizations: General improvements for better performance and usability.

## [v1.7.5] - 2024-11-28

### Added

- Dictionary Attack: Added the ability to recover screen lock passwords using a wordlist-based dictionary attack.
- Brute Force Attack: Implemented a brute force method to try all possible 4-digit PIN combinations for screen lock recovery.

### Changed

- Improved Dependency Management: Checks for missing dependencies and assists in installing them via common package managers like apt, brew, or dnf.
- Minor Optimizations: General improvements and optimizations.

## [v1.6.2] - 2024-08-15

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v1.6.1] - 2024-06-16

### Added

- Updater: Automatically checks for the latest version of LockKnife and updates itself.

### Changed

- Minor Optimizations: General improvements and optimizations.

## [v1.5.0] - 2024-06-05

### Added

- Enhanced User Interface with Main Menu and Submenus.
- Added Support for Android 10 and Newer Versions (Android 14).
- Improved Wi-Fi Password Recovery.
- Integrated Locksettings Analysis for Android 10+.
- Support for Multiple Android Versions:
  - Android 5 and Older.
  - Android 6 to 9.
  - Android 10+ and Newer.

## [v1.3.1] - 2024-06-02

### Added

- Android 14 Support.
- Multiple types of Password Recovery:
  - Wi-Fi Password Recovery.
  - Gesture Password Recovery.
  - PIN Recovery.
  - Password Recovery.
  - Privacy Protection Password Recovery.

## [v1.2.0] - 2023-12-23

### Added

- Multiple types of Password Recovery:
  - Wi-Fi Password Recovery.
  - Gesture Password Recovery.

## [v1.0.0] - 2023-07-20

### Added

- Convenient terminal-based tool to recover Android lock screen passwords.
- Easy-to-use with interactive prompts.
- Supports Android devices with USB debugging enabled.
- Automatically connects to the device using ADB.
- Auto Decrypts the password file (assuming default encryption) and displays the recovered password.
