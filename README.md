<div align="center">

<img src="https://lockknife.vercel.app/icon.png" width="75" alt="LockKnife Icon"/>

# LockKnife

### The Ultimate Android Security Research Tool

### One Tool. Any Device. Full Control. Enterprise Grade. Unlimited Power

#### Forensics, Analysis, Recovery, Intelligence - Everything

LockKnife : The Ultimate Android Security Research Tool - Your Complete Android Security Research Arsenal! 🗝️🔬🔒 Dive deep into Android security with this next-generation enterprise-grade command-line tool featuring AI-powered analysis, cryptocurrency wallet forensics, threat intelligence integration, Android 16 support, and 20+ specialized modules. Recover lock screen credentials, perform AI-driven behavior analysis, analyze crypto wallets, detect threats with real-time intelligence, extract Private Space data (Android 15+), analyze passkeys (Android 14+), orchestrate multi-device investigations, generate professional forensic reports, and conduct cutting-edge security research. Connect your device and unleash the full power of advanced Android security research! 🔒💫🚀

<br>

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-brightgreen)]()
[![Version](https://img.shields.io/badge/Release-v3.5.0-red)]()
[![License](https://img.shields.io/badge/License-GPLv3-blue)]()

<a href="https://lockknife.vercel.app">
    <img width="180" src="https://img.shields.io/badge/Website-LockKnife-blue?logo=google-chrome&style=square" alt="Website"/>
</a>

<br>

<p>
 <img height="30" src="https://img.shields.io/badge/Desktop_Apps_Coming_Soon-Under_Development-8A2BE2?style=for-the-badge&logo=tux&logoColor=white&style=square"/>
 <br/>
 <img height="25" src="https://img.shields.io/badge/macOS-101010?style=for-the-badge&logo=apple&logoColor=white&style=square"/>
 <img height="25" src="https://img.shields.io/badge/Linux-101010?style=for-the-badge&logo=linux&logoColor=white&style=square"/>
 <img height="25" src="https://img.shields.io/badge/Windows-101010?style=for-the-badge&logo=microsoft&logoColor=white&style=square"/>

</p>
</div>

## Features Status Legend

| Tag | Meaning |
|-----|---------|
| ✅ | **Fully Working** - Feature is complete and operational |
| 🔧 | **Functional** - Core functionality works, with some limitations |
| 🔬 | **Partial** - Basic implementation, results may be incomplete |
| 🚧 | **Coming Soon** - Placeholder/under development |

---

## Core Features ✅

### 🔒 Password Recovery ✅

- **Gesture Pattern Recovery** ✅: Recover lock screen gesture patterns with hash mapping and visualization
- **Dictionary Attack** ✅: Use custom wordlists to recover alphanumeric passwords with parallel processing support
- **Brute Force Attack** ✅: PIN cracking for 4, 6, or 8-digit PINs with progress tracking
- **Wi-Fi Password Extraction** ✅: Recover saved WiFi passwords from WifiConfigStore.xml
- **Locksettings Database Analysis** ✅: Extract and analyze locksettings.db for newer Android versions
- **Gatekeeper HAL Analysis** ✅: Modern credential storage analysis and response monitoring

### 📱 Android Version Support ✅

- Android 5 and Older ✅
- Android 6 to 9 ✅
- Android 10 to 13 ✅
- Android 14 (Credential Manager detection) 🔧
- Android 15 (Private Space detection) 🔧
- Android 16+ (Full compatibility mode) 🔧

### 📊 Data Extraction ✅

- **SMS Messages Extraction** ✅: Pull and analyze mmssms.db with statistics
- **Call Logs Extraction** ✅: Full call history with type classification
- **Wi-Fi Passwords** ✅: Complete WiFi credential extraction
- **WhatsApp Data** ✅: Extract msgstore.db, contacts, and media files
- **Telegram Data** ✅: Database and configuration extraction
- **Signal Data** 🔧: Extraction support (limited by SQLCipher encryption)
- **Browser Data** ✅: Chrome, Firefox, Brave, Edge history, cookies, and credentials
- **Bluetooth Pairing Keys** ✅: Extract Bluetooth configuration and paired devices

---

## Analysis Tools

### 🔍 Forensic Analysis ✅

- **Device Snapshot Creation** ✅: Capture file system for offline analysis
- **Live Analysis** ✅: Real-time device state analysis
- **Custom Data Extraction** ✅: Pull specific files or directories
- **SQLite Database Analysis** ✅: Extract and analyze any database
- **Search Functionality** ✅: Find sensitive information in snapshots
- **App-Specific Extraction** ✅: Specialized tools for popular messaging apps

### 🚀 Runtime Analysis 🔧

- **Process Monitoring** 🔧: Real-time process listing and analysis
- **Memory Mapping** 🔧: Process memory inspection
- **Frida Integration** 🔬: Runtime instrumentation (requires Frida server on device)
- **Anti-Debugging Detection** 🔬: Identify debugging attempts

### 🔓 SSL Pinning Bypass 🔧

- **Certificate Pinning Detection** 🔧: Identify SSL pinning implementations
- **Frida SSL Bypass** 🔬: Runtime SSL bypass scripts (requires Frida)
- **Network Interception Setup** 🔧: MITM proxy configuration
- **Burp Suite Integration** 🔧: Proxy setup guidance

### 📱 Advanced APK Analysis 🔧

- **Static Analysis** ✅: Manifest parsing, permission analysis, resource inspection
- **Code Analysis** 🔧: DEX/SMALI inspection (requires external tools)
- **Vulnerability Scanning** 🔧: Automated security checks
- **Malware Indicators** 🔧: Suspicious pattern detection
- **Signature Verification** ✅: APK signature validation

### 🌐 Network Traffic Analysis ✅

- **Traffic Capture** ✅: Record network traffic with tcpdump (requires root)
- **Protocol Analysis** ✅: Analyze with tshark integration
- **HTTP/DNS Analysis** ✅: Request and query extraction
- **Unencrypted Traffic Detection** ✅: Identify insecure communications

### 🔍 Advanced Memory Analysis 🔧

- **Memory Dumping** 🔬: Process memory extraction (requires root)
- **Memory Leak Detection** 🔬: Basic allocation analysis
- **Heap/Stack Analysis** 🔬: Memory inspection capabilities

### 🧠 Kernel & SELinux Analysis 🔧

- **Kernel Module Analysis** 🔧: Inspect loaded modules
- **SELinux Policy Analysis** 🔧: Review security policies
- **Security Feature Assessment** 🔧: Evaluate hardening status
- **AVC Denial Monitoring** 🔧: Track access denials

---

## Security Assessment

### 🦠 Malware Analysis ✅

- **Application Scanning** ✅: Check installed apps for suspicious indicators
- **Permission Analysis** ✅: Identify dangerous permission combinations
- **Package Analysis** ✅: Verify app signatures and sources
- **System File Scanning** 🔧: Check for compromised system files
- **Network Malware Detection** 🔧: Analyze connections for malicious activity
- **YARA Integration** 🔬: Pattern matching (requires YARA installation)

### 🔍 Vulnerability Scanning 🔧

- **System Vulnerabilities** 🔧: Check for known Android security issues
- **App Vulnerabilities** 🔧: Analyze installed apps for flaws
- **Configuration Issues** 🔧: Identify insecure settings

### 🔧 Hardware Security Analysis 🔧

- **TEE Analysis** 🔧: Trusted Execution Environment assessment
- **Hardware-Backed Keystore** 🔧: Secure key storage analysis
- **Secure Element Analysis** 🔬: eSE/UICC evaluation
- **Biometric Hardware** 🔧: Fingerprint/face recognition assessment

### 🔩 Bootloader & Firmware 🔧

- **Bootloader Assessment** ✅: Lock status and OEM unlock detection
- **Firmware Extraction** 🔧: Partition dumping capabilities
- **Boot Image Analysis** 🔬: Inspect boot images
- **Verified Boot Status** ✅: Check integrity verification

### ☁️ Cloud Backup Extraction 🔬

- **Google Drive** 🔬: Synced data detection (limited extraction)
- **Samsung Cloud** 🔬: Samsung account detection
- **Cloud Configuration** 🔧: Backup settings analysis

---

## Next-Gen(Experimental) Features 🔬

> 🔬 **Note**: These features are newly added and provide foundational analysis capabilities. As they are under active development, results may be incomplete. Some features generate reports based on available data analysis.

### 🤖 AI-Powered Analysis 🔬

- **Password Pattern Prediction** 🔧: Statistical analysis-based password guessing
- **Behavioral Anomaly Detection** 🔧: Process and network anomaly identification
- **Malware Classification** 🔧: Pattern-based risk scoring
- **User Activity Analysis** 🔬: App usage pattern detection
- **Security Assessment** 🔬: Risk forecasting and posture evaluation
- **Data Correlation** 🔬: Cross-reference extracted data

### ₿ Cryptocurrency Forensics 🔬

- **Wallet Detection** ✅: Identify crypto wallet apps (Coinbase, Binance, MetaMask, etc.)
- **Wallet Data Extraction** 🔧: Extract wallet app data (requires root)
- **Transaction History** 🔬: Transaction data analysis
- **Seed Phrase Recovery** 🔬: Attempt recovery (heavily encrypted)
- **Private Key Extraction** 🔬: Key extraction attempts
- **Exchange App Analysis** 🔧: Forensics for exchange applications
- **NFT & DeFi Analysis** 🔬: Token and protocol detection

### 🌐 Threat Intelligence 🔬

- **IOC Detection** 🔧: Indicators of Compromise identification
- **App Reputation Analysis** 🔧: Check apps against threat databases
- **URL/Domain Analysis** 🔬: Domain reputation (requires API keys)
- **File Hash Lookup** 🔬: VirusTotal integration (requires API key)
- **IP Reputation** 🔬: IP address checking
- **CVE Vulnerability Check** 🔬: Known vulnerability detection
- **Real-Time Threat Feeds** 🔬: Integration with VirusTotal, AlienVault OTX (requires API keys)

### 🔒 Private Space Analysis (Android 15+) 🔧

- **Private Space Detection** ✅: Identify Private Space usage
- **User Profile Analysis** ✅: Detect multiple isolated profiles
- **Private App Listing** 🔧: List apps in Private Space
- **Data Extraction** 🔧: Extract from isolated profiles (requires root)
- **Security Analysis** 🔧: Assess Private Space implementation
- **Isolation Boundary Testing** 🔬: Test app isolation

### 🔑 Passkey & Credential Analysis (Android 14+) 🔧

- **Credential Manager Detection** ✅: Identify modern credential storage
- **Passkey Data Extraction** 🔧: Extract passkey metadata (requires root)
- **WebAuthn Analysis** 🔧: Analyze web authentication credentials
- **FIDO2 Support** 🔬: Security key detection
- **Biometric Binding** 🔬: Analyze passkey-biometric associations

### 📱 Multi-Device Orchestration 🔧

- **Device Scanning** ✅: Detect all connected devices
- **Parallel Information Gathering** ✅: Simultaneous data collection
- **Synchronized Extraction** 🔧: Parallel data extraction
- **Cross-Device Correlation** 🔬: Find relationships between devices
- **Comparative Analysis** 🔬: Compare security postures
- **Multi-Device Timeline** 🔬: Unified event reconstruction

### 📊 Advanced Report Generation ✅

- **Executive Summary** ✅: High-level reports for stakeholders
- **Technical Reports** ✅: Detailed technical analysis
- **Timeline Reports** 🔧: Event timeline reconstruction
- **Security Assessment Reports** ✅: Comprehensive security reports
- **Evidence Collection Reports** ✅: Chain of custody documentation
- **Compliance Reports** 🔬: GDPR, HIPAA (template-based)
- **Multiple Formats** 🔬: PDF/HTML export (requires pandoc)

---

## Features 🚧 (Coming Soon)

### 📡 Real-Time Monitoring 🚧

- Live device activity monitoring
- Process activity dashboards
- Network traffic visualization
- System resource tracking
- Alert notifications

### 🌐 IoT Device Analysis 🚧

- Detect connected IoT devices
- Bluetooth LE device scanning
- Smart home protocol analysis
- IoT communication monitoring
- Security assessment

### 🔌 Plugin System 🚧

- Install community plugins
- Browse plugin marketplace
- Custom plugin development
- Plugin security scanning
- Auto-update capability

---

## Requirements

- **Operating System**: macOS, Linux, Windows (WSL)
- **Shell**: Bash-compatible environment
- **Android Device**: ADB debugging enabled
- **Required**:
  - [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb)
  - [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)
  - [openssl](https://www.openssl.org/) for encryption features

- **Recommended**:
  - [sqlite3](https://www.sqlite.org/download.html) for database analysis (Android 10+)
  - [GNU Parallel](https://www.gnu.org/software/parallel/) for faster attacks
  - [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) for network analysis
  - Root access on device for advanced features

### Optional Dependencies for Enhanced Features

**Memory Analysis:**

- gdb/lldb for debugging capabilities
- valgrind for memory leak detection

**Kernel Analysis:**

- Kernel headers for inspection
- SELinux policy tools

**Malware Analysis:**

- ClamAV or similar antivirus
- [YARA](https://virustotal.github.io/yara/) for pattern matching

**Network Analysis:**

- tcpdump for traffic capture
- nmap for network scanning

**Threat Intelligence:**

- VirusTotal API key
- AlienVault OTX API key

**Reports:**

- pandoc for PDF/HTML export

## How to Use

To use **LockKnife : The Ultimate Android Security Research Tool**, follow these steps:

1. Connect your Android device to your computer with USB debugging enabled.
2. Run the following command in your terminal:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)"
   ```

   For advanced debugging and verbose output, use:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)" -- --debug
   ```

   To create a default configuration file:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)" -- --create-config=~/.config/lockknife/lockknife.conf
   ```

   Follow the on-screen prompts to select your device and choose the desired features.

## Configuration

LockKnife looks for configuration files in the following locations (in order):

1. `./lockknife.conf` (current directory)
2. `$HOME/.config/lockknife/lockknife.conf` (user config directory)
3. `/etc/lockknife.conf` (system-wide config)

You can also specify a custom config file using the `--config=FILE` command-line option.

See `lockknife.conf` for all 100+ configurable options including:

- Attack settings (wordlist, parallel jobs, PIN length)
- Forensics settings (snapshot directories, PCAP filters)
- App-specific extraction options
- Advanced analysis depth settings
- Threat intelligence API keys
- Report generation preferences

## Disclaimer

**LockKnife : The Ultimate Android Security Research Tool** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-or-later License.

<h3 align="center">Happy Android Security Research with LockKnife! 🔒💫</h3>
