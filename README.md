<h1 align="center">LockKnife</h1>
<h3 align="center">v3.5.0</h3>

<p align="center">LockKnife : The Ultimate Android Security Research Tool - Your Complete Android Security Research Arsenal! 🗝️🔬🔒 Dive deep into Android security with this next-generation enterprise-grade command-line tool featuring AI-powered analysis, cryptocurrency wallet forensics, threat intelligence integration, Android 16 support, and 30+ specialized modules. Recover lock screen credentials, perform AI-driven behavior analysis, analyze crypto wallets, detect threats with real-time intelligence, extract Private Space data (Android 15+), analyze passkeys (Android 14+), orchestrate multi-device investigations, generate professional forensic reports, and conduct cutting-edge security research. Connect your device and unleash the full power of advanced Android security research! 🔒💫🚀</p>

## What's New (v3.5.0)

### 🚀 Next-Generation Features

- **Android 16 Support**: Full compatibility with Android 16 (API 36) and latest Android versions
- **AI-Powered Analysis**: Machine learning-based password prediction, anomaly detection, and malware classification
- **Cryptocurrency Wallet Forensics**: Complete blockchain and crypto wallet analysis, transaction tracking, and seed phrase recovery
- **Threat Intelligence Integration**: Real-time CTI feeds from VirusTotal, AlienVault OTX, and other platforms
- **Private Space Analysis**: Android 15+ Private Space detection, extraction, and security assessment
- **Passkey & Credential Manager**: Android 14+ modern authentication analysis including WebAuthn and FIDO2
- **Multi-Device Orchestration**: Analyze multiple devices simultaneously with cross-device correlation
- **Advanced Report Generator**: Professional forensic reports with executive summaries and compliance reporting
- **Real-Time Monitoring**: Live device activity monitoring with alerts and dashboards
- **IoT Device Analysis**: Connected device communication analysis and security assessment
- **Plugin System**: Extensible architecture for community contributions and custom modules

### ⚙️ Enhanced Core Features

- **30+ Specialized Modules**: Expanded from 20 to 30+ analysis modules
- **Improved Performance**: Parallel processing, checkpointing, and optimized algorithms
- **Better UX**: Enhanced menu system with Android version indicators and feature availability
- **Comprehensive Configuration**: 100+ configuration options for fine-tuned control
- **Cross-Platform Improvements**: Better Windows WSL, macOS ARM, and Linux compatibility

## Features

- 🔒 **Password Recovery**: Retrieve / Crack lock screen passwords (PIN, pattern, password) effortlessly.
- 📶 **Wi-Fi Password Extraction**: Easily recover saved Wi-Fi passwords from device.
- 📱 **Multiple Android Versions Supported**: Tailored options for different Android versions:
  - Android 5 and Older
  - Android 6 to 9
  - Android 10 to 13
  - Android 14 (Credential Manager support)
  - Android 15 (Private Space support)
  - Android 16+ (Full next-gen features)
- ⚙️ **Attack Methods**:
  - **Dictionary Attack**: Use custom wordlists to recover alphanumeric passwords.
  - **Brute Force**: Try all possible combinations for 4, 6, or 8-digit PINs.
  - **Parallel Processing**: Multi-core support for faster attacks.
  - **Pattern Recognition**: Precomputed gesture pattern hash mapping.
  - **Gatekeeper Analysis**: Extract and analyze modern credential storage.
- 🚀 **Runtime Analysis**:
  - **Process Monitoring**: Real-time process analysis and memory mapping.
  - **Dynamic Behavior Tracking**: Monitor app behavior and system calls.
  - **Frida Integration**: Runtime instrumentation and hooking capabilities.
  - **Anti-Debugging Detection**: Identify debugging and reverse engineering attempts.
  - **Memory Runtime Analysis**: Live memory inspection and analysis.
- 🔓 **SSL Pinning Bypass**:
  - **Certificate Pinning Detection**: Identify SSL pinning implementations.
  - **Frida SSL Bypass**: Runtime SSL pinning bypass with Frida.
  - **Network Interception**: MITM proxy setup and certificate management.
  - **Burp Suite Integration**: Seamless Burp Suite proxy configuration.
- 📱 **Advanced APK Analysis**:
  - **Static Analysis**: Manifest parsing, permission analysis, resource inspection.
  - **Code Analysis**: DEX/SMALI decompilation and method signature analysis.
  - **Vulnerability Scanning**: Automated security vulnerability detection.
  - **Malware Detection**: Built-in malware scanning with signature analysis.
  - **Signature Verification**: APK signature validation and certificate inspection.
- 🔧 **Hardware Security Analysis**:
  - **TEE Analysis**: Trusted Execution Environment assessment and capabilities.
  - **Hardware-Backed Keystore**: Secure key storage analysis and validation.
  - **Secure Element Analysis**: eSE/UICC security evaluation.
  - **Biometric Hardware**: Fingerprint/face recognition security assessment.
  - **Cryptographic Acceleration**: Hardware crypto capabilities analysis.
- 🔩 **Bootloader & Firmware Security**:
  - **Bootloader Assessment**: Lock status, vulnerability scanning, OEM unlock analysis.
  - **Firmware Extraction**: Partition dumping, boot image analysis, recovery inspection.
  - **Security Verification**: Verified boot status and integrity checking.
  - **Unlock Capabilities**: Bootloader unlocking procedures and safety checks.
- 🔍 **Advanced Memory Analysis**:
  - **Memory Dumping**: Extract and analyze process memory contents.
  - **Memory Leak Detection**: Identify memory leaks and excessive allocations.
  - **Heap Analysis**: Analyze application heap for sensitive data.
  - **Stack Analysis**: Examine stack memory for security vulnerabilities.
- 🧠 **Kernel & SELinux Analysis**:
  - **Kernel Module Analysis**: Inspect loaded kernel modules for anomalies.
  - **SELinux Policy Analysis**: Review security policies and contexts.
  - **Security Feature Assessment**: Evaluate kernel hardening features.
  - **AVC Denial Monitoring**: Track SELinux access vector cache denials.
- 🔍 **Forensic Analysis**:
  - **File System Snapshot**: Capture device file system for offline analysis.
  - **App Data Analysis**: Extract and analyze application data.
  - **Search Functionality**: Find sensitive information in snapshots.
  - **SQLite Database Extraction**: Pull and analyze databases.
  - **App-Specific Extraction**: Specialized tools for popular apps:
    - WhatsApp: Extract and analyze msgstore.db and contacts
    - Telegram: Extract databases and MTProto traces
    - Signal: Extract secure messaging data (requires root)
    - Browsers: Extract history, cookies, and saved passwords from Chrome/Firefox/Brave/Edge
    - **NEW**: Instagram, Facebook, Twitter, Snapchat, TikTok, and more
- ☁️ **Cloud Backup Extraction**:
  - **Google Drive**: Extract synced data and backups.
  - **Samsung Cloud**: Access Samsung account data.
  - **iCloud**: Cross-platform cloud data analysis (when available).
- 🦠 **Malware Analysis**:
  - **Malware Detection**: Scan for suspicious applications and files.
  - **Behavior Analysis**: Monitor app behavior for malicious activity.
  - **Signature Scanning**: Check against known malware signatures.
- 🔍 **Vulnerability Scanning**:
  - **System Vulnerabilities**: Scan for known Android security issues.
  - **App Vulnerabilities**: Analyze installed apps for security flaws.
  - **Configuration Issues**: Identify insecure system settings.
- 👆 **Biometric Data Analysis**:
  - **Fingerprint Data**: Extract fingerprint templates and metadata.
  - **Facial Recognition**: Analyze face unlock data.
  - **Biometric Security**: Assess biometric authentication strength.
- 🌐 **Network Analysis**:
  - **Traffic Capture**: Record network traffic with tcpdump.
  - **Protocol Analysis**: Analyze captured traffic for security issues.
  - **Unencrypted Traffic Detection**: Identify potentially insecure communications.
  - **SSL/TLS Inspection**: Examine encrypted communications.
- ⚙️ **System Service Analysis**:
  - **Service Monitoring**: Track Android system services.
  - **Intent Analysis**: Analyze inter-process communications.
  - **Binder Analysis**: Inspect Android's IPC mechanism.
- 📱 **Device Security**:
  - **Keystore Monitoring**: Track keystore access attempts.
  - **Bluetooth Security**: Extract and analyze pairing keys.
  - **Side-Channel Analysis**: Monitor Gatekeeper responses.
  - **Firmware Analysis**: Extract and analyze device firmware.
- ⚙️ **Interactive Prompts**: User-friendly interface with interactive prompts for seamless recovery.
- 🔄 **Automatic Device Connection**: Uses ADB to automatically connect to device via USB or IP.
- 🗝️ **Decryption**: Decrypts password files and displays recovered passwords.
- 📄 **Locksettings Analysis**: Analyzes locksettings for lock screen credentials on newer Android versions.
- 🔄 **Auto Updates**: Automatically checks for updates and updates itself to ensure you have the latest version of LockKnife.
- 📊 **Security Assessment**: Check device's Android version, security patch level, and root status.
- 📂 **Custom Data Extraction**: Pull and analyze custom files or databases from device.
- 🧪 **Debug Mode**: Advanced debugging capabilities for security researchers.
- 🔐 **Secure File Handling**: All sensitive files are handled securely and securely deleted when done.
- ⚙️ **Modular Architecture**: Extensible plugin system for adding new features.
- 🔒 **Enhanced Security**: Encryption, secure deletion, and anonymous operation modes.
- 📈 **Performance Optimized**: Multi-threaded processing and optimized algorithms.
- ⚙️ **Customizable Configuration**: Configure tool behavior via configuration files or command-line options.
- 🤖 **AI-Powered Analysis** :
  - **Password Pattern Prediction**: ML-based password guessing and pattern analysis
  - **Behavioral Anomaly Detection**: Detect suspicious activities with AI
  - **Malware Classification**: Neural network-based malware identification
  - **Smart Data Correlation**: AI-driven evidence correlation
- ₿ **Cryptocurrency Forensics** :
  - **Wallet Detection**: Identify Bitcoin, Ethereum, and altcoin wallets
  - **Transaction Analysis**: Blockchain transaction history tracking
  - **Seed Phrase Recovery**: Attempt to recover wallet seed phrases
  - **Exchange App Analysis**: Forensics for Coinbase, Binance, etc.
  - **NFT & DeFi Analysis**: Non-fungible token and DeFi protocol analysis
- 🌐 **Threat Intelligence** :
  - **IOC Detection**: Indicators of Compromise identification
  - **Real-Time Threat Feeds**: Integration with VirusTotal, AlienVault OTX
  - **CVE Vulnerability Checks**: Automated vulnerability assessment
  - **Threat Actor Attribution**: Advanced threat analysis
- 🔒 **Private Space Analysis** (v4.0.0 - Android 15+):
  - **Private Space Detection**: Identify Android 15 Private Space usage
  - **Multi-Profile Extraction**: Extract data from isolated user profiles
  - **Isolation Testing**: Test app isolation boundaries
  - **Privacy Assessment**: Security analysis of Private Space implementation
- 🔑 **Passkey & Credential Analysis** (v4.0.0 - Android 14+):
  - **Credential Manager Detection**: Identify modern credential storage
  - **WebAuthn Analysis**: Analyze web authentication credentials
  - **FIDO2 Support**: Security key and passkey forensics
  - **Biometric Binding**: Analyze passkey-biometric associations
- 📱 **Multi-Device Orchestration** :
  - **Simultaneous Analysis**: Analyze multiple devices at once
  - **Cross-Device Correlation**: Find relationships between devices
  - **Synchronized Extraction**: Parallel data extraction
  - **Comparative Analysis**: Compare security postures
- 📊 **Advanced Report Generation** :
  - **Executive Summaries**: High-level reports for stakeholders
  - **Technical Reports**: Detailed technical analysis
  - **Compliance Reports**: GDPR, HIPAA compliance documentation
  - **Multiple Formats**: PDF, HTML, JSON, XML export

## Requirements

- macOS, Linux, Windows
- Bash-compatible environment
- Android Device with [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb) enabled
- [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) installed and added to your system's PATH
- [sqlite3](https://www.sqlite.org/download.html) required for Android 10+ support and enhanced data extraction features
- [GNU Parallel](https://www.gnu.org/software/parallel/) recommended for faster password cracking (optional)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) recommended for network traffic analysis (optional)
- [openssl](https://www.openssl.org/) required for encryption/decryption features
- [ent](http://www.fourmilab.ch/random/) or alternative entropy analysis tools (optional)
- [yara](https://virustotal.github.io/yara/) recommended for advanced malware analysis (optional)
- Python 3.x with additional libraries for advanced analysis features (optional)

### Optional Dependencies for Enhanced Features

**Memory Analysis:**

- gdb/lldb for advanced debugging capabilities
- valgrind for memory leak detection

**Kernel Analysis:**

- Kernel headers for advanced kernel inspection
- SELinux policy analysis tools

**Malware Analysis:**

- ClamAV or similar antivirus engines
- YARA for pattern matching
- Volatility for memory forensics

**Network Analysis:**

- tcpdump for traffic capture
- Wireshark/tshark for protocol analysis
- nmap for network scanning

**Cloud Analysis:**

- rclone for cloud storage access
- API keys for various cloud services (Google Drive, etc.)

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

## Disclaimer

**LockKnife : The Ultimate Android Security Research Tool** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-or-later License.

<h3 align="center">Happy Android Security Research with LockKnife! 🔒💫</h3>
