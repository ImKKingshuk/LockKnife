<h1 align="center">LockKnife</h1>
<h3 align="center">v2.0.0</h3>

<p align="center">LockKnife : The Ultimate Android Security Research Tool - Your Gateway to Android Security Research! 🗝️ Dive deep into Android security with this powerful command-line tool designed for researchers. Recover lock screen passwords, Crack lock screen Passwords / Pins / Patterns, extract sensitive data like SMS, Call Logs and Wi-Fi credentials, assess device security, perform network traffic analysis, create file system snapshots for forensic analysis, and more. Connect your device and let LockKnife unlock a world of possibilities! 🔒💫</p>

## What's New (v2.0.0)

- **Configuration System**: Customize tool behavior via config files in multiple locations or command-line options.
- **Gesture Pattern Recognition**: Now with precomputed gesture pattern hash mapping and visual representation of lock patterns.
- **File System Snapshot**: Create comprehensive snapshots of device file systems for offline forensic analysis.
- **Network Traffic Analysis**: Capture and analyze network traffic with tcpdump to identify security issues.
- **Forensic Analysis Tools**: Enhanced capabilities for analyzing app data, searching through device snapshots, and extracting sensitive information.
- **App-Specific Extraction**: Specialized extraction for popular apps:
  - WhatsApp: Extract and analyze msgstore.db and contacts
  - Telegram: Extract databases and MTProto traces
  - Signal: Extract secure messaging data (requires root)
  - Browsers: Extract history, cookies, and saved passwords from Chrome/Firefox/Brave/Edge
- **Bluetooth Pairing Keys**: Extract and analyze Bluetooth pairing keys across different Android versions.
- **Keystore Access Monitoring**: Monitor and analyze keystore access attempts for security research.
- **Gatekeeper HAL Analysis**: Advanced credential recovery via Gatekeeper HAL analysis.
- **Modern Credential Recovery**: Support for extracting and analyzing modern Android credential storage with TEE integration.

## Features

- 🔒 **Password Recovery**: Retrieve / Crack lock screen passwords (PIN, pattern, password) effortlessly.
- 📶 **Wi-Fi Password Extraction**: Easily recover saved Wi-Fi passwords from device.
- 📱 **Multiple Android Versions Supported**: Tailored options for different Android versions:
  - Android 5 and Older
  - Android 6 to 9
  - Android 10+ and Newer Versions (Android 14)
- ⚙️ **Attack Methods**:
  - **Dictionary Attack**: Use custom wordlists to recover alphanumeric passwords.
  - **Brute Force**: Try all possible combinations for 4, 6, or 8-digit PINs.
  - **Parallel Processing**: Multi-core support for faster attacks.
  - **Pattern Recognition**: Precomputed gesture pattern hash mapping.
  - **Gatekeeper Analysis**: Extract and analyze modern credential storage.
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
- 🌐 **Network Analysis**:
  - **Traffic Capture**: Record network traffic with tcpdump.
  - **Protocol Analysis**: Analyze captured traffic for security issues.
  - **Unencrypted Traffic Detection**: Identify potentially insecure communications.
- 📱 **Device Security**:
  - **Keystore Monitoring**: Track keystore access attempts.
  - **Bluetooth Security**: Extract and analyze pairing keys.
  - **Side-Channel Analysis**: Monitor Gatekeeper responses.
- ⚙️ **Interactive Prompts**: User-friendly interface with interactive prompts for seamless recovery.
- 🔄 **Automatic Device Connection**: Uses ADB to automatically connect to device via USB or IP.
- 🗝️ **Decryption**: Decrypts password files and displays recovered passwords.
- 📄 **Locksettings Analysis**: Analyzes locksettings for lock screen credentials on newer Android versions.
- 🔄 **Auto Updates**: Automatically checks for updates and updates itself to ensure you have the latest version of LockKnife.
- 📊 **Security Assessment**: Check device's Android version, security patch level, and root status.
- 📂 **Custom Data Extraction**: Pull and analyze custom files or databases from device.
- 🧪 **Debug Mode**: Advanced debugging capabilities for security researchers.
- 🔐 **Secure File Handling**: All sensitive files are handled securely and securely deleted when done.
- ⚙️ **Customizable Configuration**: Configure tool behavior via configuration files or command-line options.

## Requirements

- macOS, Linux, Windows
- Bash-compatible environment
- Android Device with [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb) enabled
- [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) installed and added to your system's PATH
- [sqlite3](https://www.sqlite.org/download.html) required for Android 10+ support and enhanced data extraction features
- [GNU Parallel](https://www.gnu.org/software/parallel/) recommended for faster password cracking (optional)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) recommended for network traffic analysis (optional)

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
