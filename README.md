<h1 align="center">LockKnife</h1>
<h3 align="center">v1.8.5</h3>

<p align="center">LockKnife : The Ultimate Android Security Research Tool - Your Gateway to Android Security Research! 🗝️ Dive deep into Android security with this powerful command-line tool designed for researchers. Recover lock screen passwords, Crack lock screen Passwords / Pins / Patterns, extract sensitive data like SMS, Call Logs and Wi-Fi credentials, assess device security,  and more. Connect your device and let LockKnife unlock a world of possibilities! 🔒💫</p>

## What's New (v1.8.5)

- **Variable-Length PIN Cracking**: Now supports cracking 4, 6, or 8-digit PINs for more flexible brute-force attacks.
- **Alphanumeric Password Support**: Added the ability to recover alphanumeric passwords using custom wordlists for dictionary attacks.
- **Security Assessment**: Check device's Android version, security patch level, and root status with a new security check feature.
- **Enhanced Data Extraction**: Recover SMS messages, call logs, and Wi-Fi passwords.
- **Improved Dependency Management**: Checks for missing dependencies and attempts to install them via common package managers like `apt`, `brew`, or `dnf`.
- **Minor Optimizations**: General improvements for better performance and usability.

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
- ⚙️ **Interactive Prompts**: User-friendly interface with interactive prompts for seamless recovery.
- 🔄 **Automatic Device Connection**: Uses ADB to automatically connect to device.
- 🗝️ **Decryption**: Decrypts password files and displays recovered passwords.
- 📄 **Locksettings Analysis**: Analyzes locksettings for lock screen credentials on newer Android versions.
- 🔄 **Auto Updates**: Automatically checks for updates and updates itself to ensure you have the latest version of LockKnife.
- 📊 **Security Assessment**: Check device's Android version, security patch level, and root status.
- 📂 **Custom Data Extraction**: Pull and analyze custom files or databases from device

## Requirements

- macOS, Linux, Windows
- Bash-compatible environment
- Android Device with [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb) enabled
- [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) installed and added to your system's PATH
- [sqlite3](https://www.sqlite.org/download.html) required for Android 10+ support and enhanced data extraction features

## How to Use

To use **LockKnife : The Ultimate Android Security Research Tool**, follow these steps:

1. Connect your Android device to your computer with USB debugging enabled.
2. Run the following command in your terminal:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)"
   ```

   Follow the on-screen prompts to select your device and choose the desired features.

## Disclaimer

**LockKnife : The Ultimate Android Security Research Tool** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-or-later License.

<h3 align="center">Happy Android Security Research with LockKnife! 🔒💫</h3>
