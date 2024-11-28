<h1 align="center">LockKnife</h1>
<h3 align="center">v1.7.5</h3>

<p align="center">LockKnife: The Ultimate Android Password Tool - Your Key to Android Password Recovery! 🗝️ Unlock forgotten Android lock screen passwords with ease using this powerful command-line tool. Simply connect your device, and let LockKnife do the magic! 🔒💫</p>

## What's New (v1.7.5)

- **Dictionary Attack**: Added the ability to recover screen lock passwords using a wordlist-based dictionary attack.
- **Brute Force Attack**: Implemented a brute force method to try all possible 4-digit PIN combinations for screen lock recovery.
- **Improved Dependency Management**: Checks for missing dependencies and assists in installing them via common package managers like apt, brew, or dnf.
- **Minor Optimizations**: General improvements and Optimizations

## Features

- 🔒 **Password Recovery**: Retrieve lock screen passwords (PIN, pattern, password) effortlessly.
- 📶 **Wi-Fi Password Extraction**: Easily recover saved Wi-Fi passwords from your device.
- 📱 **Multiple Android Versions Supported**: Tailored options for different Android versions:
  - Android 5 and Older
  - Android 6 to 9
  - Android 10+ and Newer Versions (Android 14)
- ⚙️ **Attack Methods**:
  - Dictionary Attack: Use custom wordlists to recover passwords.
  - Brute Force: Try all possible 4-digit PIN combinations for fast and efficient recovery.
- ⚙️ **Interactive Prompts**: User-friendly interface with interactive prompts for seamless recovery.
- 🔄 **Automatic Device Connection**: Uses ADB to automatically connect to your device.
- 🗝️ **Decryption**: Decrypts password files and displays recovered passwords.
- 📄 **Locksettings Analysis**: Analyzes locksettings for lock screen credentials on newer Android versions.
- 🔄 **Auto Updates**: Automatically checks for updates and updates itself to ensure you have the latest version of LockKnife.

## Requirements

- macOS, Linux, Windows
- Bash-compatible environment
- Android Device with [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb) enabled
- [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) installed and added to your system's PATH
- [sqlite3](https://www.sqlite.org/download.html) required for Android 10+ support

## How to Use

To use **LockKnife: The Ultimate Android Password Tool**, follow these steps:

1. Connect your Android device to your computer with USB debugging enabled.
2. Run the following command in your terminal:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)"
   ```

## Disclaimer

**LockKnife: The Ultimate Android Password Tool** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-or-later License.

<h3 align="center">Happy Android Password Recovery with LockKnife! 🔒💫</h3>
