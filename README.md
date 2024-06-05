<h1 align="center">LockKnife</h1> 
<h3 align="center">v1.5.0</h3>

LockKnife is a command-line tool written in Bash that helps you recover Android lock screen passwords of an Android device.

## What's New (v1.5.0)

- Enhanced User Interface with Main Menu and Submenus
- Added Support for Android 10 and Newer Versions (Android 14)
- Improved Wi-Fi Password Recovery
- Integrated Locksettings Analysis for Android 10+
- Support for Multiple Android Versions:
  - Android 5 and Older
  - Android 6 to 9
  - Android 10 and Newer

## Features

- Convenient terminal-based tool to recover:
  - Android lock screen passwords (PIN, pattern, password)
  - WiFi passwords
- Easy-to-use with interactive prompts.
- Supports Android devices with USB debugging enabled.
- Automatically connects to the device using ADB.
- Decrypts password files and displays recovered passwords.
- Analyzes locksettings for lock screen credentials on newer Android versions.

## Requirements

- macOS, Linux, Windows
- Bash-compatible environment
- Rooted Android device
- [ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb) installed properly and added to your system's PATH.
- [sqlite3](https://www.sqlite.org/download.html) for analyzing locksettings.db (required for Android 10+ support)

## How to Use

To use LockKnife, follow these steps:

1. Connect your Android device to your computer with USB debugging enabled.
2. Run the following command in your terminal:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)"
   ```

## Disclaimer

🌟🌟🌟 "The developer of LockKnife is not responsible for any misuse or illegal activities conducted with this tool. Use at your own risk." 🌟🌟🌟

### Note

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy.
Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## Acknowledgments

`LockKnife : The Ultimate Android Password Tool` is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer acknowledges and appreciates the effort that went into creating this powerful and versatile Android password recovery tool.

Feel free to contribute to the project by reporting issues or submitting pull requests!

### 😊 Happy Android Password Recovery with LockKnife! 😊
