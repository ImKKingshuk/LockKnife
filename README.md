# LockKnife

LockKnife is a command-line tool written in Bash that helps you recover Android lock screen passwords of an Android device.

## Whats New ( v1.2.0 )

- Added multiple password recovery
- Wifi password recovery
- Gesture password recovery

## Features

- Convenient terminal-based tool to recover i.Android lock screen passwords, ii.WiFi passwords.
- Easy-to-use with interactive prompts.
- Supports Android devices with USB debugging enabled.
- Automatically connects to the device using ADB.
- Auto Decrypts the password file (assuming default encryption) and displays the recovered passwords.

## Requirements

- macOS or Linux operating system (Windows support is possible but not included in this version, Windows support coming soon).
- [ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb) installed properly and added to your system's PATH.

## How to Use

To use LockKnife, follow these steps:

1. Connect your Android device to your computer with USB debugging enabled.
2. Run the following command in your terminal:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/LockKnife.sh)"
   ```

## Disclaimer

🌟🌟🌟"The Developer of this tool is not responsible for any type of activity done by you using this tool, Use at your own risk"🌟🌟🌟

### Note

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy.

Please note that this example assumes that you have the necessary permissions and access to the Android device for which you want to recover the password. Additionally, this tool may not work on all Android devices or all Android versions or for all password types.

## Acknowledgments

LockKnife tool was created for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse of this tool.

Feel free to contribute to the project by reporting issues or submitting pull requests!

### 😊 Happy Android Password Recovery with LockKnife! 😊
