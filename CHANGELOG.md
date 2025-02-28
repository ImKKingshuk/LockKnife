# Changelog

All notable changes to `LockKnife : The Ultimate Android Security Research Tool` will be documented in this file.

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
