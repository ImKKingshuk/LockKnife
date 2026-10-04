# Installation and Troubleshooting

Install LockKnife using your preferred method, then check the installation and connect your Android device. Local evidence analysis does not require a connected device.

## Install LockKnife

### macOS: Homebrew

```bash
brew install ImKKingshuk/tap/lockknife
```

To update an existing installation:

```bash
brew update
brew upgrade ImKKingshuk/tap/lockknife
```

### macOS and Linux: Installer

```bash
curl -fsSL https://lockknife.vercel.app/install | bash
```

The installer selects the release for your platform. Review the script before running it if your organization's installation policy requires this.

### Windows: Scoop

With Scoop installed:

```powershell
scoop bucket add imkkingshuk https://github.com/ImKKingshuk/scoop-bucket
scoop install imkkingshuk/lockknife
```

To update:

```powershell
scoop update
scoop update imkkingshuk/lockknife
```

### Python Environment: Release Wheel

Download the matching wheel from [GitHub Releases](https://github.com/ImKKingshuk/LockKnife/releases). Use Python 3.12 or newer:

```bash
python -m pip install /path/to/downloaded-wheel.whl
```

Prebuilt wheels support Linux x86-64/ARM64, macOS Apple Silicon, and Windows x86-64. Choose the file matching your operating system and architecture.

## Check the Installation

```bash
lockknife --version
lockknife --cli doctor
lockknife --cli device list
```

`doctor` identifies missing tools and optional dependencies. Some workflows require additional software; a missing optional dependency does not prevent unrelated offline analysis or case review.

## Connect an Android Device

1. Install Android platform-tools and ensure `adb` is available on your command path.
2. Enable developer options and USB debugging on the authorized device.
3. Connect the device and accept its debugging authorization prompt.
4. Run `lockknife --cli device list` and copy the serial for device commands.

If the device is not listed, check the USB cable, host permissions or drivers, and the device's authorization prompt. Protected application data may require root or other authorized access even when ADB is connected.

## Optional Features

| Workflow | Additional Setup |
|----------|------------------|
| APK analysis | `apk` extra; JADX and/or apktool on the command path for decompilation |
| Runtime instrumentation | `frida` extra; compatible Frida server and sufficient target permissions |
| Network analysis | `network` extra; accessible on-device `tcpdump` for capture |
| YARA scanning | `yara` extra and a rules file |
| PDF reporting | `xhtml2pdf`, or WeasyPrint and its platform libraries |
| BLE GATT | Bleak, a supported adapter, and operating-system Bluetooth permissions |
| External reputation | `threat-intel` extra, provider credentials, and permission to send indicators |

The `full` extra includes the packaged investigation extras, but not every external executable, a PDF renderer, or Bleak. For a wheel-based Python installation, select extras when installing the downloaded file:

```bash
python -m pip install '/path/to/downloaded-wheel.whl[apk,network]'
python -m pip install '/path/to/downloaded-wheel.whl[full]'
python -m pip install xhtml2pdf
python -m pip install bleak
```

Run these commands in the Python environment containing LockKnife. For a Homebrew or Scoop installation, avoid installing dependencies into an unrelated system Python. If you need a custom dependency profile, use a dedicated Python environment and the matching release wheel.

## Common Problems

| Symptom | What to Check |
|---------|---------------|
| Protected database inaccessible | Target permissions, Android user/profile, encryption, and app version |
| Native extension cannot load | Matching wheel/platform and supported Python; reinstall the matching wheel |
| Decompiler falls back to unpacking | JADX/apktool availability and the error shown for each decompiler |
| PDF output unavailable | Renderer installation and system libraries; use HTML if a renderer cannot run |
| Frida attach fails | Server/client compatibility, target identity, privileges, and running process |
| BLE dependency unavailable | Bleak installation and adapter support |
| Reputation lookup unavailable | Optional extra and private `VT_API_KEY` or `OTX_API_KEY` configuration |

Use `lockknife --cli <group> <command> --help` for current options. If you need support, share the command, version, operating system, and sanitized error message. Omit evidence contents, service keys, device identifiers, and personal file paths.

Next: [TUI walkthrough](tui-walkthrough.md) or [CLI walkthrough](headless-cli-walkthrough.md).
