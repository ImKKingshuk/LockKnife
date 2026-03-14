# Headless CLI Walkthrough

This walkthrough shows an end-to-end investigation flow using the Click CLI (headless mode): initialize a case workspace, capture evidence, produce derived analysis, and generate a report.

## Before you start

- Run `lockknife --help` to confirm the CLI is available.
- If you want device-backed commands, ensure `adb` can see at least one device.
- This walkthrough uses `./cases/CASE-xxx` as the case workspace path.

## x. Initialize a case workspace

```bash
lockknife case init --case-id CASE-xxx --examiner "Examiner" --title "Device x" --output ./cases/CASE-xxx
```

Notes:

- `case init` requires `--output`.
- The workspace becomes the root for case-managed outputs under `evidence/`, `derived/`, `reports/`, and `logs/`.

## x. Connect and inspect a device

List devices:

```bash
lockknife device list
```

Connect to a network device (example address only):

```bash
lockknife device connect xxx.x.xxx.xx
```

Inspect one device:

```bash
lockknife device info -s <serial>
lockknife device shell -s <serial> "getprop ro.build.version.sdk"
```

## x. Capture primary evidence

Snapshot key device paths into the case workspace:

```bash
lockknife forensics snapshot -s <serial> --path /data/system --case-dir ./cases/CASE-xxx
```

Capture a short network trace:

```bash
lockknife network capture -s <serial> --duration xx --case-dir ./cases/CASE-xxx
```

## x. Produce derived analysis

Analyze a local SQLite database (outputs to stdout unless `--case-dir` or `--output` is provided):

```bash
lockknife forensics sqlite ./evidence/mmssms.db --output sqlite_report.json
```

Build a timeline (writes to `derived/` when `--case-dir` is provided):

```bash
lockknife forensics timeline --sms ./cases/CASE-xxx/evidence/sms.json --call-logs ./cases/CASE-xxx/evidence/call_logs.json --case-dir ./cases/CASE-xxx
```

Analyze a captured pcap:

```bash
lockknife network analyze ./cases/CASE-xxx/evidence/network_capture_<serial>.pcap --case-dir ./cases/CASE-xxx
lockknife network api-discovery ./cases/CASE-xxx/evidence/network_capture_<serial>.pcap --case-dir ./cases/CASE-xxx
```

## x. Summarize and inspect the case manifest

```bash
lockknife case summary --case-dir ./cases/CASE-xxx
lockknife case artifacts --case-dir ./cases/CASE-xxx --query timeline
lockknife case graph --case-dir ./cases/CASE-xxx
```

## x. Generate a report

Generate an HTML report from the case manifest (no `--artifacts` needed when `--case-dir` is set):

```bash
lockknife report generate --case-dir ./cases/CASE-xxx --template technical --format html
```

Generate integrity and chain-of-custody outputs:

```bash
lockknife report integrity --case-dir ./cases/CASE-xxx --format json
lockknife report chain-of-custody --case-dir ./cases/CASE-xxx --format text
```

## x. Export a portable case bundle

```bash
lockknife case export --case-dir ./cases/CASE-xxx --include-registered-artifacts
```

The output is a zip bundle path (defaulting under `exports/` when `--output` is not specified).
