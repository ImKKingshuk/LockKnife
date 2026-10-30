# Headless CLI Walkthrough

Use the CLI to create a case, collect accessible artifacts, analyze local evidence, and export reports. Device commands require authorization and access to the relevant Android data. The examples use `EXAMPLE_CASE` and `EXAMPLE_DEVICE_SERIAL` as placeholders, not real investigation identifiers.

All example case names, examiner labels, and evidence paths are dummy values. Replace them with your authorized inputs and chosen storage locations before running commands.

## 1. Check Installation

```bash
lockknife --version
lockknife --cli doctor
lockknife --cli device list
```

Replace `EXAMPLE_DEVICE_SERIAL` below with a serial returned by `device list`. Optional tools and service credentials are described in [Installation & Troubleshooting](installation-and-troubleshooting.md).

## 2. Create a Case

Choose a private directory for case data. The examples use a `cases/` folder in the current working directory; replace it with your investigation's storage location if needed.

```bash
lockknife --cli case init --case-id EXAMPLE_CASE --examiner "EXAMPLE_EXAMINER" --title "Example Android Assessment" --output ./cases/EXAMPLE_CASE
```

The workspace contains `evidence/`, `derived/`, `reports/`, and `logs/`. `case_store.sqlite3` stores case state; `case_manifest.json` is a generated compatibility snapshot.

## 3. Inspect and Collect

```bash
lockknife --cli device info --serial EXAMPLE_DEVICE_SERIAL
lockknife --cli device shell --serial EXAMPLE_DEVICE_SERIAL getprop ro.build.version.sdk
lockknife --cli extract sms --serial EXAMPLE_DEVICE_SERIAL --format json --case-dir ./cases/EXAMPLE_CASE
lockknife --cli extract call-logs --serial EXAMPLE_DEVICE_SERIAL --format json --case-dir ./cases/EXAMPLE_CASE
lockknife --cli extract browser --serial EXAMPLE_DEVICE_SERIAL --app chrome --kind history --case-dir ./cases/EXAMPLE_CASE
lockknife --cli extract messaging --serial EXAMPLE_DEVICE_SERIAL --app whatsapp --case-dir ./cases/EXAMPLE_CASE
```

Use the paths printed by each command. Protected paths may require root, and encrypted app databases may not expose readable messages. Empty results do not establish that data never existed.

For an authorized filesystem snapshot or packet capture:

```bash
lockknife --cli forensics snapshot --serial EXAMPLE_DEVICE_SERIAL --path /path/on/device/EXAMPLE_DIRECTORY --case-dir ./cases/EXAMPLE_CASE
lockknife --cli network capture --serial EXAMPLE_DEVICE_SERIAL --duration 10 --case-dir ./cases/EXAMPLE_CASE
```

Replace `/path/on/device/EXAMPLE_DIRECTORY` with the device directory you are authorized to collect. Capturing network traffic requires an accessible on-device `tcpdump`. Review collected data before sharing it.

## 4. Analyze Local Evidence

Replace the input paths with files produced by acquisition or supplied through your evidence workflow.

```bash
lockknife --cli forensics sqlite ./example-evidence/messages.db --case-dir ./cases/EXAMPLE_CASE
lockknife --cli forensics timeline --sms ./example-evidence/sms.json --call-logs ./example-evidence/call_logs.json --case-dir ./cases/EXAMPLE_CASE
lockknife --cli forensics correlate --input ./example-evidence/artifacts.json --case-dir ./cases/EXAMPLE_CASE
lockknife --cli network analyze ./example-evidence/capture.pcap --case-dir ./cases/EXAMPLE_CASE
lockknife --cli network api-discovery ./example-evidence/capture.pcap --case-dir ./cases/EXAMPLE_CASE
```

Carved records, anomaly scores, and security heuristics are investigation leads, not independent proof of deletion, compromise, or attribution.

## 5. Review Case State

```bash
lockknife --cli case summary --case-dir ./cases/EXAMPLE_CASE
lockknife --cli case artifacts --case-dir ./cases/EXAMPLE_CASE --query timeline
lockknife --cli case graph --case-dir ./cases/EXAMPLE_CASE
```

Use the artifact inventory to confirm which outputs were registered and inspect their provenance. Manually supplied evidence is not automatically registered merely because it resides near a case.

## 6. Verify and Report

```bash
lockknife --cli report integrity --case-dir ./cases/EXAMPLE_CASE --format json
lockknife --cli report chain-of-custody --case-dir ./cases/EXAMPLE_CASE --format text
lockknife --cli report generate --case-dir ./cases/EXAMPLE_CASE --template technical --format html
```

A case-based report does not require a separate `--artifacts` file. PDF output requires an optional renderer. Review evidence previews, identifiers, paths, and any credentials before distributing a report.

## 7. Export a Bundle

```bash
lockknife --cli case export --case-dir ./cases/EXAMPLE_CASE --include-registered-artifacts --output ./example-case-bundle.zip
```

The bundle includes a consistent case database snapshot and selected artifacts. It is not an encrypted archive. Protect it according to the same policy as the original evidence; see [Case Integrity & Privacy](case-integrity-and-privacy.md).

## 8. Automate an Investigation

Choose a playbook when you want a repeatable sequence. Inspect its steps before running it:

```bash
lockknife --cli pipeline list
lockknife --cli pipeline plan --playbook triage --format json
lockknife --cli pipeline run --playbook triage --case-dir ./cases/EXAMPLE_CASE --serial EXAMPLE_DEVICE_SERIAL --dry-run
lockknife --cli pipeline run --playbook triage --case-dir ./cases/EXAMPLE_CASE --serial EXAMPLE_DEVICE_SERIAL
lockknife --cli pipeline status --case-dir ./cases/EXAMPLE_CASE
lockknife --cli pipeline resume --case-dir ./cases/EXAMPLE_CASE
```

A dry run previews actions without acquiring evidence or marking steps complete. Resume uses a matching saved recipe and target; successful steps are reused, while failed steps can be attempted again. A partial result is not a completed investigation. Cancellation stops new actions; an already-running synchronous action must return before the run can finish stopping.

For an adaptive workflow, configure an OpenAI-compatible model endpoint with `LOCKKNIFE_AI_BASE` and `LOCKKNIFE_AI_MODEL`. Set `LOCKKNIFE_AI_KEY` in your environment if that endpoint requires authentication. The default endpoint is local (`http://localhost:11434/v1`); the server and selected model must be available before starting a live agent.

```bash
lockknife --cli agent goal "Inventory accessible evidence and summarize the device security posture" --target EXAMPLE_DEVICE_SERIAL --case-dir ./cases/EXAMPLE_CASE --budget 25
lockknife --cli agent chat --case-dir ./cases/EXAMPLE_CASE
lockknife --cli agent memory --case-dir ./cases/EXAMPLE_CASE
```

The budget limits model decisions across the goal and its delegated work. Agent mode permits host commands and device operations without repeated confirmation, so choose its working environment and accessible credentials deliberately. `--restricted` narrows the available operations; it is not an operating-system sandbox. Remote model endpoints receive the context sent to them, including tool results. Use a local model when your evidence policy prohibits that disclosure.

### Use OrcaRouter Cyber Inference

[OrcaRouter](https://www.orcarouter.ai) Cyber Inference is the named remote provider for authorized security teams: it accepts scoped investigation-prompts from analysts working inside an approved scope, where a general-purpose gateway often rejects or silently downgrades them. Its base URL is `https://api.orcarouter.ai/v1` and it uses the OpenAI-compatible wire format LockKnife already speaks. Provider page: [orcarouter.ai/cyber](https://www.orcarouter.ai/cyber) · cyber-tier model catalog: [orcarouter.ai/models?tier=cyber](https://www.orcarouter.ai/models?tier=cyber).

```bash
export ORCAROUTER_API_KEY="sk-orca-..."      # create one at https://www.orcarouter.ai/console
lockknife --cli agent models --provider orcarouter          # live text-model catalog
lockknife --cli agent goal "Inventory accessible evidence and summarize the device security posture" \
  --provider orcarouter --case-dir ./cases/EXAMPLE_CASE --budget 25
lockknife --cli agent chat --provider orcarouter --case-dir ./cases/EXAMPLE_CASE
```

`--provider orcarouter` selects the preset; `--api-key` overrides the environment variable for a single run and `--api-base` / `ORCAROUTER_API_BASE` point at a self-hosted compatible deployment (HTTPS required outside loopback). The default model is `orcarouter/auto`, which routes automatically. Security teams whose workspace has passed business verification can select the dedicated cyber models `orcacyber-ultra-1.0` (security code scanning and multi-step reasoning over large codebases) and `orcacyber-zero-1.5`; `orcarouter/fusion` is the general fallback. Model choices come from the live catalog (`GET /v1/models`), filtered to text-capable chat models; when the catalog is unreachable LockKnife shows a small verified fallback list and marks the result as degraded, and a selected model that is no longer offered is reset to `orcarouter/auto` with a notice. A rejected key reports HTTP 401 once and stops rather than retrying.

Remote models receive the investigation context sent to them, including tool results. Review that disclosure against your evidence policy before enabling a remote provider, especially for red-team engagements and blue-team evidence handling.

Case memory records observations and outcomes, but model conclusions still require evidence review. A failed provider request, unavailable capability, or partial acquisition must not be interpreted as a successful assessment. `--mock` is a simulation mode, not a live investigation.

## Command Reference

```bash
lockknife --cli --help
lockknife --cli actions --format json
lockknife --cli features
```

Use `--help` on a command to view its current options. Prefer explicit serials, output locations, and timeouts in automation.
