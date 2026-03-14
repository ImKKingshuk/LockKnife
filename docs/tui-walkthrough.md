# TUI Investigation Walkthrough

This walkthrough shows a realistic TUI flow from case creation to evidence capture, runtime preview, report generation, and bundle export.

The TUI itself is organized by investigation domain, so the same case-aware workflow patterns repeat across Extraction, Forensics, Runtime, Case Management, and related modules.

## Before you start

- Launch the TUI with `lockknife`.
- Connect a device if you want to run device-backed extraction or runtime actions.

We will use `./cases/CASE-xxx` as the case path throughout the example.

## x. Create the case workspace

x. Start `lockknife`.
x. Move to **Case Management** and press `Enter`.
x. Choose **Init workspace**.
x. Fill in at least:

- **Case directory**: `./cases/CASE-xxx`
- **Case ID**: `CASE-xxx`
- **Examiner**: your name
- **Title**: short investigation title
x. Submit the prompt.

Expected result:

- The output panel should report that the case workspace is ready.
- The result viewer should show the case directory and summary JSON.

## x. Capture evidence with Extraction → SMS

x. Move to **Extraction** and open the action menu.
x. Choose **SMS**.
x. Set:

- **Limit**: keep the default unless you need more rows
- **Format**: `json`
- **Output path (optional)**: leave blank
- **Case directory**: `./cases/CASE-xxx`
x. Submit the prompt.

Why leave output blank?

- LockKnife will derive a case-managed path automatically under `evidence/`.
- The resulting file is also registered in the case manifest.

After the action completes:

- Check the **Output** panel for the derived output path.
- Press `v` to open the result viewer and inspect the summary plus key paths.

## x. Review the case state

Use the **Case Management** module to confirm that the TUI is registering artifacts into the case.

This same domain-oriented structure is used throughout the TUI: each area keeps its own prompts and actions focused, while case-aware fields such as **Case directory** stay consistent across workflows.

Recommended actions:

- **Summary** for an overview of artifact counts and manifest state
- **Artifact search** to find specific evidence or derived outputs
- **Lineage graph** to understand parent/child relationships between related artifacts

Use the same **Case directory** value each time: `./cases/CASE-xxx`.

## x. Run a runtime preview with Runtime → Hook script

x. Move to **Runtime** and choose **Hook script**.
x. Fill in:

- **App ID**: target package name
- **Script path**: local Frida script path
- **Device ID**: optional if the selected device is already correct
- **Preview seconds**: `x` is a good short preview
- **Preview output path (optional)**: leave blank
- **Case directory**: `./cases/CASE-xxx`
x. Confirm the action when prompted.

What this does in the TUI:

- It stays a short preview instead of becoming a long blocking session.
- With **Case directory** set, it also saves runtime preview artifacts into the case workspace.

Expected case artifacts include:

- a preview summary JSON under `derived/`
- a script snapshot under `derived/`
- a JSONL preview log under `logs/`

Use the output panel or result viewer to capture the exact paths generated for your run.

## x. Generate a report from the current JSON result or an explicit artifacts file

Open **Forensics → Generate report**.

Important behavior:

- If **Artifacts JSON path** is set, the report is built from that file.
- If **Artifacts JSON path** is blank, the report uses the TUI's most recent JSON result.

Two good patterns:

x. Run **Case Management → Summary** or **Artifact search** first, then open **Generate report** with **Artifacts JSON path** blank.
x. Provide an exported JSON file explicitly in **Artifacts JSON path**.

Suggested report prompt values:

- **Case ID**: `CASE-xxx`
- **Template**: `technical`
- **Format**: `html`
- **Output path (optional if case dir set)**: leave blank
- **Case directory**: `./cases/CASE-xxx`

Expected result:

- LockKnife derives a report path under `reports/`.
- The report is registered in the case manifest.

## x. Export the case bundle

When you want to archive or share the collected investigation state:

x. Open **Case Management → Export bundle**.
x. Set **Case directory** to `./cases/CASE-xxx`.
x. Adjust any optional filters if needed.
x. Submit the prompt.

This gives you a portable bundle of the current case workspace and registered artifacts.

## x. What to expect on disk

With case-aware prompts, LockKnife typically derives outputs under:

- `evidence/` for captured primary evidence
- `derived/` for analysis outputs and runtime summaries
- `reports/` for generated reports
- `logs/` for runtime preview logs and related session output

The case manifest keeps those outputs tied together so later TUI actions can summarize, search, and export them coherently.
