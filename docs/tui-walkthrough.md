# TUI Investigation Walkthrough

The full-screen interface provides case-aware forms for acquisition, analysis, runtime sessions, reporting, and export. Start it with `lockknife`. Use the [CLI walkthrough](headless-cli-walkthrough.md) for unattended workflows.

## 1. Prepare the Workspace

Run `lockknife --cli doctor` to check dependencies. Connect and authorize an Android device for device-backed actions; local evidence analysis does not require a connected device.

The examples use `./cases/CASE-001` and the operator label `Analyst`. Choose a private storage location for your case data.

## 2. Create a Case

1. Open **Case Management** and choose **Init workspace**.
2. Enter **Case directory**, **Case ID**, **Examiner**, and **Title**.
3. Submit the form and check the output panel for the workspace path.

Example values are `./cases/CASE-001`, `CASE-001`, `Analyst`, and `Android Assessment`. The examiner value is recorded in case metadata and may appear in reports; use the identifier required by your investigation policy.

## 3. Acquire Evidence

Select the intended authorized device, open **Extraction**, and choose the artifact type. Set **Case directory** to the workspace and leave an optional output path blank to use a case-managed location.

After acquisition, review the printed path and result summary. Press `v` to inspect the result viewer. Device permissions, encryption, and application versions affect what can be collected; an empty result is not proof that an artifact never existed.

## 4. Review Provenance

Open **Case Management**:

- **Summary** shows registered artifacts and case state.
- **Artifact search** finds evidence and derived outputs.
- **Artifact lineage** shows an artifact's input relationships.

Use the same case directory across related actions. SQLite stores durable case state, while the JSON manifest remains a compatibility snapshot.

## 5. Manage an Authorized Runtime Session

Frida operations require the `frida` extra, a compatible target Frida server, and sufficient permissions. Runtime hooks can change app behavior; do not treat a short observation period as a dry run.

1. Open **Runtime** and choose **Start hook session**.
2. Supply **App ID**, **Session name**, **Script path**, **Device ID**, and **Case directory**.
3. Choose **Attach mode** and an **Initial wait seconds** value suitable for the target.
4. Confirm the action only within the approved investigation scope.
5. Review the session summary and log locations, and use the runtime session controls to stop the session when finished.

The initial wait is not an automatic stop timer. Check session status and explicitly stop active instrumentation. Case-managed session summaries, script snapshots, and message logs may contain sensitive application data.

## 6. Generate and Verify Reports

Open **Forensics** and choose **Generate report**. Set the case directory, template, and output format.

- An explicit **Artifacts JSON path** supplies report input.
- Without that path, a case directory allows a case-based summary.
- Without either, the most recent JSON result may supply the input.

Leave the optional output path blank to use `reports/`. HTML is available with the base installation; PDF requires an additional renderer. Use the integrity and chain-of-custody actions to review evidence hashes and case audit events.

Before sharing, inspect report previews, identifiers, paths, and credentials. Consult [Case Integrity & Privacy](case-integrity-and-privacy.md) for the limits of audit verification and safe export.

## 7. Export a Case

Open **Case Management** and choose **Export bundle**. Select the case directory, optional filters, and whether to include registered artifacts. Review the resulting archive before transferring it.

Bundles are not encrypted. Excluded artifact categories do not guarantee that other files are free of sensitive information.

## Navigation and Output

Use `Tab` to change panel focus, arrow keys to navigate, `Enter` to open an action, `Esc` to dismiss a form, and `?` for contextual help. Follow the visible confirmation and result messages before starting another device-changing action.

Case outputs are organized under `evidence/`, `derived/`, `reports/`, and `logs/`. Avoid editing `case_store.sqlite3` or compatibility snapshots manually.
