# Case Integrity and Privacy

Case files can contain messages, location history, account identifiers, credentials, app data, and other personal information. Collect only authorized data and keep it in private storage with appropriate access and retention controls.

Paths containing `EXAMPLE_CASE` and the filename `example-case-bundle.zip` below are dummy examples. Substitute your case directory and chosen output path.

## Durable Case State

`case_store.sqlite3` records case metadata, registered artifacts, tracked jobs, runtime sessions, and append-only audit events. `case_manifest.json` is a generated compatibility snapshot, not a second independent source of truth.

Use supported case commands to register and inspect artifacts. Avoid manually editing the database or snapshots. Preserve original evidence and work on appropriate copies when analyzing data.

## Integrity Checks

```bash
lockknife --cli report integrity --case-dir ./cases/EXAMPLE_CASE --format json
lockknife --cli report chain-of-custody --case-dir ./cases/EXAMPLE_CASE --format text
```

Integrity checks compare registered artifact hashes and verify the case event chain. A hash chain alone does not prove who created evidence or detect every change to an entire replaced history. Preserve a trusted digest, signed record, or other independent custody reference when your procedures require it.

Explicit artifact sealing requires a supplied secret or `LOCKKNIFE_SIGNING_KEY`, with at least 32 bytes. There is no shared default key. Keep the key in a protected secret store and retain it according to your verification policy; do not publish it with an artifact or bundle. Artifact seals and optional GPG report signatures are distinct mechanisms.

## Reports and Bundles

```bash
lockknife --cli report generate --case-dir ./cases/EXAMPLE_CASE --template technical --format html
lockknife --cli case export --case-dir ./cases/EXAMPLE_CASE --include-registered-artifacts --output ./example-case-bundle.zip
```

Case bundles contain a consistent database snapshot and selected outputs. Reports and ZIP bundles are not encrypted by default and may expose evidence previews, examiner identifiers, filesystem paths, and application secrets.

Before sharing:

- Inspect both report contents and archive members.
- Apply redaction and recipient-specific review under your organization's procedures.
- Protect the transfer and storage location with suitable access controls or encryption.
- Do not assume artifact filters remove sensitive content from every retained file.
- Do not attach case archives, generated reports, captures, databases, or signing material to public support requests.

## External Services

VirusTotal, OTX, wallet lookups, and other explicitly requested external integrations transmit selected indicators to their providers. Review provider policies and obtain permission before sending case-related hashes, domains, IP addresses, or addresses. Local parsing and case review do not require these service credentials.

Store `VT_API_KEY` and `OTX_API_KEY` in environment variables or a private `.env` file. Do not include service credentials in shared configuration, reports, or support requests. Revoke or rotate any credential exposed to an unauthorized recipient.

## Research Capability Limits

Dry-run previews are not completed live operations. Unavailable, simulated, or PoC capabilities must not be interpreted as verified exploitation. Check capability metadata and use device-changing workflows only within the approved operator, case, target, and authorization scope.

Report suspected vulnerabilities through the private process described in [Security Policy](../SECURITY.md), using sanitized reproduction data.
