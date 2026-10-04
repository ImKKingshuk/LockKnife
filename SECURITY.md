# Security and Privacy

Use LockKnife only on devices, applications, and networks you are authorized to examine. Device-changing actions require an appropriate investigation scope and target permissions.

## Protect Case Data

Extracted messages, databases, captures, credentials, and reports may contain personal or confidential information. Keep case workspaces in private storage and restrict access to authorized recipients.

Reports and exported ZIP bundles are not encrypted by default. Review their contents before sharing and use a protected transfer method. Integrity verification checks registered evidence hashes and case audit events; it does not replace your organization's custody procedures.

See [Case Integrity and Privacy](docs/case-integrity-and-privacy.md) for verification and sharing guidance.

## Configure Credentials Safely

- `VT_API_KEY`: optional VirusTotal credential.
- `OTX_API_KEY`: optional OTX credential.
- `LOCKKNIFE_SIGNING_KEY`: required for explicit artifact sealing unless a key is supplied directly.

Set credentials in the environment running LockKnife or through a protected secret store. Threat intelligence credentials can also be loaded from a private `.env` file. Artifact sealing reads `LOCKKNIFE_SIGNING_KEY` from the process environment and requires at least 32 bytes; placing it in `.env` alone does not configure sealing.

Do not include credentials in shared configuration, reports, screenshots, or support requests. Revoke or rotate any credential exposed to an unauthorized recipient.

## External Services

Requested reputation and blockchain lookups send selected indicators to their providers. Review provider policies before sending hashes, domains, IP addresses, or wallet addresses from an investigation. Offline evidence analysis does not require these service credentials.

## Report a Vulnerability

Report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/ImKKingshuk/LockKnife/security/advisories/new), rather than a public issue. Include the affected version, a description of the problem, and sanitized reproduction steps. Do not attach real case data or secrets.

For installation and ordinary usage problems, consult [Installation and Troubleshooting](docs/installation-and-troubleshooting.md).
