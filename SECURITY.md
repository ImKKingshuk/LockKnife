# Security Policy

## Sensitive Data Handling

LockKnife is a forensics and security research tool that handles sensitive data. This document outlines security best practices for contributors and users.

### Environment Variables and Secrets

LockKnife uses environment variables for API keys and sensitive configuration:

- **VT_API_KEY**: VirusTotal API key (optional)
- **OTX_API_KEY**: AlienVault OTX API key (optional)

**Never commit these values to version control.** Use the `.env` file locally (which is gitignored) or set them as environment variables.

### What's Excluded from Git

The following sensitive data types are automatically excluded via `.gitignore`:

1. **Credentials & Keys**
   - Private keys (*.pem, *.key, id_rsa, etc.)
   - Certificates (*.crt, *.cer, *.p12, *.pfx)
   - Keystores (*.jks, *.keystore)
   - Environment files (.env, .env.*)
   - API key files (secrets.json, credentials.json)

2. **Forensic Artifacts**
   - Database files (*.db, *.sqlite)
   - Network captures (*.pcap, *.pcapng)
   - Memory dumps (*.dump, *.dmp, *.hprof)
   - Evidence directories (evidence/, artifacts/, outputs/)

3. **Android Artifacts**
   - APK files (*.apk)
   - DEX files (*.dex, *.odex, *.vdex)
   - Decompiled code directories

4. **Build & Runtime Artifacts**
   - Python bytecode (__pycache__/, *.pyc)
   - Rust build artifacts (target/)
   - Virtual environments (venv/, .venv/)

### Security Scanning

This repository uses:
- **Bandit**: Python security linter (configured in `bandit.yaml`)
- **pip-audit**: Dependency vulnerability scanner

Run security checks before committing:
```bash
bandit -r lockknife/ lockknife_headless_cli/
pip-audit
```

### Reporting Security Issues

If you discover a security vulnerability in LockKnife, please report it privately:
- Do not open a public GitHub issue
- Contact the maintainers directly through GitHub Security Advisories
- Provide detailed information about the vulnerability

### Data Privacy

LockKnife is designed for forensic analysis of Android devices. Users must:
- Obtain proper authorization before analyzing devices
- Handle extracted data according to applicable laws and regulations
- Secure forensic outputs and evidence appropriately
- Follow chain of custody procedures for legal cases

## License

LockKnife is licensed under GPL-3.0. See LICENSE file for details.
