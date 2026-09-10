# Contributing to LockKnife

Use a feature branch and keep each change focused. Run the relevant tests and static checks before opening a pull request.

## Public-repository safety

Never commit device data, case files, forensic captures, credentials, API tokens, private keys, signing material, local configuration, or generated reports. Use environment variables for secrets and keep real evidence outside the repository.

Before committing, run:

```bash
pre-commit install
python3 scripts/check_repository_hygiene.py
git diff --check
git status --short --ignored
```

Before a release, also run the commands documented in `.github/workflows/pre-release-checks.yml`. GitHub Actions scans the complete reachable history for known secret formats, but contributors remain responsible for revoking any credential accidentally exposed to Git.

## Pull requests

- Explain the behavior change and its security impact.
- Add or update tests for user-visible and security-sensitive behavior.
- Keep generated files and unrelated formatting changes out of the pull request.
- Update `CHANGELOG.md` for changes intended for the next release.
- Report vulnerabilities privately according to `SECURITY.md`.
