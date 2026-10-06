from __future__ import annotations

import json
import pathlib
from typing import Any

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.models import PlaybookDefinition, StepDefinition

# ---------------------------------------------------------------------------
# Built-in Playbooks
# ---------------------------------------------------------------------------

_TRIAGE_PLAYBOOK = PlaybookDefinition(
    name="triage",
    title="Rapid Security & Device Triage",
    description=(
        "Fast non-invasive security assessment: device properties, AVB 2.0 dm-verity, "
        "hardware TEE attestation, SELinux enforcement, network port exposure, and summary report."
    ),
    category="security",
    steps=(
        StepDefinition(
            step_id="device.info",
            label="Device Identification & Profile",
            action_id="device.info",
            category="device",
            requires_device=True,
            timeout_s=30.0,
        ),
        StepDefinition(
            step_id="security.scan",
            label="Security Posture Baseline",
            action_id="security.scan",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="security.bootloader",
            label="Verified Boot & AVB 2.0 Audit",
            action_id="security.bootloader",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="security.hardware",
            label="Hardware TEE & Keymaster Assessment",
            action_id="security.hardware",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="security.network_scan",
            label="Network Attack Surface & Port Scan",
            action_id="security.network_scan",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=90.0,
        ),
        StepDefinition(
            step_id="report.generate",
            label="Synthesize Triage Report",
            action_id="report.generate",
            category="reporting",
            depends_on=(
                "security.scan",
                "security.bootloader",
                "security.hardware",
                "security.network_scan",
            ),
            params={"template": "technical", "format": "json"},
            timeout_s=60.0,
        ),
    ),
)


_DEEP_FORENSICS_PLAYBOOK = PlaybookDefinition(
    name="deep-forensics",
    title="Deep Forensic Extraction & Carving",
    description=(
        "Exhaustive forensic extraction: primary artifacts, private messaging, passkeys, "
        "native SQLite B-Tree deleted record carving, timeline correlation, and hash integrity audit."
    ),
    category="forensics",
    steps=(
        StepDefinition(
            step_id="device.info",
            label="Device Identification",
            action_id="device.info",
            category="device",
            requires_device=True,
            timeout_s=30.0,
        ),
        StepDefinition(
            step_id="security.posture",
            label="Pre-Acquisition Posture Check",
            action_id="security.scan",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="credentials.passkeys",
            label="FIDO2 & Keystore Passkeys Export",
            action_id="crack.passkeys",
            category="credentials",
            depends_on=("device.info",),
            requires_device=True,
            fallback_action_id="crack.keystore",
            timeout_s=90.0,
        ),
        StepDefinition(
            step_id="extract.sms",
            label="SMS Telephony Extraction",
            action_id="extract.sms",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="extract.contacts",
            label="Address Book Extraction",
            action_id="extract.contacts",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="extract.calls",
            label="Call Logs History Extraction",
            action_id="extract.call-logs",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="extract.browser",
            label="Chromium & Browser History / Logins",
            action_id="extract.browser",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=180.0,
        ),
        StepDefinition(
            step_id="extract.location",
            label="Location Artifacts & GNSS Metadata",
            action_id="extract.location",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="extract.messaging",
            label="WhatsApp & Signal Database Extraction",
            action_id="extract.messaging",
            category="extraction",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=240.0,
        ),
        StepDefinition(
            step_id="forensics.carve",
            label="SQLite B-Tree Deleted Record Carving",
            action_id="forensics.carve",
            category="forensics",
            depends_on=("extract.messaging", "extract.browser"),
            timeout_s=180.0,
        ),
        StepDefinition(
            step_id="forensics.parse",
            label="ALEAPP Evidence Normalization",
            action_id="forensics.parse",
            category="forensics",
            depends_on=("extract.sms", "extract.contacts", "extract.calls", "extract.location"),
            timeout_s=180.0,
        ),
        StepDefinition(
            step_id="forensics.timeline",
            label="Unified Forensic Timeline Correlation",
            action_id="forensics.timeline",
            category="forensics",
            depends_on=("forensics.parse", "forensics.carve"),
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="case.enrichment",
            label="Multi-Source Case Enrichment & CTI",
            action_id="case.enrich",
            category="forensics",
            depends_on=("forensics.parse",),
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="report.integrity",
            label="Tamper-Evident SHA-256 Custody Verification",
            action_id="report.integrity",
            category="reporting",
            depends_on=("forensics.timeline", "case.enrichment"),
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="report.generate",
            label="Final Comprehensive Evidence Dossier",
            action_id="report.generate",
            category="reporting",
            depends_on=("report.integrity",),
            params={"template": "technical", "format": "html"},
            timeout_s=90.0,
        ),
    ),
)


_INCIDENT_RESPONSE_PLAYBOOK = PlaybookDefinition(
    name="incident-response",
    title="Incident Response & Threat Hunt",
    description=(
        "Rapid mobile threat hunting: network socket exposure, malware pattern scanning, "
        "YARA rule evaluation, IOC extraction, CVE correlation, and incident report."
    ),
    category="security",
    steps=(
        StepDefinition(
            step_id="device.info",
            label="Device Identification",
            action_id="device.info",
            category="device",
            requires_device=True,
            timeout_s=30.0,
        ),
        StepDefinition(
            step_id="security.posture",
            label="SELinux & System Posture",
            action_id="security.scan",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="security.network_scan",
            label="Active Connections & Port Analysis",
            action_id="security.network_scan",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=90.0,
        ),
        StepDefinition(
            step_id="security.malware",
            label="Malware Signature & Pattern Scan",
            action_id="security.malware",
            category="security",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="apk.scan",
            label="Suspicious Package YARA Scan",
            action_id="apk.scan",
            category="apk",
            depends_on=("device.info",),
            requires_device=True,
            optional=True,
            timeout_s=180.0,
        ),
        StepDefinition(
            step_id="intel.ioc",
            label="IOC Extraction & CTI Feed Match",
            action_id="intel.ioc",
            category="intel",
            depends_on=("security.network_scan", "security.malware"),
            timeout_s=90.0,
        ),
        StepDefinition(
            step_id="report.integrity",
            label="Verify Incident Artifact Integrity",
            action_id="report.integrity",
            category="reporting",
            depends_on=("intel.ioc",),
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="report.generate",
            label="Incident Response Briefing",
            action_id="report.generate",
            category="reporting",
            depends_on=("report.integrity",),
            params={"template": "technical", "format": "json"},
            timeout_s=60.0,
        ),
    ),
)


_CRYPTO_AUDIT_PLAYBOOK = PlaybookDefinition(
    name="crypto-audit",
    title="Cryptocurrency Vault & Mnemonic Forensics",
    description=(
        "Mobile cryptocurrency investigation: discover on-device Web3 vaults, carve multi-chain "
        "wallet addresses (ETH, BTC, SOL, TRX), recover BIP-39 mnemonic seeds, and export audit summary."
    ),
    category="crypto-wallet",
    steps=(
        StepDefinition(
            step_id="device.info",
            label="Device Identification",
            action_id="device.info",
            category="device",
            requires_device=True,
            timeout_s=30.0,
        ),
        StepDefinition(
            step_id="crypto.scan_device",
            label="On-Device Mobile Vault Discovery",
            action_id="crypto-wallet.scan-device",
            category="crypto-wallet",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=180.0,
        ),
        StepDefinition(
            step_id="credentials.keystore",
            label="Hardware & Software Keystore Inventory",
            action_id="crack.keystore",
            category="credentials",
            depends_on=("device.info",),
            requires_device=True,
            timeout_s=90.0,
        ),
        StepDefinition(
            step_id="forensics.sqlite",
            label="Multi-Chain Address & Seed Carving",
            action_id="forensics.sqlite",
            category="forensics",
            depends_on=("crypto.scan_device",),
            timeout_s=120.0,
        ),
        StepDefinition(
            step_id="report.integrity",
            label="Cryptographic Evidence Custody Audit",
            action_id="report.integrity",
            category="reporting",
            depends_on=("forensics.sqlite", "credentials.keystore"),
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="report.generate",
            label="Crypto Assets Forensic Report",
            action_id="report.generate",
            category="reporting",
            depends_on=("report.integrity",),
            params={"template": "technical", "format": "json"},
            timeout_s=60.0,
        ),
    ),
)


_FULL_SPECTRUM_PLAYBOOK = PlaybookDefinition(
    name="full-spectrum",
    title="Full-Spectrum Autonomous Investigation",
    description=(
        "Autonomous multi-stage forensic pipeline: Triage -> Deep Acquisition -> "
        "SQLite B-Tree Carving -> Crypto Vault Discovery -> CTI Correlation -> Court-Ready Report."
    ),
    category="orchestration",
    steps=(
        *_TRIAGE_PLAYBOOK.steps[:-1],  # Include all triage steps except final report
        *_DEEP_FORENSICS_PLAYBOOK.steps[2:-2],  # Passkeys, extractions, carve, parse, timeline
        *_CRYPTO_AUDIT_PLAYBOOK.steps[1:2],  # Vault scan
        StepDefinition(
            step_id="report.integrity",
            label="Cryptographic Artifact Custody Verification",
            action_id="report.integrity",
            category="reporting",
            depends_on=("forensics.timeline", "case.enrichment"),
            timeout_s=60.0,
        ),
        StepDefinition(
            step_id="report.generate",
            label="Full-Spectrum Case Evidence Dossier",
            action_id="report.generate",
            category="reporting",
            depends_on=("report.integrity",),
            params={"template": "technical", "format": "html"},
            timeout_s=120.0,
        ),
    ),
)


BUILTIN_PLAYBOOKS: dict[str, PlaybookDefinition] = {
    _TRIAGE_PLAYBOOK.name: _TRIAGE_PLAYBOOK,
    _DEEP_FORENSICS_PLAYBOOK.name: _DEEP_FORENSICS_PLAYBOOK,
    _INCIDENT_RESPONSE_PLAYBOOK.name: _INCIDENT_RESPONSE_PLAYBOOK,
    _CRYPTO_AUDIT_PLAYBOOK.name: _CRYPTO_AUDIT_PLAYBOOK,
    _FULL_SPECTRUM_PLAYBOOK.name: _FULL_SPECTRUM_PLAYBOOK,
}


def get_playbook(name: str) -> PlaybookDefinition:
    if name not in BUILTIN_PLAYBOOKS:
        raise LockKnifeError(
            f"Unknown playbook {name!r}. Available playbooks: {list(BUILTIN_PLAYBOOKS.keys())}"
        )
    return BUILTIN_PLAYBOOKS[name]


def list_playbooks() -> list[PlaybookDefinition]:
    return list(BUILTIN_PLAYBOOKS.values())


def load_custom_playbook(path: pathlib.Path) -> PlaybookDefinition:
    """Load a custom playbook from a YAML or JSON file."""
    if not path.exists():
        raise LockKnifeError(f"Playbook file not found: {path}")

    content = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    data: Any
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(content)
        except Exception as exc:
            raise LockKnifeError(f"Failed to parse YAML playbook {path}: {exc}") from exc
    else:
        try:
            data = json.loads(content)
        except Exception as exc:
            raise LockKnifeError(f"Failed to parse JSON playbook {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise LockKnifeError(f"Playbook file must contain a mapping/object: {path}")

    try:
        return PlaybookDefinition.from_dict(data)
    except Exception as exc:
        raise LockKnifeError(f"Invalid playbook definition in {path}: {exc}") from exc
