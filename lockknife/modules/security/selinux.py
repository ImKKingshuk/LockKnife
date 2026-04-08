from __future__ import annotations

import dataclasses
import re
from typing import Any

from lockknife.core.device import DeviceManager

_AVC_RE = re.compile(
    r"scontext=u:r:(?P<source>[^:]+):s0.*tcontext=u:object_r:(?P<target>[^:]+):s0.*tclass=(?P<tclass>[^\s]+)(?:.*permissive=(?P<permissive>[01]))?"
)


@dataclasses.dataclass(frozen=True)
class SelinuxStatus:
    status: str
    mode: str
    policy_version: str | None
    domains: list[str]
    denials: list[str]
    raw: str
    posture: dict[str, Any] = dataclasses.field(default_factory=dict)
    domain_summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    denial_summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    permissive_domains: list[str] = dataclasses.field(default_factory=list)
    policy_analysis: dict[str, Any] = dataclasses.field(default_factory=dict)
    remediation_hints: list[str] = dataclasses.field(default_factory=list)


def get_selinux_status(devices: DeviceManager, serial: str) -> SelinuxStatus:
    raw = devices.shell(serial, "getenforce", timeout_s=10.0)
    mode = (raw.strip().splitlines() or [""])[-1].strip() or "Unknown"
    policy_version = _safe_shell(devices, serial, "cat /sys/fs/selinux/policyvers")
    domains_text = _safe_shell(devices, serial, "ps -AZ")
    domains = _extract_domains(domains_text)
    denials = _collect_denials(devices, serial)
    policy_text = _collect_policy_text(devices, serial)
    policy_analysis = _analyze_policy(policy_text, denials)
    permissive_domains = list(policy_analysis.get("permissive_domains") or [])
    domain_summary = _summarize_domains(domains)
    denial_summary = _summarize_denials(denials)
    posture = _posture(mode, domain_summary, denial_summary, permissive_domains)
    remediation_hints = _remediation_hints(mode, denial_summary, permissive_domains)
    return SelinuxStatus(
        status=mode,
        mode=mode,
        policy_version=policy_version,
        domains=domains,
        denials=denials,
        raw=raw,
        posture=posture,
        domain_summary=domain_summary,
        denial_summary=denial_summary,
        permissive_domains=permissive_domains,
        policy_analysis=policy_analysis,
        remediation_hints=remediation_hints,
    )


def _safe_shell(devices: DeviceManager, serial: str, command: str) -> str | None:
    try:
        output = devices.shell(serial, command, timeout_s=10.0)
    except Exception:  # pragma: no cover - exercised through callers
        return None
    text = output.strip()
    return text or None


def _extract_domains(ps_output: str | None) -> list[str]:
    if not ps_output:
        return []
    domains: set[str] = set()
    for line in ps_output.splitlines():
        if line.startswith("LABEL") or not line.strip():
            continue
        label = line.split(None, 1)[0]
        parts = label.split(":")
        if len(parts) >= 3 and parts[2].strip():
            domains.add(parts[2].strip())
    return sorted(domains)


def _collect_denials(devices: DeviceManager, serial: str) -> list[str]:
    for command in [
        "su -c dmesg | grep 'avc:'",
        "logcat -d -b all | grep 'avc:'",
    ]:
        result = _safe_shell(devices, serial, command)
        if result:
            return [line.strip() for line in result.splitlines() if line.strip()]
    return []


def _collect_policy_text(devices: DeviceManager, serial: str) -> str | None:
    for command in [
        "strings /sys/fs/selinux/policy | head -n 4096",
        "toybox strings /sys/fs/selinux/policy | head -n 4096",
        "su -c 'strings /sys/fs/selinux/policy | head -n 4096'",
    ]:
        result = _safe_shell(devices, serial, command)
        if result:
            return result
    return None


def _summarize_domains(domains: list[str]) -> dict[str, Any]:
    app_domains = [domain for domain in domains if "app" in domain]
    privileged = [
        domain
        for domain in domains
        if domain in {"system_server", "init", "installd", "vold", "zygote", "servicemanager"}
        or domain.endswith("_server")
    ]
    return {
        "count": len(domains),
        "app_domains": app_domains[:12],
        "privileged_domains": privileged[:12],
    }


def _summarize_denials(denials: list[str]) -> dict[str, Any]:
    sources: dict[str, int] = {}
    targets: dict[str, int] = {}
    classes: dict[str, int] = {}
    permissive_count = 0
    for line in denials:
        match = _AVC_RE.search(line)
        if not match:
            continue
        sources[match.group("source")] = sources.get(match.group("source"), 0) + 1
        targets[match.group("target")] = targets.get(match.group("target"), 0) + 1
        classes[match.group("tclass")] = classes.get(match.group("tclass"), 0) + 1
        if match.group("permissive") == "1":
            permissive_count += 1
    return {
        "count": len(denials),
        "top_sources": _top_counts(sources),
        "top_targets": _top_counts(targets),
        "class_counts": _top_counts(classes),
        "permissive_count": permissive_count,
    }


def _top_counts(values: dict[str, int]) -> list[dict[str, int | str]]:
    return [
        {"name": name, "count": count}
        for name, count in sorted(values.items(), key=lambda item: (-item[1], item[0]))[:6]
    ]


def _analyze_policy(policy_text: str | None, denials: list[str]) -> dict[str, Any]:
    policy_domains = sorted(
        {
            match.group(1)
            for match in re.finditer(r"\b([a-z][a-z0-9_]{2,})\b", policy_text or "")
            if match.group(1).endswith(
                ("_app", "_server", "_service", "zygote", "init", "vold", "installd")
            )
        }
    )
    permissive_domains = sorted(
        {
            match.group(1)
            for match in re.finditer(r"permissive\s+([a-zA-Z0-9_]+)", policy_text or "")
        }
    )
    for line in denials:
        match = _AVC_RE.search(line)
        if match and match.group("permissive") == "1":
            permissive_domains.append(match.group("source"))
    unique_permissive = sorted(set(permissive_domains))
    return {
        "policy_readable": policy_text is not None,
        "policy_domain_sample": policy_domains[:20],
        "policy_domain_count": len(policy_domains),
        "permissive_domains": unique_permissive,
    }


def _posture(
    mode: str,
    domain_summary: dict[str, Any],
    denial_summary: dict[str, Any],
    permissive_domains: list[str],
) -> dict[str, Any]:
    enforcing = mode.lower() == "enforcing"
    if not enforcing or permissive_domains:
        risk_level = "high"
        if not enforcing:
            assessment = (
                "SELinux is not enforcing, which materially weakens platform isolation guarantees."
            )
        else:
            assessment = "SELinux is enforcing overall, but one or more permissive domains weaken policy enforcement for targeted processes."
    elif int(denial_summary.get("count") or 0) >= 10:
        risk_level = "medium"
        assessment = "SELinux is enforcing but active denials suggest meaningful platform policy friction worth review."
    else:
        risk_level = "low"
        assessment = "SELinux appears enforcing with limited immediately visible denial pressure."
    return {
        "risk_level": risk_level,
        "assessment": assessment,
        "enforcing": enforcing,
        "domain_count": int(domain_summary.get("count") or 0),
        "denial_count": int(denial_summary.get("count") or 0),
        "permissive_domain_count": len(permissive_domains),
    }


def _remediation_hints(
    mode: str, denial_summary: dict[str, Any], permissive_domains: list[str]
) -> list[str]:
    hints: list[str] = []
    if mode.lower() != "enforcing":
        hints.append(
            "Return the device to Enforcing mode before trusting any isolation-sensitive security conclusions."
        )
    if permissive_domains:
        hints.append(
            f"Review permissive domains {', '.join(permissive_domains[:4])} because they bypass SELinux enforcement for targeted process classes."
        )
    if int(denial_summary.get("count") or 0):
        hints.append(
            "Review recent AVC denials by source domain and object class to identify policy regressions or privilege assumptions."
        )
    if any(item.get("name") == "untrusted_app" for item in denial_summary.get("top_sources") or []):
        hints.append(
            "Prioritize untrusted_app AVC denials because they often highlight app-visible filesystem or binder boundaries."
        )
    if not hints:
        hints.append(
            "Capture a fuller audit trail during the target workflow if you need stronger SELinux evidence for reporting."
        )
    return hints[:4]
