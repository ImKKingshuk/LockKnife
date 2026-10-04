from __future__ import annotations

import dataclasses
import re
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger

log = get_logger()


@dataclasses.dataclass(frozen=True)
class ListeningPort:
    proto: str
    local: str
    state: str | None
    pid: str | None = None
    program: str | None = None
    # --- Batch 7: risk & service classification ---
    port: int | None = None
    service_name: str | None = None
    risk_level: str | None = None
    risk_note: str | None = None


@dataclasses.dataclass(frozen=True)
class NetworkScan:
    dns: list[str]
    dns_cache: list[str]
    listening: list[ListeningPort]
    raw: str
    # --- Batch 7: exposure analysis ---
    vpn_active: bool = False
    vpn_interface: str | None = None
    tethering_active: bool = False
    iptables_rules: list[str] = dataclasses.field(default_factory=list)
    ip6tables_rules: list[str] = dataclasses.field(default_factory=list)
    interfaces: list[dict[str, str]] = dataclasses.field(default_factory=list)
    posture: dict[str, Any] = dataclasses.field(default_factory=dict)
    remediation_hints: list[str] = dataclasses.field(default_factory=list)


_RE_NETSTAT = re.compile(r"^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S+)?")
_RE_SS = re.compile(r"^(tcp|udp)\s+\S+\s+\S+\s+(\S+)\s+(\S+)")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PORT = re.compile(r":(\d+)$")

# --- Known service port database ---
_KNOWN_PORTS: dict[int, tuple[str, str, str]] = {
    # port: (service_name, risk_level, risk_note)
    21: ("FTP", "high", "FTP transmits credentials in cleartext; should not be exposed."),
    22: ("SSH", "medium", "SSH may be expected on rooted devices but increases remote attack surface."),
    23: ("Telnet", "critical", "Telnet is an insecure cleartext protocol; highly suspicious on mobile."),
    53: ("DNS", "low", "DNS resolver; generally expected for VPN or tethering."),
    80: ("HTTP", "medium", "Unencrypted HTTP server; review if intentional."),
    443: ("HTTPS", "low", "HTTPS server; typically a proxy or local service."),
    554: ("RTSP", "medium", "Real-time streaming; may indicate camera or media server."),
    1080: ("SOCKS", "high", "SOCKS proxy; verify this is authorized."),
    2222: ("ADB-alt", "high", "Alternative ADB port; may indicate custom ADB or reverse shell."),
    3128: ("Squid", "high", "HTTP proxy; verify this is not a covert proxy."),
    4444: ("Metasploit", "critical", "Common Metasploit/reverse-shell port; highly suspicious."),
    5037: ("ADB-daemon", "medium", "ADB daemon; expected on developer-mode devices."),
    5555: ("ADB-TCP", "high", "ADB over TCP; allows remote unauthenticated device access."),
    5900: ("VNC", "high", "VNC server; remote desktop access is a significant exposure."),
    6666: ("IRC/Backdoor", "critical", "Common backdoor/IRC bot port; requires investigation."),
    8080: ("HTTP-alt", "medium", "Alternative HTTP; review for proxy, debug, or dev-server usage."),
    8443: ("HTTPS-alt", "low", "Alternative HTTPS; typically a local service."),
    8888: ("HTTP-proxy", "medium", "HTTP proxy or debug server; verify purpose."),
    9090: ("WebSocket", "medium", "WebSocket or management interface; review exposure."),
    27042: ("Frida", "medium", "Frida default port; expected during runtime instrumentation."),
    31337: ("Elite/Backdoor", "critical", "Classic backdoor port; requires immediate investigation."),
}


def scan_network(devices: DeviceManager, serial: str) -> NetworkScan:
    if not devices.has_root(serial):
        raise DeviceError("Root required for network scan")

    # --- DNS resolution ---
    dns = _collect_dns(devices, serial)
    dns_cache = _collect_dns_cache(devices, serial)

    # --- Listening ports ---
    raw = devices.shell(
        serial, 'su -c "netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null"', timeout_s=20.0
    )
    listening = _parse_listening_ports(raw)

    # --- VPN detection ---
    vpn_active, vpn_interface = _detect_vpn(devices, serial)

    # --- Tethering detection ---
    tethering_active = _detect_tethering(devices, serial)

    # --- iptables rules ---
    iptables_rules = _collect_iptables(devices, serial)
    ip6tables_rules = _collect_ip6tables(devices, serial)

    # --- Interface inventory ---
    interfaces = _collect_interfaces(devices, serial)

    # --- Posture assessment ---
    posture = _assess_network_posture(
        listening=listening,
        vpn_active=vpn_active,
        tethering_active=tethering_active,
        iptables_rules=iptables_rules,
        dns=dns,
    )
    remediation_hints = _network_remediation_hints(posture)

    return NetworkScan(
        dns=dns,
        dns_cache=dns_cache,
        listening=listening,
        raw=raw,
        vpn_active=vpn_active,
        vpn_interface=vpn_interface,
        tethering_active=tethering_active,
        iptables_rules=iptables_rules,
        ip6tables_rules=ip6tables_rules,
        interfaces=interfaces,
        posture=posture,
        remediation_hints=remediation_hints,
    )


def _collect_dns(devices: DeviceManager, serial: str) -> list[str]:
    dns: list[str] = []
    for k in ["net.dns1", "net.dns2", "net.dns3", "net.dns4"]:
        v = devices.shell(serial, f"getprop {k}", timeout_s=10.0).strip()
        if v:
            dns.append(v)
    return dns


def _collect_dns_cache(devices: DeviceManager, serial: str) -> list[str]:
    dns_cache: list[str] = []
    for cmd in [
        'su -c "cmd netd resolver dump 2>/dev/null"',
        'su -c "cmd netd resolver getnetdns 0 2>/dev/null"',
        'su -c "dumpsys netd 2>/dev/null"',
        'su -c "cat /etc/resolv.conf 2>/dev/null"',
    ]:
        try:
            raw_dns = devices.shell(serial, cmd, timeout_s=20.0)
        except Exception:
            log.debug("dns_cache_probe_failed", exc_info=True, serial=serial, cmd=cmd)
            continue
        for m_ip in _RE_IPV4.finditer(raw_dns):
            dns_cache.append(m_ip.group(0))
        if dns_cache:
            break

    seen: set[str] = set()
    unique: list[str] = []
    for x in dns_cache:
        if x not in seen:
            seen.add(x)
            unique.append(x)
    return unique


def _parse_listening_ports(raw: str) -> list[ListeningPort]:
    listening: list[ListeningPort] = []
    for ln in raw.splitlines():
        s = ln.strip()
        m = _RE_NETSTAT.match(s)
        if not m:
            continue
        proto, local, _remote, state, pidprog = (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4),
            m.group(5),
        )
        pid = None
        prog = None
        if pidprog and "/" in pidprog:
            pid, prog = pidprog.split("/", 1)

        # Extract port number
        port_num = _extract_port(local)

        # Classify service & risk
        service_name, risk_level, risk_note = _classify_port(port_num)

        listening.append(
            ListeningPort(
                proto=proto,
                local=local,
                state=state,
                pid=pid,
                program=prog,
                port=port_num,
                service_name=service_name,
                risk_level=risk_level,
                risk_note=risk_note,
            )
        )
    return listening


def _extract_port(address: str) -> int | None:
    """Extract port number from address string like '0.0.0.0:5555' or ':::5555'."""
    m = _RE_PORT.search(address)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def _classify_port(port: int | None) -> tuple[str | None, str | None, str | None]:
    """Return (service_name, risk_level, risk_note) for a known port."""
    if port is None:
        return None, None, None
    entry = _KNOWN_PORTS.get(port)
    if entry:
        return entry
    # Heuristic classification for unknown ports
    if port < 1024:
        return None, "medium", "Privileged port with unrecognized service; review manually."
    if port >= 49152:
        return None, "low", "Ephemeral port; likely a client-side or dynamic allocation."
    return None, "info", None


def _detect_vpn(devices: DeviceManager, serial: str) -> tuple[bool, str | None]:
    """Detect active VPN tunnel interfaces."""
    try:
        ifconfig = devices.shell(serial, 'su -c "ip link show 2>/dev/null"', timeout_s=10.0)
    except Exception:
        return False, None

    vpn_patterns = ("tun", "tap", "ppp", "ipsec", "wg")
    for ln in ifconfig.splitlines():
        for pat in vpn_patterns:
            if pat in ln.lower() and "UP" in ln.upper():
                # Extract interface name
                m = re.search(r"\d+:\s+(\S+):", ln)
                iface = m.group(1) if m else pat
                return True, iface
    return False, None


def _detect_tethering(devices: DeviceManager, serial: str) -> bool:
    """Detect if USB/WiFi tethering is active."""
    try:
        tether_raw = devices.shell(
            serial, 'su -c "dumpsys tethering 2>/dev/null | head -n 50"', timeout_s=10.0
        )
    except Exception:
        return False
    return bool(
        "Tethering: true" in tether_raw
        or "active" in tether_raw.lower()
        and "tether" in tether_raw.lower()
    )


def _collect_iptables(devices: DeviceManager, serial: str) -> list[str]:
    """Collect IPv4 iptables rules."""
    try:
        raw = devices.shell(serial, 'su -c "iptables -L -n --line-numbers 2>/dev/null"', timeout_s=15.0)
    except Exception:
        log.debug("iptables_probe_failed", exc_info=True, serial=serial)
        return []
    rules = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return rules[:100]  # Cap output


def _collect_ip6tables(devices: DeviceManager, serial: str) -> list[str]:
    """Collect IPv6 ip6tables rules."""
    try:
        raw = devices.shell(serial, 'su -c "ip6tables -L -n --line-numbers 2>/dev/null"', timeout_s=15.0)
    except Exception:
        log.debug("ip6tables_probe_failed", exc_info=True, serial=serial)
        return []
    rules = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return rules[:100]


def _collect_interfaces(devices: DeviceManager, serial: str) -> list[dict[str, str]]:
    """Enumerate network interfaces with state and addresses."""
    try:
        raw = devices.shell(serial, 'su -c "ip addr show 2>/dev/null"', timeout_s=10.0)
    except Exception:
        return []

    interfaces: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for ln in raw.splitlines():
        s = ln.strip()
        # New interface line: "2: wlan0: <...> state UP ..."
        m = re.match(r"^\d+:\s+(\S+):\s+<([^>]*)>.*state\s+(\S+)", s)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "name": m.group(1).rstrip(":"),
                "flags": m.group(2),
                "state": m.group(3),
            }
        elif s.startswith("inet ") and current:
            addr_m = re.search(r"inet\s+(\S+)", s)
            if addr_m:
                current["ipv4"] = addr_m.group(1)
        elif s.startswith("inet6 ") and current:
            addr_m = re.search(r"inet6\s+(\S+)", s)
            if addr_m:
                current.setdefault("ipv6", addr_m.group(1))

    if current:
        interfaces.append(current)

    return interfaces[:20]


def _assess_network_posture(
    *,
    listening: list[ListeningPort],
    vpn_active: bool,
    tethering_active: bool,
    iptables_rules: list[str],
    dns: list[str],
) -> dict[str, Any]:
    """Derive a composite network exposure posture."""
    findings: list[dict[str, str]] = []
    risk_score = 0

    # --- High-risk ports ---
    critical_ports = [p for p in listening if p.risk_level == "critical"]
    high_risk_ports = [p for p in listening if p.risk_level == "high"]

    if critical_ports:
        for p in critical_ports:
            findings.append({
                "signal": "critical_port",
                "value": f"{p.proto}:{p.port} ({p.service_name or 'unknown'})",
                "severity": "critical",
                "detail": p.risk_note or "Critical-risk port detected.",
            })
            risk_score += 5

    if high_risk_ports:
        for p in high_risk_ports[:5]:
            findings.append({
                "signal": "high_risk_port",
                "value": f"{p.proto}:{p.port} ({p.service_name or 'unknown'})",
                "severity": "high",
                "detail": p.risk_note or "High-risk port detected.",
            })
            risk_score += 2

    # --- Wildcard listeners ---
    wildcard = [p for p in listening if "0.0.0.0" in p.local or ":::" in p.local]
    if wildcard:
        findings.append({
            "signal": "wildcard_listeners",
            "value": str(len(wildcard)),
            "severity": "warning" if len(wildcard) <= 3 else "high",
            "detail": f"{len(wildcard)} services are listening on all interfaces (0.0.0.0/::).",
        })
        if len(wildcard) > 3:
            risk_score += 2

    # --- Total open ports ---
    findings.append({
        "signal": "total_listening",
        "value": str(len(listening)),
        "severity": "info",
        "detail": f"{len(listening)} total listening ports detected.",
    })

    # --- VPN ---
    if vpn_active:
        findings.append({
            "signal": "vpn",
            "value": "active",
            "severity": "info",
            "detail": "Active VPN tunnel detected; traffic may be routed through a tunnel.",
        })

    # --- Tethering ---
    if tethering_active:
        findings.append({
            "signal": "tethering",
            "value": "active",
            "severity": "warning",
            "detail": "Tethering is active; device is sharing its network connection.",
        })
        risk_score += 1

    # --- ADB TCP ---
    adb_tcp = [p for p in listening if p.port == 5555]
    if adb_tcp:
        findings.append({
            "signal": "adb_tcp",
            "value": "open",
            "severity": "high",
            "detail": "ADB over TCP (port 5555) is listening; this allows unauthenticated remote access.",
        })
        risk_score += 3

    # --- iptables presence ---
    non_default_rules = [r for r in iptables_rules if "ACCEPT" not in r and "Chain" not in r and r.strip()]
    if non_default_rules:
        findings.append({
            "signal": "iptables_custom",
            "value": str(len(non_default_rules)),
            "severity": "info",
            "detail": f"{len(non_default_rules)} non-default iptables rules detected.",
        })

    # --- Overall ---
    if risk_score >= 8:
        risk_level = "critical"
        assessment = "Multiple critical network exposures detected; the device has highly suspicious network-accessible services."
    elif risk_score >= 4:
        risk_level = "high"
        assessment = "Significant network exposure detected; review open ports and listening services."
    elif risk_score >= 2:
        risk_level = "medium"
        assessment = "Some network exposure signals detected; most are likely benign but warrant review."
    else:
        risk_level = "low"
        assessment = "Network exposure appears minimal with no high-risk services detected."

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "assessment": assessment,
        "findings": findings,
        "finding_count": len(findings),
        "port_summary": {
            "total": len(listening),
            "critical": len(critical_ports),
            "high": len(high_risk_ports),
            "wildcard": len(wildcard),
        },
    }


def _network_remediation_hints(posture: dict[str, Any]) -> list[str]:
    """Generate actionable remediation hints from network posture."""
    hints: list[str] = []
    findings = posture.get("findings") or []

    for f in findings:
        severity = f.get("severity", "")
        signal = f.get("signal", "")

        if severity == "critical":
            if signal == "critical_port":
                hints.append(
                    f"Investigate and terminate the service on {f.get('value', 'unknown port')}; "
                    "this port is associated with known attack tooling or insecure protocols."
                )

        if severity == "high":
            if signal == "adb_tcp":
                hints.append(
                    "Disable ADB over TCP (adb tcpip 0 or disable wireless debugging) to close remote access."
                )
            elif signal == "high_risk_port":
                hints.append(
                    f"Review the service on {f.get('value', 'unknown port')} and disable if not required."
                )

        if severity == "warning":
            if signal == "tethering":
                hints.append(
                    "Disable tethering when not needed to reduce the device's network attack surface."
                )

    if not hints:
        hints.append(
            "Network posture appears clean; capture this baseline for comparison in future scans."
        )

    return hints[:6]
