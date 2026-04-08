from __future__ import annotations

import dataclasses
import re

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


@dataclasses.dataclass(frozen=True)
class NetworkScan:
    dns: list[str]
    dns_cache: list[str]
    listening: list[ListeningPort]
    raw: str


_RE_NETSTAT = re.compile(r"^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S+)?")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def scan_network(devices: DeviceManager, serial: str) -> NetworkScan:
    if not devices.has_root(serial):
        raise DeviceError("Root required for network scan")
    dns = []
    for k in ["net.dns1", "net.dns2", "net.dns3", "net.dns4"]:
        v = devices.shell(serial, f"getprop {k}", timeout_s=10.0).strip()
        if v:
            dns.append(v)

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

    seen = set()
    dns_cache_u = []
    for x in dns_cache:
        if x in seen:
            continue
        seen.add(x)
        dns_cache_u.append(x)

    raw = devices.shell(
        serial, 'su -c "netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null"', timeout_s=20.0
    )
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
        listening.append(
            ListeningPort(proto=proto, local=local, state=state, pid=pid, program=prog)
        )
    return NetworkScan(dns=dns, dns_cache=dns_cache_u, listening=listening, raw=raw)
