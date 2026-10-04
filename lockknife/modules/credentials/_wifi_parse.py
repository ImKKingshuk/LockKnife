from __future__ import annotations

import pathlib
import re

from defusedxml.ElementTree import fromstring


def parse_wpa_supplicant(text: str) -> list[tuple[str, str | None, str | None]]:
    creds: list[tuple[str, str | None, str | None]] = []
    blocks = re.split(r"\bnetwork=\{\s*", text)
    for block in blocks[1:]:
        end = block.find("}")
        if end == -1:
            continue
        ssid = None
        psk = None
        for line in block[:end].splitlines():
            line = line.strip()
            if line.startswith("ssid="):
                ssid = line.split("=", 1)[1].strip().strip('"')
            if line.startswith("psk="):
                psk = line.split("=", 1)[1].strip().strip('"')
        if ssid:
            creds.append((ssid, psk, None))
    return creds


def parse_wifi_config_store_xml(path: pathlib.Path) -> list[tuple[str, str | None, str | None]]:
    content = path.read_text(encoding="utf-8", errors="ignore")
    if not content.strip():
        return []
    root = fromstring(content)
    out: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()

    for network in root.iter():
        tag_lower = network.tag.lower()
        if not (
            tag_lower.endswith("network")
            or tag_lower.endswith("wificonfiguration")
            or tag_lower.endswith("entry")
        ):
            continue
        ssid = None
        psk = None
        security = None
        for child in network.iter():
            name = (child.attrib.get("name") or "").lower()
            val = (child.text or "").strip().strip('"')
            if name in ("ssid", "configname", "ssids"):
                if val:
                    ssid = val
            elif name in ("presharedkey", "wepkeys", "wepkey0", "pre_shared_key"):
                if val and val != "null":
                    psk = val
            elif name in ("keymgmt", "allowedkeymgmt", "security"):
                if val:
                    security = val
            elif name == "configkey" and not ssid:
                raw_val = (child.text or "").strip()
                m = re.search(r'"([^"]+)"', raw_val)
                if m:
                    ssid = m.group(1)
                elif raw_val:
                    ssid = raw_val

        if ssid and ssid not in seen:
            seen.add(ssid)
            out.append((ssid, psk, security))
    return out
