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
    root = fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    out: list[tuple[str, str | None, str | None]] = []
    for network in root.iter():
        if not network.tag.endswith("Network"):
            continue
        ssid = None
        psk = None
        security = None
        for child in network.iter():
            name = child.attrib.get("name") or ""
            if name == "SSID" and child.text:
                ssid = child.text.strip().strip('"')
            if name in {"PreSharedKey", "WEPKeys"} and child.text:
                psk = child.text.strip().strip('"')
            if name == "KeyMgmt" and child.text:
                security = child.text.strip()
        if ssid:
            out.append((ssid, psk, security))
    return out