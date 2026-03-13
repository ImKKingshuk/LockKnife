from __future__ import annotations

import dataclasses

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.modules.credentials._keystore_inventory import (
    KEYSTORE_CANDIDATE_PATHS,
    parse_keystore_listing,
)

log = get_logger()


@dataclasses.dataclass(frozen=True)
class KeystoreListing:
    path: str
    entries: list[str]


@dataclasses.dataclass(frozen=True)
class KeystoreInventory:
    serial: str
    listings: list[KeystoreListing]
    candidate_paths: list[str]


def inspect_keystore(devices: DeviceManager, serial: str) -> KeystoreInventory:
    if not devices.has_root(serial):
        raise DeviceError("Root required to inspect keystore")
    out: list[KeystoreListing] = []
    for path in KEYSTORE_CANDIDATE_PATHS:
        try:
            raw = devices.shell(serial, f"ls -1 {path} 2>/dev/null || true", timeout_s=30.0)
        except Exception:
            log.debug("keystore_ls_failed", exc_info=True, serial=serial, path=path)
            continue
        entries = parse_keystore_listing(raw)
        if entries:
            out.append(KeystoreListing(path=path, entries=entries))
    if not out:
        raise DeviceError("No keystore directories found or accessible")
    return KeystoreInventory(serial=serial, listings=out, candidate_paths=list(KEYSTORE_CANDIDATE_PATHS))


def list_keystore(devices: DeviceManager, serial: str) -> list[KeystoreListing]:
    return inspect_keystore(devices, serial).listings
