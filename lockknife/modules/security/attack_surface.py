from __future__ import annotations

import pathlib

from lockknife.core.device import DeviceManager
from lockknife.modules.security._attack_surface_report import assess_attack_surface_report


def assess_attack_surface(
    devices: DeviceManager | None,
    *,
    package: str | None = None,
    serial: str | None = None,
    apk_path: pathlib.Path | None = None,
    artifacts_path: pathlib.Path | None = None,
) -> dict[str, object]:
    return assess_attack_surface_report(
        devices,
        package=package,
        serial=serial,
        apk_path=apk_path,
        artifacts_path=artifacts_path,
    )