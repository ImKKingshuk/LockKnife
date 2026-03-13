from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class PermissionRisk:
    permission: str
    severity: str
    score: int


_DANGEROUS: dict[str, PermissionRisk] = {
    "android.permission.READ_SMS": PermissionRisk("android.permission.READ_SMS", "high", 10),
    "android.permission.SEND_SMS": PermissionRisk("android.permission.SEND_SMS", "high", 10),
    "android.permission.RECEIVE_SMS": PermissionRisk("android.permission.RECEIVE_SMS", "high", 9),
    "android.permission.READ_CONTACTS": PermissionRisk("android.permission.READ_CONTACTS", "high", 9),
    "android.permission.WRITE_CONTACTS": PermissionRisk("android.permission.WRITE_CONTACTS", "high", 9),
    "android.permission.RECORD_AUDIO": PermissionRisk("android.permission.RECORD_AUDIO", "high", 9),
    "android.permission.CAMERA": PermissionRisk("android.permission.CAMERA", "medium", 7),
    "android.permission.ACCESS_FINE_LOCATION": PermissionRisk("android.permission.ACCESS_FINE_LOCATION", "high", 9),
    "android.permission.ACCESS_COARSE_LOCATION": PermissionRisk("android.permission.ACCESS_COARSE_LOCATION", "medium", 7),
    "android.permission.READ_CALL_LOG": PermissionRisk("android.permission.READ_CALL_LOG", "high", 9),
    "android.permission.WRITE_CALL_LOG": PermissionRisk("android.permission.WRITE_CALL_LOG", "high", 9),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionRisk("android.permission.READ_EXTERNAL_STORAGE", "medium", 6),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionRisk("android.permission.WRITE_EXTERNAL_STORAGE", "medium", 6),
}


def score_permissions(permissions: list[str]) -> tuple[int, list[PermissionRisk]]:
    risks: list[PermissionRisk] = []
    total = 0
    for p in permissions:
        r = _DANGEROUS.get(p)
        if r is None:
            continue
        risks.append(r)
        total += r.score
    risks.sort(key=lambda r: r.score, reverse=True)
    return total, risks

