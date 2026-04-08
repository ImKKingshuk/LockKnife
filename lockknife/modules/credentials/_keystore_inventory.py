from __future__ import annotations

KEYSTORE_CANDIDATE_PATHS = [
    "/data/misc/keystore",
    "/data/misc/keystore/user_0",
    "/data/misc/keystore/user_10",
    "/data/misc/keystore2",
]


def parse_keystore_listing(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]
