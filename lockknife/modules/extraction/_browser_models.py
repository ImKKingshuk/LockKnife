from __future__ import annotations



import dataclasses



@dataclasses.dataclass(frozen=True)
class BrowserHistoryEntry:
    url: str
    title: str | None
    last_visit_time_raw: int | None
    visit_count: int | None

@dataclasses.dataclass(frozen=True)
class BrowserBookmarkEntry:
    url: str
    title: str | None
    folder: str | None
    date_added_raw: int | None = None

@dataclasses.dataclass(frozen=True)
class BrowserDownloadEntry:
    url: str | None
    target_path: str | None
    start_time_raw: int | None
    end_time_raw: int | None
    received_bytes: int | None

@dataclasses.dataclass(frozen=True)
class BrowserCookieEntry:
    host: str | None
    name: str | None
    value: str | None
    encrypted_value_b64: str | None
    expires_utc_raw: int | None
    last_access_utc_raw: int | None

@dataclasses.dataclass(frozen=True)
class BrowserLoginEntry:
    origin_url: str | None
    username: str | None
    password_value: str | None
    password_encrypted_b64: str | None
