from __future__ import annotations

import dataclasses
import json
import pathlib
import sqlite3
import time
from collections.abc import Iterable
from typing import Any

from lockknife.core.http import http_get, http_get_json
from lockknife.core.secrets import load_secrets
from lockknife.modules.intelligence.ioc import detect_iocs, load_stix_indicators_from_url, load_taxii_indicators


@dataclasses.dataclass(frozen=True)
class IocRecord:
    ioc: str
    kind: str
    source: str
    first_seen: float


def init_db(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE IF NOT EXISTS iocs (ioc TEXT PRIMARY KEY, kind TEXT, source TEXT, first_seen REAL)")
        con.execute(
            "CREATE TABLE IF NOT EXISTS ioc_feed_sync (feed_name TEXT PRIMARY KEY, feed_type TEXT NOT NULL, last_success REAL, last_error TEXT, last_count INTEGER NOT NULL DEFAULT 0)"
        )
        con.commit()
    finally:
        con.close()


def add_iocs(path: pathlib.Path, records: list[IocRecord]) -> int:
    init_db(path)
    con = sqlite3.connect(str(path))
    try:
        cur = con.cursor()
        n = 0
        for r in records:
            cur.execute("INSERT OR REPLACE INTO iocs(ioc, kind, source, first_seen) VALUES (?, ?, ?, ?)", (r.ioc, r.kind, r.source, float(r.first_seen)))
            n += 1
        con.commit()
        return n
    finally:
        con.close()


def list_iocs(path: pathlib.Path, limit: int = 200) -> list[IocRecord]:
    init_db(path)
    con = sqlite3.connect(str(path))
    try:
        cur = con.cursor()
        cur.execute("SELECT ioc, kind, source, first_seen FROM iocs ORDER BY first_seen DESC LIMIT ?", (limit,))
        return [IocRecord(ioc=ioc, kind=kind, source=source, first_seen=float(first_seen)) for ioc, kind, source, first_seen in cur.fetchall()]
    finally:
        con.close()


def sync_ioc_feeds(
    path: pathlib.Path,
    feeds: list[dict[str, Any]],
    *,
    force: bool = False,
    min_refresh_seconds: int = 6 * 3600,
) -> dict[str, Any]:
    init_db(path)
    results: list[dict[str, Any]] = []
    total_added = 0
    con = sqlite3.connect(str(path))
    try:
        for feed in feeds:
            name = str(feed.get("name") or f"feed-{len(results) + 1}")
            feed_type = str(feed.get("type") or "stix_url")
            state = _feed_state(con, name)
            if not force and state.get("last_success") and (now() - float(state["last_success"])) < min_refresh_seconds:
                results.append({"name": name, "feed_type": feed_type, "status": "skipped", "reason": "fresh", "added": 0})
                continue
            try:
                records = list(_load_feed_records(feed))
                added = add_iocs(path, records)
                _write_feed_state(con, name=name, feed_type=feed_type, last_success=now(), last_error=None, last_count=added)
                results.append({"name": name, "feed_type": feed_type, "status": "updated", "added": added})
                total_added += added
            except Exception as exc:
                _write_feed_state(con, name=name, feed_type=feed_type, last_success=state.get("last_success"), last_error=str(exc), last_count=0)
                results.append({"name": name, "feed_type": feed_type, "status": "error", "added": 0, "error": str(exc)})
        con.commit()
    finally:
        con.close()
    return {"db": str(path), "feeds": results, "total_added": total_added}


def load_feed_config(path: pathlib.Path) -> list[dict[str, Any]]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict) and isinstance(parsed.get("feeds"), list):
        return [item for item in parsed["feeds"] if isinstance(item, dict)]
    raise ValueError("Feed config must be a JSON array or object with a feeds array")


def _feed_state(con: sqlite3.Connection, name: str) -> dict[str, Any]:
    row = con.execute("SELECT feed_name, feed_type, last_success, last_error, last_count FROM ioc_feed_sync WHERE feed_name=?", (name,)).fetchone()
    if row is None:
        return {}
    return {"feed_name": row[0], "feed_type": row[1], "last_success": row[2], "last_error": row[3], "last_count": row[4]}


def _write_feed_state(
    con: sqlite3.Connection,
    *,
    name: str,
    feed_type: str,
    last_success: float | None,
    last_error: str | None,
    last_count: int,
) -> None:
    con.execute(
        "INSERT OR REPLACE INTO ioc_feed_sync(feed_name, feed_type, last_success, last_error, last_count) VALUES (?, ?, ?, ?, ?)",
        (name, feed_type, last_success, last_error, int(last_count)),
    )


def _load_feed_records(feed: dict[str, Any]) -> Iterable[IocRecord]:
    feed_type = str(feed.get("type") or "stix_url")
    if feed_type == "stix_url":
        source = str(feed["url"])
        return [IocRecord(ioc=item.ioc, kind=item.kind, source=source, first_seen=now()) for item in load_stix_indicators_from_url(source)]
    if feed_type == "taxii":
        source = str(feed["api_root_url"])
        return [
            IocRecord(ioc=item.ioc, kind=item.kind, source=source, first_seen=now())
            for item in load_taxii_indicators(
                source,
                collection_id=feed.get("collection_id"),
                added_after=feed.get("added_after"),
                token=feed.get("token"),
                username=feed.get("username"),
                password=feed.get("password"),
                limit=int(feed.get("limit") or 2000),
            )
        ]
    if feed_type == "otx":
        return _load_otx_records(feed)
    if feed_type == "raw_url":
        source = str(feed["url"])
        raw = http_get(source, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60).decode("utf-8", errors="ignore")
        return [IocRecord(ioc=item.ioc, kind=item.kind, source=source, first_seen=now()) for item in detect_iocs(raw, location=source)]
    raise ValueError(f"Unsupported feed type: {feed_type}")


def _load_otx_records(feed: dict[str, Any]) -> list[IocRecord]:
    api_key = str(feed.get("api_key") or load_secrets().OTX_API_KEY or "").strip()
    if not api_key:
        raise ValueError("OTX feed requires api_key or OTX_API_KEY")
    url = str(feed.get("url") or "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50")
    payload = http_get_json(url, headers={"X-OTX-API-KEY": api_key}, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60)
    results = payload.get("results") if isinstance(payload, dict) else None
    out: list[IocRecord] = []
    for pulse in results or []:
        indicators = pulse.get("indicators") if isinstance(pulse, dict) else None
        if not isinstance(indicators, list):
            continue
        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue
            value = str(indicator.get("indicator") or "").strip()
            kind = str(indicator.get("type") or "unknown").strip().lower()
            if value:
                out.append(IocRecord(ioc=value, kind=kind, source=url, first_seen=now()))
    return out


def now() -> float:
    return time.time()