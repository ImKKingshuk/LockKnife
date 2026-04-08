from __future__ import annotations

import base64
import json
import pathlib
import sqlite3
from typing import Any

from lockknife.modules.extraction._browser_models import (
    BrowserBookmarkEntry,
    BrowserCookieEntry,
    BrowserDownloadEntry,
    BrowserHistoryEntry,
    BrowserLoginEntry,
)


def _parse_chrome_history(db_path: pathlib.Path, limit: int) -> list[BrowserHistoryEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute(
            """
SELECT url, title, last_visit_time, visit_count
FROM urls
ORDER BY last_visit_time DESC
LIMIT ?
""".strip(),
            (limit,),
        )
        out: list[BrowserHistoryEntry] = []
        for url, title, lvt, vc in cur.fetchall():
            out.append(
                BrowserHistoryEntry(
                    url=str(url),
                    title=title,
                    last_visit_time_raw=int(lvt) if lvt is not None else None,
                    visit_count=int(vc) if vc is not None else None,
                )
            )
        return out
    finally:
        con.close()


def _parse_chrome_downloads(db_path: pathlib.Path, limit: int) -> list[BrowserDownloadEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT tab_url, target_path, start_time, end_time, received_bytes FROM downloads ORDER BY start_time DESC LIMIT ?",
            "SELECT NULL as tab_url, target_path, start_time, end_time, received_bytes FROM downloads ORDER BY start_time DESC LIMIT ?",
            "SELECT NULL as tab_url, target_path, start_time, end_time, NULL as received_bytes FROM downloads ORDER BY start_time DESC LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[BrowserDownloadEntry] = []
        for url, target, start, end, recv in rows:
            out.append(
                BrowserDownloadEntry(
                    url=str(url) if url is not None else None,
                    target_path=str(target) if target is not None else None,
                    start_time_raw=int(start) if start is not None else None,
                    end_time_raw=int(end) if end is not None else None,
                    received_bytes=int(recv) if recv is not None else None,
                )
            )
        return out
    finally:
        con.close()


def _parse_chrome_cookies(db_path: pathlib.Path, limit: int) -> list[BrowserCookieEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT host_key, name, value, encrypted_value, expires_utc, last_access_utc FROM cookies ORDER BY last_access_utc DESC LIMIT ?",
            "SELECT host_key, name, value, encrypted_value, expires_utc, NULL as last_access_utc FROM cookies LIMIT ?",
            "SELECT host_key, name, value, NULL as encrypted_value, expires_utc, NULL as last_access_utc FROM cookies LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[BrowserCookieEntry] = []
        for host, name, value, enc, exp, last in rows:
            enc_b64 = None
            if isinstance(enc, (bytes, bytearray)) and enc:
                enc_b64 = base64.b64encode(bytes(enc)).decode("ascii")
            out.append(
                BrowserCookieEntry(
                    host=str(host) if host is not None else None,
                    name=str(name) if name is not None else None,
                    value=str(value) if value is not None else None,
                    encrypted_value_b64=enc_b64,
                    expires_utc_raw=int(exp) if exp is not None else None,
                    last_access_utc_raw=int(last) if last is not None else None,
                )
            )
        return out
    finally:
        con.close()


def _parse_chrome_logins(db_path: pathlib.Path, limit: int) -> list[BrowserLoginEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logins'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT origin_url, username_value, password_value, password, encrypted_password FROM logins ORDER BY rowid DESC LIMIT ?",
            "SELECT origin_url, username_value, password_value, NULL as password, encrypted_password FROM logins ORDER BY rowid DESC LIMIT ?",
            "SELECT origin_url, username_value, NULL as password_value, NULL as password, encrypted_password FROM logins ORDER BY rowid DESC LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[BrowserLoginEntry] = []
        for origin, username, pw_value, pw, pw_enc in rows:
            password = None
            encrypted_b64 = None
            if pw_value is not None:
                password = str(pw_value)
            elif pw is not None and not isinstance(pw, (bytes, bytearray)):
                password = str(pw)
            blob = None
            if isinstance(pw, (bytes, bytearray)):
                blob = bytes(pw)
            if isinstance(pw_enc, (bytes, bytearray)):
                blob = bytes(pw_enc)
            if blob:
                encrypted_b64 = base64.b64encode(blob).decode("ascii")
            out.append(
                BrowserLoginEntry(
                    origin_url=str(origin) if origin is not None else None,
                    username=str(username) if username is not None else None,
                    password_value=password,
                    password_encrypted_b64=encrypted_b64,
                )
            )
        return out
    finally:
        con.close()


def _parse_chrome_bookmarks(bookmarks_path: pathlib.Path, limit: int) -> list[BrowserBookmarkEntry]:
    raw = json.loads(bookmarks_path.read_text(encoding="utf-8", errors="ignore") or "{}")
    roots = raw.get("roots") or {}
    out: list[BrowserBookmarkEntry] = []

    def walk(node: dict[str, Any], folder: str | None) -> None:
        if len(out) >= limit:
            return
        typ = node.get("type")
        if typ == "url" and node.get("url"):
            da = node.get("date_added")
            out.append(
                BrowserBookmarkEntry(
                    url=str(node.get("url")),
                    title=node.get("name"),
                    folder=folder,
                    date_added_raw=int(str(da)) if da is not None and str(da).isdigit() else None,
                )
            )
            return
        children = node.get("children") or []
        if isinstance(children, list):
            name = node.get("name")
            next_folder = folder
            if name:
                next_folder = f"{folder}/{name}" if folder else str(name)
            for c in children:
                if isinstance(c, dict):
                    walk(c, next_folder)

    for k, node in roots.items():
        if isinstance(node, dict):
            walk(node, str(k))
    return out[:limit]
