from __future__ import annotations



import json

import pathlib

import sqlite3



from lockknife.modules.extraction._browser_models import BrowserBookmarkEntry, BrowserHistoryEntry, BrowserLoginEntry



def _parse_firefox_places_history(db_path: pathlib.Path, limit: int) -> list[BrowserHistoryEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_places'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT url, title, last_visit_date, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
            "SELECT url, title, last_visit_date, NULL as visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
            "SELECT url, NULL as title, last_visit_date, NULL as visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[BrowserHistoryEntry] = []
        for url, title, lvt, vc in rows:
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

def _parse_firefox_places_bookmarks(db_path: pathlib.Path, limit: int) -> list[BrowserBookmarkEntry]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_bookmarks'")
        if cur.fetchone() is None:
            return []
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_places'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT p.url, b.title, b.dateAdded FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE p.url IS NOT NULL ORDER BY b.dateAdded DESC LIMIT ?",
            "SELECT p.url, b.title, NULL as dateAdded FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE p.url IS NOT NULL ORDER BY b.rowid DESC LIMIT ?",
            "SELECT p.url, NULL as title, NULL as dateAdded FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE p.url IS NOT NULL ORDER BY b.rowid DESC LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[BrowserBookmarkEntry] = []
        for url, title, added in rows:
            out.append(
                BrowserBookmarkEntry(
                    url=str(url),
                    title=title,
                    folder=None,
                    date_added_raw=int(added) if added is not None else None,
                )
            )
        return out
    finally:
        con.close()

def _parse_firefox_logins(path: pathlib.Path, limit: int) -> list[BrowserLoginEntry]:
    raw = json.loads(path.read_text(encoding="utf-8", errors="ignore") or "{}")
    items = raw.get("logins") or []
    out: list[BrowserLoginEntry] = []
    for it in items[:limit] if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        out.append(
            BrowserLoginEntry(
                origin_url=it.get("hostname") or it.get("formSubmitURL"),
                username=it.get("username") or it.get("encryptedUsername"),
                password_value=None,
                password_encrypted_b64=it.get("encryptedPassword"),
            )
        )
    return out
