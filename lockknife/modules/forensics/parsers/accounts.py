from __future__ import annotations

import json
import pathlib
import sqlite3
from typing import Any

from defusedxml.ElementTree import fromstring

from lockknife.core.logging import get_logger

log = get_logger()


def _looks_like_sqlite(path: pathlib.Path) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(16)
            return header == b"SQLite format 3\x00"
    except Exception:
        return False


def _sqlite_records(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return []

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Check if table accounts exists
        table_check = cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'"
        ).fetchone()
        if not table_check:
            return []

        # Query all accounts
        acc_cursor = cur.execute("SELECT * FROM accounts")
        accounts_data = [dict(r) for r in acc_cursor.fetchall()]

        # Query authtokens if table exists
        auth_tokens_map: dict[Any, dict[str, str]] = {}
        has_authtokens = cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='authtokens'"
        ).fetchone()
        if has_authtokens:
            token_rows = cur.execute("SELECT accounts_id, type, authtoken FROM authtokens").fetchall()
            for r in token_rows:
                aid = r["accounts_id"]
                if aid not in auth_tokens_map:
                    auth_tokens_map[aid] = {}
                auth_tokens_map[aid][r["type"]] = r["authtoken"]

        # Query extras if table exists
        extras_map: dict[Any, dict[str, str]] = {}
        has_extras = cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='extras'"
        ).fetchone()
        if has_extras:
            extra_rows = cur.execute("SELECT accounts_id, key, value FROM extras").fetchall()
            for r in extra_rows:
                aid = r["accounts_id"]
                if aid not in extras_map:
                    extras_map[aid] = {}
                extras_map[aid][r["key"]] = r["value"]

        for acc in accounts_data:
            aid = acc.get("_id")
            rec = {
                "account_id": aid,
                "name": acc.get("name"),
                "type": acc.get("type"),
                "password": acc.get("password"),
                "previous_name": acc.get("previous_name"),
                "last_password_entry_epoch": acc.get("last_password_entry_time_millis_epoch"),
                "auth_tokens": auth_tokens_map.get(aid, {}),
                "extras": extras_map.get(aid, {}),
            }
            rows.append(rec)

        return rows
    except Exception as e:
        log.warning("sqlite_accounts_parse_failed", exc_info=True, path=str(path), error=str(e))
        return []
    finally:
        conn.close()


def parse_accounts_artifacts(path: pathlib.Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        return _json_records(json.loads(path.read_text(encoding="utf-8")))
    if path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} or _looks_like_sqlite(path):
        return _sqlite_records(path)
    return _xml_records(path.read_text(encoding="utf-8", errors="ignore"))


def _json_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        rows: list[dict[str, Any]] = []
        for section in ("accounts", "users", "items"):
            for item in payload.get(section) or []:
                if isinstance(item, dict):
                    rows.append({"_section": section, **item})
        return rows or [payload]
    return []


def _xml_records(text: str) -> list[dict[str, Any]]:
    root = fromstring(text)
    rows: list[dict[str, Any]] = []
    for node in root.findall(".//account") + root.findall(".//item"):
        row = dict(node.attrib)
        if node.text and node.text.strip() and "name" not in row:
            row["name"] = node.text.strip()
        rows.append(row)
    return rows
