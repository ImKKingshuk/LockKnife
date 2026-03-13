from __future__ import annotations

import base64
import dataclasses
import pathlib
import sqlite3
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError, LockKnifeError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir


@dataclasses.dataclass(frozen=True)
class WhatsAppMessage:
    jid: str | None
    text: str | None
    timestamp_ms: int | None


@dataclasses.dataclass(frozen=True)
class TelegramMessage:
    uid: int | None
    mid: int | None
    date_s: int | None
    outgoing: int | None
    data_b64: str | None = None


@dataclasses.dataclass(frozen=True)
class SignalMessage:
    thread_id: int | None
    date_ms: int | None
    body: str | None


@dataclasses.dataclass(frozen=True)
class MessagingArtifacts:
    app: str
    db_paths: list[str]
    encrypted: bool
    note: str | None = None


log = get_logger()

_DEVICE_IO_ERRORS: tuple[type[BaseException], ...] = (LockKnifeError, OSError, RuntimeError, ValueError)


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _try_root_pull_file(devices: DeviceManager, serial: str, remote: str, local: pathlib.Path, *, timeout_s: float) -> bool:
    try:
        devices.pull(serial, remote, local, timeout_s=timeout_s)
        return local.exists() and local.stat().st_size > 0
    except _DEVICE_IO_ERRORS:
        log.warning("messaging_pull_failed", exc_info=True, serial=serial, remote=remote)

    tmp_remote = f"/sdcard/lockknife-tmp-{local.name}"
    try:
        devices.shell(
            serial,
            f'su -c "cp {_sh_quote(remote)} {_sh_quote(tmp_remote)} 2>/dev/null || cat {_sh_quote(remote)} > {_sh_quote(tmp_remote)} 2>/dev/null"',
            timeout_s=timeout_s,
        )
        devices.pull(serial, tmp_remote, local, timeout_s=timeout_s)
    except _DEVICE_IO_ERRORS:
        log.warning("messaging_root_pull_failed", exc_info=True, serial=serial, remote=remote)
        return False
    finally:
        try:
            devices.shell(serial, f'su -c "rm -f {_sh_quote(tmp_remote)} 2>/dev/null"', timeout_s=10.0)
        except _DEVICE_IO_ERRORS:
            log.warning("messaging_root_pull_cleanup_failed", exc_info=True, serial=serial, remote=tmp_remote)
    return local.exists() and local.stat().st_size > 0


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    cur = con.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def _parse_whatsapp_msgstore(db_path: pathlib.Path, limit: int) -> list[WhatsAppMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
        if cur.fetchone() is None:
            raise sqlite3.Error("messages table not found")
        cur.execute(
            """
SELECT key_remote_jid, data, timestamp
FROM messages
ORDER BY timestamp DESC
LIMIT ?
""".strip(),
            (limit,),
        )
        out: list[WhatsAppMessage] = []
        for jid, text, ts in cur.fetchall():
            out.append(
                WhatsAppMessage(
                    jid=jid,
                    text=text,
                    timestamp_ms=int(ts) if ts is not None else None,
                )
            )
        return out
    finally:
        con.close()


def _parse_telegram_cache(db_path: pathlib.Path, limit: int) -> list[TelegramMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages_v2'")
        table = "messages_v2" if cur.fetchone() is not None else "messages"
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if cur.fetchone() is None:
            return []
        q_list: list[str]
        if table == "messages_v2":
            q_list = [
                "SELECT uid, mid, date, out, data FROM messages_v2 ORDER BY date DESC LIMIT ?",
                "SELECT uid, mid, date, out, NULL as data FROM messages_v2 ORDER BY date DESC LIMIT ?",
                "SELECT uid, mid, date, NULL as out, NULL as data FROM messages_v2 ORDER BY date DESC LIMIT ?",
            ]
        else:
            q_list = [
                "SELECT uid, mid, date, out, data FROM messages ORDER BY date DESC LIMIT ?",
                "SELECT uid, mid, date, out, NULL as data FROM messages ORDER BY date DESC LIMIT ?",
                "SELECT uid, mid, date, NULL as out, NULL as data FROM messages ORDER BY date DESC LIMIT ?",
            ]
        rows = None
        for q in q_list:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[TelegramMessage] = []
        for uid, mid, date_s, out_flag, data in rows:
            blob_b64 = None
            if isinstance(data, (bytes, bytearray)) and data:
                blob_b64 = base64.b64encode(bytes(data)).decode("ascii")
            out.append(
                TelegramMessage(
                    uid=int(uid) if uid is not None else None,
                    mid=int(mid) if mid is not None else None,
                    date_s=int(date_s) if date_s is not None else None,
                    outgoing=int(out_flag) if out_flag is not None else None,
                    data_b64=blob_b64,
                )
            )
        return out
    finally:
        con.close()


def _parse_signal_db(db_path: pathlib.Path, limit: int) -> list[SignalMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms'")
        if cur.fetchone() is None:
            return []
        rows = None
        for q in [
            "SELECT thread_id, date, body FROM sms ORDER BY date DESC LIMIT ?",
            "SELECT NULL as thread_id, date, body FROM sms ORDER BY date DESC LIMIT ?",
            "SELECT NULL as thread_id, date, NULL as body FROM sms ORDER BY date DESC LIMIT ?",
        ]:
            try:
                cur.execute(q, (limit,))
                rows = cur.fetchall()
                break
            except sqlite3.Error:
                rows = None
        if rows is None:
            return []
        out: list[SignalMessage] = []
        for thread_id, date_ms, body in rows:
            out.append(
                SignalMessage(
                    thread_id=int(thread_id) if thread_id is not None else None,
                    date_ms=int(date_ms) if date_ms is not None else None,
                    body=body,
                )
            )
        return out
    finally:
        con.close()


def extract_whatsapp_messages(devices: DeviceManager, serial: str, limit: int = 500) -> list[WhatsAppMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access WhatsApp databases")

    candidates = [
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/data/data/com.whatsapp/databases/msgstore.db-wal",
        "/data/user_de/0/com.whatsapp/databases/msgstore.db",
    ]
    with secure_temp_dir(prefix="lockknife-whatsapp-") as d:
        for remote in candidates:
            if not remote.endswith(".db"):
                continue
            local = d / "msgstore.db"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=180.0):
                continue
            try:
                return _parse_whatsapp_msgstore(local, limit)
            except sqlite3.Error:
                log.debug("whatsapp_db_parse_failed", exc_info=True, serial=serial, local_path=str(local))
                continue

    raise DeviceError("Unable to extract WhatsApp msgstore.db")


def extract_whatsapp_artifacts(devices: DeviceManager, serial: str) -> MessagingArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access WhatsApp artifacts")
    candidates = [
        "/sdcard/WhatsApp/Databases",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/data/data/com.whatsapp/files/key",
        "/data/user_de/0/com.whatsapp/files/key",
    ]
    db_paths: list[str] = []
    encrypted = False
    note = None
    for c in candidates:
        try:
            out = devices.shell(serial, f'su -c "ls -1 {c} 2>/dev/null"', timeout_s=20.0)
        except _DEVICE_IO_ERRORS:
            log.debug("whatsapp_ls_failed", exc_info=True, serial=serial, path=c)
            continue
        for ln in [x.strip() for x in out.splitlines() if x.strip()]:
            if ln.endswith(".crypt14") or ln.endswith(".crypt15") or ln.endswith(".crypt12"):
                encrypted = True
            if ln.endswith(".db") or ".crypt" in ln or ln == "key":
                db_paths.append(f"{c}/{ln}" if not c.endswith("key") else c)
    if encrypted:
        note = "Encrypted msgstore variants detected; exported paths include key (if accessible)."
    return MessagingArtifacts(app="whatsapp", db_paths=sorted(set(db_paths)), encrypted=encrypted, note=note)


def extract_telegram_messages(devices: DeviceManager, serial: str, limit: int = 500) -> list[TelegramMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Telegram databases")

    candidates = [
        "/data/data/org.telegram.messenger/files/cache4.db",
        "/data/data/org.telegram.messenger/databases/cache4.db",
        "/data/user_de/0/org.telegram.messenger/files/cache4.db",
        "/data/user_de/0/org.telegram.messenger/databases/cache4.db",
        "/data/data/org.telegram.messenger.web/files/cache4.db",
        "/data/data/org.thunderdog.challegram/files/cache4.db",
    ]
    with secure_temp_dir(prefix="lockknife-telegram-") as d:
        for remote in candidates:
            local = d / "cache4.db"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=180.0):
                continue
            try:
                items = _parse_telegram_cache(local, limit)
                if items:
                    return items
            except sqlite3.Error:
                continue
    raise DeviceError("Unable to extract Telegram cache4.db")


def extract_telegram_artifacts(devices: DeviceManager, serial: str) -> MessagingArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Telegram artifacts")
    dirs = [
        "/data/data/org.telegram.messenger/files",
        "/data/user_de/0/org.telegram.messenger/files",
        "/data/data/org.telegram.messenger/databases",
        "/data/user_de/0/org.telegram.messenger/databases",
    ]
    paths: list[str] = []
    for d in dirs:
        try:
            out = devices.shell(serial, f'su -c "ls -1 {d} 2>/dev/null"', timeout_s=20.0)
        except _DEVICE_IO_ERRORS:
            log.debug("telegram_ls_failed", exc_info=True, serial=serial, path=d)
            continue
        for ln in [x.strip() for x in out.splitlines() if x.strip()]:
            if ln.startswith("cache") and ln.endswith(".db"):
                paths.append(f"{d}/{ln}")
    return MessagingArtifacts(app="telegram", db_paths=sorted(set(paths)), encrypted=False, note=None)


def extract_signal_messages(devices: DeviceManager, serial: str, limit: int = 500) -> list[SignalMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Signal databases")

    candidates = [
        "/data/data/org.thoughtcrime.securesms/databases/signal.db",
        "/data/user_de/0/org.thoughtcrime.securesms/databases/signal.db",
    ]
    with secure_temp_dir(prefix="lockknife-signal-") as d:
        for remote in candidates:
            local = d / "signal.db"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=180.0):
                continue
            try:
                items = _parse_signal_db(local, limit)
                if items:
                    return items
            except sqlite3.DatabaseError as e:
                raise DeviceError("Signal database appears encrypted or unreadable") from e
            except sqlite3.Error:
                continue
    raise DeviceError("Unable to extract Signal signal.db")


def extract_signal_artifacts(devices: DeviceManager, serial: str) -> MessagingArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Signal artifacts")
    candidates = [
        "/data/data/org.thoughtcrime.securesms/databases",
        "/data/user_de/0/org.thoughtcrime.securesms/databases",
        "/data/data/org.thoughtcrime.securesms/shared_prefs",
        "/data/user_de/0/org.thoughtcrime.securesms/shared_prefs",
    ]
    paths: list[str] = []
    encrypted = False
    for c in candidates:
        try:
            out = devices.shell(serial, f'su -c "ls -1 {c} 2>/dev/null"', timeout_s=20.0)
        except _DEVICE_IO_ERRORS:
            log.debug("signal_ls_failed", exc_info=True, serial=serial, path=c)
            continue
        for ln in [x.strip() for x in out.splitlines() if x.strip()]:
            if ln.endswith(".db"):
                paths.append(f"{c}/{ln}")
            if ln.endswith(".xml"):
                paths.append(f"{c}/{ln}")
    note = None
    for p in paths:
        if p.endswith("signal.db"):
            encrypted = True
            note = "Signal database may be SQLCipher-encrypted; extracted paths include shared_prefs for key material."
    return MessagingArtifacts(app="signal", db_paths=sorted(set(paths)), encrypted=encrypted, note=note)
