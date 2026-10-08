from __future__ import annotations

import base64
import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError, LockKnifeError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.extraction._extraction_common import try_root_staging_pull


@dataclasses.dataclass(frozen=True)
class WhatsAppMessage:
    jid: str | None
    text: str | None
    timestamp_ms: int | None
    from_me: int | None = None
    sender_name: str | None = None


@dataclasses.dataclass(frozen=True)
class TelegramMessage:
    uid: int | None
    mid: int | None
    date_s: int | None
    outgoing: int | None
    data_b64: str | None = None
    chat_title: str | None = None
    user_name: str | None = None
    message_text: str | None = None


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
    encryption_key: str | None = None


log = get_logger()

_DEVICE_IO_ERRORS: tuple[type[BaseException], ...] = (
    LockKnifeError,
    OSError,
    RuntimeError,
    ValueError,
)


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _try_root_pull_file(
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 60.0,
) -> bool:
    return try_root_staging_pull(devices, serial, remote, local, timeout_s=timeout_s)


def _pull_sqlite_with_wal(
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 180.0,
) -> bool:
    if not _try_root_pull_file(devices, serial, remote, local, timeout_s=timeout_s):
        return False
    # Attempt to pull sibling -wal and -shm files if present on remote
    for ext in ("-wal", "-shm"):
        remote_ext = f"{remote}{ext}"
        local_ext = local.with_name(local.name + ext)
        try:
            _try_root_pull_file(devices, serial, remote_ext, local_ext, timeout_s=30.0)
        except Exception:
            pass
    return True


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    cur = con.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def _parse_whatsapp_msgstore(db_path: pathlib.Path, limit: int) -> list[WhatsAppMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
        tables = {row[0].lower() for row in cur.fetchall()}

        # 1. Try modern WhatsApp 'message' table with joins (v2.19+)
        if "message" in tables:
            queries = [
                # Join with chat and jid tables
                """
SELECT COALESCE(j.raw_string, c.subject, c.jid_row_id, m.chat_row_id),
       m.text_data,
       m.timestamp,
       m.from_me,
       c.subject
FROM message m
LEFT JOIN chat c ON c._id = m.chat_row_id
LEFT JOIN jid j ON j._id = c.jid_row_id
WHERE m.text_data IS NOT NULL AND length(m.text_data) > 0
ORDER BY m.timestamp DESC
LIMIT ?
""".strip(),
                # Direct message table query
                """
SELECT m.chat_row_id,
       m.text_data,
       m.timestamp,
       m.from_me,
       NULL
FROM message m
WHERE m.text_data IS NOT NULL AND length(m.text_data) > 0
ORDER BY m.timestamp DESC
LIMIT ?
""".strip(),
            ]
            for q in queries:
                try:
                    cur.execute(q, (limit,))
                    rows = cur.fetchall()
                    if rows:
                        out: list[WhatsAppMessage] = []
                        for jid_val, text_val, ts_val, from_me, subject in rows:
                            out.append(
                                WhatsAppMessage(
                                    jid=str(jid_val) if jid_val is not None else None,
                                    text=text_val,
                                    timestamp_ms=int(ts_val) if ts_val is not None else None,
                                    from_me=int(from_me) if from_me is not None else None,
                                    sender_name=str(subject) if subject is not None else None,
                                )
                            )
                        return out
                except sqlite3.Error:
                    continue

        # 2. Try 'message_view' view
        if "message_view" in tables:
            view_queries = [
                "SELECT jid, text_data, timestamp, from_me FROM message_view WHERE text_data IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
                "SELECT chat_row_id, text_data, timestamp, from_me FROM message_view WHERE text_data IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
                "SELECT NULL, text_data, timestamp, NULL FROM message_view WHERE text_data IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
            ]
            for vq in view_queries:
                try:
                    cur.execute(vq, (limit,))
                    rows = cur.fetchall()
                    if rows:
                        return [
                            WhatsAppMessage(
                                jid=str(jid_val) if jid_val is not None else None,
                                text=text_val,
                                timestamp_ms=int(ts_val) if ts_val is not None else None,
                                from_me=int(from_me) if from_me is not None else None,
                            )
                            for jid_val, text_val, ts_val, from_me in rows
                        ]
                except sqlite3.Error:
                    continue

        # 3. Fallback to legacy 'messages' table (legacy WhatsApp)
        if "messages" in tables:
            cur.execute(
                """
SELECT key_remote_jid, data, timestamp
FROM messages
WHERE data IS NOT NULL
ORDER BY timestamp DESC
LIMIT ?
""".strip(),
                (limit,),
            )
            legacy_out: list[WhatsAppMessage] = []
            for jid_val, text_val, ts_val in cur.fetchall():
                legacy_out.append(
                    WhatsAppMessage(
                        jid=str(jid_val) if jid_val is not None else None,
                        text=text_val,
                        timestamp_ms=int(ts_val) if ts_val is not None else None,
                    )
                )
            return legacy_out

        raise sqlite3.Error(
            "Neither modern 'message' nor legacy 'messages' table found in msgstore.db"
        )
    finally:
        con.close()


def _parse_telegram_cache(db_path: pathlib.Path, limit: int) -> list[TelegramMessage]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
        tables = {row[0].lower() for row in cur.fetchall()}

        user_map: dict[int, str] = {}
        if "users" in tables:
            try:
                for uid, fn, ln, uname in con.execute(
                    "SELECT id, first_name, last_name, username FROM users"
                ).fetchall():
                    parts = [p for p in (fn, ln) if p]
                    name_str = " ".join(parts) if parts else (uname or str(uid))
                    user_map[int(uid)] = name_str
            except sqlite3.Error:
                pass

        chat_map: dict[int, str] = {}
        if "chats" in tables:
            try:
                for cid, title in con.execute("SELECT id, title FROM chats").fetchall():
                    if title:
                        chat_map[int(cid)] = title
            except sqlite3.Error:
                try:
                    for cid, name in con.execute("SELECT id, name FROM chats").fetchall():
                        if name:
                            chat_map[int(cid)] = name
                except sqlite3.Error:
                    pass

        table = "messages_v2" if "messages_v2" in tables else "messages"
        if table not in tables:
            return []

        q_list = [
            f"SELECT uid, mid, date, out, data FROM {table} ORDER BY date DESC LIMIT ?",  # nosec B608: fixed table allowlist.
            f"SELECT uid, mid, date, out, NULL as data FROM {table} ORDER BY date DESC LIMIT ?",  # nosec B608: fixed table allowlist.
            f"SELECT uid, mid, date, NULL as out, NULL as data FROM {table} ORDER BY date DESC LIMIT ?",  # nosec B608: fixed table allowlist.
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
            uid_int = int(uid) if uid is not None else None
            out.append(
                TelegramMessage(
                    uid=uid_int,
                    mid=int(mid) if mid is not None else None,
                    date_s=int(date_s) if date_s is not None else None,
                    outgoing=int(out_flag) if out_flag is not None else None,
                    data_b64=blob_b64,
                    user_name=user_map.get(uid_int) if uid_int is not None else None,
                    chat_title=chat_map.get(uid_int) if uid_int is not None else None,
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


def extract_whatsapp_messages(
    devices: DeviceManager, serial: str, limit: int = 500
) -> list[WhatsAppMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access WhatsApp databases")

    candidates = [
        # Standard WhatsApp
        "/data/user/0/com.whatsapp/databases/msgstore.db",
        "/data/user_de/0/com.whatsapp/databases/msgstore.db",
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/data/data/com.whatsapp/databases/msgstore.db-wal",
        # WhatsApp Business
        "/data/user/0/com.whatsapp.w4b/databases/msgstore.db",
        "/data/user_de/0/com.whatsapp.w4b/databases/msgstore.db",
        "/data/data/com.whatsapp.w4b/databases/msgstore.db",
        # Multi-user / Dual Messenger
        "/data/user/10/com.whatsapp/databases/msgstore.db",
        "/data/user/999/com.whatsapp/databases/msgstore.db",
    ]
    with secure_temp_dir(prefix="lockknife-whatsapp-") as d:
        for remote in candidates:
            if not remote.endswith(".db"):
                continue
            local = d / "msgstore.db"
            if not _pull_sqlite_with_wal(devices, serial, remote, local, timeout_s=180.0):
                continue
            try:
                rows = _parse_whatsapp_msgstore(local, limit)
                if rows:
                    return rows
            except sqlite3.Error:
                log.debug(
                    "whatsapp_db_parse_failed", exc_info=True, serial=serial, local_path=str(local)
                )
                continue

    raise DeviceError("Unable to extract WhatsApp msgstore.db")


def extract_whatsapp_artifacts(devices: DeviceManager, serial: str) -> MessagingArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access WhatsApp artifacts")
    candidates = [
        "/sdcard/WhatsApp/Databases",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
        "/data/user/0/com.whatsapp/files/key",
        "/data/user_de/0/com.whatsapp/files/key",
        "/data/data/com.whatsapp/files/key",
        "/data/user/0/com.whatsapp.w4b/files/key",
        "/data/user_de/0/com.whatsapp.w4b/files/key",
        "/data/data/com.whatsapp.w4b/files/key",
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
    return MessagingArtifacts(
        app="whatsapp", db_paths=sorted(set(db_paths)), encrypted=encrypted, note=note
    )


def extract_telegram_messages(
    devices: DeviceManager, serial: str, limit: int = 500
) -> list[TelegramMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Telegram databases")

    candidates = [
        "/data/user/0/org.telegram.messenger/files/cache4.db",
        "/data/user/0/org.telegram.messenger/databases/cache4.db",
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
            if not _pull_sqlite_with_wal(devices, serial, remote, local, timeout_s=180.0):
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
        "/data/user/0/org.telegram.messenger/files",
        "/data/user/0/org.telegram.messenger/databases",
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
    return MessagingArtifacts(
        app="telegram", db_paths=sorted(set(paths)), encrypted=False, note=None
    )


def _extract_signal_passphrase(
    devices: DeviceManager, serial: str, temp_dir: pathlib.Path
) -> str | None:
    pref_candidates = [
        "/data/user/0/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml",
        "/data/user_de/0/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml",
        "/data/data/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml",
    ]
    for remote in pref_candidates:
        local = temp_dir / "securesms_preferences.xml"
        if _try_root_pull_file(devices, serial, remote, local, timeout_s=30.0):
            try:
                content = local.read_text(encoding="utf-8", errors="ignore")
                import re

                m = re.search(
                    r'<string name="pref_database_passphrase">([a-fA-F0-9]{32,64})</string>',
                    content,
                )
                if m:
                    return m.group(1)
            except Exception:
                pass
    return None


def extract_signal_messages(
    devices: DeviceManager, serial: str, limit: int = 500
) -> list[SignalMessage]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Signal databases")

    candidates = [
        "/data/user/0/org.thoughtcrime.securesms/databases/signal.db",
        "/data/user_de/0/org.thoughtcrime.securesms/databases/signal.db",
        "/data/data/org.thoughtcrime.securesms/databases/signal.db",
    ]
    with secure_temp_dir(prefix="lockknife-signal-") as d:
        for remote in candidates:
            local = d / "signal.db"
            if not _pull_sqlite_with_wal(devices, serial, remote, local, timeout_s=180.0):
                continue
            try:
                items = _parse_signal_db(local, limit)
                if items:
                    return items
            except sqlite3.DatabaseError as e:
                passphrase = _extract_signal_passphrase(devices, serial, d)
                if passphrase:
                    raise DeviceError(
                        f"Signal database is SQLCipher encrypted. Passphrase recovered: {passphrase}"
                    ) from e
                raise DeviceError("Signal database appears encrypted or unreadable") from e
            except sqlite3.Error:
                continue
    raise DeviceError("Unable to extract Signal signal.db")


def extract_signal_artifacts(devices: DeviceManager, serial: str) -> MessagingArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Signal artifacts")
    candidates = [
        "/data/user/0/org.thoughtcrime.securesms/databases",
        "/data/user_de/0/org.thoughtcrime.securesms/databases",
        "/data/data/org.thoughtcrime.securesms/databases",
        "/data/user/0/org.thoughtcrime.securesms/shared_prefs",
        "/data/user_de/0/org.thoughtcrime.securesms/shared_prefs",
        "/data/data/org.thoughtcrime.securesms/shared_prefs",
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
            if ln == "signal.db" or ln.endswith("signal.db"):
                encrypted = True

    recovered_passphrase = None
    with secure_temp_dir(prefix="lockknife-signal-pass-") as d:
        recovered_passphrase = _extract_signal_passphrase(devices, serial, d)

    note = None
    if encrypted:
        if recovered_passphrase:
            note = f"Signal database is SQLCipher-encrypted. Passphrase successfully recovered: {recovered_passphrase}"
        else:
            note = "Signal database may be SQLCipher-encrypted; extracted paths include shared_prefs for key material."

    return MessagingArtifacts(
        app="signal",
        db_paths=sorted(set(paths)),
        encrypted=encrypted,
        note=note,
        encryption_key=recovered_passphrase,
    )
