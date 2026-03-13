from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import pathlib
import random
import ssl
import time
import threading
from typing import Any
from urllib.parse import urlparse

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger


class HttpError(LockKnifeError):
    pass


log = get_logger()
_rate_lock = threading.Lock()
_rate_last_call: dict[str, float] = {}


def _parse_https(url: str) -> tuple[str, str]:
    u = urlparse(url)
    if u.scheme != "https":
        raise HttpError("Only https:// URLs are supported")
    host = u.hostname
    if not host:
        raise HttpError("Invalid URL host")
    path = u.path or "/"
    if u.query:
        path = path + "?" + u.query
    return host, path


def _cache_root() -> pathlib.Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        root = pathlib.Path(base).expanduser()
    else:
        root = pathlib.Path.home() / ".cache"
    p = root / "lockknife" / "http"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_key(url: str, headers: dict[str, str] | None) -> str:
    hdrs = headers or {}
    norm = url + "\n" + "\n".join(f"{k.lower()}:{v}" for k, v in sorted(hdrs.items(), key=lambda kv: kv[0].lower()))
    return hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()


def _cache_key_path() -> pathlib.Path:
    path = _cache_root() / "cache.key"
    if path.exists():
        return path
    key = os.urandom(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return path


def _cache_key_bytes() -> bytes:
    return _cache_key_path().read_bytes()


def _encrypt_cache(url: str, data: bytes) -> bytes:
    try:
        from lockknife.core.security import encrypt_bytes_aes256gcm
    except Exception as e:
        raise HttpError("Cache encryption unavailable") from e
    key = _cache_key_bytes()
    return encrypt_bytes_aes256gcm(key, data, associated_data=url.encode("utf-8"))


def _decrypt_cache(url: str, data: bytes) -> bytes:
    try:
        from lockknife.core.security import decrypt_bytes_aes256gcm
    except Exception as e:
        raise HttpError("Cache decryption unavailable") from e
    key = _cache_key_bytes()
    return decrypt_bytes_aes256gcm(key, data, associated_data=url.encode("utf-8"))


def _cache_get(url: str, headers: dict[str, str] | None, *, ttl_s: float) -> bytes | None:
    if ttl_s <= 0:
        return None
    key = _cache_key(url, headers)
    path = _cache_root() / f"{key}.json"
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    exp = obj.get("expires_at")
    data_b64 = obj.get("data_b64")
    enc = obj.get("encrypted", False)
    if not isinstance(exp, (int, float)) or not isinstance(data_b64, str):
        return None
    if time.time() > float(exp):
        return None
    try:
        raw = base64.b64decode(data_b64.encode("ascii"), validate=False)
        if enc:
            return _decrypt_cache(url, raw)
        return raw
    except Exception:
        return None


def _cache_put(url: str, headers: dict[str, str] | None, data: bytes, *, ttl_s: float, encrypt: bool = True) -> None:
    if ttl_s <= 0:
        return
    key = _cache_key(url, headers)
    path = _cache_root() / f"{key}.json"
    payload = data
    encrypted = False
    if encrypt:
        try:
            payload = _encrypt_cache(url, data)
            encrypted = True
        except Exception:
            log.warning("http_cache_encrypt_failed", exc_info=True, url=url)
            return
    obj = {
        "url": url,
        "expires_at": time.time() + float(ttl_s),
        "data_b64": base64.b64encode(payload).decode("ascii"),
        "encrypted": encrypted,
    }
    try:
        path.write_text(json.dumps(obj), encoding="utf-8")
    except Exception:
        log.warning("http_cache_write_failed", exc_info=True, url=url)


def _parse_retry_after(v: str | None) -> float | None:
    if not v:
        return None
    s = v.strip()
    if not s:
        return None
    try:
        return float(int(s))
    except Exception:
        return None


def _sleep_backoff(attempt: int, *, base_s: float = 0.5, max_s: float = 10.0, retry_after_s: float | None = None) -> None:
    if retry_after_s is not None and retry_after_s > 0:
        time.sleep(min(float(retry_after_s), max_s))
        return
    exp = base_s * (2 ** max(0, attempt - 1))
    jitter = random.random() * 0.1  # nosec B311
    time.sleep(min(exp + jitter, max_s))


def _rate_limit(host: str, rate_limit_per_s: float) -> None:
    if rate_limit_per_s <= 0:
        return
    min_interval = 1.0 / rate_limit_per_s
    with _rate_lock:
        last = _rate_last_call.get(host)
        now = time.monotonic()
        if last is None:
            _rate_last_call[host] = now
            return
        wait = min_interval - (now - last)
        if wait > 0:
            time.sleep(wait)
        _rate_last_call[host] = time.monotonic()


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_s: float = 20.0,
    max_attempts: int = 3,
    cache_ttl_s: float = 0.0,
    rate_limit_per_s: float = 0.0,
    cache_sensitive: bool = False,
) -> bytes:
    """Perform an HTTPS GET with retry/backoff and optional caching.

    Args:
        url: HTTPS URL.
        headers: Optional HTTP headers.
        timeout_s: Per-attempt timeout.
        max_attempts: Max attempts including the first.
        cache_ttl_s: If >0, enables filesystem caching for this duration.

    Returns:
        Raw response bytes.

    Raises:
        HttpError: On invalid URLs, HTTP 4xx, or exhausted retries.
    """
    if cache_sensitive:
        cache_ttl_s = 0.0
    cached = _cache_get(url, headers, ttl_s=cache_ttl_s)
    if cached is not None:
        return cached

    host, path = _parse_https(url)
    ctx = ssl.create_default_context()
    attempt = 0
    while True:
        attempt += 1
        _rate_limit(host, rate_limit_per_s)
        conn = http.client.HTTPSConnection(host, timeout=timeout_s, context=ctx)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            if resp.status == 429 or resp.status >= 500:
                if attempt < max_attempts:
                    ra = _parse_retry_after(resp.getheader("Retry-After"))
                    log.warning("http_retry", url=url, status=resp.status, attempt=attempt, max_attempts=max_attempts)
                    _sleep_backoff(attempt, retry_after_s=ra)
                    continue
            if resp.status >= 400:
                snippet = data[:400].decode("utf-8", errors="ignore")
                raise HttpError(f"HTTP {resp.status} {host}{path} {snippet}".strip())
            _cache_put(url, headers, data, ttl_s=cache_ttl_s, encrypt=True)
            return data
        except HttpError:
            raise
        except Exception as e:
            if attempt >= max_attempts:
                raise HttpError(f"HTTP GET failed: {host}{path}") from e
            log.warning("http_retry_exception", exc_info=True, url=url, attempt=attempt, max_attempts=max_attempts)
            _sleep_backoff(attempt)
        finally:
            conn.close()


def http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_s: float = 20.0,
    max_attempts: int = 3,
    cache_ttl_s: float = 0.0,
    rate_limit_per_s: float = 0.0,
    cache_sensitive: bool = False,
) -> Any:
    """Perform an HTTPS GET and decode JSON.

    Returns:
        Decoded JSON value (dict/list/str/number/bool/null).
    """
    raw = http_get(
        url,
        headers=headers,
        timeout_s=timeout_s,
        max_attempts=max_attempts,
        cache_ttl_s=cache_ttl_s,
        rate_limit_per_s=rate_limit_per_s,
        cache_sensitive=cache_sensitive,
    )
    return json.loads(raw.decode("utf-8", errors="ignore") or "null")


def http_post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout_s: float = 20.0,
    max_attempts: int = 3,
    cache_ttl_s: float = 0.0,
    rate_limit_per_s: float = 0.0,
    cache_sensitive: bool = False,
) -> Any:
    """Perform an HTTPS POST with a JSON body, optional caching, and retries.

    The cache key includes a hash of the request payload when caching is enabled.
    """
    if cache_sensitive:
        cache_ttl_s = 0.0
    if cache_ttl_s > 0:
        key_headers = dict(headers or {})
        key_headers["__lockknife_payload_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8", errors="ignore")
        ).hexdigest()
        cached = _cache_get(url, key_headers, ttl_s=cache_ttl_s)
        if cached is not None:
            return json.loads(cached.decode("utf-8", errors="ignore") or "null")

    host, path = _parse_https(url)
    ctx = ssl.create_default_context()
    body = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    attempt = 0
    while True:
        attempt += 1
        _rate_limit(host, rate_limit_per_s)
        conn = http.client.HTTPSConnection(host, timeout=timeout_s, context=ctx)
        try:
            conn.request("POST", path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status == 429 or resp.status >= 500:
                if attempt < max_attempts:
                    ra = _parse_retry_after(resp.getheader("Retry-After"))
                    log.warning("http_retry", url=url, status=resp.status, attempt=attempt, max_attempts=max_attempts)
                    _sleep_backoff(attempt, retry_after_s=ra)
                    continue
            if resp.status >= 400:
                snippet = data[:400].decode("utf-8", errors="ignore")
                raise HttpError(f"HTTP {resp.status} {host}{path} {snippet}".strip())
            if cache_ttl_s > 0:
                _cache_put(url, key_headers, data, ttl_s=cache_ttl_s, encrypt=True)
            return json.loads(data.decode("utf-8", errors="ignore") or "null")
        except HttpError:
            raise
        except Exception as e:
            if attempt >= max_attempts:
                raise HttpError(f"HTTP POST failed: {host}{path}") from e
            log.warning("http_retry_exception", exc_info=True, url=url, attempt=attempt, max_attempts=max_attempts)
            _sleep_backoff(attempt)
        finally:
            conn.close()
