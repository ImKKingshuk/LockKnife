import json

import pytest


def test_http_get_retries_and_caches(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    calls: list[str] = []

    class _Resp:
        def __init__(self, status: int, data: bytes, headers: dict[str, str] | None = None) -> None:
            self.status = status
            self._data = data
            self._headers = {k.lower(): v for k, v in (headers or {}).items()}

        def read(self) -> bytes:
            return self._data

        def getheader(self, name: str):
            return self._headers.get(name.lower())

    class _Conn:
        def __init__(self, host, timeout, context) -> None:
            self._host = host

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            calls.append(f"{method} {path}")

        def getresponse(self):
            if len(calls) == 1:
                return _Resp(500, b"nope")
            return _Resp(200, b"ok")

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)

    out = http_mod.http_get("https://example.com/x", max_attempts=2, cache_ttl_s=60.0)
    assert out == b"ok"
    assert len(calls) == 2

    calls.clear()
    out2 = http_mod.http_get("https://example.com/x", max_attempts=2, cache_ttl_s=60.0)
    assert out2 == b"ok"
    assert calls == []


def test_http_post_json_caches(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    created = 0

    class _Resp:
        def __init__(self, status: int, data: bytes) -> None:
            self.status = status
            self._data = data

        def read(self) -> bytes:
            return self._data

        def getheader(self, _name: str):
            return None

    class _Conn:
        def __init__(self, host, timeout, context) -> None:
            nonlocal created
            created += 1

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            return None

        def getresponse(self):
            return _Resp(200, json.dumps({"ok": True}).encode("utf-8"))

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)

    r1 = http_mod.http_post_json("https://api.example.com/v1", {"q": "x"}, cache_ttl_s=60.0)
    r2 = http_mod.http_post_json("https://api.example.com/v1", {"q": "x"}, cache_ttl_s=60.0)
    assert r1 == {"ok": True}
    assert r2 == {"ok": True}
    assert created == 1


def test_http_get_retries_on_exception_and_retry_after(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    class _Resp:
        def __init__(
            self, status: int, headers: dict[str, str] | None = None, data: bytes = b""
        ) -> None:
            self.status = status
            self._headers = {k.lower(): v for k, v in (headers or {}).items()}
            self._data = data

        def read(self) -> bytes:
            return self._data

        def getheader(self, name: str):
            return self._headers.get(name.lower())

    class _Conn:
        n = 0

        def __init__(self, host, timeout, context) -> None:
            return None

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            _Conn.n += 1
            if _Conn.n == 1:
                raise TimeoutError("t")

        def getresponse(self):
            if _Conn.n == 2:
                return _Resp(429, headers={"Retry-After": "1"}, data=b"rate")
            return _Resp(200, data=b"ok")

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)
    assert http_mod.http_get("https://example.com/a", max_attempts=5) == b"ok"


def test_http_get_raises_on_4xx(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    class _Resp:
        status = 404

        def read(self) -> bytes:
            return b"no"

        def getheader(self, _name: str):
            return None

    class _Conn:
        def __init__(self, host, timeout, context) -> None:
            return None

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            return None

        def getresponse(self):
            return _Resp()

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)
    with pytest.raises(http_mod.HttpError):
        http_mod.http_get("https://example.com/missing", max_attempts=1)


def test_http_post_json_retries_on_500(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    class _Resp:
        def __init__(self, status: int, data: bytes) -> None:
            self.status = status
            self._data = data

        def read(self) -> bytes:
            return self._data

        def getheader(self, _name: str):
            return None

    class _Conn:
        n = 0

        def __init__(self, host, timeout, context) -> None:
            return None

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            return None

        def getresponse(self):
            _Conn.n += 1
            if _Conn.n == 1:
                return _Resp(500, b"no")
            return _Resp(200, b'{"ok":true}')

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)
    out = http_mod.http_post_json("https://example.com/p", {"x": 1}, max_attempts=3)
    assert out["ok"] is True
