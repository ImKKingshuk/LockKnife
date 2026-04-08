import json
import pathlib

import pytest


def test_http_internal_helpers(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)

    k = http_mod._cache_key("https://x", {"A": "b"})
    assert isinstance(k, str) and len(k) == 64

    assert http_mod._parse_retry_after(None) is None
    assert http_mod._parse_retry_after(" 2 ") == 2.0

    http_mod._sleep_backoff(1, retry_after_s=0.01)

    bad = tmp_path / (k + ".json")
    bad.write_text("not-json", encoding="utf-8")
    assert http_mod._cache_get("https://x", {"A": "b"}, ttl_s=60) is None

    obj = {"expires_at": 0, "data_b64": "eA=="}
    bad.write_text(json.dumps(obj), encoding="utf-8")
    assert http_mod._cache_get("https://x", {"A": "b"}, ttl_s=60) is None


def test_http_parse_https_and_cache_root(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    host, path = http_mod._parse_https("https://example.com/a?b=1")
    assert host == "example.com"
    assert path.endswith("?b=1")

    with pytest.raises(http_mod.HttpError):
        http_mod._parse_https("https:///x")

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    p = http_mod._cache_root()
    assert p.exists()


def test_http_cache_put_write_failure(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)

    def boom(*args, **kwargs):
        raise OSError("x")

    monkeypatch.setattr(pathlib.Path, "write_text", boom, raising=True)
    http_mod._cache_put("https://x", None, b"y", ttl_s=1.0)
