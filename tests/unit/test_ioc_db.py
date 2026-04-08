import pathlib
import sqlite3
import types

import pytest

from lockknife.modules.intelligence.ioc_db import (
    IocRecord,
    add_iocs,
    list_iocs,
    load_feed_config,
    now,
    sync_ioc_feeds,
)


def test_ioc_db_roundtrip(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "iocs.db"
    add_iocs(db, [IocRecord(ioc="192.0.2.2", kind="ipv4", source="test", first_seen=now())])
    rows = list_iocs(db, limit=10)
    assert rows[0].ioc == "192.0.2.2"


def test_ioc_db_sync_supports_stix_and_freshness(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife.modules.intelligence import ioc_db

    db = tmp_path / "iocs.db"
    monkeypatch.setattr(
        ioc_db,
        "load_stix_indicators_from_url",
        lambda url: [type("M", (), {"ioc": "192.0.2.3", "kind": "ipv4", "location": url})()],
    )

    result = sync_ioc_feeds(
        db,
        [{"name": "demo", "type": "stix_url", "url": "https://example.test/feed.json"}],
        force=True,
    )
    assert result["total_added"] == 1
    skipped = sync_ioc_feeds(
        db,
        [{"name": "demo", "type": "stix_url", "url": "https://example.test/feed.json"}],
        force=False,
    )
    assert skipped["feeds"][0]["status"] == "skipped"


def test_load_feed_config_accepts_wrapper_object(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "feeds.json"
    config.write_text(
        '{"feeds": [{"name": "demo", "type": "raw_url", "url": "https://example.test/iocs.txt"}]}',
        encoding="utf-8",
    )
    feeds = load_feed_config(config)
    assert feeds[0]["name"] == "demo"


def test_load_feed_config_accepts_plain_list(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "feeds.json"
    config.write_text(
        '[{"name": "demo", "type": "stix_url", "url": "https://example.test/feed.json"}]',
        encoding="utf-8",
    )
    feeds = load_feed_config(config)
    assert feeds[0]["type"] == "stix_url"


def test_load_feed_config_rejects_invalid_shape(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "feeds.json"
    config.write_text('{"unexpected": true}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_feed_config(config)


def test_ioc_db_sync_supports_raw_url(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife.modules.intelligence import ioc_db

    db = tmp_path / "iocs.db"
    monkeypatch.setattr(
        ioc_db, "http_get", lambda *_a, **_k: b"192.0.2.4\nhttps://example.test/x\n"
    )
    monkeypatch.setattr(
        ioc_db,
        "detect_iocs",
        lambda raw, location: [
            types.SimpleNamespace(ioc="192.0.2.4", kind="ipv4", location=location),
            types.SimpleNamespace(ioc="https://example.test/x", kind="url", location=location),
        ],
    )

    result = sync_ioc_feeds(
        db, [{"name": "raw", "type": "raw_url", "url": "https://example.test/iocs.txt"}], force=True
    )

    assert result["total_added"] == 2
    assert {row.ioc for row in list_iocs(db, limit=10)} == {"192.0.2.4", "https://example.test/x"}


def test_ioc_db_sync_supports_taxii(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife.modules.intelligence import ioc_db

    db = tmp_path / "iocs.db"
    seen: dict[str, object] = {}

    def _taxii(api_root_url, **kwargs):
        seen["api_root_url"] = api_root_url
        seen.update(kwargs)
        return [types.SimpleNamespace(ioc="192.0.2.5", kind="ipv4")]

    monkeypatch.setattr(ioc_db, "load_taxii_indicators", _taxii)

    result = sync_ioc_feeds(
        db,
        [
            {
                "name": "taxii",
                "type": "taxii",
                "api_root_url": "https://taxii.example/api",
                "collection_id": "abc",
                "limit": 9,
            }
        ],
        force=True,
    )

    assert result["feeds"][0]["status"] == "updated"
    assert seen["api_root_url"] == "https://taxii.example/api"
    assert seen["collection_id"] == "abc"
    assert seen["limit"] == 9


def test_ioc_db_sync_supports_otx_via_secret(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife.modules.intelligence import ioc_db

    db = tmp_path / "iocs.db"
    monkeypatch.setattr(
        ioc_db, "load_secrets", lambda: types.SimpleNamespace(OTX_API_KEY="secret-key")
    )
    monkeypatch.setattr(
        ioc_db,
        "http_get_json",
        lambda url, headers, **_kwargs: {
            "results": [
                {
                    "indicators": [
                        {"indicator": "evil.example", "type": "domain"},
                        {"indicator": "", "type": "domain"},
                    ]
                },
                {"ignored": True},
            ]
        },
    )

    result = sync_ioc_feeds(db, [{"name": "otx", "type": "otx"}], force=True)

    assert result["total_added"] == 1
    rows = list_iocs(db, limit=10)
    assert rows[0].ioc == "evil.example"
    assert rows[0].kind == "domain"


def test_ioc_db_sync_records_error_state(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife.modules.intelligence import ioc_db

    db = tmp_path / "iocs.db"
    monkeypatch.setattr(
        ioc_db,
        "load_stix_indicators_from_url",
        lambda _url: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    result = sync_ioc_feeds(
        db,
        [{"name": "broken", "type": "stix_url", "url": "https://example.test/feed.json"}],
        force=True,
    )

    assert result["feeds"][0]["status"] == "error"
    con = sqlite3.connect(str(db))
    try:
        row = con.execute(
            "SELECT last_error, last_count FROM ioc_feed_sync WHERE feed_name='broken'"
        ).fetchone()
    finally:
        con.close()
    assert row == ("boom", 0)


def test_ioc_db_sync_rejects_unsupported_feed_type(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "iocs.db"
    result = sync_ioc_feeds(db, [{"name": "bad", "type": "nope"}], force=True)
    assert result["feeds"][0]["status"] == "error"
