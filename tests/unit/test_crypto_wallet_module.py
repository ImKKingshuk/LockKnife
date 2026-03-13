import pathlib

from lockknife.modules.crypto_wallet import wallet as wallet_mod


def test_extract_wallet_addresses_from_sqlite(tmp_path: pathlib.Path) -> None:
    sample = "addr 0x52908400098527886E0F7030069857D2E4169EE7 and 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    p = tmp_path / "db.sqlite"
    p.write_text(sample, encoding="utf-8")
    out = wallet_mod.extract_wallet_addresses_from_sqlite(p, limit=10)
    kinds = {w.kind for w in out}
    assert {"eth", "btc"}.issubset(kinds)


def test_lookup_wallet_address_invalid_kind() -> None:
    out = wallet_mod.lookup_wallet_address("addr", "x")
    assert out.balance is None


def test_lookup_wallet_address_success(monkeypatch) -> None:
    monkeypatch.setattr(wallet_mod, "http_get_json", lambda *_a, **_k: {"final_balance": 1, "n_tx": 2})
    out = wallet_mod.lookup_wallet_address("0x52908400098527886E0F7030069857D2E4169EE7", "eth")
    assert out.balance == 1
    assert out.tx_count == 2


def test_list_wallet_transactions(monkeypatch) -> None:
    monkeypatch.setattr(
        wallet_mod,
        "http_get_json",
        lambda *_a, **_k: {"txrefs": [{"tx_hash": "h", "value": 1, "confirmations": 2, "received": "r"}]},
    )
    out = wallet_mod.list_wallet_transactions("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "btc", limit=1)
    assert out[0]["hash"] == "h"
