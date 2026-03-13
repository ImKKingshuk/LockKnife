from lockknife.modules.crypto_wallet.wallet import WalletAddress, enrich_wallet_addresses


def test_enrich_wallet_addresses_lookup(monkeypatch) -> None:
    from lockknife.modules.crypto_wallet import wallet

    monkeypatch.setattr(wallet, "http_get_json", lambda url, **kwargs: {"final_balance": 123, "n_tx": 4})
    rows = enrich_wallet_addresses([WalletAddress(address="1abc", kind="btc", source="t")])
    assert rows[0]["lookup"]["balance"] == 123
