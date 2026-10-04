from __future__ import annotations

import json
import pathlib
from unittest.mock import MagicMock

from click.testing import CliRunner

from lockknife.core.device import DeviceManager
from lockknife.modules.crypto_wallet._bip39_wordlist import (
    is_bip39_word,
    validate_bip39_checksum,
)
from lockknife.modules.crypto_wallet.wallet import (
    extract_device_wallets,
    extract_mnemonics,
    extract_wallet_addresses,
    extract_wallet_addresses_from_text,
    extract_web3_keystores,
)
from lockknife_headless_cli.crypto_wallet import crypto_wallet
from lockknife_headless_cli.extract import extract


def test_tui_wallet_offline_and_device_dispatch(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from lockknife_headless_cli.tui_callback import build_tui_callback

    source = tmp_path / "wallet.bin"
    source.write_text("0x" + "a" * 40)
    callback = build_tui_callback(SimpleNamespace(devices=MagicMock(spec=DeviceManager)))
    result = callback("crypto.wallets", {"path": str(source), "lookup": False})
    assert result["ok"] is True
    assert "0x" + "a" * 40 in result["data_json"]
    calls = []
    monkeypatch.setattr(
        "lockknife.modules.crypto_wallet.wallet.extract_device_wallets",
        lambda devices, serial, **kwargs: calls.append(serial) or [],
    )
    result = callback("crypto.scan_device", {"serial": "DEVICE", "limit": 3})
    assert result["ok"] is True
    assert calls == ["DEVICE"]


def test_bip39_wordlist_and_checksum_validation() -> None:
    assert is_bip39_word("abandon") is True
    assert is_bip39_word("zoo") is True
    assert is_bip39_word("nonexistentword123") is False

    valid_12 = ["abandon"] * 11 + ["about"]
    assert validate_bip39_checksum(valid_12) is True

    invalid_12 = ["abandon"] * 12
    assert validate_bip39_checksum(invalid_12) is False


def test_multichain_address_carving() -> None:
    sample_text = """
    ETH address: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
    Bitcoin SegWit Bech32: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
    Bitcoin Taproot Bech32: bc1p5d7rjq7g6rdk2yhzks9s2cqmmxdumgah52q6g2ymdua3uejlsszq0qwvx0
    Bitcoin Legacy: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    Tron address: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
    Solana address: 7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs
    Random string: some_variable_name_without_crypto
    """
    addrs = extract_wallet_addresses_from_text(sample_text, source="test_stream")
    by_kind = {a.kind: a for a in addrs}

    assert "eth" in by_kind
    assert by_kind["eth"].address == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    btc_addrs = [a for a in addrs if a.kind == "btc"]
    assert len(btc_addrs) >= 3
    bech32_addrs = [a.address for a in btc_addrs if a.label == "bech32"]
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in bech32_addrs
    assert "bc1p5d7rjq7g6rdk2yhzks9s2cqmmxdumgah52q6g2ymdua3uejlsszq0qwvx0" in bech32_addrs

    legacy_addrs = [a.address for a in btc_addrs if a.label == "legacy"]
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in legacy_addrs

    assert "trx" in by_kind
    assert by_kind["trx"].address == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

    assert "sol" in by_kind
    assert by_kind["sol"].address == "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs"


def test_bip39_mnemonic_extraction() -> None:
    data = (
        "Logs starting up. Random words: quick brown fox. "
        "User seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about. "
        "Trailing noise."
    )
    mnemonics = extract_mnemonics(data, source="mem_dump")
    assert len(mnemonics) == 1
    assert mnemonics[0].word_count == 12
    assert mnemonics[0].valid_checksum is True
    assert "abandon" in mnemonics[0].phrase


def test_web3_keystore_and_metamask_vault_detection() -> None:
    keystore_json = json.dumps(
        {
            "version": 3,
            "id": "e3914a1a-3136-4074-b580-0a25b161f364",
            "address": "001d3f1ef827552ae1114027bd3ecf1f086ba0f9",
            "crypto": {
                "ciphertext": "d172bf743a674da9638fa37c5c0f005f",
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
            },
        }
    )
    vaults = extract_web3_keystores(keystore_json, source="keystore.json")
    assert len(vaults) == 1
    assert vaults[0].vault_type == "ethereum_v3_keystore"
    assert vaults[0].metadata["cipher"] == "aes-128-ctr"
    assert vaults[0].metadata["address"] == "001d3f1ef827552ae1114027bd3ecf1f086ba0f9"

    metamask_blob = "localStorage KeyringController vault state data"
    mm_vaults = extract_web3_keystores(metamask_blob, source="leveldb.ldb")
    assert len(mm_vaults) == 1
    assert mm_vaults[0].vault_type == "metamask_keyring"


def test_device_wallet_extraction(monkeypatch, tmp_path: pathlib.Path) -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = True

    # Simulate MetaMask package installed
    def fake_shell(serial: str, cmd: str, timeout_s: float = 10.0) -> str:
        if "ls -d" in cmd:
            if "io.metamask" in cmd:
                return "/data/user/0/io.metamask\n"
            return ""
        if "find" in cmd:
            return "/data/user/0/io.metamask/databases/metamask.db\n"
        return ""

    dev.shell.side_effect = fake_shell

    # Mock try_root_staging_pull
    def fake_pull(devices, serial, remote, local, timeout_s=90.0):
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(
            "Sample wallet DB: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 and KeyringController",
            encoding="utf-8",
        )
        return True

    monkeypatch.setattr("lockknife.modules.crypto_wallet.wallet.try_root_staging_pull", fake_pull)

    wallets = extract_device_wallets(dev, "device-123", limit_files_per_app=5)
    assert len(wallets) == 1
    assert wallets[0].package == "io.metamask"
    assert wallets[0].app_name == "MetaMask"
    assert len(wallets[0].files) == 1
    assert len(wallets[0].addresses) == 1
    assert wallets[0].addresses[0].address == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert len(wallets[0].vaults) == 1
    assert wallets[0].vaults[0].vault_type == "metamask_keyring"


def test_cli_wallet_command_with_carve_options(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "wallet_evidence.db"
    db.write_text(
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n"
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    # Baseline address extraction
    out_base = tmp_path / "out_base.json"
    res_base = runner.invoke(crypto_wallet, ["wallet", str(db), "--output", str(out_base)])
    assert res_base.exit_code == 0
    parsed_base = json.loads(out_base.read_text(encoding="utf-8"))
    assert isinstance(parsed_base, list)
    assert len(parsed_base) >= 2

    # With seeds carving
    out_seeds = tmp_path / "out_seeds.json"
    res_seeds = runner.invoke(
        crypto_wallet, ["wallet", str(db), "--carve-seeds", "--output", str(out_seeds)]
    )
    assert res_seeds.exit_code == 0
    parsed_seeds = json.loads(out_seeds.read_text(encoding="utf-8"))
    assert isinstance(parsed_seeds, dict)
    assert "addresses" in parsed_seeds
    assert "mnemonics" in parsed_seeds
    assert len(parsed_seeds["mnemonics"]) == 1
    assert parsed_seeds["mnemonics"][0]["valid_checksum"] is True


def test_cli_scan_device_and_extract_wallets_aliases(tmp_path: pathlib.Path) -> None:
    fake_dev = MagicMock(spec=DeviceManager)
    fake_dev.has_root.return_value = False
    fake_dev.shell.return_value = ""

    class FakeApp:
        devices = fake_dev

    runner = CliRunner()
    # Test scan-device
    out_scan = tmp_path / "out_scan.json"
    res_scan = runner.invoke(
        crypto_wallet,
        ["scan-device", "--serial", "fake-serial", "--output", str(out_scan)],
        obj=FakeApp(),
    )
    assert res_scan.exit_code == 0
    assert json.loads(out_scan.read_text(encoding="utf-8")) == []

    # Test extract wallets alias
    out_extract = tmp_path / "out_extract.json"
    res_extract = runner.invoke(
        extract,
        ["wallets", "--serial", "fake-serial", "--output", str(out_extract)],
        obj=FakeApp(),
    )
    assert res_extract.exit_code == 0
    assert json.loads(out_extract.read_text(encoding="utf-8")) == []
