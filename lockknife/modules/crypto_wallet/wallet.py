from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.http import http_get_json
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.crypto_wallet._bip39_wordlist import (
    BIP39_WORD_SET,
    is_bip39_word,
    validate_bip39_checksum,
)
from lockknife.modules.extraction._extraction_common import (
    DEVICE_IO_ERRORS,
    sh_quote,
    try_root_staging_pull,
)

log = get_logger()


@dataclasses.dataclass(frozen=True)
class WalletAddress:
    address: str
    kind: str
    source: str
    label: str | None = None


@dataclasses.dataclass(frozen=True)
class WalletLookup:
    address: str
    kind: str
    balance: int | None
    tx_count: int | None
    raw: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class MnemonicPhrase:
    phrase: str
    word_count: int
    source: str
    valid_checksum: bool = False


@dataclasses.dataclass(frozen=True)
class WalletVault:
    vault_type: str
    path: str
    metadata: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class DeviceWalletArtifacts:
    package: str
    app_name: str
    files: list[str]
    addresses: list[WalletAddress]
    mnemonics: list[MnemonicPhrase]
    vaults: list[WalletVault]


_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_BTC_BECH32 = re.compile(
    r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,87}|tb1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,87})\b",
    re.IGNORECASE,
)
_RE_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_RE_SOLANA = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

# Well-known Android cryptocurrency wallet packages
KNOWN_MOBILE_WALLETS: dict[str, str] = {
    "io.metamask": "MetaMask",
    "com.wallet.crypto.trustapp": "Trust Wallet",
    "org.toshi": "Coinbase Wallet",
    "app.phantom": "Phantom",
    "exodusmovement.exodus": "Exodus",
    "com.ton_keeper": "Tonkeeper",
    "com.binance.dev": "Binance",
    "com.okinc.okex.gp": "OKX",
    "com.bitkeep.wallet": "Bitget Wallet",
    "com.uniswap.mobile": "Uniswap",
}


def _is_plausible_solana(s: str) -> bool:
    if len(s) < 32 or len(s) > 44:
        return False
    # Avoid Bitcoin legacy (starts with 1 or 3) and Tron (starts with T)
    if s[0] in {"1", "3", "T"}:
        return False
    # Avoid pure hex (which are md5, sha256, hashes)
    if all(c in "0123456789abcdefABCDEF" for c in s):
        return False
    # Base58 typically mixes case or combines digits with letters
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return (has_upper and has_lower) or (has_digit and (has_upper or has_lower))


def extract_wallet_addresses_from_text(
    text: str, source: str = "raw", limit: int = 5000
) -> list[WalletAddress]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    out: dict[str, WalletAddress] = {}

    # Ethereum / EVM
    for m in _RE_ETH.finditer(text):
        addr = m.group(0)
        if addr not in out:
            out[addr] = WalletAddress(address=addr, kind="eth", source=source)
            if len(out) >= limit:
                return list(out.values())

    # Bitcoin Bech32 (SegWit / Taproot)
    for m in _RE_BTC_BECH32.finditer(text):
        addr = m.group(0)
        if addr not in out:
            out[addr] = WalletAddress(address=addr, kind="btc", source=source, label="bech32")
            if len(out) >= limit:
                return list(out.values())

    # Bitcoin Legacy (P2PKH / P2SH)
    for m in _RE_BTC_LEGACY.finditer(text):
        addr = m.group(0)
        if addr not in out:
            out[addr] = WalletAddress(address=addr, kind="btc", source=source, label="legacy")
            if len(out) >= limit:
                return list(out.values())

    # Tron (TRC-20 / TRX)
    for m in _RE_TRON.finditer(text):
        addr = m.group(0)
        if addr not in out:
            out[addr] = WalletAddress(address=addr, kind="trx", source=source)
            if len(out) >= limit:
                return list(out.values())

    # Solana Base58
    for m in _RE_SOLANA.finditer(text):
        addr = m.group(0)
        if addr not in out and _is_plausible_solana(addr):
            out[addr] = WalletAddress(address=addr, kind="sol", source=source)
            if len(out) >= limit:
                return list(out.values())

    return list(out.values())


def extract_wallet_addresses_from_sqlite(
    path: pathlib.Path, limit: int = 5000
) -> list[WalletAddress]:
    """Extract multi-chain cryptocurrency addresses from an SQLite database or raw file."""
    text = path.read_bytes().decode("utf-8", errors="ignore")
    return extract_wallet_addresses_from_text(text, source=str(path), limit=limit)


def extract_wallet_addresses(path: pathlib.Path, limit: int = 5000) -> list[WalletAddress]:
    """Alias for carving wallet addresses from any given file."""
    return extract_wallet_addresses_from_sqlite(path, limit=limit)


def extract_mnemonics(
    data: bytes | str, source: str = "raw", limit: int = 100
) -> list[MnemonicPhrase]:
    """Extract BIP-39 mnemonic seed phrases (12, 15, 18, 21, 24 words) from text or binary data."""
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="ignore")
    else:
        text = str(data)

    tokens = re.findall(r"\b[a-zA-Z]+\b", text.lower())
    if len(tokens) < 12:
        return []

    phrases: list[MnemonicPhrase] = []
    seen: set[str] = set()
    matched_ranges: list[tuple[int, int]] = []

    # Pass 1: Prioritize exact checksum-valid BIP-39 seed phrases
    i = 0
    while i <= len(tokens) - 12 and len(phrases) < limit:
        matched = False
        for length in (24, 21, 18, 15, 12):
            if i + length <= len(tokens):
                window = tokens[i : i + length]
                if all(w in BIP39_WORD_SET for w in window):
                    if validate_bip39_checksum(window):
                        phrase_str = " ".join(window)
                        if phrase_str not in seen:
                            phrases.append(
                                MnemonicPhrase(
                                    phrase=phrase_str,
                                    word_count=length,
                                    source=source,
                                    valid_checksum=True,
                                )
                            )
                            seen.add(phrase_str)
                            matched_ranges.append((i, i + length))
                        i += length
                        matched = True
                        break
        if not matched:
            i += 1

    # Pass 2: Carve remaining non-overlapping candidate BIP-39 runs
    if len(phrases) < limit:
        i = 0
        while i <= len(tokens) - 12 and len(phrases) < limit:
            matched = False
            for length in (24, 21, 18, 15, 12):
                if i + length <= len(tokens):
                    overlaps = any(
                        max(start, i) < min(end, i + length) for start, end in matched_ranges
                    )
                    if overlaps:
                        continue
                    window = tokens[i : i + length]
                    if all(w in BIP39_WORD_SET for w in window):
                        phrase_str = " ".join(window)
                        if phrase_str not in seen:
                            phrases.append(
                                MnemonicPhrase(
                                    phrase=phrase_str,
                                    word_count=length,
                                    source=source,
                                    valid_checksum=False,
                                )
                            )
                            seen.add(phrase_str)
                            matched_ranges.append((i, i + length))
                        i += length
                        matched = True
                        break
            if not matched:
                i += 1

    return phrases


def extract_web3_keystores(data: bytes | str, source: str = "raw") -> list[WalletVault]:
    """Detect and parse Web3 JSON keystores (e.g. Ethereum V3) and encrypted wallet state blobs."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="ignore")
    else:
        text = str(data)

    vaults: list[WalletVault] = []

    # Check for Web3 Ethereum V3 Keystore JSON objects
    if "crypto" in text.lower() and "ciphertext" in text.lower():
        # Try parsing JSON blocks or whole string
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                crypto_block = parsed.get("crypto") or parsed.get("Crypto")
                if isinstance(crypto_block, dict) and "ciphertext" in crypto_block:
                    vaults.append(
                        WalletVault(
                            vault_type="ethereum_v3_keystore",
                            path=source,
                            metadata={
                                "version": parsed.get("version"),
                                "id": parsed.get("id"),
                                "address": parsed.get("address"),
                                "cipher": crypto_block.get("cipher"),
                                "kdf": crypto_block.get("kdf"),
                            },
                        )
                    )
        except Exception:
            pass

    # Check for MetaMask KeyringController
    if "KeyringController" in text or "keyring" in text.lower():
        vaults.append(
            WalletVault(
                vault_type="metamask_keyring",
                path=source,
                metadata={"detected_marker": "KeyringController"},
            )
        )

    return vaults


def extract_device_wallets(
    devices: DeviceManager,
    serial: str,
    *,
    case_dir: pathlib.Path | None = None,
    limit_files_per_app: int = 20,
) -> list[DeviceWalletArtifacts]:
    """Discover installed mobile cryptocurrency wallet apps, extract their vault files and databases,

    and carve addresses, mnemonics, and keystores.
    """
    if limit_files_per_app <= 0:
        raise ValueError("limit_files_per_app must be > 0")
    has_root = devices.has_root(serial)
    results: list[DeviceWalletArtifacts] = []

    with secure_temp_dir(prefix="lockknife-wallets-") as temp_dir:
        for pkg, app_name in KNOWN_MOBILE_WALLETS.items():
            candidate_base_dirs = [
                f"/data/user/0/{pkg}",
                f"/data/data/{pkg}",
                f"/data/user/10/{pkg}",
            ]

            found_remote_files: list[str] = []
            for base_dir in candidate_base_dirs:
                quoted = sh_quote(base_dir)
                check_cmd = f"ls -d {quoted} 2>/dev/null"
                if has_root:
                    check_cmd = f'su -c "{check_cmd}"'
                try:
                    out = devices.shell(serial, check_cmd, timeout_s=10.0).strip()
                    if not out:
                        continue
                except DEVICE_IO_ERRORS:
                    continue

                # Directory exists, find database, preferences, and vault files
                find_cmd = (
                    f"find {quoted} -maxdepth 3 -type f "
                    f"\\( -name '*.db' -o -name '*.xml' -o -name '*vault*' -o -name '*keystore*' -o -name '*keyring*' \\) "
                    f"2>/dev/null | head -n {int(limit_files_per_app)}"
                )
                if has_root:
                    find_cmd = f'su -c "{find_cmd}"'
                try:
                    listing = devices.shell(serial, find_cmd, timeout_s=25.0)
                    for ln in listing.splitlines():
                        fpath = ln.strip()
                        if fpath and fpath not in found_remote_files:
                            found_remote_files.append(fpath)
                except DEVICE_IO_ERRORS:
                    continue

            if not found_remote_files:
                continue

            app_addresses: list[WalletAddress] = []
            app_mnemonics: list[MnemonicPhrase] = []
            app_vaults: list[WalletVault] = []
            pulled_files: list[str] = []

            for remote_file in found_remote_files[:limit_files_per_app]:
                fname = pathlib.PurePosixPath(remote_file).name
                digest = hashlib.sha256(remote_file.encode()).hexdigest()[:16]
                local_file = temp_dir / f"{pkg}_{digest}_{fname}"
                pulled = try_root_staging_pull(devices, serial, remote_file, local_file)
                if not pulled or not local_file.exists() or local_file.stat().st_size == 0:
                    continue

                pulled_files.append(remote_file)
                content = local_file.read_bytes()

                # Carve artifacts from file
                addrs = extract_wallet_addresses_from_text(
                    content.decode("utf-8", errors="ignore"), source=remote_file
                )
                app_addresses.extend(addrs)

                mnems = extract_mnemonics(content, source=remote_file)
                app_mnemonics.extend(mnems)

                vls = extract_web3_keystores(content, source=remote_file)
                app_vaults.extend(vls)

            results.append(
                DeviceWalletArtifacts(
                    package=pkg,
                    app_name=app_name,
                    files=pulled_files,
                    addresses=app_addresses,
                    mnemonics=app_mnemonics,
                    vaults=app_vaults,
                )
            )

    return results


def lookup_wallet_address(address: str, kind: str) -> WalletLookup:
    a = address.strip()
    k = kind.lower().strip()
    if k not in {"btc", "eth"}:
        return WalletLookup(address=a, kind=k, balance=None, tx_count=None, raw={})
    try:
        if k == "btc":
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{a}/balance"
        else:
            url = f"https://api.blockcypher.com/v1/eth/main/addrs/{a}/balance"
        raw = http_get_json(
            url, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60, rate_limit_per_s=1.0
        )
        balance = raw.get("final_balance")
        tx_count = raw.get("n_tx")
        return WalletLookup(
            address=a,
            kind=k,
            balance=int(balance) if balance is not None else None,
            tx_count=int(tx_count) if tx_count is not None else None,
            raw=raw if isinstance(raw, dict) else {"raw": raw},
        )
    except Exception:
        log.warning("wallet_lookup_failed", exc_info=True, kind=k, address=a)
        return WalletLookup(address=a, kind=k, balance=None, tx_count=None, raw={})


def enrich_wallet_addresses(addrs: list[WalletAddress]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for w in addrs:
        lk = lookup_wallet_address(w.address, w.kind)
        out.append(
            {
                "address": w.address,
                "kind": w.kind,
                "source": w.source,
                "label": w.label,
                "lookup": dataclasses.asdict(lk),
            }
        )
    return out


def list_wallet_transactions(address: str, kind: str, *, limit: int = 50) -> list[dict[str, Any]]:
    a = address.strip()
    k = kind.lower().strip()
    if k not in {"btc", "eth"}:
        return []
    try:
        base = "btc" if k == "btc" else "eth"
        url = f"https://api.blockcypher.com/v1/{base}/main/addrs/{a}"
        raw = http_get_json(
            url, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60, rate_limit_per_s=1.0
        )
        txrefs = raw.get("txrefs") if isinstance(raw, dict) else None
        if not isinstance(txrefs, list):
            return []
        out: list[dict[str, Any]] = []
        for tx in txrefs[: max(1, int(limit))]:
            if not isinstance(tx, dict):
                continue
            out.append(
                {
                    "hash": tx.get("tx_hash"),
                    "value": tx.get("value"),
                    "confirmations": tx.get("confirmations"),
                    "received": tx.get("received"),
                    "double_spend": tx.get("double_spend"),
                }
            )
        return out
    except Exception:
        log.warning("wallet_transactions_failed", exc_info=True, kind=k, address=a)
        return []
