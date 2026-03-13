from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Any

from lockknife.core.http import http_get_json
from lockknife.core.logging import get_logger

log = get_logger()

@dataclasses.dataclass(frozen=True)
class WalletAddress:
    address: str
    kind: str
    source: str


@dataclasses.dataclass(frozen=True)
class WalletLookup:
    address: str
    kind: str
    balance: int | None
    tx_count: int | None
    raw: dict[str, Any]


_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_BTC = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")


def extract_wallet_addresses_from_sqlite(path: pathlib.Path, limit: int = 5000) -> list[WalletAddress]:
    text = path.read_bytes().decode("utf-8", errors="ignore")
    out: dict[str, WalletAddress] = {}
    for m in _RE_ETH.finditer(text):
        out[m.group(0)] = WalletAddress(address=m.group(0), kind="eth", source=str(path))
        if len(out) >= limit:
            break
    if len(out) < limit:
        for m in _RE_BTC.finditer(text):
            out[m.group(0)] = WalletAddress(address=m.group(0), kind="btc", source=str(path))
            if len(out) >= limit:
                break
    return list(out.values())


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
        raw = http_get_json(url, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60, rate_limit_per_s=1.0)
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
        out.append({"address": w.address, "kind": w.kind, "source": w.source, "lookup": dataclasses.asdict(lk)})
    return out


def list_wallet_transactions(address: str, kind: str, *, limit: int = 50) -> list[dict[str, Any]]:
    a = address.strip()
    k = kind.lower().strip()
    if k not in {"btc", "eth"}:
        return []
    try:
        base = "btc" if k == "btc" else "eth"
        url = f"https://api.blockcypher.com/v1/{base}/main/addrs/{a}"
        raw = http_get_json(url, timeout_s=20.0, max_attempts=4, cache_ttl_s=10 * 60, rate_limit_per_s=1.0)
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
