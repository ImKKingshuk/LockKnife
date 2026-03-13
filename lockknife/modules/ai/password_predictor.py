from __future__ import annotations

import collections
import json
import pathlib
import random
import re
from typing import Any


class PasswordPredictor:
    def __init__(self, transitions: dict[str, dict[str, int]], *, order: int = 1) -> None:
        self._t = transitions
        self._order = max(1, order)

    @classmethod
    def train_from_wordlist(cls, path: pathlib.Path, *, max_words: int = 200_000, order: int = 2) -> "PasswordPredictor":
        trans: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        start = "^" * max(1, order)
        end = "$"
        n = 0
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w:
                    continue
                n += 1
                if n > max_words:
                    break
                prev = start
                for ch in w:
                    trans[prev][ch] += 1
                    prev = (prev + ch)[-max(1, order) :]
                trans[prev][end] += 1
        return cls({k: dict(v) for k, v in trans.items()}, order=max(1, order))

    def generate(
        self,
        *,
        count: int = 50,
        min_len: int = 6,
        max_len: int = 12,
        seed: int | None = None,
        personal_data: Any | None = None,
    ) -> list[str]:
        rng = random.Random(seed)  # nosec B311
        out: list[str] = []
        seen: set[str] = set()
        for candidate in self.augment_with_personal_data(personal_data, min_len=min_len, max_len=max_len):
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
                if len(out) >= count:
                    return out
        attempts = 0
        while len(out) < count and attempts < count * 20:
            attempts += 1
            s = []
            prev = "^" * self._order
            while True:
                nxt = self._sample_next(prev, rng)
                if nxt == "$":
                    break
                s.append(nxt)
                if len(s) >= max_len:
                    break
                prev = (prev + nxt)[-self._order :]
            w = "".join(s)
            if len(w) < min_len or w in seen:
                continue
            seen.add(w)
            out.append(w)
        return out

    def augment_with_personal_data(self, personal_data: Any | None, *, min_len: int, max_len: int) -> list[str]:
        tokens = _extract_personal_tokens(personal_data)
        if not tokens:
            return []
        candidates: list[str] = []
        suffixes = ["2024", "2025", "2026", "123", "1234", "!"]
        for token in tokens:
            variants = {token, token.lower(), token.capitalize(), token.title()}
            for variant in variants:
                if min_len <= len(variant) <= max_len:
                    candidates.append(variant)
                for suffix in suffixes:
                    merged = f"{variant}{suffix}"
                    if min_len <= len(merged) <= max_len:
                        candidates.append(merged)
        return list(dict.fromkeys(candidates))[: max(25, len(tokens) * 6)]

    def _sample_next(self, prev: str, rng: random.Random) -> str:
        dist = self._t.get(prev) or {"$": 1}
        total = sum(dist.values())
        r = rng.randint(1, total)
        acc = 0
        for k, v in dist.items():
            acc += v
            if r <= acc:
                return k
        return "$"


def load_personal_data(path: pathlib.Path) -> Any:
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return {"raw": path.read_text(encoding="utf-8", errors="ignore")}


def _extract_personal_tokens(personal_data: Any | None) -> list[str]:
    if personal_data is None:
        return []
    values: list[str] = []
    for item in _flatten_values(personal_data):
        values.extend(_tokenize_value(item))
    return list(dict.fromkeys(token for token in values if len(token) >= 3))[:80]


def _flatten_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for nested in value.values():
            out.extend(_flatten_values(nested))
        return out
    if isinstance(value, list):
        out = []
        for nested in value:
            out.extend(_flatten_values(nested))
        return out
    if value is None:
        return []
    return [str(value)]


def _tokenize_value(value: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9@._-]{3,}", value)
    out: list[str] = []
    for token in tokens:
        if "@" in token:
            local = token.split("@", 1)[0]
            if len(local) >= 3:
                out.append(local)
        compact = re.sub(r"[^A-Za-z0-9]", "", token)
        if len(compact) >= 3:
            out.append(compact)
    return out

