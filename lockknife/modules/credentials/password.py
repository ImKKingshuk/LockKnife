from __future__ import annotations

import pathlib

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger


class PasswordCrackError(LockKnifeError):
    pass


_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})
log = get_logger()


def _variants(word: str) -> set[str]:
    w = word.strip()
    if not w:
        return set()
    out = {w, w.lower(), w.upper(), w.capitalize()}
    out.add(w.translate(_LEET))
    out.add(w.lower().translate(_LEET))
    return out


def crack_password_with_rules(
    target_hash_hex: str, algo: str, wordlist_path: pathlib.Path, max_suffix: int = 100
) -> str | None:
    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as e:
        raise PasswordCrackError("lockknife_core extension is not available") from e

    algo_l = algo.lower()
    if algo_l not in {"sha1", "sha256", "sha512"}:
        raise PasswordCrackError("Unsupported algorithm")

    if hasattr(lockknife_core, "dictionary_attack_rules"):
        try:
            found = lockknife_core.dictionary_attack_rules(
                target_hash_hex, algo_l, str(wordlist_path), int(max_suffix)
            )
            if found is not None:
                return str(found)
        except Exception:
            log.warning(
                "password_crack_rules_failed",
                exc_info=True,
                algo=algo_l,
                wordlist=str(wordlist_path),
            )

    def digest(b: bytes) -> str:
        if algo_l == "sha1":
            return lockknife_core.sha1_hex(b)
        if algo_l == "sha512":
            return lockknife_core.sha512_hex(b)
        return lockknife_core.sha256_hex(b)

    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            base = line.strip()
            for v in _variants(base):
                if digest(v.encode("utf-8")) == target_hash_hex:
                    return v
                for n in range(max_suffix + 1):
                    cand = f"{v}{n}"
                    if digest(cand.encode("utf-8")) == target_hash_hex:
                        return cand
    return None
