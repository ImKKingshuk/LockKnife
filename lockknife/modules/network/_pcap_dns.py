from __future__ import annotations

import re
from collections import Counter
from typing import Any

_DNS_HINT = re.compile(r"(?i)(?:qname|query|question|dns)[:=\s]+([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")
_DOMAIN = re.compile(r"\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}\b")
_DNS_ANSWER = re.compile(r"(?i)(?:answer|resolved|address)[:=\s]+([a-zA-Z0-9._:-]+)")


def extract_dns_records(texts: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for text in texts:
        answers = [match.group(1).strip() for match in _DNS_ANSWER.finditer(text)]
        for match in _DNS_HINT.finditer(text):
            query = _normalize(match.group(1))
            if not query:
                continue
            answer = answers[0] if answers else None
            key = (query, answer)
            if key in seen:
                continue
            seen.add(key)
            out.append({"query": query, "answer": answer, "source": "text"})
        for match in _DOMAIN.finditer(text):
            query = _normalize(match.group(0))
            if not query or query.startswith("http"):
                continue
            key = (query, None)
            if key in seen:
                continue
            seen.add(key)
            out.append({"query": query, "answer": None, "source": "text"})
    return out[:150]


def extract_dns_queries(texts: list[str]) -> list[str]:
    return [str(item.get("query") or "") for item in extract_dns_records(texts) if str(item.get("query") or "")]


def summarize_dns_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    domains = [str(item.get("query") or "") for item in records if str(item.get("query") or "")]
    answers = [str(item.get("answer") or "") for item in records if str(item.get("answer") or "")]
    counts = Counter(domains)
    answer_counts = Counter(answers)
    return {
        "query_count": len(domains),
        "unique_domain_count": len(set(domains)),
        "answer_count": len(answers),
        "top_domains": [{"name": name, "count": count} for name, count in counts.most_common(8)],
        "top_answers": [{"name": name, "count": count} for name, count in answer_counts.most_common(8)],
        "domains": sorted(set(domains))[:25],
        "records": records[:25],
    }


def summarize_dns_queries(domains: list[str]) -> dict[str, Any]:
    return summarize_dns_records([{"query": domain, "answer": None, "source": "summary"} for domain in domains])


def _normalize(value: str) -> str:
    return value.strip().strip(".").lower()