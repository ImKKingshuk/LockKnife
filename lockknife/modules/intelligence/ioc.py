from __future__ import annotations

import dataclasses
import base64
import ipaddress
import json
import re
from urllib.parse import urlencode, urljoin
from typing import Any

from lockknife.core.http import http_get, http_get_json


@dataclasses.dataclass(frozen=True)
class IocMatch:
    ioc: str
    kind: str
    location: str
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()


_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_URL = re.compile(r"\bhttps?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")


def detect_iocs(data: Any, *, location: str = "text", composite_rules: list[dict[str, Any]] | None = None) -> list[IocMatch]:
    out: list[IocMatch] = []
    seen: set[tuple[str, str, str]] = set()
    for frag_location, text in _iter_text_fragments(data, location=location):
        for match in _RE_SHA256.finditer(text):
            _append_match(out, seen, IocMatch(ioc=match.group(0).lower(), kind="sha256", location=frag_location, confidence=_confidence_for_match("sha256", frag_location)))
        for match in _RE_URL.finditer(text):
            _append_match(out, seen, IocMatch(ioc=match.group(0), kind="url", location=frag_location, confidence=_confidence_for_match("url", frag_location)))
        for match in _RE_IPV4.finditer(text):
            candidate = match.group(0)
            if _is_valid_ipv4(candidate):
                _append_match(out, seen, IocMatch(ioc=candidate, kind="ipv4", location=frag_location, confidence=_confidence_for_match("ipv4", frag_location)))
        for match in _RE_DOMAIN.finditer(text):
            candidate = match.group(0).lower().strip(".")
            if candidate.startswith("http"):
                continue
            _append_match(out, seen, IocMatch(ioc=candidate, kind="domain", location=frag_location, confidence=_confidence_for_match("domain", frag_location)))
    if composite_rules:
        for composite in evaluate_composite_iocs(out, composite_rules):
            _append_match(out, seen, composite)
    return out


def load_stix_indicators_from_url(url: str) -> list[IocMatch]:
    raw = http_get(url, timeout_s=20.0, max_attempts=4, cache_ttl_s=6 * 3600).decode("utf-8", errors="ignore")
    try:
        parsed = json.loads(raw)
        return parse_stix_bundle_for_iocs(parsed, location=url)
    except Exception:
        return detect_iocs(raw, location=url)


_RE_STIX_VALUE = re.compile(r"(?P<type>domain-name|ipv4-addr|url|file:hashes\.\'SHA-256\'|file:hashes\.\"SHA-256\"):[^=]+=\s*'(?P<val>[^']+)'")


def parse_stix_pattern(pattern: str, *, location: str) -> list[IocMatch]:
    out: list[IocMatch] = []
    for m in _RE_STIX_VALUE.finditer(pattern or ""):
        typ = m.group("type")
        val = m.group("val")
        if typ == "domain-name":
            out.append(IocMatch(ioc=val.lower(), kind="domain", location=location, confidence=0.9))
        elif typ == "ipv4-addr":
            out.append(IocMatch(ioc=val, kind="ipv4", location=location, confidence=0.92))
        elif typ == "url":
            out.append(IocMatch(ioc=val, kind="url", location=location, confidence=0.94))
        else:
            out.append(IocMatch(ioc=val.lower(), kind="sha256", location=location, confidence=0.98))
    operator = _stix_boolean_operator(pattern)
    if len(out) >= 2 and operator:
        out.append(
            IocMatch(
                ioc=f"{operator}:{' '.join(sorted(match.ioc for match in out))}",
                kind=f"composite_{operator.lower()}",
                location=location,
                confidence=min(0.99, round(sum(match.confidence for match in out) / len(out) + 0.05, 3)),
                evidence=tuple(match.ioc for match in out),
            )
        )
    return out


def parse_stix_bundle_for_iocs(bundle: dict[str, Any], *, location: str = "stix") -> list[IocMatch]:
    objs = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objs, list):
        return []
    out: list[IocMatch] = []
    for o in objs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "indicator":
            continue
        pattern = o.get("pattern")
        if isinstance(pattern, str) and pattern:
            out.extend(parse_stix_pattern(pattern, location=location))
        name = o.get("name")
        if name:
            out.extend(detect_iocs(name, location=f"{location}.name"))
        desc = o.get("description")
        if desc:
            out.extend(detect_iocs(desc, location=f"{location}.description"))
    return out


def _taxii_headers(
    *,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, str]:
    headers = {"Accept": "application/taxii+json;version=2.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if username and password:
        auth = (f"{username}:{password}").encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(auth).decode("ascii")
    return headers


def load_taxii_indicators(
    api_root_url: str,
    *,
    collection_id: str | None = None,
    added_after: str | None = None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    limit: int = 2000,
) -> list[IocMatch]:
    api_root = api_root_url.rstrip("/") + "/"
    collections_url = urljoin(api_root, "collections/")
    collections = http_get_json(
        collections_url,
        headers=_taxii_headers(token=token, username=username, password=password),
        timeout_s=20.0,
        max_attempts=4,
        cache_ttl_s=10 * 60,
        rate_limit_per_s=1.0,
    )
    cols = collections.get("collections") if isinstance(collections, dict) else None
    if not isinstance(cols, list) or not cols:
        return []
    cid = collection_id
    if cid is None:
        first = cols[0]
        if isinstance(first, dict):
            cid = first.get("id")
    if not cid:
        return []

    params: dict[str, str] = {"match[type]": "indicator", "limit": str(int(limit))}
    if added_after:
        params["added_after"] = added_after
    objects_url = urljoin(api_root, f"collections/{cid}/objects/") + ("?" + urlencode(params))
    raw = http_get(
        objects_url,
        headers=_taxii_headers(token=token, username=username, password=password),
        timeout_s=25.0,
        max_attempts=4,
        cache_ttl_s=10 * 60,
        rate_limit_per_s=1.0,
    ).decode(
        "utf-8", errors="ignore"
    )
    try:
        parsed = json.loads(raw)
        return parse_stix_bundle_for_iocs(parsed, location=objects_url)
    except Exception:
        return detect_iocs(raw, location=objects_url)


def evaluate_composite_iocs(matches: list[IocMatch], rules: list[dict[str, Any]]) -> list[IocMatch]:
    out: list[IocMatch] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            continue
        operator = str(rule.get("operator") or "and").strip().lower()
        matched_sets: list[list[IocMatch]] = []
        for condition in conditions:
            if not isinstance(condition, dict):
                matched_sets.append([])
                continue
            matched_sets.append([match for match in matches if _condition_matches(match, condition)])
        success = all(matched_sets) if operator == "and" else any(matched_sets)
        if not success:
            continue
        matched_items = [match for bucket in matched_sets for match in bucket]
        if not matched_items:
            continue
        label = str(rule.get("name") or f"composite_{operator}")
        confidence_boost = float(rule.get("confidence_boost") or 0.0)
        base_confidence = sum(item.confidence for item in matched_items) / len(matched_items)
        out.append(
            IocMatch(
                ioc=label,
                kind=f"composite_{operator}",
                location=str(rule.get("location") or "composite-rule"),
                confidence=min(0.99, round(base_confidence + confidence_boost, 3)),
                evidence=tuple(sorted({item.ioc for item in matched_items})),
            )
        )
    return out


def _iter_text_fragments(data: Any, *, location: str) -> list[tuple[str, str]]:
    if isinstance(data, dict):
        out: list[tuple[str, str]] = []
        for key, value in data.items():
            child = f"{location}.{key}" if location else str(key)
            out.extend(_iter_text_fragments(value, location=child))
        return out
    if isinstance(data, list):
        out = []
        for index, item in enumerate(data):
            out.extend(_iter_text_fragments(item, location=f"{location}[{index}]"))
        return out
    if data is None:
        return []
    return [(location, str(data))]


def _append_match(out: list[IocMatch], seen: set[tuple[str, str, str]], match: IocMatch) -> None:
    key = (match.kind, match.ioc.lower(), match.location)
    if key in seen:
        return
    seen.add(key)
    out.append(match)


def _confidence_for_match(kind: str, location: str) -> float:
    base = {"sha256": 0.95, "url": 0.82, "ipv4": 0.74, "domain": 0.66}.get(kind, 0.5)
    lowered = location.lower()
    if any(token in lowered for token in ("hash", "indicator", "artifact", "ioc", "pattern")):
        base += 0.08
    if kind == "domain" and any(token in lowered for token in ("domain", "host", "fqdn")):
        base += 0.08
    if kind == "url" and "url" in lowered:
        base += 0.08
    if kind == "ipv4" and any(token in lowered for token in ("ip", "address", "remote")):
        base += 0.08
    return min(0.99, round(base, 3))


def _condition_matches(match: IocMatch, condition: dict[str, Any]) -> bool:
    kind = str(condition.get("kind") or "").strip().lower()
    if kind and match.kind != kind:
        return False
    value = str(condition.get("ioc") or condition.get("value") or "").strip()
    if value and match.ioc != value:
        return False
    pattern = str(condition.get("pattern") or "").strip()
    if pattern and not re.search(pattern, match.ioc):
        return False
    min_conf = condition.get("min_confidence")
    if min_conf is not None and match.confidence < float(min_conf):
        return False
    return True


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except Exception:
        return False
    return True


def _stix_boolean_operator(pattern: str) -> str | None:
    upper = (pattern or "").upper()
    if " AND " in upper:
        return "AND"
    if " OR " in upper:
        return "OR"
    return None
