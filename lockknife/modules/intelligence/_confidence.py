from __future__ import annotations

from typing import Any


def confidence_level(*, evidence_count: int = 0, mode: str = "remote", credential_configured: bool | None = None, has_error: bool = False) -> str:
    if has_error:
        return "limited"
    if mode == "local":
        return "moderate" if evidence_count else "limited"
    if credential_configured is False:
        return "limited"
    if evidence_count >= 5:
        return "high"
    if evidence_count >= 1:
        return "moderate"
    return "limited"


def confidence_notes(
    provider: str,
    *,
    evidence_count: int,
    cache_mode: str = "none",
    cache_ttl_s: int | None = None,
    credential_required: bool = False,
    credential_configured: bool | None = None,
    has_error: bool = False,
) -> list[str]:
    notes: list[str] = []
    if has_error:
        notes.append(f"{provider} returned an error or could not be queried for this subject.")
    if cache_mode != "none":
        ttl = f" (ttl {cache_ttl_s}s)" if cache_ttl_s else ""
        notes.append(f"Provider responses may be served from {cache_mode} cache{ttl}.")
    if credential_required and credential_configured is False:
        notes.append("Provider credentials are not configured, so coverage may be incomplete or unavailable.")
    if evidence_count == 0 and not has_error:
        notes.append("No provider evidence was returned for this query.")
    elif evidence_count > 0:
        notes.append(f"Provider returned {evidence_count} evidence item(s) relevant to this query.")
    return notes[:4]


def coverage_summary(subject: str, *, evidence_count: int, confidence: str, providers: list[str]) -> dict[str, Any]:
    return {
        "subject": subject,
        "provider_count": len(providers),
        "providers": providers,
        "evidence_count": evidence_count,
        "confidence": confidence,
    }