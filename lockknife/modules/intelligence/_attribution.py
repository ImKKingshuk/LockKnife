from __future__ import annotations

from typing import Any

from lockknife.modules.intelligence._confidence import confidence_level, confidence_notes


def attributed_source(
    provider: str,
    *,
    mode: str,
    description: str,
    subject: str,
    evidence_count: int = 0,
    credential_required: bool = False,
    credential_configured: bool | None = None,
    credential_source: str | None = None,
    cache_mode: str = "none",
    cache_ttl_s: int | None = None,
    rate_limit_hint: str | None = None,
    has_error: bool = False,
) -> dict[str, Any]:
    confidence = confidence_level(
        evidence_count=evidence_count,
        mode=mode,
        credential_configured=credential_configured,
        has_error=has_error,
    )
    payload = {
        "provider": provider,
        "mode": mode,
        "description": description,
        "subject": subject,
        "credentials": {
            "required": credential_required,
            "configured": credential_configured,
            "source": credential_source,
        },
        "cache": {"mode": cache_mode, "ttl_s": cache_ttl_s},
        "confidence": confidence,
        "confidence_notes": confidence_notes(
            provider,
            evidence_count=evidence_count,
            cache_mode=cache_mode,
            cache_ttl_s=cache_ttl_s,
            credential_required=credential_required,
            credential_configured=credential_configured,
            has_error=has_error,
        ),
    }
    if rate_limit_hint:
        payload["rate_limit_hint"] = rate_limit_hint
    return payload