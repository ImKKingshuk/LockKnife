"""OrcaRouter Cyber Inference: a named, first-class LLM provider preset.

OrcaRouter is an OpenAI-compatible inference gateway aimed at authorized
security teams. LockKnife's agent kernel already speaks the OpenAI wire format,
so this module only adds the named provider plumbing around it: origin and
credential resolution, the real model catalog, capability filtering for the
text-only agent entry points, and a small verified cold-start seed used when
live discovery is unavailable.

Reference: https://www.orcarouter.ai/cyber and
https://www.orcarouter.ai/models?tier=cyber
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any

logger = logging.getLogger("lockknife.agent.orcarouter")

PROVIDER_ID = "orcarouter"
PROVIDER_LABEL = "OrcaRouter Cyber Inference"
PROVIDER_DOC_URL = "https://www.orcarouter.ai/cyber"
PROVIDER_MODELS_URL = "https://www.orcarouter.ai/models?tier=cyber"
KEY_DASHBOARD_URL = "https://www.orcarouter.ai/console"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"
DEFAULT_MODEL = "orcarouter/auto"
FUSION_MODEL = "orcarouter/fusion"
CYBER_MODELS = ("orcacyber-ultra-1.0", "orcacyber-zero-1.5")
API_KEY_ENV_VARS = ("ORCAROUTER_API_KEY", "ORCA_API_KEY")
API_BASE_ENV_VARS = ("ORCAROUTER_API_BASE", "ORCA_API_BASE")
MODEL_ENV_VAR = "ORCAROUTER_MODEL"
API_KEY_PREFIX = "sk-orca-"

CATALOG_TIMEOUT_S = 8.0
CATALOG_MAX_BYTES = 2 * 1024 * 1024
CATALOG_MAX_ITEMS = 2000
TEXT_ENDPOINT_TYPES = frozenset(
    {"openai", "openai-response", "anthropic", "gemini", "google-gemini"}
)
NON_TEXT_ENDPOINT_TYPES = frozenset({"image-generation", "openai-video", "jina-rerank"})


@dataclasses.dataclass(frozen=True)
class CatalogModel:
    """A model usable by the text-only agent entry points."""

    id: str
    name: str
    context_length: int | None = None
    reasoning_efforts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "reasoning_efforts": list(self.reasoning_efforts),
        }


@dataclasses.dataclass(frozen=True)
class CatalogResult:
    """Result of model discovery; ``source`` explains what produced ``models``."""

    models: tuple[CatalogModel, ...]
    source: str  # "live" | "last-known-good" | "seed"
    detail: str = ""

    @property
    def degraded(self) -> bool:
        return self.source != "live"


# Verified cold-start seed, captured from GET https://api.orcarouter.ai/v1/models
# (2026-10-30). Only text-capable models with known metadata are listed. The
# documented automatic-routing alias ``orcarouter/auto`` is the provider default;
# live discovery replaces this list with the authoritative catalog.
VERIFIED_SEED: tuple[CatalogModel, ...] = (
    CatalogModel(
        "openai/gpt-5.5",
        "GPT-5.5",
        context_length=400000,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
    ),
    CatalogModel("anthropic/claude-opus-4.8", "Claude Opus 4.8", context_length=200000),
    CatalogModel("google/gemini-3.5-flash", "Gemini 3.5 Flash", context_length=1000000),
    CatalogModel("deepseek/deepseek-v4-pro", "DeepSeek V4 Pro", context_length=164000),
    CatalogModel("orcarouter/fusion", "OrcaRouter Fusion", context_length=1000000),
)


@dataclasses.dataclass(frozen=True)
class OrcaRouterSettings:
    """Resolved OrcaRouter provider settings."""

    api_base: str = DEFAULT_API_BASE
    api_key: str = ""
    model: str = DEFAULT_MODEL

    def public_summary(self) -> dict[str, Any]:
        """Metadata safe to print: never includes the key value."""
        return {
            "provider": PROVIDER_ID,
            "label": PROVIDER_LABEL,
            "api_base": self.api_base,
            "model": self.model,
            "api_key_configured": bool(self.api_key),
            "api_key_hint": mask_api_key(self.api_key),
        }


def mask_api_key(key: str) -> str:
    """Return a redacted hint for a key; empty string when no key is set."""
    if not key:
        return ""
    if len(key) <= len(API_KEY_PREFIX) + 4:
        return "****"
    return f"{key[: len(API_KEY_PREFIX)]}****{key[-4:]}"


def key_format_issue(key: str) -> str | None:
    """Cheap format check only. A well-formed prefix is not proof of validity."""
    if not key:
        return "no OrcaRouter API key is configured"
    if not key.startswith(API_KEY_PREFIX):
        return f"expected an OrcaRouter key beginning with '{API_KEY_PREFIX}'"
    return None


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_api_base(api_base: str) -> str:
    """Require HTTPS for remote origins; plain HTTP is allowed for loopback only."""
    parsed = urllib.parse.urlsplit(api_base)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("OrcaRouter API base must be an absolute http(s) URL")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise ValueError("OrcaRouter API base must use HTTPS outside loopback development")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("OrcaRouter API base must not contain credentials, query, or fragment")
    return api_base.rstrip("/")


def _env(candidates: Iterable[str]) -> str | None:
    for name in candidates:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def resolve_settings(
    *,
    api_key: str | None = None,
    model: str | None = None,
    api_base: str | None = None,
) -> OrcaRouterSettings:
    """Explicit arguments win over OrcaRouter-specific environment variables."""
    base = (api_base or "").strip() or _env(API_BASE_ENV_VARS) or DEFAULT_API_BASE
    key = (api_key or "").strip() or (_env(API_KEY_ENV_VARS) or "")
    selected_model = (model or "").strip() or (_env((MODEL_ENV_VAR,)) or DEFAULT_MODEL)
    return OrcaRouterSettings(api_base=validate_api_base(base), api_key=key, model=selected_model)


def _endpoint_types(record: dict[str, Any]) -> set[str]:
    raw = record.get("supported_endpoint_types") or record.get("supported_endpoint_type") or []
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(item) for item in raw if isinstance(item, str)}
    return set()


def _reasoning_efforts(record: dict[str, Any]) -> tuple[str, ...]:
    candidates = record.get("reasoning_efforts") or record.get("reasoning_levels")
    if isinstance(candidates, list):
        return tuple(str(item) for item in candidates if isinstance(item, str))
    supported = record.get("supports_reasoning")
    if supported is True and isinstance(record.get("reasoning"), dict):
        levels = record["reasoning"].get("efforts")
        if isinstance(levels, list):
            return tuple(str(item) for item in levels if isinstance(item, str))
    return ()


def _context_length(record: dict[str, Any]) -> int | None:
    raw = record.get("context_length") or record.get("context_window")
    if isinstance(raw, int) and raw > 0:
        return raw
    top = record.get("top_provider")
    if isinstance(top, dict):
        ctx = top.get("context_length")
        if isinstance(ctx, int) and ctx > 0:
            return ctx
    return None


def is_text_chat_model(record: dict[str, Any]) -> bool:
    """Fail closed: a record is text-capable only when it declares a text endpoint type."""
    endpoint_types = _endpoint_types(record)
    if not (endpoint_types & TEXT_ENDPOINT_TYPES):
        return False
    if endpoint_types & NON_TEXT_ENDPOINT_TYPES:
        # Dedicated generation/rerank models; never offer them to the text agent.
        return False
    architecture = record.get("architecture")
    if isinstance(architecture, dict):
        inputs = architecture.get("input_modalities")
        if isinstance(inputs, list) and "text" not in inputs:
            return False
        outputs = architecture.get("output_modalities")
        if isinstance(outputs, list) and "text" not in outputs:
            return False
    return True


def parse_catalog(payload: Any) -> tuple[CatalogModel, ...]:
    """Parse a ``GET /v1/models`` response into text-capable models."""
    if isinstance(payload, dict):
        items = payload.get("data")
    elif isinstance(payload, list):
        items = payload
    else:
        items = None
    if not isinstance(items, list):
        raise ValueError("model catalog response is not a data array")
    models: list[CatalogModel] = []
    seen: set[str] = set()
    for record in items[:CATALOG_MAX_ITEMS]:
        if not isinstance(record, dict):
            continue
        model_id = record.get("id")
        if not isinstance(model_id, str) or not model_id.strip() or model_id in seen:
            continue
        if not is_text_chat_model(record):
            continue
        seen.add(model_id)
        name = record.get("name")
        models.append(
            CatalogModel(
                id=model_id,
                name=name if isinstance(name, str) and name else model_id,
                context_length=_context_length(record),
                reasoning_efforts=_reasoning_efforts(record),
            )
        )
    return tuple(models)


def fetch_catalog(
    settings: OrcaRouterSettings,
    *,
    opener: Callable[..., Any] | None = None,
    timeout_s: float = CATALOG_TIMEOUT_S,
) -> tuple[CatalogModel, ...]:
    """Fetch and parse the live catalog. Raises on transport or shape errors."""
    query = urllib.parse.urlencode({"capability": "chat"})
    url = f"{settings.api_base.rstrip('/')}/models?{query}"
    headers = {"Accept": "application/json", "User-Agent": "LockKnife-Agent/1.4.0"}
    if settings.api_key:
        headers["Authorization"] = f"Bearer {settings.api_key}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    open_fn = opener or urllib.request.urlopen
    with open_fn(request, timeout=timeout_s) as response:  # nosec B310 - validated base URL
        raw = response.read(CATALOG_MAX_BYTES + 1)
    if len(raw) > CATALOG_MAX_BYTES:
        raise ValueError("model catalog response exceeded the size limit")
    return parse_catalog(json.loads(raw.decode("utf-8")))


class ModelCatalogCache:
    """Process-local cache: live result wins, last-known-good fills outages."""

    def __init__(self) -> None:
        self._last_good: dict[str, tuple[CatalogModel, ...]] = {}

    def last_known_good(self, api_base: str) -> tuple[CatalogModel, ...]:
        return self._last_good.get(api_base.rstrip("/"), ())

    def remember(self, api_base: str, models: tuple[CatalogModel, ...]) -> None:
        if models:
            self._last_good[api_base.rstrip("/")] = models

    def discover(self, settings: OrcaRouterSettings) -> CatalogResult:
        try:
            models = fetch_catalog(settings)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            return self._fallback(settings, f"catalog request failed ({type(exc).__name__})")
        except (ValueError, json.JSONDecodeError) as exc:
            return self._fallback(settings, f"catalog response invalid ({exc})")
        if not models:
            return self._fallback(settings, "catalog returned no text-capable models")
        self.remember(settings.api_base, models)
        return CatalogResult(models=models, source="live")

    def _fallback(self, settings: OrcaRouterSettings, detail: str) -> CatalogResult:
        last = self.last_known_good(settings.api_base)
        if last:
            return CatalogResult(models=last, source="last-known-good", detail=detail)
        return CatalogResult(models=VERIFIED_SEED, source="seed", detail=detail)


def ensure_model_supported(model: str, models: Iterable[CatalogModel]) -> tuple[bool, str | None]:
    """Return (ok, reason). The previous value is cleared when it is not compatible."""
    ids = {item.id for item in models}
    if model in ids:
        return True, None
    return False, (
        f"model '{model}' is not in the current OrcaRouter text catalog; "
        f"choose one of: {', '.join(sorted(ids)[:8])}"
    )


def describe_catalog(result: CatalogResult) -> dict[str, Any]:
    """JSON-safe catalog payload for CLI output."""
    return {
        "provider": PROVIDER_ID,
        "label": PROVIDER_LABEL,
        "catalog_source": result.source,
        "degraded": result.degraded,
        "detail": result.detail,
        "model_count": len(result.models),
        "default_model": DEFAULT_MODEL,
        "cyber_models": [m for m in CYBER_MODELS if any(x.id == m for x in result.models)],
        "models": [item.to_dict() for item in result.models],
    }


def print_catalog(result: CatalogResult) -> None:
    """Human-readable catalog listing via the project console."""
    from lockknife.core.output import console

    console.print(
        f"{PROVIDER_LABEL} — {len(result.models)} text models "
        f"(catalog source: {result.source}{'; ' + result.detail if result.detail else ''})"
    )
    for item in result.models:
        marker = " (default)" if item.id == DEFAULT_MODEL else ""
        console.print(f"  {item.id}{marker} — {item.name}")
