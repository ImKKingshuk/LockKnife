from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from typing import Any

import pytest
from click.testing import CliRunner

from lockknife.core.agent import orcarouter
from lockknife.core.agent.models import DecisionKind
from lockknife.core.agent.provider import OpenAICompatibleProvider, ProviderConfig
from lockknife_headless_cli import _tui_callback_agent as agent_cb
from lockknife_headless_cli.agent import agent_group
from lockknife_headless_cli.tui_callback import build_tui_callback

FAKE_KEY = "sk-orca-" + "test" * 8


def _record(model_id: str, endpoint_types: list[str], **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {"id": model_id, "supported_endpoint_types": endpoint_types}
    record.update(extra)
    return record


LIVE_PAYLOAD = {
    "data": [
        _record(
            "openai/gpt-5.5",
            ["openai", "openai-response"],
            context_length=400000,
            reasoning_efforts=["low", "medium", "high", "xhigh"],
        ),
        _record(
            "anthropic/claude-opus-4.8",
            ["anthropic"],
            architecture={"input_modalities": ["text", "image"], "output_modalities": ["text"]},
        ),
        _record("google/gemini-3.5-flash", ["gemini"]),
        _record("orcarouter/auto", ["openai"]),
        _record("black-forest-labs/flux-2", ["image-generation"]),
        _record("openai/sora-3", ["openai-video"]),
        _record("jina/reranker-v3", ["jina-rerank"]),
        _record("openai/text-embedding-4", ["embeddings"]),
        {"id": "undeclared/model"},
        "not-a-record",
        _record("audio/only", ["openai"], architecture={"input_modalities": ["audio"]}),
        _record("orcarouter/auto", ["openai"]),
    ]
}


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _size: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def _fake_opener(
    calls: list[urllib.request.Request], payload: Any = LIVE_PAYLOAD, status: int = 200
):
    body = json.dumps(payload).encode()

    def opener(request: urllib.request.Request, timeout: float = 0) -> _FakeResponse:
        calls.append(request)
        if status != 200:
            raise urllib.error.HTTPError(request.full_url, status, "err", {}, None)  # type: ignore[arg-type]
        return _FakeResponse(body)

    return opener


def _json_from_output(output: str) -> dict[str, Any]:
    """Extract the JSON document from CLI output that may also carry log lines."""
    start = output.index("{\n")
    return json.loads(output[start : output.rindex("}") + 1])


# ---------------------------------------------------------------- config seams


def test_settings_resolve_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORCAROUTER_API_BASE", raising=False)
    monkeypatch.delenv("ORCA_API_BASE", raising=False)
    monkeypatch.delenv("ORCAROUTER_MODEL", raising=False)
    monkeypatch.setenv("ORCAROUTER_API_KEY", FAKE_KEY)
    settings = orcarouter.resolve_settings()
    assert settings.api_base == "https://api.orcarouter.ai/v1"
    assert settings.api_key == FAKE_KEY
    assert settings.model == "orcarouter/auto"


def test_explicit_values_win_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCAROUTER_API_BASE", "https://api.orcarouter.ai/v1")
    monkeypatch.setenv("ORCAROUTER_MODEL", "openai/gpt-5.5")
    settings = orcarouter.resolve_settings(
        model="orcarouter/fusion", api_base="https://gateway.example.test/v1", api_key="k"
    )
    assert settings.api_base == "https://gateway.example.test/v1"
    assert settings.model == "orcarouter/fusion"


def test_remote_http_base_rejected_but_loopback_allowed() -> None:
    with pytest.raises(ValueError):
        orcarouter.validate_api_base("http://api.orcarouter.ai/v1")
    assert orcarouter.validate_api_base("http://127.0.0.1:8080/v1") == "http://127.0.0.1:8080/v1"
    with pytest.raises(ValueError):
        orcarouter.validate_api_base("https://user:pass@api.orcarouter.ai/v1")


def test_provider_config_from_cli_selects_named_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCKKNIFE_AI_BASE", "http://ollama:11434/v1")
    cfg = ProviderConfig.from_cli(provider="orcarouter", api_key="k1")
    assert cfg.api_base == orcarouter.DEFAULT_API_BASE
    assert cfg.model_name == "orcarouter/auto"
    assert cfg.is_orcarouter
    legacy = ProviderConfig.from_cli()
    assert legacy.api_base == "http://ollama:11434/v1"


def test_key_masking_and_format_hint() -> None:
    hint = orcarouter.mask_api_key(FAKE_KEY)
    assert hint.startswith("sk-orca-****")
    assert FAKE_KEY not in hint
    assert orcarouter.key_format_issue("sk-orca-abc") is None
    assert orcarouter.key_format_issue("sk-other") is not None


# ------------------------------------------------------------ catalog parsing


def test_parse_catalog_filters_non_text_and_undeclared() -> None:
    models = orcarouter.parse_catalog(LIVE_PAYLOAD)
    ids = [m.id for m in models]
    assert ids == [
        "openai/gpt-5.5",
        "anthropic/claude-opus-4.8",
        "google/gemini-3.5-flash",
        "orcarouter/auto",
    ]
    gpt = models[0]
    assert gpt.context_length == 400000
    assert gpt.reasoning_efforts == ("low", "medium", "high", "xhigh")


def test_parse_catalog_fails_closed_by_attachment_need() -> None:
    models = orcarouter.parse_catalog(LIVE_PAYLOAD)
    image_input_ids = {m.id for m in models if m.id == "anthropic/claude-opus-4.8"}
    assert image_input_ids == {"anthropic/claude-opus-4.8"}
    assert "audio/only" not in {m.id for m in models}
    assert "undeclared/model" not in {m.id for m in models}


def test_parse_catalog_rejects_non_list() -> None:
    with pytest.raises(ValueError):
        orcarouter.parse_catalog({"error": "boom"})


def test_live_discovery_wins_and_authoritative() -> None:
    calls: list[urllib.request.Request] = []
    cache = orcarouter.ModelCatalogCache()
    settings = orcarouter.OrcaRouterSettings(api_key=FAKE_KEY)
    real_opener = urllib.request.urlopen
    urllib.request.urlopen = _fake_opener(calls)  # type: ignore[assignment]
    try:
        result = cache.discover(settings)
    finally:
        urllib.request.urlopen = real_opener  # type: ignore[assignment]
    assert result.source == "live"
    assert result.degraded is False
    assert [m.id for m in result.models][-1] == "orcarouter/auto"
    request = calls[0]
    assert request.full_url.startswith("https://api.orcarouter.ai/v1/models?")
    assert "capability=chat" in request.full_url
    assert request.get_header("Authorization") == f"Bearer {FAKE_KEY}"


def test_outage_falls_back_to_seed_with_metadata() -> None:
    cache = orcarouter.ModelCatalogCache()

    def broken(request: urllib.request.Request, timeout: float = 0) -> _FakeResponse:
        raise urllib.error.URLError("down")

    real_opener = urllib.request.urlopen
    urllib.request.urlopen = broken  # type: ignore[assignment]
    try:
        result = cache.discover(orcarouter.OrcaRouterSettings(api_key=FAKE_KEY))
    finally:
        urllib.request.urlopen = real_opener  # type: ignore[assignment]
    assert result.source == "seed"
    assert result.degraded is True
    ids = [m.id for m in result.models]
    assert "orcarouter/fusion" in ids
    gpt = next(m for m in result.models if m.id == "openai/gpt-5.5")
    assert gpt.reasoning_efforts == ("low", "medium", "high", "xhigh")
    assert gpt.context_length == 400000


def test_outage_after_success_uses_last_known_good() -> None:
    cache = orcarouter.ModelCatalogCache()
    cache.remember(orcarouter.DEFAULT_API_BASE, orcarouter.parse_catalog(LIVE_PAYLOAD))
    real_opener = urllib.request.urlopen
    urllib.request.urlopen = _fake_opener([], status=500)  # type: ignore[assignment]
    try:
        result = cache.discover(orcarouter.OrcaRouterSettings())
    finally:
        urllib.request.urlopen = real_opener  # type: ignore[assignment]
    assert result.source == "last-known-good"
    assert [m.id for m in result.models][0] == "openai/gpt-5.5"


def test_stale_model_is_reported_and_resets_to_default() -> None:
    models = orcarouter.VERIFIED_SEED
    ok, reason = orcarouter.ensure_model_supported("openai/gpt-5.5", models)
    assert ok and reason is None
    ok, reason = orcarouter.ensure_model_supported("legacy/model-1", models)
    assert not ok and reason is not None and "legacy/model-1" in reason


# ------------------------------------------------------------- provider call


def test_provider_request_goes_to_orcarouter_with_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []

    def opener(request: urllib.request.Request, timeout: float = 0) -> _FakeResponse:
        captured.append(request)
        return _FakeResponse(
            json.dumps(
                {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
            ).encode()
        )

    monkeypatch.setattr(urllib.request, "urlopen", opener)
    cfg = ProviderConfig.for_orcarouter(api_key=FAKE_KEY)
    decision = OpenAICompatibleProvider(cfg).complete([{"role": "user", "content": "hi"}])
    assert decision.kind == DecisionKind.RESPOND
    request = captured[0]
    assert request.full_url == "https://api.orcarouter.ai/v1/chat/completions"
    assert request.get_header("Authorization") == f"Bearer {FAKE_KEY}"
    body = json.loads(request.data.decode())
    assert body["model"] == "orcarouter/auto"


def test_revoked_key_401_is_terminal_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def opener(request: urllib.request.Request, timeout: float = 0):
        attempts.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", opener)
    cfg = ProviderConfig.for_orcarouter(api_key=FAKE_KEY)
    decision = OpenAICompatibleProvider(cfg).complete([{"role": "user", "content": "hi"}])
    assert decision.kind == DecisionKind.ERROR
    assert len(attempts) == 1
    assert "401" in decision.text
    assert "revoked" in decision.text
    assert FAKE_KEY not in decision.text


# ------------------------------------------------------------------- CLI/TUI


def test_cli_models_uses_live_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_opener(calls))
    monkeypatch.setenv("ORCAROUTER_API_KEY", FAKE_KEY)
    import lockknife_headless_cli.agent as agent_mod

    monkeypatch.setattr(agent_mod, "_ORCAROUTER_CATALOG", orcarouter.ModelCatalogCache())
    result = CliRunner().invoke(
        agent_group, ["models", "--provider", "orcarouter", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = _json_from_output(result.output)
    assert payload["catalog_source"] == "live"
    ids = [m["id"] for m in payload["models"]]
    assert "orcarouter/auto" in ids
    assert not {"black-forest-labs/flux-2", "openai/sora-3", "jina/reranker-v3"} & set(ids)
    assert FAKE_KEY not in result.output


def test_cli_models_degraded_seed_on_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(request: urllib.request.Request, timeout: float = 0):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(urllib.request, "urlopen", broken)
    import lockknife_headless_cli.agent as agent_mod

    monkeypatch.setattr(agent_mod, "_ORCAROUTER_CATALOG", orcarouter.ModelCatalogCache())
    result = CliRunner().invoke(agent_group, ["models", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = _json_from_output(result.output)
    assert payload["catalog_source"] == "seed"
    assert payload["degraded"] is True
    assert {m["id"] for m in payload["models"]} == {m.id for m in orcarouter.VERIFIED_SEED}


def test_cli_goal_orcarouter_incompatible_model_resets(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_opener(calls))
    import lockknife_headless_cli.agent as agent_mod

    monkeypatch.setattr(agent_mod, "_ORCAROUTER_CATALOG", orcarouter.ModelCatalogCache())
    created: list[ProviderConfig] = []

    def make_provider(cfg: ProviderConfig):
        created.append(cfg)
        from lockknife.core.agent import DeterministicMockProvider

        return DeterministicMockProvider()

    monkeypatch.setattr(agent_mod, "OpenAICompatibleProvider", make_provider)
    result = CliRunner().invoke(
        agent_group,
        [
            "goal",
            "triage",
            "--provider",
            "orcarouter",
            "--model",
            "nonexistent/model",
            "--budget",
            "1",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    assert created and created[0].model_name == "orcarouter/auto"
    assert created[0].api_base == orcarouter.DEFAULT_API_BASE


def test_tui_callback_provider_orcarouter_and_models(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_opener(calls))
    monkeypatch.setattr(agent_cb, "_orcarouter_catalog", None)
    from lockknife.core.agent import DeterministicMockProvider

    created: list[ProviderConfig] = []

    def make_provider(cfg: ProviderConfig):
        created.append(cfg)
        return DeterministicMockProvider()

    monkeypatch.setattr("lockknife.core.agent.OpenAICompatibleProvider", make_provider)
    callback = build_tui_callback(None)
    listing = callback("agent.models", {"provider": "orcarouter"})
    assert listing["ok"]
    payload = json.loads(listing["data_json"])
    assert payload["catalog_source"] == "live"
    assert payload["model_count"] == 4

    chat = callback("agent.chat", {"prompt": "status", "provider": "orcarouter"})
    assert chat["ok"]
    assert created[0].model_name == "orcarouter/auto"
    assert created[0].api_base == orcarouter.DEFAULT_API_BASE

    unknown = callback("agent.chat", {"prompt": "status", "provider": "mystery"})
    assert not unknown["ok"]


def test_legacy_path_unchanged_without_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCKKNIFE_AI_BASE", "http://ollama:11434/v1")
    monkeypatch.delenv("ORCAROUTER_API_BASE", raising=False)
    agent_cb._close_chat_sessions()
    cfg = agent_cb._resolve_provider_config(provider_id=None, model="llama3.3:70b")
    assert dataclasses.asdict(cfg)["api_base"] == "http://ollama:11434/v1"
    assert cfg.model_name == "llama3.3:70b"
