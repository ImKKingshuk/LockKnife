from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from lockknife.core.agent.models import DecisionKind, ModelDecision, ToolInvocation
from lockknife.core.agent.provider import (
    DeterministicMockProvider,
    OpenAICompatibleProvider,
    ProviderConfig,
)


def test_provider_config_from_env(monkeypatch):
    monkeypatch.setenv("LOCKKNIFE_AI_BASE", "http://ollama:11434/v1")
    monkeypatch.setenv("LOCKKNIFE_AI_KEY", "secret-key")
    monkeypatch.setenv("LOCKKNIFE_AI_MODEL", "llama3.3:70b")

    cfg = ProviderConfig.from_env()
    assert cfg.api_base == "http://ollama:11434/v1"
    assert cfg.api_key == "secret-key"
    assert cfg.model_name == "llama3.3:70b"


def test_deterministic_mock_provider():
    d1 = ModelDecision.call_tools([ToolInvocation(call_id="1", tool_id="tool_a")])
    d2 = ModelDecision.finish("All done")
    provider = DeterministicMockProvider([d1, d2])

    res1 = provider.complete([{"role": "user", "content": "hi"}])
    assert res1.kind == DecisionKind.TOOL_CALL
    assert res1.tool_calls[0].tool_id == "tool_a"

    res2 = provider.complete([{"role": "user", "content": "next"}])
    assert res2.kind == DecisionKind.FINISH
    assert res2.text == "All done"

    # Default fallback once exhausted
    res3 = provider.complete([{"role": "user", "content": "extra"}])
    assert res3.kind == DecisionKind.FINISH


def test_openai_compatible_provider_parses_tool_calls():
    provider = OpenAICompatibleProvider(
        ProviderConfig(api_base="http://localhost:11434/v1", model_name="qwen2.5")
    )

    mock_response_payload = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Let me check device health first.",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "core.health",
                                "arguments": json.dumps({"detailed": True}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_response_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        decision = provider.complete([{"role": "user", "content": "run audit"}])
        assert decision.is_tool_call
        assert len(decision.tool_calls) == 1
        assert decision.tool_calls[0].call_id == "call_123"
        assert decision.tool_calls[0].tool_id == "core.health"
        assert decision.tool_calls[0].arguments == {"detailed": True}
        assert decision.reasoning == "Let me check device health first."
