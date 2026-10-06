from __future__ import annotations

import dataclasses
import json
import logging
import os
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any, Protocol

from lockknife.core.agent.models import ModelDecision, ToolInvocation

logger = logging.getLogger("lockknife.agent.provider")


@dataclasses.dataclass(frozen=True)
class ProviderConfig:
    """Configuration parameters for the LLM Provider."""
    api_base: str = "http://localhost:11434/v1"
    api_key: str = ""
    model_name: str = "qwen2.5:latest"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout_s: float = 60.0

    @classmethod
    def from_env(cls) -> ProviderConfig:
        """Infer configuration from environment variables."""
        api_base = (
            os.getenv("LOCKKNIFE_AI_BASE")
            or os.getenv("OPENAI_BASE_URL")
            or os.getenv("OPENAI_API_BASE")
            or "http://localhost:11434/v1"
        )
        api_key = (
            os.getenv("LOCKKNIFE_AI_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        )
        model = (
            os.getenv("LOCKKNIFE_AI_MODEL")
            or os.getenv("OPENAI_MODEL")
            or "qwen2.5:latest"
        )
        return cls(api_base=api_base.rstrip("/"), api_key=api_key, model_name=model)


class LLMProvider(Protocol):
    """Protocol for models generating agent decisions."""

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> ModelDecision: ...


class OpenAICompatibleProvider:
    """Universal provider for Ollama, vLLM, OpenAI, Groq, DeepSeek, and LocalAI."""

    def __init__(self, config: ProviderConfig | None = None) -> None:
        self.config = config or ProviderConfig.from_env()

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> ModelDecision:
        formatted_messages: list[dict[str, Any]] = []
        if system_prompt:
            formatted_messages.append({"role": "system", "content": system_prompt})
        formatted_messages.extend(messages)

        payload: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": formatted_messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        endpoint = f"{self.config.api_base.rstrip('/')}/chat/completions"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "LockKnife-Agent/1.4.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        body_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=body_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as response:  # nosec B310
                res_body = response.read().decode("utf-8")
                data = json.loads(res_body)
        except urllib.error.HTTPError as exc:
            err_msg = exc.read().decode("utf-8", errors="replace")
            logger.error("Provider HTTP %s: %s", exc.code, err_msg)
            return ModelDecision.finish(
                f"LLM API Error (HTTP {exc.code}): {err_msg}",
                reasoning=f"Provider endpoint {endpoint} failed",
            )
        except Exception as exc:
            logger.error("Provider connection error: %s", exc)
            return ModelDecision.finish(
                f"Provider Connection Failure: {exc}",
                reasoning=f"Failed to communicate with {endpoint}",
            )

        choices = data.get("choices") or []
        if not choices:
            return ModelDecision.finish("Empty choices received from provider.")

        choice = choices[0]
        message = choice.get("message") or {}
        tool_calls_raw = message.get("tool_calls") or []

        if tool_calls_raw:
            parsed_calls: list[ToolInvocation] = []
            for item in tool_calls_raw:
                call_id = str(item.get("id") or str(uuid.uuid4())[:8])
                fn = item.get("function") or {}
                name = str(fn.get("name") or "")
                raw_args = fn.get("arguments") or "{}"
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except Exception:
                        args = {"raw": raw_args}
                elif isinstance(raw_args, dict):
                    args = raw_args
                else:
                    args = {}
                parsed_calls.append(ToolInvocation(call_id=call_id, tool_id=name, arguments=args))

            content = str(message.get("content") or "")
            return ModelDecision.call_tools(parsed_calls, reasoning=content or None)

        content = str(message.get("content") or "")
        return ModelDecision.respond(content)


class DeterministicMockProvider:
    """Mock provider for unit tests and deterministic simulated investigations."""

    def __init__(
        self,
        scripted_decisions: list[ModelDecision] | None = None,
        decision_hook: Callable[[list[dict[str, Any]]], ModelDecision] | None = None,
    ) -> None:
        self._scripted = list(scripted_decisions or [])
        self._hook = decision_hook
        self.call_history: list[dict[str, Any]] = []

    def queue_decision(self, decision: ModelDecision) -> None:
        self._scripted.append(decision)

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> ModelDecision:
        self.call_history.append(
            {"messages": messages, "tools": tools, "system_prompt": system_prompt}
        )
        if self._hook is not None:
            return self._hook(messages)
        if self._scripted:
            return self._scripted.pop(0)
        return ModelDecision.finish("Default mock termination: Goal achieved.")
