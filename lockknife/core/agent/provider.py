from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any, Protocol

from lockknife.core.agent import orcarouter
from lockknife.core.agent.models import ModelDecision, ToolInvocation

logger = logging.getLogger("lockknife.agent.provider")

# Named providers that LockKnife can select without a generic base URL.
KNOWN_PROVIDER_IDS = (orcarouter.PROVIDER_ID,)



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
        api_key = os.getenv("LOCKKNIFE_AI_KEY") or os.getenv("OPENAI_API_KEY") or ""
        model = os.getenv("LOCKKNIFE_AI_MODEL") or os.getenv("OPENAI_MODEL") or "qwen2.5:latest"
        return cls(api_base=api_base.rstrip("/"), api_key=api_key, model_name=model)

    @classmethod
    def for_orcarouter(
        cls,
        *,
        api_key: str | None = None,
        model: str | None = None,
        api_base: str | None = None,
    ) -> ProviderConfig:
        """Build a config for the named OrcaRouter Cyber Inference provider."""
        settings = orcarouter.resolve_settings(api_key=api_key, model=model, api_base=api_base)
        return cls(
            api_base=settings.api_base,
            api_key=settings.api_key,
            model_name=settings.model,
        )

    @classmethod
    def from_cli(
        cls,
        *,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        api_base: str | None = None,
    ) -> ProviderConfig:
        """Resolve a provider name plus explicit overrides into a configuration.

        ``--provider`` is required whenever the config comes from a named provider
        preset, so a copied command cannot silently leave the project default in
        place. Without a provider name the historical env/flag resolution applies.
        """
        if provider == orcarouter.PROVIDER_ID:
            return cls.for_orcarouter(api_key=api_key, model=model, api_base=api_base)
        cfg = cls.from_env()
        if api_base:
            cfg = dataclasses.replace(cfg, api_base=api_base.rstrip("/"))
        if api_key:
            cfg = dataclasses.replace(cfg, api_key=api_key)
        if model:
            cfg = dataclasses.replace(cfg, model_name=model)
        return cfg

    @property
    def is_orcarouter(self) -> bool:
        return self.api_base.rstrip("/") == orcarouter.DEFAULT_API_BASE


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
        reserved_names = {tool["function"]["name"] for tool in tools or []}

        def alias(name: str) -> str:
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
                return name
            candidate = "lk_" + hashlib.sha256(name.encode()).hexdigest()[:60]
            suffix = 0
            while candidate in reserved_names:
                suffix += 1
                candidate = "lk_" + hashlib.sha256(f"{name}:{suffix}".encode()).hexdigest()[:60]
            return candidate

        selected_tools = copy.deepcopy(tools or [])
        overflow: dict[str, dict[str, Any]] = {}
        overflow_alias = ""
        if len(selected_tools) > 128:
            overflow = {t["function"]["name"]: t for t in selected_tools[127:]}
            overflow_alias = "lk_overflow"
            while any(t["function"]["name"] == overflow_alias for t in selected_tools):
                overflow_alias = (
                    "lk_overflow_" + hashlib.sha256(overflow_alias.encode()).hexdigest()[:48]
                )
            selected_tools = selected_tools[:127] + [
                {
                    "type": "function",
                    "function": {
                        "name": overflow_alias,
                        "description": "Invoke a remaining LockKnife action. Action schemas: "
                        + json.dumps(overflow),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string", "enum": list(overflow)},
                                "arguments": {"type": "object"},
                            },
                            "required": ["action", "arguments"],
                        },
                    },
                }
            ]
        names = {alias(t["function"]["name"]): t["function"]["name"] for t in selected_tools}
        if len(names) != len(selected_tools):
            return ModelDecision.failure("Duplicate provider function aliases")
        for tool in selected_tools:
            tool["function"]["name"] = alias(tool["function"]["name"])
        formatted_messages: list[dict[str, Any]] = []
        if system_prompt:
            formatted_messages.append({"role": "system", "content": system_prompt})
        history = copy.deepcopy(messages)
        for message in history:
            for call in message.get("tool_calls", []):
                function = call["function"]
                if function["name"] in overflow:
                    function["arguments"] = json.dumps(
                        {
                            "action": function["name"],
                            "arguments": json.loads(function["arguments"]),
                        }
                    )
                    function["name"] = overflow_alias
                else:
                    function["name"] = alias(function["name"])
        formatted_messages.extend(history)

        payload: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": formatted_messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            payload["tools"] = selected_tools
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

        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_s) as response:  # nosec B310
                    data = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if attempt < 2 and (exc.code == 429 or exc.code >= 500):
                    exc.close()
                    time.sleep(0.1 * (2**attempt))
                    continue
                exc.close()
                if exc.code == 401:
                    return ModelDecision.failure(
                        "LLM API Error (HTTP 401 - the API key was rejected or revoked)"
                    )
                return ModelDecision.failure(f"LLM API Error (HTTP {exc.code})")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(0.1 * (2**attempt))
                    continue
                return ModelDecision.failure(f"Provider connection failure: {type(exc).__name__}")
            except (ValueError, TypeError):
                return ModelDecision.failure("Invalid JSON response from provider")

        if not isinstance(data, dict):
            return ModelDecision.failure("Invalid provider response object")
        choices = data.get("choices") or []
        if not choices:
            return ModelDecision.failure("Empty choices received from provider.")

        if not isinstance(choices, list) or not isinstance(choices[0], dict):
            return ModelDecision.failure("Invalid provider choices")
        choice = choices[0]
        message = choice.get("message") or {}
        if not isinstance(message, dict):
            return ModelDecision.failure("Invalid provider message")
        tool_calls_raw = message.get("tool_calls") or []
        if not isinstance(tool_calls_raw, list):
            return ModelDecision.failure("Invalid provider tool calls")

        if tool_calls_raw:
            parsed_calls: list[ToolInvocation] = []
            for item in tool_calls_raw:
                if not isinstance(item, dict) or not isinstance(item.get("function"), dict):
                    return ModelDecision.failure("Invalid provider tool call")
                call_id = str(item.get("id") or str(uuid.uuid4())[:8])
                fn = item.get("function") or {}
                name = str(fn.get("name") or "")
                if name not in names:
                    return ModelDecision.failure("Provider returned an unadvertised tool")
                name = names[name]
                raw_args = fn.get("arguments") or "{}"
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except (ValueError, TypeError):
                        return ModelDecision.failure("Provider returned invalid tool arguments")
                elif isinstance(raw_args, dict):
                    args = raw_args
                else:
                    return ModelDecision.failure("Provider returned invalid tool arguments")
                if not isinstance(args, dict):
                    return ModelDecision.failure("Provider tool arguments must be an object")
                if name == overflow_alias:
                    action = args.get("action")
                    if not isinstance(action, str) or action not in overflow:
                        return ModelDecision.failure("Provider returned an unadvertised action")
                    name = action
                    args = args.get("arguments")
                    if not isinstance(args, dict):
                        return ModelDecision.failure("Provider action arguments must be an object")
                parsed_calls.append(ToolInvocation(call_id=call_id, tool_id=name, arguments=args))

            content = str(message.get("content") or "")
            return ModelDecision.call_tools(parsed_calls, reasoning=content or None)

        content = str(message.get("content") or "")
        if choice.get("finish_reason") == "length":
            return ModelDecision.continue_run(content)
        if not content:
            return ModelDecision.failure("Provider returned an empty response")
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
