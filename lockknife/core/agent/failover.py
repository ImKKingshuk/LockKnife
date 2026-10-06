from __future__ import annotations

import logging
from typing import Any

from lockknife.core.agent.models import ModelDecision
from lockknife.core.agent.provider import LLMProvider

logger = logging.getLogger("lockknife.agent.failover")


class FailoverProvider:
    """Resilient provider ladder with automated fallback and safety circuit breaker."""

    def __init__(
        self,
        providers: list[LLMProvider],
        max_consecutive_errors: int = 5,
    ) -> None:
        if not providers:
            raise ValueError("FailoverProvider requires at least one provider")
        self.providers = list(providers)
        self.max_consecutive_errors = max_consecutive_errors
        self.consecutive_errors = 0
        self.circuit_tripped = False
        self.failover_count = 0

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> ModelDecision:
        if self.circuit_tripped:
            return ModelDecision.finish(
                "Circuit breaker tripped: Model requests halted due to excessive consecutive provider failures.",
                reasoning="Circuit breaker active.",
            )

        last_error = ""

        for idx, provider in enumerate(self.providers):
            try:
                decision = provider.complete(messages, tools, system_prompt)

                # Check if decision text indicates an API-level error
                if decision.is_terminal and any(
                    err in decision.text.lower()
                    for err in ("llm api error", "provider connection failure", "quota exceeded")
                ):
                    logger.warning(
                        "Provider #%d failed with API error: %s. Failing over...",
                        idx + 1,
                        decision.text[:120],
                    )
                    last_error = decision.text
                    self.failover_count += 1
                    continue

                # Successful completion
                self.consecutive_errors = 0
                return decision

            except Exception as exc:
                logger.warning(
                    "Provider #%d raised exception: %s. Failing over...", idx + 1, exc
                )
                last_error = str(exc)
                self.failover_count += 1
                continue

        # All providers failed
        self.consecutive_errors += 1
        if self.consecutive_errors >= self.max_consecutive_errors:
            self.circuit_tripped = True
            logger.critical("Circuit breaker tripped: %d consecutive failures.", self.consecutive_errors)
            return ModelDecision.finish(
                f"Circuit breaker tripped after {self.consecutive_errors} consecutive failures: {last_error}",
                reasoning="All providers exhausted and threshold reached.",
            )

        return ModelDecision.finish(
            f"All providers in failover ladder failed. Last error: {last_error}",
            reasoning="Failover ladder exhausted.",
        )
