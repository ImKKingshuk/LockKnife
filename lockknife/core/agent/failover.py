from __future__ import annotations

import logging
import time
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
        cooldown_s: float = 60.0,
    ) -> None:
        if not providers:
            raise ValueError("FailoverProvider requires at least one provider")
        self.providers = list(providers)
        self.max_consecutive_errors = max_consecutive_errors
        self.cooldown_s = cooldown_s
        self.consecutive_errors = 0
        self.circuit_tripped = False
        self.last_tripped_at = 0.0
        self.failover_count = 0

    def reset(self) -> None:
        """Manually reset the circuit breaker and consecutive error counter."""
        self.circuit_tripped = False
        self.consecutive_errors = 0
        self.last_tripped_at = 0.0
        logger.info("FailoverProvider circuit breaker and error counters manually reset.")

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> ModelDecision:
        now = time.time()
        if self.circuit_tripped:
            if now - self.last_tripped_at >= self.cooldown_s:
                logger.info(
                    "Circuit breaker cooldown elapsed (%.1fs). Entering half-open trial state.",
                    self.cooldown_s,
                )
            else:
                remaining = int(self.cooldown_s - (now - self.last_tripped_at))
                return ModelDecision.finish(
                    f"Circuit breaker tripped: Model requests halted due to excessive consecutive provider failures (cooldown remaining: {remaining}s).",
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
                self.circuit_tripped = False
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
            self.last_tripped_at = time.time()
            logger.critical("Circuit breaker tripped: %d consecutive failures.", self.consecutive_errors)
            return ModelDecision.finish(
                f"Circuit breaker tripped after {self.consecutive_errors} consecutive failures: {last_error}",
                reasoning="All providers exhausted and threshold reached.",
            )

        return ModelDecision.finish(
            f"All providers in failover ladder failed. Last error: {last_error}",
            reasoning="Failover ladder exhausted.",
        )
