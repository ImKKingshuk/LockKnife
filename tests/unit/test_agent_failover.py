from __future__ import annotations

from unittest.mock import MagicMock

from lockknife.core.agent.failover import FailoverProvider
from lockknife.core.agent.models import ModelDecision


def test_failover_provider_fallback_on_error():
    # Primary returns API error
    mock_primary = MagicMock()
    mock_primary.complete.return_value = ModelDecision.finish("LLM API Error (HTTP 429): Rate limit exceeded")

    # Secondary succeeds
    mock_secondary = MagicMock()
    mock_secondary.complete.return_value = ModelDecision.respond("Secondary model response.")

    failover = FailoverProvider([mock_primary, mock_secondary])
    decision = failover.complete([{"role": "user", "content": "hello"}])

    assert decision.text == "Secondary model response."
    assert failover.failover_count == 1
    mock_primary.complete.assert_called_once()
    mock_secondary.complete.assert_called_once()


def test_failover_provider_circuit_breaker():
    # Provider always throws
    mock_bad = MagicMock()
    mock_bad.complete.side_effect = RuntimeError("Connection timeout")

    failover = FailoverProvider([mock_bad], max_consecutive_errors=2)

    # Error 1
    d1 = failover.complete([{"role": "user", "content": "1"}])
    assert not failover.circuit_tripped

    # Error 2: Trips circuit breaker
    d2 = failover.complete([{"role": "user", "content": "2"}])
    assert failover.circuit_tripped
    assert "Circuit breaker tripped" in d2.text

    # Subsequent call immediately rejected
    d3 = failover.complete([{"role": "user", "content": "3"}])
    assert "Circuit breaker tripped" in d3.text
