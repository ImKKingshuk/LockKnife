"""Unit tests for rate limiter."""

import time

from lockknife.core.rate_limiter import (
    RateLimiter,
    TokenBucket,
    get_rate_limiter,
    reset_rate_limiter,
)


def test_token_bucket_acquire() -> None:
    """Test token bucket basic acquisition."""
    bucket = TokenBucket(capacity=5, refill_rate=1.0)
    assert bucket.acquire(timeout_s=1.0)
    assert bucket.tokens == 4.0


def test_token_bucket_refill() -> None:
    """Test token bucket refill over time."""
    bucket = TokenBucket(capacity=5, refill_rate=10.0)
    # Drain all tokens
    for _ in range(5):
        bucket.acquire(timeout_s=1.0)
    # Allow for small floating point error
    assert bucket.tokens < 0.1
    # Wait for refill
    time.sleep(0.2)
    bucket.acquire(timeout_s=1.0)
    # Should have refilled ~2 tokens (0.2s * 10/s)
    assert bucket.tokens > 0.0


def test_token_bucket_timeout() -> None:
    """Test token bucket timeout when empty."""
    bucket = TokenBucket(capacity=1, refill_rate=0.1)
    bucket.acquire(timeout_s=1.0)
    assert bucket.tokens == 0.0
    # Should timeout since refill rate is very slow
    assert not bucket.acquire(timeout_s=0.1)


def test_rate_limiter_acquire() -> None:
    """Test rate limiter acquisition."""
    limiter = RateLimiter(per_device_limit=10, global_limit=50)
    assert limiter.acquire("device1", timeout_s=1.0)


def test_rate_limiter_per_device_limit() -> None:
    """Test per-device rate limiting."""
    limiter = RateLimiter(per_device_limit=2, global_limit=100)
    # Acquire 2 tokens for device1
    assert limiter.acquire("device1", timeout_s=1.0)
    assert limiter.acquire("device1", timeout_s=1.0)
    # Third should timeout
    assert not limiter.acquire("device1", timeout_s=0.1)


def test_rate_limiter_global_limit() -> None:
    """Test global rate limiting."""
    limiter = RateLimiter(per_device_limit=100, global_limit=2)
    # Acquire 2 tokens globally
    assert limiter.acquire("device1", timeout_s=1.0)
    assert limiter.acquire("device2", timeout_s=1.0)
    # Third should timeout due to global limit
    assert not limiter.acquire("device3", timeout_s=0.1)


def test_rate_limiter_wrap() -> None:
    """Test rate limiter decorator wrapper."""
    limiter = RateLimiter(per_device_limit=10, global_limit=50)

    @limiter.wrap("device1")
    def test_func(x: int) -> int:
        return x * 2

    assert test_func(5) == 10


def test_rate_limiter_wrap_timeout() -> None:
    """Test rate limiter decorator timeout."""
    # Use very low refill rate to ensure bucket doesn't refill during test
    limiter = RateLimiter(per_device_limit=1, global_limit=1)
    # Manually set refill rate to 0 to prevent refill during test
    limiter.per_device_buckets["device1"] = TokenBucket(1, 0.0)
    limiter.global_bucket = TokenBucket(1, 0.0)

    @limiter.wrap("device1")
    def test_func(x: int) -> int:
        return x * 2

    # First call should succeed
    assert test_func(5) == 10

    # Second call should fail due to rate limit (bucket is empty)
    try:
        test_func(5)
        raise AssertionError("Should have raised RuntimeError")
    except RuntimeError as e:
        assert "Rate limit exceeded" in str(e)


def test_get_rate_limiter() -> None:
    """Test default rate limiter singleton."""
    reset_rate_limiter()
    limiter1 = get_rate_limiter(per_device_limit=10, global_limit=50)
    limiter2 = get_rate_limiter(per_device_limit=10, global_limit=50)
    assert limiter1 is limiter2


def test_reset_rate_limiter() -> None:
    """Test rate limiter reset."""
    reset_rate_limiter()
    limiter1 = get_rate_limiter(per_device_limit=10, global_limit=50)
    reset_rate_limiter()
    limiter2 = get_rate_limiter(per_device_limit=10, global_limit=50)
    assert limiter1 is not limiter2
