"""Rate limiting for ADB operations to prevent device flooding."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from threading import Lock
from typing import TypeVar

from lockknife.core.logging import get_logger

T = TypeVar("T")


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float) -> None:
        """Initialize token bucket.

        Args:
            capacity: Maximum number of tokens.
            refill_rate: Tokens per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self._lock = Lock()
        self._log = get_logger()

    def acquire(self, timeout_s: float = 10.0) -> bool:
        """Acquire a token, blocking if necessary.

        Args:
            timeout_s: Maximum time to wait for a token.

        Returns:
            True if token acquired, False if timeout.
        """
        start = time.time()
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

            # Wait a bit before retrying
            if time.time() - start >= timeout_s:
                self._log.warning(
                    "rate_limit_timeout", capacity=self.capacity, rate=self.refill_rate
                )
                return False
            time.sleep(0.01)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed > 0:
            new_tokens = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_refill = now


class RateLimiter:
    """Rate limiter for ADB operations with per-device and global limits."""

    def __init__(
        self,
        per_device_limit: int = 10,
        global_limit: int = 50,
    ) -> None:
        """Initialize rate limiter.

        Args:
            per_device_limit: Operations per second per device.
            global_limit: Operations per second globally.
        """
        self.per_device_limit = per_device_limit
        self.global_limit = global_limit
        self.per_device_buckets: dict[str, TokenBucket] = {}
        self.global_bucket = TokenBucket(global_limit, global_limit)
        self._lock = Lock()
        self._log = get_logger()

    def acquire(self, serial: str, timeout_s: float = 10.0) -> bool:
        """Acquire permission to perform an operation.

        Args:
            serial: Device serial number.
            timeout_s: Maximum time to wait.

        Returns:
            True if permission granted, False if timeout.
        """
        # Get or create per-device bucket
        with self._lock:
            if serial not in self.per_device_buckets:
                self.per_device_buckets[serial] = TokenBucket(
                    self.per_device_limit, self.per_device_limit
                )
            device_bucket = self.per_device_buckets[serial]

        # Try to acquire from both buckets
        if not device_bucket.acquire(timeout_s):
            self._log.warning("rate_limit_device", serial=serial)
            return False

        if not self.global_bucket.acquire(timeout_s):
            self._log.warning("rate_limit_global")
            return False

        return True

    def wrap(self, serial: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator to rate-limit a function.

        Args:
            serial: Device serial number.

        Returns:
            Decorated function.
        """

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            def wrapper(*args, **kwargs) -> T:
                if not self.acquire(serial):
                    raise RuntimeError(f"Rate limit exceeded for device {serial}")
                return func(*args, **kwargs)

            return wrapper

        return decorator


# Default rate limiter instance
_DEFAULT_LIMITER: RateLimiter | None = None
_LIMITER_LOCK = Lock()


def get_rate_limiter(per_device_limit: int = 10, global_limit: int = 50) -> RateLimiter:
    """Get the default rate limiter instance.

    Args:
        per_device_limit: Operations per second per device (fallback if env not set).
        global_limit: Operations per second globally (fallback if env not set).

    Returns:
        Rate limiter instance.
    """
    global _DEFAULT_LIMITER
    with _LIMITER_LOCK:
        if _DEFAULT_LIMITER is None:
            per_device = int(os.getenv("LOCKKNIFE_RATE_LIMIT_PER_DEVICE", str(per_device_limit)))
            global_limit = int(os.getenv("LOCKKNIFE_RATE_LIMIT_GLOBAL", str(global_limit)))
            _DEFAULT_LIMITER = RateLimiter(per_device, global_limit)
        return _DEFAULT_LIMITER


def reset_rate_limiter() -> None:
    """Reset the default rate limiter (mainly for testing)."""
    global _DEFAULT_LIMITER
    with _LIMITER_LOCK:
        _DEFAULT_LIMITER = None
