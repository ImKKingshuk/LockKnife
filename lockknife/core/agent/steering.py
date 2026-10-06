from __future__ import annotations

import collections
import logging
import threading

logger = logging.getLogger("lockknife.agent.steering")


class SteeringQueue:
    """Thread-safe queue for mid-flight operator guidance and out-of-band steering."""

    def __init__(self) -> None:
        self._queue: collections.deque[str] = collections.deque()
        self._lock = threading.Lock()

    def push(self, message: str) -> None:
        """Push a steering guidance message to be drained at the start of the next turn."""
        clean = message.strip()
        if not clean:
            return
        with self._lock:
            self._queue.append(clean)
            logger.info("Operator steering pushed: %s", clean[:80])

    def drain(self) -> list[str]:
        """Drain all pending steering messages."""
        with self._lock:
            messages: list[str] = list(self._queue)
            self._queue.clear()
            return messages

    def has_messages(self) -> bool:
        with self._lock:
            return len(self._queue) > 0
