from __future__ import annotations

import threading
from lockknife.core.agent.steering import SteeringQueue


def test_steering_queue_push_and_drain():
    queue = SteeringQueue()
    assert not queue.has_messages()
    assert queue.drain() == []

    queue.push("Check port 5555 first")
    queue.push("Look for com.malware.sample")
    assert queue.has_messages()

    drained = queue.drain()
    assert len(drained) == 2
    assert drained[0] == "Check port 5555 first"
    assert drained[1] == "Look for com.malware.sample"
    assert not queue.has_messages()


def test_steering_queue_multithreaded():
    queue = SteeringQueue()

    def _pusher(idx: int):
        queue.push(f"Note from thread {idx}")

    threads = [threading.Thread(target=_pusher, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    drained = queue.drain()
    assert len(drained) == 10
