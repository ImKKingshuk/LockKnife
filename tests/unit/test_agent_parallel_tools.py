from __future__ import annotations

import pathlib
import time
from lockknife.core.agent.models import ToolInvocation
from lockknife.core.agent.tools import AgentToolRegistry


def test_agent_parallel_tool_execution(tmp_path: pathlib.Path):
    # Action callback that sleeps 0.2s
    def _slow_cb(action_id: str, params: dict):
        time.sleep(0.15)
        return {"ok": True, "action": action_id}

    registry = AgentToolRegistry(case_dir=tmp_path, action_callback=_slow_cb)

    calls = [
        ToolInvocation(call_id="c1", tool_id="core.health", arguments={"id": 1}),
        ToolInvocation(call_id="c2", tool_id="core.health", arguments={"id": 2}),
        ToolInvocation(call_id="c3", tool_id="core.health", arguments={"id": 3}),
    ]

    start = time.perf_counter()
    observations = registry.execute_batch(calls, max_concurrency=3)
    duration = time.perf_counter() - start

    assert len(observations) == 3
    assert all(o.success for o in observations)
    assert observations[0].call_id == "c1"
    assert observations[1].call_id == "c2"
    assert observations[2].call_id == "c3"

    # Running sequentially would take 3 * 0.15s = 0.45s. Parallel execution should complete in ~0.25s
    assert duration < 0.40, f"Expected parallel speedup, but took {duration:.2f}s"
