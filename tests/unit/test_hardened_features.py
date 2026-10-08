from __future__ import annotations

import pathlib
import time
from typing import Any
from unittest.mock import MagicMock

from lockknife.core.agent.failover import FailoverProvider
from lockknife.core.agent.memory import MemoryStore, WorkingMemory
from lockknife.core.agent.models import (
    AgentGoal,
    ModelDecision,
    ToolInvocation,
    ToolObservation,
    TurnRecord,
)
from lockknife.core.agent.planner import GoalPlan, MilestoneStatus, PlanMilestone
from lockknife.core.agent.provider import LLMProvider
from lockknife.core.agent.reflexion import ReflexionEngine
from lockknife.core.http import _parse_https
from lockknife.core.pipeline.engine import PipelineExecutor
from lockknife.core.pipeline.models import (
    PipelineStatus,
    PlaybookDefinition,
    StepDefinition,
    StepStatus,
)
from lockknife.modules.extraction.messaging import _pull_sqlite_with_wal
from lockknife.modules.forensics.carving import carve_deleted_files
from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite


# 1. Pipeline Engine Retries & Offline Fallback Tests
def test_pipeline_engine_retries_transient_failure(tmp_path: pathlib.Path) -> None:
    call_count = 0

    def mock_dispatch(action: str, params: dict[str, Any]) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise RuntimeError("Temporary device timeout")
        return {"ok": True, "attempts": call_count}

    step = StepDefinition(
        step_id="step_flaky",
        label="Flaky Step",
        action_id="custom.flaky",
        category="core",
        retries=2,
        retry_backoff_s=0.01,
    )
    pb = PlaybookDefinition(
        name="test-retry",
        title="Test Retry",
        description="Testing retry backoff",
        category="core",
        steps=(step,),
    )
    executor = PipelineExecutor(case_dir=tmp_path / "case-retry")
    executor._action_callback = mock_dispatch
    summary = executor.execute(pb)

    assert summary.status == PipelineStatus.COMPLETED
    assert call_count == 3
    records = {r.step_id: r for r in summary.step_records}
    assert records["step_flaky"].status == StepStatus.COMPLETED


def test_pipeline_engine_offline_fallback(tmp_path: pathlib.Path) -> None:
    step = StepDefinition(
        step_id="step_device",
        label="Device Step",
        action_id="device.live_pull",
        fallback_action_id="offline.cache_pull",
        category="core",
        requires_device=True,
    )
    pb = PlaybookDefinition(
        name="test-offline-fallback",
        title="Test Fallback",
        description="Testing fallback without device",
        category="core",
        steps=(step,),
    )
    # No target_serial supplied (offline / no target device)
    executor = PipelineExecutor(case_dir=tmp_path / "case-offline", target_serial=None)
    executor._action_callback = lambda act, params: {"ok": True, "action": act}
    summary = executor.execute(pb)

    assert summary.status == PipelineStatus.COMPLETED
    records = {r.step_id: r for r in summary.step_records}
    assert records["step_device"].status == StepStatus.COMPLETED
    assert records["step_device"].used_fallback is True


# 2. Agent Memory Tool-Call Pairing Test
def test_agent_memory_appends_empty_reasoning_tool_call(tmp_path: pathlib.Path) -> None:
    store = MemoryStore(case_dir=tmp_path)
    wm = WorkingMemory(goal=AgentGoal(objective="Test goal"))
    # Assistant decides to call tool without reasoning text
    decision = ModelDecision.call_tools(
        tool_calls=[ToolInvocation(call_id="call_123", tool_id="device_shell", arguments={"command": "id"})],
        reasoning="",
    )
    wm.recent_turns.append(TurnRecord(turn_index=1, decision=decision, observations=[]))
    messages = store.build_llm_messages(working_memory=wm)

    # Assistant message MUST be present with tool_calls
    asst_msgs = [m for m in messages if m.get("role") == "assistant"]
    assert len(asst_msgs) == 1
    assert "tool_calls" in asst_msgs[0]
    assert asst_msgs[0]["tool_calls"][0]["function"]["name"] == "device_shell"


# 3. Failover Provider Cooldown & Reset Tests
class FailingProvider(LLMProvider):
    def complete(self, messages, tools=None, system_prompt=None) -> ModelDecision:
        raise RuntimeError("API down")


class WorkingProvider(LLMProvider):
    def complete(self, messages, tools=None, system_prompt=None) -> ModelDecision:
        return ModelDecision.finish("Success from backup")


def test_failover_provider_cooldown_and_reset() -> None:
    failing = FailingProvider()
    failover = FailoverProvider(
        providers=[failing],
        max_consecutive_errors=2,
        cooldown_s=0.05,
    )

    # 1st failure
    d1 = failover.complete([{"role": "user", "content": "hi"}])
    assert not failover.circuit_tripped

    # 2nd failure trips circuit breaker
    d2 = failover.complete([{"role": "user", "content": "hi"}])
    assert failover.circuit_tripped
    assert "tripped" in d2.text.lower()

    # Immediate call is blocked by circuit breaker
    d3 = failover.complete([{"role": "user", "content": "hi"}])
    assert "halted" in d3.text.lower()

    # Wait for cooldown to expire
    time.sleep(0.06)
    # Swap in a working provider to test half-open recovery
    failover.providers = [WorkingProvider()]
    d4 = failover.complete([{"role": "user", "content": "hi"}])
    assert not failover.circuit_tripped
    assert d4.text == "Success from backup"

    # Test manual reset
    failover.circuit_tripped = True
    failover.consecutive_errors = 5
    failover.reset()
    assert not failover.circuit_tripped
    assert failover.consecutive_errors == 0


# 4. Reflexion Milestone Multi-Phase Progression Test
def test_reflexion_milestones_advancement() -> None:
    plan = GoalPlan(
        goal=AgentGoal(objective="Forensic audit of device"),
        milestones=[
            PlanMilestone(milestone_id="m1", title="Device Triage and Inventory", description="Detect device"),
            PlanMilestone(milestone_id="m2", title="App Data Extraction", description="Extract app data"),
            PlanMilestone(milestone_id="m3", title="Vulnerability Analysis", description="Audit APKs"),
            PlanMilestone(milestone_id="m4", title="Final Case Report", description="Generate report"),
        ],
    )
    engine = ReflexionEngine(plan=plan)

    # 1. Triage tool validates milestone 1
    engine.evaluate(
        [ToolInvocation(call_id="c1", tool_id="device_health", arguments={})],
        [ToolObservation(call_id="c1", tool_id="device_health", success=True, output="Device online", error=None)],
    )
    assert plan.milestones[0].status == MilestoneStatus.COMPLETED
    assert plan.milestones[1].status == MilestoneStatus.PENDING

    # 2. Extraction tool validates milestone 2
    engine.evaluate(
        [ToolInvocation(call_id="c2", tool_id="messaging_extract", arguments={})],
        [ToolObservation(call_id="c2", tool_id="messaging_extract", success=True, output="Messages extracted", error=None)],
    )
    assert plan.milestones[1].status == MilestoneStatus.COMPLETED
    assert plan.milestones[2].status == MilestoneStatus.PENDING

    # 3. Analysis tool validates milestone 3
    engine.evaluate(
        [ToolInvocation(call_id="c3", tool_id="apk_analyze", arguments={})],
        [ToolObservation(call_id="c3", tool_id="apk_analyze", success=True, output="Vulnerabilities scanned", error=None)],
    )
    assert plan.milestones[2].status == MilestoneStatus.COMPLETED
    assert plan.milestones[3].status == MilestoneStatus.PENDING

    # 4. Report tool validates milestone 4
    engine.evaluate(
        [ToolInvocation(call_id="c4", tool_id="report_generate", arguments={})],
        [ToolObservation(call_id="c4", tool_id="report_generate", success=True, output="Report ready", error=None)],
    )
    assert plan.milestones[3].status == MilestoneStatus.COMPLETED


# 5. HTTP Custom Port Parsing Test
def test_parse_https_with_custom_ports() -> None:
    h, p, path = _parse_https("https://internal.secops.local:9443/v1/telemetry?token=abc")
    assert h == "internal.secops.local"
    assert p == 9443
    assert path == "/v1/telemetry?token=abc"

    h2, p2, path2 = _parse_https("https://api.example.com/status")
    assert h2 == "api.example.com"
    assert p2 is None
    assert path2 == "/status"


# 6. Carving Streaming & Non-Existent File Test
def test_carving_missing_file_and_chunked_scanning(tmp_path: pathlib.Path) -> None:
    out_dir = tmp_path / "carved_out"
    # Missing file
    res = carve_deleted_files(tmp_path / "missing.bin", out_dir)
    assert res["carved_count"] == 0
    assert "does not exist" in res.get("error", "")

    # Valid image carving
    img = tmp_path / "test.img"
    img.write_bytes(b"\x00" * 10 + b"\xff\xd8\xffsamplejpg\xff\xd9" + b"\x00" * 10)
    res2 = carve_deleted_files(img, out_dir, source="image")
    assert res2["carved_count"] == 1
    assert len(res2["carved"]) == 1
    assert res2["carved"][0]["kind"] == "jpg"


# 7. Corrupted SQLite Triage Test
def test_analyze_sqlite_corrupted_file(tmp_path: pathlib.Path) -> None:
    corrupt_db = tmp_path / "corrupt.db"
    # Write corrupt non-sqlite data
    corrupt_db.write_bytes(b"CORRUPTED_BINARY_DATA\x00\xff\xfe\x00\x12\x34\x56\x78")

    analysis = analyze_sqlite(corrupt_db)
    assert analysis.tables == []
    assert analysis.objects == []
    assert analysis.integrity_check is not None
    assert "corrupted" in analysis.integrity_check.lower() or "file is not a database" in analysis.integrity_check.lower()


# 8. WAL-Aware Pull Test
def test_pull_sqlite_with_wal(tmp_path: pathlib.Path) -> None:
    devices = MagicMock()
    # Mock root staging pull
    def mock_pull(devs, serial, remote, local, timeout_s=60.0):
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(b"mock_db_content")
        return True

    from unittest.mock import patch
    with patch("lockknife.modules.extraction.messaging.try_root_staging_pull", side_effect=mock_pull):
        dest = tmp_path / "extracted" / "msgstore.db"
        success = _pull_sqlite_with_wal(devices, "device123", "/data/data/com.whatsapp/databases/msgstore.db", dest)
        assert success is True
        assert dest.exists()
        assert (tmp_path / "extracted" / "msgstore.db-wal").exists()
        assert (tmp_path / "extracted" / "msgstore.db-shm").exists()
