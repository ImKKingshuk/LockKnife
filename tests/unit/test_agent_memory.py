from __future__ import annotations

import pathlib

from lockknife.core.agent.memory import MemoryStore, WorkingMemory
from lockknife.core.agent.models import (
    AgentGoal,
    ModelDecision,
    ToolInvocation,
    ToolObservation,
    TurnRecord,
)


def test_memory_store_facts_persistence(tmp_path: pathlib.Path):
    store1 = MemoryStore(case_dir=tmp_path)
    store1.set_fact("android_version", "14")
    store1.set_fact("target_package", "com.bank.app")
    assert store1.get_facts()["android_version"] == "14"

    # Verify reloading from disk
    store2 = MemoryStore(case_dir=tmp_path)
    facts2 = store2.get_facts()
    assert facts2.get("android_version") == "14"
    assert facts2.get("target_package") == "com.bank.app"


def test_memory_store_episodic_persistence(tmp_path: pathlib.Path):
    store = MemoryStore(case_dir=tmp_path)
    dec = ModelDecision.call_tools([ToolInvocation(call_id="c1", tool_id="core.health")])
    obs = ToolObservation(call_id="c1", tool_id="core.health", success=True, output="OK")
    turn = TurnRecord(turn_index=1, decision=dec, observations=[obs])

    store.persist_turn(turn)
    loaded = store.load_episodic_turns()
    assert len(loaded) == 1
    assert loaded[0]["turn_index"] == 1
    assert loaded[0]["decision"]["tool_calls"][0]["tool_id"] == "core.health"


def test_memory_store_truncation(tmp_path: pathlib.Path):
    store = MemoryStore(case_dir=tmp_path)
    large_payload = "A" * 10000

    preview, artifact_path = store.truncate_observation_payload("dump_db", large_payload)
    assert artifact_path is not None
    assert pathlib.Path(artifact_path).exists()
    assert len(preview) < 5000
    assert "Truncated" in preview


def test_autocompact_context_trigger(tmp_path: pathlib.Path):
    store = MemoryStore(case_dir=tmp_path, max_context_tokens=50)  # low token threshold to force compact
    goal = AgentGoal(objective="Investigation")
    working = WorkingMemory(goal=goal)

    # Add 6 turns to trigger compact
    for i in range(1, 7):
        dec = ModelDecision.call_tools([ToolInvocation(call_id=f"c{i}", tool_id=f"tool_{i}")])
        obs = ToolObservation(call_id=f"c{i}", tool_id=f"tool_{i}", success=True)
        turn = TurnRecord(turn_index=i, decision=dec, observations=[obs])
        working.recent_turns.append(turn)

    compacted_working, summary = store.check_and_compact(working, None)
    assert summary is not None
    assert "Turn 1" in summary
    # Only last 3 turns should remain in recent_turns
    assert len(compacted_working.recent_turns) == 3
    assert compacted_working.recent_turns[-1].turn_index == 6
