from __future__ import annotations

import pathlib
from unittest.mock import MagicMock
from lockknife.core.agent.memory import MemoryStore
from lockknife.core.agent.models import ToolInvocation
from lockknife.core.agent.tools import AgentToolRegistry


def test_agent_tool_registry_specs(tmp_path: pathlib.Path):
    registry = AgentToolRegistry(case_dir=tmp_path)
    specs = registry.get_tool_specs()
    names = [s["function"]["name"] for s in specs]

    # Verify forensic primitives are present
    assert "device_shell" in names
    assert "case_read_file" in names
    assert "case_write_file" in names
    assert "record_fact" in names
    assert "delegate_subagent" in names


def test_agent_tool_case_fs_primitives(tmp_path: pathlib.Path):
    memory = MemoryStore(case_dir=tmp_path)
    registry = AgentToolRegistry(case_dir=tmp_path, memory_store=memory)

    # 1. Write file
    write_inv = ToolInvocation(
        call_id="w1",
        tool_id="case_write_file",
        arguments={"relative_path": "reports/findings.txt", "content": "Sensitive token found."},
    )
    obs_w = registry.execute(write_inv)
    assert obs_w.success is True
    assert (tmp_path / "reports" / "findings.txt").exists()

    # 2. Read file
    read_inv = ToolInvocation(
        call_id="r1",
        tool_id="case_read_file",
        arguments={"relative_path": "reports/findings.txt"},
    )
    obs_r = registry.execute(read_inv)
    assert obs_r.success is True
    assert obs_r.output == "Sensitive token found."

    # 3. Path traversal protection
    traversal_inv = ToolInvocation(
        call_id="r2",
        tool_id="case_read_file",
        arguments={"relative_path": "../../../etc/passwd"},
    )
    obs_bad = registry.execute(traversal_inv)
    assert obs_bad.success is False
    assert "Access denied" in (obs_bad.error or "")


def test_agent_tool_record_fact(tmp_path: pathlib.Path):
    memory = MemoryStore(case_dir=tmp_path)
    registry = AgentToolRegistry(case_dir=tmp_path, memory_store=memory)

    fact_inv = ToolInvocation(
        call_id="f1",
        tool_id="record_fact",
        arguments={"key": "target_abi", "value": "arm64-v8a"},
    )
    obs = registry.execute(fact_inv)
    assert obs.success is True
    assert memory.get_facts()["target_abi"] == "arm64-v8a"


def test_agent_tool_action_callback(tmp_path: pathlib.Path):
    mock_cb = MagicMock(return_value={"ok": True, "result": "scan_complete"})
    registry = AgentToolRegistry(case_dir=tmp_path, action_callback=mock_cb)

    inv = ToolInvocation(call_id="a1", tool_id="core.health", arguments={"detailed": True})
    obs = registry.execute(inv)

    assert obs.success is True
    mock_cb.assert_called_once()
    assert mock_cb.call_args[0][0] == "core.health"
    assert mock_cb.call_args[0][1]["case_dir"] == str(tmp_path)
