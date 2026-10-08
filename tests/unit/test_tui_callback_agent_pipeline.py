"""Tests for TUI callbacks of agent and pipeline action modules."""

from __future__ import annotations

import json
from pathlib import Path

from lockknife_headless_cli.tui_callback import build_tui_callback


def test_tui_callback_pipeline_actions(tmp_path: Path) -> None:
    cb = build_tui_callback(None)

    # 1. pipeline.list
    res_list = cb("pipeline.list", {})
    assert res_list["ok"] is True
    list_data = json.loads(res_list["data_json"])
    assert isinstance(list_data, list)
    assert len(list_data) >= 5

    # 2. pipeline.plan
    res_plan = cb("pipeline.plan", {"playbook": "triage", "case_dir": str(tmp_path / "CASE-PLAN")})
    assert res_plan["ok"] is True
    plan_data = json.loads(res_plan["data_json"])
    assert plan_data["playbook_name"] == "triage"
    assert "tiers" in plan_data


def test_tui_callback_agent_actions(tmp_path: Path) -> None:
    cb = build_tui_callback(None)
    case_dir = str(tmp_path / "CASE-AGENT")

    # 1. agent.goal with mock provider
    res_goal = cb(
        "agent.goal",
        {
            "objective": "Triage connected device",
            "mock": True,
            "case_dir": case_dir,
            "budget": 5,
        },
    )
    assert res_goal["ok"] is True
    goal_data = json.loads(res_goal["data_json"])
    assert goal_data["status"] == "completed"

    # 2. agent.chat with mock provider
    res_chat = cb(
        "agent.chat",
        {
            "prompt": "Hello assistant",
            "mock": True,
            "case_dir": case_dir,
        },
    )
    assert res_chat["ok"] is True
    chat_data = json.loads(res_chat["data_json"])
    assert "Echo response" in chat_data["response"]

    # 3. agent.daemon
    res_daemon = cb("agent.daemon", {"action": "status", "interval": 10})
    assert res_daemon["ok"] is True

    # 4. agent.memory
    res_mem = cb("agent.memory", {"case_dir": case_dir})
    assert res_mem["ok"] is True
    mem_data = json.loads(res_mem["data_json"])
    assert "facts" in mem_data
    assert "turns" in mem_data
