from __future__ import annotations

import pathlib

import pytest

from lockknife.core._case_store import is_case_workspace
from lockknife.core.agent.policy import ResearcherPolicy


def test_researcher_policy_unrestricted_mode(tmp_path: pathlib.Path):
    policy = ResearcherPolicy(unrestricted=True, auto_provision_case=True, operator="alice")
    workspace = policy.ensure_case_workspace(tmp_path / "research_case")
    assert is_case_workspace(workspace)

    # In unrestricted mode, high risk and exploit capabilities are allowed
    auth1 = policy.authorize_tool("exploit.stage_payload", {"target": "device"}, case_dir=workspace)
    assert auth1.allowed is True
    assert auth1.auto_approved is True

    auth2 = policy.authorize_tool("device_shell", {"command": "id"}, case_dir=workspace)
    assert auth2.allowed is True

    # Audit log was written into case_dir/.agent/audit.log
    audit_file = workspace / ".agent" / "audit.log"
    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8")
    assert "alice" in content
    assert "exploit.stage_payload" in content


def test_researcher_policy_restricted_mode(tmp_path: pathlib.Path):
    policy = ResearcherPolicy(unrestricted=False, auto_provision_case=False)

    # Denies without valid workspace
    auth_no_ws = policy.authorize_tool("core.health", {}, case_dir=None)
    assert auth_no_ws.allowed is False
    assert "workspace is required" in auth_no_ws.reason

    # Create workspace
    from lockknife.core.case import create_case_workspace
    ws = tmp_path / "valid_ws"
    ws.mkdir()
    create_case_workspace(
        case_dir=ws,
        case_id="test_case",
        examiner="tester",
        title="Test Workspace",
    )

    # Safe tool allowed
    auth_safe = policy.authorize_tool("core.health", {}, case_dir=ws)
    assert auth_safe.allowed is True

    # High-risk tool blocked in restricted mode
    auth_exploit = policy.authorize_tool("exploit.cve_runner", {}, case_dir=ws)
    assert auth_exploit.allowed is False
    assert "requires manual interactive confirmation" in auth_exploit.reason
