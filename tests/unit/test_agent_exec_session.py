from __future__ import annotations

import sys
import time
from lockknife.core.agent.exec_session import ExecSessionManager


def test_exec_session_manager_lifecycle():
    manager = ExecSessionManager()

    # Start a python process that echoes input
    cmd = f"{sys.executable} -c \"import sys; print('READY', flush=True); line = sys.stdin.readline(); print('ECHO:' + line.strip(), flush=True)\""
    start_res = manager.start_session(command=cmd, session_id="test_sess", use_shell=True)
    assert start_res["ok"] is True
    assert start_res["session_id"] == "test_sess"

    # Poll initial output
    poll1 = manager.poll_session("test_sess", wait_s=0.3)
    assert poll1["ok"] is True
    assert "READY" in poll1["output"]

    # Write stdin
    write_res = manager.write_session("test_sess", "hello_agent\n")
    assert write_res["ok"] is True

    # Poll echo response
    poll2 = manager.poll_session("test_sess", wait_s=0.3)
    assert "ECHO:hello_agent" in poll2["output"]

    # List sessions
    active = manager.list_sessions()
    assert len(active) == 1
    assert active[0]["session_id"] == "test_sess"

    # Close session
    close_res = manager.close_session("test_sess")
    assert close_res["ok"] is True
    assert len(manager.list_sessions()) == 0


def test_exec_session_manager_close_all():
    manager = ExecSessionManager()
    cmd = f"{sys.executable} -c \"import time; time.sleep(10)\""
    manager.start_session(command=cmd, session_id="sleep1", use_shell=True)
    manager.start_session(command=cmd, session_id="sleep2", use_shell=True)

    assert len(manager.list_sessions()) == 2
    manager.close_all()
    assert len(manager.list_sessions()) == 0
