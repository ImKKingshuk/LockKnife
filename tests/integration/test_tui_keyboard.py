"""Exercise the native event loop with a fake backend, never a connected device."""

from __future__ import annotations

import os
import pathlib
import select
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="PTY smoke test requires POSIX")
def test_native_tui_opens_forms_search_and_export(tmp_path: pathlib.Path) -> None:
    import fcntl
    import pty
    import struct
    import termios

    pytest.importorskip("lockknife.lockknife_core")
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
    program = """
from lockknife import lockknife_core
from lockknife_headless_cli.tui_callback import build_action_registry
def callback(action, params):
    return {"ok": True, "data_json": "[]"}
lockknife_core.run_tui(callback, build_action_registry().catalog_json())
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={**os.environ, "HOME": str(tmp_path), "TERM": "xterm-256color"},
    )
    os.close(slave)

    def send(keys: bytes) -> None:
        while select.select([master], [], [], 0)[0]:
            os.read(master, 65536)
        os.write(master, keys)

    def expect(text: str) -> None:
        output = bytearray()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    break
                if text.encode() in output:
                    return
            if process.poll() is not None:
                break
        pytest.fail(
            f"Native TUI did not display {text!r}; output={output.decode(errors='replace')!r}"
        )

    try:
        expect("Modules")
        send(b"n")
        expect("Case directory:")
        send(b"\x1b[27u")
        time.sleep(0.3)
        send(b"/")
        expect("Search Modules")
        send(b"\x1b[27u")
        time.sleep(0.3)
        send(b"e")
        expect("Export")
        send(b"\x1b[27u")
        time.sleep(0.3)
        send(b"\r")
        expect("Actions:")
        send(b"\x1b[27u")
        time.sleep(0.3)
        send(b"q")
        deadline = time.monotonic() + 10
        while process.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    os.read(master, 65536)
                except OSError:
                    break
        assert process.wait(timeout=1) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
