from __future__ import annotations

import collections
import logging
import subprocess  # nosec B404
import threading
import time
import uuid
from typing import Any

logger = logging.getLogger("lockknife.agent.exec_session")


class ExecSession:
    """A single stateful interactive process session with non-blocking I/O buffers."""

    def __init__(self, session_id: str, command: str, proc: subprocess.Popen) -> None:
        self.session_id = session_id
        self.command = command
        self.proc = proc
        self.created_at = time.time()
        self.last_active_at = time.time()
        self._output_buffer: collections.deque[str] = collections.deque(maxlen=2000)
        self._lock = threading.Lock()
        self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader_thread.start()

    def _read_stdout(self) -> None:
        try:
            if self.proc.stdout:
                for line in iter(self.proc.stdout.readline, ""):
                    with self._lock:
                        self._output_buffer.append(line)
                        self.last_active_at = time.time()
        except Exception as exc:
            logger.debug("ExecSession %s stdout closed: %s", self.session_id, exc)

    def write_input(self, text: str) -> bool:
        """Write stdin text to the running interactive process."""
        if self.proc.poll() is not None or not self.proc.stdin:
            return False
        try:
            if not text.endswith("\n"):
                text += "\n"
            self.proc.stdin.write(text)
            self.proc.stdin.flush()
            self.last_active_at = time.time()
            return True
        except Exception as exc:
            logger.warning("Failed to write to ExecSession %s stdin: %s", self.session_id, exc)
            return False

    def poll_output(self, wait_s: float = 0.5) -> dict[str, Any]:
        """Poll and drain buffered output lines since last read."""
        if wait_s > 0:
            time.sleep(min(wait_s, 5.0))

        lines: list[str] = []
        with self._lock:
            while self._output_buffer:
                lines.append(self._output_buffer.popleft())

        returncode = self.proc.poll()
        is_running = returncode is None

        return {
            "session_id": self.session_id,
            "output": "".join(lines),
            "is_running": is_running,
            "returncode": returncode,
            "elapsed_s": time.time() - self.created_at,
        }

    def close(self) -> None:
        """Terminate the running process cleanly."""
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


class ExecSessionManager:
    """Manages active interactive device/shell sessions across agent turns."""

    def __init__(self) -> None:
        self._sessions: dict[str, ExecSession] = {}
        self._lock = threading.Lock()

    def start_session(
        self,
        command: str,
        session_id: str | None = None,
        use_shell: bool = False,
    ) -> dict[str, Any]:
        sid = session_id or f"sess_{str(uuid.uuid4())[:6]}"
        with self._lock:
            if sid in self._sessions:
                return {"ok": False, "error": f"Session {sid} already exists", "session_id": sid}

            try:
                # Use shlex or list if not shell
                args = command if use_shell else command.split()
                proc = subprocess.Popen(  # nosec B603 B602
                    args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    shell=use_shell,
                )
                session = ExecSession(sid, command, proc)
                self._sessions[sid] = session
                logger.info("Started ExecSession %s: %s", sid, command)
                return {"ok": True, "session_id": sid, "command": command}
            except Exception as exc:
                logger.error("Failed to start ExecSession %s: %s", sid, exc)
                return {"ok": False, "error": str(exc), "session_id": sid}

    def write_session(self, session_id: str, input_text: str) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            return {"ok": False, "error": f"Session {session_id} not found"}
        ok = sess.write_input(input_text)
        return {"ok": ok, "session_id": session_id}

    def poll_session(self, session_id: str, wait_s: float = 0.5) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            return {"ok": False, "error": f"Session {session_id} not found", "output": ""}
        result = sess.poll_output(wait_s=wait_s)
        result["ok"] = True
        return result

    def close_session(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if not sess:
            return {"ok": False, "error": f"Session {session_id} not found"}
        sess.close()
        logger.info("Closed ExecSession %s", session_id)
        return {"ok": True, "session_id": session_id}

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "session_id": sid,
                    "command": s.command,
                    "is_running": s.proc.poll() is None,
                    "elapsed_s": round(time.time() - s.created_at, 2),
                }
                for sid, s in self._sessions.items()
            ]

    def close_all(self) -> None:
        """Cleanup all running sessions."""
        with self._lock:
            for s in list(self._sessions.values()):
                s.close()
            self._sessions.clear()
