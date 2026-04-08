from __future__ import annotations

import json
import threading
import time
from typing import Any

from lockknife.core.logging import get_logger
from lockknife.modules.runtime.frida_manager import FridaManager

log = get_logger()


def memory_search(
    app_id: str,
    pattern: str,
    *,
    device_id: str | None = None,
    protection: str = "r--",
    timeout_s: float = 30.0,
) -> str:
    started = time.perf_counter()
    mgr = FridaManager(device_id=device_id)
    _, session = mgr.spawn_and_attach(app_id)
    pat = pattern
    pat_type = "ascii"
    if pat.startswith("hex:"):
        pat_type = "hex"
        pat = pat[4:]
    script_source = f"""
Java.perform(function() {{
  send('memory search starting');
}});
setImmediate(function() {{
  var ranges = Process.enumerateRangesSync({{protection: '{protection}', coalesce: true}});
  var needle = null;
  var patType = '{pat_type}';
  var pat = '{pat}';
  if (patType === 'hex') {{
    needle = pat.trim().replace(/\\s+/g, ' ');
  }} else {{
    needle = pat.split('').map(function(c) {{ return ('0' + c.charCodeAt(0).toString(16)).slice(-2); }}).join(' ');
  }}
  var hits = [];
  ranges.forEach(function(r) {{
    try {{
      var res = Memory.scanSync(r.base, r.size, needle);
      res.forEach(function(m) {{
        hits.push(m.address.toString());
      }});
    }} catch (e) {{}}
  }});
  send(JSON.stringify({{pattern: '{pattern}', pattern_type: patType, protection: '{protection}', hits: hits}}));
}});
""".strip()
    script = mgr.load_script(session, script_source)
    out: dict[str, object] = {
        "pattern": pattern,
        "pattern_type": pat_type,
        "protection": protection,
        "hits": [],
    }
    done = threading.Event()

    def on_message(m: dict[str, Any], _data: Any) -> None:
        if m.get("type") == "send":
            payload = m.get("payload")
            if isinstance(payload, str) and payload.startswith("{"):
                try:
                    parsed = json.loads(payload)
                    out.update(parsed)
                    done.set()
                except Exception:
                    log.warning("frida_message_parse_failed", exc_info=True)

    script.on("message", on_message)
    completed = done.wait(timeout=timeout_s)
    raw_hits = out.get("hits")
    hits = [str(item) for item in raw_hits] if isinstance(raw_hits, list) else []
    out.update(
        {
            "status": "pass" if completed else "warn",
            "timed_out": not completed,
            "hit_count": len(hits),
            "sample_hits": hits[:10],
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "recovery_hint": (
                None
                if completed
                else "Increase the timeout or narrow the protection scope before retrying the runtime memory search."
            ),
            "runtime_dashboard": {
                "mode": "memory-search",
                "status": "pass" if completed else "warn",
                "pattern": pattern,
                "pattern_type": pat_type,
                "protection": protection,
                "hit_count": len(hits),
                "timed_out": not completed,
                "recommended_next_action": (
                    "Review the hit list and register the saved JSON in the active case if it matters."
                    if completed
                    else "Retry with a narrower scope or a longer timeout so the scan can finish."
                ),
            },
        }
    )

    return json.dumps(out)


def heap_dump(
    app_id: str, output_path: str, *, device_id: str | None = None, timeout_s: float = 30.0
) -> str:
    started = time.perf_counter()
    mgr = FridaManager(device_id=device_id)
    _, session = mgr.spawn_and_attach(app_id)
    done = threading.Event()
    out: dict[str, object] = {"output_path": output_path, "ok": False}
    script_source = f"""
Java.perform(function() {{
  try {{
    var Debug = Java.use('android.os.Debug');
    Debug.dumpHprofData('{output_path}');
    send(JSON.stringify({{ok: true, output_path: '{output_path}'}}));
  }} catch (e) {{
    send(JSON.stringify({{ok: false, output_path: '{output_path}', error: String(e)}}));
  }}
}});
""".strip()
    script = mgr.load_script(session, script_source)

    def on_message(m: dict[str, Any], _data: Any) -> None:
        if m.get("type") == "send":
            payload = m.get("payload")
            if isinstance(payload, str) and payload.startswith("{"):
                try:
                    parsed = json.loads(payload)
                    out.update(parsed)
                    done.set()
                except Exception:
                    log.warning("frida_message_parse_failed", exc_info=True)

    script.on("message", on_message)
    completed = done.wait(timeout=timeout_s)
    status = "pass" if completed and out.get("ok") else ("warn" if not completed else "fail")
    out.update(
        {
            "status": status,
            "timed_out": not completed,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "remote_output_path": output_path,
            "recovery_hint": (
                None
                if status == "pass"
                else (
                    "Increase the timeout or confirm the target app is stable before retrying the heap dump."
                    if not completed
                    else "Review the error and confirm the app/device supports Debug.dumpHprofData for this target."
                )
            ),
            "runtime_dashboard": {
                "mode": "heap-dump",
                "status": status,
                "remote_output_path": output_path,
                "timed_out": not completed,
                "recommended_next_action": (
                    "Preserve the heap-dump result JSON with the same case so later reporting stays reproducible."
                    if status == "pass"
                    else "Retry once the target is stable or the timeout is large enough for the dump to complete."
                ),
            },
        }
    )
    return json.dumps(out)
