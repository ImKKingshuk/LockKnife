import json

import pytest


def test_execute_wasm_plugin_success(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")

    # 1. Define a success WAT string that reads input, logs it, and returns output
    wat_code = """(module
  (import "env" "log_message" (func $log (param i32 i32)))
  (memory (export "memory") 1)

  (func (export "alloc") (param $size i32) (result i32)
    (i32.const 1024)
  )

  (func (export "dealloc") (param $ptr i32) (param $size i32)
  )

  (func (export "run_plugin") (param $ptr i32) (param $len i32) (result i64)
    ;; Log the input message to host
    (call $log (local.get $ptr) (local.get $len))

    ;; Return packed output (ptr = 2048, len = 38)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
      (i64.extend_i32_u (i32.const 38))
    )
  )

  (data (i32.const 2048) "{\\"status\\":\\"success\\",\\"message\\":\\"hello\\"}")
)"""

    wat_file = tmp_path / "plugin.wat"
    wat_file.write_text(wat_code, encoding="utf-8")

    # Run the plugin
    input_data = '{"action":"test"}'
    out_str = lockknife_core.execute_wasm_plugin(str(wat_file), input_data)

    # Parse and assert output
    res = json.loads(out_str)
    assert res["status"] == "success"
    assert res["message"] == "hello"


def test_execute_wasm_plugin_trap(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")

    # 2. Define a trapping WAT string that performs unreachable to simulate panic
    wat_code = """(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    (i32.const 0)
  )
  (func (export "dealloc") (param i32) (param i32)
  )
  (func (export "run_plugin") (param i32) (param i32) (result i64)
    (unreachable)
  )
)"""

    wat_file = tmp_path / "trap.wat"
    wat_file.write_text(wat_code, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        lockknife_core.execute_wasm_plugin(str(wat_file), "{}")

    assert "WASM Sandbox Execution Error" in str(excinfo.value)
    assert "wasm backtrace" in str(excinfo.value)


def test_execute_wasm_plugin_sandbox_directory(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")

    # 3. Create sandbox directory
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()

    # Define a WAT string that does nothing else but succeeds
    wat_code = """(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    (i32.const 1024)
  )
  (func (export "dealloc") (param i32) (param i32)
  )
  (func (export "run_plugin") (param i32) (param i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
      (i64.extend_i32_u (i32.const 38))
    )
  )
  (data (i32.const 2048) "{\\"status\\":\\"success\\",\\"message\\":\\"hello\\"}")
)"""

    wat_file = tmp_path / "sandbox.wat"
    wat_file.write_text(wat_code, encoding="utf-8")

    # Run the plugin with sandbox directory
    out_str = lockknife_core.execute_wasm_plugin(str(wat_file), "{}", str(sandbox_dir))
    res = json.loads(out_str)
    assert res["status"] == "success"
