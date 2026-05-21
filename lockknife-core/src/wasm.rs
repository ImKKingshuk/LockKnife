use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{WasiCtxBuilder, DirPerms, FilePerms};
use std::path::Path;

#[pyfunction]
#[pyo3(signature = (wasm_path, input_json, sandbox_dir=None))]
pub fn execute_wasm_plugin(
    py: Python<'_>,
    wasm_path: &str,
    input_json: &str,
    sandbox_dir: Option<&str>,
) -> PyResult<String> {
    let wasm_path_str = wasm_path.to_string();
    let input_json_str = input_json.to_string();
    let sandbox_dir_str = sandbox_dir.map(|s| s.to_string());

    // Release the GIL to allow other Python threads to execute concurrently using py.detach
    py.detach(move || {
        execute_wasm_plugin_inner(&wasm_path_str, &input_json_str, sandbox_dir_str.as_deref())
            .map_err(|e| PyValueError::new_err(format!("WASM Sandbox Execution Error: {}", e)))
    })
}

fn execute_wasm_plugin_inner(
    wasm_path: &str,
    input_json: &str,
    sandbox_dir: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Create the Wasmtime engine
    let engine = Engine::default();

    // 2. Create the WASI P1 Linker
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s| s)?;

    // 3. Register our custom logging host function under "env" "log_message"
    linker.func_wrap(
        "env",
        "log_message",
        |mut caller: Caller<'_, WasiP1Ctx>, ptr: i32, len: i32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return,
            };
            let data = mem.data(&caller);
            let start = ptr as usize;
            let end = start + len as usize;
            if end <= data.len() {
                let msg = String::from_utf8_lossy(&data[start..end]);
                println!("[WASM LOG] {}", msg);
            }
        },
    )?;

    // 4. Configure the WASI context builder
    let mut builder = WasiCtxBuilder::new();
    builder.inherit_stdout();
    builder.inherit_stderr();

    // If sandbox_dir is provided, validate it and preopen it under standard guest-visible path
    if let Some(dir) = sandbox_dir {
        let path = Path::new(dir);
        if !path.exists() {
            return Err(format!("Sandbox directory does not exist: {}", dir).into());
        }
        if !path.is_dir() {
            return Err(format!("Sandbox path is not a directory: {}", dir).into());
        }
        builder.preopened_dir(
            path,
            "./sandbox",
            DirPerms::all(),
            FilePerms::all(),
        )?;
    }

    let wasi_ctx = builder.build_p1();

    // 5. Create the Store containing the WASI P1 context
    let mut store = Store::new(&engine, wasi_ctx);

    // 6. Load and compile the Wasm module from file
    let module = Module::from_file(&engine, wasm_path)?;

    // 7. Instantiate the module with our linked imports
    let instance = linker.instantiate(&mut store, &module)?;

    // 8. Retrieve exported memory and guest functions
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("WASM module does not export 'memory'")?;

    let alloc = instance.get_typed_func::<i32, i32>(&mut store, "alloc")?;
    let dealloc = instance.get_typed_func::<(i32, i32), ()>(&mut store, "dealloc")?;
    let run_plugin = instance.get_typed_func::<(i32, i32), i64>(&mut store, "run_plugin")?;

    // 9. Allocate a buffer inside Wasm guest memory for the input string
    let input_bytes = input_json.as_bytes();
    let input_len = input_bytes.len() as i32;
    let input_ptr = alloc.call(&mut store, input_len)?;

    // 10. Write the input JSON bytes directly to guest memory
    memory.write(&mut store, input_ptr as usize, input_bytes)?;

    // 11. Execute the guest plugin
    let result_packed = run_plugin.call(&mut store, (input_ptr, input_len))?;

    // 12. Deallocate the input buffer in guest memory
    dealloc.call(&mut store, (input_ptr, input_len))?;

    // 13. Decode the returned packed i64: (pointer << 32) | length
    let output_ptr = ((result_packed as u64) >> 32) as i32;
    let output_len = (result_packed & 0xFFFF_FFFF) as i32;

    if output_len < 0 || output_len > 50 * 1024 * 1024 {
        return Err("WASM guest returned invalid or excessively large output length".into());
    }

    // 14. Read the output string bytes from guest memory
    let mut output_bytes = vec![0u8; output_len as usize];
    memory.read(&mut store, output_ptr as usize, &mut output_bytes)?;

    // 15. Deallocate the output buffer inside the guest memory
    dealloc.call(&mut store, (output_ptr, output_len))?;

    // 16. Parse output as standard UTF-8 string
    let output_str = String::from_utf8(output_bytes)?;
    Ok(output_str)
}
