use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

fn make_adb_cmd(service: &str) -> Vec<u8> {
    let len = service.len();
    let header = format!("{:04x}", len);
    let mut cmd = header.into_bytes();
    cmd.extend_from_slice(service.as_bytes());
    cmd
}

fn execute_host_command(cmd: &str) -> PyResult<String> {
    let mut stream = TcpStream::connect("127.0.0.1:5037")
        .map_err(|e| PyValueError::new_err(format!("Failed to connect to ADB server: {}", e)))?;
    let payload = make_adb_cmd(cmd);
    stream
        .write_all(&payload)
        .map_err(|e| PyValueError::new_err(format!("Failed to write to ADB server: {}", e)))?;

    let mut status = [0u8; 4];
    stream
        .read_exact(&mut status)
        .map_err(|e| PyValueError::new_err(format!("Failed to read ADB status: {}", e)))?;

    if &status == b"OKAY" {
        let mut len_hex = [0u8; 4];
        if stream.read_exact(&mut len_hex).is_err() {
            return Ok(String::new());
        }
        let len_str = std::str::from_utf8(&len_hex)
            .map_err(|_| PyValueError::new_err("Invalid UTF-8 length prefix from ADB server"))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| PyValueError::new_err("Invalid hex length prefix from ADB server"))?;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).map_err(|e| {
            PyValueError::new_err(format!("Failed to read payload from ADB server: {}", e))
        })?;
        Ok(String::from_utf8_lossy(&data).to_string())
    } else if &status == b"FAIL" {
        let mut len_hex = [0u8; 4];
        stream.read_exact(&mut len_hex).map_err(|e| {
            PyValueError::new_err(format!(
                "Failed to read error length from ADB server: {}",
                e
            ))
        })?;
        let len_str = std::str::from_utf8(&len_hex)
            .map_err(|_| PyValueError::new_err("Invalid UTF-8 error length prefix"))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| PyValueError::new_err("Invalid hex error length prefix"))?;
        let mut err_msg = vec![0u8; len];
        stream
            .read_exact(&mut err_msg)
            .map_err(|e| PyValueError::new_err(format!("Failed to read error message: {}", e)))?;
        Err(PyValueError::new_err(
            String::from_utf8_lossy(&err_msg).to_string(),
        ))
    } else {
        Err(PyValueError::new_err(format!(
            "Unexpected ADB status response: {:?}",
            status
        )))
    }
}

#[pyfunction]
pub fn adb_list_devices(py: Python<'_>) -> PyResult<String> {
    py.detach(move || execute_host_command("host:devices-l"))
}

#[pyfunction]
pub fn adb_connect(py: Python<'_>, host: String) -> PyResult<String> {
    py.detach(move || execute_host_command(&format!("host:connect:{}", host)))
}

#[pyfunction]
pub fn adb_disconnect(py: Python<'_>, host: String) -> PyResult<String> {
    py.detach(move || execute_host_command(&format!("host:disconnect:{}", host)))
}

#[pyfunction]
pub fn adb_shell(py: Python<'_>, serial: String, command: String) -> PyResult<String> {
    py.detach(move || {
        let mut stream = TcpStream::connect("127.0.0.1:5037").map_err(|e| {
            PyValueError::new_err(format!("Failed to connect to ADB server: {}", e))
        })?;

        // Step 1: Transport switch
        let transport_cmd = format!("host:transport:{}", serial);
        stream
            .write_all(&make_adb_cmd(&transport_cmd))
            .map_err(|e| {
                PyValueError::new_err(format!("Failed to write transport command: {}", e))
            })?;

        let mut status = [0u8; 4];
        stream.read_exact(&mut status).map_err(|e| {
            PyValueError::new_err(format!("Failed to read transport status: {}", e))
        })?;

        if &status != b"OKAY" {
            let mut len_hex = [0u8; 4];
            stream.read_exact(&mut len_hex).ok();
            let len_str = std::str::from_utf8(&len_hex).unwrap_or("0000");
            let len = usize::from_str_radix(len_str, 16).unwrap_or(0);
            let mut err_msg = vec![0u8; len];
            stream.read_exact(&mut err_msg).ok();
            return Err(PyValueError::new_err(format!(
                "Transport failed: {}",
                String::from_utf8_lossy(&err_msg)
            )));
        }

        // Step 2: Shell service initiation
        let shell_cmd = format!("shell:{}", command);
        stream
            .write_all(&make_adb_cmd(&shell_cmd))
            .map_err(|e| PyValueError::new_err(format!("Failed to write shell command: {}", e)))?;

        stream
            .read_exact(&mut status)
            .map_err(|e| PyValueError::new_err(format!("Failed to read shell status: {}", e)))?;

        if &status != b"OKAY" {
            let mut len_hex = [0u8; 4];
            stream.read_exact(&mut len_hex).ok();
            let len_str = std::str::from_utf8(&len_hex).unwrap_or("0000");
            let len = usize::from_str_radix(len_str, 16).unwrap_or(0);
            let mut err_msg = vec![0u8; len];
            stream.read_exact(&mut err_msg).ok();
            return Err(PyValueError::new_err(format!(
                "Shell setup failed: {}",
                String::from_utf8_lossy(&err_msg)
            )));
        }

        // Step 3: Stream and collect command output until EOF
        let mut output = Vec::new();
        stream
            .read_to_end(&mut output)
            .map_err(|e| PyValueError::new_err(format!("Failed to read command output: {}", e)))?;

        Ok(String::from_utf8_lossy(&output).to_string())
    })
}

fn send_sync_req(stream: &mut TcpStream, id: &[u8; 4], path: &str) -> std::io::Result<()> {
    stream.write_all(id)?;
    let len = path.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(path.as_bytes())?;
    Ok(())
}

#[pyfunction]
pub fn adb_pull(
    py: Python<'_>,
    serial: String,
    remote_path: String,
    local_path: String,
) -> PyResult<()> {
    py.detach(move || {
        let mut stream = TcpStream::connect("127.0.0.1:5037")
            .map_err(|e| PyValueError::new_err(format!("Failed to connect to ADB: {}", e)))?;

        // Transport switch
        let transport_cmd = format!("host:transport:{}", serial);
        stream
            .write_all(&make_adb_cmd(&transport_cmd))
            .map_err(|e| PyValueError::new_err(format!("Failed to write transport: {}", e)))?;

        let mut status = [0u8; 4];
        stream.read_exact(&mut status)?;
        if &status != b"OKAY" {
            return Err(PyValueError::new_err("Transport failed"));
        }

        // Open sync service
        stream.write_all(&make_adb_cmd("sync:"))?;
        stream.read_exact(&mut status)?;
        if &status != b"OKAY" {
            return Err(PyValueError::new_err("Sync service initiation failed"));
        }

        // Send RECV command
        send_sync_req(&mut stream, b"RECV", &remote_path)
            .map_err(|e| PyValueError::new_err(format!("Failed to send RECV command: {}", e)))?;

        let mut file = File::create(&local_path)
            .map_err(|e| PyValueError::new_err(format!("Failed to create local file: {}", e)))?;

        loop {
            let mut id = [0u8; 4];
            stream
                .read_exact(&mut id)
                .map_err(|e| PyValueError::new_err(format!("Failed to read chunk ID: {}", e)))?;

            let mut val_bytes = [0u8; 4];
            stream
                .read_exact(&mut val_bytes)
                .map_err(|e| PyValueError::new_err(format!("Failed to read chunk value: {}", e)))?;

            let val = u32::from_le_bytes(val_bytes);

            if &id == b"DATA" {
                let mut chunk = vec![0u8; val as usize];
                stream.read_exact(&mut chunk).map_err(|e| {
                    PyValueError::new_err(format!("Failed to read DATA chunk: {}", e))
                })?;
                file.write_all(&chunk).map_err(|e| {
                    PyValueError::new_err(format!("Failed to write to local file: {}", e))
                })?;
            } else if &id == b"DONE" {
                break;
            } else if &id == b"FAIL" {
                let mut err_msg = vec![0u8; val as usize];
                stream.read_exact(&mut err_msg).map_err(|e| {
                    PyValueError::new_err(format!("Failed to read FAIL message: {}", e))
                })?;
                return Err(PyValueError::new_err(format!(
                    "ADB Sync Pull failed: {}",
                    String::from_utf8_lossy(&err_msg)
                )));
            } else {
                return Err(PyValueError::new_err(format!(
                    "Unexpected Sync chunk ID: {:?}",
                    id
                )));
            }
        }

        Ok(())
    })
}

#[pyfunction]
pub fn adb_push(
    py: Python<'_>,
    serial: String,
    local_path: String,
    remote_path: String,
) -> PyResult<()> {
    py.detach(move || {
        let mut stream = TcpStream::connect("127.0.0.1:5037")
            .map_err(|e| PyValueError::new_err(format!("Failed to connect to ADB: {}", e)))?;

        // Transport switch
        let transport_cmd = format!("host:transport:{}", serial);
        stream
            .write_all(&make_adb_cmd(&transport_cmd))
            .map_err(|e| PyValueError::new_err(format!("Failed to write transport: {}", e)))?;

        let mut status = [0u8; 4];
        stream.read_exact(&mut status)?;
        if &status != b"OKAY" {
            return Err(PyValueError::new_err("Transport failed"));
        }

        // Open sync service
        stream.write_all(&make_adb_cmd("sync:"))?;
        stream.read_exact(&mut status)?;
        if &status != b"OKAY" {
            return Err(PyValueError::new_err("Sync service initiation failed"));
        }

        // SEND request payload: "<remote_path>,33206" (mode 0o100666)
        let send_arg = format!("{},33206", remote_path);
        stream.write_all(b"SEND")?;
        let arg_len = send_arg.len() as u32;
        stream.write_all(&arg_len.to_le_bytes())?;
        stream.write_all(send_arg.as_bytes())?;

        let mut file = File::open(&local_path)
            .map_err(|e| PyValueError::new_err(format!("Failed to open local file: {}", e)))?;

        let mut buffer = [0u8; 64 * 1024];
        loop {
            let bytes_read = file
                .read(&mut buffer)
                .map_err(|e| PyValueError::new_err(format!("Failed to read local file: {}", e)))?;
            if bytes_read == 0 {
                break;
            }

            stream.write_all(b"DATA")?;
            let len = bytes_read as u32;
            stream.write_all(&len.to_le_bytes())?;
            stream.write_all(&buffer[..bytes_read])?;
        }

        // Send DONE message
        stream.write_all(b"DONE")?;
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        stream.write_all(&mtime.to_le_bytes())?;

        // Read final response
        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .map_err(|e| PyValueError::new_err(format!("Failed to read Sync response: {}", e)))?;

        if &response == b"OKAY" {
            let mut unused = [0u8; 4];
            stream.read_exact(&mut unused).ok();
        } else if &response == b"FAIL" {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes)?;
            let len = u32::from_le_bytes(len_bytes);
            let mut err_msg = vec![0u8; len as usize];
            stream.read_exact(&mut err_msg)?;
            return Err(PyValueError::new_err(format!(
                "ADB Sync Push failed: {}",
                String::from_utf8_lossy(&err_msg)
            )));
        } else {
            return Err(PyValueError::new_err(format!(
                "Unexpected Sync response chunk ID: {:?}",
                response
            )));
        }

        Ok(())
    })
}
