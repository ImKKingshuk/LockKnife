use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use goblin::elf::Elf;
use nom::number::complete::le_u32;
use nom::IResult;

const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;

fn dex_header_fields(input: &[u8]) -> IResult<&[u8], (String, u32, u32, u32, u32)> {
    let (input, magic_raw) = nom::bytes::complete::take(8usize)(input)?;
    let magic = std::str::from_utf8(magic_raw).unwrap_or("").to_string();
    let (input, checksum) = le_u32(input)?;
    let (input, _) = nom::bytes::complete::take(4usize)(input)?;
    let (input, _) = nom::bytes::complete::take(20usize)(input)?;
    let (input, file_size) = le_u32(input)?;
    let (input, header_size) = le_u32(input)?;
    let (input, endian_tag) = le_u32(input)?;
    Ok((input, (magic, checksum, file_size, header_size, endian_tag)))
}

#[pyfunction]
pub fn parse_dex_header_json(dex_bytes: &[u8]) -> PyResult<String> {
    if dex_bytes.len() > MAX_BINARY_BYTES {
        return Err(PyValueError::new_err("dex_bytes exceeds size limit"));
    }
    if dex_bytes.len() < 0x70 {
        return Err(PyValueError::new_err("dex_bytes too small"));
    }
    let (_rest, (magic, checksum, file_size, header_size, endian_tag)) =
        dex_header_fields(dex_bytes).map_err(|_| PyValueError::new_err("invalid DEX header"))?;
    if !magic.starts_with("dex\n") {
        return Err(PyValueError::new_err("invalid DEX magic"));
    }
    let obj = serde_json::json!({
        "magic": magic,
        "checksum_u32": checksum,
        "file_size": file_size,
        "header_size": header_size,
        "endian_tag": endian_tag
    });
    Ok(obj.to_string())
}

#[pyfunction]
pub fn parse_elf_header_json(data: &[u8]) -> PyResult<String> {
    if data.len() > MAX_BINARY_BYTES {
        return Err(PyValueError::new_err("data exceeds size limit"));
    }
    if data.len() < 16 {
        return Err(PyValueError::new_err("data too small"));
    }
    if &data[0..4] != b"\x7FELF" {
        return Err(PyValueError::new_err("invalid ELF magic"));
    }
    let elf = Elf::parse(data).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ident = elf.header.e_ident;
    let obj = serde_json::json!({
        "class": ident[4],
        "endianness": ident[5],
        "osabi": ident[7],
        "abi_version": ident[8],
        "machine": elf.header.e_machine,
        "entry": elf.entry,
        "program_headers": elf.program_headers.len(),
        "section_headers": elf.section_headers.len(),
    });
    Ok(obj.to_string())
}

#[cfg(test)]
mod tests {
    use super::{parse_dex_header_json, parse_elf_header_json};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
        });
    }

    #[test]
    fn test_parse_dex_header_ok() {
        init_python();
        let mut buf = vec![0u8; 0x70];
        buf[..8].copy_from_slice(b"dex\n035\0");
        let out = parse_dex_header_json(&buf).unwrap();
        assert!(out.contains("dex"));
    }

    #[test]
    fn test_parse_dex_header_invalid_magic() {
        init_python();
        let buf = vec![0u8; 0x70];
        let err = parse_dex_header_json(&buf).unwrap_err();
        assert!(format!("{err}").contains("DEX"));
    }

    #[test]
    fn test_parse_elf_invalid() {
        init_python();
        let err = parse_elf_header_json(b"not-elf").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid") || msg.contains("too small"));
    }

    #[test]
    fn test_parse_elf_header_ok() {
        init_python();
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16] = 2;
        elf[18] = 0x3e;
        elf[20] = 1;
        elf[52] = 64;
        elf[54] = 56;
        elf[58] = 64;
        let out = parse_elf_header_json(&elf).unwrap();
        assert!(out.contains("\"class\""));
    }
}
