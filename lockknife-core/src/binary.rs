use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use goblin::elf::Elf;
use nom::number::complete::le_u32;
use nom::IResult;

const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;

struct DexHeader {
    magic: String,
    checksum: u32,
    signature: Vec<u8>,
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
}

fn parse_dex_header(input: &[u8]) -> IResult<&[u8], DexHeader> {
    let (input, magic_raw) = nom::bytes::complete::take(8usize)(input)?;
    let magic = std::str::from_utf8(magic_raw).unwrap_or("").to_string();
    let (input, checksum) = le_u32(input)?;
    let (input, signature_raw) = nom::bytes::complete::take(20usize)(input)?;
    let signature = signature_raw.to_vec();
    let (input, file_size) = le_u32(input)?;
    let (input, header_size) = le_u32(input)?;
    let (input, endian_tag) = le_u32(input)?;
    let (input, link_size) = le_u32(input)?;
    let (input, link_off) = le_u32(input)?;
    let (input, map_off) = le_u32(input)?;
    let (input, string_ids_size) = le_u32(input)?;
    let (input, string_ids_off) = le_u32(input)?;
    let (input, type_ids_size) = le_u32(input)?;
    let (input, type_ids_off) = le_u32(input)?;
    let (input, proto_ids_size) = le_u32(input)?;
    let (input, proto_ids_off) = le_u32(input)?;
    let (input, field_ids_size) = le_u32(input)?;
    let (input, field_ids_off) = le_u32(input)?;
    let (input, method_ids_size) = le_u32(input)?;
    let (input, method_ids_off) = le_u32(input)?;
    let (input, class_defs_size) = le_u32(input)?;
    let (input, class_defs_off) = le_u32(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, data_off) = le_u32(input)?;

    Ok((
        input,
        DexHeader {
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        },
    ))
}

#[pyfunction]
pub fn parse_dex_header_json(py: Python<'_>, dex_bytes: &[u8]) -> PyResult<String> {
    if dex_bytes.len() > MAX_BINARY_BYTES {
        return Err(PyValueError::new_err("dex_bytes exceeds size limit"));
    }
    if dex_bytes.len() < 0x70 {
        return Err(PyValueError::new_err("dex_bytes too small"));
    }
    let dex_bytes = dex_bytes.to_vec();
    py.detach(move || {
        let (_rest, header) = parse_dex_header(&dex_bytes)
            .map_err(|_| PyValueError::new_err("invalid DEX header"))?;
        if !header.magic.starts_with("dex\n") {
            return Err(PyValueError::new_err("invalid DEX magic"));
        }
        let obj = serde_json::json!({
            "magic": header.magic,
            "checksum_u32": header.checksum,
            "signature_hex": hex::encode(&header.signature),
            "file_size": header.file_size,
            "header_size": header.header_size,
            "endian_tag": header.endian_tag,
            "link_size": header.link_size,
            "link_off": header.link_off,
            "map_off": header.map_off,
            "string_ids_size": header.string_ids_size,
            "string_ids_off": header.string_ids_off,
            "type_ids_size": header.type_ids_size,
            "type_ids_off": header.type_ids_off,
            "proto_ids_size": header.proto_ids_size,
            "proto_ids_off": header.proto_ids_off,
            "field_ids_size": header.field_ids_size,
            "field_ids_off": header.field_ids_off,
            "method_ids_size": header.method_ids_size,
            "method_ids_off": header.method_ids_off,
            "class_defs_size": header.class_defs_size,
            "class_defs_off": header.class_defs_off,
            "data_size": header.data_size,
            "data_off": header.data_off,
        });
        Ok(obj.to_string())
    })
}

#[pyfunction]
pub fn parse_elf_header_json(py: Python<'_>, data: &[u8]) -> PyResult<String> {
    if data.len() > MAX_BINARY_BYTES {
        return Err(PyValueError::new_err("data exceeds size limit"));
    }
    if data.len() < 16 {
        return Err(PyValueError::new_err("data too small"));
    }
    if &data[0..4] != b"\x7FELF" {
        return Err(PyValueError::new_err("invalid ELF magic"));
    }
    let data = data.to_vec();
    py.detach(move || {
        let elf = Elf::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let ident = elf.header.e_ident;
        let dynsyms: Vec<String> = elf
            .dynsyms
            .iter()
            .map(|sym| {
                elf.dynstrtab
                    .get_at(sym.st_name)
                    .unwrap_or("<unknown>")
                    .to_string()
            })
            .collect();
        let libraries: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

        let obj = serde_json::json!({
            "class": ident[4],
            "endianness": ident[5],
            "osabi": ident[7],
            "abi_version": ident[8],
            "machine": elf.header.e_machine,
            "entry": elf.entry,
            "program_headers": elf.program_headers.len(),
            "section_headers": elf.section_headers.len(),
            "dynsyms": dynsyms,
            "libraries": libraries,
        });
        Ok(obj.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_dex_header_json, parse_elf_header_json};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::Python::initialize();
        });
    }

    #[test]
    fn test_parse_dex_header_ok() {
        init_python();
        let mut buf = vec![0u8; 0x70];
        buf[..8].copy_from_slice(b"dex\n035\0");
        let out = pyo3::Python::attach(|py| parse_dex_header_json(py, &buf).unwrap());
        assert!(out.contains("dex"));
    }

    #[test]
    fn test_parse_dex_header_invalid_magic() {
        init_python();
        let buf = vec![0u8; 0x70];
        let err = pyo3::Python::attach(|py| parse_dex_header_json(py, &buf).unwrap_err());
        assert!(format!("{err}").contains("DEX"));
    }

    #[test]
    fn test_parse_elf_invalid() {
        init_python();
        let err = pyo3::Python::attach(|py| parse_elf_header_json(py, b"not-elf").unwrap_err());
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
        let out = pyo3::Python::attach(|py| parse_elf_header_json(py, &elf).unwrap());
        assert!(out.contains("\"class\""));
    }
}
