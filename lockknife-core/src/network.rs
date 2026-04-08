use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;

const MAX_PACKET_BYTES: usize = 1024 * 1024;

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_be(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn parse_dns_qname(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    for _ in 0..50 {
        let len = *buf.get(off)? as usize;
        off += 1;
        if len == 0 {
            return Some((labels.join("."), off));
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let part = buf.get(off..off + len)?;
        off += len;
        labels.push(String::from_utf8_lossy(part).to_string());
    }
    None
}

#[pyfunction]
pub fn parse_ipv4_header_json(packet_bytes: &[u8]) -> PyResult<String> {
    if packet_bytes.len() > MAX_PACKET_BYTES {
        return Err(PyValueError::new_err("packet_bytes exceeds size limit"));
    }
    if packet_bytes.len() < 20 {
        return Err(PyValueError::new_err("packet_bytes too small"));
    }
    let vihl = packet_bytes[0];
    let version = vihl >> 4;
    let ihl = (vihl & 0x0f) as usize * 4;
    if version != 4 || ihl < 20 || packet_bytes.len() < ihl {
        return Err(PyValueError::new_err("not an IPv4 header"));
    }
    let total_len = read_u16_be(packet_bytes, 2).unwrap_or(0);
    let proto = packet_bytes[9];
    let src = format!(
        "{}.{}.{}.{}",
        packet_bytes[12], packet_bytes[13], packet_bytes[14], packet_bytes[15]
    );
    let dst = format!(
        "{}.{}.{}.{}",
        packet_bytes[16], packet_bytes[17], packet_bytes[18], packet_bytes[19]
    );

    let mut out = json!({
        "version": version,
        "ihl": ihl,
        "total_len": total_len,
        "protocol": proto,
        "src": src,
        "dst": dst
    });

    let payload = &packet_bytes[ihl..];
    if proto == 6 && payload.len() >= 20 {
        let src_port = read_u16_be(payload, 0).unwrap_or(0);
        let dst_port = read_u16_be(payload, 2).unwrap_or(0);
        let seq = read_u32_be(payload, 4).unwrap_or(0);
        let ack = read_u32_be(payload, 8).unwrap_or(0);
        let data_off = ((payload[12] >> 4) as usize) * 4;
        let flags = payload[13];
        out["tcp"] = json!({
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "data_offset": data_off,
            "flags": flags
        });
    } else if proto == 17 && payload.len() >= 8 {
        let src_port = read_u16_be(payload, 0).unwrap_or(0);
        let dst_port = read_u16_be(payload, 2).unwrap_or(0);
        let len = read_u16_be(payload, 4).unwrap_or(0);
        out["udp"] = json!({"src_port": src_port, "dst_port": dst_port, "len": len});
        if src_port == 53 || dst_port == 53 {
            let dns = &payload[8..];
            if dns.len() >= 12 {
                let qdcount = read_u16_be(dns, 4).unwrap_or(0);
                let mut qname = None;
                if qdcount > 0 {
                    if let Some((name, next_off)) = parse_dns_qname(dns, 12) {
                        if dns.len() >= next_off + 4 {
                            let qtype = read_u16_be(dns, next_off).unwrap_or(0);
                            let qclass = read_u16_be(dns, next_off + 2).unwrap_or(0);
                            qname = Some(json!({"name": name, "qtype": qtype, "qclass": qclass}));
                        }
                    }
                }
                out["dns"] = json!({
                    "qdcount": qdcount,
                    "question": qname
                });
            }
        }
    }

    Ok(out.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_ipv4_header_json;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
        });
    }

    #[test]
    fn test_ipv4_min_packet() {
        init_python();
        let pkt = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
        ];
        let out = parse_ipv4_header_json(&pkt).unwrap();
        assert!(out.contains("192.0.2.1"));
    }

    #[test]
    fn test_ipv4_rejects_small() {
        init_python();
        let err = parse_ipv4_header_json(&[1, 2, 3]).unwrap_err();
        assert!(format!("{err}").contains("too small"));
    }

    #[test]
    fn test_ipv4_udp_dns() {
        init_python();
        let dns = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let udp_len = 8 + dns.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0u8; 20 + udp_len];
        pkt[0] = 0x45;
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = (total_len & 0xff) as u8;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20] = 0x04;
        pkt[21] = 0xd2;
        pkt[22] = 0x00;
        pkt[23] = 0x35;
        pkt[24] = (udp_len >> 8) as u8;
        pkt[25] = (udp_len & 0xff) as u8;
        pkt[28..28 + dns.len()].copy_from_slice(&dns);
        let out = parse_ipv4_header_json(&pkt).unwrap();
        assert!(out.contains("\"udp\""));
        assert!(out.contains("example"));
    }

    #[test]
    fn test_ipv4_tcp_header() {
        init_python();
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 0x28;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 2]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 3]);
        pkt[20] = 0x1f;
        pkt[21] = 0x90;
        pkt[22] = 0x00;
        pkt[23] = 0x50;
        pkt[32] = 0x50;
        let out = parse_ipv4_header_json(&pkt).unwrap();
        assert!(out.contains("\"tcp\""));
        assert!(out.contains("\"dst_port\":80"));
    }
}
