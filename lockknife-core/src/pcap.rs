use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Serialize)]
struct ConnectionEdge {
    src: String,
    dst: String,
    protocol: String,
    source_port: Option<u16>,
    dest_port: Option<u16>,
    packet_count: u64,
    byte_count: u64,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ParsedPacket {
    src_ip: String,
    dst_ip: String,
    protocol: String,
    sport: Option<u16>,
    dport: Option<u16>,
    payload_len: usize,
    raw_payload: Vec<u8>,
    dns_query: Option<String>,
    dns_answer: Option<String>,
}

fn parse_dns_qname_local(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    for _ in 0..50 {
        let len = *buf.get(off)? as usize;
        off += 1;
        if len == 0 {
            return Some((labels.join("."), off));
        }
        if len & 0xC0 != 0 {
            return Some((labels.join("."), off + 1));
        }
        let part = buf.get(off..off + len)?;
        off += len;
        labels.push(String::from_utf8_lossy(part).to_string());
    }
    None
}

fn parse_dns(dns_payload: &[u8]) -> Option<(Option<String>, Option<String>)> {
    if dns_payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]) as usize;
    let ancount = u16::from_be_bytes([dns_payload[6], dns_payload[7]]) as usize;
    let mut off = 12;
    let mut qname = None;
    let mut answer = None;

    if qdcount > 0 {
        if let Some((name, next_off)) = parse_dns_qname_local(dns_payload, off) {
            qname = Some(name);
            off = next_off + 4;
        }
    }

    if ancount > 0 && off < dns_payload.len() {
        if let Some(first_byte) = dns_payload.get(off) {
            if first_byte & 0xC0 == 0xC0 {
                off += 2;
            } else if let Some((_, next_off)) = parse_dns_qname_local(dns_payload, off) {
                off = next_off;
            }
        }
        if off + 10 <= dns_payload.len() {
            let atype = u16::from_be_bytes([dns_payload[off], dns_payload[off + 1]]);
            let rdlength =
                u16::from_be_bytes([dns_payload[off + 8], dns_payload[off + 9]]) as usize;
            off += 10;
            if atype == 1 && rdlength == 4 && off + 4 <= dns_payload.len() {
                answer = Some(format!(
                    "{}.{}.{}.{}",
                    dns_payload[off],
                    dns_payload[off + 1],
                    dns_payload[off + 2],
                    dns_payload[off + 3]
                ));
            } else if atype == 5 && off + rdlength <= dns_payload.len() {
                if let Some((cname, _)) = parse_dns_qname_local(dns_payload, off) {
                    answer = Some(cname);
                }
            }
        }
    }

    Some((qname, answer))
}

fn parse_ipv4(ip_data: &[u8]) -> Option<ParsedPacket> {
    if ip_data.len() < 20 {
        return None;
    }
    let ihl = (ip_data[0] & 0x0f) as usize * 4;
    let proto = ip_data[9];
    let src = format!(
        "{}.{}.{}.{}",
        ip_data[12], ip_data[13], ip_data[14], ip_data[15]
    );
    let dst = format!(
        "{}.{}.{}.{}",
        ip_data[16], ip_data[17], ip_data[18], ip_data[19]
    );
    if ip_data.len() < ihl {
        return None;
    }

    let payload = &ip_data[ihl..];
    let mut sport = None;
    let mut dport = None;
    let mut protocol = "ip".to_string();
    let mut dns_query = None;
    let mut dns_answer = None;

    if proto == 6 && payload.len() >= 20 {
        protocol = "tcp".to_string();
        sport = Some(u16::from_be_bytes([payload[0], payload[1]]));
        dport = Some(u16::from_be_bytes([payload[2], payload[3]]));
        let data_off = ((payload[12] >> 4) as usize) * 4;
        if payload.len() >= data_off {
            let tcp_payload = &payload[data_off..];
            return Some(ParsedPacket {
                src_ip: src,
                dst_ip: dst,
                protocol,
                sport,
                dport,
                payload_len: tcp_payload.len(),
                raw_payload: tcp_payload.to_vec(),
                dns_query,
                dns_answer,
            });
        }
    } else if proto == 17 && payload.len() >= 8 {
        protocol = "udp".to_string();
        sport = Some(u16::from_be_bytes([payload[0], payload[1]]));
        dport = Some(u16::from_be_bytes([payload[2], payload[3]]));
        let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let udp_payload = if payload.len() >= 8 {
            let end = std::cmp::min(
                payload.len(),
                if udp_len >= 8 { udp_len } else { payload.len() },
            );
            &payload[8..end]
        } else {
            &[]
        };

        if sport == Some(53) || dport == Some(53) {
            if let Some((q, a)) = parse_dns(udp_payload) {
                dns_query = q;
                dns_answer = a;
            }
        }

        return Some(ParsedPacket {
            src_ip: src,
            dst_ip: dst,
            protocol,
            sport,
            dport,
            payload_len: udp_payload.len(),
            raw_payload: udp_payload.to_vec(),
            dns_query,
            dns_answer,
        });
    }

    Some(ParsedPacket {
        src_ip: src,
        dst_ip: dst,
        protocol,
        sport,
        dport,
        payload_len: payload.len(),
        raw_payload: payload.to_vec(),
        dns_query,
        dns_answer,
    })
}

fn parse_ipv6(ip_data: &[u8]) -> Option<ParsedPacket> {
    if ip_data.len() < 40 {
        return None;
    }
    let next_header = ip_data[6];
    let mut src = String::new();
    for i in 0..8 {
        src.push_str(&format!(
            "{:x}",
            u16::from_be_bytes([ip_data[8 + i * 2], ip_data[9 + i * 2]])
        ));
        if i < 7 {
            src.push(':');
        }
    }
    let mut dst = String::new();
    for i in 0..8 {
        dst.push_str(&format!(
            "{:x}",
            u16::from_be_bytes([ip_data[24 + i * 2], ip_data[25 + i * 2]])
        ));
        if i < 7 {
            dst.push(':');
        }
    }

    let payload = &ip_data[40..];
    let mut sport = None;
    let mut dport = None;
    let mut protocol = "ipv6".to_string();
    let mut dns_query = None;
    let mut dns_answer = None;

    if next_header == 6 && payload.len() >= 20 {
        protocol = "tcp".to_string();
        sport = Some(u16::from_be_bytes([payload[0], payload[1]]));
        dport = Some(u16::from_be_bytes([payload[2], payload[3]]));
        let data_off = ((payload[12] >> 4) as usize) * 4;
        if payload.len() >= data_off {
            let tcp_payload = &payload[data_off..];
            return Some(ParsedPacket {
                src_ip: src,
                dst_ip: dst,
                protocol,
                sport,
                dport,
                payload_len: tcp_payload.len(),
                raw_payload: tcp_payload.to_vec(),
                dns_query,
                dns_answer,
            });
        }
    } else if next_header == 17 && payload.len() >= 8 {
        protocol = "udp".to_string();
        sport = Some(u16::from_be_bytes([payload[0], payload[1]]));
        dport = Some(u16::from_be_bytes([payload[2], payload[3]]));
        let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let udp_payload = if payload.len() >= 8 {
            let end = std::cmp::min(
                payload.len(),
                if udp_len >= 8 { udp_len } else { payload.len() },
            );
            &payload[8..end]
        } else {
            &[]
        };

        if sport == Some(53) || dport == Some(53) {
            if let Some((q, a)) = parse_dns(udp_payload) {
                dns_query = q;
                dns_answer = a;
            }
        }

        return Some(ParsedPacket {
            src_ip: src,
            dst_ip: dst,
            protocol,
            sport,
            dport,
            payload_len: udp_payload.len(),
            raw_payload: udp_payload.to_vec(),
            dns_query,
            dns_answer,
        });
    }

    Some(ParsedPacket {
        src_ip: src,
        dst_ip: dst,
        protocol,
        sport,
        dport,
        payload_len: payload.len(),
        raw_payload: payload.to_vec(),
        dns_query,
        dns_answer,
    })
}

fn parse_packet_data(packet: &[u8], link_type: u32) -> Option<ParsedPacket> {
    let ip_offset;
    if link_type == 1 {
        if packet.len() < 14 {
            return None;
        }
        let mut ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype == 0x8100 {
            if packet.len() < 18 {
                return None;
            }
            ethertype = u16::from_be_bytes([packet[16], packet[17]]);
            ip_offset = 18;
        } else {
            ip_offset = 14;
        }
        if ethertype == 0x0800 {
            parse_ipv4(&packet[ip_offset..])
        } else if ethertype == 0x86dd {
            parse_ipv6(&packet[ip_offset..])
        } else {
            None
        }
    } else if link_type == 12 || link_type == 14 || link_type == 101 {
        if packet.is_empty() {
            return None;
        }
        let ver = packet[0] >> 4;
        if ver == 4 {
            parse_ipv4(packet)
        } else if ver == 6 {
            parse_ipv6(packet)
        } else {
            None
        }
    } else if link_type == 0 {
        if packet.len() < 4 {
            return None;
        }
        let family = u32::from_ne_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let ver = packet.get(4).map(|&b| b >> 4).unwrap_or(0);
        if family == 2 || ver == 4 {
            parse_ipv4(&packet[4..])
        } else if family == 24 || family == 28 || family == 30 || ver == 6 {
            parse_ipv6(&packet[4..])
        } else {
            None
        }
    } else {
        None
    }
}

struct PcapReader<'a> {
    data: &'a [u8],
    offset: usize,
    link_type: u32,
    is_swapped: bool,
}

impl<'a> PcapReader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut is_swapped = false;
        let link_type;

        if magic == 0xa1b2c3d4 || magic == 0xa1b23c4d {
            link_type = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        } else if magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1 {
            is_swapped = true;
            link_type = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        } else {
            return None;
        }

        Some(Self {
            data,
            offset: 24,
            link_type,
            is_swapped,
        })
    }

    pub fn next_packet(&mut self) -> Option<&'a [u8]> {
        if self.offset + 16 > self.data.len() {
            return None;
        }

        let incl_len_bytes = &self.data[self.offset + 8..self.offset + 12];
        let incl_len = if self.is_swapped {
            u32::from_le_bytes([
                incl_len_bytes[0],
                incl_len_bytes[1],
                incl_len_bytes[2],
                incl_len_bytes[3],
            ]) as usize
        } else {
            u32::from_be_bytes([
                incl_len_bytes[0],
                incl_len_bytes[1],
                incl_len_bytes[2],
                incl_len_bytes[3],
            ]) as usize
        };

        self.offset += 16;
        if self.offset + incl_len > self.data.len() {
            return None;
        }

        let pkt = &self.data[self.offset..self.offset + incl_len];
        self.offset += incl_len;
        Some(pkt)
    }
}

struct PcapngReader<'a> {
    data: &'a [u8],
    offset: usize,
    link_type: u32,
    is_swapped: bool,
}

impl<'a> PcapngReader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let block_type = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if block_type != 0x0A0D0D0A {
            return None;
        }

        let bom = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let mut is_swapped = false;
        if bom == 0x1A2B3C4D {
            // correct order
        } else if bom == 0x4D3C2B1A {
            is_swapped = true;
        } else {
            return None;
        }

        let mut offset = 0;
        let mut link_type = 1;

        while offset + 12 <= data.len() {
            let btype = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let blen_bytes = &data[offset + 4..offset + 8];
            let blen = if is_swapped {
                u32::from_le_bytes([blen_bytes[0], blen_bytes[1], blen_bytes[2], blen_bytes[3]])
                    as usize
            } else {
                u32::from_be_bytes([blen_bytes[0], blen_bytes[1], blen_bytes[2], blen_bytes[3]])
                    as usize
            };
            if blen < 12 || offset + blen > data.len() {
                break;
            }

            if btype == 0x00000001 {
                let lt_bytes = &data[offset + 8..offset + 10];
                link_type = if is_swapped {
                    u16::from_le_bytes([lt_bytes[0], lt_bytes[1]]) as u32
                } else {
                    u16::from_be_bytes([lt_bytes[0], lt_bytes[1]]) as u32
                };
                break;
            }
            offset += blen;
        }

        let shb_len_bytes = &data[4..8];
        let shb_len = if is_swapped {
            u32::from_le_bytes([
                shb_len_bytes[0],
                shb_len_bytes[1],
                shb_len_bytes[2],
                shb_len_bytes[3],
            ]) as usize
        } else {
            u32::from_be_bytes([
                shb_len_bytes[0],
                shb_len_bytes[1],
                shb_len_bytes[2],
                shb_len_bytes[3],
            ]) as usize
        };

        Some(Self {
            data,
            offset: shb_len,
            link_type,
            is_swapped,
        })
    }

    pub fn next_packet(&mut self) -> Option<&'a [u8]> {
        while self.offset + 12 <= self.data.len() {
            let btype_bytes = &self.data[self.offset..self.offset + 4];
            let btype = u32::from_be_bytes([
                btype_bytes[0],
                btype_bytes[1],
                btype_bytes[2],
                btype_bytes[3],
            ]);

            let blen_bytes = &self.data[self.offset + 4..self.offset + 8];
            let blen = if self.is_swapped {
                u32::from_le_bytes([blen_bytes[0], blen_bytes[1], blen_bytes[2], blen_bytes[3]])
                    as usize
            } else {
                u32::from_be_bytes([blen_bytes[0], blen_bytes[1], blen_bytes[2], blen_bytes[3]])
                    as usize
            };

            if blen < 12 || self.offset + blen > self.data.len() {
                return None;
            }

            let current_block_data = &self.data[self.offset..self.offset + blen];
            self.offset += blen;

            if btype == 0x00000006 {
                if current_block_data.len() < 28 {
                    continue;
                }
                let cap_len_bytes = &current_block_data[20..24];
                let cap_len = if self.is_swapped {
                    u32::from_le_bytes([
                        cap_len_bytes[0],
                        cap_len_bytes[1],
                        cap_len_bytes[2],
                        cap_len_bytes[3],
                    ]) as usize
                } else {
                    u32::from_be_bytes([
                        cap_len_bytes[0],
                        cap_len_bytes[1],
                        cap_len_bytes[2],
                        cap_len_bytes[3],
                    ]) as usize
                };
                if 28 + cap_len <= current_block_data.len() {
                    return Some(&current_block_data[28..28 + cap_len]);
                }
            } else if btype == 0x00000003 {
                if current_block_data.len() < 12 {
                    continue;
                }
                let cap_len_bytes = &current_block_data[8..12];
                let cap_len = if self.is_swapped {
                    u32::from_le_bytes([
                        cap_len_bytes[0],
                        cap_len_bytes[1],
                        cap_len_bytes[2],
                        cap_len_bytes[3],
                    ]) as usize
                } else {
                    u32::from_be_bytes([
                        cap_len_bytes[0],
                        cap_len_bytes[1],
                        cap_len_bytes[2],
                        cap_len_bytes[3],
                    ]) as usize
                };
                if 12 + cap_len <= current_block_data.len() {
                    return Some(&current_block_data[12..12 + cap_len]);
                }
            }
        }
        None
    }
}

#[pyfunction]
#[allow(clippy::type_complexity)]
pub fn analyze_pcap_native(py: Python<'_>, file_path: &str) -> PyResult<String> {
    let mut file = File::open(file_path)
        .map_err(|e| PyValueError::new_err(format!("Failed to open PCAP file: {}", e)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| PyValueError::new_err(format!("Failed to read PCAP file: {}", e)))?;

    py.detach(move || {
        let mut protocols = HashMap::new();
        let mut ports = HashMap::new();
        let mut dns_records = Vec::new();
        let mut texts = Vec::new();
        let mut edges: HashMap<(String, String, String, Option<u16>, Option<u16>), ConnectionEdge> =
            HashMap::new();

        let link_type;
        let mut pcap_reader = PcapReader::new(&bytes);
        let mut pcapng_reader = PcapngReader::new(&bytes);

        let mut packets = Vec::new();

        if let Some(ref mut reader) = pcap_reader {
            link_type = reader.link_type;
            while let Some(pkt) = reader.next_packet() {
                packets.push(pkt);
            }
        } else if let Some(ref mut reader) = pcapng_reader {
            link_type = reader.link_type;
            while let Some(pkt) = reader.next_packet() {
                packets.push(pkt);
            }
        } else {
            return Err(PyValueError::new_err("Invalid PCAP/PCAPNG file format"));
        }

        let total_packets = packets.len() as u64;

        for pkt in packets {
            if let Some(parsed) = parse_packet_data(pkt, link_type) {
                *protocols.entry(parsed.protocol.clone()).or_insert(0u64) += 1;
                if let Some(dp) = parsed.dport {
                    *ports.entry(dp.to_string()).or_insert(0u64) += 1;
                }

                // Connection edges accumulation
                let key = (
                    parsed.src_ip.clone(),
                    parsed.dst_ip.clone(),
                    parsed.protocol.clone(),
                    parsed.sport,
                    parsed.dport,
                );
                let edge = edges.entry(key).or_insert(ConnectionEdge {
                    src: parsed.src_ip.clone(),
                    dst: parsed.dst_ip.clone(),
                    protocol: parsed.protocol.clone(),
                    source_port: parsed.sport,
                    dest_port: parsed.dport,
                    packet_count: 0,
                    byte_count: 0,
                });
                edge.packet_count += 1;
                edge.byte_count += pkt.len() as u64;

                // DNS records accumulation
                if let Some(q) = parsed.dns_query {
                    dns_records.push(json!({
                        "query": q.to_lowercase(),
                        "answer": parsed.dns_answer,
                        "source": "rust"
                    }));
                }

                // Decode payload texts (up to 50)
                if texts.len() < 50 && !parsed.raw_payload.is_empty() {
                    let text = String::from_utf8_lossy(&parsed.raw_payload).to_string();
                    if !text.trim().is_empty() {
                        texts.push(text);
                    }
                }
            }
        }

        let connection_edges: Vec<ConnectionEdge> = edges.into_values().collect();

        let out = json!({
            "total_packets": total_packets,
            "protocols": protocols,
            "ports": ports,
            "dns_records": dns_records,
            "texts": texts,
            "connection_edges": connection_edges
        });

        Ok(out.to_string())
    })
}
