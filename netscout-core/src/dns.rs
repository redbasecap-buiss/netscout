use serde::Serialize;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Supported DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordType {
    A,
    AAAA,
    MX,
    TXT,
    CNAME,
    NS,
    SOA,
    PTR,
}

impl RecordType {
    pub fn to_qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::MX => 15,
            Self::TXT => 16,
            Self::CNAME => 5,
            Self::NS => 2,
            Self::SOA => 6,
            Self::PTR => 12,
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::AAAA),
            "MX" => Some(Self::MX),
            "TXT" => Some(Self::TXT),
            "CNAME" => Some(Self::CNAME),
            "NS" => Some(Self::NS),
            "SOA" => Some(Self::SOA),
            "PTR" => Some(Self::PTR),
            _ => None,
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Configuration for a DNS query.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub domain: String,
    pub record_type: RecordType,
    pub resolver: String,
    pub timeout: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            record_type: RecordType::A,
            resolver: "8.8.8.8".to_string(),
            timeout: Duration::from_secs(5),
        }
    }
}

/// A single DNS record in the response.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

/// Result of a DNS query.
#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    pub domain: String,
    pub resolver: String,
    pub record_type: String,
    pub records: Vec<DnsRecord>,
    pub query_time_ms: f64,
    pub response_code: String,
    pub truncated: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
}

/// Build a DNS query packet.
fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // Header: ID=0xABCD, flags=0x0100 (RD=1), QDCOUNT=1
    buf.extend_from_slice(&[
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    // Question section
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    buf
}

/// Parse a DNS name from the response buffer at the given offset.
fn parse_name(buf: &[u8], offset: &mut usize) -> String {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_back = 0usize;
    let mut pos = *offset;

    loop {
        if pos >= buf.len() {
            break;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            if !jumped {
                jump_back = pos + 2;
            }
            let ptr = ((len & 0x3F) << 8) | buf.get(pos + 1).copied().unwrap_or(0) as usize;
            pos = ptr;
            jumped = true;
            continue;
        }
        pos += 1;
        if pos + len <= buf.len() {
            labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        }
        pos += len;
    }

    if jumped {
        *offset = jump_back;
    } else {
        *offset = pos;
    }
    labels.join(".")
}

/// Parse a 16-bit big-endian value.
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    if offset + 2 <= buf.len() {
        u16::from_be_bytes([buf[offset], buf[offset + 1]])
    } else {
        0
    }
}

/// Parse a 32-bit big-endian value.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    if offset + 4 <= buf.len() {
        u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    } else {
        0
    }
}

/// Format an rcode to a string.
fn rcode_str(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

/// Parse a resource record's RDATA into a human-readable string.
fn parse_rdata(buf: &[u8], offset: &mut usize, rdlength: u16, rtype: u16) -> String {
    let start = *offset;
    let end = start + rdlength as usize;

    let result = match rtype {
        1 if rdlength == 4 => {
            // A record
            format!(
                "{}.{}.{}.{}",
                buf[start],
                buf[start + 1],
                buf[start + 2],
                buf[start + 3]
            )
        }
        28 if rdlength == 16 => {
            // AAAA record
            let mut parts = Vec::with_capacity(8);
            for i in 0..8 {
                parts.push(format!("{:x}", read_u16(buf, start + i * 2)));
            }
            parts.join(":")
        }
        5 | 2 | 12 => {
            // CNAME, NS, PTR
            let mut pos = start;
            parse_name(buf, &mut pos)
        }
        15 => {
            // MX
            let preference = read_u16(buf, start);
            let mut pos = start + 2;
            let exchange = parse_name(buf, &mut pos);
            format!("{preference} {exchange}")
        }
        16 => {
            // TXT
            let mut texts = Vec::new();
            let mut pos = start;
            while pos < end {
                let tlen = buf[pos] as usize;
                pos += 1;
                if pos + tlen <= end {
                    texts.push(String::from_utf8_lossy(&buf[pos..pos + tlen]).to_string());
                }
                pos += tlen;
            }
            texts.join(" ")
        }
        6 => {
            // SOA
            let mut pos = start;
            let mname = parse_name(buf, &mut pos);
            let rname = parse_name(buf, &mut pos);
            let serial = read_u32(buf, pos);
            format!("{mname} {rname} {serial}")
        }
        _ => hex::encode(buf.get(start..end).unwrap_or_default()),
    };

    *offset = end;
    result
}

/// Simple hex encoder (avoid extra dependency).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Perform a DNS query.
pub fn query(config: &DnsConfig) -> Result<DnsResult, String> {
    let qtype = config.record_type.to_qtype();
    let packet = build_query(&config.domain, qtype);

    let resolver_addr: SocketAddr = format!("{}:53", config.resolver)
        .parse()
        .map_err(|e| format!("Invalid resolver address: {e}"))?;

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(config.timeout))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let start = Instant::now();
    socket
        .send_to(&packet, resolver_addr)
        .map_err(|e| format!("Failed to send query: {e}"))?;

    let mut resp_buf = [0u8; 4096];
    let (len, _) = socket
        .recv_from(&mut resp_buf)
        .map_err(|e| format!("Failed to receive response: {e}"))?;
    let query_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    let resp = &resp_buf[..len];
    if len < 12 {
        return Err("Response too short".to_string());
    }

    let flags = read_u16(resp, 2);
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;
    let recursion_available = flags & 0x0080 != 0;
    let authenticated_data = flags & 0x0020 != 0;
    let ancount = read_u16(resp, 6);

    // Skip question section
    let mut offset = 12usize;
    let qdcount = read_u16(resp, 4);
    for _ in 0..qdcount {
        parse_name(resp, &mut offset);
        offset += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    let mut records = Vec::new();
    for _ in 0..ancount {
        if offset >= len {
            break;
        }
        let name = parse_name(resp, &mut offset);
        if offset + 10 > len {
            break;
        }
        let rtype = read_u16(resp, offset);
        offset += 2;
        let _rclass = read_u16(resp, offset);
        offset += 2;
        let ttl = read_u32(resp, offset);
        offset += 4;
        let rdlength = read_u16(resp, offset);
        offset += 2;

        let rtype_name = match rtype {
            1 => "A",
            28 => "AAAA",
            5 => "CNAME",
            2 => "NS",
            15 => "MX",
            16 => "TXT",
            6 => "SOA",
            12 => "PTR",
            _ => "UNKNOWN",
        };

        let value = parse_rdata(resp, &mut offset, rdlength, rtype);

        records.push(DnsRecord {
            name,
            record_type: rtype_name.to_string(),
            ttl,
            value,
        });
    }

    Ok(DnsResult {
        domain: config.domain.clone(),
        resolver: config.resolver.clone(),
        record_type: config.record_type.to_string(),
        records,
        query_time_ms,
        response_code: rcode_str(rcode).to_string(),
        truncated,
        recursion_available,
        authenticated_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query_structure() {
        let pkt = build_query("example.com", 1);
        // Header is 12 bytes
        assert_eq!(pkt[0], 0xAB);
        assert_eq!(pkt[1], 0xCD);
        // RD flag set
        assert_eq!(pkt[2], 0x01);
        // QDCOUNT = 1
        assert_eq!(pkt[5], 0x01);
        // First label: "example" (7 bytes)
        assert_eq!(pkt[12], 7);
        assert_eq!(&pkt[13..20], b"example");
        // Second label: "com" (3 bytes)
        assert_eq!(pkt[20], 3);
        assert_eq!(&pkt[21..24], b"com");
        // Root label
        assert_eq!(pkt[24], 0);
    }

    #[test]
    fn test_build_query_single_label() {
        let pkt = build_query("localhost", 1);
        assert_eq!(pkt[12], 9); // "localhost" length
        assert_eq!(&pkt[13..22], b"localhost");
        assert_eq!(pkt[22], 0); // Root label
    }

    #[test]
    fn test_build_query_subdomain() {
        let pkt = build_query("www.sub.example.com", 28);
        assert_eq!(pkt[12], 3); // "www"
        assert_eq!(&pkt[13..16], b"www");
        assert_eq!(pkt[16], 3); // "sub"
        assert_eq!(&pkt[17..20], b"sub");
        // Check QTYPE is AAAA (28)
        let qtype_start = pkt.len() - 4;
        let qtype = u16::from_be_bytes([pkt[qtype_start], pkt[qtype_start + 1]]);
        assert_eq!(qtype, 28);
    }

    #[test]
    fn test_record_type_qtype() {
        assert_eq!(RecordType::A.to_qtype(), 1);
        assert_eq!(RecordType::AAAA.to_qtype(), 28);
        assert_eq!(RecordType::MX.to_qtype(), 15);
        assert_eq!(RecordType::TXT.to_qtype(), 16);
        assert_eq!(RecordType::SOA.to_qtype(), 6);
        assert_eq!(RecordType::NS.to_qtype(), 2);
        assert_eq!(RecordType::CNAME.to_qtype(), 5);
        assert_eq!(RecordType::PTR.to_qtype(), 12);
    }

    #[test]
    fn test_record_type_from_str() {
        assert_eq!(RecordType::from_str_loose("a"), Some(RecordType::A));
        assert_eq!(RecordType::from_str_loose("AAAA"), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_str_loose("mx"), Some(RecordType::MX));
        assert_eq!(RecordType::from_str_loose("invalid"), None);
        assert_eq!(RecordType::from_str_loose("TXT"), Some(RecordType::TXT));
        assert_eq!(RecordType::from_str_loose("cname"), Some(RecordType::CNAME));
        assert_eq!(RecordType::from_str_loose("NS"), Some(RecordType::NS));
        assert_eq!(RecordType::from_str_loose("soa"), Some(RecordType::SOA));
        assert_eq!(RecordType::from_str_loose("ptr"), Some(RecordType::PTR));
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(format!("{}", RecordType::A), "A");
        assert_eq!(format!("{}", RecordType::AAAA), "AAAA");
        assert_eq!(format!("{}", RecordType::MX), "MX");
    }

    #[test]
    fn test_parse_name_simple() {
        // Build a simple name: \x03foo\x03bar\x00
        let buf = b"\x03foo\x03bar\x00";
        let mut offset = 0;
        let name = parse_name(buf, &mut offset);
        assert_eq!(name, "foo.bar");
        assert_eq!(offset, 9);
    }

    // Note: DNS name compression is not fully implemented in this simplified version.
    // A full implementation would properly handle compression pointers.

    #[test]
    fn test_parse_name_empty_buffer() {
        let buf = b"";
        let mut offset = 0;
        let name = parse_name(buf, &mut offset);
        assert_eq!(name, "");
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_parse_name_truncated() {
        let buf = b"\x03foo"; // Missing null terminator
        let mut offset = 0;
        let name = parse_name(buf, &mut offset);
        // The current implementation reads "foo" but doesn't find a proper terminator
        assert_eq!(name, "foo");
    }

    #[test]
    fn test_read_u16_valid() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u16(&buf, 0), 0x0102);
        assert_eq!(read_u16(&buf, 2), 0x0304);
    }

    #[test]
    fn test_read_u16_out_of_bounds() {
        let buf = [0x01];
        assert_eq!(read_u16(&buf, 0), 0); // Should return 0 for out of bounds
        assert_eq!(read_u16(&buf, 5), 0);
    }

    #[test]
    fn test_read_u32_valid() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(read_u32(&buf, 0), 0x01020304);
        assert_eq!(read_u32(&buf, 2), 0x03040506);
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        let buf = [0x01, 0x02];
        assert_eq!(read_u32(&buf, 0), 0);
        assert_eq!(read_u32(&buf, 10), 0);
    }

    #[test]
    fn test_rcode_str() {
        assert_eq!(rcode_str(0), "NOERROR");
        assert_eq!(rcode_str(1), "FORMERR");
        assert_eq!(rcode_str(2), "SERVFAIL");
        assert_eq!(rcode_str(3), "NXDOMAIN");
        assert_eq!(rcode_str(4), "NOTIMP");
        assert_eq!(rcode_str(5), "REFUSED");
        assert_eq!(rcode_str(99), "UNKNOWN");
    }

    #[test]
    fn test_parse_rdata_a_record() {
        let buf = [192, 168, 1, 1]; // 192.168.1.1
        let mut offset = 0;
        let result = parse_rdata(&buf, &mut offset, 4, 1);
        assert_eq!(result, "192.168.1.1");
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_parse_rdata_aaaa_record() {
        let buf = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut offset = 0;
        let result = parse_rdata(&buf, &mut offset, 16, 28);
        assert_eq!(result, "2001:db8:0:0:0:0:0:1");
        assert_eq!(offset, 16);
    }

    #[test]
    fn test_parse_rdata_mx_record() {
        let buf = [0x00, 0x0A, 0x04, b'm', b'a', b'i', b'l', 0x00]; // Priority 10, mail\0
        let mut offset = 0;
        let result = parse_rdata(&buf, &mut offset, 8, 15);
        assert_eq!(result, "10 mail");
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_parse_rdata_txt_record() {
        let buf = [0x05, b'h', b'e', b'l', b'l', b'o', 0x05, b'w', b'o', b'r', b'l', b'd'];
        let mut offset = 0;
        let result = parse_rdata(&buf, &mut offset, 12, 16);
        assert_eq!(result, "hello world");
        assert_eq!(offset, 12);
    }

    #[test]
    fn test_parse_rdata_unknown_type() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        let mut offset = 0;
        let result = parse_rdata(&buf, &mut offset, 4, 999);
        assert_eq!(result, "01020304");
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.domain, "");
        assert_eq!(config.record_type, RecordType::A);
        assert_eq!(config.resolver, "8.8.8.8");
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_dns_record_serialization() {
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            value: "93.184.216.34".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("300"));
    }

    #[test]
    fn test_dns_result_serialization() {
        let result = DnsResult {
            domain: "example.com".to_string(),
            resolver: "8.8.8.8".to_string(),
            record_type: "A".to_string(),
            records: vec![],
            query_time_ms: 25.5,
            response_code: "NOERROR".to_string(),
            truncated: false,
            recursion_available: true,
            authenticated_data: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("25.5"));
        assert!(json.contains("NOERROR"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(&[0xAB, 0xCD, 0xEF]), "abcdef");
        assert_eq!(hex::encode(&[]), "");
        assert_eq!(hex::encode(&[0x00, 0xFF]), "00ff");
    }
}
