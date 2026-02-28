use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for TLS certificate inspection.
#[derive(Debug, Clone)]
pub struct CertConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 443,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Information about a certificate in the chain.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub serial: String,
    pub is_ca: bool,
}

/// Result of a TLS certificate inspection.
#[derive(Debug, Clone, Serialize)]
pub struct CertResult {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub certificate_chain: Vec<CertInfo>,
    pub connection_time_ms: f64,
    pub warning: Option<String>,
}

/// Parse a DER-encoded X.509 certificate to extract basic fields.
/// This is a simplified parser — a full ASN.1 parser would be more robust.
fn parse_basic_cert_info(der: &[u8]) -> CertInfo {
    // We'll extract what we can from the DER; for a robust solution,
    // we'd use the x509-parser crate, but keeping deps minimal.
    let hex_serial = if der.len() > 20 {
        der[15..20]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        "unknown".to_string()
    };

    CertInfo {
        subject: extract_cn_from_der(der, "subject"),
        issuer: extract_cn_from_der(der, "issuer"),
        not_before: "see raw certificate".to_string(),
        not_after: "see raw certificate".to_string(),
        days_until_expiry: -1,
        serial: hex_serial,
        is_ca: false,
    }
}

/// Attempt to find CN-like strings in DER data.
fn extract_cn_from_der(der: &[u8], _field: &str) -> String {
    // Look for common OID for CN (2.5.4.3 = 55 04 03)
    let cn_oid = [0x55, 0x04, 0x03];
    for i in 0..der.len().saturating_sub(5) {
        if der[i..].starts_with(&cn_oid) {
            // Skip OID + tag + length
            let start = i + 3;
            if start + 2 < der.len() {
                let _tag = der[start];
                let len = der[start + 1] as usize;
                let str_start = start + 2;
                if str_start + len <= der.len() {
                    if let Ok(s) = std::str::from_utf8(&der[str_start..str_start + len]) {
                        return s.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

/// Inspect TLS certificate for a host.
pub fn inspect(config: &CertConfig) -> Result<CertResult, String> {
    let addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS failed: {e}"))?
        .next()
        .ok_or("No address")?;

    let start = Instant::now();

    // Set up rustls
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = config
        .host
        .clone()
        .try_into()
        .map_err(|e| format!("Invalid server name: {e}"))?;

    let mut conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;

    let mut sock = TcpStream::connect_timeout(&addr, config.timeout)
        .map_err(|e| format!("Connect failed: {e}"))?;
    sock.set_read_timeout(Some(config.timeout)).ok();
    sock.set_write_timeout(Some(config.timeout)).ok();

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

    // Drive the handshake by writing an empty slice and reading
    let _ = tls_stream.write_all(b"");
    let mut buf = [0u8; 1];
    // Ignore read errors — we just need the handshake to complete
    let _ = tls_stream.read(&mut buf);

    let connection_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    let tls_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        _ => "unknown",
    }
    .to_string();

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    let mut chain = Vec::new();
    if let Some(certs) = conn.peer_certificates() {
        for cert_der in certs {
            chain.push(parse_basic_cert_info(cert_der.as_ref()));
        }
    }

    let warning = chain.first().and_then(|c| {
        if c.days_until_expiry >= 0 && c.days_until_expiry <= 30 {
            Some(format!(
                "⚠️  Certificate expires in {} days!",
                c.days_until_expiry
            ))
        } else {
            None
        }
    });

    Ok(CertResult {
        host: config.host.clone(),
        port: config.port,
        tls_version,
        cipher_suite,
        certificate_chain: chain,
        connection_time_ms,
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_config_default() {
        let cfg = CertConfig::default();
        assert!(cfg.host.is_empty());
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_cert_config_custom() {
        let cfg = CertConfig {
            host: "example.com".to_string(),
            port: 8443,
            timeout: Duration::from_secs(30),
        };
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_extract_cn_no_match() {
        let data = vec![0u8; 100];
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "unknown");
    }

    #[test]
    fn test_extract_cn_empty_data() {
        let data = vec![];
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "unknown");
    }

    #[test]
    fn test_extract_cn_partial_oid() {
        let data = vec![0x55, 0x04]; // Incomplete CN OID
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "unknown");
    }

    #[test]
    fn test_extract_cn_with_valid_pattern() {
        // Simulate a DER-encoded certificate with CN
        let mut data = vec![0u8; 10];
        data.extend_from_slice(&[0x55, 0x04, 0x03]); // CN OID
        data.extend_from_slice(&[0x0C, 0x0B]); // UTF8String tag and length 11
        data.extend_from_slice(b"example.com"); // CN value
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "example.com");
    }

    #[test]
    fn test_extract_cn_truncated_string() {
        let mut data = vec![0u8; 10];
        data.extend_from_slice(&[0x55, 0x04, 0x03]); // CN OID
        data.extend_from_slice(&[0x0C, 0xFF]); // Length too large for available data
        data.extend_from_slice(b"short");
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "unknown");
    }

    #[test]
    fn test_parse_basic_cert_info() {
        let cert_data = vec![0x30, 0x82, 0x05, 0x10]; // Basic ASN.1 structure
        let cert_data = [cert_data, vec![0u8; 100]].concat(); // Add padding
        let info = parse_basic_cert_info(&cert_data);

        assert_eq!(info.subject, "unknown");
        assert_eq!(info.issuer, "unknown");
        assert_eq!(info.not_before, "see raw certificate");
        assert_eq!(info.not_after, "see raw certificate");
        assert_eq!(info.days_until_expiry, -1);
        assert!(!info.is_ca);
    }

    #[test]
    fn test_parse_basic_cert_info_short() {
        let cert_data = vec![0x30, 0x82]; // Too short
        let info = parse_basic_cert_info(&cert_data);
        assert_eq!(info.serial, "unknown");
        assert_eq!(info.subject, "unknown");
    }

    #[test]
    fn test_cert_info_serialization() {
        let info = CertInfo {
            subject: "example.com".into(),
            issuer: "Let's Encrypt".into(),
            not_before: "2024-01-01".into(),
            not_after: "2025-01-01".into(),
            days_until_expiry: 180,
            serial: "AA:BB:CC".into(),
            is_ca: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("Let's Encrypt"));
        assert!(json.contains("180"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_cert_info_ca_certificate() {
        let info = CertInfo {
            subject: "CN=Root CA".into(),
            issuer: "CN=Root CA".into(),
            not_before: "2020-01-01".into(),
            not_after: "2030-01-01".into(),
            days_until_expiry: 2000,
            serial: "01".into(),
            is_ca: true,
        };
        assert!(info.is_ca);
        assert_eq!(info.subject, info.issuer); // Self-signed root
    }

    #[test]
    fn test_cert_result_warning() {
        let result = CertResult {
            host: "example.com".into(),
            port: 443,
            tls_version: "TLSv1.3".into(),
            cipher_suite: "AES_256_GCM".into(),
            certificate_chain: vec![CertInfo {
                subject: "example.com".into(),
                issuer: "CA".into(),
                not_before: "2024-01-01".into(),
                not_after: "2024-02-01".into(),
                days_until_expiry: 15,
                serial: "AA".into(),
                is_ca: false,
            }],
            connection_time_ms: 50.0,
            warning: Some("⚠️  Certificate expires in 15 days!".into()),
        };
        assert!(result.warning.is_some());
        assert!(result.warning.unwrap().contains("15 days"));
    }

    #[test]
    fn test_cert_result_no_warning() {
        let result = CertResult {
            host: "secure.com".into(),
            port: 443,
            tls_version: "TLSv1.3".into(),
            cipher_suite: "ChaCha20Poly1305".into(),
            certificate_chain: vec![CertInfo {
                subject: "secure.com".into(),
                issuer: "DigiCert".into(),
                not_before: "2024-01-01".into(),
                not_after: "2025-01-01".into(),
                days_until_expiry: 180,
                serial: "12:34:56".into(),
                is_ca: false,
            }],
            connection_time_ms: 25.0,
            warning: None,
        };
        assert!(result.warning.is_none());
        assert_eq!(result.cipher_suite, "ChaCha20Poly1305");
    }

    #[test]
    fn test_cert_result_empty_chain() {
        let result = CertResult {
            host: "test.com".into(),
            port: 8443,
            tls_version: "TLSv1.2".into(),
            cipher_suite: "AES_128_GCM".into(),
            certificate_chain: vec![],
            connection_time_ms: 100.0,
            warning: None,
        };
        assert!(result.certificate_chain.is_empty());
        assert_eq!(result.port, 8443);
        assert_eq!(result.tls_version, "TLSv1.2");
    }

    #[test]
    fn test_cert_result_multiple_certs() {
        let chain = vec![
            CertInfo {
                subject: "example.com".into(),
                issuer: "Intermediate CA".into(),
                not_before: "2024-01-01".into(),
                not_after: "2025-01-01".into(),
                days_until_expiry: 200,
                serial: "LEAF".into(),
                is_ca: false,
            },
            CertInfo {
                subject: "Intermediate CA".into(),
                issuer: "Root CA".into(),
                not_before: "2020-01-01".into(),
                not_after: "2030-01-01".into(),
                days_until_expiry: 1500,
                serial: "INTERMEDIATE".into(),
                is_ca: true,
            },
            CertInfo {
                subject: "Root CA".into(),
                issuer: "Root CA".into(),
                not_before: "2015-01-01".into(),
                not_after: "2035-01-01".into(),
                days_until_expiry: 3000,
                serial: "ROOT".into(),
                is_ca: true,
            },
        ];

        let result = CertResult {
            host: "example.com".into(),
            port: 443,
            tls_version: "TLSv1.3".into(),
            cipher_suite: "AES_256_GCM".into(),
            certificate_chain: chain,
            connection_time_ms: 35.0,
            warning: None,
        };

        assert_eq!(result.certificate_chain.len(), 3);
        assert!(!result.certificate_chain[0].is_ca); // Leaf cert
        assert!(result.certificate_chain[1].is_ca); // Intermediate
        assert!(result.certificate_chain[2].is_ca); // Root
    }

    #[test]
    fn test_cert_result_serialization() {
        let result = CertResult {
            host: "api.example.com".into(),
            port: 443,
            tls_version: "TLSv1.3".into(),
            cipher_suite: "AES_256_GCM".into(),
            certificate_chain: vec![],
            connection_time_ms: 75.5,
            warning: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("api.example.com"));
        assert!(json.contains("TLSv1.3"));
        assert!(json.contains("75.5"));
    }
}
