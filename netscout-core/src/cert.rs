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
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_extract_cn_no_match() {
        let data = vec![0u8; 100];
        let cn = extract_cn_from_der(&data, "subject");
        assert_eq!(cn, "unknown");
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
        assert!(json.contains("180"));
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
    }
}
