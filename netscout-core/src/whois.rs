use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Configuration for a WHOIS query.
#[derive(Debug, Clone)]
pub struct WhoisConfig {
    pub target: String,
    pub server: Option<String>,
    pub timeout: Duration,
}

impl Default for WhoisConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            server: None,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Parsed WHOIS result.
#[derive(Debug, Clone, Serialize)]
pub struct WhoisResult {
    pub target: String,
    pub server: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub updated_date: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub raw: String,
    pub query_time_ms: f64,
}

/// Determine the WHOIS server for a domain.
fn whois_server_for(target: &str) -> String {
    // Use IANA WHOIS for TLD lookup, then follow referral
    let tld = target.rsplit('.').next().unwrap_or("");
    match tld.to_lowercase().as_str() {
        "com" | "net" => "whois.verisign-grs.com".to_string(),
        "org" => "whois.pir.org".to_string(),
        "io" => "whois.nic.io".to_string(),
        "dev" => "whois.nic.google".to_string(),
        "app" => "whois.nic.google".to_string(),
        "xyz" => "whois.nic.xyz".to_string(),
        "info" => "whois.afilias.net".to_string(),
        "me" => "whois.nic.me".to_string(),
        "co" => "whois.nic.co".to_string(),
        "ai" => "whois.nic.ai".to_string(),
        "de" => "whois.denic.de".to_string(),
        "uk" => "whois.nic.uk".to_string(),
        "fr" => "whois.nic.fr".to_string(),
        "ch" => "whois.nic.ch".to_string(),
        _ => "whois.iana.org".to_string(),
    }
}

/// Perform raw WHOIS query to a server.
fn raw_whois(server: &str, query: &str, timeout_dur: Duration) -> Result<(String, f64), String> {
    let addr = format!("{server}:43");
    let start = Instant::now();

    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("Connect to {server}: {e}"))?;
    stream.set_read_timeout(Some(timeout_dur)).ok();
    stream.set_write_timeout(Some(timeout_dur)).ok();

    let q = format!("{query}\r\n");
    stream
        .write_all(q.as_bytes())
        .map_err(|e| format!("Write: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Read: {e}"))?;

    let query_time_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((response, query_time_ms))
}

/// Extract a field value from WHOIS response text.
fn extract_field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_lowercase();
        for key in keys {
            if lower.contains(&key.to_lowercase()) {
                if let Some((_k, v)) = line.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract all values for a field from WHOIS text.
fn extract_all(text: &str, keys: &[&str]) -> Vec<String> {
    let mut results = Vec::new();
    for line in text.lines() {
        let lower = line.to_lowercase();
        for key in keys {
            if lower.contains(&key.to_lowercase()) {
                if let Some((_k, v)) = line.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() {
                        results.push(v.to_string());
                    }
                }
            }
        }
    }
    results
}

/// Query WHOIS for a domain or IP.
pub fn query(config: &WhoisConfig) -> Result<WhoisResult, String> {
    let server = config
        .server
        .clone()
        .unwrap_or_else(|| whois_server_for(&config.target));

    let (raw, query_time_ms) = raw_whois(&server, &config.target, config.timeout)?;

    let registrar = extract_field(&raw, &["Registrar:", "registrar"]);
    let creation_date = extract_field(&raw, &["Creation Date", "Created", "created"]);
    let expiry_date = extract_field(
        &raw,
        &[
            "Registry Expiry Date",
            "Expiry Date",
            "Expiration Date",
            "expires",
        ],
    );
    let updated_date = extract_field(&raw, &["Updated Date", "Last Updated", "changed"]);
    let nameservers = extract_all(&raw, &["Name Server", "nserver", "nameserver"]);
    let status = extract_all(&raw, &["Status", "Domain Status"]);

    Ok(WhoisResult {
        target: config.target.clone(),
        server,
        registrar,
        creation_date,
        expiry_date,
        updated_date,
        nameservers,
        status,
        raw,
        query_time_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whois_server_for_com() {
        assert_eq!(whois_server_for("example.com"), "whois.verisign-grs.com");
    }

    #[test]
    fn test_whois_server_for_org() {
        assert_eq!(whois_server_for("example.org"), "whois.pir.org");
    }

    #[test]
    fn test_whois_server_for_unknown() {
        assert_eq!(whois_server_for("example.zzzz"), "whois.iana.org");
    }

    #[test]
    fn test_extract_field() {
        let text = "Domain Name: example.com\nRegistrar: GoDaddy\nCreation Date: 2020-01-01\n";
        assert_eq!(
            extract_field(text, &["Registrar"]),
            Some("GoDaddy".to_string())
        );
        assert_eq!(
            extract_field(text, &["Creation Date"]),
            Some("2020-01-01".to_string())
        );
        assert_eq!(extract_field(text, &["Nonexistent"]), None);
    }

    #[test]
    fn test_extract_all() {
        let text = "Name Server: ns1.example.com\nName Server: ns2.example.com\n";
        let ns = extract_all(text, &["Name Server"]);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0], "ns1.example.com");
        assert_eq!(ns[1], "ns2.example.com");
    }

    #[test]
    fn test_whois_config_default() {
        let cfg = WhoisConfig::default();
        assert!(cfg.server.is_none());
    }
}
