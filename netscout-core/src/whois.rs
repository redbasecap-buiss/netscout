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

impl WhoisResult {
    /// Returns `true` if the WHOIS response contains registrar information.
    pub fn has_registrar(&self) -> bool {
        self.registrar.is_some()
    }

    /// Returns `true` if expiry date information is available.
    pub fn has_expiry(&self) -> bool {
        self.expiry_date.is_some()
    }

    /// Returns the number of nameservers found.
    pub fn nameserver_count(&self) -> usize {
        self.nameservers.len()
    }

    /// Returns `true` if the WHOIS response contains any parsed data beyond raw text.
    pub fn is_parsed(&self) -> bool {
        self.registrar.is_some()
            || self.creation_date.is_some()
            || self.expiry_date.is_some()
            || !self.nameservers.is_empty()
    }

    /// Returns a short one-line summary of the WHOIS result.
    pub fn summary(&self) -> String {
        let registrar = self.registrar.as_deref().unwrap_or("unknown registrar");
        let ns_count = self.nameservers.len();
        format!(
            "{} via {} — {} ({} nameserver{})",
            self.target,
            registrar,
            self.expiry_date
                .as_deref()
                .map(|d| format!("expires {d}"))
                .unwrap_or_else(|| "no expiry info".to_string()),
            ns_count,
            if ns_count == 1 { "" } else { "s" }
        )
    }
}

impl std::fmt::Display for WhoisResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "WHOIS: {}", self.target)?;
        writeln!(f, "  Server:     {}", self.server)?;
        if let Some(ref reg) = self.registrar {
            writeln!(f, "  Registrar:  {reg}")?;
        }
        if let Some(ref d) = self.creation_date {
            writeln!(f, "  Created:    {d}")?;
        }
        if let Some(ref d) = self.expiry_date {
            writeln!(f, "  Expires:    {d}")?;
        }
        if let Some(ref d) = self.updated_date {
            writeln!(f, "  Updated:    {d}")?;
        }
        if !self.nameservers.is_empty() {
            writeln!(f, "  Nameservers:")?;
            for ns in &self.nameservers {
                writeln!(f, "    - {ns}")?;
            }
        }
        if !self.status.is_empty() {
            writeln!(f, "  Status:")?;
            for s in &self.status {
                writeln!(f, "    - {s}")?;
            }
        }
        write!(f, "  Query time: {:.1} ms", self.query_time_ms)
    }
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
        assert_eq!(whois_server_for("google.com"), "whois.verisign-grs.com");
        assert_eq!(whois_server_for("test.net"), "whois.verisign-grs.com");
    }

    #[test]
    fn test_whois_server_for_org() {
        assert_eq!(whois_server_for("example.org"), "whois.pir.org");
        assert_eq!(whois_server_for("mozilla.org"), "whois.pir.org");
    }

    #[test]
    fn test_whois_server_for_google_tlds() {
        assert_eq!(whois_server_for("example.dev"), "whois.nic.google");
        assert_eq!(whois_server_for("myapp.app"), "whois.nic.google");
    }

    #[test]
    fn test_whois_server_for_country_tlds() {
        assert_eq!(whois_server_for("example.de"), "whois.denic.de");
        assert_eq!(whois_server_for("example.uk"), "whois.nic.uk");
        assert_eq!(whois_server_for("example.fr"), "whois.nic.fr");
        assert_eq!(whois_server_for("example.ch"), "whois.nic.ch");
    }

    #[test]
    fn test_whois_server_for_new_tlds() {
        assert_eq!(whois_server_for("example.io"), "whois.nic.io");
        assert_eq!(whois_server_for("example.xyz"), "whois.nic.xyz");
        assert_eq!(whois_server_for("example.info"), "whois.afilias.net");
        assert_eq!(whois_server_for("example.me"), "whois.nic.me");
        assert_eq!(whois_server_for("example.co"), "whois.nic.co");
        assert_eq!(whois_server_for("example.ai"), "whois.nic.ai");
    }

    #[test]
    fn test_whois_server_for_unknown() {
        assert_eq!(whois_server_for("example.zzzz"), "whois.iana.org");
        assert_eq!(whois_server_for("test.nonexistent"), "whois.iana.org");
    }

    #[test]
    fn test_whois_server_case_insensitive() {
        assert_eq!(whois_server_for("EXAMPLE.COM"), "whois.verisign-grs.com");
        assert_eq!(whois_server_for("Example.ORG"), "whois.pir.org");
        assert_eq!(whois_server_for("test.IO"), "whois.nic.io");
    }

    #[test]
    fn test_whois_server_subdomain() {
        assert_eq!(
            whois_server_for("www.example.com"),
            "whois.verisign-grs.com"
        );
        assert_eq!(whois_server_for("api.test.org"), "whois.pir.org");
        assert_eq!(whois_server_for("sub.domain.xyz"), "whois.nic.xyz");
    }

    #[test]
    fn test_whois_server_no_tld() {
        assert_eq!(whois_server_for("example"), "whois.iana.org");
        assert_eq!(whois_server_for(""), "whois.iana.org");
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
    fn test_extract_field_case_insensitive() {
        let text = "DOMAIN NAME: example.com\nREGISTRAR: GoDaddy LLC\nCREATION DATE: 2020-01-01T12:00:00Z\n";
        assert_eq!(
            extract_field(text, &["domain name"]),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_field(text, &["registrar"]),
            Some("GoDaddy LLC".to_string())
        );
    }

    #[test]
    fn test_extract_field_multiple_keys() {
        let text = "Created: 2020-01-01\nLast Updated: 2021-01-01\n";
        assert_eq!(
            extract_field(text, &["Creation Date", "Created", "created"]),
            Some("2020-01-01".to_string())
        );
        assert_eq!(
            extract_field(text, &["Updated Date", "Last Updated", "changed"]),
            Some("2021-01-01".to_string())
        );
    }

    #[test]
    fn test_extract_field_empty_value() {
        let text = "Domain Name:\nRegistrar: \nCreation Date: 2020-01-01\n";
        assert_eq!(extract_field(text, &["Domain Name"]), None);
        assert_eq!(extract_field(text, &["Registrar"]), None);
        assert_eq!(
            extract_field(text, &["Creation Date"]),
            Some("2020-01-01".to_string())
        );
    }

    #[test]
    fn test_extract_field_no_colon() {
        let text = "Domain Name example.com\nRegistrar GoDaddy\n";
        assert_eq!(extract_field(text, &["Domain Name"]), None);
        assert_eq!(extract_field(text, &["Registrar"]), None);
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
    fn test_extract_all_mixed_case() {
        let text = "Name Server: ns1.example.com\nname server: ns2.example.com\nNAME SERVER: ns3.example.com\n";
        let ns = extract_all(text, &["Name Server"]);
        assert_eq!(ns.len(), 3);
        assert!(ns.contains(&"ns1.example.com".to_string()));
        assert!(ns.contains(&"ns2.example.com".to_string()));
        assert!(ns.contains(&"ns3.example.com".to_string()));
    }

    #[test]
    fn test_extract_all_empty_values() {
        let text = "Name Server: ns1.example.com\nName Server: \nName Server: ns2.example.com\n";
        let ns = extract_all(text, &["Name Server"]);
        assert_eq!(ns.len(), 2); // Empty values should be skipped
        assert_eq!(ns[0], "ns1.example.com");
        assert_eq!(ns[1], "ns2.example.com");
    }

    #[test]
    fn test_extract_all_no_matches() {
        let text = "Domain Name: example.com\nRegistrar: GoDaddy\n";
        let ns = extract_all(text, &["Name Server"]);
        assert!(ns.is_empty());
    }

    #[test]
    fn test_extract_all_multiple_keys() {
        let text =
            "Name Server: ns1.example.com\nnserver: ns2.example.com\nnameserver: ns3.example.com\n";
        let ns = extract_all(text, &["Name Server", "nserver", "nameserver"]);
        assert_eq!(ns.len(), 3);
    }

    #[test]
    fn test_whois_config_default() {
        let cfg = WhoisConfig::default();
        assert!(cfg.target.is_empty());
        assert!(cfg.server.is_none());
        assert_eq!(cfg.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_whois_config_custom() {
        let cfg = WhoisConfig {
            target: "example.com".to_string(),
            server: Some("whois.verisign-grs.com".to_string()),
            timeout: Duration::from_secs(5),
        };
        assert_eq!(cfg.target, "example.com");
        assert!(cfg.server.is_some());
        assert_eq!(cfg.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_whois_result_serialization() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: Some("GoDaddy LLC".to_string()),
            creation_date: Some("1995-08-14T04:00:00Z".to_string()),
            expiry_date: Some("2025-08-13T04:00:00Z".to_string()),
            updated_date: Some("2021-08-14T07:01:44Z".to_string()),
            nameservers: vec![
                "a.iana-servers.net".to_string(),
                "b.iana-servers.net".to_string(),
            ],
            status: vec![
                "clientDeleteProhibited".to_string(),
                "clientTransferProhibited".to_string(),
            ],
            raw: "Raw WHOIS data here...".to_string(),
            query_time_ms: 1250.5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("GoDaddy LLC"));
        assert!(json.contains("a.iana-servers.net"));
        assert!(json.contains("1250.5"));
    }

    #[test]
    fn test_whois_result_minimal() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.iana.org".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: "No match for domain".to_string(),
            query_time_ms: 500.0,
        };

        assert!(result.registrar.is_none());
        assert!(result.creation_date.is_none());
        assert!(result.nameservers.is_empty());
        assert_eq!(result.target, "example.com");
    }

    #[test]
    fn test_whois_result_has_registrar() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: Some("GoDaddy LLC".to_string()),
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: String::new(),
            query_time_ms: 100.0,
        };
        assert!(result.has_registrar());

        let no_reg = WhoisResult {
            registrar: None,
            ..result.clone()
        };
        assert!(!no_reg.has_registrar());
    }

    #[test]
    fn test_whois_result_has_expiry() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: Some("2025-08-13".to_string()),
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: String::new(),
            query_time_ms: 100.0,
        };
        assert!(result.has_expiry());

        let no_exp = WhoisResult {
            expiry_date: None,
            ..result.clone()
        };
        assert!(!no_exp.has_expiry());
    }

    #[test]
    fn test_whois_result_nameserver_count() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            status: vec![],
            raw: String::new(),
            query_time_ms: 100.0,
        };
        assert_eq!(result.nameserver_count(), 2);
    }

    #[test]
    fn test_whois_result_is_parsed() {
        let empty = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.iana.org".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: "No match".to_string(),
            query_time_ms: 200.0,
        };
        assert!(!empty.is_parsed());

        let with_registrar = WhoisResult {
            registrar: Some("GoDaddy".to_string()),
            ..empty.clone()
        };
        assert!(with_registrar.is_parsed());

        let with_ns = WhoisResult {
            nameservers: vec!["ns1.example.com".to_string()],
            ..empty.clone()
        };
        assert!(with_ns.is_parsed());
    }

    #[test]
    fn test_whois_result_summary() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: Some("GoDaddy LLC".to_string()),
            creation_date: Some("2020-01-01".to_string()),
            expiry_date: Some("2025-01-01".to_string()),
            updated_date: None,
            nameservers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            status: vec![],
            raw: String::new(),
            query_time_ms: 150.0,
        };
        let s = result.summary();
        assert!(s.contains("example.com"));
        assert!(s.contains("GoDaddy LLC"));
        assert!(s.contains("expires 2025-01-01"));
        assert!(s.contains("2 nameservers"));
    }

    #[test]
    fn test_whois_result_summary_minimal() {
        let result = WhoisResult {
            target: "test.org".to_string(),
            server: "whois.pir.org".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: String::new(),
            query_time_ms: 50.0,
        };
        let s = result.summary();
        assert!(s.contains("unknown registrar"));
        assert!(s.contains("no expiry info"));
        assert!(s.contains("0 nameservers"));
    }

    #[test]
    fn test_whois_result_summary_single_ns() {
        let result = WhoisResult {
            target: "test.io".to_string(),
            server: "whois.nic.io".to_string(),
            registrar: Some("Namecheap".to_string()),
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec!["ns1.test.io".to_string()],
            status: vec![],
            raw: String::new(),
            query_time_ms: 75.0,
        };
        let s = result.summary();
        assert!(s.contains("1 nameserver"));
        // Should NOT have plural "s"
        assert!(!s.contains("1 nameservers"));
    }

    #[test]
    fn test_whois_result_display() {
        let result = WhoisResult {
            target: "example.com".to_string(),
            server: "whois.verisign-grs.com".to_string(),
            registrar: Some("GoDaddy LLC".to_string()),
            creation_date: Some("2020-01-01".to_string()),
            expiry_date: Some("2025-01-01".to_string()),
            updated_date: Some("2023-06-15".to_string()),
            nameservers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            status: vec!["clientTransferProhibited".to_string()],
            raw: String::new(),
            query_time_ms: 150.5,
        };
        let display = format!("{result}");
        assert!(display.contains("WHOIS: example.com"));
        assert!(display.contains("Server:     whois.verisign-grs.com"));
        assert!(display.contains("Registrar:  GoDaddy LLC"));
        assert!(display.contains("Created:    2020-01-01"));
        assert!(display.contains("Expires:    2025-01-01"));
        assert!(display.contains("Updated:    2023-06-15"));
        assert!(display.contains("ns1.example.com"));
        assert!(display.contains("ns2.example.com"));
        assert!(display.contains("clientTransferProhibited"));
        assert!(display.contains("150.5 ms"));
    }

    #[test]
    fn test_whois_result_display_minimal() {
        let result = WhoisResult {
            target: "unknown.xyz".to_string(),
            server: "whois.iana.org".to_string(),
            registrar: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            raw: String::new(),
            query_time_ms: 300.0,
        };
        let display = format!("{result}");
        assert!(display.contains("WHOIS: unknown.xyz"));
        assert!(display.contains("Server:     whois.iana.org"));
        assert!(!display.contains("Registrar"));
        assert!(!display.contains("Created"));
        assert!(!display.contains("Nameservers"));
        assert!(display.contains("300.0 ms"));
    }

}
