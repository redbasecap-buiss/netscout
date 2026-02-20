use netscout_core::dns::{DnsConfig, RecordType};
use netscout_core::ping::PingConfig;
use netscout_core::port::{parse_ports, top_ports};
use netscout_core::scan::parse_subnet;
use netscout_core::OutputFormat;
use std::time::Duration;

#[test]
fn test_output_format_equality() {
    assert_eq!(OutputFormat::Json, OutputFormat::Json);
    assert_ne!(OutputFormat::Json, OutputFormat::Human);
    assert_ne!(OutputFormat::Table, OutputFormat::Human);
}

#[test]
fn test_ping_config_construction() {
    let config = PingConfig {
        target: "google.com".to_string(),
        count: 10,
        interval: Duration::from_millis(500),
        timeout: Duration::from_secs(1),
        port: 443,
    };
    assert_eq!(config.count, 10);
    assert_eq!(config.port, 443);
}

#[test]
fn test_dns_config_construction() {
    let config = DnsConfig {
        domain: "example.com".to_string(),
        record_type: RecordType::MX,
        resolver: "1.1.1.1".to_string(),
        ..Default::default()
    };
    assert_eq!(config.record_type, RecordType::MX);
    assert_eq!(config.resolver, "1.1.1.1");
}

#[test]
fn test_port_parse_complex() {
    let ports = parse_ports("22,80,443,3000-3005,8080").unwrap();
    assert_eq!(
        ports,
        vec![22, 80, 443, 3000, 3001, 3002, 3003, 3004, 3005, 8080]
    );
}

#[test]
fn test_top_ports_contains_essentials() {
    let ports = top_ports();
    assert!(ports.contains(&22)); // SSH
    assert!(ports.contains(&80)); // HTTP
    assert!(ports.contains(&443)); // HTTPS
    assert!(ports.contains(&53)); // DNS
}

#[test]
fn test_subnet_parse_various() {
    // /24 should give 254 hosts
    assert_eq!(parse_subnet("10.0.0.0/24").unwrap().len(), 254);
    // /28 should give 14 hosts
    assert_eq!(parse_subnet("10.0.0.0/28").unwrap().len(), 14);
    // /31 should give 2 hosts
    assert_eq!(parse_subnet("10.0.0.0/31").unwrap().len(), 2);
}
