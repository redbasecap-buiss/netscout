use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Configuration for LAN scan.
#[derive(Debug, Clone)]
pub struct LanScanConfig {
    pub subnet: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub parallel: usize,
}

impl Default for LanScanConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.1.0/24".to_string(),
            ports: vec![22, 80, 443, 8080],
            timeout: Duration::from_millis(500),
            parallel: 256,
        }
    }
}

/// A discovered host.
#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: String,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub rtt_ms: f64,
}

/// LAN scan result.
#[derive(Debug, Clone, Serialize)]
pub struct LanScanResult {
    pub subnet: String,
    pub hosts: Vec<HostResult>,
    pub total_scanned: u32,
    pub hosts_found: usize,
    pub scan_time_ms: f64,
}

/// Parse a CIDR subnet into a list of IP addresses.
pub fn parse_subnet(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR: {cidr}. Expected format: x.x.x.x/N"))?;

    let ip: Ipv4Addr = ip_str.parse().map_err(|e| format!("Invalid IP: {e}"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|e| format!("Invalid prefix: {e}"))?;

    if prefix > 32 {
        return Err(format!("Invalid prefix length: {prefix}"));
    }

    if prefix < 16 {
        return Err("Prefix too large (< /16). Maximum 65536 hosts.".to_string());
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = ip_u32 & mask;
    let host_count = 1u32 << (32 - prefix);

    let mut addrs = Vec::new();
    // Skip network and broadcast for /24 and larger
    let (start, end) = if prefix < 31 {
        (1, host_count - 1)
    } else {
        (0, host_count)
    };

    for i in start..end {
        addrs.push(Ipv4Addr::from(network + i));
    }

    Ok(addrs)
}

/// Check if a host has any open ports.
async fn probe_host(
    ip: Ipv4Addr,
    ports: &[u16],
    to: Duration,
) -> Option<(Ipv4Addr, Vec<u16>, f64)> {
    let start = Instant::now();
    let mut open_ports = Vec::new();

    for &port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        if timeout(to, TcpStream::connect(addr)).await.is_ok() {
            open_ports.push(port);
        }
    }

    if open_ports.is_empty() {
        None
    } else {
        let rtt = start.elapsed().as_secs_f64() * 1000.0;
        Some((ip, open_ports, rtt))
    }
}

/// Run a LAN scan.
pub async fn scan(config: &LanScanConfig) -> Result<LanScanResult, String> {
    let addrs = parse_subnet(&config.subnet)?;
    let total_scanned = addrs.len() as u32;
    let sem = std::sync::Arc::new(Semaphore::new(config.parallel));
    let start = Instant::now();

    let mut handles = Vec::new();
    for ip in addrs {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let ports = config.ports.clone();
        let to = config.timeout;
        handles.push(tokio::spawn(async move {
            let result = probe_host(ip, &ports, to).await;
            drop(permit);
            result
        }));
    }

    let mut hosts = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, open_ports, rtt_ms))) = handle.await {
            hosts.push(HostResult {
                ip: ip.to_string(),
                hostname: None, // Reverse DNS could be added
                open_ports,
                rtt_ms,
            });
        }
    }

    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    let hosts_found = hosts.len();
    let scan_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(LanScanResult {
        subnet: config.subnet.clone(),
        hosts,
        total_scanned,
        hosts_found,
        scan_time_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subnet_24() {
        let addrs = parse_subnet("192.168.1.0/24").unwrap();
        assert_eq!(addrs.len(), 254); // Excluding network and broadcast
        assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addrs[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_parse_subnet_30() {
        let addrs = parse_subnet("10.0.0.0/30").unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(addrs[1], Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_parse_subnet_32() {
        let addrs = parse_subnet("10.0.0.1/32").unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_parse_subnet_invalid() {
        assert!(parse_subnet("192.168.1.0").is_err());
        assert!(parse_subnet("192.168.1.0/33").is_err());
        assert!(parse_subnet("192.168.1.0/8").is_err()); // Too large
    }

    #[test]
    fn test_host_result_serialization() {
        let host = HostResult {
            ip: "192.168.1.1".into(),
            hostname: Some("router.local".into()),
            open_ports: vec![22, 80],
            rtt_ms: 1.5,
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("router.local"));
    }
}
