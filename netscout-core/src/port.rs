use serde::Serialize;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Configuration for a port scan.
#[derive(Debug, Clone)]
pub struct PortConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub parallel: usize,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: top_ports(),
            timeout: Duration::from_secs(2),
            parallel: 100,
        }
    }
}

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// Aggregated scan result.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub target: String,
    pub resolved_addr: String,
    pub ports: Vec<PortResult>,
    pub open_count: usize,
    pub closed_count: usize,
    pub scan_time_ms: f64,
}

/// Parse a port range string like "80,443,8000-9000".
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {start}"))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {end}"))?;
            if start > end {
                return Err(format!("Invalid range: {start}-{end}"));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().map_err(|_| format!("Invalid port: {part}"))?;
            ports.push(port);
        }
    }
    Ok(ports)
}

/// Return the top 100 most common ports.
pub fn top_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080, 8443, 8888, 20, 26, 69, 79, 81, 88, 106, 113, 119, 123, 137, 138, 161, 162,
        179, 194, 389, 427, 443, 465, 500, 514, 515, 520, 521, 546, 547, 554, 563, 587, 593, 631,
        636, 691, 860, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194,
        1214, 1241, 1311, 1337, 1433, 1434, 1512, 1589, 1701, 1723, 1725, 1741, 1755, 1812, 1813,
        1863, 1900, 1985, 2000, 2049, 2082, 2083, 2100, 2222, 2483, 2484, 2745, 3000, 3128, 3268,
        3306, 3389,
    ]
}

/// Well-known service names for common ports.
fn service_map() -> HashMap<u16, &'static str> {
    let mut m = HashMap::new();
    let entries: &[(u16, &str)] = &[
        (20, "ftp-data"),
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (67, "dhcp"),
        (68, "dhcp"),
        (69, "tftp"),
        (80, "http"),
        (88, "kerberos"),
        (110, "pop3"),
        (111, "rpcbind"),
        (119, "nntp"),
        (123, "ntp"),
        (135, "msrpc"),
        (137, "netbios-ns"),
        (138, "netbios-dgm"),
        (139, "netbios-ssn"),
        (143, "imap"),
        (161, "snmp"),
        (162, "snmptrap"),
        (179, "bgp"),
        (194, "irc"),
        (389, "ldap"),
        (443, "https"),
        (445, "smb"),
        (465, "smtps"),
        (514, "syslog"),
        (515, "printer"),
        (554, "rtsp"),
        (587, "submission"),
        (631, "ipp"),
        (636, "ldaps"),
        (873, "rsync"),
        (993, "imaps"),
        (995, "pop3s"),
        (1080, "socks"),
        (1194, "openvpn"),
        (1433, "mssql"),
        (1434, "mssql-udp"),
        (1723, "pptp"),
        (1883, "mqtt"),
        (2049, "nfs"),
        (2082, "cpanel"),
        (2083, "cpanel-ssl"),
        (2222, "ssh-alt"),
        (3000, "dev"),
        (3128, "squid"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (5900, "vnc"),
        (5901, "vnc"),
        (6379, "redis"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (8888, "http-alt"),
        (9090, "prometheus"),
        (9200, "elasticsearch"),
        (27017, "mongodb"),
    ];
    for &(port, name) in entries {
        m.insert(port, name);
    }
    m
}

/// Scan a single port.
async fn scan_port(addr: SocketAddr, to: Duration) -> (bool, Option<f64>) {
    let start = Instant::now();
    match timeout(to, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => (true, Some(start.elapsed().as_secs_f64() * 1000.0)),
        _ => (false, None),
    }
}

/// Run a port scan.
pub async fn scan(config: &PortConfig) -> Result<ScanResult, String> {
    let base_addr: SocketAddr = format!("{}:0", config.target)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {e}", config.target))?
        .next()
        .ok_or_else(|| format!("No address for {}", config.target))?;

    let services = service_map();
    let sem = std::sync::Arc::new(Semaphore::new(config.parallel));
    let start = Instant::now();

    let mut handles = Vec::new();
    for &port in &config.ports {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let addr = SocketAddr::new(base_addr.ip(), port);
        let to = config.timeout;
        handles.push(tokio::spawn(async move {
            let result = scan_port(addr, to).await;
            drop(permit);
            (port, result)
        }));
    }

    let mut ports = Vec::new();
    for handle in handles {
        let (port, (open, rtt_ms)) = handle.await.map_err(|e| format!("Task failed: {e}"))?;
        if open {
            ports.push(PortResult {
                port,
                open,
                service: services.get(&port).map(|s| s.to_string()),
                rtt_ms,
            });
        }
    }

    ports.sort_by_key(|p| p.port);
    let open_count = ports.len();
    let closed_count = config.ports.len() - open_count;
    let scan_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(ScanResult {
        target: config.target.clone(),
        resolved_addr: base_addr.ip().to_string(),
        ports,
        open_count,
        closed_count,
        scan_time_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_csv() {
        let ports = parse_ports("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("8000-8003").unwrap();
        assert_eq!(ports, vec![8000, 8001, 8002, 8003]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80,8000-8002").unwrap();
        assert_eq!(ports, vec![22, 80, 8000, 8001, 8002]);
    }

    #[test]
    fn test_parse_ports_invalid() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn test_top_ports_nonempty() {
        let ports = top_ports();
        assert!(ports.len() >= 50);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_service_map_common() {
        let m = service_map();
        assert_eq!(m.get(&80), Some(&"http"));
        assert_eq!(m.get(&443), Some(&"https"));
        assert_eq!(m.get(&22), Some(&"ssh"));
    }
}
