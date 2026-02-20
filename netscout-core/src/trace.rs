use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Configuration for traceroute.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub target: String,
    pub max_hops: u8,
    pub timeout: Duration,
    pub port: u16,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            max_hops: 30,
            timeout: Duration::from_secs(2),
            port: 80,
        }
    }
}

/// A single hop in the traceroute.
#[derive(Debug, Clone, Serialize)]
pub struct TraceHop {
    pub hop: u8,
    pub addr: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
    pub timed_out: bool,
}

/// Traceroute result.
#[derive(Debug, Clone, Serialize)]
pub struct TraceResult {
    pub target: String,
    pub resolved_addr: String,
    pub hops: Vec<TraceHop>,
    pub reached: bool,
}

/// Perform traceroute using TCP connections.
///
/// Note: True TTL-based traceroute requires raw sockets (root privileges).
/// This implementation uses TCP connect probes — it shows the destination
/// reachability but cannot enumerate intermediate hops without raw sockets.
/// Each "hop" attempts a TCP connect to simulate traceroute output.
pub async fn trace(config: &TraceConfig) -> Result<TraceResult, String> {
    let addr: SocketAddr = format!("{}:{}", config.target, config.port)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {e}", config.target))?
        .next()
        .ok_or_else(|| format!("No address for {}", config.target))?;

    let resolved = addr.ip().to_string();
    let mut hops = Vec::new();

    // Attempt TCP connects with increasing simulated hop numbers.
    // Without raw sockets we cannot set TTL, so we do a single probe
    // to the target and report it as a single-hop trace.
    // For a full experience, the user would need to run with elevated privileges.

    for hop_num in 1..=config.max_hops {
        let start = Instant::now();
        match timeout(config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                // Reverse DNS lookup
                let hostname = tokio::task::spawn_blocking({
                    let ip = addr.ip();
                    move || {
                        use std::net::SocketAddr;
                        let sock = SocketAddr::new(ip, 0);
                        dns_lookup_reverse(sock)
                    }
                })
                .await
                .ok()
                .flatten();

                hops.push(TraceHop {
                    hop: hop_num,
                    addr: Some(resolved.clone()),
                    hostname,
                    rtt_ms: Some(rtt),
                    timed_out: false,
                });
                // Reached destination
                return Ok(TraceResult {
                    target: config.target.clone(),
                    resolved_addr: resolved,
                    hops,
                    reached: true,
                });
            }
            Ok(Err(_)) => {
                // Connection refused = host is there but port closed
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                hops.push(TraceHop {
                    hop: hop_num,
                    addr: Some(resolved.clone()),
                    hostname: None,
                    rtt_ms: Some(rtt),
                    timed_out: false,
                });
                return Ok(TraceResult {
                    target: config.target.clone(),
                    resolved_addr: resolved,
                    hops,
                    reached: true,
                });
            }
            Err(_) => {
                hops.push(TraceHop {
                    hop: hop_num,
                    addr: None,
                    hostname: None,
                    rtt_ms: None,
                    timed_out: true,
                });
            }
        }
    }

    Ok(TraceResult {
        target: config.target.clone(),
        resolved_addr: resolved,
        hops,
        reached: false,
    })
}

/// Simple reverse DNS lookup.
fn dns_lookup_reverse(addr: SocketAddr) -> Option<String> {
    // There's no stdlib reverse DNS, so we just return None for now.
    // A full implementation would query PTR records.
    let _ = addr;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_config_default() {
        let cfg = TraceConfig::default();
        assert_eq!(cfg.max_hops, 30);
        assert_eq!(cfg.port, 80);
    }

    #[test]
    fn test_trace_hop_serialization() {
        let hop = TraceHop {
            hop: 1,
            addr: Some("1.2.3.4".into()),
            hostname: Some("router.example.com".into()),
            rtt_ms: Some(5.2),
            timed_out: false,
        };
        let json = serde_json::to_string(&hop).unwrap();
        assert!(json.contains("router.example.com"));
        assert!(json.contains("5.2"));
    }

    #[test]
    fn test_trace_result_serialization() {
        let result = TraceResult {
            target: "example.com".into(),
            resolved_addr: "93.184.216.34".into(),
            hops: vec![],
            reached: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("example.com"));
    }

    #[tokio::test]
    async fn test_trace_invalid_host() {
        let config = TraceConfig {
            target: "this.host.does.not.exist.invalid".into(),
            ..Default::default()
        };
        let result = trace(&config).await;
        assert!(result.is_err());
    }
}
