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
        assert_eq!(cfg.timeout, Duration::from_secs(2));
        assert_eq!(cfg.target, "");
    }

    #[test]
    fn test_trace_config_custom() {
        let cfg = TraceConfig {
            target: "example.com".to_string(),
            max_hops: 15,
            timeout: Duration::from_secs(5),
            port: 443,
        };
        assert_eq!(cfg.target, "example.com");
        assert_eq!(cfg.max_hops, 15);
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.timeout, Duration::from_secs(5));
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
        assert!(json.contains("1.2.3.4"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_trace_hop_timeout() {
        let hop = TraceHop {
            hop: 5,
            addr: None,
            hostname: None,
            rtt_ms: None,
            timed_out: true,
        };
        let json = serde_json::to_string(&hop).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("\"addr\":null"));
        assert!(json.contains("\"hostname\":null"));
        assert!(json.contains("\"rtt_ms\":null"));
    }

    #[test]
    fn test_trace_hop_no_hostname() {
        let hop = TraceHop {
            hop: 2,
            addr: Some("10.0.0.1".into()),
            hostname: None,
            rtt_ms: Some(15.7),
            timed_out: false,
        };
        assert_eq!(hop.addr.as_ref().unwrap(), "10.0.0.1");
        assert!(hop.hostname.is_none());
        assert!(!hop.timed_out);
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
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_trace_result_with_hops() {
        let hop1 = TraceHop {
            hop: 1,
            addr: Some("192.168.1.1".into()),
            hostname: Some("gateway".into()),
            rtt_ms: Some(1.0),
            timed_out: false,
        };
        let hop2 = TraceHop {
            hop: 2,
            addr: None,
            hostname: None,
            rtt_ms: None,
            timed_out: true,
        };
        let result = TraceResult {
            target: "example.com".into(),
            resolved_addr: "93.184.216.34".into(),
            hops: vec![hop1, hop2],
            reached: true,
        };
        assert_eq!(result.hops.len(), 2);
        assert!(result.reached);
        assert_eq!(result.hops[0].hop, 1);
        assert_eq!(result.hops[1].hop, 2);
    }

    #[test]
    fn test_dns_lookup_reverse_returns_none() {
        use std::net::{IpAddr, Ipv4Addr};
        let addr = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let result = dns_lookup_reverse(addr);
        // Current implementation always returns None
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_trace_invalid_host() {
        let config = TraceConfig {
            target: "this.host.does.not.exist.invalid".into(),
            ..Default::default()
        };
        let result = trace(&config).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("Failed to resolve"));
    }

    #[tokio::test]
    async fn test_trace_localhost() {
        let config = TraceConfig {
            target: "127.0.0.1".into(),
            port: 80,
            timeout: Duration::from_millis(100),
            max_hops: 1,
        };
        let result = trace(&config).await;
        // This might succeed or fail depending on whether port 80 is open on localhost
        // The test verifies the function doesn't panic and returns a proper result
        if let Ok(trace_result) = result {
            assert_eq!(trace_result.target, "127.0.0.1");
            assert_eq!(trace_result.resolved_addr, "127.0.0.1");
        }
    }

    #[tokio::test]
    async fn test_trace_unreachable_host() {
        let config = TraceConfig {
            target: "192.0.2.1".into(), // Non-routable IP
            port: 80,
            timeout: Duration::from_millis(50),
            max_hops: 2,
        };
        let result = trace(&config).await;
        if let Ok(trace_result) = result {
            assert_eq!(trace_result.target, "192.0.2.1");
            assert_eq!(trace_result.resolved_addr, "192.0.2.1");
            // Should timeout and not reach destination
            assert!(!trace_result.reached);
        }
    }

    #[test]
    fn test_trace_config_validation() {
        let cfg = TraceConfig {
            target: "".into(),
            max_hops: 0,
            timeout: Duration::from_secs(0),
            port: 0,
        };
        // These are edge cases that should be handled gracefully
        assert_eq!(cfg.max_hops, 0);
        assert_eq!(cfg.port, 0);
        assert!(cfg.target.is_empty());
    }

    #[test]
    fn test_trace_hop_display_properties() {
        let hop = TraceHop {
            hop: 10,
            addr: Some("203.0.113.1".into()),
            hostname: Some("backbone.provider.com".into()),
            rtt_ms: Some(45.123),
            timed_out: false,
        };
        
        // Test various properties
        assert_eq!(hop.hop, 10);
        assert_eq!(hop.addr.as_ref().unwrap(), "203.0.113.1");
        assert_eq!(hop.hostname.as_ref().unwrap(), "backbone.provider.com");
        assert!(hop.rtt_ms.unwrap() > 45.0);
        assert!(hop.rtt_ms.unwrap() < 46.0);
    }

    #[test]
    fn test_trace_result_reached_destination() {
        let result = TraceResult {
            target: "example.com".into(),
            resolved_addr: "93.184.216.34".into(),
            hops: vec![
                TraceHop {
                    hop: 1,
                    addr: Some("93.184.216.34".into()),
                    hostname: Some("example.com".into()),
                    rtt_ms: Some(25.0),
                    timed_out: false,
                }
            ],
            reached: true,
        };
        
        assert!(result.reached);
        assert_eq!(result.hops.len(), 1);
        assert_eq!(result.target, "example.com");
    }
}
