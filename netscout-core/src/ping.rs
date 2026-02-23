use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Configuration for a ping operation.
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub target: String,
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
    pub port: u16,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            count: 4,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            port: 80,
        }
    }
}

/// Result of a single ping probe.
#[derive(Debug, Clone, Serialize)]
pub struct PingProbe {
    pub seq: u32,
    pub success: bool,
    pub rtt_ms: Option<f64>,
    pub addr: String,
}

/// Aggregated ping statistics.
#[derive(Debug, Clone, Serialize)]
pub struct PingStats {
    pub target: String,
    pub resolved_addr: String,
    pub probes: Vec<PingProbe>,
    pub sent: u32,
    pub received: u32,
    pub lost: u32,
    pub loss_percent: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
}

/// Resolve hostname to a socket address.
fn resolve(target: &str, port: u16) -> Result<SocketAddr, String> {
    let host = format!("{target}:{port}");
    host.to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("No addresses found for {target}"))
}

/// Perform a single TCP connect ping.
async fn tcp_ping(addr: SocketAddr, to: Duration) -> (bool, Option<f64>) {
    let start = Instant::now();
    match timeout(to, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            let rtt = start.elapsed().as_secs_f64() * 1000.0;
            (true, Some(rtt))
        }
        _ => (false, None),
    }
}

/// Run a full ping session.
pub async fn ping(config: &PingConfig) -> Result<PingStats, String> {
    // Try port 80, then 443 as fallback
    let addr = resolve(&config.target, config.port).or_else(|_| resolve(&config.target, 443))?;

    let mut probes = Vec::with_capacity(config.count as usize);

    for seq in 0..config.count {
        if seq > 0 {
            tokio::time::sleep(config.interval).await;
        }
        let (success, rtt_ms) = tcp_ping(addr, config.timeout).await;
        probes.push(PingProbe {
            seq,
            success,
            rtt_ms,
            addr: addr.ip().to_string(),
        });
    }

    let rtts: Vec<f64> = probes.iter().filter_map(|p| p.rtt_ms).collect();
    let received = rtts.len() as u32;
    let lost = config.count - received;
    let loss_percent = if config.count > 0 {
        (lost as f64 / config.count as f64) * 100.0
    } else {
        0.0
    };

    let (min_ms, avg_ms, max_ms, stddev_ms, jitter_ms) = if rtts.is_empty() {
        (None, None, None, None, None)
    } else {
        let min = rtts.iter().cloned().reduce(f64::min).unwrap();
        let max = rtts.iter().cloned().reduce(f64::max).unwrap();
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();
        let jitter = if rtts.len() > 1 {
            let diffs: Vec<f64> = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
            Some(diffs.iter().sum::<f64>() / diffs.len() as f64)
        } else {
            None
        };
        (Some(min), Some(avg), Some(max), Some(stddev), jitter)
    };

    Ok(PingStats {
        target: config.target.clone(),
        resolved_addr: addr.ip().to_string(),
        probes,
        sent: config.count,
        received,
        lost,
        loss_percent,
        min_ms,
        avg_ms,
        max_ms,
        stddev_ms,
        jitter_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_config_default() {
        let cfg = PingConfig::default();
        assert_eq!(cfg.count, 4);
        assert_eq!(cfg.port, 80);
        assert_eq!(cfg.timeout, Duration::from_secs(2));
        assert_eq!(cfg.interval, Duration::from_secs(1));
        assert_eq!(cfg.target, "");
    }

    #[test]
    fn test_ping_config_custom() {
        let cfg = PingConfig {
            target: "example.com".to_string(),
            count: 10,
            interval: Duration::from_millis(500),
            timeout: Duration::from_secs(5),
            port: 443,
        };
        assert_eq!(cfg.target, "example.com");
        assert_eq!(cfg.count, 10);
        assert_eq!(cfg.port, 443);
    }

    #[test]
    fn test_resolve_localhost() {
        let addr = resolve("127.0.0.1", 80);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_resolve_ipv6_localhost() {
        let addr = resolve("::1", 80);
        if addr.is_ok() {
            assert_eq!(addr.unwrap().ip().to_string(), "::1");
        }
        // IPv6 might not be available on all systems, so don't assert success
    }

    #[test]
    fn test_resolve_with_port() {
        let addr = resolve("127.0.0.1", 8080);
        assert!(addr.is_ok());
        let socket_addr = addr.unwrap();
        assert_eq!(socket_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(socket_addr.port(), 8080);
    }

    #[test]
    fn test_resolve_bad_host() {
        let addr = resolve("this.host.definitely.does.not.exist.invalid", 80);
        assert!(addr.is_err());
        assert!(addr.unwrap_err().contains("DNS resolution failed"));
    }

    #[test]
    fn test_resolve_empty_host() {
        let addr = resolve("", 80);
        assert!(addr.is_err());
    }

    #[tokio::test]
    async fn test_tcp_ping_unreachable() {
        // Connect to a likely-closed port on localhost
        let addr: SocketAddr = "127.0.0.1:19291".parse().unwrap();
        let (success, _) = tcp_ping(addr, Duration::from_millis(100)).await;
        // On most systems this will be refused quickly (success=false) or possibly connect
        // Either way, the function should not panic
        let _ = success;
    }

    #[tokio::test]
    async fn test_tcp_ping_timeout() {
        // Use a non-routable IP that should timeout
        let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let start = std::time::Instant::now();
        let (success, rtt) = tcp_ping(addr, Duration::from_millis(50)).await;
        let elapsed = start.elapsed();
        
        assert!(!success);
        assert!(rtt.is_none());
        // Should timeout quickly
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    fn test_stats_calculation() {
        let probes = [
            PingProbe {
                seq: 0,
                success: true,
                rtt_ms: Some(10.0),
                addr: "1.2.3.4".into(),
            },
            PingProbe {
                seq: 1,
                success: true,
                rtt_ms: Some(20.0),
                addr: "1.2.3.4".into(),
            },
            PingProbe {
                seq: 2,
                success: false,
                rtt_ms: None,
                addr: "1.2.3.4".into(),
            },
            PingProbe {
                seq: 3,
                success: true,
                rtt_ms: Some(30.0),
                addr: "1.2.3.4".into(),
            },
        ];
        let rtts: Vec<f64> = probes.iter().filter_map(|p| p.rtt_ms).collect();
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        assert!((avg - 20.0).abs() < f64::EPSILON);
        
        let min = rtts.iter().cloned().reduce(f64::min).unwrap();
        let max = rtts.iter().cloned().reduce(f64::max).unwrap();
        assert_eq!(min, 10.0);
        assert_eq!(max, 30.0);
    }

    #[test]
    fn test_ping_probe_serialization() {
        let probe = PingProbe {
            seq: 1,
            success: true,
            rtt_ms: Some(15.5),
            addr: "8.8.8.8".to_string(),
        };
        let json = serde_json::to_string(&probe).unwrap();
        assert!(json.contains("8.8.8.8"));
        assert!(json.contains("15.5"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_ping_probe_failed() {
        let probe = PingProbe {
            seq: 2,
            success: false,
            rtt_ms: None,
            addr: "192.0.2.1".to_string(),
        };
        assert!(!probe.success);
        assert!(probe.rtt_ms.is_none());
    }

    #[test]
    fn test_ping_stats_serialization() {
        let stats = PingStats {
            target: "example.com".to_string(),
            resolved_addr: "93.184.216.34".to_string(),
            probes: vec![],
            sent: 4,
            received: 3,
            lost: 1,
            loss_percent: 25.0,
            min_ms: Some(10.0),
            avg_ms: Some(20.0),
            max_ms: Some(30.0),
            stddev_ms: Some(5.0),
            jitter_ms: Some(2.5),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("25.0"));
        assert!(json.contains("93.184.216.34"));
    }

    #[test]
    fn test_ping_stats_all_failed() {
        let stats = PingStats {
            target: "unreachable.invalid".to_string(),
            resolved_addr: "192.0.2.1".to_string(),
            probes: vec![],
            sent: 3,
            received: 0,
            lost: 3,
            loss_percent: 100.0,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            stddev_ms: None,
            jitter_ms: None,
        };
        assert_eq!(stats.loss_percent, 100.0);
        assert!(stats.min_ms.is_none());
        assert!(stats.avg_ms.is_none());
    }

    #[test]
    fn test_jitter_calculation() {
        // Test jitter calculation with multiple RTT values
        let rtts = vec![10.0_f64, 15.0, 12.0, 18.0];
        let diffs: Vec<f64> = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
        let jitter = diffs.iter().sum::<f64>() / diffs.len() as f64;
        
        // Expected: |15-10| + |12-15| + |18-12| = 5 + 3 + 6 = 14, avg = 14/3 = 4.67
        let expected = 14.0 / 3.0;
        assert!((jitter - expected).abs() < 0.01);
    }

    #[test]
    fn test_variance_calculation() {
        let rtts = vec![10.0, 20.0, 30.0];
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64; // 20.0
        let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();
        
        // Variance = ((10-20)² + (20-20)² + (30-20)²) / 3 = (100 + 0 + 100) / 3 = 66.67
        // Stddev = sqrt(66.67) ≈ 8.16
        assert!((variance - 200.0/3.0).abs() < 0.01);
        assert!((stddev - (200.0/3.0_f64).sqrt()).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_ping_invalid_target() {
        let config = PingConfig {
            target: "invalid.domain.that.should.not.exist.ever".to_string(),
            count: 1,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let result = ping(&config).await;
        assert!(result.is_err());
    }
}
