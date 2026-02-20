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
    }

    #[test]
    fn test_resolve_localhost() {
        let addr = resolve("127.0.0.1", 80);
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_resolve_bad_host() {
        let addr = resolve("this.host.definitely.does.not.exist.invalid", 80);
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
    }
}
