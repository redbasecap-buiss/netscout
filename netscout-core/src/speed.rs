use serde::Serialize;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Configuration for a speed test.
#[derive(Debug, Clone)]
pub struct SpeedConfig {
    pub download_url: String,
    pub upload_url: Option<String>,
    pub download_only: bool,
    pub upload_only: bool,
    pub timeout: Duration,
}

impl Default for SpeedConfig {
    fn default() -> Self {
        Self {
            download_url: "http://speed.cloudflare.com/__down?bytes=10000000".to_string(),
            upload_url: None,
            download_only: false,
            upload_only: false,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Result of a speed test.
#[derive(Debug, Clone, Serialize)]
pub struct SpeedResult {
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub download_bytes: Option<u64>,
    pub upload_bytes: Option<u64>,
    pub download_time_ms: Option<f64>,
    pub upload_time_ms: Option<f64>,
}

/// Parse URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("Speed test requires http:// URL")?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "Bad port")?),
        None => (host_port.to_string(), 80),
    };
    if host.is_empty() {
        return Err("Empty host".to_string());
    }
    Ok((host, port, path.to_string()))
}

/// Perform a download speed test via HTTP.
fn download_test(url: &str, timeout_dur: Duration) -> Result<(f64, u64, f64), String> {
    let (host, port, path) = parse_http_url(url)?;
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| format!("DNS: {e}"))?
        .next()
        .ok_or("No address")?;

    let mut stream =
        TcpStream::connect_timeout(&addr, timeout_dur).map_err(|e| format!("Connect: {e}"))?;
    stream.set_read_timeout(Some(timeout_dur)).ok();

    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    std::io::Write::write_all(&mut stream, req.as_bytes()).map_err(|e| format!("Write: {e}"))?;

    // Skip headers
    let start = Instant::now();
    let mut total_bytes: u64 = 0;
    let mut buf = [0u8; 65536];
    let mut headers_done = false;
    let mut header_buf = Vec::new();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !headers_done {
                    header_buf.extend_from_slice(&buf[..n]);
                    if let Some(pos) = find_header_end(&header_buf) {
                        headers_done = true;
                        let body_start = pos + 4;
                        total_bytes += (header_buf.len() - body_start) as u64;
                    }
                } else {
                    total_bytes += n as u64;
                }
            }
            Err(_) => break,
        }
    }

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mbps = if elapsed_ms > 0.0 {
        (total_bytes as f64 * 8.0) / (elapsed_ms / 1000.0) / 1_000_000.0
    } else {
        0.0
    };

    Ok((mbps, total_bytes, elapsed_ms))
}

/// Find the end of HTTP headers (\r\n\r\n).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Run a speed test.
pub fn test_speed(config: &SpeedConfig) -> Result<SpeedResult, String> {
    let mut result = SpeedResult {
        download_mbps: None,
        upload_mbps: None,
        download_bytes: None,
        upload_bytes: None,
        download_time_ms: None,
        upload_time_ms: None,
    };

    if !config.upload_only {
        let (mbps, bytes, time_ms) = download_test(&config.download_url, config.timeout)?;
        result.download_mbps = Some(mbps);
        result.download_bytes = Some(bytes);
        result.download_time_ms = Some(time_ms);
    }

    // Upload test would work similarly with POST, skipped for v0.1.0 with HTTP-only
    // Full implementation would use configurable upload endpoint

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_config_default() {
        let cfg = SpeedConfig::default();
        assert!(cfg.download_url.contains("cloudflare"));
        assert!(!cfg.download_only);
        assert!(!cfg.upload_only);
        assert!(cfg.upload_url.is_none());
        assert_eq!(cfg.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_speed_config_custom() {
        let cfg = SpeedConfig {
            download_url: "http://test.example.com/10MB".to_string(),
            upload_url: Some("http://test.example.com/upload".to_string()),
            download_only: true,
            upload_only: false,
            timeout: Duration::from_secs(60),
        };
        assert_eq!(cfg.download_url, "http://test.example.com/10MB");
        assert!(cfg.upload_url.is_some());
        assert!(cfg.download_only);
        assert!(!cfg.upload_only);
    }

    #[test]
    fn test_speed_config_upload_only() {
        let cfg = SpeedConfig {
            upload_only: true,
            download_only: false,
            ..Default::default()
        };
        assert!(cfg.upload_only);
        assert!(!cfg.download_only);
    }

    #[test]
    fn test_parse_http_url() {
        let (host, port, path) = parse_http_url("http://example.com/file").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/file");
    }

    #[test]
    fn test_parse_http_url_with_port() {
        let (host, port, path) = parse_http_url("http://localhost:8080/test").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/test");
    }

    #[test]
    fn test_parse_http_url_no_path() {
        let (host, port, path) = parse_http_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_http_url_root_path() {
        let (host, port, path) = parse_http_url("http://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_http_url_complex_path() {
        let (host, port, path) =
            parse_http_url("http://speed.example.com:9000/download?size=100MB&format=binary")
                .unwrap();
        assert_eq!(host, "speed.example.com");
        assert_eq!(port, 9000);
        assert_eq!(path, "/download?size=100MB&format=binary");
    }

    #[test]
    fn test_parse_http_url_ipv4() {
        let (host, port, path) = parse_http_url("http://192.168.1.1:8080/speedtest").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
        assert_eq!(path, "/speedtest");
    }

    #[test]
    fn test_parse_http_url_https_fails() {
        assert!(parse_http_url("https://example.com").is_err());
    }

    #[test]
    fn test_parse_http_url_invalid() {
        assert!(parse_http_url("ftp://example.com").is_err());
        assert!(parse_http_url("example.com").is_err());
        assert!(parse_http_url("http://").is_err());
        assert!(parse_http_url("").is_err());
    }

    #[test]
    fn test_parse_http_url_invalid_port() {
        assert!(parse_http_url("http://example.com:abc/test").is_err());
        assert!(parse_http_url("http://example.com:99999/test").is_err());
        assert!(parse_http_url("http://example.com:-1/test").is_err());
    }

    #[test]
    fn test_find_header_end() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        let pos = find_header_end(buf);
        assert!(pos.is_some());
        assert_eq!(pos.unwrap(), 41); // Position of first \r\n\r\n
    }

    #[test]
    fn test_find_header_end_at_start() {
        let buf = b"\r\n\r\nbody content";
        let pos = find_header_end(buf);
        assert!(pos.is_some());
        assert_eq!(pos.unwrap(), 0);
    }

    #[test]
    fn test_find_header_end_at_end() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let pos = find_header_end(buf);
        assert!(pos.is_some());
        assert_eq!(pos.unwrap(), 34);
    }

    #[test]
    fn test_find_header_end_none() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain";
        assert!(find_header_end(buf).is_none());
    }

    #[test]
    fn test_find_header_end_partial_match() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r";
        assert!(find_header_end(buf).is_none());
    }

    #[test]
    fn test_find_header_end_empty() {
        let buf = b"";
        assert!(find_header_end(buf).is_none());
    }

    #[test]
    fn test_find_header_end_short() {
        let buf = b"\r\n";
        assert!(find_header_end(buf).is_none());
    }

    #[test]
    fn test_speed_result_serialization() {
        let result = SpeedResult {
            download_mbps: Some(100.5),
            upload_mbps: Some(50.25),
            download_bytes: Some(10_000_000),
            upload_bytes: Some(5_000_000),
            download_time_ms: Some(800.0),
            upload_time_ms: Some(800.0),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("100.5"));
        assert!(json.contains("50.25"));
        assert!(json.contains("10000000"));
    }

    #[test]
    fn test_speed_result_download_only() {
        let result = SpeedResult {
            download_mbps: Some(75.0),
            upload_mbps: None,
            download_bytes: Some(1_000_000),
            upload_bytes: None,
            download_time_ms: Some(107.0),
            upload_time_ms: None,
        };
        assert!(result.download_mbps.is_some());
        assert!(result.upload_mbps.is_none());
        assert!(result.upload_bytes.is_none());
    }

    #[test]
    fn test_speed_result_upload_only() {
        let result = SpeedResult {
            download_mbps: None,
            upload_mbps: Some(25.0),
            download_bytes: None,
            upload_bytes: Some(500_000),
            download_time_ms: None,
            upload_time_ms: Some(160.0),
        };
        assert!(result.download_mbps.is_none());
        assert!(result.upload_mbps.is_some());
        assert!(result.download_bytes.is_none());
    }

    #[test]
    fn test_speed_result_no_data() {
        let result = SpeedResult {
            download_mbps: None,
            upload_mbps: None,
            download_bytes: None,
            upload_bytes: None,
            download_time_ms: None,
            upload_time_ms: None,
        };
        assert!(result.download_mbps.is_none());
        assert!(result.upload_mbps.is_none());
    }
}
