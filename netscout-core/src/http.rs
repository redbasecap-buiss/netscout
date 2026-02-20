use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Configuration for an HTTP probe.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub timeout: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            follow_redirects: false,
            max_redirects: 10,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Timing breakdown of an HTTP request.
#[derive(Debug, Clone, Serialize)]
pub struct HttpTiming {
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: f64,
    pub transfer_ms: f64,
    pub total_ms: f64,
}

/// A single redirect in the chain.
#[derive(Debug, Clone, Serialize)]
pub struct HttpRedirect {
    pub url: String,
    pub status: u16,
}

/// Result of an HTTP probe.
#[derive(Debug, Clone, Serialize)]
pub struct HttpResult {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body_size: usize,
    pub timing: HttpTiming,
    pub redirects: Vec<HttpRedirect>,
    pub tls: bool,
}

/// Parse a URL into (scheme, host, port, path).
fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("URL must start with http:// or https://".to_string());
    };

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| format!("Invalid port: {p}"))?;
            (h.to_string(), port)
        }
        None => (host_port.to_string(), if tls { 443 } else { 80 }),
    };

    Ok((tls, host, port, path.to_string()))
}

/// Raw HTTP response data.
type HttpRawResponse = (
    u16,
    String,
    HashMap<String, String>,
    usize,
    f64,
    f64,
    f64,
    f64,
);

/// Perform a simple HTTP request (no TLS — for HTTP only).
fn http_request_plain(
    host: &str,
    port: u16,
    path: &str,
    method: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
    timeout_dur: Duration,
) -> Result<HttpRawResponse, String> {
    let t_start = Instant::now();

    // DNS
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| format!("DNS failed: {e}"))?
        .next()
        .ok_or("No address")?;
    let dns_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    // Connect
    let t_conn = Instant::now();
    let mut stream = TcpStream::connect_timeout(&addr, timeout_dur)
        .map_err(|e| format!("Connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(timeout_dur))
        .map_err(|e| format!("Set timeout: {e}"))?;
    let connect_ms = t_conn.elapsed().as_secs_f64() * 1000.0;

    // Send request
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }

    let t_send = Instant::now();
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;

    // Read response
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("Read failed: {e}"))?;
    let ttfb_ms = t_send.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t_start.elapsed().as_secs_f64() * 1000.0;
    let transfer_ms = total_ms - dns_ms - connect_ms - ttfb_ms;

    let response_str = String::from_utf8_lossy(&response);
    let (status, status_text, headers, body_size) = parse_response(&response_str)?;

    Ok((
        status,
        status_text,
        headers,
        body_size,
        dns_ms,
        connect_ms,
        ttfb_ms,
        transfer_ms.max(0.0),
    ))
}

/// Parse an HTTP response string into components.
fn parse_response(resp: &str) -> Result<(u16, String, HashMap<String, String>, usize), String> {
    let (header_section, body) = resp.split_once("\r\n\r\n").unwrap_or((resp, ""));

    let mut lines = header_section.lines();
    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid status line: {status_line}"));
    }
    let status: u16 = parts[1].parse().map_err(|_| "Invalid status code")?;
    let status_text = parts.get(2).unwrap_or(&"").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    Ok((status, status_text, headers, body.len()))
}

/// Probe an HTTP(S) URL.
pub fn probe(config: &HttpConfig) -> Result<HttpResult, String> {
    let (tls, host, port, path) = parse_url(&config.url)?;

    if tls {
        // For HTTPS, we report that TLS is required but use a simplified approach
        // A full TLS implementation would use rustls here
        return Err("HTTPS probing requires the cert module. Use `netscout http` with http:// URLs, or use `netscout cert` for TLS inspection.".to_string());
    }

    let (status, status_text, headers, body_size, dns_ms, connect_ms, ttfb_ms, transfer_ms) =
        http_request_plain(
            &host,
            port,
            &path,
            &config.method,
            &config.headers,
            config.body.as_deref(),
            config.timeout,
        )?;

    let total_ms = dns_ms + connect_ms + ttfb_ms + transfer_ms;

    let mut redirects = Vec::new();
    if config.follow_redirects && (300..400).contains(&status) {
        if let Some(location) = headers.get("location") {
            redirects.push(HttpRedirect {
                url: location.clone(),
                status,
            });
        }
    }

    Ok(HttpResult {
        url: config.url.clone(),
        method: config.method.clone(),
        status,
        status_text,
        headers,
        body_size,
        timing: HttpTiming {
            dns_ms,
            connect_ms,
            tls_ms: None,
            ttfb_ms,
            transfer_ms,
            total_ms,
        },
        redirects,
        tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_http() {
        let (tls, host, port, path) = parse_url("http://example.com/path").unwrap();
        assert!(!tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_url_https() {
        let (tls, host, port, path) = parse_url("https://example.com").unwrap();
        assert!(tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_url_custom_port() {
        let (tls, host, port, path) = parse_url("http://localhost:8080/api").unwrap();
        assert!(!tls);
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn test_parse_url_invalid() {
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("example.com").is_err());
    }

    #[test]
    fn test_parse_response() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>";
        let (status, text, headers, body_size) = parse_response(resp).unwrap();
        assert_eq!(status, 200);
        assert_eq!(text, "OK");
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
        assert_eq!(body_size, 18);
    }
}
