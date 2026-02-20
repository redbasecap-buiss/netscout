use crate::OutputFormat;
use colored::Colorize;
use serde::Serialize;

/// Format a value as JSON, table, or human-readable.
pub fn format_output<T: Serialize + HumanReadable>(value: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("JSON error: {e}"))
        }
        OutputFormat::Table => value.to_table(),
        OutputFormat::Human => value.to_human(),
    }
}

/// Trait for human-readable output formatting.
pub trait HumanReadable {
    fn to_human(&self) -> String;
    fn to_table(&self) -> String {
        self.to_human()
    }
}

/// Format a duration in milliseconds nicely.
pub fn format_ms(ms: f64) -> String {
    if ms < 1.0 {
        format!("{:.2} µs", ms * 1000.0)
    } else if ms < 1000.0 {
        format!("{ms:.2} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

/// Format bytes into human-readable size.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Print a section header.
pub fn section_header(title: &str) -> String {
    format!("\n{}", title.bold().underline())
}

/// Print a key-value pair.
pub fn kv(key: &str, value: &str) -> String {
    format!("  {}: {}", key.dimmed(), value)
}

/// Print a success/fail indicator.
pub fn status_icon(success: bool) -> &'static str {
    if success {
        "✓"
    } else {
        "✗"
    }
}

/// Pad a string to a fixed width.
pub fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - s.len()))
    }
}

// Implement HumanReadable for core types
impl HumanReadable for crate::ping::PingStats {
    fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} ({}) — {} probes\n",
            "PING".green().bold(),
            self.target,
            self.resolved_addr,
            self.sent,
        ));
        for p in &self.probes {
            if p.success {
                out.push_str(&format!(
                    "  {} seq={} time={}\n",
                    "✓".green(),
                    p.seq,
                    format_ms(p.rtt_ms.unwrap_or(0.0)),
                ));
            } else {
                out.push_str(&format!("  {} seq={} timeout\n", "✗".red(), p.seq));
            }
        }
        out.push_str(&format!("\n  --- {} ping statistics ---\n", self.target));
        out.push_str(&format!(
            "  {} sent, {} received, {:.1}% loss\n",
            self.sent, self.received, self.loss_percent,
        ));
        if let (Some(min), Some(avg), Some(max)) = (self.min_ms, self.avg_ms, self.max_ms) {
            out.push_str(&format!(
                "  rtt min/avg/max = {:.2}/{:.2}/{:.2} ms",
                min, avg, max,
            ));
            if let Some(stddev) = self.stddev_ms {
                out.push_str(&format!(", stddev = {:.2} ms", stddev));
            }
            if let Some(jitter) = self.jitter_ms {
                out.push_str(&format!(", jitter = {:.2} ms", jitter));
            }
            out.push('\n');
        }
        out
    }
}

impl HumanReadable for crate::dns::DnsResult {
    fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} @{} — {} — {}\n",
            "DNS".cyan().bold(),
            self.domain,
            self.resolver,
            self.record_type,
            self.response_code,
        ));
        out.push_str(&format!(
            "  Query time: {}\n",
            format_ms(self.query_time_ms)
        ));
        if self.records.is_empty() {
            out.push_str("  No records found.\n");
        }
        for r in &self.records {
            out.push_str(&format!(
                "  {} {} TTL={} {}\n",
                r.record_type.yellow(),
                r.name,
                r.ttl,
                r.value.green(),
            ));
        }
        out
    }
}

impl HumanReadable for crate::port::ScanResult {
    fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} ({}) — {} open, {} closed, {}\n",
            "PORT SCAN".magenta().bold(),
            self.target,
            self.resolved_addr,
            self.open_count,
            self.closed_count,
            format_ms(self.scan_time_ms),
        ));
        for p in &self.ports {
            let svc = p.service.as_deref().unwrap_or("unknown");
            out.push_str(&format!(
                "  {} {}/{} ({})\n",
                "OPEN".green().bold(),
                p.port,
                "tcp",
                svc,
            ));
        }
        out
    }
}

impl HumanReadable for crate::scan::LanScanResult {
    fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} — {} hosts found / {} scanned, {}\n",
            "LAN SCAN".blue().bold(),
            self.subnet,
            self.hosts_found,
            self.total_scanned,
            format_ms(self.scan_time_ms),
        ));
        for h in &self.hosts {
            let name = h.hostname.as_deref().unwrap_or("");
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!(
                "  {} {} ports=[{}] {}\n",
                h.ip.green(),
                name,
                ports.join(","),
                format_ms(h.rtt_ms),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ms() {
        assert!(format_ms(0.5).contains("µs"));
        assert!(format_ms(5.0).contains("ms"));
        assert!(format_ms(1500.0).contains("s"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert!(format_bytes(2048).contains("KB"));
        assert!(format_bytes(5_000_000).contains("MB"));
    }

    #[test]
    fn test_pad_right() {
        assert_eq!(pad_right("hi", 5), "hi   ");
        assert_eq!(pad_right("hello", 3), "hello");
    }

    #[test]
    fn test_status_icon() {
        assert_eq!(status_icon(true), "✓");
        assert_eq!(status_icon(false), "✗");
    }

    #[test]
    fn test_kv_format() {
        let result = kv("Key", "Value");
        assert!(result.contains("Key"));
        assert!(result.contains("Value"));
    }
}
