use crate::OutputFormat;
use colored::Colorize;
use serde::Serialize;

/// Format a value as JSON, table, CSV, or human-readable.
pub fn format_output<T: Serialize + HumanReadable>(value: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("JSON error: {e}"))
        }
        OutputFormat::Table => value.to_table(),
        OutputFormat::Csv => value.to_csv(),
        OutputFormat::Human => value.to_human(),
    }
}

/// Trait for human-readable output formatting.
pub trait HumanReadable {
    fn to_human(&self) -> String;
    fn to_table(&self) -> String {
        self.to_human()
    }
    fn to_csv(&self) -> String {
        // Default: no CSV; subcommands override
        String::from("CSV output not supported for this command\n")
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
    fn to_csv(&self) -> String {
        let mut out = String::from("seq,status,rtt_ms,addr\n");
        for p in &self.probes {
            let status = if p.success { "ok" } else { "timeout" };
            let rtt = p.rtt_ms.map(|r| format!("{r:.2}")).unwrap_or_default();
            out.push_str(&format!("{},{},{},{}\n", p.seq, status, rtt, p.addr));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!(
            "Ping: {} ({}) — {}/{} received ({:.1}% loss)\n\n",
            self.target, self.resolved_addr, self.received, self.sent, self.loss_percent,
        );
        out.push_str(&format!("{:<6} {:<10} {:<15}\n", "SEQ", "STATUS", "RTT"));
        out.push_str(&format!("{}\n", "-".repeat(31)));
        for p in &self.probes {
            let status = if p.success { "ok" } else { "timeout" };
            let rtt = p.rtt_ms.map(format_ms).unwrap_or_else(|| "-".to_string());
            out.push_str(&format!("{:<6} {:<10} {:<15}\n", p.seq, status, rtt));
        }
        if let (Some(min), Some(avg), Some(max)) = (self.min_ms, self.avg_ms, self.max_ms) {
            out.push_str(&format!(
                "\nmin={:.2} ms  avg={:.2} ms  max={:.2} ms",
                min, avg, max,
            ));
            if let Some(jitter) = self.jitter_ms {
                out.push_str(&format!("  jitter={:.2} ms", jitter));
            }
            out.push('\n');
        }
        out
    }

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
    fn to_csv(&self) -> String {
        let mut out = String::from("type,name,ttl,value\n");
        for r in &self.records {
            // Escape values that might contain commas
            let val = if r.value.contains(',') {
                format!("\"{}\"", r.value)
            } else {
                r.value.clone()
            };
            out.push_str(&format!("{},{},{},{}\n", r.record_type, r.name, r.ttl, val));
        }
        out
    }

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

    fn to_table(&self) -> String {
        let mut out = format!(
            "DNS: {} @{} — {} ({})\n\n",
            self.domain, self.resolver, self.record_type, self.response_code,
        );
        out.push_str(&format!(
            "{:<8} {:<30} {:<8} {}\n",
            "TYPE", "NAME", "TTL", "VALUE"
        ));
        out.push_str(&format!("{}\n", "-".repeat(70)));
        for r in &self.records {
            out.push_str(&format!(
                "{:<8} {:<30} {:<8} {}\n",
                r.record_type, r.name, r.ttl, r.value,
            ));
        }
        out
    }
}

impl HumanReadable for crate::port::ScanResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("port,proto,service\n");
        for p in &self.ports {
            let svc = p.service.as_deref().unwrap_or("unknown");
            out.push_str(&format!("{},tcp,{}\n", p.port, svc));
        }
        out
    }

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

    fn to_table(&self) -> String {
        let mut out = format!(
            "Port Scan: {} ({}) — {} open, {} closed\n\n",
            self.target, self.resolved_addr, self.open_count, self.closed_count,
        );
        out.push_str(&format!("{:<8} {:<8} {:<20}\n", "PORT", "PROTO", "SERVICE"));
        out.push_str(&format!("{}\n", "-".repeat(36)));
        for p in &self.ports {
            let svc = p.service.as_deref().unwrap_or("unknown");
            out.push_str(&format!("{:<8} {:<8} {:<20}\n", p.port, "tcp", svc));
        }
        out
    }
}

impl HumanReadable for crate::scan::LanScanResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("ip,hostname,open_ports,rtt_ms\n");
        for h in &self.hosts {
            let name = h.hostname.as_deref().unwrap_or("");
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!(
                "{},{},\"{}\",{:.2}\n",
                h.ip,
                name,
                ports.join(";"),
                h.rtt_ms
            ));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!(
            "LAN Scan: {} — {} found / {} scanned\n\n",
            self.subnet, self.hosts_found, self.total_scanned,
        );
        out.push_str(&format!(
            "{:<16} {:<20} {:<20} {}\n",
            "IP", "HOSTNAME", "OPEN PORTS", "RTT"
        ));
        out.push_str(&format!("{}\n", "-".repeat(65)));
        for h in &self.hosts {
            let name = h.hostname.as_deref().unwrap_or("-");
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!(
                "{:<16} {:<20} {:<20} {}\n",
                h.ip,
                name,
                ports.join(","),
                format_ms(h.rtt_ms),
            ));
        }
        out
    }

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

impl HumanReadable for crate::trace::TraceResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("hop,addr,hostname,rtt_ms,timed_out\n");
        for hop in &self.hops {
            let addr = hop.addr.as_deref().unwrap_or("");
            let name = hop.hostname.as_deref().unwrap_or("");
            let rtt = hop.rtt_ms.map(|r| format!("{r:.2}")).unwrap_or_default();
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                hop.hop, addr, name, rtt, hop.timed_out
            ));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!("Traceroute: {} ({})\n\n", self.target, self.resolved_addr);
        out.push_str(&format!(
            "{:<5} {:<16} {:<30} {}\n",
            "HOP", "ADDRESS", "HOSTNAME", "RTT"
        ));
        out.push_str(&format!("{}\n", "-".repeat(60)));
        for hop in &self.hops {
            if hop.timed_out {
                out.push_str(&format!("{:<5} {:<16} {:<30} {}\n", hop.hop, "*", "*", "*"));
            } else {
                let addr = hop.addr.as_deref().unwrap_or("???");
                let name = hop.hostname.as_deref().unwrap_or("-");
                let rtt = hop
                    .rtt_ms
                    .map(|r| format!("{r:.2} ms"))
                    .unwrap_or_else(|| "-".into());
                out.push_str(&format!(
                    "{:<5} {:<16} {:<30} {}\n",
                    hop.hop, addr, name, rtt
                ));
            }
        }
        if self.reached {
            out.push_str("\nDestination reached.\n");
        } else {
            out.push_str("\nDestination not reached.\n");
        }
        out
    }

    fn to_human(&self) -> String {
        let mut out = format!(
            "{} {} ({})\n",
            "TRACEROUTE".yellow().bold(),
            self.target,
            self.resolved_addr,
        );
        for hop in &self.hops {
            if hop.timed_out {
                out.push_str(&format!("  {:>2}  {}\n", hop.hop, "* * *".dimmed()));
            } else {
                let addr = hop.addr.as_deref().unwrap_or("???");
                let name = hop
                    .hostname
                    .as_deref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default();
                let rtt = hop.rtt_ms.map(|r| format!("{r:.2} ms")).unwrap_or_default();
                out.push_str(&format!("  {:>2}  {addr}{name}  {rtt}\n", hop.hop));
            }
        }
        if self.reached {
            out.push_str(&format!("  {}\n", "Destination reached.".green()));
        } else {
            out.push_str(&format!("  {}\n", "Destination not reached.".red()));
        }
        out
    }
}

impl HumanReadable for crate::http::HttpResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("field,value\n");
        out.push_str(&format!("url,{}\n", self.url));
        out.push_str(&format!("method,{}\n", self.method));
        out.push_str(&format!("status,{}\n", self.status));
        out.push_str(&format!("body_size,{}\n", self.body_size));
        out.push_str(&format!("dns_ms,{:.1}\n", self.timing.dns_ms));
        out.push_str(&format!("connect_ms,{:.1}\n", self.timing.connect_ms));
        out.push_str(&format!("ttfb_ms,{:.1}\n", self.timing.ttfb_ms));
        out.push_str(&format!("total_ms,{:.1}\n", self.timing.total_ms));
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!(
            "HTTP {} {} — {} {}\n\n",
            self.method, self.url, self.status, self.status_text
        );
        out.push_str(&format!("{:<15} {} bytes\n", "Body Size", self.body_size));
        out.push_str(&format!(
            "{:<15} {}\n",
            "DNS",
            format_ms(self.timing.dns_ms)
        ));
        out.push_str(&format!(
            "{:<15} {}\n",
            "Connect",
            format_ms(self.timing.connect_ms)
        ));
        out.push_str(&format!(
            "{:<15} {}\n",
            "TTFB",
            format_ms(self.timing.ttfb_ms)
        ));
        out.push_str(&format!(
            "{:<15} {}\n",
            "Transfer",
            format_ms(self.timing.transfer_ms)
        ));
        out.push_str(&format!(
            "{:<15} {}\n",
            "Total",
            format_ms(self.timing.total_ms)
        ));
        if !self.redirects.is_empty() {
            out.push_str("\nRedirects:\n");
            for r in &self.redirects {
                out.push_str(&format!("  {} → {}\n", r.status, r.url));
            }
        }
        out
    }

    fn to_human(&self) -> String {
        let mut out = format!("{} {} {}\n", "HTTP".blue().bold(), self.method, self.url);
        let status_color = if self.status < 300 {
            format!("{} {}", self.status, self.status_text)
                .green()
                .to_string()
        } else if self.status < 400 {
            format!("{} {}", self.status, self.status_text)
                .yellow()
                .to_string()
        } else {
            format!("{} {}", self.status, self.status_text)
                .red()
                .to_string()
        };
        out.push_str(&format!("  Status: {status_color}\n"));
        out.push_str(&format!("  Body: {} bytes\n", self.body_size));
        out.push_str(&format!(
            "  Timing: DNS={:.1}ms Connect={:.1}ms TTFB={:.1}ms Total={:.1}ms\n",
            self.timing.dns_ms, self.timing.connect_ms, self.timing.ttfb_ms, self.timing.total_ms,
        ));
        if !self.redirects.is_empty() {
            out.push_str("  Redirects:\n");
            for r in &self.redirects {
                out.push_str(&format!("    {} → {}\n", r.status, r.url));
            }
        }
        out
    }
}

impl HumanReadable for crate::cert::CertResult {
    fn to_csv(&self) -> String {
        let mut out =
            String::from("index,subject,issuer,not_before,not_after,days_until_expiry,serial\n");
        for (i, cert) in self.certificate_chain.iter().enumerate() {
            // Quote fields that may contain commas
            out.push_str(&format!(
                "{},\"{}\",\"{}\",{},{},{},{}\n",
                i,
                cert.subject,
                cert.issuer,
                cert.not_before,
                cert.not_after,
                cert.days_until_expiry,
                cert.serial,
            ));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!("TLS Certificate: {}:{}\n", self.host, self.port);
        out.push_str(&format!(
            "TLS: {}  Cipher: {}  Connect: {}\n\n",
            self.tls_version,
            self.cipher_suite,
            format_ms(self.connection_time_ms)
        ));
        out.push_str(&format!(
            "{:<4} {:<35} {:<35} {:<12} {}\n",
            "#", "SUBJECT", "ISSUER", "EXPIRES", "DAYS LEFT"
        ));
        out.push_str(&format!("{}\n", "-".repeat(95)));
        for (i, cert) in self.certificate_chain.iter().enumerate() {
            let subj = if cert.subject.len() > 33 {
                &cert.subject[..33]
            } else {
                &cert.subject
            };
            let iss = if cert.issuer.len() > 33 {
                &cert.issuer[..33]
            } else {
                &cert.issuer
            };
            out.push_str(&format!(
                "{:<4} {:<35} {:<35} {:<12} {}\n",
                i, subj, iss, cert.not_after, cert.days_until_expiry,
            ));
        }
        if let Some(w) = &self.warning {
            out.push_str(&format!("\nWarning: {w}\n"));
        }
        out
    }

    fn to_human(&self) -> String {
        let mut out = format!(
            "{} {}:{}\n",
            "TLS CERT".green().bold(),
            self.host,
            self.port
        );
        out.push_str(&format!("  TLS Version: {}\n", self.tls_version));
        out.push_str(&format!("  Cipher: {}\n", self.cipher_suite));
        out.push_str(&format!("  Connect: {:.1} ms\n", self.connection_time_ms));
        for (i, cert) in self.certificate_chain.iter().enumerate() {
            out.push_str(&format!("  Certificate #{i}:\n"));
            out.push_str(&format!("    Subject: {}\n", cert.subject));
            out.push_str(&format!("    Issuer: {}\n", cert.issuer));
            out.push_str(&format!("    Serial: {}\n", cert.serial));
        }
        if let Some(w) = &self.warning {
            out.push_str(&format!("  {}\n", w.yellow()));
        }
        out
    }
}

impl HumanReadable for crate::speed::SpeedResult {
    fn to_human(&self) -> String {
        let mut out = format!("{}\n", "SPEED TEST".cyan().bold());
        if let Some(dl) = self.download_mbps {
            out.push_str(&format!("  Download: {:.2} Mbps\n", dl));
        }
        if let Some(ul) = self.upload_mbps {
            out.push_str(&format!("  Upload: {:.2} Mbps\n", ul));
        }
        if let Some(bytes) = self.download_bytes {
            out.push_str(&format!("  Downloaded: {}\n", format_bytes(bytes)));
        }
        if let Some(ms) = self.download_time_ms {
            out.push_str(&format!("  Duration: {}\n", format_ms(ms)));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = String::from("Speed Test Results\n\n");
        out.push_str(&format!(
            "{:<15} {:<15} {:<15} {}\n",
            "DIRECTION", "SPEED", "BYTES", "TIME"
        ));
        out.push_str(&format!("{}\n", "-".repeat(55)));
        if let Some(dl) = self.download_mbps {
            let bytes = self
                .download_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".into());
            let time = self
                .download_time_ms
                .map(format_ms)
                .unwrap_or_else(|| "-".into());
            out.push_str(&format!(
                "{:<15} {:<15} {:<15} {}\n",
                "Download",
                format!("{:.2} Mbps", dl),
                bytes,
                time
            ));
        }
        if let Some(ul) = self.upload_mbps {
            let bytes = self
                .upload_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".into());
            let time = self
                .upload_time_ms
                .map(format_ms)
                .unwrap_or_else(|| "-".into());
            out.push_str(&format!(
                "{:<15} {:<15} {:<15} {}\n",
                "Upload",
                format!("{:.2} Mbps", ul),
                bytes,
                time
            ));
        }
        out
    }

    fn to_csv(&self) -> String {
        let mut out = String::from("direction,speed_mbps,bytes,time_ms\n");
        if let Some(dl) = self.download_mbps {
            out.push_str(&format!(
                "download,{:.2},{},{:.1}\n",
                dl,
                self.download_bytes.unwrap_or(0),
                self.download_time_ms.unwrap_or(0.0),
            ));
        }
        if let Some(ul) = self.upload_mbps {
            out.push_str(&format!(
                "upload,{:.2},{},{:.1}\n",
                ul,
                self.upload_bytes.unwrap_or(0),
                self.upload_time_ms.unwrap_or(0.0),
            ));
        }
        out
    }
}

impl HumanReadable for crate::whois::WhoisResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("field,value\n");
        out.push_str(&format!("target,{}\n", self.target));
        out.push_str(&format!("server,{}\n", self.server));
        if let Some(r) = &self.registrar {
            out.push_str(&format!("registrar,{r}\n"));
        }
        if let Some(d) = &self.creation_date {
            out.push_str(&format!("created,{d}\n"));
        }
        if let Some(d) = &self.expiry_date {
            out.push_str(&format!("expires,{d}\n"));
        }
        if let Some(d) = &self.updated_date {
            out.push_str(&format!("updated,{d}\n"));
        }
        for ns in &self.nameservers {
            out.push_str(&format!("nameserver,{ns}\n"));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!("WHOIS: {} @{}\n\n", self.target, self.server);
        out.push_str(&format!("{:<15} {}\n", "FIELD", "VALUE"));
        out.push_str(&format!("{}\n", "-".repeat(50)));
        if let Some(r) = &self.registrar {
            out.push_str(&format!("{:<15} {}\n", "Registrar", r));
        }
        if let Some(d) = &self.creation_date {
            out.push_str(&format!("{:<15} {}\n", "Created", d));
        }
        if let Some(d) = &self.expiry_date {
            out.push_str(&format!("{:<15} {}\n", "Expires", d));
        }
        if let Some(d) = &self.updated_date {
            out.push_str(&format!("{:<15} {}\n", "Updated", d));
        }
        if !self.nameservers.is_empty() {
            out.push_str(&format!(
                "{:<15} {}\n",
                "Nameservers",
                self.nameservers.join(", ")
            ));
        }
        out.push_str(&format!(
            "{:<15} {}\n",
            "Query Time",
            format_ms(self.query_time_ms)
        ));
        out
    }

    fn to_human(&self) -> String {
        let mut out = format!(
            "{} {} @{}\n",
            "WHOIS".yellow().bold(),
            self.target,
            self.server
        );
        if let Some(reg) = &self.registrar {
            out.push_str(&format!("  Registrar: {reg}\n"));
        }
        if let Some(d) = &self.creation_date {
            out.push_str(&format!("  Created: {d}\n"));
        }
        if let Some(d) = &self.expiry_date {
            out.push_str(&format!("  Expires: {d}\n"));
        }
        if !self.nameservers.is_empty() {
            out.push_str("  Nameservers:\n");
            for ns in &self.nameservers {
                out.push_str(&format!("    {ns}\n"));
            }
        }
        out.push_str(&format!("  Query time: {:.1} ms\n", self.query_time_ms));
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
    fn test_format_ms_edge_cases() {
        assert_eq!(format_ms(0.1), "100.00 µs");
        assert_eq!(format_ms(1.0), "1.00 ms");
        assert_eq!(format_ms(999.99), "999.99 ms");
        assert_eq!(format_ms(1000.0), "1.00 s");
        assert_eq!(format_ms(5432.1), "5.43 s");
    }

    #[test]
    fn test_format_ms_zero() {
        assert_eq!(format_ms(0.0), "0.00 µs");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert!(format_bytes(2048).contains("KB"));
        assert!(format_bytes(5_000_000).contains("MB"));
    }

    #[test]
    fn test_format_bytes_edge_cases() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_bytes_large() {
        assert_eq!(format_bytes(2_147_483_648), "2.00 GB"); // 2 GB
        assert_eq!(format_bytes(5_368_709_120), "5.00 GB"); // 5 GB
        assert!(format_bytes(u64::MAX).contains("GB"));
    }

    #[test]
    fn test_pad_right() {
        assert_eq!(pad_right("hi", 5), "hi   ");
        assert_eq!(pad_right("hello", 3), "hello");
    }

    #[test]
    fn test_pad_right_edge_cases() {
        assert_eq!(pad_right("", 3), "   ");
        assert_eq!(pad_right("test", 4), "test");
        assert_eq!(pad_right("longer", 2), "longer"); // No truncation
        assert_eq!(pad_right("exact", 5), "exact");
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
        assert!(result.contains(":"));
    }

    #[test]
    fn test_kv_format_empty() {
        let result = kv("", "");
        assert!(result.contains(":"));
    }

    #[test]
    fn test_kv_format_special_chars() {
        let result = kv("Special: Key", "Value with spaces");
        assert!(result.contains("Special: Key"));
        assert!(result.contains("Value with spaces"));
    }

    #[test]
    fn test_section_header() {
        let header = section_header("Test Section");
        assert!(header.contains("Test Section"));
        assert!(header.starts_with('\n')); // Should start with newline
    }

    #[test]
    fn test_section_header_empty() {
        let header = section_header("");
        assert!(header.starts_with('\n'));
    }

    #[test]
    fn test_format_output_json() {
        use crate::dns::{DnsRecord, DnsResult};

        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            value: "93.184.216.34".to_string(),
        };

        let result = DnsResult {
            domain: "example.com".to_string(),
            resolver: "8.8.8.8".to_string(),
            record_type: "A".to_string(),
            records: vec![record],
            query_time_ms: 25.0,
            response_code: "NOERROR".to_string(),
            truncated: false,
            recursion_available: true,
            authenticated_data: false,
        };

        let output = format_output(&result, OutputFormat::Json);
        assert!(output.contains("example.com"));
        assert!(output.contains("93.184.216.34"));
        assert!(output.contains("NOERROR"));
    }

    #[test]
    fn test_format_output_human() {
        use crate::ping::{PingProbe, PingStats};

        let stats = PingStats {
            target: "example.com".to_string(),
            resolved_addr: "93.184.216.34".to_string(),
            probes: vec![PingProbe {
                seq: 0,
                success: true,
                rtt_ms: Some(25.0),
                addr: "93.184.216.34".to_string(),
            }],
            sent: 1,
            received: 1,
            lost: 0,
            loss_percent: 0.0,
            min_ms: Some(25.0),
            avg_ms: Some(25.0),
            max_ms: Some(25.0),
            stddev_ms: Some(0.0),
            jitter_ms: None,
        };

        let output = format_output(&stats, OutputFormat::Human);
        assert!(output.contains("PING"));
        assert!(output.contains("example.com"));
        assert!(output.contains("✓"));
    }

    #[test]
    fn test_format_output_table() {
        use crate::port::{PortResult, ScanResult};

        let result = ScanResult {
            target: "example.com".to_string(),
            resolved_addr: "93.184.216.34".to_string(),
            ports: vec![PortResult {
                port: 80,
                open: true,
                service: Some("http".to_string()),
                rtt_ms: Some(10.0),
            }],
            open_count: 1,
            closed_count: 0,
            scan_time_ms: 100.0,
        };

        let output = format_output(&result, OutputFormat::Table);
        assert!(output.contains("PORT"));
        assert!(output.contains("PROTO"));
        assert!(output.contains("SERVICE"));
        assert!(output.contains("80"));
        assert!(output.contains("http"));
    }

    #[test]
    fn test_format_output_csv() {
        use crate::dns::{DnsRecord, DnsResult};

        let result = DnsResult {
            domain: "example.com".to_string(),
            resolver: "8.8.8.8".to_string(),
            record_type: "A".to_string(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: "A".to_string(),
                ttl: 300,
                value: "93.184.216.34".to_string(),
            }],
            query_time_ms: 25.0,
            response_code: "NOERROR".to_string(),
            truncated: false,
            recursion_available: true,
            authenticated_data: false,
        };

        let output = format_output(&result, OutputFormat::Csv);
        assert!(output.contains("type,name,ttl,value"));
        assert!(output.contains("A,example.com,300,93.184.216.34"));
    }
}
