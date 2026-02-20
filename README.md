# 🔍 netscout

**The Swiss Army knife for network diagnostics.** One binary, every tool you need. Fast, beautiful, scriptable.

[![CI](https://github.com/redbasecap-buiss/netscout/actions/workflows/ci.yml/badge.svg)](https://github.com/redbasecap-buiss/netscout/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

| Tool | Command | Description |
|------|---------|-------------|
| 🏓 Ping | `netscout ping` | TCP connect ping with min/avg/max/stddev/jitter stats |
| 🌐 DNS | `netscout dns` | DNS resolver — A, AAAA, MX, TXT, CNAME, NS, SOA, PTR |
| 🔌 Port Scan | `netscout port` | TCP port scanner with service detection, concurrent |
| 🗺️ Traceroute | `netscout trace` | TCP traceroute with reverse DNS |
| 📡 HTTP Probe | `netscout http` | HTTP probe with timing breakdown (DNS→Connect→TTFB→Transfer) |
| 🔒 TLS Cert | `netscout cert` | TLS certificate inspection — chain, expiry, cipher suite |
| ⚡ Speed Test | `netscout speed` | Bandwidth test via HTTP download |
| 📋 WHOIS | `netscout whois` | WHOIS lookup with field parsing |
| 📡 LAN Scan | `netscout scan` | Subnet host discovery with port checking |

All commands support `--json` for machine-readable output.

## Installation

### From source (cargo)
```bash
cargo install --git https://github.com/redbasecap-buiss/netscout netscout-cli
```

### From binary releases
Download from [GitHub Releases](https://github.com/redbasecap-buiss/netscout/releases).

## Quick Start

```bash
# Ping a host
netscout ping google.com

# DNS lookup
netscout dns example.com --type MX

# Scan ports
netscout port scanme.nmap.org --ports 22,80,443

# Traceroute
netscout trace cloudflare.com

# HTTP probe with timing
netscout http http://example.com

# Check TLS certificate
netscout cert google.com

# Speed test
netscout speed

# WHOIS lookup
netscout whois github.com

# Scan your LAN
netscout scan 192.168.1.0/24
```

## Usage

### Ping
```bash
netscout ping <target> [--count N] [--interval MS] [--timeout MS]
```
TCP connect ping (no root required). Reports min/avg/max/stddev/jitter and packet loss.

### DNS
```bash
netscout dns <domain> [--type A|AAAA|MX|TXT|CNAME|NS|SOA|PTR] [--resolver IP]
```
Raw DNS queries via UDP. Supports multiple resolvers (default: 8.8.8.8).

### Port Scan
```bash
netscout port <target> [--ports RANGE] [--timeout MS] [--parallel N]
```
Concurrent TCP connect scan. Supports ranges like `80,443,8000-9000`. Built-in service name detection.

### Traceroute
```bash
netscout trace <target> [--max-hops N] [--timeout MS]
```

### HTTP Probe
```bash
netscout http <url> [--method GET|POST|...] [--header K:V] [--follow]
```
Full HTTP request with timing breakdown: DNS → Connect → TLS → TTFB → Transfer.

### TLS Certificate
```bash
netscout cert <host> [--port 443]
```
Inspect TLS certificate chain, expiry dates, cipher suite. Warns if expiring within 30 days.

### Speed Test
```bash
netscout speed [--url URL] [--download-only] [--upload-only]
```

### WHOIS
```bash
netscout whois <domain|ip>
```
Automatic registrar detection. Parses registrar, dates, nameservers.

### LAN Scan
```bash
netscout scan <subnet> [--ports RANGE] [--timeout MS]
```
TCP ping sweep on a subnet with concurrent host/port discovery.

### Global Flags
```
--json       Output as JSON
--no-color   Disable colored output
-v, --verbose  Verbose output
```

## vs. Individual Tools

| Task | Traditional | netscout |
|------|------------|----------|
| Ping | `ping` | `netscout ping` (TCP, no root) |
| DNS | `dig` / `nslookup` | `netscout dns` |
| Port scan | `nmap` | `netscout port` |
| Traceroute | `traceroute` / `mtr` | `netscout trace` |
| HTTP timing | `curl -w` | `netscout http` |
| TLS check | `openssl s_client` | `netscout cert` |
| Speed test | `speedtest-cli` | `netscout speed` |
| WHOIS | `whois` | `netscout whois` |
| LAN scan | `nmap -sn` | `netscout scan` |

**Why netscout?** One `cargo install`, one binary, consistent JSON output, no Python/Perl/system dependencies.

## Architecture

```
netscout/
├── netscout-core/    # Library — all diagnostic modules
├── netscout-cli/     # CLI binary (clap)
└── netscout-tui/     # Terminal UI dashboard (ratatui)
```

**Key design decisions:**
- Pure Rust — no OpenSSL, no C dependencies
- `rustls` for TLS (secure, auditable)
- TCP-based probes — no raw sockets = no sudo required
- Async with `tokio` for concurrent scanning
- Minimal dependencies

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Ensure `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` pass
4. Commit and push
5. Open a Pull Request

## License

MIT — see [LICENSE](LICENSE).
