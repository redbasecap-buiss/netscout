# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-20

### Added
- Initial release
- **ping** — TCP connect ping with statistics (min/avg/max/stddev/jitter)
- **dns** — DNS resolver supporting A, AAAA, MX, TXT, CNAME, NS, SOA, PTR records
- **port** — TCP port scanner with service detection and configurable parallelism
- **trace** — Traceroute via TCP connections
- **http** — HTTP probe with timing breakdown (DNS/Connect/TTFB/Transfer)
- **cert** — TLS certificate inspection (chain, expiry, cipher suite)
- **speed** — Bandwidth speed test via HTTP download
- **whois** — WHOIS client with field parsing
- **scan** — LAN subnet scanner with host discovery
- JSON output support (`--json` flag)
- Colored human-readable output
- Terminal UI dashboard (netscout-tui)
- CI/CD with GitHub Actions
