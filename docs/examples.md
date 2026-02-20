# netscout Examples

## Ping

```bash
# Basic ping
netscout ping google.com

# 10 pings with 500ms interval
netscout ping google.com --count 10 --interval 500

# JSON output
netscout ping google.com --json
```

## DNS

```bash
# A record lookup
netscout dns example.com

# MX records
netscout dns example.com --type MX

# Use Cloudflare resolver
netscout dns example.com --resolver 1.1.1.1

# All record types
netscout dns example.com --type AAAA
netscout dns example.com --type NS
netscout dns example.com --type TXT
netscout dns example.com --type SOA
netscout dns example.com --type CNAME
```

## Port Scan

```bash
# Scan common ports
netscout port scanme.nmap.org

# Specific ports
netscout port example.com --ports 80,443,8080

# Port range
netscout port example.com --ports 8000-8100

# Increase parallelism
netscout port example.com --parallel 200
```

## Traceroute

```bash
# Basic traceroute
netscout trace google.com

# Limit hops
netscout trace google.com --max-hops 15
```

## HTTP Probe

```bash
# Basic probe
netscout http http://example.com

# Custom method and headers
netscout http http://api.example.com --method POST --header "Content-Type: application/json"

# Follow redirects
netscout http http://google.com --follow
```

## TLS Certificate

```bash
# Inspect certificate
netscout cert google.com

# Custom port
netscout cert example.com --port 8443

# JSON output for monitoring
netscout cert google.com --json
```

## Speed Test

```bash
# Run speed test
netscout speed

# Custom URL
netscout speed --url http://speedtest.example.com/file

# Download only
netscout speed --download-only
```

## WHOIS

```bash
# Domain lookup
netscout whois example.com

# JSON for parsing
netscout whois google.com --json
```

## LAN Scan

```bash
# Scan local network
netscout scan 192.168.1.0/24

# Custom ports
netscout scan 10.0.0.0/24 --ports 22,80,443,3389

# Quick scan with short timeout
netscout scan 192.168.1.0/24 --timeout 200
```

## Global Flags

```bash
# JSON output (works with any command)
netscout dns example.com --json

# No colors (for piping)
netscout ping google.com --no-color

# Verbose output
netscout port example.com -v
```
