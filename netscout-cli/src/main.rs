use clap::{Parser, Subcommand};
use colored::Colorize;
use netscout_core::config::{self, Config};
use netscout_core::output::format_output;
use netscout_core::OutputFormat;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "netscout",
    version,
    about = "🔍 All-in-one network diagnostic toolkit",
    long_about = "netscout — The Swiss Army knife for network diagnostics.\nOne binary, every tool you need. Fast, beautiful, scriptable."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Output as a table
    #[arg(long, global = true)]
    table: bool,

    /// Output as CSV (for scripting/pipelines)
    #[arg(long, global = true)]
    csv: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Enable verbose output
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Path to config file (default: ~/.netscout.toml)
    #[arg(long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// TCP ping a target host
    Ping {
        /// Target hostname or IP
        target: String,
        /// Number of pings to send
        #[arg(short, long)]
        count: Option<u32>,
        /// Interval between pings in milliseconds
        #[arg(short, long)]
        interval: Option<u64>,
        /// Timeout per ping in milliseconds
        #[arg(short, long)]
        timeout: Option<u64>,
        /// TCP port to ping
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Query DNS records
    Dns {
        /// Domain to query
        domain: String,
        /// Record type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR)
        #[arg(short = 't', long = "type")]
        record_type: Option<String>,
        /// DNS resolver IP
        #[arg(short, long)]
        resolver: Option<String>,
    },
    /// Scan TCP ports on a target
    Port {
        /// Target hostname or IP
        target: String,
        /// Ports to scan (e.g., "80,443,8000-9000")
        #[arg(short, long)]
        ports: Option<String>,
        /// Timeout per connection in milliseconds
        #[arg(short, long)]
        timeout: Option<u64>,
        /// Number of parallel connections
        #[arg(long)]
        parallel: Option<usize>,
    },
    /// Traceroute to a target
    Trace {
        /// Target hostname or IP
        target: String,
        /// Maximum number of hops
        #[arg(long)]
        max_hops: Option<u8>,
        /// Timeout per hop in milliseconds
        #[arg(short, long)]
        timeout: Option<u64>,
    },
    /// Probe an HTTP(S) URL
    Http {
        /// URL to probe
        url: String,
        /// HTTP method
        #[arg(short, long)]
        method: Option<String>,
        /// Extra headers (K:V format, repeatable)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Follow redirects
        #[arg(short, long)]
        follow: bool,
    },
    /// Inspect TLS certificate
    Cert {
        /// Hostname to inspect
        host: String,
        /// Port number
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Run a bandwidth speed test
    Speed {
        /// Download test URL
        #[arg(long)]
        url: Option<String>,
        /// Download only
        #[arg(long)]
        download_only: bool,
        /// Upload only
        #[arg(long)]
        upload_only: bool,
    },
    /// WHOIS lookup
    Whois {
        /// Domain or IP to query
        target: String,
    },
    /// List network interfaces
    Netif {
        /// Show only interfaces that are UP
        #[arg(long)]
        up_only: bool,
    },
    /// Scan a LAN subnet for hosts
    Scan {
        /// Subnet in CIDR notation (e.g., 192.168.1.0/24)
        subnet: String,
        /// Ports to check per host
        #[arg(short, long)]
        ports: Option<String>,
        /// Timeout per connection in milliseconds
        #[arg(short, long)]
        timeout: Option<u64>,
    },
}

fn get_format(cli: &Cli, cfg: &Config) -> OutputFormat {
    if cli.json {
        OutputFormat::Json
    } else if cli.csv {
        OutputFormat::Csv
    } else if cli.table {
        OutputFormat::Table
    } else if let Some(ref fmt) = cfg.defaults.output {
        OutputFormat::parse(fmt).unwrap_or(OutputFormat::Human)
    } else {
        OutputFormat::Human
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let cfg = match &cli.config {
        Some(path) => config::load_config_from(Some(path.into()))?,
        None => config::load_config()?,
    };

    let no_color = cli.no_color || cfg.defaults.no_color.unwrap_or(false);
    if no_color {
        colored::control::set_override(false);
    }

    let format = get_format(&cli, &cfg);

    let result: Result<String, String> = match cli.command {
        Commands::Ping {
            target,
            count,
            interval,
            timeout,
            port,
        } => {
            let config = netscout_core::ping::PingConfig {
                target,
                count: count.or(cfg.ping.count).unwrap_or(4),
                interval: Duration::from_millis(interval.or(cfg.ping.interval).unwrap_or(1000)),
                timeout: Duration::from_millis(timeout.or(cfg.ping.timeout).unwrap_or(2000)),
                port: port.or(cfg.ping.port).unwrap_or(80),
            };
            netscout_core::ping::ping(&config)
                .await
                .map(|r| format_output(&r, format))
        }
        Commands::Dns {
            domain,
            record_type,
            resolver,
        } => {
            let rt_str = record_type
                .or(cfg.dns.record_type.clone())
                .unwrap_or_else(|| "A".to_string());
            let rt = netscout_core::dns::RecordType::from_str_loose(&rt_str)
                .ok_or_else(|| format!("Unknown record type: {rt_str}"))?;
            let config = netscout_core::dns::DnsConfig {
                domain,
                record_type: rt,
                resolver: resolver
                    .or(cfg.dns.resolver.clone())
                    .unwrap_or_else(|| "8.8.8.8".to_string()),
                ..Default::default()
            };
            netscout_core::dns::query(&config).map(|r| format_output(&r, format))
        }
        Commands::Port {
            target,
            ports,
            timeout,
            parallel,
        } => {
            let port_list = match ports {
                Some(p) => netscout_core::port::parse_ports(&p)?,
                None => netscout_core::port::top_ports(),
            };
            let config = netscout_core::port::PortConfig {
                target,
                ports: port_list,
                timeout: Duration::from_millis(timeout.or(cfg.port.timeout).unwrap_or(2000)),
                parallel: parallel.or(cfg.port.parallel).unwrap_or(100),
            };
            netscout_core::port::scan(&config)
                .await
                .map(|r| format_output(&r, format))
        }
        Commands::Trace {
            target,
            max_hops,
            timeout,
        } => {
            let config = netscout_core::trace::TraceConfig {
                target,
                max_hops: max_hops.or(cfg.trace.max_hops).unwrap_or(30),
                timeout: Duration::from_millis(timeout.or(cfg.trace.timeout).unwrap_or(2000)),
                ..Default::default()
            };
            netscout_core::trace::trace(&config)
                .await
                .map(|r| format_output(&r, format))
        }
        Commands::Http {
            url,
            method,
            headers,
            follow,
        } => {
            let parsed_headers: Vec<(String, String)> = headers
                .iter()
                .filter_map(|h| {
                    h.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            let config = netscout_core::http::HttpConfig {
                url,
                method: method
                    .or(cfg.http.method.clone())
                    .unwrap_or_else(|| "GET".to_string()),
                headers: parsed_headers,
                follow_redirects: follow || cfg.http.follow.unwrap_or(false),
                ..Default::default()
            };
            netscout_core::http::probe(&config).map(|r| format_output(&r, format))
        }
        Commands::Cert { host, port } => {
            let config = netscout_core::cert::CertConfig {
                host,
                port: port.or(cfg.cert.port).unwrap_or(443),
                ..Default::default()
            };
            netscout_core::cert::inspect(&config).map(|r| format_output(&r, format))
        }
        Commands::Speed {
            url,
            download_only,
            upload_only,
        } => {
            let config = netscout_core::speed::SpeedConfig {
                download_url: url.unwrap_or_else(|| {
                    "http://speed.cloudflare.com/__down?bytes=10000000".to_string()
                }),
                download_only,
                upload_only,
                ..Default::default()
            };
            netscout_core::speed::test_speed(&config).map(|r| format_output(&r, format))
        }
        Commands::Whois { target } => {
            let config = netscout_core::whois::WhoisConfig {
                target,
                ..Default::default()
            };
            netscout_core::whois::query(&config).map(|r| format_output(&r, format))
        }
        Commands::Netif { up_only } => netscout_core::netif::list_interfaces().map(|mut r| {
            if up_only {
                r.interfaces.retain(|i| i.is_up);
                r.total = r.interfaces.len();
            }
            format_output(&r, format)
        }),
        Commands::Scan {
            subnet,
            ports,
            timeout,
        } => {
            let port_list = match ports {
                Some(p) => netscout_core::port::parse_ports(&p)?,
                None => vec![22, 80, 443, 8080],
            };
            let config = netscout_core::scan::LanScanConfig {
                subnet,
                ports: port_list,
                timeout: Duration::from_millis(timeout.or(cfg.scan.timeout).unwrap_or(500)),
                ..Default::default()
            };
            netscout_core::scan::scan(&config)
                .await
                .map(|r| format_output(&r, format))
        }
    };

    match result {
        Ok(output) => print!("{output}"),
        Err(e) => {
            eprintln!("{} {e}", "Error:".red().bold());
            std::process::exit(1);
        }
    }

    Ok(())
}
