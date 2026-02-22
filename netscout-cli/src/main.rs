use clap::{Parser, Subcommand};
use colored::Colorize;
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

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Enable verbose output
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// TCP ping a target host
    Ping {
        /// Target hostname or IP
        target: String,
        /// Number of pings to send
        #[arg(short, long, default_value = "4")]
        count: u32,
        /// Interval between pings in milliseconds
        #[arg(short, long, default_value = "1000")]
        interval: u64,
        /// Timeout per ping in milliseconds
        #[arg(short, long, default_value = "2000")]
        timeout: u64,
        /// TCP port to ping (default: 80)
        #[arg(short, long, default_value = "80")]
        port: u16,
    },
    /// Query DNS records
    Dns {
        /// Domain to query
        domain: String,
        /// Record type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR)
        #[arg(short = 't', long = "type", default_value = "A")]
        record_type: String,
        /// DNS resolver IP
        #[arg(short, long, default_value = "8.8.8.8")]
        resolver: String,
    },
    /// Scan TCP ports on a target
    Port {
        /// Target hostname or IP
        target: String,
        /// Ports to scan (e.g., "80,443,8000-9000")
        #[arg(short, long)]
        ports: Option<String>,
        /// Timeout per connection in milliseconds
        #[arg(short, long, default_value = "2000")]
        timeout: u64,
        /// Number of parallel connections
        #[arg(long, default_value = "100")]
        parallel: usize,
    },
    /// Traceroute to a target
    Trace {
        /// Target hostname or IP
        target: String,
        /// Maximum number of hops
        #[arg(long, default_value = "30")]
        max_hops: u8,
        /// Timeout per hop in milliseconds
        #[arg(short, long, default_value = "2000")]
        timeout: u64,
    },
    /// Probe an HTTP(S) URL
    Http {
        /// URL to probe
        url: String,
        /// HTTP method
        #[arg(short, long, default_value = "GET")]
        method: String,
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
        #[arg(short, long, default_value = "443")]
        port: u16,
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
        #[arg(short, long, default_value = "500")]
        timeout: u64,
    },
}

fn get_format(cli: &Cli) -> OutputFormat {
    if cli.json {
        OutputFormat::Json
    } else if cli.table {
        OutputFormat::Table
    } else {
        OutputFormat::Human
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let format = get_format(&cli);

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
                count,
                interval: Duration::from_millis(interval),
                timeout: Duration::from_millis(timeout),
                port,
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
            let rt = netscout_core::dns::RecordType::from_str_loose(&record_type)
                .ok_or_else(|| format!("Unknown record type: {record_type}"))?;
            let config = netscout_core::dns::DnsConfig {
                domain,
                record_type: rt,
                resolver,
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
                timeout: Duration::from_millis(timeout),
                parallel,
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
                max_hops,
                timeout: Duration::from_millis(timeout),
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
                method,
                headers: parsed_headers,
                follow_redirects: follow,
                ..Default::default()
            };
            netscout_core::http::probe(&config).map(|r| format_output(&r, format))
        }
        Commands::Cert { host, port } => {
            let config = netscout_core::cert::CertConfig {
                host,
                port,
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
                timeout: Duration::from_millis(timeout),
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
