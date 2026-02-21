pub mod cert;
pub mod dns;
pub mod http;
pub mod netif;
pub mod output;
pub mod ping;
pub mod port;
pub mod scan;
pub mod speed;
pub mod trace;
pub mod whois;

/// Output format for all commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Table,
}
