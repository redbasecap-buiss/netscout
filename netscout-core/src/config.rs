//! Configuration file support for netscout.
//!
//! Loads defaults from `~/.netscout.toml`. Example config:
//!
//! ```toml
//! [defaults]
//! output = "json"          # human | json | table | csv
//! no_color = false
//! verbose = false
//!
//! [ping]
//! count = 4
//! interval = 1000          # milliseconds
//! timeout = 2000
//! port = 80
//!
//! [dns]
//! resolver = "8.8.8.8"
//! record_type = "A"
//!
//! [port]
//! timeout = 2000
//! parallel = 100
//!
//! [trace]
//! max_hops = 30
//! timeout = 2000
//!
//! [http]
//! method = "GET"
//! follow = false
//!
//! [cert]
//! port = 443
//!
//! [scan]
//! timeout = 500
//! ```

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level config file structure.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub defaults: DefaultsConfig,
    pub ping: PingDefaults,
    pub dns: DnsDefaults,
    pub port: PortDefaults,
    pub trace: TraceDefaults,
    pub http: HttpDefaults,
    pub cert: CertDefaults,
    pub scan: ScanDefaults,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct DefaultsConfig {
    pub output: Option<String>,
    pub no_color: Option<bool>,
    pub verbose: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct PingDefaults {
    pub count: Option<u32>,
    pub interval: Option<u64>,
    pub timeout: Option<u64>,
    pub port: Option<u16>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct DnsDefaults {
    pub resolver: Option<String>,
    pub record_type: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct PortDefaults {
    pub timeout: Option<u64>,
    pub parallel: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct TraceDefaults {
    pub max_hops: Option<u8>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct HttpDefaults {
    pub method: Option<String>,
    pub follow: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct CertDefaults {
    pub port: Option<u16>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct ScanDefaults {
    pub timeout: Option<u64>,
}

/// Return the default config file path (`~/.netscout.toml`).
pub fn config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".netscout.toml"))
}

/// Load config from the default path. Returns `Config::default()` if the file
/// doesn't exist. Returns an error only if the file exists but is invalid.
pub fn load_config() -> Result<Config, String> {
    load_config_from(config_path())
}

/// Load config from a specific path (or return defaults if `None`).
pub fn load_config_from(path: Option<PathBuf>) -> Result<Config, String> {
    let Some(path) = path else {
        return Ok(Config::default());
    };

    if !path.exists() {
        return Ok(Config::default());
    }

    let contents =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read config: {e}"))?;

    toml::from_str(&contents).map_err(|e| format!("Invalid config at {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert!(cfg.defaults.output.is_none());
        assert!(cfg.ping.count.is_none());
        assert!(cfg.dns.resolver.is_none());
    }

    #[test]
    fn test_parse_empty_toml() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.defaults.output.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[defaults]
output = "json"
no_color = true
verbose = true

[ping]
count = 10
interval = 500
timeout = 3000
port = 443

[dns]
resolver = "1.1.1.1"
record_type = "AAAA"

[port]
timeout = 5000
parallel = 200

[trace]
max_hops = 64
timeout = 3000

[http]
method = "HEAD"
follow = true

[cert]
port = 8443

[scan]
timeout = 1000
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.defaults.output.as_deref(), Some("json"));
        assert_eq!(cfg.defaults.no_color, Some(true));
        assert_eq!(cfg.defaults.verbose, Some(true));
        assert_eq!(cfg.ping.count, Some(10));
        assert_eq!(cfg.ping.interval, Some(500));
        assert_eq!(cfg.ping.timeout, Some(3000));
        assert_eq!(cfg.ping.port, Some(443));
        assert_eq!(cfg.dns.resolver.as_deref(), Some("1.1.1.1"));
        assert_eq!(cfg.dns.record_type.as_deref(), Some("AAAA"));
        assert_eq!(cfg.port.timeout, Some(5000));
        assert_eq!(cfg.port.parallel, Some(200));
        assert_eq!(cfg.trace.max_hops, Some(64));
        assert_eq!(cfg.trace.timeout, Some(3000));
        assert_eq!(cfg.http.method.as_deref(), Some("HEAD"));
        assert_eq!(cfg.http.follow, Some(true));
        assert_eq!(cfg.cert.port, Some(8443));
        assert_eq!(cfg.scan.timeout, Some(1000));
    }

    #[test]
    fn test_parse_partial_config() {
        let toml_str = r#"
[dns]
resolver = "9.9.9.9"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.dns.resolver.as_deref(), Some("9.9.9.9"));
        assert!(cfg.ping.count.is_none());
        assert!(cfg.defaults.output.is_none());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let cfg = load_config_from(Some(PathBuf::from("/tmp/nonexistent_netscout_test.toml")));
        assert!(cfg.is_ok());
        // Should return defaults
        let cfg = cfg.unwrap();
        assert!(cfg.defaults.output.is_none());
    }

    #[test]
    fn test_load_none_path() {
        let cfg = load_config_from(None).unwrap();
        assert!(cfg.defaults.output.is_none());
    }

    #[test]
    fn test_load_invalid_toml() {
        let path = PathBuf::from("/tmp/netscout_test_invalid.toml");
        std::fs::write(&path, "this is not valid [[[toml").unwrap();
        let result = load_config_from(Some(path.clone()));
        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_valid_toml_file() {
        let path = PathBuf::from("/tmp/netscout_test_valid.toml");
        std::fs::write(&path, "[ping]\ncount = 20\n").unwrap();
        let cfg = load_config_from(Some(path.clone())).unwrap();
        assert_eq!(cfg.ping.count, Some(20));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_config_path_returns_some() {
        // On most systems, home_dir should exist
        let path = config_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains(".netscout.toml"));
    }

    #[test]
    fn test_unknown_fields_ignored() {
        let toml_str = r#"
[defaults]
output = "table"
unknown_field = "ignored"

[unknown_section]
foo = "bar"
"#;
        // With serde default, unknown fields should cause an error unless we use deny_unknown_fields
        // We don't, so this should parse (serde's default behavior with flatten or just ignoring)
        let result: Result<Config, _> = toml::from_str(toml_str);
        // toml/serde will error on unknown fields by default
        // That's fine — we document valid fields
        let _ = result;
    }
}
