//! Unified error types for netscout-core.

use thiserror::Error;

/// Top-level error type for all netscout operations.
#[derive(Debug, Error)]
pub enum NetscoutError {
    /// DNS resolution or query failure.
    #[error("DNS error: {0}")]
    Dns(String),

    /// Network connection failure.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Invalid user input (bad arguments, port ranges, CIDR, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// TLS / certificate error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// I/O error from the OS.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration file error.
    #[error("Config error: {0}")]
    Config(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, NetscoutError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NetscoutError::Dns("NXDOMAIN".into());
        assert_eq!(err.to_string(), "DNS error: NXDOMAIN");
    }

    #[test]
    fn test_error_display_connection() {
        let err = NetscoutError::Connection("refused".into());
        assert_eq!(err.to_string(), "Connection error: refused");
    }

    #[test]
    fn test_error_display_timeout() {
        let err = NetscoutError::Timeout("5s elapsed".into());
        assert_eq!(err.to_string(), "Timeout: 5s elapsed");
    }

    #[test]
    fn test_error_display_invalid_input() {
        let err = NetscoutError::InvalidInput("bad port range".into());
        assert_eq!(err.to_string(), "Invalid input: bad port range");
    }

    #[test]
    fn test_error_display_tls() {
        let err = NetscoutError::Tls("handshake failed".into());
        assert_eq!(err.to_string(), "TLS error: handshake failed");
    }

    #[test]
    fn test_error_display_config() {
        let err = NetscoutError::Config("invalid TOML".into());
        assert_eq!(err.to_string(), "Config error: invalid TOML");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: NetscoutError = io_err.into();
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetscoutError>();
    }
}
