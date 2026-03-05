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


impl NetscoutError {
    /// Returns `true` if this is a timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Returns `true` if this is a network-related error (DNS, connection, or timeout).
    pub fn is_network(&self) -> bool {
        matches!(self, Self::Dns(_) | Self::Connection(_) | Self::Timeout(_))
    }

    /// Returns `true` if this is caused by invalid user input.
    pub fn is_user_error(&self) -> bool {
        matches!(self, Self::InvalidInput(_) | Self::Config(_))
    }
}

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
    
    #[test]
    fn test_is_timeout() {
        assert!(NetscoutError::Timeout("elapsed".into()).is_timeout());
        assert!(!NetscoutError::Dns("fail".into()).is_timeout());
        assert!(!NetscoutError::Connection("refused".into()).is_timeout());
    }

    #[test]
    fn test_is_network() {
        assert!(NetscoutError::Dns("NXDOMAIN".into()).is_network());
        assert!(NetscoutError::Connection("refused".into()).is_network());
        assert!(NetscoutError::Timeout("5s".into()).is_network());
        assert!(!NetscoutError::InvalidInput("bad".into()).is_network());
        assert!(!NetscoutError::Tls("fail".into()).is_network());
        assert!(!NetscoutError::Config("bad toml".into()).is_network());
    }

    #[test]
    fn test_is_user_error() {
        assert!(NetscoutError::InvalidInput("bad port".into()).is_user_error());
        assert!(NetscoutError::Config("parse fail".into()).is_user_error());
        assert!(!NetscoutError::Dns("fail".into()).is_user_error());
        assert!(!NetscoutError::Timeout("5s".into()).is_user_error());
    }

}
}
