//! Server configuration loading and validation.

use crate::error::ConfigError;
use std::net::SocketAddr;
use std::str::FromStr;

/// Log formatting output mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Machine-readable structured JSON format (default for production observability).
    #[default]
    Json,
    /// Human-readable text format (useful in local interactive development).
    Text,
}

impl FromStr for LogFormat {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" | "pretty" | "compact" => Ok(Self::Text),
            other => Err(ConfigError::InvalidLogFormat(format!(
                "unsupported log format '{other}', expected 'json' or 'text'"
            ))),
        }
    }
}

/// Server runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Bind host / IP address (e.g. "127.0.0.1" or "0.0.0.0").
    pub host: String,
    /// Bind TCP port (e.g. 8080).
    pub port: u16,
    /// Tracing filter / log level directive (e.g. "info", "debug,zk_server=trace").
    pub log_level: String,
    /// Formatting style for structured log events.
    pub log_format: LogFormat,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            log_level: "info".to_string(),
            log_format: LogFormat::Json,
        }
    }
}

impl ServerConfig {
    /// Loads configuration from standard process environment variables.
    ///
    /// Supported variables:
    /// - `ZK_SERVER_HOST` / `HOST` (default: 127.0.0.1)
    /// - `ZK_SERVER_PORT` / `PORT` (default: 8080)
    /// - `ZK_SERVER_LOG_LEVEL` / `RUST_LOG` (default: info)
    /// - `ZK_SERVER_LOG_FORMAT` / `LOG_FORMAT` (default: json)
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Loads configuration using a generic key-value lookup function.
    ///
    /// This enables deterministic testing without mutating process-global environment variables.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let host = lookup("ZK_SERVER_HOST")
            .or_else(|| lookup("HOST"))
            .unwrap_or_else(|| "127.0.0.1".to_string());

        if host.trim().is_empty() {
            return Err(ConfigError::InvalidHost("host cannot be empty".to_string()));
        }

        let port_str = lookup("ZK_SERVER_PORT").or_else(|| lookup("PORT"));
        let port = match port_str {
            Some(raw) => {
                let p = raw.trim().parse::<u16>().map_err(|e| {
                    ConfigError::InvalidPort(format!("failed to parse '{raw}' as port number: {e}"))
                })?;
                if p == 0 {
                    return Err(ConfigError::InvalidPort("port must be > 0".to_string()));
                }
                p
            }
            None => 8080,
        };

        let log_level = lookup("ZK_SERVER_LOG_LEVEL")
            .or_else(|| lookup("RUST_LOG"))
            .unwrap_or_else(|| "info".to_string());

        let log_format = match lookup("ZK_SERVER_LOG_FORMAT").or_else(|| lookup("LOG_FORMAT")) {
            Some(raw) => raw.parse::<LogFormat>()?,
            None => LogFormat::Json,
        };

        let config = Self {
            host,
            port,
            log_level,
            log_format,
        };

        // Validate that the host:port combination parses into a valid SocketAddr
        let _ = config.socket_addr()?;

        Ok(config)
    }

    /// Parses host and port into a [`SocketAddr`].
    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        let addr_str = format!("{}:{}", self.host, self.port);
        addr_str.parse::<SocketAddr>().map_err(|e| {
            ConfigError::InvalidSocketAddr(format!("invalid socket address '{addr_str}': {e}"))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_config() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert!(cfg.socket_addr().is_ok());
    }

    #[test]
    fn test_from_lookup_custom() {
        let mut env = HashMap::new();
        env.insert("ZK_SERVER_HOST".to_string(), "0.0.0.0".to_string());
        env.insert("ZK_SERVER_PORT".to_string(), "9000".to_string());
        env.insert("ZK_SERVER_LOG_LEVEL".to_string(), "debug".to_string());
        env.insert("ZK_SERVER_LOG_FORMAT".to_string(), "text".to_string());

        let cfg = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap();
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert_eq!(
            cfg.socket_addr().unwrap(),
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_from_lookup_fallback_env_keys() {
        let mut env = HashMap::new();
        env.insert("HOST".to_string(), "127.0.0.2".to_string());
        env.insert("PORT".to_string(), "3000".to_string());
        env.insert("RUST_LOG".to_string(), "warn".to_string());
        env.insert("LOG_FORMAT".to_string(), "compact".to_string());

        let cfg = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap();
        assert_eq!(cfg.host, "127.0.0.2");
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.log_level, "warn");
        assert_eq!(cfg.log_format, LogFormat::Text);
    }

    #[test]
    fn test_invalid_port_zero() {
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "0".to_string());
        let err = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPort(_)));
    }

    #[test]
    fn test_invalid_port_not_a_number() {
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "invalid".to_string());
        let err = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPort(_)));
    }

    #[test]
    fn test_invalid_host_empty() {
        let mut env = HashMap::new();
        env.insert("HOST".to_string(), "   ".to_string());
        let err = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHost(_)));
    }

    #[test]
    fn test_invalid_host_socket_addr() {
        let mut env = HashMap::new();
        env.insert("HOST".to_string(), "999.999.999.999".to_string());
        let err = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidSocketAddr(_)));
    }

    #[test]
    fn test_invalid_log_format() {
        let mut env = HashMap::new();
        env.insert("LOG_FORMAT".to_string(), "xml".to_string());
        let err = ServerConfig::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogFormat(_)));
    }
}
