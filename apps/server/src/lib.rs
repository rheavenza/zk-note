//! Zero-knowledge ciphertext storage and sync coordination server library.
//!
//! In accordance with SEC-002, the server operates exclusively on opaque
//! ciphertext and protocol metadata and does not depend on crypto or core
//! plaintext models.

pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod logging;
pub mod routes;
pub mod server;

pub use app::{create_app, AppState, ErrorResponse};
pub use auth::{auth_middleware, authenticate_bearer_token, AuthError, AuthenticatedAccount};
pub use config::{LogFormat, ServerConfig};
pub use error::{ConfigError, DbError, ServerError};

pub use logging::{
    init_logging, is_sensitive_header, redact_header_value, sanitize_header_map, sanitize_headers,
    REDACTED_PLACEHOLDER,
};
pub use server::{run_server, run_server_with_state, shutdown_signal};
