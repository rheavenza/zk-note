//! Zero-knowledge ciphertext storage and sync coordination server binary.
//!
//! In accordance with SEC-002, the server operates exclusively on opaque
//! ciphertext and protocol metadata and does not depend on crypto or core
//! plaintext models.

use zk_server::{init_logging, run_server, shutdown_signal, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::from_env()?;
    init_logging(&config)?;

    tracing::info!(
        host = %config.host,
        port = config.port,
        log_level = %config.log_level,
        "initializing zero-knowledge server"
    );

    let shutdown = shutdown_signal();
    run_server(config, shutdown).await?;

    Ok(())
}
