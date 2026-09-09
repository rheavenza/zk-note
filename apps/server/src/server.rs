use crate::app::{create_app, AppState};
use crate::config::ServerConfig;
use crate::error::ServerError;
use std::future::Future;

/// Runs the HTTP server using an in-memory database until the shutdown signal completes.
pub async fn run_server(
    config: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    let state = AppState::new_in_memory(config)?;
    run_server_with_state(state, shutdown).await
}

/// Runs the HTTP server with the provided application state.
pub async fn run_server_with_state(
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    let addr = state.config.socket_addr()?;

    tracing::info!(
        host = %state.config.host,
        port = state.config.port,
        log_level = %state.config.log_level,
        "binding TCP listener"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(ServerError::Io)?;

    tracing::info!(addr = %addr, "server listening and ready for requests");

    let app = create_app(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(ServerError::Io)?;

    tracing::info!("server gracefully stopped");
    Ok(())
}

/// Waits for a process termination signal (Ctrl+C or Unix SIGTERM).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("failed to listen for Ctrl+C: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!("failed to listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("shutdown signal received (Ctrl+C)");
        },
        _ = terminate => {
            tracing::info!("shutdown signal received (SIGTERM)");
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_starts_and_stops_with_shutdown_signal() {
        // Bind to port 0 on loopback so OS assigns an available ephemeral port
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            run_server(config, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });

        // Trigger shutdown immediately
        shutdown_tx.send(()).unwrap();

        let result = server_task.await.unwrap();
        assert!(result.is_ok());
    }
}
