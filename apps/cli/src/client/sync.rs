//! Reusable guarded synchronization services (ZK-101).

use crate::auth::{has_auth_session, load_auth_session};
use crate::config::{auth_session_file, db_file, resolve_data_dir, vault_file};
use crate::error::CliError;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_storage::traits::ConflictStore;
use zk_storage::SqliteStorage;
use zk_sync::adapter::NativeHttpSyncAdapter;
use zk_sync::orchestrator::{SyncCycleOptions, SyncEngine};

/// Contextual sync status for the TUI status bar and indicators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Device is not logged in to a sync server.
    Offline,
    /// Device is authenticated and idle, ready to sync.
    Idle,
    /// Synchronization cycle is currently in flight.
    Syncing,
    /// Last sync succeeded cleanly.
    Synced {
        /// Number of mutations accepted by server.
        accepted: usize,
    },
    /// Last sync finished with unresolved conflicts.
    Conflict {
        /// Number of unresolved conflicts.
        conflict_count: usize,
    },
    /// Last sync failed with an error.
    Error(String),
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncStatus::Offline => write!(f, "Offline (not logged in)"),
            SyncStatus::Idle => write!(f, "Idle"),
            SyncStatus::Syncing => write!(f, "Syncing..."),
            SyncStatus::Synced { accepted } => write!(f, "Synced ({accepted} pushed)"),
            SyncStatus::Conflict { conflict_count } => {
                write!(f, "Conflict ({conflict_count} unresolved)")
            }
            SyncStatus::Error(err) => write!(f, "Sync Error: {err}"),
        }
    }
}

/// Checks the current authentication and sync state without performing network operations.
pub fn get_initial_sync_status(custom_data_dir: Option<&Path>) -> SyncStatus {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return SyncStatus::Offline;
    }

    if let Ok(storage) = SqliteStorage::open(&db_path) {
        if let Ok(conflicts) = storage.list_conflicts(Some(false)) {
            if !conflicts.is_empty() {
                return SyncStatus::Conflict {
                    conflict_count: conflicts.len(),
                };
            }
        }
    }

    SyncStatus::Idle
}

/// Runs a guarded pull-before-push sync cycle.
///
/// Uses the existing [`SyncEngine`] with CAS revision safety.
pub async fn perform_sync(
    custom_data_dir: Option<&Path>,
    vault_key: Option<&VaultKey>,
) -> Result<SyncStatus, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let auth_path = auth_session_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    if !has_auth_session(&auth_path) {
        return Ok(SyncStatus::Offline);
    }

    let auth_session = load_auth_session(&auth_path)?;
    let adapter = NativeHttpSyncAdapter::new(
        &auth_session.server_url,
        Some(auth_session.token.expose_secret().to_string()),
    )
    .map_err(|e| CliError::Network(format!("failed to initialize sync adapter: {e}")))?;

    let storage = Arc::new(SqliteStorage::open(&db_path)?);
    let engine = SyncEngine::new(adapter, Arc::clone(&storage));

    let report_result = match vault_key {
        Some(key) => {
            let mut session = VaultSession::from_key(key.clone());
            engine
                .sync_with_session(&mut session, SyncCycleOptions::default())
                .await
        }
        None => engine.sync(SyncCycleOptions::default()).await,
    };

    let report = match report_result {
        Ok(r) => r,
        Err(e) => {
            return Ok(SyncStatus::Error(e.to_string()));
        }
    };

    let active_conflicts = storage
        .list_conflicts(Some(false))
        .map(|c| c.len())
        .unwrap_or(0);

    if active_conflicts > 0 {
        Ok(SyncStatus::Conflict {
            conflict_count: active_conflicts,
        })
    } else {
        Ok(SyncStatus::Synced {
            accepted: report.mutations_accepted,
        })
    }
}
