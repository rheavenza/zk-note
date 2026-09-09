//! SQLite-backed local encrypted cache implementation for native/CLI environments.

use crate::error::StorageError;
use crate::models::{
    MutationStatus, MutationType, ObjectFilter, PendingMutation, StoredEncryptedObject, SyncState,
};
use crate::traits::{BaseVersionStore, MutationStore, ObjectStore, SyncStateStore};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zk_protocol::envelope::EncryptedEnvelope;

const MIGRATION_001: &str = include_str!("../../../migrations/001_initial_local_storage.sql");

/// SQLite-backed persistent local encrypted storage.
///
/// Implements [`LocalStorage`] using SQLite. All sensitive content is stored
/// strictly within encrypted envelopes.
#[derive(Debug)]
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
}

impl SqliteStorage {
    /// Opens or creates an encrypted local SQLite database at the specified file path.
    ///
    /// Automatically applies pending schema migrations upon connection.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StorageError::Backend(format!(
                    "failed to create parent directory for SQLite database: {e}"
                ))
            })?;
        }

        let mut conn = Connection::open(&path_buf).map_err(|e| {
            StorageError::Backend(format!(
                "failed to open SQLite database at {}: {e}",
                path_buf.display()
            ))
        })?;

        // Configure performance and safety pragmas
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| StorageError::Backend(format!("failed to configure pragmas: {e}")))?;

        run_migrations(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: Some(path_buf),
        })
    }

    /// Opens an ephemeral in-memory SQLite database.
    ///
    /// Useful for fast integration testing.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let mut conn = Connection::open_in_memory()
            .map_err(|e| StorageError::Backend(format!("failed to open in-memory SQLite: {e}")))?;

        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| StorageError::Backend(format!("failed to configure pragmas: {e}")))?;

        run_migrations(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: None,
        })
    }

    /// Returns the file path of the database, if not in-memory.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

fn run_migrations(conn: &mut Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| StorageError::Backend(format!("failed to initialize migrations table: {e}")))?;

    let current_version: Option<i64> = conn
        .query_row("SELECT MAX(version) FROM _schema_migrations;", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| StorageError::Backend(format!("failed to query schema version: {e}")))?
        .flatten();

    let version = current_version.unwrap_or(0);

    if version < 1 {
        let tx = conn.transaction().map_err(|e| {
            StorageError::Backend(format!("failed to begin migration transaction: {e}"))
        })?;

        tx.execute_batch(MIGRATION_001)
            .map_err(|e| StorageError::Backend(format!("failed to execute migration 001: {e}")))?;

        tx.commit()
            .map_err(|e| StorageError::Backend(format!("failed to commit migration 001: {e}")))?;
    }

    Ok(())
}

impl ObjectStore for SqliteStorage {
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT object_id, object_kind, revision, server_seq, is_deleted, envelope, updated_at
                 FROM local_objects WHERE object_id = ?1;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare get_object failed: {e}")))?;

        let row = stmt
            .query_row(params![object_id], |row| {
                let object_id: String = row.get(0)?;
                let object_kind: u16 = row.get(1)?;
                let revision: u64 = row.get(2)?;
                let server_seq: u64 = row.get(3)?;
                let is_deleted_num: i64 = row.get(4)?;
                let envelope_json: String = row.get(5)?;
                let updated_at: String = row.get(6)?;
                Ok((
                    object_id,
                    object_kind,
                    revision,
                    server_seq,
                    is_deleted_num != 0,
                    envelope_json,
                    updated_at,
                ))
            })
            .optional()
            .map_err(|e| StorageError::Backend(format!("get_object query failed: {e}")))?;

        match row {
            Some((
                object_id,
                object_kind,
                revision,
                server_seq,
                is_deleted,
                envelope_json,
                updated_at,
            )) => {
                let envelope =
                    serde_json::from_str::<EncryptedEnvelope>(&envelope_json).map_err(|e| {
                        StorageError::Serialization(format!("deserialize envelope: {e}"))
                    })?;

                Ok(Some(StoredEncryptedObject {
                    object_id,
                    object_kind,
                    revision,
                    server_seq,
                    is_deleted,
                    envelope,
                    updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let envelope_json = serde_json::to_string(&object.envelope)
            .map_err(|e| StorageError::Serialization(format!("serialize envelope: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO local_objects (object_id, object_kind, revision, server_seq, is_deleted, envelope, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(object_id) DO UPDATE SET
                    object_kind = excluded.object_kind,
                    revision = excluded.revision,
                    server_seq = excluded.server_seq,
                    is_deleted = excluded.is_deleted,
                    envelope = excluded.envelope,
                    updated_at = excluded.updated_at;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare put_object failed: {e}")))?;

        stmt.execute(params![
            object.object_id,
            object.object_kind,
            object.revision,
            object.server_seq,
            if object.is_deleted { 1 } else { 0 },
            envelope_json,
            object.updated_at,
        ])
        .map_err(|e| StorageError::Backend(format!("put_object execute failed: {e}")))?;

        Ok(())
    }

    fn list_objects(
        &self,
        filter: &ObjectFilter,
    ) -> Result<Vec<StoredEncryptedObject>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut sql = "SELECT object_id, object_kind, revision, server_seq, is_deleted, envelope, updated_at FROM local_objects WHERE 1=1".to_string();
        if !filter.include_deleted {
            sql.push_str(" AND is_deleted = 0");
        }
        if filter.kind.is_some() {
            sql.push_str(" AND object_kind = ?1");
        }
        sql.push_str(" ORDER BY object_id ASC;");

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(format!("prepare list_objects failed: {e}")))?;

        let map_row = |row: &rusqlite::Row| {
            let object_id: String = row.get(0)?;
            let object_kind: u16 = row.get(1)?;
            let revision: u64 = row.get(2)?;
            let server_seq: u64 = row.get(3)?;
            let is_deleted_num: i64 = row.get(4)?;
            let envelope_json: String = row.get(5)?;
            let updated_at: String = row.get(6)?;
            Ok((
                object_id,
                object_kind,
                revision,
                server_seq,
                is_deleted_num != 0,
                envelope_json,
                updated_at,
            ))
        };

        let raw_rows = if let Some(kind) = filter.kind {
            stmt.query_map(params![kind], map_row)
        } else {
            stmt.query_map([], map_row)
        }
        .map_err(|e| StorageError::Backend(format!("list_objects query failed: {e}")))?;

        let mut results = Vec::new();
        for item in raw_rows {
            let (
                object_id,
                object_kind,
                revision,
                server_seq,
                is_deleted,
                envelope_json,
                updated_at,
            ) = item.map_err(|e| StorageError::Backend(format!("row mapping error: {e}")))?;

            let envelope = serde_json::from_str::<EncryptedEnvelope>(&envelope_json)
                .map_err(|e| StorageError::Serialization(format!("deserialize envelope: {e}")))?;

            results.push(StoredEncryptedObject {
                object_id,
                object_kind,
                revision,
                server_seq,
                is_deleted,
                envelope,
                updated_at,
            });
        }

        Ok(results)
    }

    fn mark_deleted(
        &self,
        object_id: &str,
        revision: u64,
        envelope: EncryptedEnvelope,
        updated_at: String,
    ) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let envelope_json = serde_json::to_string(&envelope)
            .map_err(|e| StorageError::Serialization(format!("serialize envelope: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "UPDATE local_objects SET is_deleted = 1, revision = ?1, envelope = ?2, updated_at = ?3 WHERE object_id = ?4;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare mark_deleted failed: {e}")))?;

        let rows_affected = stmt
            .execute(params![revision, envelope_json, updated_at, object_id])
            .map_err(|e| StorageError::Backend(format!("mark_deleted execute failed: {e}")))?;

        if rows_affected == 0 {
            Err(StorageError::NotFound {
                entity: "object",
                id: object_id.to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn purge_object(&self, object_id: &str) -> Result<bool, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached("DELETE FROM local_objects WHERE object_id = ?1;")
            .map_err(|e| StorageError::Backend(format!("prepare purge_object failed: {e}")))?;

        let rows = stmt
            .execute(params![object_id])
            .map_err(|e| StorageError::Backend(format!("purge_object execute failed: {e}")))?;

        Ok(rows > 0)
    }
}

impl MutationStore for SqliteStorage {
    fn enqueue_mutation(&self, mutation: &PendingMutation) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let envelope_json = serde_json::to_string(&mutation.envelope)
            .map_err(|e| StorageError::Serialization(format!("serialize envelope: {e}")))?;

        let mutation_type_str = match mutation.mutation_type {
            MutationType::Upsert => "Upsert",
            MutationType::Delete => "Delete",
        };

        let status_str = match mutation.status {
            MutationStatus::Pending => "Pending",
            MutationStatus::InFlight => "InFlight",
            MutationStatus::Failed => "Failed",
        };

        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO pending_mutations
                 (mutation_id, object_id, expected_revision, object_kind, mutation_type, envelope, created_at, retry_count, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);",
            )
            .map_err(|e| StorageError::Backend(format!("prepare enqueue_mutation failed: {e}")))?;

        let res = stmt.execute(params![
            mutation.mutation_id,
            mutation.object_id,
            mutation.expected_revision,
            mutation.object_kind,
            mutation_type_str,
            envelope_json,
            mutation.created_at,
            mutation.retry_count,
            status_str,
        ]);

        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StorageError::AlreadyExists {
                    entity: "pending_mutation",
                    id: mutation.mutation_id.clone(),
                })
            }
            Err(e) => Err(StorageError::Backend(format!(
                "enqueue_mutation failed: {e}"
            ))),
        }
    }

    fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT mutation_id, object_id, expected_revision, object_kind, mutation_type, envelope, created_at, retry_count, status
                 FROM pending_mutations WHERE mutation_id = ?1;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare get_mutation failed: {e}")))?;

        let row = stmt
            .query_row(params![mutation_id], parse_mutation_row)
            .optional()
            .map_err(|e| StorageError::Backend(format!("get_mutation query failed: {e}")))?;

        row.map(build_mutation).transpose()
    }

    fn list_pending_mutations(&self) -> Result<Vec<PendingMutation>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT mutation_id, object_id, expected_revision, object_kind, mutation_type, envelope, created_at, retry_count, status
                 FROM pending_mutations ORDER BY created_at ASC;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare list_pending_mutations failed: {e}")))?;

        let rows = stmt.query_map([], parse_mutation_row).map_err(|e| {
            StorageError::Backend(format!("list_pending_mutations query failed: {e}"))
        })?;

        let mut results = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| StorageError::Backend(format!("row mapping error: {e}")))?;
            results.push(build_mutation(raw)?);
        }

        Ok(results)
    }

    fn list_mutations_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<PendingMutation>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT mutation_id, object_id, expected_revision, object_kind, mutation_type, envelope, created_at, retry_count, status
                 FROM pending_mutations WHERE object_id = ?1 ORDER BY created_at ASC;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare list_mutations_for_object failed: {e}")))?;

        let rows = stmt
            .query_map(params![object_id], parse_mutation_row)
            .map_err(|e| {
                StorageError::Backend(format!("list_mutations_for_object query failed: {e}"))
            })?;

        let mut results = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| StorageError::Backend(format!("row mapping error: {e}")))?;
            results.push(build_mutation(raw)?);
        }

        Ok(results)
    }

    fn remove_mutation(&self, mutation_id: &str) -> Result<bool, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached("DELETE FROM pending_mutations WHERE mutation_id = ?1;")
            .map_err(|e| StorageError::Backend(format!("prepare remove_mutation failed: {e}")))?;

        let rows = stmt
            .execute(params![mutation_id])
            .map_err(|e| StorageError::Backend(format!("remove_mutation execute failed: {e}")))?;

        Ok(rows > 0)
    }

    fn update_mutation_status(
        &self,
        mutation_id: &str,
        status: MutationStatus,
        retry_count: u32,
    ) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let status_str = match status {
            MutationStatus::Pending => "Pending",
            MutationStatus::InFlight => "InFlight",
            MutationStatus::Failed => "Failed",
        };

        let mut stmt = conn
            .prepare_cached(
                "UPDATE pending_mutations SET status = ?1, retry_count = ?2 WHERE mutation_id = ?3;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare update_mutation_status failed: {e}")))?;

        let rows = stmt
            .execute(params![status_str, retry_count, mutation_id])
            .map_err(|e| {
                StorageError::Backend(format!("update_mutation_status execute failed: {e}"))
            })?;

        if rows == 0 {
            Err(StorageError::NotFound {
                entity: "pending_mutation",
                id: mutation_id.to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn pending_mutation_count(&self) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pending_mutations;", [], |r| r.get(0))
            .map_err(|e| {
                StorageError::Backend(format!("pending_mutation_count query failed: {e}"))
            })?;

        Ok(count as usize)
    }
}

type RawMutationRow = (
    String,
    String,
    u64,
    u16,
    String,
    String,
    String,
    u32,
    String,
);

fn parse_mutation_row(row: &rusqlite::Row) -> rusqlite::Result<RawMutationRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn build_mutation(raw: RawMutationRow) -> Result<PendingMutation, StorageError> {
    let (
        mutation_id,
        object_id,
        expected_revision,
        object_kind,
        mutation_type_str,
        envelope_json,
        created_at,
        retry_count,
        status_str,
    ) = raw;

    let mutation_type = match mutation_type_str.as_str() {
        "Upsert" => MutationType::Upsert,
        "Delete" => MutationType::Delete,
        other => {
            return Err(StorageError::Serialization(format!(
                "unknown mutation_type: {other}"
            )))
        }
    };

    let status = match status_str.as_str() {
        "Pending" => MutationStatus::Pending,
        "InFlight" => MutationStatus::InFlight,
        "Failed" => MutationStatus::Failed,
        other => {
            return Err(StorageError::Serialization(format!(
                "unknown mutation status: {other}"
            )))
        }
    };

    let envelope = serde_json::from_str::<EncryptedEnvelope>(&envelope_json)
        .map_err(|e| StorageError::Serialization(format!("deserialize envelope: {e}")))?;

    Ok(PendingMutation {
        mutation_id,
        object_id,
        expected_revision,
        object_kind,
        mutation_type,
        envelope,
        created_at,
        retry_count,
        status,
    })
}

impl BaseVersionStore for SqliteStorage {
    fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT envelope FROM encrypted_base_versions WHERE object_id = ?1 AND revision = ?2;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare get_base_version failed: {e}")))?;

        let envelope_json: Option<String> = stmt
            .query_row(params![object_id, revision], |r| r.get(0))
            .optional()
            .map_err(|e| StorageError::Backend(format!("get_base_version query failed: {e}")))?;

        match envelope_json {
            Some(json) => {
                let envelope = serde_json::from_str::<EncryptedEnvelope>(&json).map_err(|e| {
                    StorageError::Serialization(format!("deserialize base envelope: {e}"))
                })?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    fn put_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let envelope_json = serde_json::to_string(envelope)
            .map_err(|e| StorageError::Serialization(format!("serialize base envelope: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO encrypted_base_versions (object_id, revision, envelope, stored_at)
                 VALUES (?1, ?2, ?3, datetime('now'))
                 ON CONFLICT(object_id, revision) DO UPDATE SET
                    envelope = excluded.envelope,
                    stored_at = excluded.stored_at;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare put_base_version failed: {e}")))?;

        stmt.execute(params![object_id, revision, envelope_json])
            .map_err(|e| StorageError::Backend(format!("put_base_version execute failed: {e}")))?;

        Ok(())
    }

    fn prune_base_versions(
        &self,
        object_id: &str,
        older_than_revision: u64,
    ) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "DELETE FROM encrypted_base_versions WHERE object_id = ?1 AND revision < ?2;",
            )
            .map_err(|e| {
                StorageError::Backend(format!("prepare prune_base_versions failed: {e}"))
            })?;

        let rows = stmt
            .execute(params![object_id, older_than_revision])
            .map_err(|e| {
                StorageError::Backend(format!("prune_base_versions execute failed: {e}"))
            })?;

        Ok(rows)
    }

    fn clear_base_versions(&self, object_id: &str) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached("DELETE FROM encrypted_base_versions WHERE object_id = ?1;")
            .map_err(|e| {
                StorageError::Backend(format!("prepare clear_base_versions failed: {e}"))
            })?;

        let rows = stmt.execute(params![object_id]).map_err(|e| {
            StorageError::Backend(format!("clear_base_versions execute failed: {e}"))
        })?;

        Ok(rows)
    }

    fn list_base_versions(
        &self,
        object_id: &str,
    ) -> Result<Vec<(u64, EncryptedEnvelope)>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT revision, envelope FROM encrypted_base_versions WHERE object_id = ?1 ORDER BY revision ASC;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare list_base_versions failed: {e}")))?;

        let rows = stmt
            .query_map(params![object_id], |r| {
                let rev: u64 = r.get(0)?;
                let env_json: String = r.get(1)?;
                Ok((rev, env_json))
            })
            .map_err(|e| StorageError::Backend(format!("list_base_versions query failed: {e}")))?;

        let mut results = Vec::new();
        for item in rows {
            let (rev, env_json) =
                item.map_err(|e| StorageError::Backend(format!("row mapping error: {e}")))?;
            let envelope: EncryptedEnvelope = serde_json::from_str(&env_json).map_err(|e| {
                StorageError::Serialization(format!("deserialize base envelope: {e}"))
            })?;
            results.push((rev, envelope));
        }

        Ok(results)
    }
}

impl SyncStateStore for SqliteStorage {
    fn get_sync_state(&self) -> Result<SyncState, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT sync_cursor, last_sync_at, device_id FROM sync_state WHERE id = 1;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare get_sync_state failed: {e}")))?;

        let state = stmt
            .query_row([], |r| {
                let sync_cursor: u64 = r.get(0)?;
                let last_sync_at: Option<String> = r.get(1)?;
                let device_id: Option<String> = r.get(2)?;
                Ok(SyncState {
                    sync_cursor,
                    last_sync_at,
                    device_id,
                })
            })
            .map_err(|e| StorageError::Backend(format!("get_sync_state query failed: {e}")))?;

        Ok(state)
    }

    fn set_sync_cursor(&self, cursor: u64) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached("UPDATE sync_state SET sync_cursor = ?1 WHERE id = 1;")
            .map_err(|e| StorageError::Backend(format!("prepare set_sync_cursor failed: {e}")))?;

        stmt.execute(params![cursor])
            .map_err(|e| StorageError::Backend(format!("set_sync_cursor execute failed: {e}")))?;

        Ok(())
    }

    fn set_sync_state(&self, state: &SyncState) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Backend(format!("mutex lock failed: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "UPDATE sync_state SET sync_cursor = ?1, last_sync_at = ?2, device_id = ?3 WHERE id = 1;",
            )
            .map_err(|e| StorageError::Backend(format!("prepare set_sync_state failed: {e}")))?;

        stmt.execute(params![
            state.sync_cursor,
            state.last_sync_at,
            state.device_id
        ])
        .map_err(|e| StorageError::Backend(format!("set_sync_state execute failed: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE, OBJECT_KIND_NOTEBOOK};
    use zk_protocol::envelope::{EncryptedKeyContainer, EncryptedPayloadContainer};

    fn dummy_envelope(object_id: &str, kind: u16) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: object_id.to_string(),
            object_kind: kind,
            wrapped_key: EncryptedKeyContainer {
                nonce: "AA==".to_string(),
                ciphertext: "BB==".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "CC==".to_string(),
                ciphertext: "DD==".to_string(),
            },
        }
    }

    fn temp_db_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zk_test_{}_{}.db", name, std::process::id()));
        path
    }

    #[test]
    fn test_sqlite_in_memory_crud() {
        let storage = SqliteStorage::open_in_memory().expect("open in memory");
        let id = "obj-memory-1";
        let env = dummy_envelope(id, OBJECT_KIND_NOTE);

        let stored = StoredEncryptedObject {
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            revision: 1,
            server_seq: 42,
            is_deleted: false,
            envelope: env.clone(),
            updated_at: "2026-09-09T05:00:00Z".to_string(),
        };

        storage.put_object(&stored).expect("put");
        let fetched = storage.get_object(id).expect("get").expect("found");
        assert_eq!(stored, fetched);

        // Mark deleted
        storage
            .mark_deleted(id, 2, env, "2026-09-09T05:30:00Z".to_string())
            .expect("mark deleted");
        let active = storage
            .list_objects(&ObjectFilter::active_only())
            .expect("list active");
        assert_eq!(active.len(), 0);

        let all = storage
            .list_objects(&ObjectFilter::all())
            .expect("list all");
        assert_eq!(all.len(), 1);
        assert!(all[0].is_deleted);
        assert_eq!(all[0].revision, 2);

        // Purge
        assert!(storage.purge_object(id).expect("purge"));
        assert_eq!(storage.get_object(id).expect("get"), None);
    }

    #[test]
    fn test_sqlite_reopen_preserves_encrypted_objects() {
        let path = temp_db_path("reopen");
        let _ = fs::remove_file(&path);

        let id = "550e8400-e29b-41d4-a716-446655440000";
        let env = dummy_envelope(id, OBJECT_KIND_NOTE);

        let original = StoredEncryptedObject {
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            revision: 5,
            server_seq: 101,
            is_deleted: false,
            envelope: env,
            updated_at: "2026-09-09T10:00:00Z".to_string(),
        };

        // Open, write, and drop
        {
            let storage = SqliteStorage::open(&path).expect("open initial");
            storage.put_object(&original).expect("put");

            // Also test mutation and sync state persistence across reopen
            let mutation = PendingMutation {
                mutation_id: "mut-reopen-1".to_string(),
                object_id: id.to_string(),
                expected_revision: 5,
                object_kind: OBJECT_KIND_NOTE,
                mutation_type: MutationType::Upsert,
                envelope: original.envelope.clone(),
                created_at: "2026-09-09T10:01:00Z".to_string(),
                retry_count: 2,
                status: MutationStatus::InFlight,
            };
            storage.enqueue_mutation(&mutation).expect("enqueue");

            let sync_state = SyncState {
                sync_cursor: 101,
                last_sync_at: Some("2026-09-09T10:02:00Z".to_string()),
                device_id: Some("device-test-123".to_string()),
            };
            storage.set_sync_state(&sync_state).expect("set sync state");
        }

        // Reopen from disk
        {
            let reopened = SqliteStorage::open(&path).expect("reopen");

            let fetched_obj = reopened.get_object(id).expect("get").expect("exists");
            assert_eq!(original, fetched_obj);

            let fetched_mut = reopened
                .get_mutation("mut-reopen-1")
                .expect("get mut")
                .expect("exists");
            assert_eq!(fetched_mut.mutation_id, "mut-reopen-1");
            assert_eq!(fetched_mut.status, MutationStatus::InFlight);
            assert_eq!(fetched_mut.retry_count, 2);

            let state = reopened.get_sync_state().expect("sync state");
            assert_eq!(state.sync_cursor, 101);
            assert_eq!(state.device_id, Some("device-test-123".to_string()));
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_sqlite_no_plaintext_columns() {
        let storage = SqliteStorage::open_in_memory().expect("open");
        let conn = storage.conn.lock().expect("lock");

        let tables = [
            "local_objects",
            "pending_mutations",
            "encrypted_base_versions",
            "sync_state",
        ];

        let forbidden_keywords = [
            "title",
            "body",
            "tag",
            "plaintext",
            "content",
            "note_text",
            "search",
            "decrypted",
        ];

        for &table in &tables {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({table});"))
                .expect("pragma");

            let column_names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .expect("query map")
                .map(|r| r.expect("col name"))
                .collect();

            for col in &column_names {
                let lower = col.to_lowercase();
                for forbidden in &forbidden_keywords {
                    assert!(
                        !lower.contains(forbidden),
                        "forbidden keyword '{forbidden}' found in column '{col}' of table '{table}'"
                    );
                }
            }
        }
    }

    #[test]
    fn test_sqlite_no_plaintext_content_leakage() {
        let path = temp_db_path("no_plaintext_leakage");
        let _ = fs::remove_file(&path);

        let canary_title = "CANARY_PLAIN_TITLE_CONFIDENTIAL_12345";
        let canary_body = "CANARY_PLAIN_BODY_SECRET_67890";
        let canary_tag = "canary_plain_tag_secret_54321";

        // Create an envelope containing ciphertext (not plaintext canary strings)
        let id = "canary-obj-1";
        let envelope = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGVzdC1ub25jZQ==".to_string(),
                ciphertext: "dGVzdC1jaXBoZXJ0ZXh0".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "dGVzdC1ub25jZQ==".to_string(),
                ciphertext: "c29tZS1jaXBoZXJ0ZXh0LWJ5dGVz".to_string(),
            },
        };

        {
            let storage = SqliteStorage::open(&path).expect("open");

            storage
                .put_object(&StoredEncryptedObject {
                    object_id: id.to_string(),
                    object_kind: OBJECT_KIND_NOTE,
                    revision: 1,
                    server_seq: 1,
                    is_deleted: false,
                    envelope: envelope.clone(),
                    updated_at: "2026-09-09T05:00:00Z".to_string(),
                })
                .expect("put object");

            storage
                .enqueue_mutation(&PendingMutation {
                    mutation_id: "canary-mut-1".to_string(),
                    object_id: id.to_string(),
                    expected_revision: 1,
                    object_kind: OBJECT_KIND_NOTE,
                    mutation_type: MutationType::Upsert,
                    envelope: envelope.clone(),
                    created_at: "2026-09-09T05:01:00Z".to_string(),
                    retry_count: 0,
                    status: MutationStatus::Pending,
                })
                .expect("enqueue");

            storage
                .put_base_version(id, 1, &envelope)
                .expect("put base version");
        }

        // Now read the raw DB file from disk
        let file_bytes = fs::read(&path).expect("read db file");
        let file_str = String::from_utf8_lossy(&file_bytes);

        assert!(
            !file_str.contains(canary_title),
            "plaintext title leaked to SQLite file!"
        );
        assert!(
            !file_str.contains(canary_body),
            "plaintext body leaked to SQLite file!"
        );
        assert!(
            !file_str.contains(canary_tag),
            "plaintext tag leaked to SQLite file!"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_sqlite_filter_by_kind() {
        let storage = SqliteStorage::open_in_memory().expect("open");
        let note_env = dummy_envelope("note-1", OBJECT_KIND_NOTE);
        let nb_env = dummy_envelope("nb-1", OBJECT_KIND_NOTEBOOK);

        storage
            .put_object(&StoredEncryptedObject {
                object_id: "note-1".to_string(),
                object_kind: OBJECT_KIND_NOTE,
                revision: 1,
                server_seq: 1,
                is_deleted: false,
                envelope: note_env,
                updated_at: "2026-09-09T05:00:00Z".to_string(),
            })
            .expect("put note");

        storage
            .put_object(&StoredEncryptedObject {
                object_id: "nb-1".to_string(),
                object_kind: OBJECT_KIND_NOTEBOOK,
                revision: 1,
                server_seq: 2,
                is_deleted: false,
                envelope: nb_env,
                updated_at: "2026-09-09T05:00:00Z".to_string(),
            })
            .expect("put notebook");

        let notes = storage
            .list_objects(&ObjectFilter::for_kind(OBJECT_KIND_NOTE))
            .expect("list notes");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].object_id, "note-1");

        let nbs = storage
            .list_objects(&ObjectFilter::for_kind(OBJECT_KIND_NOTEBOOK))
            .expect("list nbs");
        assert_eq!(nbs.len(), 1);
        assert_eq!(nbs[0].object_id, "nb-1");
    }

    #[test]
    fn test_sqlite_base_version_lifecycle() {
        let storage = SqliteStorage::open_in_memory().expect("open");
        let obj_id = "test-obj-history";
        let env1 = dummy_envelope(obj_id, OBJECT_KIND_NOTE);
        let mut env2 = env1.clone();
        env2.wrapped_key.nonce = "NONCE_REV_2".to_string();

        storage
            .put_base_version(obj_id, 1, &env1)
            .expect("put rev 1");
        storage
            .put_base_version(obj_id, 2, &env2)
            .expect("put rev 2");

        let fetched1 = storage
            .get_base_version(obj_id, 1)
            .expect("get rev 1")
            .expect("found");
        assert_eq!(env1, fetched1);

        let list = storage.list_base_versions(obj_id).expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, 1);
        assert_eq!(list[1].0, 2);

        let pruned = storage.prune_base_versions(obj_id, 2).expect("prune");
        assert_eq!(pruned, 1);
        assert_eq!(storage.get_base_version(obj_id, 1).expect("get 1"), None);

        let remaining = storage.list_base_versions(obj_id).expect("list");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 2);

        let cleared = storage.clear_base_versions(obj_id).expect("clear");
        assert_eq!(cleared, 1);
        assert!(storage.list_base_versions(obj_id).expect("list").is_empty());
    }
}
