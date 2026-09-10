//! Server database migration definitions and runner.

use crate::db::schema::verify_database_schema;
use crate::error::DbError;
use rusqlite::Connection;

/// Raw SQL contents of migration 002 (initial server schema).
pub const MIGRATION_002_SQL: &str =
    include_str!("../../../../migrations/002_initial_server_schema.sql");

/// Raw SQL contents of migration 003 (account sequence allocator).
pub const MIGRATION_003_SQL: &str =
    include_str!("../../../../migrations/003_account_sequences.sql");

/// Raw SQL contents of migration 004 (mutation idempotency).
pub const MIGRATION_004_SQL: &str =
    include_str!("../../../../migrations/004_mutation_idempotency.sql");

/// Raw SQL contents of migration 007 (server sessions).
pub const MIGRATION_007_SQL: &str = include_str!("../../../../migrations/007_server_sessions.sql");

/// Raw SQL contents of migration 008 (webauthn credentials).
pub const MIGRATION_008_SQL: &str =
    include_str!("../../../../migrations/008_webauthn_credentials.sql");

/// A versioned SQL schema migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// Incremental version number.
    pub version: u32,
    /// Migration identifier / name.
    pub name: &'static str,
    /// Migration SQL script.
    pub sql: &'static str,
}

/// All registered server schema migrations in chronological order.
pub const SERVER_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 2,
        name: "002_initial_server_schema",
        sql: MIGRATION_002_SQL,
    },
    Migration {
        version: 3,
        name: "003_account_sequences",
        sql: MIGRATION_003_SQL,
    },
    Migration {
        version: 4,
        name: "004_mutation_idempotency",
        sql: MIGRATION_004_SQL,
    },
    Migration {
        version: 7,
        name: "007_server_sessions",
        sql: MIGRATION_007_SQL,
    },
    Migration {
        version: 8,
        name: "008_webauthn_credentials",
        sql: MIGRATION_008_SQL,
    },
];

/// Runs all pending server database migrations on the given connection.
///
/// Ensures migrations are reproducible, transactional, and idempotent:
/// - Applied migrations are tracked in the `schema_migrations` table;
/// - Unapplied migrations are executed inside a transaction in version order;
/// - Already-applied migrations are safely skipped.
///
/// Returns the list of newly applied migration versions.
pub fn run_server_migrations(conn: &mut Connection) -> Result<Vec<u32>, DbError> {
    // 1. Ensure schema_migrations table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )?;

    // 2. Fetch list of already applied versions
    let applied_versions: Vec<u32> = {
        let mut stmt =
            conn.prepare("SELECT version FROM schema_migrations ORDER BY version ASC")?;
        let versions = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        versions
    };

    let mut newly_applied = Vec::new();

    // 3. Execute each pending migration in a transaction
    for migration in SERVER_MIGRATIONS {
        if applied_versions.contains(&migration.version) {
            continue;
        }

        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at)
             VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT (version) DO NOTHING",
            rusqlite::params![migration.version, migration.name],
        )?;
        tx.commit()?;

        newly_applied.push(migration.version);
    }

    Ok(newly_applied)
}

/// Creates a new in-memory SQLite database initialized with all server migrations.
///
/// Foreign key constraints are explicitly enabled.
pub fn create_in_memory_db() -> Result<Connection, DbError> {
    let mut conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    run_server_migrations(&mut conn)?;
    verify_database_schema(&conn)?;
    Ok(conn)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::db::schema::*;

    #[test]
    fn test_migrations_reproducible_and_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // First migration run applies versions 2, 3, 4, 7, and 8
        let applied1 = run_server_migrations(&mut conn).unwrap();
        assert_eq!(applied1, vec![2, 3, 4, 7, 8]);

        // Schema verification passes
        verify_database_schema(&conn).unwrap();

        // Second migration run is a no-op
        let applied2 = run_server_migrations(&mut conn).unwrap();
        assert!(
            applied2.is_empty(),
            "subsequent migration run must be idempotent"
        );
    }

    #[test]
    fn test_account_and_vault_uniqueness_and_fk() {
        let conn = create_in_memory_db().unwrap();

        let acc_id = uuid::Uuid::new_v4().to_string();

        // 1. Insert account
        conn.execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
            [&acc_id],
        )
        .unwrap();

        // 2. Duplicate account ID fails
        let dup_acc = conn.execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
            [&acc_id],
        );
        assert!(dup_acc.is_err(), "duplicate account ID must fail");

        // 3. Vault for existing account succeeds
        conn.execute(
            "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
             VALUES (?1, 1, 'Argon2id', '{}', X'00', X'01', X'02')",
            [&acc_id],
        )
        .unwrap();

        // 4. Duplicate vault for same account fails (primary key is account_id)
        let dup_vault = conn.execute(
            "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
             VALUES (?1, 1, 'Argon2id', '{}', X'00', X'01', X'02')",
            [&acc_id],
        );
        assert!(dup_vault.is_err(), "duplicate vault for account must fail");

        // 5. Vault for non-existent account fails foreign key check
        let nonexistent_acc = uuid::Uuid::new_v4().to_string();
        let bad_fk = conn.execute(
            "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
             VALUES (?1, 1, 'Argon2id', '{}', X'00', X'01', X'02')",
            [&nonexistent_acc],
        );
        assert!(bad_fk.is_err(), "vault foreign key constraint must fail");
    }

    #[test]
    fn test_encrypted_objects_uniqueness_and_sequence_index() {
        let conn = create_in_memory_db().unwrap();

        let acc_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
            [&acc_id],
        )
        .unwrap();

        let obj_1 = uuid::Uuid::new_v4().to_string();
        let obj_2 = uuid::Uuid::new_v4().to_string();

        // Insert obj_1 at revision 1, server_seq 1
        conn.execute(
            "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
             VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
            rusqlite::params![acc_id, obj_1],
        )
        .unwrap();

        // 1. Duplicate (account_id, object_id) fails primary key constraint
        let dup_obj = conn.execute(
            "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
             VALUES (?1, ?2, 1, 2, 2, 1, X'01', X'02')",
            rusqlite::params![acc_id, obj_1],
        );
        assert!(
            dup_obj.is_err(),
            "duplicate (account_id, object_id) must be rejected"
        );

        // 2. Duplicate (account_id, server_seq) with different object_id fails unique index
        let dup_seq = conn.execute(
            "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
             VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
            rusqlite::params![acc_id, obj_2],
        );
        assert!(
            dup_seq.is_err(),
            "duplicate (account_id, server_seq) must be rejected by unique index"
        );

        // 3. Different server_seq succeeds
        conn.execute(
            "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
             VALUES (?1, ?2, 1, 1, 2, 1, X'01', X'02')",
            rusqlite::params![acc_id, obj_2],
        )
        .unwrap();

        // 4. Verify index is used for sync sequence query
        let mut explain = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT object_id, revision, server_seq
                 FROM encrypted_objects
                 WHERE account_id = ?1 AND server_seq > ?2
                 ORDER BY server_seq ASC
                 LIMIT ?3",
            )
            .unwrap();

        let plan: String = explain
            .query_row(rusqlite::params![acc_id, 0, 10], |row| row.get(3))
            .unwrap();

        assert!(
            plan.contains(INDEX_ENCRYPTED_OBJECTS_ACCOUNT_SEQ),
            "query plan must utilize encrypted_objects_account_seq_idx for sync sequence reads, got: {plan}"
        );
    }

    #[test]
    fn test_object_history_uniqueness() {
        let conn = create_in_memory_db().unwrap();

        let acc_id = uuid::Uuid::new_v4().to_string();
        let obj_id = uuid::Uuid::new_v4().to_string();

        // Insert revision 1
        conn.execute(
            "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
             VALUES (?1, ?2, 1, 1, 1, X'01', X'02', FALSE)",
            rusqlite::params![acc_id, obj_id],
        )
        .unwrap();

        // Duplicate (account_id, object_id, revision) fails
        let dup_hist = conn.execute(
            "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
             VALUES (?1, ?2, 1, 2, 1, X'01', X'02', FALSE)",
            rusqlite::params![acc_id, obj_id],
        );
        assert!(
            dup_hist.is_err(),
            "duplicate (account_id, object_id, revision) must be rejected"
        );

        // Next revision 2 succeeds
        conn.execute(
            "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
             VALUES (?1, ?2, 2, 2, 1, X'01', X'02', FALSE)",
            rusqlite::params![acc_id, obj_id],
        )
        .unwrap();
    }

    #[test]
    fn test_processed_mutations_and_devices_uniqueness() {
        let conn = create_in_memory_db().unwrap();

        let acc_id = uuid::Uuid::new_v4().to_string();
        let mut_id = uuid::Uuid::new_v4().to_string();
        let obj_id = uuid::Uuid::new_v4().to_string();
        let dev_id = uuid::Uuid::new_v4().to_string();

        // 1. Processed mutation insert
        conn.execute(
            "INSERT INTO processed_mutations (account_id, mutation_id, object_id, resulting_revision, resulting_server_seq, response_body)
             VALUES (?1, ?2, ?3, 1, 1, '{}')",
            rusqlite::params![acc_id, mut_id, obj_id],
        )
        .unwrap();

        // Duplicate mutation for same account fails
        let dup_mut = conn.execute(
            "INSERT INTO processed_mutations (account_id, mutation_id, object_id, resulting_revision, resulting_server_seq, response_body)
             VALUES (?1, ?2, ?3, 1, 1, '{}')",
            rusqlite::params![acc_id, mut_id, obj_id],
        );
        assert!(dup_mut.is_err(), "duplicate mutation must be rejected");

        // 2. Device insert
        conn.execute(
            "INSERT INTO devices (account_id, device_id, display_name, last_ack_server_seq)
             VALUES (?1, ?2, 'Laptop', 0)",
            rusqlite::params![acc_id, dev_id],
        )
        .unwrap();

        // Duplicate device for same account fails
        let dup_dev = conn.execute(
            "INSERT INTO devices (account_id, device_id, display_name, last_ack_server_seq)
             VALUES (?1, ?2, 'Laptop Clone', 0)",
            rusqlite::params![acc_id, dev_id],
        );
        assert!(dup_dev.is_err(), "duplicate device must be rejected");
    }
}
