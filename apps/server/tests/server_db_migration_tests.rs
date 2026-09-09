//! Integration tests for server PostgreSQL schema and migrations (ZK-031).
//!
//! Validates acceptance criteria:
//! 1. Migrations reproducible and idempotent;
//! 2. Account and object uniqueness enforced;
//! 3. Indexes support sync sequence reads;
//! 4. Zero-knowledge schema invariants (no plaintext note fields).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use rusqlite::Connection;
use uuid::Uuid;
use zk_server::db::migrations::{create_in_memory_db, run_server_migrations};
use zk_server::db::schema::*;

#[test]
fn test_migrations_reproducible_clean_state_and_idempotent() {
    let mut conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable foreign keys");

    // Clean run applies migrations 2, 3, and 4
    let applied = run_server_migrations(&mut conn).expect("run migrations");
    assert_eq!(applied, vec![2, 3, 4]);

    // Verify all 8 tables and 4 indexes exist
    verify_database_schema(&conn).expect("schema verification");

    // Check schema_migrations rows
    let (v2, n2): (i32, String) = conn
        .query_row(
            "SELECT version, name FROM schema_migrations WHERE version = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query migration 2 row");
    assert_eq!(v2, 2);
    assert_eq!(n2, "002_initial_server_schema");

    let (v3, n3): (i32, String) = conn
        .query_row(
            "SELECT version, name FROM schema_migrations WHERE version = 3",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query migration 3 row");
    assert_eq!(v3, 3);
    assert_eq!(n3, "003_account_sequences");

    let (v4, n4): (i32, String) = conn
        .query_row(
            "SELECT version, name FROM schema_migrations WHERE version = 4",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query migration 4 row");
    assert_eq!(v4, 4);
    assert_eq!(n4, "004_mutation_idempotency");

    // Second run is idempotent
    let second_run = run_server_migrations(&mut conn).expect("second run");
    assert!(second_run.is_empty(), "must be idempotent");
}

#[test]
fn test_account_and_vault_uniqueness_and_foreign_keys() {
    let conn = create_in_memory_db().expect("init db");

    let acc_id_1 = Uuid::new_v4().to_string();
    let acc_id_2 = Uuid::new_v4().to_string();

    // 1. Account uniqueness
    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_id_1],
    )
    .expect("insert account 1");

    let dup_acc = conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_id_1],
    );
    assert!(dup_acc.is_err(), "duplicate account ID must fail PK check");

    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_id_2],
    )
    .expect("insert account 2");

    // 2. Vault uniqueness (1:1 with account)
    conn.execute(
        "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
         VALUES (?1, 1, 'Argon2id', '{\"m\":65536,\"t\":3,\"p\":4}', X'aabbcc', X'112233', X'445566')",
        [&acc_id_1],
    )
    .expect("insert vault for account 1");

    let dup_vault = conn.execute(
        "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
         VALUES (?1, 1, 'Argon2id', '{\"m\":65536,\"t\":3,\"p\":4}', X'aabbcc', X'112233', X'445566')",
        [&acc_id_1],
    );
    assert!(
        dup_vault.is_err(),
        "duplicate vault for same account must fail PK constraint"
    );

    // 3. Vault foreign key enforcement
    let non_existent_acc = Uuid::new_v4().to_string();
    let fk_fail = conn.execute(
        "INSERT INTO vaults (account_id, crypto_version, kdf_algorithm, kdf_params, kdf_salt, wrapped_vault_key, recovery_wrapped_vault_key)
         VALUES (?1, 1, 'Argon2id', '{\"m\":65536,\"t\":3,\"p\":4}', X'aabbcc', X'112233', X'445566')",
        [&non_existent_acc],
    );
    assert!(
        fk_fail.is_err(),
        "inserting vault for non-existent account must fail FK constraint"
    );
}

#[test]
fn test_encrypted_objects_account_object_uniqueness() {
    let conn = create_in_memory_db().expect("init db");

    let acc_1 = Uuid::new_v4().to_string();
    let acc_2 = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_1],
    )
    .expect("insert acc_1");
    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_2],
    )
    .expect("insert acc_2");

    let obj_1 = Uuid::new_v4().to_string();

    // Insert obj_1 for acc_1
    conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
        rusqlite::params![acc_1, obj_1],
    )
    .expect("insert obj_1 for acc_1");

    // Duplicate (acc_1, obj_1) must fail
    let dup = conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 2, 2, 1, X'01', X'02')",
        rusqlite::params![acc_1, obj_1],
    );
    assert!(
        dup.is_err(),
        "duplicate (account_id, object_id) must fail PRIMARY KEY"
    );

    // Same object_id for different account acc_2 succeeds (cross-account isolation)
    conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
        rusqlite::params![acc_2, obj_1],
    )
    .expect("same object_id for different account must succeed");
}

#[test]
fn test_encrypted_objects_sequence_uniqueness_and_indexed_sync_reads() {
    let conn = create_in_memory_db().expect("init db");

    let acc_1 = Uuid::new_v4().to_string();
    let acc_2 = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_1],
    )
    .expect("insert acc_1");
    conn.execute(
        "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
        [&acc_2],
    )
    .expect("insert acc_2");

    let obj_1 = Uuid::new_v4().to_string();
    let obj_2 = Uuid::new_v4().to_string();

    // Insert obj_1 with server_seq = 1 for acc_1
    conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
        rusqlite::params![acc_1, obj_1],
    )
    .expect("insert obj_1");

    // Duplicate server_seq = 1 for acc_1 fails unique index
    let dup_seq = conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
        rusqlite::params![acc_1, obj_2],
    );
    assert!(
        dup_seq.is_err(),
        "duplicate (account_id, server_seq) must fail unique index"
    );

    // Different server_seq = 2 for acc_1 succeeds
    conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 2, 1, X'01', X'02')",
        rusqlite::params![acc_1, obj_2],
    )
    .expect("insert obj_2 with server_seq = 2");

    // Same server_seq = 1 for different account acc_2 succeeds (sequence is per-account)
    let obj_3 = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
         VALUES (?1, ?2, 1, 1, 1, 1, X'01', X'02')",
        rusqlite::params![acc_2, obj_3],
    )
    .expect("server_seq = 1 for acc_2 must succeed");

    // Query plan test: sync pull query MUST use encrypted_objects_account_seq_idx
    let mut explain = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT object_id, revision, server_seq, payload
             FROM encrypted_objects
             WHERE account_id = ?1 AND server_seq > ?2
             ORDER BY server_seq ASC
             LIMIT ?3",
        )
        .expect("prepare explain");

    let plan: String = explain
        .query_row(rusqlite::params![acc_1, 0, 50], |row| row.get(3))
        .expect("execute explain");

    assert!(
        plan.contains(INDEX_ENCRYPTED_OBJECTS_ACCOUNT_SEQ),
        "query plan must use index {INDEX_ENCRYPTED_OBJECTS_ACCOUNT_SEQ}, got: {plan}"
    );
}

#[test]
fn test_object_history_revision_uniqueness() {
    let conn = create_in_memory_db().expect("init db");

    let acc_id = Uuid::new_v4().to_string();
    let obj_id = Uuid::new_v4().to_string();

    // Revision 1
    conn.execute(
        "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
         VALUES (?1, ?2, 1, 1, 1, X'01', X'02', FALSE)",
        rusqlite::params![acc_id, obj_id],
    )
    .expect("insert revision 1");

    // Duplicate revision 1 for same (acc, obj) fails
    let dup_rev = conn.execute(
        "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
         VALUES (?1, ?2, 1, 2, 1, X'01', X'02', FALSE)",
        rusqlite::params![acc_id, obj_id],
    );
    assert!(dup_rev.is_err(), "duplicate revision must fail PK");

    // Revision 2 succeeds
    conn.execute(
        "INSERT INTO object_history (account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted)
         VALUES (?1, ?2, 2, 2, 1, X'01', X'02', FALSE)",
        rusqlite::params![acc_id, obj_id],
    )
    .expect("insert revision 2");
}

#[test]
fn test_processed_mutations_and_devices_uniqueness() {
    let conn = create_in_memory_db().expect("init db");

    let acc_id = Uuid::new_v4().to_string();
    let mut_id = Uuid::new_v4().to_string();
    let obj_id = Uuid::new_v4().to_string();
    let dev_id = Uuid::new_v4().to_string();

    // 1. Processed mutation idempotency uniqueness
    conn.execute(
        "INSERT INTO processed_mutations (account_id, mutation_id, object_id, resulting_revision, resulting_server_seq, response_body)
         VALUES (?1, ?2, ?3, 1, 1, '{\"status\":\"ok\"}')",
        rusqlite::params![acc_id, mut_id, obj_id],
    )
    .expect("insert mutation");

    let dup_mut = conn.execute(
        "INSERT INTO processed_mutations (account_id, mutation_id, object_id, resulting_revision, resulting_server_seq, response_body)
         VALUES (?1, ?2, ?3, 1, 1, '{\"status\":\"ok\"}')",
        rusqlite::params![acc_id, mut_id, obj_id],
    );
    assert!(
        dup_mut.is_err(),
        "duplicate (account_id, mutation_id) must fail PK"
    );

    // 2. Devices uniqueness
    conn.execute(
        "INSERT INTO devices (account_id, device_id, display_name, last_ack_server_seq)
         VALUES (?1, ?2, 'Phone', 0)",
        rusqlite::params![acc_id, dev_id],
    )
    .expect("insert device");

    let dup_dev = conn.execute(
        "INSERT INTO devices (account_id, device_id, display_name, last_ack_server_seq)
         VALUES (?1, ?2, 'Phone Duplicate', 0)",
        rusqlite::params![acc_id, dev_id],
    );
    assert!(
        dup_dev.is_err(),
        "duplicate (account_id, device_id) must fail PK"
    );
}

#[test]
fn test_zero_knowledge_schema_invariants_sec_001_and_sec_002() {
    let conn = create_in_memory_db().expect("init db");

    // Inspect columns of encrypted_objects
    let mut stmt = conn
        .prepare("PRAGMA table_info(encrypted_objects)")
        .expect("table info");
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(1))
        .expect("query columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect columns");

    // Plaintext note fields MUST NOT exist in database schema (SEC-001/SEC-002)
    let forbidden = ["title", "body", "tags", "plaintext", "content", "note"];
    for col in &columns {
        let col_lower = col.to_ascii_lowercase();
        for f in forbidden {
            assert_ne!(
                col_lower, f,
                "Schema must not contain plaintext note field '{f}'"
            );
        }
    }

    // Must contain envelope components
    assert!(columns.contains(&"wrapped_key".to_string()));
    assert!(columns.contains(&"payload".to_string()));
    assert!(columns.contains(&"envelope_version".to_string()));
}
