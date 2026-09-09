//! Integration tests for server sequence allocator (ZK-033).
//!
//! Validates acceptance criteria:
//! 1. Monotonic per account (starts at 1, increments strictly per account);
//! 2. Transactional (allocations within transactions commit or roll back cleanly);
//! 3. Concurrency test proves uniqueness and order (no gaps, no duplicates under concurrent access).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use tokio::task::JoinSet;
use uuid::Uuid;
use zk_server::db::store::ServerDb;

#[tokio::test]
async fn test_sequence_allocator_monotonic_single_account() {
    let db = ServerDb::new_in_memory().expect("init in-memory db");
    let account_id = Uuid::new_v4();

    // Account initially has current_sequence 0
    let initial_seq = db
        .current_sequence(account_id)
        .await
        .expect("query initial sequence");
    assert_eq!(initial_seq, 0, "unallocated account sequence must be 0");

    // Allocate 50 sequential numbers and assert exact monotonicity
    for expected in 1..=50 {
        let seq = db
            .allocate_next_sequence(account_id)
            .await
            .expect("allocate next sequence");
        assert_eq!(seq, expected, "sequence must increment strictly by 1");

        let current = db
            .current_sequence(account_id)
            .await
            .expect("query current sequence");
        assert_eq!(current, expected, "current sequence must track allocation");
    }
}

#[tokio::test]
async fn test_sequence_allocator_multi_account_isolation() {
    let db = ServerDb::new_in_memory().expect("init in-memory db");
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let account_c = Uuid::new_v4();

    // Interleave allocations between accounts A and B
    assert_eq!(db.allocate_next_sequence(account_a).await.unwrap(), 1);
    assert_eq!(db.allocate_next_sequence(account_b).await.unwrap(), 1);
    assert_eq!(db.allocate_next_sequence(account_a).await.unwrap(), 2);
    assert_eq!(db.allocate_next_sequence(account_b).await.unwrap(), 2);
    assert_eq!(db.allocate_next_sequence(account_b).await.unwrap(), 3);
    assert_eq!(db.allocate_next_sequence(account_b).await.unwrap(), 4);
    assert_eq!(db.allocate_next_sequence(account_a).await.unwrap(), 3);

    // Account A is at 3, Account B is at 4
    assert_eq!(db.current_sequence(account_a).await.unwrap(), 3);
    assert_eq!(db.current_sequence(account_b).await.unwrap(), 4);

    // Unallocated Account C remains at 0
    assert_eq!(db.current_sequence(account_c).await.unwrap(), 0);
}

#[tokio::test]
async fn test_sequence_allocator_transactional_rollback() {
    let db = ServerDb::new_in_memory().expect("init in-memory db");
    let account_id = Uuid::new_v4();

    // 1. Transaction 1 commits sequence 1
    {
        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().expect("begin tx 1");
        let seq = ServerDb::allocate_sequence_in_tx(&tx, account_id).expect("allocate seq in tx 1");
        assert_eq!(seq, 1);
        tx.commit().expect("commit tx 1");
    }
    assert_eq!(db.current_sequence(account_id).await.unwrap(), 1);

    // 2. Transaction 2 allocates sequence 2 but aborts (rolls back)
    {
        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().expect("begin tx 2");
        let seq = ServerDb::allocate_sequence_in_tx(&tx, account_id).expect("allocate seq in tx 2");
        assert_eq!(seq, 2);
        // Explicit rollback
        tx.rollback().expect("rollback tx 2");
    }

    // Sequence must roll back to 1 (not leave sequence gap 2)
    assert_eq!(
        db.current_sequence(account_id).await.unwrap(),
        1,
        "rolled back transaction must not increment current_sequence"
    );

    // 3. Transaction 3 allocates and gets sequence 2
    {
        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().expect("begin tx 3");
        let seq = ServerDb::allocate_sequence_in_tx(&tx, account_id).expect("allocate seq in tx 3");
        assert_eq!(
            seq, 2,
            "next transaction after rollback must re-use the uncommitted sequence number"
        );
        tx.commit().expect("commit tx 3");
    }
    assert_eq!(db.current_sequence(account_id).await.unwrap(), 2);

    // 4. Drop transaction without commit also rolls back
    {
        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().expect("begin tx 4");
        let seq = ServerDb::allocate_sequence_in_tx(&tx, account_id).expect("allocate seq in tx 4");
        assert_eq!(seq, 3);
        // dropping tx without commit triggers automatic rollback
        drop(tx);
    }
    assert_eq!(
        db.current_sequence(account_id).await.unwrap(),
        2,
        "dropped transaction must roll back uncommitted allocation"
    );

    // 5. Multiple allocations within the same transaction increment and commit together
    {
        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().expect("begin tx 5");
        let s1 = ServerDb::allocate_sequence_in_tx(&tx, account_id).unwrap();
        let s2 = ServerDb::allocate_sequence_in_tx(&tx, account_id).unwrap();
        let s3 = ServerDb::allocate_sequence_in_tx(&tx, account_id).unwrap();

        assert_eq!(s1, 3);
        assert_eq!(s2, 4);
        assert_eq!(s3, 5);
        assert_eq!(
            ServerDb::current_sequence_in_tx(&tx, account_id).unwrap(),
            5
        );

        tx.commit().expect("commit tx 5");
    }
    assert_eq!(db.current_sequence(account_id).await.unwrap(), 5);
}

#[tokio::test]
async fn test_sequence_allocator_concurrency_single_account() {
    let db = ServerDb::new_in_memory().expect("init in-memory db");
    let account_id = Uuid::new_v4();
    let num_tasks = 50;

    let mut join_set = JoinSet::new();

    for _ in 0..num_tasks {
        let db_clone = db.clone();
        join_set.spawn(async move { db_clone.allocate_next_sequence(account_id).await });
    }

    let mut allocated_sequences = Vec::with_capacity(num_tasks);
    while let Some(res) = join_set.join_next().await {
        let seq = res
            .expect("task join error")
            .expect("allocate_next_sequence failed");
        allocated_sequences.push(seq);
    }

    assert_eq!(
        allocated_sequences.len(),
        num_tasks,
        "every concurrent task must successfully receive a sequence"
    );

    // Verify all sequence numbers are unique
    let unique_set: HashSet<u64> = allocated_sequences.iter().copied().collect();
    assert_eq!(
        unique_set.len(),
        num_tasks,
        "concurrent allocations must produce strictly unique sequence numbers with no duplicates"
    );

    // Verify sequence numbers form a contiguous range from 1 to num_tasks
    let expected_set: HashSet<u64> = (1..=(num_tasks as u64)).collect();
    assert_eq!(
        unique_set, expected_set,
        "concurrent allocations must produce a contiguous sequence from 1 to {num_tasks} without gaps"
    );

    // Verify final current_sequence matches num_tasks
    let final_seq = db
        .current_sequence(account_id)
        .await
        .expect("query current sequence");
    assert_eq!(final_seq, num_tasks as u64);
}

#[tokio::test]
async fn test_sequence_allocator_concurrency_multi_account() {
    let db = ServerDb::new_in_memory().expect("init in-memory db");
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let account_c = Uuid::new_v4();
    let num_tasks_per_account = 30;

    let mut join_set = JoinSet::new();

    // Spawn concurrent tasks across accounts A, B, and C
    for _ in 0..num_tasks_per_account {
        let db_a = db.clone();
        join_set.spawn(async move { ("A", db_a.allocate_next_sequence(account_a).await) });

        let db_b = db.clone();
        join_set.spawn(async move { ("B", db_b.allocate_next_sequence(account_b).await) });

        let db_c = db.clone();
        join_set.spawn(async move { ("C", db_c.allocate_next_sequence(account_c).await) });
    }

    let mut seqs_a = Vec::new();
    let mut seqs_b = Vec::new();
    let mut seqs_c = Vec::new();

    while let Some(res) = join_set.join_next().await {
        let (tag, alloc_res) = res.expect("join task");
        let seq = alloc_res.expect("sequence allocation");
        match tag {
            "A" => seqs_a.push(seq),
            "B" => seqs_b.push(seq),
            "C" => seqs_c.push(seq),
            _ => unreachable!(),
        }
    }

    assert_eq!(seqs_a.len(), num_tasks_per_account);
    assert_eq!(seqs_b.len(), num_tasks_per_account);
    assert_eq!(seqs_c.len(), num_tasks_per_account);

    let expected_set: HashSet<u64> = (1..=(num_tasks_per_account as u64)).collect();

    let set_a: HashSet<u64> = seqs_a.into_iter().collect();
    let set_b: HashSet<u64> = seqs_b.into_iter().collect();
    let set_c: HashSet<u64> = seqs_c.into_iter().collect();

    assert_eq!(
        set_a, expected_set,
        "Account A sequence space must be 1..=30"
    );
    assert_eq!(
        set_b, expected_set,
        "Account B sequence space must be 1..=30"
    );
    assert_eq!(
        set_c, expected_set,
        "Account C sequence space must be 1..=30"
    );

    assert_eq!(
        db.current_sequence(account_a).await.unwrap(),
        num_tasks_per_account as u64
    );
    assert_eq!(
        db.current_sequence(account_b).await.unwrap(),
        num_tasks_per_account as u64
    );
    assert_eq!(
        db.current_sequence(account_c).await.unwrap(),
        num_tasks_per_account as u64
    );
}

#[tokio::test]
async fn test_sequence_allocator_backfill_from_existing_objects() {
    // Test that migration 003 backfills existing encrypted_objects server_seq
    let mut raw_conn = rusqlite::Connection::open_in_memory().unwrap();
    raw_conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

    // Run only migration 2 first
    raw_conn
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
        )
        .unwrap();
    raw_conn
        .execute_batch(zk_server::db::migrations::MIGRATION_002_SQL)
        .unwrap();

    let account_id = Uuid::new_v4();
    let acc_str = account_id.to_string();

    // Create account
    raw_conn
        .execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
            [&acc_str],
        )
        .unwrap();

    // Insert 3 objects with server_seq 1, 2, 5
    for (obj_id, seq) in [
        (Uuid::new_v4(), 1),
        (Uuid::new_v4(), 2),
        (Uuid::new_v4(), 5),
    ] {
        raw_conn.execute(
            "INSERT INTO encrypted_objects (account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload)
             VALUES (?1, ?2, 1, 1, ?3, 1, X'01', X'02')",
            rusqlite::params![acc_str, obj_id.to_string(), seq],
        ).unwrap();
    }

    // Now run migration 3
    zk_server::db::migrations::run_server_migrations(&mut raw_conn).unwrap();

    let db = ServerDb::from_connection(raw_conn);

    // Initial sequence after migration should be 5 (MAX(server_seq))
    let current = db.current_sequence(account_id).await.unwrap();
    assert_eq!(
        current, 5,
        "migration 3 must backfill current_seq from MAX(server_seq)"
    );

    // Next allocated sequence must be 6
    let next = db.allocate_next_sequence(account_id).await.unwrap();
    assert_eq!(
        next, 6,
        "next allocated sequence after backfill must be max + 1"
    );
}
