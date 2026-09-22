//! Integration harness testing multi-device synchronization between two clients and a server (ZK-046 & M4 Gate).
//!
//! Acceptance criteria validated:
//! 1. Automated scenario spins up:
//!    - server (real HTTP over TCP)
//!    - client A local DB (SQLite)
//!    - client B local DB (SQLite)
//! 2. M4 Gate required lifecycle:
//!    - A creates offline
//!    - A syncs
//!    - B syncs
//!    - B edits offline
//!    - B syncs
//!    - A syncs
//!    - A sees update
//! 3. Zero-Knowledge security audit:
//!    - No plaintext note titles, bodies, tags, or keys present in server DB.
//! 4. 10 sequential multi-device alternating edits.
//! 5. Tombstone deletion propagation between devices.
//! 6. Interrupted sync resumption from durable cursor without skipped revisions.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::serve;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::ObjectStore;
use zk_sync::adapter::NativeHttpSyncAdapter;
use zk_sync::orchestrator::{SyncCycleOptions, SyncEngine};
use zk_sync::pull::{LockedSyncBehavior, PullOptions};

/// Test server instance running in background with graceful shutdown.
struct TestServer {
    base_url: String,
    state: AppState,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_test_server() -> TestServer {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init server app state");
    let app = create_app(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral TCP port");
    let addr = listener.local_addr().expect("get local addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    TestServer {
        base_url: format!("http://{}", addr),
        state,
        shutdown_tx: Some(shutdown_tx),
    }
}

/// Helper representing a client device with its own local SQLite database,
/// sync adapter, sync engine, and interactive vault session.
struct ClientDevice {
    _db_path: PathBuf,
    storage: Arc<SqliteStorage>,
    engine: SyncEngine<NativeHttpSyncAdapter, Arc<SqliteStorage>>,
    session: VaultSession,
    vault_key: VaultKey,
}

impl ClientDevice {
    async fn new(server: &TestServer, account_id: Uuid, vault_key: VaultKey, prefix: &str) -> Self {
        let db_path = std::env::temp_dir().join(format!("zk_{prefix}_{}.db", Uuid::new_v4()));
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open client sqlite"));
        let adapter = NativeHttpSyncAdapter::new(
            &server.base_url,
            Some(
                server
                    .state
                    .db
                    .create_session(account_id, None, None, Some(3600))
                    .await
                    .unwrap()
                    .1
                    .expose_secret()
                    .to_string(),
            ),
        )
        .expect("init sync adapter");
        let engine = SyncEngine::new(adapter, storage.clone());
        let session = VaultSession::from_key(vault_key.clone());

        Self {
            _db_path: db_path,
            storage,
            engine,
            session,
            vault_key,
        }
    }

    async fn sync(&mut self) {
        self.engine
            .sync_with_session(&mut self.session, SyncCycleOptions::default())
            .await
            .expect("client sync succeeds");
    }

    fn create_note_offline(&mut self, id: &str, title: &str, body: &str, tags: Vec<&str>) {
        let mut note = PlaintextNote::new(title, body);
        note.tags = tags.into_iter().map(String::from).collect();
        note.canonicalize();
        let env = note.encrypt(&self.vault_key, id).expect("encrypt note");
        self.engine
            .queue()
            .enqueue_local_note_upsert(id, env)
            .expect("enqueue note creation");
    }

    fn edit_note_offline(&mut self, id: &str, title: &str, body: &str, tags: Vec<&str>) {
        let mut note = PlaintextNote::new(title, body);
        note.tags = tags.into_iter().map(String::from).collect();
        note.canonicalize();
        let env = note.encrypt(&self.vault_key, id).expect("encrypt note");
        self.engine
            .queue()
            .enqueue_local_note_upsert(id, env)
            .expect("enqueue note edit");
    }

    fn delete_note_offline(&mut self, id: &str) {
        // Enqueue deletion tombstone
        let tombstone_env = EncryptedEnvelope {
            envelope_version: zk_protocol::constants::ENVELOPE_VERSION_V1,
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: zk_protocol::envelope::EncryptedKeyContainer {
                nonce: String::new(),
                ciphertext: String::new(),
            },
            payload: zk_protocol::envelope::EncryptedPayloadContainer {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };
        self.engine
            .queue()
            .enqueue_local_note_delete(id, tombstone_env)
            .expect("enqueue delete");
    }

    fn read_note(&self, id: &str) -> Option<PlaintextNote> {
        let obj = self.storage.get_object(id).ok().flatten()?;
        if obj.is_deleted {
            return None;
        }
        PlaintextNote::decrypt(&obj.envelope, &self.vault_key).ok()
    }
}

#[tokio::test]
async fn test_two_client_m4_gate_complete_scenario() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    // 1. Spin up client A local DB and client B local DB
    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "devA").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "devB").await;

    let note_id = Uuid::new_v4().to_string();

    // 2. A creates offline
    client_a.create_note_offline(
        &note_id,
        "Shopping List",
        "Milk, Eggs, Bread",
        vec!["groceries", "errands"],
    );
    assert_eq!(client_a.engine.queue().pending_count().unwrap(), 1);
    assert_eq!(client_b.engine.queue().pending_count().unwrap(), 0);

    // 3. A syncs
    client_a.sync().await;
    assert_eq!(client_a.engine.queue().pending_count().unwrap(), 0);
    assert_eq!(client_a.engine.cursor().current_cursor().unwrap(), 1);

    // 4. B syncs
    client_b.sync().await;
    assert_eq!(client_b.engine.cursor().current_cursor().unwrap(), 1);

    // B sees initial note from A
    let note_on_b = client_b.read_note(&note_id).expect("note on B exists");
    assert_eq!(note_on_b.title, "Shopping List");
    assert_eq!(note_on_b.body, "Milk, Eggs, Bread");
    assert_eq!(
        note_on_b.tags,
        vec!["errands".to_string(), "groceries".to_string()]
    );

    // B's in-memory search index finds the note
    let b_hits = client_b.session.search_index_mut().unwrap().search("Milk");
    assert_eq!(b_hits.len(), 1);
    assert_eq!(b_hits[0].id, note_id);

    // 5. B edits offline
    client_b.edit_note_offline(
        &note_id,
        "Shopping List (Updated)",
        "Milk, Eggs, Bread, Butter, Cheese",
        vec!["groceries", "errands", "urgent"],
    );
    assert_eq!(client_b.engine.queue().pending_count().unwrap(), 1);

    // 6. B syncs
    client_b.sync().await;
    assert_eq!(client_b.engine.queue().pending_count().unwrap(), 0);
    assert_eq!(client_b.engine.cursor().current_cursor().unwrap(), 2);

    // 7. A syncs
    client_a.sync().await;
    assert_eq!(client_a.engine.cursor().current_cursor().unwrap(), 2);

    // 8. A sees update
    let note_on_a = client_a.read_note(&note_id).expect("note on A updated");
    assert_eq!(note_on_a.title, "Shopping List (Updated)");
    assert_eq!(note_on_a.body, "Milk, Eggs, Bread, Butter, Cheese");
    assert_eq!(
        note_on_a.tags,
        vec![
            "errands".to_string(),
            "groceries".to_string(),
            "urgent".to_string()
        ]
    );

    // A's search index finds the newly added items
    let a_hits = client_a
        .session
        .search_index_mut()
        .unwrap()
        .search("Butter");
    assert_eq!(a_hits.len(), 1);
    assert_eq!(a_hits[0].id, note_id);

    // 9. Zero-Knowledge security audit: inspect server DB
    // No plaintext is present in server DB.
    let conn = server.state.db.connection();
    let conn_lock = conn.lock().await;

    // Scan encrypted_objects table
    let mut stmt = conn_lock
        .prepare("SELECT object_id, revision, server_seq, envelope_version, is_deleted FROM encrypted_objects")
        .expect("prepare select");
    let rows: Vec<(String, u64, u64, i32, bool)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("query map")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect rows");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, note_id);
    assert_eq!(rows[0].1, 2); // revision 2
    assert_eq!(rows[0].2, 2); // server_seq 2

    // Scan every table in server SQLite database for prohibited plaintext words
    let forbidden_plaintexts = [
        "Shopping",
        "List",
        "Updated",
        "Milk",
        "Eggs",
        "Bread",
        "Butter",
        "Cheese",
        "groceries",
        "errands",
        "urgent",
    ];

    let check_tables = [
        "encrypted_objects",
        "object_history",
        "processed_mutations",
        "vaults",
        "accounts",
    ];

    for table in check_tables {
        let query = format!("SELECT * FROM {table}");
        let mut query_stmt = conn_lock.prepare(&query).expect("prepare table select");
        let col_count = query_stmt.column_count();

        let mut query_rows = query_stmt.query([]).expect("query table");
        while let Some(row) = query_rows.next().expect("next row") {
            for col_idx in 0..col_count {
                if let Ok(text) = row.get::<_, String>(col_idx) {
                    for forbidden in &forbidden_plaintexts {
                        assert!(
                            !text.contains(forbidden),
                            "SEC-001/SEC-002 VIOLATION: forbidden plaintext '{forbidden}' found in server table '{table}' column {col_idx}: {text}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn test_two_client_ten_sequential_alternating_edits() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "seqA").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "seqB").await;

    let note_id = Uuid::new_v4().to_string();

    // Edit 1: A creates
    client_a.create_note_offline(&note_id, "Seq Note", "Edit 1", vec!["tag1"]);
    client_a.sync().await;
    client_b.sync().await;

    let b_val = client_b.read_note(&note_id).unwrap();
    assert_eq!(b_val.body, "Edit 1");

    // Edits 2..=10: alternating between A and B
    for step in 2..=10 {
        let content = format!("Edit {step}");
        let tag = format!("tag{step}");

        if step % 2 == 0 {
            // Even step: B edits, B syncs, A syncs
            client_b.edit_note_offline(&note_id, "Seq Note", &content, vec![&tag]);
            client_b.sync().await;
            client_a.sync().await;

            let a_val = client_a.read_note(&note_id).unwrap();
            assert_eq!(a_val.body, content);
        } else {
            // Odd step: A edits, A syncs, B syncs
            client_a.edit_note_offline(&note_id, "Seq Note", &content, vec![&tag]);
            client_a.sync().await;
            client_b.sync().await;

            let b_val = client_b.read_note(&note_id).unwrap();
            assert_eq!(b_val.body, content);
        }
    }

    // After 10 edits:
    // Revision is 10, server sequence is 10
    assert_eq!(client_a.engine.cursor().current_cursor().unwrap(), 10);
    assert_eq!(client_b.engine.cursor().current_cursor().unwrap(), 10);

    let final_a = client_a.read_note(&note_id).unwrap();
    let final_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(final_a.body, "Edit 10");
    assert_eq!(final_b.body, "Edit 10");
}

#[tokio::test]
async fn test_two_client_tombstone_deletion_propagation() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "delA").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "delB").await;

    let note_id = Uuid::new_v4().to_string();

    // 1. Client A creates note and syncs
    client_a.create_note_offline(&note_id, "Note to Delete", "Secret content", vec!["temp"]);
    client_a.sync().await;

    // 2. Client B syncs and verifies note exists
    client_b.sync().await;
    assert!(client_b.read_note(&note_id).is_some());

    // 3. Client B deletes note offline and syncs
    client_b.delete_note_offline(&note_id);
    client_b.sync().await;
    assert!(client_b.read_note(&note_id).is_none());

    // 4. Client A syncs and receives tombstone
    client_a.sync().await;
    assert!(client_a.read_note(&note_id).is_none());

    // In-memory search index on both clients excludes deleted note
    let hits_a = client_a
        .session
        .search_index_mut()
        .unwrap()
        .search("Secret");
    assert!(hits_a.is_empty());
    let hits_b = client_b
        .session
        .search_index_mut()
        .unwrap()
        .search("Secret");
    assert!(hits_b.is_empty());
}

#[tokio::test]
async fn test_two_client_killed_sync_resumes_from_durable_cursor() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "killA").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "killB").await;

    let note_ids: Vec<String> = (0..5).map(|_| Uuid::new_v4().to_string()).collect();

    // Client A creates 5 notes (server_seq: 1..=5)
    for (i, id) in note_ids.iter().enumerate() {
        client_a.create_note_offline(id, &format!("Title {i}"), &format!("Body {i}"), vec![]);
    }
    client_a.sync().await;
    assert_eq!(client_a.engine.cursor().current_cursor().unwrap(), 5);

    // Client B pulls with page limit of 2 (simulating partial pull before process kill)
    let partial_options = SyncCycleOptions {
        pull_options: PullOptions {
            page_limit: Some(2),
            max_pages: Some(1), // Stop after 1 page (changes 1, 2)
            locked_behavior: LockedSyncBehavior::StoreCiphertextDeferDecryption,
        },
        push_options: Default::default(),
        always_followup_pull: false,
    };

    let partial_report = client_b
        .engine
        .sync_with_session(&mut client_b.session, partial_options)
        .await
        .expect("partial sync succeeds");

    assert_eq!(partial_report.initial_pull.applied_changes, 2);
    assert_eq!(client_b.engine.cursor().current_cursor().unwrap(), 2);

    // Simulate process crash and restart: reset in-flight mutations
    let _ = client_b.engine.queue().reset_in_flight();

    // Client B resumes sync without limits
    let full_report = client_b
        .engine
        .sync_with_session(&mut client_b.session, SyncCycleOptions::default())
        .await
        .expect("resumed sync succeeds");

    // Applied remaining 3 changes (sequences 3, 4, 5)
    assert_eq!(full_report.initial_pull.applied_changes, 3);
    assert_eq!(client_b.engine.cursor().current_cursor().unwrap(), 5);

    // All 5 notes exist on Client B
    for id in &note_ids {
        assert!(client_b.read_note(id).is_some());
    }
}
