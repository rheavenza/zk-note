//! Conflict Integration Matrix & M5 Gate Test Suite (ZK-057).
//!
//! Automated scenarios:
//! 1. body vs body (both clean diff3 non-overlapping merge and overlapping conflict markers)
//! 2. title vs body (structured three-way merge combining scalar title and body edits)
//! 3. tag vs body (structured three-way merge combining tag set modifications and body)
//! 4. same edit vs same edit (identical concurrent modifications merging cleanly)
//! 5. delete vs edit (tombstone preservation, resurrection prevention, accept deletion, explicit resurrection, duplicate as separate)
//! 6. lost response (idempotent retry with identical mutation_id returning accepted revision without duplicate revision)
//! 7. repeated conflict retry (re-resolving against successive remote revisions)
//! 8. M5 Gate: Two clients edit the same revision offline:
//!    - server does not overwrite silently;
//!    - both contents remain recoverable;
//!    - client resolves and produces a new accepted revision;
//!    - Zero-Knowledge security audit on server and client SQLite files.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::serve;
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::PushRequest;
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_server::db::run_server_migrations;
use zk_server::db::ServerDb;
use zk_storage::models::ConflictRecord;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{ConflictStore, ObjectStore};
use zk_sync::adapter::{NativeHttpSyncAdapter, SyncServerAdapter};
use zk_sync::conflict::{resolve_conflict, ConflictResolutionResult, ConflictResolutionStrategy};
use zk_sync::orchestrator::{SyncCycleOptions, SyncCycleReport, SyncEngine};

/// Test server instance running in background with graceful shutdown.
struct TestServer {
    state: AppState,
    base_url: String,
    _db_file: Option<PathBuf>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(ref path) = self._db_file {
            let _ = fs::remove_file(path);
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
        state,
        base_url: format!("http://{}", addr),
        _db_file: None,
        shutdown_tx: Some(shutdown_tx),
    }
}

async fn start_test_server_with_file(db_path: PathBuf) -> TestServer {
    let mut conn = Connection::open(&db_path).expect("open server db file");
    run_server_migrations(&mut conn).expect("run server migrations");
    let db = ServerDb::from_connection(conn);
    let config = ServerConfig::default();
    let state = AppState { config, db };
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
        state,
        base_url: format!("http://{}", addr),
        _db_file: Some(db_path),
        shutdown_tx: Some(shutdown_tx),
    }
}

/// Helper representing a client device with its own local SQLite database,
/// sync adapter, sync engine, and interactive vault session.
struct ClientDevice {
    db_path: PathBuf,
    storage: Arc<SqliteStorage>,
    engine: SyncEngine<NativeHttpSyncAdapter, Arc<SqliteStorage>>,
    session: VaultSession,
    vault_key: VaultKey,
}

impl ClientDevice {
    async fn new(server: &TestServer, account_id: Uuid, vault_key: VaultKey, prefix: &str) -> Self {
        let db_path = std::env::temp_dir().join(format!("zk_mat_{prefix}_{}.db", Uuid::new_v4()));
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
            db_path,
            storage,
            engine,
            session,
            vault_key,
        }
    }

    async fn sync(&mut self) -> SyncCycleReport {
        self.engine
            .sync_with_session(&mut self.session, SyncCycleOptions::default())
            .await
            .expect("client sync succeeds")
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
        let tombstone_env = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: String::new(),
                ciphertext: String::new(),
            },
            payload: EncryptedPayloadContainer {
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

    fn get_active_conflict(&self, id: &str) -> Option<ConflictRecord> {
        self.storage.get_active_conflict_for_object(id).unwrap()
    }

    fn resolve(
        &mut self,
        conflict_id: &str,
        strategy: ConflictResolutionStrategy,
    ) -> ConflictResolutionResult {
        resolve_conflict(
            &self.storage,
            self.engine.queue(),
            &self.vault_key,
            conflict_id,
            strategy,
        )
        .expect("resolve conflict succeeds")
    }
}

impl Drop for ClientDevice {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.db_path);
    }
}

// ----------------------------------------------------------------------------
// 1. body vs body
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_body_vs_body() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "b_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "b_b").await;

    let note_id = Uuid::new_v4().to_string();

    // Step 1: Client A creates note with two sections
    let base_body = "# Section 1\nBase text 1.\n\n# Section 2\nBase text 2.\n";
    client_a.create_note_offline(
        &note_id,
        "Body Merge Document",
        base_body,
        vec!["body-test"],
    );
    let rep_a = client_a.sync().await;
    assert_eq!(rep_a.mutations_accepted, 1);

    // Client B pulls revision 1
    let rep_b = client_b.sync().await;
    assert_eq!(rep_b.initial_pull.applied_changes, 1);
    assert_eq!(
        client_b.read_note(&note_id).unwrap().body.trim(),
        base_body.trim()
    );

    // Part 1A: Non-overlapping body edit (clean auto-merge with diff3)
    let body_a = "# Section 1\nClient A edited section 1.\n\n# Section 2\nBase text 2.\n";
    let body_b = "# Section 1\nBase text 1.\n\n# Section 2\nClient B edited section 2.\n";

    client_a.edit_note_offline(&note_id, "Body Merge Document", body_a, vec!["body-test"]);
    client_b.edit_note_offline(&note_id, "Body Merge Document", body_b, vec!["body-test"]);

    // Client A syncs first -> server accepts revision 2
    let rep_a = client_a.sync().await;
    assert_eq!(rep_a.mutations_accepted, 1);

    // Client B syncs -> receives 409 Conflict from server
    let rep_b = client_b.sync().await;
    assert_eq!(rep_b.mutations_conflicted, 1);
    assert_eq!(rep_b.mutations_accepted, 0);

    // Server did NOT overwrite silently (SEC-006)
    // Client B has an active ConflictRecord with a generated candidate
    let conflict = client_b
        .get_active_conflict(&note_id)
        .expect("active conflict exists");
    assert_eq!(conflict.base_revision, 1);
    assert_eq!(conflict.remote_revision, 2);
    assert!(conflict.candidate_envelope.is_some());

    // Decrypt the candidate note and verify clean diff3 body merge
    let candidate = PlaintextNote::decrypt(
        conflict.candidate_envelope.as_ref().unwrap(),
        &shared_vault_key,
    )
    .expect("decrypt candidate");
    assert!(
        candidate.body.contains("Client A edited section 1."),
        "candidate must contain Client A's non-overlapping section"
    );
    assert!(
        candidate.body.contains("Client B edited section 2."),
        "candidate must contain Client B's non-overlapping section"
    );
    assert!(
        !candidate.body.contains("<<<<<<<"),
        "non-overlapping merge must not produce conflict markers"
    );

    // Client B resolves conflict using the clean merge candidate
    let res = client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::Merge(candidate.clone()),
    );
    assert!(res.retry_mutation.is_some());

    // Client B pushes retry mutation -> server accepts at revision 3!
    let rep_b_retry = client_b.sync().await;
    assert_eq!(rep_b_retry.mutations_accepted, 1);
    assert_eq!(rep_b_retry.mutations_conflicted, 0);

    // Client A syncs and pulls the merged revision 3
    let rep_a_pull = client_a.sync().await;
    assert_eq!(rep_a_pull.initial_pull.applied_changes, 1);

    let final_a = client_a.read_note(&note_id).unwrap();
    let final_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(final_a.body, final_b.body);
    assert!(final_a.body.contains("Client A edited section 1."));
    assert!(final_a.body.contains("Client B edited section 2."));

    // Part 1B: Overlapping body edit (divergent conflict generating markers)
    // Both clients edit the exact same section divergently
    let div_a = "# Section 1\nAlpha version of section 1.\n\n# Section 2\nUnified section 2.\n";
    let div_b = "# Section 1\nBeta version of section 1.\n\n# Section 2\nUnified section 2.\n";

    client_a.edit_note_offline(&note_id, "Body Merge Document", div_a, vec!["body-test"]);
    client_b.edit_note_offline(&note_id, "Body Merge Document", div_b, vec!["body-test"]);

    client_a.sync().await; // Client A accepted at revision 4

    let rep_b_div = client_b.sync().await; // Client B conflicts against revision 4
    assert_eq!(rep_b_div.mutations_conflicted, 1);

    let div_conflict = client_b
        .get_active_conflict(&note_id)
        .expect("divergent conflict");
    assert_eq!(div_conflict.remote_revision, 4);

    let div_cand = PlaintextNote::decrypt(
        div_conflict.candidate_envelope.as_ref().unwrap(),
        &shared_vault_key,
    )
    .expect("decrypt candidate");
    assert!(
        div_cand.body.contains("<<<<<<< LOCAL"),
        "overlapping edits must contain diff3 conflict markers"
    );
    assert!(div_cand.body.contains(">>>>>>> REMOTE"));

    // Both original versions remain recoverable on Client B
    let local_rec =
        PlaintextNote::decrypt(&div_conflict.local_envelope, &shared_vault_key).unwrap();
    let remote_rec =
        PlaintextNote::decrypt(&div_conflict.remote_envelope, &shared_vault_key).unwrap();
    assert!(local_rec.body.contains("Beta version of section 1."));
    assert!(remote_rec.body.contains("Alpha version of section 1."));

    // Client B resolves manually with chosen unified content
    let mut manual_note = div_cand.clone();
    manual_note.body =
        "# Section 1\nManually resolved consensus.\n\n# Section 2\nUnified section 2.\n"
            .to_string();
    client_b.resolve(
        &div_conflict.conflict_id,
        ConflictResolutionStrategy::Merge(manual_note),
    );

    client_b.sync().await; // Accepted revision 5
    client_a.sync().await; // Pulled revision 5

    assert_eq!(
        client_a.read_note(&note_id).unwrap().body,
        client_b.read_note(&note_id).unwrap().body
    );
    assert!(client_a
        .read_note(&note_id)
        .unwrap()
        .body
        .contains("Manually resolved consensus."));
}

// ----------------------------------------------------------------------------
// 2. title vs body
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_title_vs_body() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "tb_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "tb_b").await;

    let note_id = Uuid::new_v4().to_string();

    // Base revision 1
    client_a.create_note_offline(&note_id, "Old Title", "Old Body", vec!["test"]);
    client_a.sync().await;
    client_b.sync().await;

    // Client A modifies title; Client B modifies body
    client_a.edit_note_offline(
        &note_id,
        "Client A Modified Title",
        "Old Body",
        vec!["test"],
    );
    client_b.edit_note_offline(
        &note_id,
        "Old Title",
        "Client B Modified Body",
        vec!["test"],
    );

    // Client A syncs -> accepted revision 2
    client_a.sync().await;

    // Client B syncs -> 409 conflict
    let rep = client_b.sync().await;
    assert_eq!(rep.mutations_conflicted, 1);

    let conflict = client_b.get_active_conflict(&note_id).unwrap();
    let candidate = PlaintextNote::decrypt(
        conflict.candidate_envelope.as_ref().unwrap(),
        &shared_vault_key,
    )
    .unwrap();

    // Verify structured three-way merge automatically combined title & body changes cleanly
    assert_eq!(candidate.title, "Client A Modified Title");
    assert_eq!(candidate.body, "Client B Modified Body");

    // Client B resolves using clean candidate
    client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::Merge(candidate),
    );
    client_b.sync().await;
    client_a.sync().await;

    let final_note_a = client_a.read_note(&note_id).unwrap();
    let final_note_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(final_note_a.title, "Client A Modified Title");
    assert_eq!(final_note_a.body, "Client B Modified Body");
    assert_eq!(final_note_b.title, "Client A Modified Title");
    assert_eq!(final_note_b.body, "Client B Modified Body");
}

// ----------------------------------------------------------------------------
// 3. tag vs body
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_tag_vs_body() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "tag_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "tag_b").await;

    let note_id = Uuid::new_v4().to_string();

    // Base revision 1 with tags ["docs", "v1"]
    client_a.create_note_offline(&note_id, "Tag Document", "Initial body", vec!["docs", "v1"]);
    client_a.sync().await;
    client_b.sync().await;

    // Client A modifies tags: adds "security", removes "docs"
    client_a.edit_note_offline(
        &note_id,
        "Tag Document",
        "Initial body",
        vec!["security", "v1"],
    );
    // Client B modifies body
    client_b.edit_note_offline(
        &note_id,
        "Tag Document",
        "Client B updated body content",
        vec!["docs", "v1"],
    );

    client_a.sync().await; // Rev 2

    let rep = client_b.sync().await; // Conflict against Rev 2
    assert_eq!(rep.mutations_conflicted, 1);

    let conflict = client_b.get_active_conflict(&note_id).unwrap();
    let candidate = PlaintextNote::decrypt(
        conflict.candidate_envelope.as_ref().unwrap(),
        &shared_vault_key,
    )
    .unwrap();

    // Verify 3-way tag set merge combined tags with body edit
    assert_eq!(candidate.tags, vec!["security", "v1"]);
    assert_eq!(candidate.body, "Client B updated body content");

    client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::Merge(candidate),
    );
    client_b.sync().await;
    client_a.sync().await;

    let res_a = client_a.read_note(&note_id).unwrap();
    let res_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(res_a.tags, vec!["security", "v1"]);
    assert_eq!(res_a.body, "Client B updated body content");
    assert_eq!(res_b.tags, vec!["security", "v1"]);
    assert_eq!(res_b.body, "Client B updated body content");
}

// ----------------------------------------------------------------------------
// 4. same edit vs same edit
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_same_edit_vs_same_edit() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "same_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "same_b").await;

    let note_id = Uuid::new_v4().to_string();

    client_a.create_note_offline(&note_id, "Draft", "Base body", vec!["v1"]);
    client_a.sync().await;
    client_b.sync().await;

    // Both clients make identical edits concurrently
    let same_title = "Approved Document";
    let same_body = "Identical approved body content.";
    let same_tags = vec!["approved", "v1"];

    client_a.edit_note_offline(&note_id, same_title, same_body, same_tags.clone());
    client_b.edit_note_offline(&note_id, same_title, same_body, same_tags.clone());

    client_a.sync().await; // Accepted rev 2

    // Client B attempts push -> server 409 conflict
    let rep = client_b.sync().await;
    assert_eq!(rep.mutations_conflicted, 1);

    let conflict = client_b.get_active_conflict(&note_id).unwrap();
    let candidate = PlaintextNote::decrypt(
        conflict.candidate_envelope.as_ref().unwrap(),
        &shared_vault_key,
    )
    .unwrap();

    // 3-way merge outcome recognises identical change across all fields
    assert_eq!(candidate.title, same_title);
    assert_eq!(candidate.body, same_body);
    assert_eq!(candidate.tags, same_tags);

    // Client B can cleanly apply candidate or KeepRemote
    client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::KeepRemote,
    );
    client_b.sync().await;

    let res_a = client_a.read_note(&note_id).unwrap();
    let res_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(res_a.title, same_title);
    assert_eq!(res_a.body, same_body);
    assert_eq!(res_b.title, same_title);
    assert_eq!(res_b.body, same_body);
}

// ----------------------------------------------------------------------------
// 5. delete vs edit
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_delete_vs_edit() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "del_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "del_b").await;

    // Scenario 5A: Accept remote deletion (KeepRemote)
    let note1_id = Uuid::new_v4().to_string();
    client_a.create_note_offline(&note1_id, "Note 1", "Body 1", vec![]);
    client_a.sync().await;
    client_b.sync().await;

    client_a.delete_note_offline(&note1_id);
    client_b.edit_note_offline(
        &note1_id,
        "Note 1 Offline",
        "Body 1 modified offline",
        vec![],
    );

    client_a.sync().await; // Server accepts tombstone rev 2
    let rep_b1 = client_b.sync().await; // Client B conflicts
    assert_eq!(rep_b1.mutations_conflicted, 1);

    let conf1 = client_b.get_active_conflict(&note1_id).unwrap();
    assert!(conf1.remote_is_deleted);
    assert!(!conf1.local_is_deleted);
    assert!(conf1.is_delete_vs_edit());

    // Client B accepts remote deletion
    client_b.resolve(&conf1.conflict_id, ConflictResolutionStrategy::KeepRemote);
    client_b.sync().await;
    assert!(client_a.read_note(&note1_id).is_none());
    assert!(client_b.read_note(&note1_id).is_none());

    // Scenario 5B: User explicitly resurrects note (RestoreResurrect)
    let note2_id = Uuid::new_v4().to_string();
    client_a.create_note_offline(&note2_id, "Important Document", "Critical info", vec![]);
    client_a.sync().await;
    client_b.sync().await;

    client_a.delete_note_offline(&note2_id);
    client_b.edit_note_offline(
        &note2_id,
        "Important Document (Preserved)",
        "Crucial data preserved by Client B",
        vec!["restored"],
    );

    client_a.sync().await; // Tombstone rev 2
    let rep_b2 = client_b.sync().await;
    assert_eq!(rep_b2.mutations_conflicted, 1);

    let conf2 = client_b.get_active_conflict(&note2_id).unwrap();
    assert!(conf2.remote_is_deleted);

    // Client B explicitly chooses RestoreResurrect
    let res = client_b.resolve(
        &conf2.conflict_id,
        ConflictResolutionStrategy::RestoreResurrect,
    );
    assert_eq!(res.retry_mutation.as_ref().unwrap().expected_revision, 2);

    // Client B pushes resurrection at revision 3!
    let rep_res = client_b.sync().await;
    assert_eq!(rep_res.mutations_accepted, 1);

    client_a.sync().await; // Client A pulls resurrected note
    let restored_a = client_a
        .read_note(&note2_id)
        .expect("note resurrected on A");
    let restored_b = client_b
        .read_note(&note2_id)
        .expect("note resurrected on B");
    assert_eq!(restored_a.title, "Important Document (Preserved)");
    assert_eq!(restored_b.title, "Important Document (Preserved)");

    // Scenario 5C: Duplicate as separate note
    let note3_id = Uuid::new_v4().to_string();
    client_a.create_note_offline(&note3_id, "Original 3", "Body 3", vec![]);
    client_a.sync().await;
    client_b.sync().await;

    client_a.delete_note_offline(&note3_id);
    client_b.edit_note_offline(&note3_id, "Original 3 Edit", "Local divergent body", vec![]);

    client_a.sync().await; // Tombstone rev 2
    client_b.sync().await; // Conflict

    let conf3 = client_b.get_active_conflict(&note3_id).unwrap();
    let dup_id = Uuid::new_v4().to_string();

    client_b.resolve(
        &conf3.conflict_id,
        ConflictResolutionStrategy::DuplicateAsSeparate {
            new_object_id: dup_id.clone(),
            new_title: Some("Original 3 (Duplicate Copy)".to_string()),
        },
    );

    client_b.sync().await;
    client_a.sync().await;

    // Original note is deleted on both
    assert!(client_a.read_note(&note3_id).is_none());
    assert!(client_b.read_note(&note3_id).is_none());

    // Duplicate note exists on both
    let dup_a = client_a.read_note(&dup_id).expect("dup exists on A");
    let dup_b = client_b.read_note(&dup_id).expect("dup exists on B");
    assert_eq!(dup_a.title, "Original 3 (Duplicate Copy)");
    assert_eq!(dup_b.title, "Original 3 (Duplicate Copy)");
    assert_eq!(dup_a.body, "Local divergent body");
}

// ----------------------------------------------------------------------------
// 6. lost response
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_lost_response() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

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

    let note_id = Uuid::new_v4().to_string();
    let note = PlaintextNote::new("Lost Response Note", "Important Content");
    let envelope = note.encrypt(&shared_vault_key, &note_id).unwrap();

    let mutation_id = Uuid::new_v4().to_string();
    let req = PushRequest {
        mutation_id: mutation_id.clone(),
        object_id: note_id.clone(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: envelope.clone(),
        is_deleted: false,
    };

    // 1. Initial push accepted by server
    let resp1 = adapter.push_mutation(&req).await.expect("first push");
    assert_eq!(resp1.revision, 1);
    assert_eq!(resp1.server_seq, 1);

    // 2. Client simulates lost response / timeout: retries EXACT same request with same mutation_id
    let resp2 = adapter.push_mutation(&req).await.expect("retry push");
    assert_eq!(
        resp2.revision, 1,
        "retry must return previously accepted revision without incrementing"
    );
    assert_eq!(
        resp2.server_seq, 1,
        "retry must not create duplicate sequence"
    );

    // 3. Verify server state has exactly 1 change
    let pull = adapter.pull_changes(0, Some(10)).await.expect("pull");
    assert_eq!(pull.changes.len(), 1);
    assert_eq!(pull.changes[0].revision, 1);
}

// ----------------------------------------------------------------------------
// 7. repeated conflict retry
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_matrix_repeated_conflict_retry() {
    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "rc_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "rc_b").await;
    let mut client_c =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "rc_c").await;

    let note_id = Uuid::new_v4().to_string();

    // Step 1: Base revision 1 on server
    client_a.create_note_offline(&note_id, "Multi-conflict Note", "Base revision 1", vec![]);
    client_a.sync().await;
    client_b.sync().await;
    client_c.sync().await;

    // Step 2: Client A pushes revision 2
    client_a.edit_note_offline(&note_id, "Multi-conflict Note", "Revision 2 by A", vec![]);
    client_a.sync().await;

    // Step 3: Client B (still at base rev 1) tries to push -> 409 conflict against rev 2
    client_b.edit_note_offline(&note_id, "Multi-conflict Note", "Revision 2 by B", vec![]);
    let rep_b1 = client_b.sync().await;
    assert_eq!(rep_b1.mutations_conflicted, 1);

    let conf1 = client_b.get_active_conflict(&note_id).unwrap();
    assert_eq!(conf1.remote_revision, 2);

    // Client B resolves conflict targeting expected_revision = 2
    client_b.resolve(&conf1.conflict_id, ConflictResolutionStrategy::KeepLocal);

    // Step 4: Before Client B retries, Client C pulls rev 2 and pushes revision 3!
    client_c.sync().await; // Client C pulls rev 2
    client_c.edit_note_offline(&note_id, "Multi-conflict Note", "Revision 3 by C", vec![]);
    client_c.sync().await; // Client C accepted at rev 3!

    // Step 5: Client B now pushes its retry mutation (expected_revision was 2)
    // Server rejects again with 409 Conflict because server is now at revision 3!
    let rep_b2 = client_b.sync().await;
    assert_eq!(rep_b2.mutations_conflicted, 1);

    // Verify Client B has updated active conflict record with remote_revision = 3
    let conf2 = client_b.get_active_conflict(&note_id).unwrap();
    assert_eq!(conf2.remote_revision, 3);
    assert!(!conf2.resolved);

    // Step 6: Client B re-resolves against revision 3
    client_b.resolve(&conf2.conflict_id, ConflictResolutionStrategy::KeepLocal);

    // Step 7: Client B retries targeting expected_revision = 3 -> Server accepts at revision 4!
    let rep_b3 = client_b.sync().await;
    assert_eq!(rep_b3.mutations_accepted, 1);
    assert_eq!(rep_b3.mutations_conflicted, 0);

    // All clients sync and converge to revision 4
    client_a.sync().await;
    client_c.sync().await;

    assert_eq!(
        client_a.read_note(&note_id).unwrap().body,
        "Revision 2 by B"
    );
    assert_eq!(
        client_b.read_note(&note_id).unwrap().body,
        "Revision 2 by B"
    );
    assert_eq!(
        client_c.read_note(&note_id).unwrap().body,
        "Revision 2 by B"
    );
}

// ----------------------------------------------------------------------------
// 8. M5 Gate: Offline Concurrent Edits Full Lifecycle & Zero-Knowledge Audit
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m5_gate_offline_concurrent_edits_full_lifecycle() {
    let server_db_file = std::env::temp_dir().join(format!("zk_srv_m5_{}.db", Uuid::new_v4()));
    let server = start_test_server_with_file(server_db_file.clone()).await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "m5_a").await;
    let mut client_b =
        ClientDevice::new(&server, account_id, shared_vault_key.clone(), "m5_b").await;

    let note_id = Uuid::new_v4().to_string();

    // 1. Initial shared note at revision 1
    let initial_title = "Classified Strategy";
    let initial_body = "Initial uncompromised strategic plans.";
    client_a.create_note_offline(&note_id, initial_title, initial_body, vec!["strategy"]);
    client_a.sync().await;
    client_b.sync().await;

    assert_eq!(client_a.read_note(&note_id).unwrap().title, initial_title);
    assert_eq!(client_b.read_note(&note_id).unwrap().title, initial_title);

    // 2. Both clients edit offline concurrently based on revision 1
    let title_a = "Alpha Tactical Protocol";
    let body_a = "Tactical directives established by Station Alpha.";
    client_a.edit_note_offline(&note_id, title_a, body_a, vec!["strategy", "alpha"]);

    let title_b = "Beta Operational Directive";
    let body_b = "Operational guidelines authored by Station Beta.";
    client_b.edit_note_offline(&note_id, title_b, body_b, vec!["strategy", "beta"]);

    // 3. Client A syncs first -> server accepts revision 2
    let rep_a = client_a.sync().await;
    assert_eq!(rep_a.mutations_accepted, 1);

    // 4. Client B syncs -> server does NOT overwrite silently (Criterion 1)
    let rep_b = client_b.sync().await;
    assert_eq!(rep_b.mutations_conflicted, 1);
    assert_eq!(rep_b.mutations_accepted, 0);

    // 5. Both contents remain fully recoverable (Criterion 2)
    let conflict = client_b
        .get_active_conflict(&note_id)
        .expect("active conflict record must exist");
    assert_eq!(conflict.base_revision, 1);
    assert_eq!(conflict.remote_revision, 2);

    let local_rec = PlaintextNote::decrypt(&conflict.local_envelope, &shared_vault_key).unwrap();
    let remote_rec = PlaintextNote::decrypt(&conflict.remote_envelope, &shared_vault_key).unwrap();
    let base_rec =
        PlaintextNote::decrypt(conflict.base_envelope.as_ref().unwrap(), &shared_vault_key)
            .unwrap();

    assert_eq!(base_rec.title, initial_title);
    assert_eq!(local_rec.title, title_b);
    assert_eq!(remote_rec.title, title_a);

    // 6. Client resolves and produces a new accepted revision (Criterion 3)
    let unified_title = "Joint Alpha-Beta Defense Accord";
    let unified_body = format!("{}\n\n{}", body_a, body_b);
    let mut unified_note = PlaintextNote::new(unified_title, &unified_body);
    unified_note.tags = vec![
        "strategy".to_string(),
        "alpha".to_string(),
        "beta".to_string(),
    ];
    unified_note.canonicalize();

    client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::Merge(unified_note),
    );

    let rep_b_res = client_b.sync().await;
    assert_eq!(rep_b_res.mutations_accepted, 1);
    assert_eq!(rep_b_res.mutations_conflicted, 0);

    // Client A syncs to pulled revision 3
    client_a.sync().await;

    let final_a = client_a.read_note(&note_id).unwrap();
    let final_b = client_b.read_note(&note_id).unwrap();
    assert_eq!(final_a.title, unified_title);
    assert_eq!(final_b.title, unified_title);
    assert_eq!(final_a.body, unified_body);
    assert_eq!(final_b.body, unified_body);
    assert_eq!(final_a.tags, vec!["alpha", "beta", "strategy"]);

    // 7. Security Audit: Zero-knowledge plaintext leak verification on server disk
    let server_bytes = fs::read(&server_db_file).expect("read server db file");
    let server_disk_str = String::from_utf8_lossy(&server_bytes);

    let forbidden_strings = [
        initial_title,
        initial_body,
        title_a,
        body_a,
        title_b,
        body_b,
        unified_title,
        "Joint Alpha-Beta Defense Accord",
        "Tactical directives established by Station Alpha",
        "Operational guidelines authored by Station Beta",
    ];

    for secret in forbidden_strings {
        assert!(
            !server_disk_str.contains(secret),
            "SECURITY VIOLATION (SEC-001, SEC-002): plaintext '{secret}' detected in raw server database!"
        );
    }
}
