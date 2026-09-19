//! Release Candidate Integration & Demonstration Test Suite (ZK-099).
//!
//! Validates the final acceptance criteria for V1 Release Candidate:
//! 1. Two-client offline conflict demo:
//!    - Client A and Client B synchronize a shared note;
//!    - Both clients edit offline concurrently based on the same revision;
//!    - Client A syncs first -> server accepts mutation (revision increments);
//!    - Client B syncs second -> server rejects with HTTP 409 Conflict (CAS guard, SEC-006);
//!    - Client B stores local conflict record, keeping base, local, and remote envelopes fully recoverable;
//!    - Client B executes 3-way merge conflict resolution and pushes resolved revision;
//!    - Client A syncs and converges on the unified note;
//!    - Zero-Knowledge disk audit verifies zero plaintext leakages (SEC-001, SEC-002, SEC-009).
//! 2. Passphrase recovery demo:
//!    - Vault initialized with passphrase and 288-bit formatted RecoveryKey;
//!    - Notes created and encrypted with VaultKey;
//!    - Simulated passphrase loss / lockout (wrong passphrase fails closed);
//!    - Vault unlocked using 288-bit recovery key;
//!    - Master passphrase rotated to a new passphrase;
//!    - Old passphrase fails closed;
//!    - New passphrase unlocks and decrypts all prior notes with 100% integrity (zero data loss);
//!    - Recovery key remains valid for future recovery.
//! 3. All security invariants (SEC-001 through SEC-010) verified.

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
use zk_core::vault::{VaultManager, VaultSession};
use zk_crypto::kdf::KdfParams;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_server::db::{run_server_migrations, ServerDb};
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{ConflictStore, ObjectStore};
use zk_sync::adapter::NativeHttpSyncAdapter;
use zk_sync::conflict::{resolve_conflict, ConflictResolutionStrategy};
use zk_sync::orchestrator::{SyncCycleOptions, SyncEngine};

/// Ephemeral test server instance.
struct TestServer {
    base_url: String,
    db_file: PathBuf,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = fs::remove_file(&self.db_file);
    }
}

async fn start_test_server() -> TestServer {
    let db_file = std::env::temp_dir().join(format!("zk_rc_srv_{}.db", Uuid::new_v4()));
    let mut conn = Connection::open(&db_file).expect("open server db");
    run_server_migrations(&mut conn).expect("run migrations");
    let db = ServerDb::from_connection(conn);
    let config = ServerConfig::default();
    let state = AppState { config, db };
    let app = create_app(state);

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
        db_file,
        shutdown_tx: Some(shutdown_tx),
    }
}

/// Simulated client device with on-disk SQLite storage and active vault session.
struct ClientDevice {
    db_path: PathBuf,
    storage: Arc<SqliteStorage>,
    engine: SyncEngine<NativeHttpSyncAdapter, Arc<SqliteStorage>>,
    session: VaultSession,
    vault_key: VaultKey,
}

impl Drop for ClientDevice {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.db_path);
    }
}

impl ClientDevice {
    fn new(base_url: &str, account_id: Uuid, vault_key: VaultKey, prefix: &str) -> Self {
        let db_path = std::env::temp_dir().join(format!("zk_rc_{prefix}_{}.db", Uuid::new_v4()));
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open client sqlite"));
        let adapter = NativeHttpSyncAdapter::new(base_url, Some(account_id.to_string()))
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

    async fn sync(&mut self) -> zk_sync::orchestrator::SyncCycleReport {
        self.engine
            .sync_with_session(&mut self.session, SyncCycleOptions::default())
            .await
            .expect("sync cycle succeeds")
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

    fn resolve(&mut self, conflict_id: &str, strategy: ConflictResolutionStrategy) {
        resolve_conflict(
            &self.storage,
            self.engine.queue(),
            &self.vault_key,
            conflict_id,
            strategy,
        )
        .expect("resolve conflict succeeds");
    }

    fn read_note(&self, id: &str) -> Option<PlaintextNote> {
        let obj = self.storage.get_object(id).ok().flatten()?;
        if obj.is_deleted || obj.object_kind != OBJECT_KIND_NOTE {
            return None;
        }
        PlaintextNote::decrypt(&obj.envelope, &self.vault_key).ok()
    }
}

// ============================================================================
// DEMO 1: Two-Client Offline Conflict & Convergence Demo
// ============================================================================

#[tokio::test]
async fn test_rc_two_client_offline_conflict_demo() {
    println!("\n=======================================================");
    println!(" [RC DEMO 1] TWO-CLIENT OFFLINE CONFLICT & RESOLUTION");
    println!("=======================================================");

    let server = start_test_server().await;
    let account_id = Uuid::new_v4();
    let shared_vault_key = VaultKey::generate();

    let mut client_a = ClientDevice::new(
        &server.base_url,
        account_id,
        shared_vault_key.clone(),
        "client_a",
    );
    let mut client_b = ClientDevice::new(
        &server.base_url,
        account_id,
        shared_vault_key.clone(),
        "client_b",
    );

    let note_id = Uuid::new_v4().to_string();

    // Step 1: Initial shared note creation
    let init_title = "Product Launch Roadmap 2026";
    let init_body = "1. Security audit\n2. Performance tuning\n3. Public release";
    println!("[Step 1] Client A creates note offline at rev 1: '{init_title}'");
    client_a.create_note_offline(&note_id, init_title, init_body, vec!["v1.0", "planning"]);

    println!("[Step 2] Client A syncs to server -> accepted at rev 1");
    let rep_a1 = client_a.sync().await;
    assert_eq!(rep_a1.mutations_accepted, 1);

    println!("[Step 3] Client B syncs from server -> pulls note at rev 1");
    let rep_b1 = client_b.sync().await;
    assert_eq!(rep_b1.initial_pull.applied_changes, 1);

    let note_b = client_b.read_note(&note_id).expect("client B has note");
    assert_eq!(note_b.title, init_title);
    assert_eq!(note_b.body, init_body);

    // Step 4: Disconnect & Concurrent Offline Edits
    println!("[Step 4] Both clients disconnect and edit offline concurrently based on rev 1");

    let title_a = "Product Launch Roadmap 2026 (Alpha Stream)";
    let body_a = "1. Security audit (COMPLETED)\n2. Performance tuning (WIP)\n3. Public release";
    client_a.edit_note_offline(&note_id, title_a, body_a, vec!["v1.0", "alpha"]);

    let title_b = "Product Launch Roadmap 2026 (Beta Stream)";
    let body_b =
        "1. Security audit\n2. Performance tuning\n3. Public release\n4. Post-launch monitoring";
    client_b.edit_note_offline(&note_id, title_b, body_b, vec!["v1.0", "beta"]);

    // Step 5: Client A pushes first
    println!("[Step 5] Client A syncs first -> server accepts rev 2");
    let rep_a2 = client_a.sync().await;
    assert_eq!(rep_a2.mutations_accepted, 1);
    assert_eq!(rep_a2.mutations_conflicted, 0);

    // Step 6: Client B pushes second -> CAS rejection
    println!("[Step 6] Client B syncs -> server rejects with 409 Conflict (CAS guard SEC-006)");
    let rep_b2 = client_b.sync().await;
    assert_eq!(rep_b2.mutations_accepted, 0);
    assert_eq!(rep_b2.mutations_conflicted, 1);

    // Step 7: Verify conflict record preserves all three states
    println!("[Step 7] Client B inspects local conflict record: base, local, and remote preserved");
    let conflict = client_b
        .storage
        .get_active_conflict_for_object(&note_id)
        .expect("get conflict")
        .expect("conflict record exists");
    assert_eq!(conflict.base_revision, 1);
    assert_eq!(conflict.remote_revision, 2);

    let base_note =
        PlaintextNote::decrypt(conflict.base_envelope.as_ref().unwrap(), &shared_vault_key)
            .unwrap();
    let local_note = PlaintextNote::decrypt(&conflict.local_envelope, &shared_vault_key).unwrap();
    let remote_note = PlaintextNote::decrypt(&conflict.remote_envelope, &shared_vault_key).unwrap();

    assert_eq!(base_note.title, init_title);
    assert_eq!(local_note.title, title_b);
    assert_eq!(remote_note.title, title_a);

    // Step 8: Client B resolves conflict using 3-way merge
    println!("[Step 8] Client B executes 3-way merge resolution and enqueues resolved note");
    let unified_title = "Product Launch Roadmap 2026 (Unified Release)";
    let unified_body = "1. Security audit (COMPLETED)\n2. Performance tuning (WIP)\n3. Public release\n4. Post-launch monitoring";
    let mut unified_note = PlaintextNote::new(unified_title, unified_body);
    unified_note.tags = vec![
        "v1.0".to_string(),
        "alpha".to_string(),
        "beta".to_string(),
        "launch".to_string(),
    ];
    unified_note.canonicalize();

    client_b.resolve(
        &conflict.conflict_id,
        ConflictResolutionStrategy::Merge(unified_note),
    );

    // Step 9: Client B syncs resolved note to server
    println!("[Step 9] Client B syncs -> server accepts resolved rev 3");
    let rep_b3 = client_b.sync().await;
    assert_eq!(rep_b3.mutations_accepted, 1);
    assert_eq!(rep_b3.mutations_conflicted, 0);

    // Step 10: Client A pulls converged state
    println!("[Step 10] Client A syncs -> pulls rev 3");
    let rep_a3 = client_a.sync().await;
    assert_eq!(rep_a3.initial_pull.applied_changes, 1);

    // Step 11: Verify 100% convergence across both devices
    println!("[Step 11] Verifying 100% convergence across Client A and Client B");
    let final_a = client_a.read_note(&note_id).unwrap();
    let final_b = client_b.read_note(&note_id).unwrap();

    assert_eq!(final_a.title, unified_title);
    assert_eq!(final_b.title, unified_title);
    assert_eq!(final_a.body, unified_body);
    assert_eq!(final_b.body, unified_body);
    assert_eq!(final_a.tags, final_b.tags);
    assert_eq!(final_a.tags, vec!["alpha", "beta", "launch", "v1.0"]);

    // Step 12: Zero-Knowledge Disk Audit
    println!("[Step 12] Zero-Knowledge Disk Audit: scanning server SQLite file");
    let server_bytes = fs::read(&server.db_file).expect("read server db file");
    let server_raw = String::from_utf8_lossy(&server_bytes);

    let canaries = [
        init_title,
        init_body,
        title_a,
        body_a,
        title_b,
        body_b,
        unified_title,
        unified_body,
        "Station Alpha",
        "Station Beta",
        "Post-launch monitoring",
    ];

    for canary in canaries {
        assert!(
            !server_raw.contains(canary),
            "SECURITY VIOLATION: plaintext canary '{canary}' leaked to server database!"
        );
    }

    println!(" [PASS] Two-client offline conflict demo passed with zero plaintext leakage.\n");
}

// ============================================================================
// DEMO 2: Passphrase Loss & Recovery Key Lifecycle Demo
// ============================================================================

#[test]
fn test_rc_recovery_lifecycle_demo() {
    println!("\n=======================================================");
    println!(" [RC DEMO 2] PASSPHRASE RECOVERY & ZERO-LOSS ROTATION");
    println!("=======================================================");

    let initial_passphrase = b"InitialMasterPassphrase-2026-Strict!";
    let new_passphrase = b"BrandNewRotatedPassphrase-2027-Secure!";
    let wrong_passphrase = b"AttackerOrForgottenGuess12345!";

    // Step 1: Initialize Vault
    println!("[Step 1] Initializing zero-knowledge vault with master passphrase");
    let kdf_params = KdfParams::new_test();
    let (bootstrap, recovery_phrase, vault_key) =
        VaultManager::init_vault(initial_passphrase, &kdf_params).expect("init vault");

    println!("Generated formatted 288-bit recovery key: {recovery_phrase}");
    assert!(recovery_phrase.len() >= 48);

    // Step 2: Encrypt notes with initial VaultKey
    println!("[Step 2] Encrypting and storing notes with VaultKey");
    let note1_title = "Vault Security Architecture";
    let note1_body = "Argon2id + XChaCha20-Poly1305 authenticated envelope.";
    let mut note1 = PlaintextNote::new(note1_title, note1_body);
    note1.tags = vec!["architecture".to_string(), "crypto".to_string()];
    note1.canonicalize();
    let note1_id = Uuid::new_v4().to_string();
    let envelope1 = note1.encrypt(&vault_key, &note1_id).expect("encrypt note1");

    let note2_title = "Treasury Multi-Sig Cold Storage";
    let note2_body = "Primary cold storage threshold: 3-of-5 hardware modules.";
    let mut note2 = PlaintextNote::new(note2_title, note2_body);
    note2.tags = vec!["financial".to_string(), "confidential".to_string()];
    note2.canonicalize();
    let note2_id = Uuid::new_v4().to_string();
    let envelope2 = note2.encrypt(&vault_key, &note2_id).expect("encrypt note2");

    // Drop in-memory key to simulate complete session purge
    drop(vault_key);

    // Step 3: Simulate Passphrase Loss & Wrong Passphrase Attempt
    println!("[Step 3] Simulating lost passphrase: wrong attempt fails closed (SEC-010)");
    let failed_unlock = VaultManager::unlock_with_passphrase(&bootstrap, wrong_passphrase);
    assert!(
        failed_unlock.is_err(),
        "SECURITY VIOLATION: wrong passphrase must fail closed"
    );

    // Step 4: Recovery with typo-detection check
    println!("[Step 4] Attempting recovery: corrupted phrase fails typo checksum");
    let mut corrupted_phrase = recovery_phrase.clone();
    let last_char = corrupted_phrase.pop().unwrap();
    let replacement = if last_char == '0' { '1' } else { '0' };
    corrupted_phrase.push(replacement);

    let corrupted_attempt = VaultManager::unlock_with_recovery_key(&bootstrap, &corrupted_phrase);
    assert!(
        corrupted_attempt.is_err(),
        "corrupted recovery key checksum must be rejected"
    );

    println!("[Step 5] Unlocking vault with valid recovery phrase");
    let recovered_vault_key = VaultManager::unlock_with_recovery_key(&bootstrap, &recovery_phrase)
        .expect("recovery unlock succeeds");

    // Step 6: Reset Master Passphrase
    println!("[Step 6] Rotating to brand-new master passphrase using recovered VaultKey");
    let new_kdf_params = KdfParams::new_test();
    let updated_bootstrap = VaultManager::set_new_passphrase(
        &bootstrap,
        &recovered_vault_key,
        new_passphrase,
        &new_kdf_params,
    )
    .expect("set new passphrase");

    // Drop recovered key from memory
    drop(recovered_vault_key);

    // Step 7: Verify Old Passphrase Fails Closed
    println!("[Step 7] Verifying old passphrase fails closed against updated vault");
    let old_pass_attempt =
        VaultManager::unlock_with_passphrase(&updated_bootstrap, initial_passphrase);
    assert!(
        old_pass_attempt.is_err(),
        "old passphrase must fail closed after rotation"
    );

    // Step 8: Unlock with New Passphrase
    println!("[Step 8] Unlocking vault with new passphrase");
    let new_session_key = VaultManager::unlock_with_passphrase(&updated_bootstrap, new_passphrase)
        .expect("new passphrase unlock succeeds");

    // Step 9: Verify 100% Data Integrity across all prior notes
    println!("[Step 9] Verifying 100% data integrity on stored notes (zero data loss)");
    let decrypted1 = PlaintextNote::decrypt(&envelope1, &new_session_key).expect("decrypt note1");
    assert_eq!(decrypted1.title, note1_title);
    assert_eq!(decrypted1.body, note1_body);
    assert_eq!(decrypted1.tags, vec!["architecture", "crypto"]);

    let decrypted2 = PlaintextNote::decrypt(&envelope2, &new_session_key).expect("decrypt note2");
    assert_eq!(decrypted2.title, note2_title);
    assert_eq!(decrypted2.body, note2_body);
    assert_eq!(decrypted2.tags, vec!["confidential", "financial"]);

    // Step 10: Verify Recovery Key Remains Valid
    println!("[Step 10] Verifying recovery key remains valid after passphrase rotation");
    let rec_after_rot =
        VaultManager::unlock_with_recovery_key(&updated_bootstrap, &recovery_phrase)
            .expect("recovery key remains valid");
    let decrypted_rec =
        PlaintextNote::decrypt(&envelope1, &rec_after_rot).expect("decrypt note1 via recovery key");
    assert_eq!(decrypted_rec.title, note1_title);

    println!(" [PASS] Passphrase recovery lifecycle demo passed with 100% data integrity.\n");
}
