#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::auth::save_auth_session;
use crate::client::{notes, sync::perform_sync};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use zk_crypto::keys::VaultKey;
use zk_protocol::{
    auth::AuthToken,
    sync::{PullChangesResponse, PushRequest, PushResponse},
};
use zk_sync::{adapter::MockSyncAdapter, error::SyncNetworkError};

#[derive(Debug)]
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("zk110-{}", Uuid::new_v4()));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn initialize(dir: &Path) -> (VaultBootstrap, String, VaultKey) {
    let (b, r, k) =
        VaultManager::init_vault(b"LOCAL-PASS-CANARY", &zk_crypto::kdf::KdfParams::new_test())
            .unwrap();
    fs::write(config::vault_file(dir), serde_json::to_vec(&b).unwrap()).unwrap();
    (b, r, k)
}
fn auth() -> StoredAuthSession {
    StoredAuthSession {
        server_url: "https://example.com".into(),
        account_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        token: AuthToken::new("TOKEN-CANARY"),
        expires_at: None,
    }
}
#[derive(Debug, Default)]
struct Instrumented {
    inner: MockSyncAdapter,
    push: AtomicUsize,
    post: AtomicUsize,
    pull: AtomicUsize,
    fail_pull: Option<usize>,
    fail_get: bool,
    traffic: Mutex<Vec<String>>,
}
impl SyncServerAdapter for Instrumented {
    async fn get_vault_bootstrap(&self) -> Result<Option<VaultBootstrap>, SyncNetworkError> {
        if self.fail_get {
            return Err(SyncNetworkError::ConnectionFailed("injected".into()));
        }
        self.inner.get_vault_bootstrap().await
    }
    async fn post_vault_bootstrap(&self, b: &VaultBootstrap) -> Result<(), SyncNetworkError> {
        self.post.fetch_add(1, Ordering::SeqCst);
        self.traffic
            .lock()
            .unwrap()
            .push(serde_json::to_string(b).unwrap());
        self.inner.post_vault_bootstrap(b).await
    }
    async fn push_mutation(&self, r: &PushRequest) -> Result<PushResponse, SyncNetworkError> {
        self.push.fetch_add(1, Ordering::SeqCst);
        self.traffic
            .lock()
            .unwrap()
            .push(serde_json::to_string(r).unwrap());
        self.inner.push_mutation(r).await
    }
    async fn pull_changes(
        &self,
        after: u64,
        _: Option<u32>,
    ) -> Result<PullChangesResponse, SyncNetworkError> {
        let n = self.pull.fetch_add(1, Ordering::SeqCst);
        if self.fail_pull == Some(n) {
            return Err(SyncNetworkError::ConnectionFailed("injected".into()));
        }
        self.traffic.lock().unwrap().push(format!("after={after}"));
        self.inner.pull_changes(after, Some(1)).await
    }
}
fn preflight(dir: &Path, a: &StoredAuthSession, b: VaultBootstrap) -> ReplacePreflight {
    ReplacePreflight {
        current_link: load_link(dir).ok(),
        current_fingerprint: local_bootstrap(dir).ok().map(|b| fingerprint(&b).unwrap()),
        counts: unsynced_counts(dir).unwrap(),
        target_link: VaultLink::new(a, fingerprint(&b).unwrap()).unwrap(),
        bootstrap: b,
        auth: a.clone(),
    }
}
async fn populate(a: &Instrumented, key: &VaultKey, deleted: bool) -> String {
    let id = Uuid::new_v4().to_string();
    let note = zk_core::note::PlaintextNote::new("TITLE-CANARY", "BODY-CANARY");
    let envelope = note.encrypt(key, &id).unwrap();
    a.push_mutation(&PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: id.clone(),
        expected_revision: 0,
        object_kind: 1,
        envelope,
        is_deleted: deleted,
    })
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn explicit_link_create_adopt_fail_closed_and_atomic_reload() {
    let dir = TempDir::new();
    let (b, _, _) = initialize(&dir.0);
    let auth = auth();
    let a = Instrumented::default();
    let link = link_with_adapter(&dir.0, &auth, &a).await.unwrap();
    assert_eq!(load_link(&dir.0).unwrap(), link);
    assert_eq!(a.post.load(Ordering::SeqCst), 1);
    fs::remove_file(dir.0.join("vault-link.json")).unwrap();
    link_with_adapter(&dir.0, &auth, &a).await.unwrap();
    assert_eq!(a.post.load(Ordering::SeqCst), 1);
    let different = TempDir::new();
    initialize(&different.0);
    assert!(matches!(
        link_with_adapter(&different.0, &auth, &a).await,
        Err(CliError::VaultLink(LinkError::RemoteVaultMismatch))
    ));
    assert_eq!(a.post.load(Ordering::SeqCst), 1);
    assert!(!different.0.join("vault-link.json").exists());
    let fail = Instrumented {
        fail_get: true,
        ..Default::default()
    };
    fs::remove_file(dir.0.join("vault-link.json")).unwrap();
    assert!(link_with_adapter(&dir.0, &auth, &fail).await.is_err());
    assert!(!dir.0.join("vault-link.json").exists());
    assert_eq!(local_bootstrap(&dir.0).unwrap(), b);
    link.save(&dir.0).unwrap();
    fs::write(dir.0.join("vault-link.json"), b"{bad").unwrap();
    assert!(matches!(
        load_link(&dir.0),
        Err(CliError::VaultLink(LinkError::CorruptLink))
    ));
}
#[tokio::test]
async fn all_local_guard_mismatches_make_zero_sync_requests() {
    let dir = TempDir::new();
    initialize(&dir.0);
    let auth = auth();
    let link = VaultLink::new(
        &auth,
        fingerprint(&local_bootstrap(&dir.0).unwrap()).unwrap(),
    )
    .unwrap();
    // Even an unreachable server must produce the local typed refusal first.
    for case in 0..6 {
        link.save(&dir.0).unwrap();
        let mut current = auth.clone();
        match case {
            0 => {
                fs::remove_file(dir.0.join("vault-link.json")).unwrap();
            }
            1 => {
                fs::write(dir.0.join("vault-link.json"), b"{}").unwrap();
            }
            2 => current.account_id = Uuid::new_v4(),
            3 => current.server_url = "https://other.example.com".into(),
            4 => {
                let mut l = link.clone();
                l.vault_fingerprint = format!("blake2s-v1:{}", "a".repeat(64));
                l.save(&dir.0).unwrap();
            }
            _ => current.server_url = "http://remote.example.com".into(),
        }
        save_auth_session(&config::auth_session_file(&dir.0), &current).unwrap();
        assert!(perform_sync(Some(&dir.0), None).await.is_err());
        assert!(
            !config::db_file(&dir.0).exists(),
            "guard must run before DB open"
        );
    }
    let a = Instrumented::default();
    assert!(matches!(
        validate_remote_link(&link, &a).await,
        Err(CliError::VaultLink(LinkError::RemoteVaultMissing))
    ));
    let other = TempDir::new();
    let (b, _, _) = initialize(&other.0);
    a.inner.post_vault_bootstrap(&b).await.unwrap();
    assert!(matches!(
        validate_remote_link(&link, &a).await,
        Err(CliError::VaultLink(LinkError::RemoteVaultMismatch))
    ));
    assert_eq!(a.push.load(Ordering::SeqCst), 0);
    assert_eq!(a.pull.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn staged_restore_tombstones_wal_reopen_and_discard_never_push() {
    let origin = TempDir::new();
    let (b, recovery, key) = initialize(&origin.0);
    let a = Instrumented::default();
    a.inner.post_vault_bootstrap(&b).await.unwrap();
    let live = populate(&a, &key, false).await;
    let deleted = populate(&a, &key, true).await;
    a.push.store(0, Ordering::SeqCst);
    let target = TempDir::new();
    let (_, _, old_key) = initialize(&target.0);
    let local_note = notes::create_note(
        Some(&target.0),
        &old_key,
        "DISCARDED-TITLE",
        "DISCARDED-BODY",
        vec![],
    )
    .unwrap();
    let mut p = preflight(&target.0, &auth(), b);
    assert_eq!(p.counts.pending, 1);
    assert_eq!(p.counts.unconfirmed_objects, 1);
    let storage = SqliteStorage::open(config::db_file(&target.0)).unwrap();
    let mut mutation = storage.list_pending_mutations().unwrap()[0].clone();
    mutation.mutation_id = Uuid::new_v4().to_string();
    mutation.status = MutationStatus::InFlight;
    storage.enqueue_mutation(&mutation).unwrap();
    mutation.mutation_id = Uuid::new_v4().to_string();
    mutation.status = MutationStatus::Failed;
    storage.enqueue_mutation(&mutation).unwrap();
    let conflict = zk_storage::models::ConflictRecord::new(
        Uuid::new_v4().to_string(),
        local_note,
        1,
        0,
        1,
        None,
        mutation.envelope.clone(),
        mutation.envelope.clone(),
        None,
        zk_core::time::now_utc_rfc3339(),
    );
    storage.put_conflict(&conflict).unwrap();
    drop(storage);
    p.counts = unsynced_counts(&target.0).unwrap();
    assert_eq!(
        p.counts,
        UnsyncedCounts {
            pending: 1,
            in_flight: 1,
            failed: 1,
            conflicts: 1,
            unconfirmed_objects: 1
        }
    );
    fs::write(target.0.join(".auth_session"), b"auth-preserved").unwrap();
    fs::write(target.0.join("device.json"), b"device-preserved").unwrap();
    crate::session::save_session_key(&target.0.join(".session"), &old_key).unwrap();
    let stage = stage_with_adapter(&target.0, &p, UnlockSecret::RecoveryKey(&recovery), &a)
        .await
        .unwrap();
    assert_eq!(a.push.load(Ordering::SeqCst), 0);
    assert_eq!(unsynced_counts(&target.0).unwrap(), p.counts); // active untouched during staging
    vault_files::install(&target.0, stage).unwrap();
    let storage = SqliteStorage::open(config::db_file(&target.0)).unwrap();
    assert_eq!(storage.get_sync_state().unwrap().sync_cursor, 2);
    assert!(storage.get_object(&deleted).unwrap().unwrap().is_deleted);
    assert_eq!(
        notes::get_note(Some(&target.0), &key, &live).unwrap().body,
        "BODY-CANARY"
    );
    assert_eq!(
        unsynced_counts(&target.0).unwrap(),
        UnsyncedCounts::default()
    );
    assert!(!target.0.join(".session").exists());
    assert_eq!(
        fs::read(target.0.join(".auth_session")).unwrap(),
        b"auth-preserved"
    );
    assert_eq!(
        fs::read(target.0.join("device.json")).unwrap(),
        b"device-preserved"
    );
    assert_eq!(a.push.load(Ordering::SeqCst), 0);
    let traffic = a.traffic.lock().unwrap().join("\n");
    for secret in [
        "LOCAL-PASS-CANARY",
        &recovery,
        "TITLE-CANARY",
        "BODY-CANARY",
        "DISCARDED-TITLE",
        "DISCARDED-BODY",
    ] {
        assert!(!traffic.contains(secret));
    }
}
#[tokio::test]
async fn restore_failures_leave_active_generation_unchanged_and_scrub_staging() {
    for fail in 0..5 {
        let target = TempDir::new();
        let (old, _, _) = initialize(&target.0);
        let origin = TempDir::new();
        let (b, _, key) = initialize(&origin.0);
        let a = Instrumented {
            fail_pull: match fail {
                2 => Some(0),
                3 => Some(1),
                _ => None,
            },
            ..Default::default()
        };
        a.inner.post_vault_bootstrap(&b).await.unwrap();
        populate(&a, &key, false).await;
        populate(&a, &key, false).await;
        a.push.store(0, Ordering::SeqCst);
        let mut p = preflight(&target.0, &auth(), b);
        if fail == 4 {
            p.bootstrap.crypto_version = 99;
        }
        let secret = match fail {
            0 => UnlockSecret::Passphrase(b"wrong"),
            1 => UnlockSecret::RecoveryKey("wrong recovery"),
            _ => UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"),
        };
        assert!(stage_with_adapter(&target.0, &p, secret, &a).await.is_err());
        assert_eq!(local_bootstrap(&target.0).unwrap(), old);
        assert!(!config::db_file(&target.0).exists());
        assert!(!fs::read_dir(&target.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".replace-")));
        assert_eq!(a.push.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug)]
struct Server {
    state: zk_server::app::AppState,
    origin: String,
    task: tokio::task::JoinHandle<()>,
    pulls: Arc<AtomicUsize>,
    pushes: Arc<AtomicUsize>,
    traffic: Arc<Mutex<Vec<Vec<u8>>>>,
    bootstrap_failure: Arc<AtomicUsize>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start() -> Self {
        let state =
            zk_server::app::AppState::new_in_memory(zk_server::config::ServerConfig::default())
                .unwrap();
        let pulls = Arc::new(AtomicUsize::new(0));
        let pushes = Arc::new(AtomicUsize::new(0));
        let traffic = Arc::new(Mutex::new(Vec::new()));
        let p = pulls.clone();
        let q = pushes.clone();
        let t = traffic.clone();
        let bootstrap_failure = Arc::new(AtomicUsize::new(0));
        let failure = bootstrap_failure.clone();
        let app = zk_server::app::create_app(state.clone()).layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let (p, q, t, failure) = (p.clone(), q.clone(), t.clone(), failure.clone());
                async move {
                    let path = request.uri().path();
                    if path == "/v1/vault/bootstrap" {
                        let failure = failure.load(Ordering::SeqCst);
                        let get = request.method() == axum::http::Method::GET;
                        if failure == 1 && get || failure == 3 && !get {
                            return axum::http::Response::builder()
                                .status(500)
                                .body(axum::body::Body::from("UNTRUSTED-ERROR-CANARY"))
                                .unwrap();
                        }
                        if failure == 2 && get {
                            return axum::http::Response::builder()
                                .status(200)
                                .body(axum::body::Body::from("{malformed bootstrap"))
                                .unwrap();
                        }
                    }
                    if path == "/v1/sync/changes" {
                        p.fetch_add(1, Ordering::SeqCst);
                    }
                    if path == "/v1/sync/push" {
                        q.fetch_add(1, Ordering::SeqCst);
                    }
                    let (parts, body) = request.into_parts();
                    let bytes = axum::body::to_bytes(body, 20_000_000).await.unwrap();
                    t.lock().unwrap().push(bytes.to_vec());
                    next.run(axum::extract::Request::from_parts(
                        parts,
                        axum::body::Body::from(bytes),
                    ))
                    .await
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            state,
            origin,
            task,
            pulls,
            pushes,
            traffic,
            bootstrap_failure,
        }
    }
    async fn session(&self, dir: &Path, account: Uuid) -> StoredAuthSession {
        let device = crate::auth::get_or_create_device_id(dir, None).unwrap();
        let (session, token) = self
            .state
            .db
            .create_session(account, Some(device), None, Some(3600))
            .await
            .unwrap();
        let auth = StoredAuthSession {
            server_url: self.origin.clone(),
            account_id: account,
            device_id: device,
            session_id: Some(session.session_id),
            token,
            expires_at: session.expires_at,
        };
        save_auth_session(&config::auth_session_file(dir), &auth).unwrap();
        auth
    }
}
#[tokio::test]
async fn two_isolated_native_machines_link_sync_restore_decrypt_and_tombstones() {
    let server = Server::start().await;
    let account = Uuid::new_v4();
    let machine_a = TempDir::new();
    let (_, recovery, key) = initialize(&machine_a.0);
    let auth_a = server.session(&machine_a.0, account).await;
    link_local_vault_to_server(&machine_a.0).await.unwrap();
    let live = notes::create_note(
        Some(&machine_a.0),
        &key,
        "TITLE-CANARY",
        "BODY-CANARY",
        vec!["TAG-CANARY".into()],
    )
    .unwrap();
    let deleted = notes::create_note(
        Some(&machine_a.0),
        &key,
        "DELETE-TITLE",
        "DELETE-BODY",
        vec![],
    )
    .unwrap();
    perform_sync(Some(&machine_a.0), Some(&key)).await.unwrap();
    notes::delete_note(Some(&machine_a.0), &deleted, false).unwrap();
    perform_sync(Some(&machine_a.0), Some(&key)).await.unwrap();
    let machine_b = TempDir::new();
    let auth_b = server.session(&machine_b.0, account).await;
    assert_ne!(auth_a.device_id, auth_b.device_id);
    let p = replacement_preflight(&machine_b.0).await.unwrap();
    let before = server.pushes.load(Ordering::SeqCst);
    let stage = stage_remote_vault(
        &machine_b.0,
        &p,
        UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"),
        false,
        false,
    )
    .await
    .unwrap();
    vault_files::install(&machine_b.0, stage).unwrap();
    let restored = VaultManager::unlock_with_passphrase(
        &local_bootstrap(&machine_b.0).unwrap(),
        b"LOCAL-PASS-CANARY",
    )
    .unwrap();
    let note = notes::get_note(Some(&machine_b.0), &restored, &live).unwrap();
    assert_eq!(note.body, "BODY-CANARY");
    assert_eq!(note.tags, vec!["tag-canary"]);
    let storage = SqliteStorage::open(config::db_file(&machine_b.0)).unwrap();
    assert!(storage.get_object(&deleted).unwrap().unwrap().is_deleted);
    assert!(storage.get_sync_state().unwrap().sync_cursor > 0);
    assert_eq!(server.pushes.load(Ordering::SeqCst), before);
    perform_sync(Some(&machine_b.0), Some(&restored))
        .await
        .unwrap();
    assert_eq!(
        load_link(&machine_a.0).unwrap(),
        load_link(&machine_b.0).unwrap()
    );
    let bodies = server
        .traffic
        .lock()
        .unwrap()
        .iter()
        .flat_map(|b| b.iter().copied())
        .collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&bodies);
    for secret in [
        "LOCAL-PASS-CANARY",
        &recovery,
        "TITLE-CANARY",
        "BODY-CANARY",
        "tag-canary",
        "DELETE-TITLE",
        "DELETE-BODY",
    ] {
        assert!(!text.contains(secret));
    }
    let before = (
        server.pulls.load(Ordering::SeqCst),
        server.pushes.load(Ordering::SeqCst),
    );
    let wrong = server.session(&machine_b.0, Uuid::new_v4()).await;
    assert_ne!(wrong.account_id, account);
    assert!(matches!(
        perform_sync(Some(&machine_b.0), None).await,
        Err(CliError::VaultLink(LinkError::WrongAccount))
    ));
    assert_eq!(
        (
            server.pulls.load(Ordering::SeqCst),
            server.pushes.load(Ordering::SeqCst)
        ),
        before
    );
}

#[tokio::test]
async fn failure_at_each_staging_transition_and_actual_cursor_write_failure_keeps_old_vault() {
    for fail_at in 0..13 {
        let target = TempDir::new();
        let (old, _, old_key) = initialize(&target.0);
        let local =
            notes::create_note(Some(&target.0), &old_key, "old", "old body", vec![]).unwrap();
        let before = fs::read(config::db_file(&target.0)).unwrap();
        let origin = TempDir::new();
        let (b, _, key) = initialize(&origin.0);
        let a = Instrumented::default();
        a.inner.post_vault_bootstrap(&b).await.unwrap();
        populate(&a, &key, false).await;
        a.push.store(0, Ordering::SeqCst);
        let p = preflight(&target.0, &auth(), b);
        let result = stage_with_hook(&target.0, &p, UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"), &a, |n, stage| {
            if fail_at == 12 && n == 3 {
                let conn = rusqlite::Connection::open(config::db_file(stage)).unwrap();
                conn.execute_batch("CREATE TRIGGER fail_cursor BEFORE UPDATE OF sync_cursor ON sync_state BEGIN SELECT RAISE(FAIL, 'injected cursor persistence failure'); END;").unwrap();
            }
            if n == fail_at { Err(CliError::Io("injected filesystem/DB transition failure".into())) } else { Ok(()) }
        }).await;
        assert!(result.is_err(), "transition {fail_at}");
        assert_eq!(local_bootstrap(&target.0).unwrap(), old);
        assert_eq!(fs::read(config::db_file(&target.0)).unwrap(), before);
        assert_eq!(
            notes::get_note(Some(&target.0), &old_key, &local)
                .unwrap()
                .body,
            "old body"
        );
        assert_eq!(a.push.load(Ordering::SeqCst), 0);
        assert!(!fs::read_dir(&target.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".replace-")));
    }
}
#[test]
fn preflight_reads_do_not_create_or_mutate_local_cache_files() {
    let dir = TempDir::new();
    let (_, _, key) = initialize(&dir.0);
    notes::create_note(Some(&dir.0), &key, "pending", "body", vec![]).unwrap();
    fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }
    let before = snapshot(&dir.0);
    assert_eq!(unsynced_counts(&dir.0).unwrap().pending, 1);
    let after = snapshot(&dir.0);
    assert!(
        after == before,
        "preflight changed files: before {:?}, after {:?}",
        before.keys(),
        after.keys()
    );
}
#[tokio::test]
async fn missing_destructive_confirmation_is_refused_before_any_write_or_network() {
    let dir = TempDir::new();
    let (b, _, _) = initialize(&dir.0);
    let p = preflight(&dir.0, &auth(), b);
    assert!(matches!(
        stage_remote_vault(&dir.0, &p, UnlockSecret::Passphrase(b"wrong"), true, false).await,
        Err(CliError::VaultLink(LinkError::ConfirmationRequired))
    ));
    assert!(!fs::read_dir(&dir.0).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".replace-")));
}

#[test]
fn preflight_refuses_uncheckpointed_wal_without_undercounting_or_mutation() {
    let dir = TempDir::new();
    let (_, _, key) = initialize(&dir.0);
    let storage = SqliteStorage::open(config::db_file(&dir.0)).unwrap();
    storage.checkpoint().unwrap();
    let note = zk_core::note::PlaintextNote::new("WAL note", "WAL body");
    let envelope = note.encrypt(&key, &Uuid::new_v4().to_string()).unwrap();
    let m = zk_storage::models::PendingMutation {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: envelope.object_id.clone(),
        expected_revision: 0,
        object_kind: 1,
        mutation_type: zk_storage::models::MutationType::Upsert,
        envelope,
        created_at: zk_core::time::now_utc_rfc3339(),
        retry_count: 0,
        status: MutationStatus::InFlight,
    };
    storage.enqueue_mutation(&m).unwrap();
    let before = fs::read(config::db_file(&dir.0)).unwrap();
    let wal = fs::read(dir.0.join("notes.db-wal")).unwrap();
    assert!(!wal.is_empty());
    assert!(unsynced_counts(&dir.0).is_err());
    assert!(fs::read(config::db_file(&dir.0)).unwrap() == before);
    assert!(fs::read(dir.0.join("notes.db-wal")).unwrap() == wal);
    storage.checkpoint().unwrap();
    drop(storage);
    assert_eq!(unsynced_counts(&dir.0).unwrap().in_flight, 1);
}
#[tokio::test]
async fn real_server_replacement_keeps_account_device_and_rebuilds_same_vault_without_push() {
    let server = Server::start().await;
    let dir = TempDir::new();
    let (b, recovery, key) = initialize(&dir.0);
    let auth = server.session(&dir.0, Uuid::new_v4()).await;
    link_local_vault_to_server(&dir.0).await.unwrap();
    let id = notes::create_note(Some(&dir.0), &key, "remote", "server content", vec![]).unwrap();
    perform_sync(Some(&dir.0), Some(&key)).await.unwrap();
    notes::create_note(Some(&dir.0), &key, "discarded", "never upload", vec![]).unwrap();
    let auth_before = fs::read(config::auth_session_file(&dir.0)).unwrap();
    let device_before = fs::read(config::device_file(&dir.0)).unwrap();
    let p = replacement_preflight(&dir.0).await.unwrap();
    assert_eq!(p.counts.pending, 1);
    let before = server.pushes.load(Ordering::SeqCst);
    let stage = stage_remote_vault(&dir.0, &p, UnlockSecret::RecoveryKey(&recovery), true, true)
        .await
        .unwrap();
    vault_files::install(&dir.0, stage).unwrap();
    assert_eq!(server.pushes.load(Ordering::SeqCst), before);
    assert_eq!(local_bootstrap(&dir.0).unwrap(), b);
    assert_eq!(unsynced_counts(&dir.0).unwrap(), UnsyncedCounts::default());
    assert_eq!(
        fs::read(config::auth_session_file(&dir.0)).unwrap(),
        auth_before
    );
    assert_eq!(
        fs::read(config::device_file(&dir.0)).unwrap(),
        device_before
    );
    assert_eq!(
        notes::get_note(Some(&dir.0), &key, &id).unwrap().body,
        "server content"
    );
    assert_eq!(
        server
            .state
            .db
            .get_vault_bootstrap(auth.account_id)
            .await
            .unwrap()
            .unwrap(),
        b
    );
}

#[tokio::test]
async fn real_server_guard_checks_remote_and_server_identity_before_any_sync_request() {
    let s = Server::start().await;
    let dir = TempDir::new();
    let (b, _, _) = initialize(&dir.0);
    let a = s.session(&dir.0, Uuid::new_v4()).await;
    VaultLink::new(&a, fingerprint(&b).unwrap())
        .unwrap()
        .save(&dir.0)
        .unwrap();
    assert!(matches!(
        perform_sync(Some(&dir.0), None).await,
        Err(CliError::VaultLink(LinkError::RemoteVaultMissing))
    ));
    let other = TempDir::new();
    let (other_b, _, _) = initialize(&other.0);
    s.state
        .db
        .create_vault_bootstrap(a.account_id, &other_b)
        .await
        .unwrap();
    assert!(matches!(
        perform_sync(Some(&dir.0), None).await,
        Err(CliError::VaultLink(LinkError::RemoteVaultMismatch))
    ));
    let mut wrong_server = a.clone();
    wrong_server.server_url = "https://wrong.example.com".into();
    save_auth_session(&config::auth_session_file(&dir.0), &wrong_server).unwrap();
    assert!(matches!(
        perform_sync(Some(&dir.0), None).await,
        Err(CliError::VaultLink(LinkError::WrongServer))
    ));
    assert_eq!(s.pulls.load(Ordering::SeqCst), 0);
    assert_eq!(s.pushes.load(Ordering::SeqCst), 0);
}
#[test]
fn vault_cli_commands_parse_and_secrets_are_redacted() {
    use clap::Parser;
    for args in [
        vec!["zk-note", "vault", "status"],
        vec!["zk-note", "vault", "link"],
        vec!["zk-note", "vault", "restore", "--recovery-key"],
        vec![
            "zk-note",
            "vault",
            "restore",
            "--passphrase",
            "CLI-SECRET-CANARY",
        ],
        vec![
            "zk-note",
            "vault",
            "replace-from-server",
            "--discard-local",
            "--recovery-key",
            "CLI-RECOVERY-CANARY",
        ],
        vec![
            "zk-note",
            "login",
            "--server",
            "https://example.com",
            "--token",
            "fixture-token",
        ],
    ] {
        let parsed = crate::Cli::try_parse_from(args).unwrap();
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("CLI-SECRET-CANARY"));
        assert!(!debug.contains("CLI-RECOVERY-CANARY"));
    }
    assert!(crate::Cli::try_parse_from([
        "zk-note",
        "vault",
        "restore",
        "--passphrase",
        "x",
        "--recovery-key",
        "y"
    ])
    .is_err());
}

#[tokio::test]
async fn bootstrap_http_parse_and_post_failures_preserve_active_files_and_do_not_reflect_errors() {
    let server = Server::start().await;
    let dir = TempDir::new();
    let (b, _, _) = initialize(&dir.0);
    server.session(&dir.0, Uuid::new_v4()).await;
    for mode in [1, 2, 3] {
        server.bootstrap_failure.store(mode, Ordering::SeqCst);
        let result = if mode == 3 {
            link_local_vault_to_server(&dir.0).await.map(|_| ())
        } else {
            replacement_preflight(&dir.0).await.map(|_| ())
        };
        let error = result.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("UNTRUSTED-ERROR-CANARY"));
        assert_eq!(local_bootstrap(&dir.0).unwrap(), b);
        assert!(!config::db_file(&dir.0).exists());
        assert!(!dir.0.join("vault-link.json").exists());
        assert_eq!(server.pushes.load(Ordering::SeqCst), 0);
        assert_eq!(server.pulls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn wrong_secret_and_actual_staged_db_creation_failure_leave_empty_machine_uninitialized() {
    let origin = TempDir::new();
    let (b, _, _) = initialize(&origin.0);
    let a = Instrumented::default();
    a.inner.post_vault_bootstrap(&b).await.unwrap();
    for mode in 0..3 {
        let dir = TempDir::new();
        let p = preflight(&dir.0, &auth(), b.clone());
        let secret = match mode {
            0 => UnlockSecret::Passphrase(b"wrong"),
            1 => UnlockSecret::RecoveryKey("wrong key"),
            _ => UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"),
        };
        let result = stage_with_hook(&dir.0, &p, secret, &a, |n, stage| {
            if mode == 2 && n == 2 {
                fs::create_dir(stage.join("notes.db")).unwrap();
            }
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(!config::vault_file(&dir.0).exists());
        assert!(!config::db_file(&dir.0).exists());
        assert!(!dir.0.join("vault-link.json").exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
        assert_eq!(a.push.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn real_server_different_local_vault_replacement_requires_discard_and_never_pushes_old_work()
{
    let server = Server::start().await;
    let remote = TempDir::new();
    let (b, _, remote_key) = initialize(&remote.0);
    let account = Uuid::new_v4();
    server.session(&remote.0, account).await;
    link_local_vault_to_server(&remote.0).await.unwrap();
    let id = notes::create_note(
        Some(&remote.0),
        &remote_key,
        "remote",
        "target content",
        vec![],
    )
    .unwrap();
    perform_sync(Some(&remote.0), Some(&remote_key))
        .await
        .unwrap();
    let local = TempDir::new();
    let (old, _, old_key) = initialize(&local.0);
    notes::create_note(
        Some(&local.0),
        &old_key,
        "discard",
        "never push old content",
        vec![],
    )
    .unwrap();
    server.session(&local.0, account).await;
    let p = replacement_preflight(&local.0).await.unwrap();
    assert_ne!(
        p.current_fingerprint.as_ref().unwrap(),
        &p.target_link.vault_fingerprint
    );
    let pushes = server.pushes.load(Ordering::SeqCst);
    assert!(matches!(
        stage_remote_vault(
            &local.0,
            &p,
            UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"),
            true,
            false
        )
        .await,
        Err(CliError::VaultLink(LinkError::ConfirmationRequired))
    ));
    assert_eq!(local_bootstrap(&local.0).unwrap(), old);
    let stage = stage_remote_vault(
        &local.0,
        &p,
        UnlockSecret::Passphrase(b"LOCAL-PASS-CANARY"),
        true,
        true,
    )
    .await
    .unwrap();
    vault_files::install(&local.0, stage).unwrap();
    assert_eq!(local_bootstrap(&local.0).unwrap(), b);
    assert_eq!(server.pushes.load(Ordering::SeqCst), pushes);
    assert_eq!(
        notes::get_note(Some(&local.0), &remote_key, &id)
            .unwrap()
            .body,
        "target content"
    );
    assert_eq!(
        unsynced_counts(&local.0).unwrap(),
        UnsyncedCounts::default()
    );
}
