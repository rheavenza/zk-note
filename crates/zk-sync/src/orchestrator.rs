//! Pull-before-push synchronization orchestrator (ZK-045).
//!
//! In accordance with MASTER_SPEC.md § 9.6:
//!
//! Default sync cycle:
//! 1. load local durable cursor (and reset stuck in-flight mutations from interrupted runs)
//! 2. PULL remote changes after cursor
//! 3. durably store encrypted remote changes
//! 4. decrypt/apply while unlocked (or defer if locked)
//! 5. reconcile against local pending mutations
//! 6. PUSH pending mutations (with CAS expected_revision)
//! 7. handle accepted/conflicted results
//! 8. PULL once more if pushes produced remote-visible sequences
//! 9. persist final cursor
//!
//! Guarantees:
//! - Deterministic execution order.
//! - Retryable network failures never drop mutations or corrupt cursors.
//! - Final cursor is consistent with durably committed server sequences.
//! - No mutation is silently dropped under any condition.

use crate::adapter::SyncServerAdapter;
use crate::cursor::{CursorError, DurableSyncCursor};
use crate::error::SyncNetworkError;
use crate::pull::{pull_remote_changes, pull_with_session, PullError, PullOptions, PullReport};
use crate::push::{push_pending_changes, PushError, PushOptions, PushReport};
use crate::queue::{PendingMutationQueue, QueueError};
use std::fmt;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_storage::error::StorageError;
use zk_storage::traits::{
    BaseVersionStore, ConflictStore, MutationStore, ObjectStore, SyncStateStore,
};

/// Configuration options for a full synchronization cycle.
#[derive(Debug, Clone, Default)]
pub struct SyncCycleOptions {
    /// Options controlling pull behavior (pagination, batch size, locked deferral).
    pub pull_options: PullOptions,
    /// Options controlling push behavior (limits, conflict handling).
    pub push_options: PushOptions,
    /// If true, always performs a follow-up pull even if no mutations were accepted.
    pub always_followup_pull: bool,
}

/// Comprehensive summary report of an orchestrated sync cycle.
#[derive(Debug, Clone)]
pub struct SyncCycleReport {
    /// Summary of the initial pull phase.
    pub initial_pull: PullReport,
    /// Summary of the push pending mutations phase.
    pub push: PushReport,
    /// Summary of the follow-up pull phase (if executed).
    pub followup_pull: Option<PullReport>,
    /// Durable cursor at the beginning of the sync cycle.
    pub initial_cursor: u64,
    /// Durable cursor at the end of the sync cycle.
    pub final_cursor: u64,
    /// Total mutations successfully accepted by the server.
    pub mutations_accepted: usize,
    /// Total mutations encountering revision conflicts.
    pub mutations_conflicted: usize,
    /// Total mutations remaining in the queue after sync.
    pub mutations_remaining: usize,
}

/// Errors that can occur during an orchestrated sync cycle.
#[derive(Debug)]
pub enum SyncCycleError {
    /// Direct network or transport failure.
    Network(SyncNetworkError),
    /// Pull phase error.
    Pull(PullError),
    /// Push phase error.
    Push(PushError),
    /// Pending mutation queue error.
    Queue(QueueError),
    /// Durable sync cursor error.
    Cursor(CursorError),
    /// Local storage error.
    Storage(StorageError),
}

impl SyncCycleError {
    /// Returns true if this error represents a transient failure (e.g. dropped network connection,
    /// server 5xx, or rate limit) that can be safely retried without user intervention.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(net) => net.is_retryable(),
            Self::Pull(PullError::Network(net)) => net.is_retryable(),
            Self::Push(PushError::Network(net)) => net.is_retryable(),
            _ => false,
        }
    }
}

impl fmt::Display for SyncCycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(err) => write!(f, "sync cycle network error: {err}"),
            Self::Pull(err) => write!(f, "sync cycle pull error: {err}"),
            Self::Push(err) => write!(f, "sync cycle push error: {err}"),
            Self::Queue(err) => write!(f, "sync cycle queue error: {err}"),
            Self::Cursor(err) => write!(f, "sync cycle cursor error: {err}"),
            Self::Storage(err) => write!(f, "sync cycle storage error: {err}"),
        }
    }
}

impl std::error::Error for SyncCycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(err) => Some(err),
            Self::Pull(err) => Some(err),
            Self::Push(err) => Some(err),
            Self::Queue(err) => Some(err),
            Self::Cursor(err) => Some(err),
            Self::Storage(err) => Some(err),
        }
    }
}

impl From<SyncNetworkError> for SyncCycleError {
    fn from(err: SyncNetworkError) -> Self {
        Self::Network(err)
    }
}

impl From<PullError> for SyncCycleError {
    fn from(err: PullError) -> Self {
        Self::Pull(err)
    }
}

impl From<PushError> for SyncCycleError {
    fn from(err: PushError) -> Self {
        Self::Push(err)
    }
}

impl From<QueueError> for SyncCycleError {
    fn from(err: QueueError) -> Self {
        Self::Queue(err)
    }
}

impl From<CursorError> for SyncCycleError {
    fn from(err: CursorError) -> Self {
        Self::Cursor(err)
    }
}

impl From<StorageError> for SyncCycleError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

/// Executes a deterministic pull-before-push sync cycle without an active interactive session
/// (locked sync or with explicit optional [`VaultKey`]).
pub async fn run_sync_cycle<A, S>(
    adapter: &A,
    cursor: &DurableSyncCursor<S>,
    queue: &PendingMutationQueue<S>,
    storage: &S,
    vault_key: Option<&VaultKey>,
    options: SyncCycleOptions,
) -> Result<SyncCycleReport, SyncCycleError>
where
    A: SyncServerAdapter,
    S: ObjectStore + SyncStateStore + MutationStore + BaseVersionStore + ConflictStore,
{
    // Step 1: Crash recovery - reset any stuck InFlight mutations back to Pending (SEC-007)
    let _ = queue.reset_in_flight();

    // Load initial durable cursor
    let initial_cursor = cursor.current_cursor()?;

    // Step 2, 3, 4: PULL remote changes after cursor and store durably
    let initial_pull = pull_remote_changes(
        adapter,
        storage,
        cursor,
        vault_key,
        options.pull_options.clone(),
    )
    .await?;

    // Step 5, 6, 7: PUSH pending mutations (CAS checked, accepted cleared, conflicts retained)
    let push_report = push_pending_changes(adapter, queue, options.push_options.clone()).await?;

    // Step 8: Follow-up PULL if pushes produced remote-visible sequences
    let followup_pull = if !push_report.accepted.is_empty() || options.always_followup_pull {
        let followup = pull_remote_changes(
            adapter,
            storage,
            cursor,
            vault_key,
            options.pull_options.clone(),
        )
        .await?;
        Some(followup)
    } else {
        None
    };

    // Step 9: Final cursor and remaining mutations count
    let final_cursor = cursor.current_cursor()?;
    let mutations_remaining = queue.pending_count()?;
    let mutations_accepted = push_report.accepted.len();
    let mutations_conflicted = push_report.conflicts.len();

    Ok(SyncCycleReport {
        initial_pull,
        push: push_report,
        followup_pull,
        initial_cursor,
        final_cursor,
        mutations_accepted,
        mutations_conflicted,
        mutations_remaining,
    })
}

/// Executes a deterministic pull-before-push sync cycle with an active interactive [`VaultSession`],
/// updating in-memory decrypted search indexes if unlocked.
pub async fn run_sync_cycle_with_session<A, S>(
    adapter: &A,
    cursor: &DurableSyncCursor<S>,
    queue: &PendingMutationQueue<S>,
    storage: &S,
    session: &mut VaultSession,
    options: SyncCycleOptions,
) -> Result<SyncCycleReport, SyncCycleError>
where
    A: SyncServerAdapter,
    S: ObjectStore + SyncStateStore + MutationStore + BaseVersionStore + ConflictStore,
{
    // Step 1: Crash recovery - reset any stuck InFlight mutations back to Pending (SEC-007)
    let _ = queue.reset_in_flight();

    // Load initial durable cursor
    let initial_cursor = cursor.current_cursor()?;

    // Step 2, 3, 4: PULL remote changes after cursor and update session index
    let initial_pull = pull_with_session(
        adapter,
        storage,
        cursor,
        session,
        options.pull_options.clone(),
    )
    .await?;

    // Step 5, 6, 7: PUSH pending mutations (CAS checked, accepted cleared, conflicts retained)
    let push_report = push_pending_changes(adapter, queue, options.push_options.clone()).await?;

    // Step 8: Follow-up PULL if pushes produced remote-visible sequences
    let followup_pull = if !push_report.accepted.is_empty() || options.always_followup_pull {
        let followup = pull_with_session(
            adapter,
            storage,
            cursor,
            session,
            options.pull_options.clone(),
        )
        .await?;
        Some(followup)
    } else {
        None
    };

    // Step 9: Final cursor and remaining mutations count
    let final_cursor = cursor.current_cursor()?;
    let mutations_remaining = queue.pending_count()?;
    let mutations_accepted = push_report.accepted.len();
    let mutations_conflicted = push_report.conflicts.len();

    Ok(SyncCycleReport {
        initial_pull,
        push: push_report,
        followup_pull,
        initial_cursor,
        final_cursor,
        mutations_accepted,
        mutations_conflicted,
        mutations_remaining,
    })
}

/// High-level synchronization engine orchestrating client pull/push workflows.
#[derive(Debug, Clone)]
pub struct SyncEngine<A, S> {
    adapter: A,
    cursor: DurableSyncCursor<S>,
    queue: PendingMutationQueue<S>,
    storage: S,
}

impl<A, S> SyncEngine<A, S>
where
    A: SyncServerAdapter,
    S: ObjectStore + SyncStateStore + MutationStore + BaseVersionStore + ConflictStore + Clone,
{
    /// Creates a new [`SyncEngine`] wrapping the network adapter and storage backend.
    pub fn new(adapter: A, storage: S) -> Self {
        let cursor = DurableSyncCursor::new(storage.clone());
        let queue = PendingMutationQueue::new(storage.clone());
        Self {
            adapter,
            cursor,
            queue,
            storage,
        }
    }

    /// Returns a reference to the network adapter.
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Returns a reference to the durable sync cursor.
    pub fn cursor(&self) -> &DurableSyncCursor<S> {
        &self.cursor
    }

    /// Returns a reference to the pending mutation queue.
    pub fn queue(&self) -> &PendingMutationQueue<S> {
        &self.queue
    }

    /// Returns a reference to the underlying storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Executes a sync cycle without an active session (locked sync).
    pub async fn sync(&self, options: SyncCycleOptions) -> Result<SyncCycleReport, SyncCycleError> {
        run_sync_cycle(
            &self.adapter,
            &self.cursor,
            &self.queue,
            &self.storage,
            None,
            options,
        )
        .await
    }

    /// Executes a sync cycle with an explicit optional [`VaultKey`].
    pub async fn sync_with_key(
        &self,
        vault_key: Option<&VaultKey>,
        options: SyncCycleOptions,
    ) -> Result<SyncCycleReport, SyncCycleError> {
        run_sync_cycle(
            &self.adapter,
            &self.cursor,
            &self.queue,
            &self.storage,
            vault_key,
            options,
        )
        .await
    }

    /// Executes a sync cycle with an active [`VaultSession`].
    pub async fn sync_with_session(
        &self,
        session: &mut VaultSession,
        options: SyncCycleOptions,
    ) -> Result<SyncCycleReport, SyncCycleError> {
        run_sync_cycle_with_session(
            &self.adapter,
            &self.cursor,
            &self.queue,
            &self.storage,
            session,
            options,
        )
        .await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapter::MockSyncAdapter;
    use zk_core::note::PlaintextNote;
    use zk_protocol::constants::OBJECT_KIND_NOTE;
    use zk_protocol::sync::PushRequest;
    use zk_storage::memory::MemoryStorage;

    fn sample_envelope(
        vault_key: &VaultKey,
        obj_id: &str,
        title: &str,
    ) -> zk_protocol::envelope::EncryptedEnvelope {
        let note = PlaintextNote::new(title, format!("Body for {title}"));
        note.encrypt(vault_key, obj_id).expect("encrypt")
    }

    #[tokio::test]
    async fn test_deterministic_sync_cycle_execution() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let engine = SyncEngine::new(adapter, storage.clone());
        let vault_key = VaultKey::generate();

        // 1. Remote server has 1 existing note (server_seq: 1)
        let remote_env = sample_envelope(&vault_key, "remote-1", "Remote Note");
        let remote_req = PushRequest {
            mutation_id: "mut-remote-1".to_string(),
            object_id: "remote-1".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: remote_env,
            is_deleted: false,
        };
        engine.adapter().push_mutation(&remote_req).await.unwrap();

        // 2. Client has 1 local pending edit (note-local-1)
        let local_env = sample_envelope(&vault_key, "local-1", "Local Note");
        engine
            .queue()
            .enqueue_local_note_upsert("local-1", local_env)
            .unwrap();

        assert_eq!(engine.cursor().current_cursor().unwrap(), 0);
        assert_eq!(engine.queue().pending_count().unwrap(), 1);

        // 3. Execute sync cycle
        let report = engine
            .sync_with_key(Some(&vault_key), SyncCycleOptions::default())
            .await
            .expect("sync cycle succeeds");

        // Assert deterministic flow:
        // - Initial pull fetched remote-1 (server_seq: 1)
        assert_eq!(report.initial_pull.applied_changes, 1);
        assert_eq!(report.initial_cursor, 0);

        // - Push submitted local-1, server allocated revision 1, server_seq 2
        assert_eq!(report.mutations_accepted, 1);
        assert_eq!(report.push.accepted.len(), 1);
        assert_eq!(report.push.accepted[0].server_seq, 2);

        // - Follow-up pull advanced cursor to 2
        assert!(report.followup_pull.is_some());
        assert_eq!(report.final_cursor, 2);
        assert_eq!(engine.cursor().current_cursor().unwrap(), 2);

        // - Queue is cleared and both objects exist in local storage
        assert_eq!(report.mutations_remaining, 0);
        assert_eq!(engine.queue().pending_count().unwrap(), 0);
        assert!(storage.get_object("remote-1").unwrap().is_some());
        assert!(storage.get_object("local-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn test_retryable_network_failure_leaves_queue_and_cursor_intact() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let engine = SyncEngine::new(adapter, storage.clone());
        let vault_key = VaultKey::generate();

        let local_env = sample_envelope(&vault_key, "retry-1", "Retry Note");
        let mut_item = engine
            .queue()
            .enqueue_local_note_upsert("retry-1", local_env)
            .unwrap();

        // Inject network failure on first pull
        engine
            .adapter()
            .set_fail_next(Some(SyncNetworkError::ConnectionFailed(
                "network down".to_string(),
            )));

        let err = engine.sync(SyncCycleOptions::default()).await.unwrap_err();
        assert!(err.is_retryable());

        // Invariant: cursor and queue are intact, NO MUTATIONS DROPPED
        assert_eq!(engine.cursor().current_cursor().unwrap(), 0);
        assert_eq!(engine.queue().pending_count().unwrap(), 1);
        let queued = engine
            .queue()
            .get_mutation(&mut_item.mutation_id)
            .unwrap()
            .unwrap();
        assert_eq!(queued.object_id, "retry-1");

        // Retry succeeds cleanly once network is back
        let report = engine
            .sync(SyncCycleOptions::default())
            .await
            .expect("retry succeeds");
        assert_eq!(report.mutations_accepted, 1);
        assert_eq!(report.final_cursor, 1);
        assert_eq!(engine.queue().pending_count().unwrap(), 0);
    }
}
