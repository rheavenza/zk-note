//! Explicit native vault association and pull-only onboarding; no printing or UI.
use super::{
    auth::validate_and_normalize_server_url,
    vault_files::{self, StagedVault},
};
use crate::{
    auth::{api_query_status, load_auth_session, StoredAuthSession},
    config,
    error::CliError,
};
use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::Path, sync::Arc};
use uuid::Uuid;
use zk_core::{
    vault::VaultManager,
    vault_identity::{validate_bootstrap, vault_fingerprint},
};
use zk_protocol::vault::VaultBootstrap;
use zk_storage::{
    models::MutationStatus,
    traits::{ConflictStore, MutationStore, ObjectStore, SyncStateStore},
    SqliteStorage,
};
use zk_sync::{
    adapter::{NativeHttpSyncAdapter, SyncServerAdapter},
    cursor::DurableSyncCursor,
    pull::{pull_remote_changes, PullOptions},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    MissingLink,
    CorruptLink,
    WrongAccount,
    WrongServer,
    LocalVaultMismatch,
    RemoteVaultMissing,
    RemoteVaultMismatch,
    InvalidBootstrap,
    ConfirmationRequired,
}
impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingLink => "local vault is unlinked; explicitly link or restore before sync",
            Self::CorruptLink => "corrupt vault link; sync disabled",
            Self::WrongAccount => "vault linked to another account; sync disabled",
            Self::WrongServer => "vault linked to another server; sync disabled",
            Self::LocalVaultMismatch => "local vault identity differs from its link; sync disabled",
            Self::RemoteVaultMissing => "remote vault bootstrap is missing; sync disabled",
            Self::RemoteVaultMismatch => {
                "remote vault identity differs; explicit local replacement required"
            }
            Self::InvalidBootstrap => "invalid or unsupported vault bootstrap",
            Self::ConfirmationRequired => {
                "replacement requires explicit confirmation to discard local changes"
            }
        })
    }
}
impl From<LinkError> for CliError {
    fn from(e: LinkError) -> Self {
        Self::VaultLink(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultLink {
    pub format_version: u32,
    pub server_origin: String,
    pub account_id: Uuid,
    pub vault_fingerprint: String,
}
impl VaultLink {
    fn new(auth: &StoredAuthSession, fingerprint: String) -> Result<Self, CliError> {
        Ok(Self {
            format_version: 1,
            server_origin: validate_and_normalize_server_url(&auth.server_url)?,
            account_id: auth.account_id,
            vault_fingerprint: fingerprint,
        })
    }
    pub fn save(&self, dir: &Path) -> Result<(), CliError> {
        self.validate()?;
        vault_files::atomic_write(
            &dir.join("vault-link.json"),
            &serde_json::to_vec_pretty(self).map_err(|_| LinkError::CorruptLink)?,
        )
    }
    fn validate(&self) -> Result<(), CliError> {
        if self.format_version != 1
            || validate_and_normalize_server_url(&self.server_origin)
                .ok()
                .as_deref()
                != Some(&self.server_origin)
            || !self.vault_fingerprint.starts_with("blake2s-v1:")
            || self.vault_fingerprint.len() != 75
            || !self.vault_fingerprint[11..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(LinkError::CorruptLink.into());
        }
        Ok(())
    }
}
pub fn load_link(dir: &Path) -> Result<VaultLink, CliError> {
    let bytes = fs::read(dir.join("vault-link.json")).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::from(LinkError::MissingLink)
        } else {
            CliError::from(LinkError::CorruptLink)
        }
    })?;
    let link: VaultLink = serde_json::from_slice(&bytes).map_err(|_| LinkError::CorruptLink)?;
    link.validate()?;
    Ok(link)
}
fn fingerprint(b: &VaultBootstrap) -> Result<String, CliError> {
    vault_fingerprint(b).map_err(|_| LinkError::InvalidBootstrap.into())
}
pub fn local_bootstrap(dir: &Path) -> Result<VaultBootstrap, CliError> {
    let b = serde_json::from_slice(&fs::read(config::vault_file(dir))?)
        .map_err(|_| LinkError::InvalidBootstrap)?;
    validate_bootstrap(&b).map_err(|_| LinkError::InvalidBootstrap)?;
    Ok(b)
}
/// Check local binding before constructing/requesting any sync transport.
pub fn validate_local_link(dir: &Path, auth: &StoredAuthSession) -> Result<VaultLink, CliError> {
    vault_files::recover(dir)?;
    let link = load_link(dir)?;
    if link.account_id != auth.account_id {
        return Err(LinkError::WrongAccount.into());
    }
    if link.server_origin != validate_and_normalize_server_url(&auth.server_url)? {
        return Err(LinkError::WrongServer.into());
    }
    if link.vault_fingerprint != fingerprint(&local_bootstrap(dir)?)? {
        return Err(LinkError::LocalVaultMismatch.into());
    }
    Ok(link)
}
pub async fn validate_remote_link<A: SyncServerAdapter>(
    link: &VaultLink,
    adapter: &A,
) -> Result<(), CliError> {
    let b = adapter
        .get_vault_bootstrap()
        .await
        .map_err(|_| CliError::Network("cannot verify remote vault".into()))?
        .ok_or(LinkError::RemoteVaultMissing)?;
    if fingerprint(&b)? != link.vault_fingerprint {
        return Err(LinkError::RemoteVaultMismatch.into());
    }
    Ok(())
}
pub fn adapter(auth: &StoredAuthSession) -> Result<NativeHttpSyncAdapter, CliError> {
    NativeHttpSyncAdapter::with_client(
        validate_and_normalize_server_url(&auth.server_url)?,
        Some(auth.token.expose_secret().to_string()),
        crate::auth::auth_http_client()?,
    )
    .map_err(|_| CliError::Network("cannot initialize vault transport".into()))
}
async fn verified_auth(dir: &Path) -> Result<StoredAuthSession, CliError> {
    vault_files::recover(dir)?;
    let mut auth = load_auth_session(&config::auth_session_file(dir))?;
    auth.server_url = validate_and_normalize_server_url(&auth.server_url)?;
    let status = api_query_status(&auth).await?;
    if status.status != "active"
        || status.account_id != auth.account_id
        || status.device_id != Some(auth.device_id)
        || status.session_id != auth.session_id
    {
        return Err(CliError::AuthError(
            "server session identity does not match saved authentication".into(),
        ));
    }
    Ok(auth)
}

#[derive(Debug)]
pub struct VaultInspection {
    pub local_fingerprint: Option<String>,
    pub link: Option<VaultLink>,
    pub status: String,
    pub remote_fingerprint: Option<String>,
}
pub async fn inspect_vault_link(dir: &Path) -> Result<VaultInspection, CliError> {
    vault_files::recover(dir)?;
    let local = if config::vault_file(dir).exists() {
        Some(fingerprint(&local_bootstrap(dir)?)?)
    } else {
        None
    };
    let link_result = load_link(dir);
    let mut status = match &link_result {
        Ok(_) => "Linked (remote not verified)".into(),
        Err(e) => e.to_string(),
    };
    let link = link_result.ok();
    let auth = load_auth_session(&config::auth_session_file(dir));
    let mut remote = None;
    if let Ok(auth) = auth {
        if local.is_some() {
            if let Err(e) = validate_local_link(dir, &auth) {
                status = e.to_string();
            }
        }
        let b = adapter(&auth)?
            .get_vault_bootstrap()
            .await
            .map_err(|_| CliError::Network("cannot inspect remote vault".into()))?;
        remote = b.as_ref().map(fingerprint).transpose()?;
        if let Some(l) = &link {
            if remote.is_none() {
                status = LinkError::RemoteVaultMissing.to_string();
            } else if remote.as_ref() != Some(&l.vault_fingerprint) {
                status = LinkError::RemoteVaultMismatch.to_string();
            } else if validate_local_link(dir, &auth).is_ok() {
                status = "Linked (verified remote vault identity)".into();
            }
        }
    }
    Ok(VaultInspection {
        local_fingerprint: local,
        link,
        status,
        remote_fingerprint: remote,
    })
}
pub async fn link_local_vault_to_server(dir: &Path) -> Result<VaultLink, CliError> {
    let auth = verified_auth(dir).await?;
    link_with_adapter(dir, &auth, &adapter(&auth)?).await
}
async fn link_with_adapter<A: SyncServerAdapter>(
    dir: &Path,
    auth: &StoredAuthSession,
    adapter: &A,
) -> Result<VaultLink, CliError> {
    let b = local_bootstrap(dir)?;
    let link = VaultLink::new(auth, fingerprint(&b)?)?;
    // An existing association never silently changes, even for the same vault.
    match load_link(dir) {
        Ok(_) => {
            validate_local_link(dir, auth)?;
        }
        Err(CliError::VaultLink(LinkError::MissingLink)) => {}
        Err(e) => return Err(e),
    }
    let remote = adapter
        .get_vault_bootstrap()
        .await
        .map_err(|_| CliError::Network("cannot inspect remote vault".into()))?;
    if let Some(remote) = remote {
        if fingerprint(&remote)? != link.vault_fingerprint {
            return Err(LinkError::RemoteVaultMismatch.into());
        }
    } else {
        adapter.post_vault_bootstrap(&b).await.map_err(|_| {
            CliError::Network(
                "remote bootstrap creation failed; local vault remains unlinked".into(),
            )
        })?;
    }
    validate_remote_link(&link, adapter).await?;
    link.save(dir)?;
    Ok(link)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UnsyncedCounts {
    pub pending: usize,
    pub in_flight: usize,
    pub failed: usize,
    pub conflicts: usize,
    pub unconfirmed_objects: usize,
}
#[derive(Debug)]
pub struct ReplacePreflight {
    pub current_link: Option<VaultLink>,
    pub current_fingerprint: Option<String>,
    pub target_link: VaultLink,
    pub counts: UnsyncedCounts,
    pub(crate) bootstrap: VaultBootstrap,
    pub(crate) auth: StoredAuthSession,
}
pub fn unsynced_counts(dir: &Path) -> Result<UnsyncedCounts, CliError> {
    let mut counts = UnsyncedCounts::default();
    if !config::db_file(dir).exists() {
        return Ok(counts);
    }
    let storage = SqliteStorage::open_read_only(config::db_file(dir))?;
    for m in storage.list_pending_mutations()? {
        match m.status {
            MutationStatus::Pending => counts.pending += 1,
            MutationStatus::InFlight => counts.in_flight += 1,
            MutationStatus::Failed => counts.failed += 1,
        }
    }
    counts.conflicts = storage.list_conflicts(Some(false))?.len();
    counts.unconfirmed_objects = storage
        .list_objects(&zk_storage::models::ObjectFilter::all())?
        .iter()
        .filter(|o| o.server_seq == 0)
        .count();
    Ok(counts)
}
pub async fn replacement_preflight(dir: &Path) -> Result<ReplacePreflight, CliError> {
    let auth = verified_auth(dir).await?;
    let b = adapter(&auth)?
        .get_vault_bootstrap()
        .await
        .map_err(|_| CliError::Network("cannot fetch remote bootstrap".into()))?
        .ok_or(LinkError::RemoteVaultMissing)?;
    let target_link = VaultLink::new(&auth, fingerprint(&b)?)?;
    Ok(ReplacePreflight {
        current_link: load_link(dir).ok(),
        current_fingerprint: if config::vault_file(dir).exists() {
            Some(fingerprint(&local_bootstrap(dir)?)?)
        } else {
            None
        },
        target_link,
        counts: unsynced_counts(dir)?,
        bootstrap: b,
        auth,
    })
}
/// Never formats or stores the supplied secret. The caller uses zeroizing storage.
pub enum UnlockSecret<'a> {
    Passphrase(&'a [u8]),
    RecoveryKey(&'a str),
}
impl fmt::Debug for UnlockSecret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnlockSecret([REDACTED])")
    }
}

pub async fn stage_remote_vault(
    dir: &Path,
    preflight: &ReplacePreflight,
    secret: UnlockSecret<'_>,
    replace: bool,
    discard_confirmed: bool,
) -> Result<StagedVault, CliError> {
    if replace && !discard_confirmed {
        return Err(LinkError::ConfirmationRequired.into());
    }
    if !replace
        && (config::vault_file(dir).exists()
            || config::db_file(dir).exists()
            || dir.join("vault-link.json").exists())
    {
        return Err(CliError::VaultAlreadyInitialized);
    }
    let current = verified_auth(dir).await?;
    if current != preflight.auth {
        return Err(CliError::AuthError(
            "authentication changed after preflight".into(),
        ));
    }
    let a = adapter(&current)?;
    validate_remote_link(&preflight.target_link, &a).await?;
    stage_with_adapter(dir, preflight, secret, &a).await
}
async fn stage_with_adapter<A: SyncServerAdapter>(
    dir: &Path,
    preflight: &ReplacePreflight,
    secret: UnlockSecret<'_>,
    a: &A,
) -> Result<StagedVault, CliError> {
    stage_with_hook(dir, preflight, secret, a, |_, _| Ok(())).await
}
async fn stage_with_hook<A: SyncServerAdapter>(
    dir: &Path,
    preflight: &ReplacePreflight,
    secret: UnlockSecret<'_>,
    a: &A,
    mut hook: impl FnMut(usize, &Path) -> Result<(), CliError>,
) -> Result<StagedVault, CliError> {
    validate_bootstrap(&preflight.bootstrap).map_err(|_| LinkError::InvalidBootstrap)?;
    let stage = StagedVault::create(dir, preflight.target_link.vault_fingerprint.clone())?;
    hook(0, &stage.dir)?;
    vault_files::atomic_write(
        &config::vault_file(&stage.dir),
        &serde_json::to_vec(&preflight.bootstrap).map_err(|_| LinkError::InvalidBootstrap)?,
    )?;
    hook(1, &stage.dir)?;
    let key = match secret {
        UnlockSecret::Passphrase(p) => {
            VaultManager::unlock_with_passphrase(&preflight.bootstrap, p)?
        }
        UnlockSecret::RecoveryKey(k) => {
            VaultManager::unlock_with_recovery_key(&preflight.bootstrap, k)?
        }
    };
    hook(2, &stage.dir)?;
    {
        let storage = Arc::new(SqliteStorage::open(config::db_file(&stage.dir))?);
        hook(3, &stage.dir)?;
        let cursor = DurableSyncCursor::new(Arc::clone(&storage));
        if cursor
            .current_cursor()
            .map_err(|_| CliError::Io("staged cursor unavailable".into()))?
            != 0
            || storage.pending_mutation_count()? != 0
        {
            return Err(CliError::Io("staging database is not empty".into()));
        }
        // Shared pull ONLY, never SyncEngine or push. Validate decrypted envelopes
        // in memory with the recovered key; nothing plaintext is persisted or sent.
        let mut report = pull_remote_changes(
            a,
            storage.as_ref(),
            &cursor,
            Some(&key),
            PullOptions::default(),
        )
        .await
        .map_err(|_| {
            CliError::Network(
                "remote pull or ciphertext validation failed; active vault unchanged".into(),
            )
        })?;
        // Decrypted validation output is unnecessary after verification.
        use zeroize::Zeroize;
        for item in &mut report.decrypted_items {
            if let Some(note) = &mut item.note {
                note.title.zeroize();
                note.body.zeroize();
                note.tags.zeroize();
            }
        }
        hook(4, &stage.dir)?;
        if storage.get_sync_state()?.sync_cursor != report.final_cursor
            || storage.pending_mutation_count()? != 0
        {
            return Err(CliError::Io("staged cursor verification failed".into()));
        }
        hook(5, &stage.dir)?;
        storage.checkpoint()?;
        hook(6, &stage.dir)?;
    }
    let reopened = SqliteStorage::open(config::db_file(&stage.dir))?;
    reopened.checkpoint()?;
    drop(reopened);
    hook(7, &stage.dir)?;
    // WAL must have been checkpointed/closed, never discard uncheckpointed data.
    for name in ["notes.db-wal", "notes.db-shm"] {
        let p = stage.dir.join(name);
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    fs::File::open(config::db_file(&stage.dir))?.sync_all()?;
    hook(8, &stage.dir)?;
    if fingerprint(&local_bootstrap(&stage.dir)?)? != stage.fingerprint {
        return Err(LinkError::LocalVaultMismatch.into());
    }
    preflight.target_link.save(&stage.dir)?;
    hook(9, &stage.dir)?;
    vault_files::sync_dir(&stage.dir)?;
    hook(10, &stage.dir)?;
    validate_remote_link(&preflight.target_link, a).await?;
    hook(11, &stage.dir)?;
    Ok(stage)
}

#[cfg(test)]
mod tests;
