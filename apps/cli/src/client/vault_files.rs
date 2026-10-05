//! Crash-safe native vault replacement. The caller owns NativeDataGuard.
use crate::error::CliError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const FILES: [&str; 5] = [
    "vault.json",
    "notes.db",
    "notes.db-wal",
    "notes.db-shm",
    "vault-link.json",
];
const JOURNAL: &str = ".replace-transaction.json";

/// Held for the entire CLI/TUI lifetime; OS releases it even after process death.
#[derive(Debug)]
pub struct NativeDataGuard {
    _file: File,
}
impl NativeDataGuard {
    pub fn acquire(dir: &Path) -> Result<Self, CliError> {
        fs::create_dir_all(dir)?;
        // Lock the directory descriptor itself: no lock-file write during preflight.
        let file = File::open(dir)?;
        file.try_lock().map_err(|_| {
            CliError::Io("native data directory is in use by another process".into())
        })?;
        recover(dir)?;
        clean_orphans(dir)?;
        Ok(Self { _file: file })
    }
}

// Only at process startup under the exclusive lock: never remove an in-use stage.
fn clean_orphans(dir: &Path) -> Result<(), CliError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if [".replace-", ".backup-"].iter().any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
        }) && entry.file_type()?.is_dir()
        {
            fs::remove_dir_all(entry.path())?;
        }
        if name
            .strip_prefix(".write-")
            .and_then(|s| s.strip_suffix(".tmp"))
            .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    sync_dir(dir)
}

pub fn sync_dir(dir: &Path) -> Result<(), CliError> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Io("missing parent directory".into()))?;
    let tmp = parent.join(format!(".write-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    Prepared,
    OldMoved,
    NewInstalled,
    Committed,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format_version: u32,
    transaction_id: Uuid,
    target_fingerprint: String,
    old_present: [bool; 5],
    phase: Phase,
}
fn paths(dir: &Path, id: Uuid) -> (PathBuf, PathBuf) {
    (
        dir.join(format!(".replace-{id}")),
        dir.join(format!(".backup-{id}")),
    )
}
fn write_journal(dir: &Path, j: &Journal) -> Result<(), CliError> {
    atomic_write(
        &dir.join(JOURNAL),
        &serde_json::to_vec(j)
            .map_err(|_| CliError::Io("cannot encode replacement journal".into()))?,
    )
}

/// Recover before ANY active vault/database open. Uncommitted swaps roll back.
/// Backups are copied, not renamed, during rollback: recovery itself is repeatable
/// after a crash between any two restores. Never trust paths supplied by JSON.
pub fn recover(dir: &Path) -> Result<(), CliError> {
    let bytes = match fs::read(dir.join(JOURNAL)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let j: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| CliError::Io("corrupt replacement journal; vault access refused".into()))?;
    if j.format_version != 1 {
        return Err(CliError::Io("unsupported replacement journal".into()));
    }
    let (stage, backup) = paths(dir, j.transaction_id);
    if j.phase != Phase::Committed {
        for (i, name) in FILES.iter().enumerate() {
            let old = backup.join(name);
            let active = dir.join(name);
            if old.exists() {
                atomic_write(&active, &fs::read(old)?)?;
            } else if !j.old_present[i] {
                if active.exists() {
                    fs::remove_file(active)?;
                }
            } else if j.phase != Phase::Prepared {
                return Err(CliError::Io(
                    "replacement backup missing; vault access refused".into(),
                ));
            }
        }
        sync_dir(dir)?;
    }
    // Removing the journal is the rollback/commit completion point. Keep backups
    // until it is durably removed; a subsequent cleanup crash cannot mix generations.
    fs::remove_file(dir.join(JOURNAL))?;
    sync_dir(dir)?;
    if stage.exists() {
        fs::remove_dir_all(stage)?;
    }
    if backup.exists() {
        fs::remove_dir_all(backup)?;
    }
    sync_dir(dir)
}

/// A fully validated generation. Drop cleans staging; no secret is persisted here.
#[derive(Debug)]
pub struct StagedVault {
    pub(crate) dir: PathBuf,
    pub(crate) id: Uuid,
    pub(crate) fingerprint: String,
}
impl Drop for StagedVault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
impl StagedVault {
    pub(crate) fn create(dir: &Path, fingerprint: String) -> Result<Self, CliError> {
        let id = Uuid::new_v4();
        let (path, _) = paths(dir, id);
        fs::create_dir(&path)?;
        sync_dir(dir)?;
        Ok(Self {
            dir: path,
            id,
            fingerprint,
        })
    }
}

/// Call only after releasing SQLite handles and scrubbing active in-memory keys/UI.
pub fn install(dir: &Path, staged: StagedVault) -> Result<(), CliError> {
    // Main/TUI hold the data-directory lock, and own no long-lived DB handle.
    // Checkpoint the OLD cache too; never rename a live SQLite WAL generation.
    if dir.join("notes.db").exists() {
        let old = zk_storage::SqliteStorage::open(dir.join("notes.db"))?;
        old.checkpoint()?;
        drop(old);
    }
    let result = install_with_hook(dir, staged, |_| Ok(()));
    if result.is_err() {
        recover(dir)?;
    }
    result
}
fn install_with_hook(
    dir: &Path,
    staged: StagedVault,
    mut hook: impl FnMut(usize) -> Result<(), CliError>,
) -> Result<(), CliError> {
    recover(dir)?;
    crate::session::clear_session(&dir.join(".session"))?;
    let (_, backup) = paths(dir, staged.id);
    fs::create_dir(&backup)?;
    sync_dir(dir)?;
    for name in FILES {
        if dir.join(name).exists() {
            File::open(dir.join(name))?.sync_all()?;
        }
    }
    let mut j = Journal {
        format_version: 1,
        transaction_id: staged.id,
        target_fingerprint: staged.fingerprint.clone(),
        old_present: FILES.map(|f| dir.join(f).exists()),
        phase: Phase::Prepared,
    };
    write_journal(dir, &j)?;
    hook(0)?;
    for (i, name) in FILES.iter().enumerate() {
        if j.old_present[i] {
            fs::rename(dir.join(name), backup.join(name))?;
        }
        sync_dir(&backup)?;
        sync_dir(dir)?;
        hook(i + 1)?;
    }
    j.phase = Phase::OldMoved;
    write_journal(dir, &j)?;
    hook(6)?;
    for (i, name) in ["vault.json", "notes.db", "vault-link.json"]
        .iter()
        .enumerate()
    {
        fs::rename(staged.dir.join(name), dir.join(name))?;
        sync_dir(&staged.dir)?;
        sync_dir(dir)?;
        hook(i + 7)?;
    }
    j.phase = Phase::NewInstalled;
    write_journal(dir, &j)?;
    hook(10)?;
    j.phase = Phase::Committed;
    write_journal(dir, &j)?;
    hook(11)?;
    recover(dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn recovery_after_every_swap_transition_is_a_complete_generation() {
        for fail_at in 0..12 {
            let dir = std::env::temp_dir().join(format!("zk-swap-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            for f in FILES {
                fs::write(dir.join(f), b"old").unwrap();
            }
            fs::write(dir.join(".auth_session"), b"auth").unwrap();
            fs::write(dir.join("device.json"), b"device").unwrap();
            let stage = StagedVault::create(&dir, "test".into()).unwrap();
            for f in ["vault.json", "notes.db", "vault-link.json"] {
                fs::write(stage.dir.join(f), b"new").unwrap();
            }
            assert!(install_with_hook(&dir, stage, |n| if n == fail_at {
                Err(CliError::Io("injected crash".into()))
            } else {
                Ok(())
            })
            .is_err());
            recover(&dir).unwrap();
            recover(&dir).unwrap();
            for f in ["vault.json", "notes.db", "vault-link.json"] {
                assert_eq!(
                    fs::read(dir.join(f)).unwrap(),
                    if fail_at == 11 { b"new" } else { b"old" }
                );
            }
            assert_eq!(fs::read(dir.join(".auth_session")).unwrap(), b"auth");
            assert_eq!(fs::read(dir.join("device.json")).unwrap(), b"device");
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod real_generation_tests {
    use super::*;
    use zk_core::{vault_identity::vault_fingerprint, VaultManager};
    use zk_storage::{traits::SyncStateStore, SqliteStorage};
    #[test]
    fn real_sqlite_and_bootstrap_are_coherent_after_every_swap_failure() {
        for fail_at in 0..12 {
            let dir = std::env::temp_dir().join(format!("zk110-real-swap-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let (old, _, old_key) =
                VaultManager::init_vault(b"old", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
            let (new, _, new_key) =
                VaultManager::init_vault(b"new", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
            let old_id = vault_fingerprint(&old).unwrap();
            let new_id = vault_fingerprint(&new).unwrap();
            fs::write(dir.join("vault.json"), serde_json::to_vec(&old).unwrap()).unwrap();
            fs::write(dir.join("vault-link.json"), &old_id).unwrap();
            let db = SqliteStorage::open(dir.join("notes.db")).unwrap();
            db.set_sync_cursor(10).unwrap();
            db.checkpoint().unwrap();
            drop(db);
            let stage = StagedVault::create(&dir, new_id.clone()).unwrap();
            fs::write(
                stage.dir.join("vault.json"),
                serde_json::to_vec(&new).unwrap(),
            )
            .unwrap();
            fs::write(stage.dir.join("vault-link.json"), &new_id).unwrap();
            let db = SqliteStorage::open(stage.dir.join("notes.db")).unwrap();
            db.set_sync_cursor(20).unwrap();
            db.checkpoint().unwrap();
            drop(db);
            assert!(install_with_hook(&dir, stage, |n| if n == fail_at {
                Err(CliError::Io("injected".into()))
            } else {
                Ok(())
            })
            .is_err());
            recover(&dir).unwrap();
            let b = serde_json::from_slice(&fs::read(dir.join("vault.json")).unwrap()).unwrap();
            let installed_id = vault_fingerprint(&b).unwrap();
            let link_id = fs::read_to_string(dir.join("vault-link.json")).unwrap();
            assert_eq!(installed_id, link_id);
            let db = SqliteStorage::open(dir.join("notes.db")).unwrap();
            if fail_at == 11 {
                assert_eq!(installed_id, new_id);
                assert_eq!(db.get_sync_state().unwrap().sync_cursor, 20);
                assert_eq!(
                    VaultManager::unlock_with_passphrase(&b, b"new")
                        .unwrap()
                        .as_bytes(),
                    new_key.as_bytes()
                );
            } else {
                assert_eq!(installed_id, old_id);
                assert_eq!(db.get_sync_state().unwrap().sync_cursor, 10);
                assert_eq!(
                    VaultManager::unlock_with_passphrase(&b, b"old")
                        .unwrap()
                        .as_bytes(),
                    old_key.as_bytes()
                );
            }
            drop(db);
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn native_directory_lock_excludes_a_second_client_and_cleans_orphans_only_at_startup() {
        let dir = std::env::temp_dir().join(format!("zk110-lock-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let orphan = dir.join(format!(".replace-{}", Uuid::new_v4()));
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("vault.json"), b"encrypted bootstrap").unwrap();
        let guard = NativeDataGuard::acquire(&dir).unwrap();
        assert!(!orphan.exists());
        assert!(NativeDataGuard::acquire(&dir).is_err());
        drop(guard);
        assert!(NativeDataGuard::acquire(&dir).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corrupt_journal_refuses_recovery_before_vault_access() {
        let dir = std::env::temp_dir().join(format!("zk110-corrupt-journal-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(JOURNAL), b"{}").unwrap();
        fs::write(dir.join("vault.json"), b"old").unwrap();
        assert!(NativeDataGuard::acquire(&dir).is_err());
        assert_eq!(fs::read(dir.join("vault.json")).unwrap(), b"old");
        fs::remove_dir_all(dir).unwrap();
    }
}
