//! Terminal/CLI client for zero-knowledge notes (`zk-note`).

mod commands;
mod config;
mod edit;
mod error;
mod session;

use clap::{Parser, Subcommand};
use commands::{
    cmd_conflicts, cmd_delete, cmd_edit, cmd_history, cmd_init, cmd_list, cmd_lock, cmd_new,
    cmd_resolve, cmd_search, cmd_show, cmd_status, cmd_unlock,
};
use error::CliError;
use std::path::PathBuf;

/// Zero-knowledge encrypted note client (`zk-note`).
#[derive(Parser, Debug)]
#[command(
    name = "zk-note",
    author = "Zero-Knowledge Notes Team",
    version = "0.1.0",
    about = "Zero-knowledge, offline-first note-taking CLI"
)]
pub struct Cli {
    /// Custom data directory (defaults to ~/.zk-notes or ZK_NOTE_DIR)
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new encrypted vault
    Init {
        /// Optional passphrase (for automated scripts or tests)
        #[arg(long)]
        passphrase: Option<String>,

        /// Fast KDF test parameters (for testing only)
        #[arg(long, hide = true)]
        test_kdf: bool,
    },
    /// Unlock the vault and begin an active session
    Unlock {
        /// Master passphrase
        #[arg(long)]
        passphrase: Option<String>,

        /// Unlock using formatted recovery key instead of passphrase
        #[arg(long)]
        recovery_key: Option<String>,
    },
    /// Lock the vault and clear active session
    Lock,
    /// Display vault status (UNINITIALIZED, LOCKED, or UNLOCKED)
    Status,
    /// Create a new encrypted note
    #[command(alias = "create")]
    New {
        /// Note title
        #[arg(short = 't', long)]
        title: Option<String>,

        /// Note body content (reads from stdin if omitted and piped)
        #[arg(short = 'b', long)]
        body: Option<String>,

        /// Tags associated with the note (comma-separated or repeatable)
        #[arg(short = 'g', long = "tag", value_delimiter = ',')]
        tag: Vec<String>,
    },
    /// Edit an existing note in $EDITOR
    Edit {
        /// Note identifier (or unique prefix)
        note_id: String,

        /// Custom editor command to override $EDITOR or $VISUAL
        #[arg(long)]
        editor: Option<String>,

        /// Override note title (skips interactive editor if specified)
        #[arg(short = 't', long)]
        title: Option<String>,

        /// Override note body (skips interactive editor if specified)
        #[arg(short = 'b', long)]
        body: Option<String>,

        /// Override note tags (comma-separated, skips interactive editor if specified)
        #[arg(short = 'g', long = "tag", value_delimiter = ',')]
        tag: Option<Vec<String>>,
    },
    /// Show a decrypted note
    Show {
        /// Note identifier (or unique prefix)
        note_id: String,

        /// Output note in raw JSON format
        #[arg(long)]
        json: bool,
    },
    /// Search notes by title, body, or tag (requires unlocked vault)
    Search {
        /// Search query terms
        query: String,

        /// Output results in raw JSON format
        #[arg(long)]
        json: bool,
    },
    /// Delete a note (creates a revisioned tombstone)
    Delete {
        /// Note identifier (or unique prefix)
        note_id: String,

        /// Hard-purge the note and its history completely from local database
        #[arg(long)]
        purge: bool,
    },
    /// Display revision history or a specific historical revision of a note
    History {
        /// Note identifier (or unique prefix)
        note_id: String,

        /// Display note contents at a specific historical revision
        #[arg(short = 'r', long)]
        revision: Option<u64>,

        /// Output history in raw JSON format
        #[arg(long)]
        json: bool,
    },
    /// List notes (requires unlocked vault)
    List {
        /// Filter by tag
        #[arg(short = 'g', long = "tag")]
        tag: Option<String>,

        /// Include deleted notes (tombstones) in output
        #[arg(long)]
        include_deleted: bool,

        /// Output notes in raw JSON format
        #[arg(long)]
        json: bool,
    },
    /// List active or all conflict records
    Conflicts {
        /// Include resolved conflicts in output
        #[arg(long)]
        all: bool,

        /// Output conflicts in raw JSON format
        #[arg(long)]
        json: bool,
    },
    /// Resolve an active conflict record
    Resolve {
        /// Conflict identifier (or unique prefix)
        conflict_id: String,

        /// Resolve by keeping local version (retry push on next sync)
        #[arg(short = 'l', long)]
        local: bool,

        /// Resolve by accepting remote version (discard local changes)
        #[arg(short = 'r', long)]
        remote: bool,

        /// Resolve with merged note (manual edit in $EDITOR or candidate)
        #[arg(short = 'm', long)]
        merge: bool,

        /// Resolve by keeping remote version and duplicating local changes as a separate note
        #[arg(short = 'd', long)]
        duplicate: bool,

        /// Explicitly restore/resurrect note at current revision (for delete-vs-edit conflicts)
        #[arg(long)]
        restore: bool,

        /// Custom title for duplicated note (when using --duplicate)
        #[arg(long)]
        duplicate_title: Option<String>,

        /// Custom editor command to override $EDITOR or $VISUAL for manual merge
        #[arg(long)]
        editor: Option<String>,

        /// Override note title for manual merge (skips interactive editor if specified with --merge)
        #[arg(short = 't', long)]
        title: Option<String>,

        /// Override note body for manual merge (skips interactive editor if specified with --merge)
        #[arg(short = 'b', long)]
        body: Option<String>,

        /// Override note tags for manual merge (comma-separated)
        #[arg(short = 'g', long = "tag", value_delimiter = ',')]
        tag: Option<Vec<String>>,
    },
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.as_deref();

    match cli.command {
        Commands::Init {
            passphrase,
            test_kdf,
        } => cmd_init(data_dir, passphrase, test_kdf),
        Commands::Unlock {
            passphrase,
            recovery_key,
        } => cmd_unlock(data_dir, passphrase, recovery_key),
        Commands::Lock => cmd_lock(data_dir),
        Commands::Status => cmd_status(data_dir),
        Commands::New { title, body, tag } => {
            cmd_new(data_dir, title, body, tag)?;
            Ok(())
        }
        Commands::Edit {
            note_id,
            editor,
            title,
            body,
            tag,
        } => {
            cmd_edit(data_dir, &note_id, editor.as_deref(), title, body, tag)?;
            Ok(())
        }
        Commands::Show { note_id, json } => {
            cmd_show(data_dir, &note_id, json)?;
            Ok(())
        }
        Commands::Search { query, json } => {
            cmd_search(data_dir, &query, json)?;
            Ok(())
        }
        Commands::Delete { note_id, purge } => {
            cmd_delete(data_dir, &note_id, purge)?;
            Ok(())
        }
        Commands::History {
            note_id,
            revision,
            json,
        } => {
            cmd_history(data_dir, &note_id, revision, json)?;
            Ok(())
        }
        Commands::List {
            tag,
            include_deleted,
            json,
        } => {
            cmd_list(data_dir, tag, include_deleted, json)?;
            Ok(())
        }
        Commands::Conflicts { all, json } => {
            cmd_conflicts(data_dir, all, json)?;
            Ok(())
        }
        Commands::Resolve {
            conflict_id,
            local,
            remote,
            merge,
            duplicate,
            restore,
            duplicate_title,
            editor,
            title,
            body,
            tag,
        } => {
            cmd_resolve(
                data_dir,
                &conflict_id,
                local,
                remote,
                merge,
                duplicate,
                restore,
                duplicate_title,
                editor.as_deref(),
                title,
                body,
                tag,
            )?;
            Ok(())
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use zk_core::note::PlaintextNote;
    use zk_protocol::constants::OBJECT_KIND_NOTE;
    use zk_storage::traits::{BaseVersionStore, ObjectStore};
    use zk_storage::SqliteStorage;

    fn temp_test_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zk_cli_test_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test dir");
        path
    }

    #[test]
    fn test_cli_vault_init_unlock_lock_lifecycle() {
        let test_dir = temp_test_dir("lifecycle");
        let dir_path = test_dir.as_path();
        let pass = "test-master-password-456".to_string();

        // 1. Initial status is UNINITIALIZED
        let v_file = config::vault_file(dir_path);
        assert!(!v_file.exists());

        // 2. Initialize vault
        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init vault");
        assert!(v_file.exists());
        assert!(config::db_file(dir_path).exists());
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // 3. Double init fails
        let err = cmd_init(Some(dir_path), Some(pass.clone()), true).unwrap_err();
        match err {
            CliError::VaultAlreadyInitialized => (),
            other => panic!("expected VaultAlreadyInitialized, got {other:?}"),
        }

        // 4. Lock vault
        cmd_lock(Some(dir_path)).expect("lock vault");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // 5. Unlock with wrong password fails closed
        let wrong_err =
            cmd_unlock(Some(dir_path), Some("wrong-password".to_string()), None).unwrap_err();
        match wrong_err {
            CliError::AuthenticationFailed => (),
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // 6. Unlock with correct password succeeds
        cmd_unlock(Some(dir_path), Some(pass), None).expect("unlock vault");
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // 7. Verify session key can be loaded and matches valid 32-byte key
        let key = session::load_session_key(&config::session_file(dir_path)).expect("load session");
        assert_eq!(key.as_bytes().len(), 32);

        // 8. Lock again
        cmd_lock(Some(dir_path)).expect("lock");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // Cleanup
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_unlock_with_recovery_key() {
        let test_dir = temp_test_dir("recovery");
        let dir_path = test_dir.as_path();
        let pass = "password-to-recover".to_string();

        // Initialize vault via VaultManager directly to capture recovery key string
        let (bootstrap, recovery_str, _vault_key) = zk_core::vault::VaultManager::init_vault(
            pass.as_bytes(),
            &zk_crypto::kdf::KdfParams::new_test(),
        )
        .expect("init vault");

        let bootstrap_json = serde_json::to_string_pretty(&bootstrap).expect("serialize");
        fs::write(config::vault_file(dir_path), bootstrap_json).expect("write vault");
        let _ = zk_storage::SqliteStorage::open(config::db_file(dir_path)).expect("open db");

        // Verify initially locked
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // Wrong recovery key fails
        let bad_rec_err = cmd_unlock(
            Some(dir_path),
            None,
            Some("1234-5678-90AB-CDEF-1234-5678-90AB-CDEF-1234".to_string()),
        )
        .unwrap_err();

        match bad_rec_err {
            CliError::InvalidRecoveryKey(_) => (),
            other => panic!("expected InvalidRecoveryKey, got {other:?}"),
        }

        // Correct recovery key succeeds
        cmd_unlock(Some(dir_path), None, Some(recovery_str)).expect("unlock with recovery key");
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // Lock
        cmd_lock(Some(dir_path)).expect("lock");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_session_file_permissions_and_clearing() {
        let test_dir = temp_test_dir("permissions");
        let sess_path = test_dir.join(".session");
        let key = zk_crypto::keys::VaultKey::generate();

        session::save_session_key(&sess_path, &key).expect("save session");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&sess_path).expect("metadata");
            let mode = metadata.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "session file permissions must be exactly 0600"
            );
        }

        let loaded = session::load_session_key(&sess_path).expect("load session");
        assert_eq!(key, loaded);

        session::clear_session(&sess_path).expect("clear session");
        assert!(!sess_path.exists());
        assert!(session::load_session_key(&sess_path).is_err());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_create_show_list_note_lifecycle() {
        let test_dir = temp_test_dir("notes_lifecycle");
        let dir_path = test_dir.as_path();
        let pass = "vault-passphrase-123".to_string();

        // 1. Uninitialized vault rejects note creation
        let uninit_err = cmd_new(
            Some(dir_path),
            Some("Note 0".to_string()),
            Some("Body".to_string()),
            vec![],
        )
        .unwrap_err();
        match uninit_err {
            CliError::VaultUninitialized => (),
            other => panic!("expected VaultUninitialized, got {other:?}"),
        }

        // 2. Initialize vault (auto-unlocks session)
        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init");

        // 3. Create Note 1
        let note1_id = cmd_new(
            Some(dir_path),
            Some("Architecture Plan".to_string()),
            Some("Client-side encryption details.".to_string()),
            vec!["architecture".to_string(), "crypto".to_string()],
        )
        .expect("create note 1");

        // 4. Create Note 2
        let note2_id = cmd_new(
            Some(dir_path),
            Some("Shopping List".to_string()),
            Some("Milk, tea, apples.".to_string()),
            vec!["personal".to_string()],
        )
        .expect("create note 2");

        // 5. Show Note 1 by full ID
        let note1 = cmd_show(Some(dir_path), &note1_id, false).expect("show note 1");
        assert_eq!(note1.title, "Architecture Plan");
        assert_eq!(note1.body, "Client-side encryption details.");
        assert_eq!(note1.tags, vec!["architecture", "crypto"]);

        // 6. Show Note 1 by prefix (first 8 characters)
        let note1_prefix = &note1_id[..8];
        let note1_by_prefix =
            cmd_show(Some(dir_path), note1_prefix, false).expect("show by prefix");
        assert_eq!(note1_by_prefix.title, "Architecture Plan");

        // 7. List notes (expect 2 notes)
        let all_notes = cmd_list(Some(dir_path), None, false, false).expect("list notes");
        assert_eq!(all_notes.len(), 2);
        // Sorted by updated_at descending, note 2 was created after note 1
        assert_eq!(all_notes[0].id, note2_id);
        assert_eq!(all_notes[1].id, note1_id);

        // 8. List notes with tag filter
        let crypto_notes = cmd_list(Some(dir_path), Some("crypto".to_string()), false, false)
            .expect("list crypto notes");
        assert_eq!(crypto_notes.len(), 1);
        assert_eq!(crypto_notes[0].id, note1_id);
        assert_eq!(crypto_notes[0].title, "Architecture Plan");

        let personal_notes = cmd_list(Some(dir_path), Some("personal".to_string()), false, false)
            .expect("list personal notes");
        assert_eq!(personal_notes.len(), 1);
        assert_eq!(personal_notes[0].id, note2_id);

        let non_existent_tag = cmd_list(
            Some(dir_path),
            Some("nonexistent".to_string()),
            false,
            false,
        )
        .expect("list nonexistent tag");
        assert!(non_existent_tag.is_empty());

        // 9. Lock vault -> all note operations fail closed
        cmd_lock(Some(dir_path)).expect("lock");

        let locked_show = cmd_show(Some(dir_path), &note1_id, false).unwrap_err();
        match locked_show {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked on show, got {other:?}"),
        }

        let locked_list = cmd_list(Some(dir_path), None, false, false).unwrap_err();
        match locked_list {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked on list, got {other:?}"),
        }

        let locked_new = cmd_new(
            Some(dir_path),
            Some("Locked Note".to_string()),
            Some("Cannot create while locked".to_string()),
            vec![],
        )
        .unwrap_err();
        match locked_new {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked on new, got {other:?}"),
        }

        // 10. Unlock again -> show and list succeed
        cmd_unlock(Some(dir_path), Some(pass), None).expect("unlock");

        let unlocked_show = cmd_show(Some(dir_path), &note1_id, false).expect("show unlocked");
        assert_eq!(unlocked_show.title, "Architecture Plan");

        let unlocked_list = cmd_list(Some(dir_path), None, false, false).expect("list unlocked");
        assert_eq!(unlocked_list.len(), 2);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_database_contains_ciphertext_only() {
        let test_dir = temp_test_dir("no_plaintext_db");
        let dir_path = test_dir.as_path();
        let pass = "db-cipher-only-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let unique_title = "CLASSIFIED_TOP_SECRET_TITLENAME_9999";
        let unique_body = "BODY_SUPER_SECRET_PAYLOAD_STRING_8888";
        let unique_tag = "tagclassified7777";

        let note_id = cmd_new(
            Some(dir_path),
            Some(unique_title.to_string()),
            Some(unique_body.to_string()),
            vec![unique_tag.to_string()],
        )
        .expect("create note");

        let db_path = config::db_file(dir_path);
        assert!(db_path.exists());

        // 1. Raw disk byte scan: no plaintext string exists anywhere in the sqlite database file
        let db_bytes = fs::read(&db_path).expect("read db file");
        assert!(
            !db_bytes
                .windows(unique_title.len())
                .any(|w| w == unique_title.as_bytes()),
            "plaintext title found in raw sqlite file bytes!"
        );
        assert!(
            !db_bytes
                .windows(unique_body.len())
                .any(|w| w == unique_body.as_bytes()),
            "plaintext body found in raw sqlite file bytes!"
        );
        assert!(
            !db_bytes
                .windows(unique_tag.len())
                .any(|w| w == unique_tag.as_bytes()),
            "plaintext tag found in raw sqlite file bytes!"
        );

        // 2. Query sqlite tables directly via rusqlite
        let conn = rusqlite::Connection::open(&db_path).expect("open raw conn");

        // Check local_objects
        let (obj_id, envelope_json): (String, String) = conn
            .query_row(
                "SELECT object_id, envelope FROM local_objects WHERE object_id = ?1",
                rusqlite::params![note_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query local_objects");

        assert_eq!(obj_id, note_id);
        assert!(!envelope_json.contains(unique_title));
        assert!(!envelope_json.contains(unique_body));
        assert!(!envelope_json.contains(unique_tag));

        // Parse envelope to confirm it contains ciphertext and wrapped key
        let envelope: zk_protocol::envelope::EncryptedEnvelope =
            serde_json::from_str(&envelope_json).expect("parse envelope json");
        assert_eq!(envelope.envelope_version, 1);
        assert!(!envelope.payload.ciphertext.is_empty());

        // Check pending_mutations
        let (mut_obj_id, mut_envelope_json): (String, String) = conn
            .query_row(
                "SELECT object_id, envelope FROM pending_mutations WHERE object_id = ?1",
                rusqlite::params![note_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query pending_mutations");

        assert_eq!(mut_obj_id, note_id);
        assert!(!mut_envelope_json.contains(unique_title));
        assert!(!mut_envelope_json.contains(unique_body));
        assert!(!mut_envelope_json.contains(unique_tag));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_edit_flow_with_custom_editor() {
        let test_dir = temp_test_dir("edit_editor");
        let dir_path = test_dir.as_path();
        let pass = "edit-test-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let note_id = cmd_new(
            Some(dir_path),
            Some("Draft Plan".to_string()),
            Some("Initial draft.".to_string()),
            vec!["planning".to_string()],
        )
        .expect("create note");

        // Mock editor that updates frontmatter and body
        let editor_script = r#"sh -c 'printf -- "---\ntitle: Updated Plan\ntags: [planning, v2]\n---\n\nNew edited content.\n" > "$1"' --"#;

        let updated = cmd_edit(
            Some(dir_path),
            &note_id,
            Some(editor_script),
            None,
            None,
            None,
        )
        .expect("edit note with custom editor");

        assert_eq!(updated.title, "Updated Plan");
        assert_eq!(updated.tags, vec!["planning", "v2"]);
        assert_eq!(updated.body, "New edited content.");

        // Verify SQLite storage has revision 2 and base revision 1 is archived
        let db_path = config::db_file(dir_path);
        let storage = zk_storage::SqliteStorage::open(&db_path).expect("open storage");
        let stored_obj = storage
            .get_object(&note_id)
            .expect("get object")
            .expect("object exists");
        assert_eq!(stored_obj.revision, 2);

        // Check base version retention in BaseVersionStore
        let base_env = storage
            .get_base_version(&note_id, 1)
            .expect("get base version")
            .expect("base version 1 exists");
        assert_eq!(base_env.envelope_version, 1);

        // Verify decrypted base version matches initial state
        let sess_path = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_path).expect("session key");
        let base_note =
            zk_core::note::PlaintextNote::decrypt(&base_env, &vault_key).expect("decrypt base");
        assert_eq!(base_note.title, "Draft Plan");
        assert_eq!(base_note.body, "Initial draft.");
        assert_eq!(base_note.tags, vec!["planning"]);

        // Verify show displays the updated note
        let shown = cmd_show(Some(dir_path), &note_id, false).expect("show updated");
        assert_eq!(shown.title, "Updated Plan");
        assert_eq!(shown.body, "New edited content.");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_edit_failure_does_not_corrupt_prior_note() {
        let test_dir = temp_test_dir("edit_failure");
        let dir_path = test_dir.as_path();
        let pass = "edit-fail-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let note_id = cmd_new(
            Some(dir_path),
            Some("Untouched Title".to_string()),
            Some("Untouched body.".to_string()),
            vec!["safe".to_string()],
        )
        .expect("create note");

        // Mock editor that fails with exit status 13
        let failing_editor = r#"sh -c 'exit 13' --"#;

        let err = cmd_edit(
            Some(dir_path),
            &note_id,
            Some(failing_editor),
            None,
            None,
            None,
        )
        .unwrap_err();

        match err {
            CliError::Io(msg) => assert!(msg.contains("exited with non-zero status")),
            other => panic!("expected Io error for non-zero status, got {other:?}"),
        }

        // Verify note in database is completely untouched (revision still 1, content intact)
        let shown = cmd_show(Some(dir_path), &note_id, false).expect("show after fail");
        assert_eq!(shown.title, "Untouched Title");
        assert_eq!(shown.body, "Untouched body.");
        assert_eq!(shown.tags, vec!["safe"]);

        let db_path = config::db_file(dir_path);
        let storage = zk_storage::SqliteStorage::open(&db_path).expect("open storage");
        let stored_obj = storage
            .get_object(&note_id)
            .expect("get object")
            .expect("object exists");
        assert_eq!(stored_obj.revision, 1);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_edit_programmatic_and_locked_guards() {
        let test_dir = temp_test_dir("edit_programmatic");
        let dir_path = test_dir.as_path();
        let pass = "edit-prog-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let note_id = cmd_new(
            Some(dir_path),
            Some("Initial".to_string()),
            Some("Body".to_string()),
            vec![],
        )
        .expect("create");

        // Programmatic edit
        let updated = cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("New Title".to_string()),
            Some("New Body".to_string()),
            Some(vec!["tag-a".to_string()]),
        )
        .expect("edit programmatic");

        assert_eq!(updated.title, "New Title");
        assert_eq!(updated.body, "New Body");
        assert_eq!(updated.tags, vec!["tag-a"]);

        // Lock vault -> edit fails closed
        cmd_lock(Some(dir_path)).expect("lock");

        let locked_err = cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("Should Fail".to_string()),
            None,
            None,
        )
        .unwrap_err();

        match locked_err {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_delete_tombstone_and_history_lifecycle() {
        use zk_storage::traits::{BaseVersionStore, MutationStore};

        let test_dir = temp_test_dir("delete_tombstone_lifecycle");
        let dir_path = test_dir.as_path();
        let pass = "tombstone-test-pass".to_string();

        // 1. Initialize vault
        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init");

        // 2. Create note (revision 1)
        let note_id = cmd_new(
            Some(dir_path),
            Some("Original Title".to_string()),
            Some("Original secret body.".to_string()),
            vec!["v1".to_string()],
        )
        .expect("create");

        // 3. Edit note (revision 2)
        let _ = cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("Edited Title".to_string()),
            Some("Edited secret body.".to_string()),
            Some(vec!["v2".to_string()]),
        )
        .expect("edit");

        // Verify it is at revision 2
        let db_path = config::db_file(dir_path);
        let storage = zk_storage::SqliteStorage::open(&db_path).expect("open");
        let obj_r2 = storage.get_object(&note_id).expect("get").expect("found");
        assert_eq!(obj_r2.revision, 2);
        assert!(!obj_r2.is_deleted);

        // 4. Delete note (creates revision 3 tombstone)
        let tombstone_rev = cmd_delete(Some(dir_path), &note_id, false).expect("delete");
        assert_eq!(tombstone_rev, 3);

        // 5. Verify local tombstone state in SQLite:
        // - is_deleted == true
        // - revision == 3
        // - envelope is preserved
        let obj_r3 = storage.get_object(&note_id).expect("get").expect("found");
        assert!(obj_r3.is_deleted);
        assert_eq!(obj_r3.revision, 3);
        assert_eq!(obj_r3.envelope, obj_r2.envelope);

        // 6. Verify deletion revision intent in pending_mutations:
        // - PendingMutation with mutation_type == MutationType::Delete
        // - expected_revision == 2 (prior revision before deletion)
        let pending = storage.list_pending_mutations().expect("list mutations");
        let del_mutation = pending
            .iter()
            .find(|m| m.object_id == note_id && m.mutation_type == zk_storage::MutationType::Delete)
            .expect("delete mutation found");
        assert_eq!(del_mutation.expected_revision, 2);
        assert_eq!(del_mutation.status, zk_storage::MutationStatus::Pending);

        // 7. Verify show fails closed on deleted note
        let show_err = cmd_show(Some(dir_path), &note_id, false).unwrap_err();
        match show_err {
            CliError::NoteAlreadyDeleted(id) => assert_eq!(id, note_id),
            other => panic!("expected NoteAlreadyDeleted, got {other:?}"),
        }

        // 8. Verify delete on already-deleted note fails closed
        let del_again_err = cmd_delete(Some(dir_path), &note_id, false).unwrap_err();
        match del_again_err {
            CliError::NoteAlreadyDeleted(id) => assert_eq!(id, note_id),
            other => panic!("expected NoteAlreadyDeleted, got {other:?}"),
        }

        // 9. Verify list excludes deleted notes by default, but includes with include_deleted: true
        let list_default = cmd_list(Some(dir_path), None, false, false).expect("list");
        assert!(list_default.is_empty());

        let list_with_deleted = cmd_list(Some(dir_path), None, true, false).expect("list all");
        assert_eq!(list_with_deleted.len(), 1);
        assert_eq!(list_with_deleted[0].id, note_id);
        assert!(list_with_deleted[0].is_deleted);
        assert_eq!(list_with_deleted[0].revision, 3);

        // 10. Verify history/base state remains available:
        // - list_base_versions has revisions 1 and 2
        let base_versions = storage.list_base_versions(&note_id).expect("base versions");
        assert_eq!(base_versions.len(), 2);
        assert_eq!(base_versions[0].0, 1);
        assert_eq!(base_versions[1].0, 2);

        // - cmd_history returns all 3 revisions
        let history = cmd_history(Some(dir_path), &note_id, None, false).expect("history");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[0].title, "Original Title");
        assert!(!history[0].is_deleted);

        assert_eq!(history[1].revision, 2);
        assert_eq!(history[1].title, "Edited Title");
        assert!(!history[1].is_deleted);

        assert_eq!(history[2].revision, 3);
        assert_eq!(history[2].title, "Edited Title");
        assert!(history[2].is_deleted);

        // - cmd_history with specific revision retrieves historical content
        let rev1_items = cmd_history(Some(dir_path), &note_id, Some(1), false).expect("history r1");
        assert_eq!(rev1_items.len(), 1);
        assert_eq!(rev1_items[0].body, "Original secret body.");

        let rev2_items = cmd_history(Some(dir_path), &note_id, Some(2), false).expect("history r2");
        assert_eq!(rev2_items.len(), 1);
        assert_eq!(rev2_items[0].body, "Edited secret body.");

        // 11. Lock vault -> delete and history fail closed
        cmd_lock(Some(dir_path)).expect("lock");
        let locked_del = cmd_delete(Some(dir_path), &note_id, false).unwrap_err();
        assert!(matches!(locked_del, CliError::VaultLocked));
        let locked_hist = cmd_history(Some(dir_path), &note_id, None, false).unwrap_err();
        assert!(matches!(locked_hist, CliError::VaultLocked));

        // 12. Unlock and test purge
        cmd_unlock(Some(dir_path), Some(pass), None).expect("unlock");
        cmd_delete(Some(dir_path), &note_id, true).expect("purge");
        assert!(storage.get_object(&note_id).expect("get").is_none());
        assert!(storage
            .list_base_versions(&note_id)
            .expect("base")
            .is_empty());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_delete_and_history_no_plaintext_leakage() {
        let test_dir = temp_test_dir("delete_no_leakage");
        let dir_path = test_dir.as_path();
        let pass = "leakage-test-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let secret_title = "CANARY_TITLE_ABCDEF";
        let secret_body = "CANARY_BODY_123456789";
        let secret_tag = "canary-tag-xyz";

        let note_id = cmd_new(
            Some(dir_path),
            Some(secret_title.to_string()),
            Some(secret_body.to_string()),
            vec![secret_tag.to_string()],
        )
        .expect("create");

        // Edit note to produce a base version in encrypted_base_versions
        let edited_body = "EDITED_CANARY_BODY_987654321";
        cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            None,
            Some(edited_body.to_string()),
            None,
        )
        .expect("edit");

        // Delete note to produce a tombstone in local_objects and a pending mutation in pending_mutations
        cmd_delete(Some(dir_path), &note_id, false).expect("delete");

        // Lock vault to ensure clean cache flush
        cmd_lock(Some(dir_path)).expect("lock");

        let db_path = config::db_file(dir_path);
        let raw_db_bytes = fs::read(&db_path).expect("read db bytes");
        let raw_db_str = String::from_utf8_lossy(&raw_db_bytes);

        assert!(
            !raw_db_str.contains(secret_title),
            "plaintext title found in raw SQLite file"
        );
        assert!(
            !raw_db_str.contains(secret_body),
            "plaintext body found in raw SQLite file"
        );
        assert!(
            !raw_db_str.contains(secret_tag),
            "plaintext tag found in raw SQLite file"
        );
        assert!(
            !raw_db_str.contains(edited_body),
            "plaintext edited body found in raw SQLite file"
        );

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_search_title_body_and_tags() {
        let test_dir = temp_test_dir("search_lifecycle");
        let dir_path = test_dir.as_path();
        let pass = "search-test-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        // 1. Create Note A
        let note_a_id = cmd_new(
            Some(dir_path),
            Some("Project Roadmap".to_string()),
            Some("Rust-based architecture with offline sync and local caching.".to_string()),
            vec!["work".to_string(), "roadmap".to_string()],
        )
        .expect("create note A");

        // 2. Create Note B
        let note_b_id = cmd_new(
            Some(dir_path),
            Some("Weekly Groceries".to_string()),
            Some("Buy green tea, oat milk, and dark chocolate.".to_string()),
            vec!["personal".to_string()],
        )
        .expect("create note B");

        // 3. Create Note C
        let note_c_id = cmd_new(
            Some(dir_path),
            Some("Cryptographic Invariants".to_string()),
            Some("Zero-knowledge server stores only ciphertext payloads.".to_string()),
            vec!["security".to_string(), "crypto".to_string()],
        )
        .expect("create note C");

        // 4. Search by title
        let results_roadmap = cmd_search(Some(dir_path), "Roadmap", false).expect("search roadmap");
        assert_eq!(results_roadmap.len(), 1);
        assert_eq!(results_roadmap[0].id, note_a_id);
        assert_eq!(results_roadmap[0].title, "Project Roadmap");

        // 5. Search by body content with snippet
        let results_chocolate =
            cmd_search(Some(dir_path), "chocolate", false).expect("search chocolate");
        assert_eq!(results_chocolate.len(), 1);
        assert_eq!(results_chocolate[0].id, note_b_id);
        assert!(results_chocolate[0].snippet.contains("chocolate"));

        // 6. Search by tag
        let results_crypto = cmd_search(Some(dir_path), "crypto", false).expect("search crypto");
        assert_eq!(results_crypto.len(), 1);
        assert_eq!(results_crypto[0].id, note_c_id);

        // 7. Search by explicit #tag syntax
        let results_hash_personal =
            cmd_search(Some(dir_path), "#personal", false).expect("search #personal");
        assert_eq!(results_hash_personal.len(), 1);
        assert_eq!(results_hash_personal[0].id, note_b_id);

        // 8. Multi-term query (AND semantics across fields)
        let results_multi =
            cmd_search(Some(dir_path), "rust architecture", false).expect("search multi");
        assert_eq!(results_multi.len(), 1);
        assert_eq!(results_multi[0].id, note_a_id);

        // 9. Case-insensitive search
        let results_case =
            cmd_search(Some(dir_path), "zErO-kNoWlEdGe", false).expect("search case");
        assert_eq!(results_case.len(), 1);
        assert_eq!(results_case[0].id, note_c_id);

        // 10. Non-matching query returns empty
        let results_none =
            cmd_search(Some(dir_path), "nonexistenttoken", false).expect("search none");
        assert!(results_none.is_empty());

        // 11. Deleted / tombstoned notes are excluded from search results
        cmd_delete(Some(dir_path), &note_a_id, false).expect("delete note A");
        let results_after_delete =
            cmd_search(Some(dir_path), "Roadmap", false).expect("search after delete");
        assert!(results_after_delete.is_empty());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_search_fails_closed_when_locked() {
        let test_dir = temp_test_dir("search_locked");
        let dir_path = test_dir.as_path();
        let pass = "locked-search-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        cmd_new(
            Some(dir_path),
            Some("Secret Note".to_string()),
            Some("Secret content".to_string()),
            vec![],
        )
        .expect("create");

        // Lock vault
        cmd_lock(Some(dir_path)).expect("lock");

        // Search while locked must fail closed
        let locked_err = cmd_search(Some(dir_path), "Secret", false).unwrap_err();
        match locked_err {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked error, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_search_persistent_db_has_no_plaintext_index() {
        let test_dir = temp_test_dir("search_db_no_plaintext");
        let dir_path = test_dir.as_path();
        let pass = "db-plaintext-pass".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init");

        let unique_term = "INDEX_SEARCH_TOKEN_99999";
        let unique_title = "TITLE_FOR_SEARCH_88888";

        cmd_new(
            Some(dir_path),
            Some(unique_title.to_string()),
            Some(format!("Body containing {unique_term} strictly in memory.")),
            vec!["indexed-tag".to_string()],
        )
        .expect("create note");

        // Execute searches while unlocked
        let res1 = cmd_search(Some(dir_path), unique_term, false).expect("search term");
        assert_eq!(res1.len(), 1);

        let res2 = cmd_search(Some(dir_path), unique_title, false).expect("search title");
        assert_eq!(res2.len(), 1);

        // Lock vault to cleanly close session
        cmd_lock(Some(dir_path)).expect("lock");

        // Inspect raw SQLite file bytes
        let db_path = config::db_file(dir_path);
        let raw_db_bytes = fs::read(&db_path).expect("read db");
        let raw_db_str = String::from_utf8_lossy(&raw_db_bytes);

        assert!(
            !raw_db_str.contains(unique_term),
            "search query/body token found in persistent database file"
        );
        assert!(
            !raw_db_str.contains(unique_title),
            "search title token found in persistent database file"
        );

        // Verify SQLite tables: no plaintext FTS or index tables exist
        let storage = zk_storage::SqliteStorage::open(&db_path).expect("open sqlite");
        let tables: Vec<String> = {
            // Check table names in sqlite_master
            let conn = rusqlite::Connection::open(&db_path).expect("open raw sqlite");
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';")
                .expect("prepare");
            let rows = stmt
                .query_map([], |r| r.get(0))
                .expect("query")
                .collect::<Result<Vec<String>, _>>()
                .expect("collect");
            rows
        };

        // Allowed tables: local_objects, encrypted_base_versions, pending_mutations, sync_state
        for t in &tables {
            assert!(
                !t.contains("fts") && !t.contains("search") && !t.contains("index"),
                "unexpected plaintext search table found in database: {t}"
            );
        }

        let _ = storage;
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_history_multi_revision_retention_and_selection() {
        use zk_storage::traits::BaseVersionStore;

        let test_dir = temp_test_dir("history_multi_rev");
        let dir_path = test_dir.as_path();
        let pass = "history-multi-pass".to_string();

        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init");

        // 1. Create note (r1)
        let note_id = cmd_new(
            Some(dir_path),
            Some("Architecture RFC".to_string()),
            Some("Initial design doc.".to_string()),
            vec!["arch".to_string()],
        )
        .expect("create");

        // 2. Edit note (r2)
        cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("Architecture RFC v2".to_string()),
            Some("Updated with Argon2id parameters.".to_string()),
            Some(vec!["arch".to_string(), "kdf".to_string()]),
        )
        .expect("edit r2");

        // 3. Edit note (r3)
        cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("Architecture RFC v3".to_string()),
            Some("Added XChaCha20-Poly1305 encryption details.".to_string()),
            Some(vec!["arch".to_string(), "crypto".to_string()]),
        )
        .expect("edit r3");

        // 4. Edit note (r4)
        cmd_edit(
            Some(dir_path),
            &note_id,
            None,
            Some("Architecture RFC Final".to_string()),
            Some("Completed specifications.".to_string()),
            Some(vec![
                "arch".to_string(),
                "crypto".to_string(),
                "final".to_string(),
            ]),
        )
        .expect("edit r4");

        // Verify base versions in SQLite
        let db_path = config::db_file(dir_path);
        let storage = zk_storage::SqliteStorage::open(&db_path).expect("open storage");
        let base_versions = storage.list_base_versions(&note_id).expect("list base");
        assert_eq!(base_versions.len(), 3);
        assert_eq!(base_versions[0].0, 1);
        assert_eq!(base_versions[1].0, 2);
        assert_eq!(base_versions[2].0, 3);

        // Verify full history list returns 4 items
        let history = cmd_history(Some(dir_path), &note_id, None, false).expect("cmd_history list");
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[0].title, "Architecture RFC");
        assert_eq!(history[0].body, "Initial design doc.");

        assert_eq!(history[1].revision, 2);
        assert_eq!(history[1].title, "Architecture RFC v2");
        assert_eq!(history[1].body, "Updated with Argon2id parameters.");

        assert_eq!(history[2].revision, 3);
        assert_eq!(history[2].title, "Architecture RFC v3");
        assert_eq!(
            history[2].body,
            "Added XChaCha20-Poly1305 encryption details."
        );

        assert_eq!(history[3].revision, 4);
        assert_eq!(history[3].title, "Architecture RFC Final");
        assert_eq!(history[3].body, "Completed specifications.");

        // Query each revision specifically
        let r1 = cmd_history(Some(dir_path), &note_id, Some(1), false).expect("r1");
        assert_eq!(r1[0].revision, 1);
        assert_eq!(r1[0].title, "Architecture RFC");
        assert_eq!(r1[0].body, "Initial design doc.");

        let r2 = cmd_history(Some(dir_path), &note_id, Some(2), false).expect("r2");
        assert_eq!(r2[0].revision, 2);
        assert_eq!(r2[0].title, "Architecture RFC v2");
        assert_eq!(r2[0].body, "Updated with Argon2id parameters.");

        let r3 = cmd_history(Some(dir_path), &note_id, Some(3), false).expect("r3");
        assert_eq!(r3[0].revision, 3);
        assert_eq!(r3[0].title, "Architecture RFC v3");
        assert_eq!(r3[0].body, "Added XChaCha20-Poly1305 encryption details.");

        let r4 = cmd_history(Some(dir_path), &note_id, Some(4), false).expect("r4");
        assert_eq!(r4[0].revision, 4);
        assert_eq!(r4[0].title, "Architecture RFC Final");
        assert_eq!(r4[0].body, "Completed specifications.");

        // Non-existent revision returns RevisionNotFound
        let not_found_err = cmd_history(Some(dir_path), &note_id, Some(99), false).unwrap_err();
        match not_found_err {
            CliError::RevisionNotFound {
                note_id: err_id,
                revision: 99,
            } => assert_eq!(err_id, note_id),
            other => panic!("expected RevisionNotFound, got {other:?}"),
        }

        // Lock vault -> history queries fail closed
        cmd_lock(Some(dir_path)).expect("lock");
        let locked_list = cmd_history(Some(dir_path), &note_id, None, false).unwrap_err();
        assert!(matches!(locked_list, CliError::VaultLocked));

        let locked_rev = cmd_history(Some(dir_path), &note_id, Some(2), false).unwrap_err();
        assert!(matches!(locked_rev, CliError::VaultLocked));

        // Unlock and verify access restored
        cmd_unlock(Some(dir_path), Some(pass), None).expect("unlock");
        let unlocked_rev =
            cmd_history(Some(dir_path), &note_id, Some(2), false).expect("unlocked r2");
        assert_eq!(unlocked_rev[0].revision, 2);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_m2_gate_full_lifecycle_demo() {
        // Manual demo script from M2 Gate:
        // init vault -> create notes -> close process -> inspect SQLite (no plaintext) ->
        // reopen -> unlock -> search -> edit -> delete -> history -> lock
        let test_dir = temp_test_dir("m2_gate_demo");
        let dir_path = test_dir.as_path();
        let pass = "m2-gate-demo-pass".to_string();

        let canary_term = "CANARY_DEMO_SECRET_TOKEN_42";
        let note1_title = "Secret Note 1";
        let note1_body = format!("Important secret details about {canary_term}.");

        // 1. init vault
        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("1. init vault");

        // 2. create notes
        let note1_id = cmd_new(
            Some(dir_path),
            Some(note1_title.to_string()),
            Some(note1_body.clone()),
            vec!["demo".to_string(), "secret".to_string()],
        )
        .expect("2. create note 1");

        let note2_id = cmd_new(
            Some(dir_path),
            Some("Ordinary Note 2".to_string()),
            Some("Just an everyday checklist.".to_string()),
            vec!["routine".to_string()],
        )
        .expect("2. create note 2");

        // 3. close process (lock vault)
        cmd_lock(Some(dir_path)).expect("3. close process / lock");

        // 4. inspect SQLite -> no note plaintext
        let db_path = config::db_file(dir_path);
        let raw_db_bytes = fs::read(&db_path).expect("read db");
        let raw_db_str = String::from_utf8_lossy(&raw_db_bytes);
        assert!(
            !raw_db_str.contains(canary_term),
            "canary term found in SQLite file after lock"
        );
        assert!(
            !raw_db_str.contains(note1_title),
            "note title found in SQLite file after lock"
        );
        assert!(
            !raw_db_str.contains("everyday checklist"),
            "note 2 body found in SQLite file after lock"
        );

        // 5. reopen (check status)
        cmd_status(Some(dir_path)).expect("5. reopen status");

        // 6. unlock
        cmd_unlock(Some(dir_path), Some(pass), None).expect("6. unlock");

        // 7. search
        let search_results = cmd_search(Some(dir_path), canary_term, false).expect("7. search");
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].id, note1_id);
        assert!(search_results[0].snippet.contains(canary_term));

        // 8. edit
        let updated_note1 = cmd_edit(
            Some(dir_path),
            &note1_id,
            None,
            Some("Secret Note 1 Revised".to_string()),
            Some("Updated confidential content.".to_string()),
            None,
        )
        .expect("8. edit");
        assert_eq!(updated_note1.title, "Secret Note 1 Revised");

        // 9. delete (tombstone note 2)
        let tombstone_rev = cmd_delete(Some(dir_path), &note2_id, false).expect("9. delete");
        assert_eq!(tombstone_rev, 2);

        // 10. history
        // - History for note 1 has rev 1 (base) and rev 2 (current)
        let note1_hist =
            cmd_history(Some(dir_path), &note1_id, None, false).expect("10. history note 1");
        assert_eq!(note1_hist.len(), 2);
        assert_eq!(note1_hist[0].revision, 1);
        assert_eq!(note1_hist[0].title, "Secret Note 1");
        assert_eq!(note1_hist[1].revision, 2);
        assert_eq!(note1_hist[1].title, "Secret Note 1 Revised");

        // - History can display selected revision 1
        let rev1_shown =
            cmd_history(Some(dir_path), &note1_id, Some(1), false).expect("10. history r1");
        assert_eq!(rev1_shown[0].body, note1_body);

        // - History for note 2 shows tombstone
        let note2_hist =
            cmd_history(Some(dir_path), &note2_id, None, false).expect("10. history note 2");
        assert_eq!(note2_hist.len(), 2);
        assert!(note2_hist[1].is_deleted);

        // 11. lock
        cmd_lock(Some(dir_path)).expect("11. lock");

        // Operations fail closed after lock
        assert!(matches!(
            cmd_show(Some(dir_path), &note1_id, false).unwrap_err(),
            CliError::VaultLocked
        ));
        assert!(matches!(
            cmd_search(Some(dir_path), "Secret", false).unwrap_err(),
            CliError::VaultLocked
        ));
        assert!(matches!(
            cmd_history(Some(dir_path), &note1_id, None, false).unwrap_err(),
            CliError::VaultLocked
        ));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_conflicts_listing_and_filtering() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::ConflictStore;

        let test_dir = temp_test_dir("conflicts_listing");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-conflicts".to_string();

        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        // 1. When no conflicts exist
        let initial_conflicts = cmd_conflicts(Some(dir_path), false, false).expect("list empty");
        assert!(initial_conflicts.is_empty());

        // 2. Insert two conflicts into SqliteStorage: one active, one resolved
        let obj1_id = uuid::Uuid::new_v4().to_string();
        let note1 = PlaintextNote::new("Active Note Title", "Local body content");
        let note1_remote = PlaintextNote::new("Remote Note Title", "Remote body content");
        let env1_local = note1.encrypt(&vault_key, &obj1_id).expect("enc local");
        let env1_remote = note1_remote
            .encrypt(&vault_key, &obj1_id)
            .expect("enc remote");

        let conf1_id = format!("c100-{}", uuid::Uuid::new_v4());
        let record1 = ConflictRecord::new(
            &conf1_id,
            &obj1_id,
            OBJECT_KIND_NOTE,
            1,
            2,
            None,
            env1_local,
            env1_remote,
            None,
            "2026-09-10T02:00:00Z",
        );

        let obj2_id = uuid::Uuid::new_v4().to_string();
        let note2 = PlaintextNote::new("Resolved Note Title", "Resolved content");
        let env2_local = note2.encrypt(&vault_key, &obj2_id).expect("enc local");
        let env2_remote = note2.encrypt(&vault_key, &obj2_id).expect("enc remote");

        let conf2_id = format!("c200-{}", uuid::Uuid::new_v4());
        let mut record2 = ConflictRecord::new(
            &conf2_id,
            &obj2_id,
            OBJECT_KIND_NOTE,
            3,
            4,
            None,
            env2_local,
            env2_remote,
            None,
            "2026-09-10T01:00:00Z",
        );
        record2.resolved = true;
        record2.resolved_at = Some("2026-09-10T01:30:00Z".to_string());

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record1).expect("put conf1");
            storage.put_conflict(&record2).expect("put conf2");
        }

        // 3. List active conflicts (all = false): should return only record1 with decrypted title
        let active = cmd_conflicts(Some(dir_path), false, false).expect("list active");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].conflict_id, conf1_id);
        assert_eq!(active[0].title, "Active Note Title");
        assert!(!active[0].resolved);

        // 4. List all conflicts (all = true): should return both
        let all = cmd_conflicts(Some(dir_path), true, false).expect("list all");
        assert_eq!(all.len(), 2);

        // 5. JSON output
        let json_items = cmd_conflicts(Some(dir_path), true, true).expect("list json");
        assert_eq!(json_items.len(), 2);

        // 6. When locked: listing still works but title is masked as [locked] (SEC-009)
        cmd_lock(Some(dir_path)).expect("lock");
        let locked_list = cmd_conflicts(Some(dir_path), false, false).expect("list locked");
        assert_eq!(locked_list.len(), 1);
        assert_eq!(locked_list[0].conflict_id, conf1_id);
        assert_eq!(locked_list[0].title, "[locked]");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_resolve_keep_local() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::{ConflictStore, ObjectStore};

        let test_dir = temp_test_dir("resolve_local");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-resolve".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Local Title", "My local edited body");
        let remote_note = PlaintextNote::new("Remote Title", "Server edited body");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let env_remote = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-loc-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            2,
            5,
            None,
            env_local.clone(),
            env_remote,
            None,
            "2026-09-10T02:00:00Z",
        );

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // Resolve by keeping local version
        let result = cmd_resolve(
            Some(dir_path),
            &conf_id,
            true,  // local
            false, // remote
            false, // merge
            false, // duplicate
            false, // restore
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve keep local");

        assert_eq!(result.conflict_id, conf_id);
        assert_eq!(result.object_id, obj_id);

        let retry_mut = result.retry_mutation.expect("retry mutation");
        assert_eq!(retry_mut.expected_revision, 5);
        assert_eq!(retry_mut.envelope, env_local);

        // Verify storage state
        let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
        let conf_after = storage
            .get_conflict(&conf_id)
            .expect("get")
            .expect("exists");
        assert!(conf_after.resolved);
        assert!(conf_after.resolved_at.is_some());

        // Verify local object has local envelope
        let obj = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(obj.revision, 5);
        assert_eq!(obj.envelope, env_local);

        // Resolving again fails closed
        let second_try = cmd_resolve(
            Some(dir_path),
            &conf_id,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(second_try, CliError::ConflictAlreadyResolved(_)));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_resolve_keep_remote() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::{ConflictStore, ObjectStore};

        let test_dir = temp_test_dir("resolve_remote");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-remote".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Local Title", "Local Body");
        let remote_note = PlaintextNote::new("Remote Winner", "Remote Body Content");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let env_remote = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-rem-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            1,
            3,
            None,
            env_local,
            env_remote.clone(),
            None,
            "2026-09-10T02:00:00Z",
        );

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // Resolve by keeping remote
        let result = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false, // local
            true,  // remote
            false, // merge
            false, // duplicate
            false, // restore
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve keep remote");

        assert_eq!(result.conflict_id, conf_id);
        assert_eq!(result.object_id, obj_id);
        assert!(result.retry_mutation.is_none());

        // Verify local object has remote envelope
        let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
        let obj = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(obj.revision, 3);
        assert_eq!(obj.envelope, env_remote);

        // cmd_show displays remote winner
        let shown = cmd_show(Some(dir_path), &obj_id, false).expect("show");
        assert_eq!(shown.title, "Remote Winner");
        assert_eq!(shown.body, "Remote Body Content");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_resolve_manual_merge() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::{ConflictStore, ObjectStore};

        let test_dir = temp_test_dir("resolve_merge");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-merge".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Local Title", "Local Body");
        let remote_note = PlaintextNote::new("Remote Title", "Remote Body");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let env_remote = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-mrg-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            1,
            4,
            None,
            env_local,
            env_remote,
            None,
            "2026-09-10T02:00:00Z",
        );

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // Resolve using manual merge overrides (--merge with --title and --body)
        let result = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false, // local
            false, // remote
            true,  // merge
            false, // duplicate
            false, // restore
            None,
            None,
            Some("Manually Merged Title".to_string()),
            Some("Consolidated body containing both changes".to_string()),
            Some(vec!["merged".to_string(), "notes".to_string()]),
        )
        .expect("resolve merge");

        assert_eq!(result.conflict_id, conf_id);
        let retry_mut = result.retry_mutation.expect("retry mutation");
        assert_eq!(retry_mut.expected_revision, 4);

        // Verify storage decrypted object reflects merged note
        let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
        let obj = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(obj.revision, 4);

        let shown = cmd_show(Some(dir_path), &obj_id, false).expect("show");
        assert_eq!(shown.title, "Manually Merged Title");
        assert_eq!(shown.body, "Consolidated body containing both changes");
        assert_eq!(shown.tags, vec!["merged", "notes"]);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_resolve_duplicate_as_separate() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::ConflictStore;

        let test_dir = temp_test_dir("resolve_duplicate");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-dup".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Important Idea", "Offline brilliant thought");
        let remote_note = PlaintextNote::new("Remote Important Idea", "Remote revision content");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let env_remote = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-dup-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            2,
            7,
            None,
            env_local,
            env_remote,
            None,
            "2026-09-10T02:00:00Z",
        );

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // Resolve via --duplicate
        let result = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false, // local
            false, // remote
            false, // merge
            true,  // duplicate
            false, // restore
            Some("Important Idea (Branch Copy)".to_string()),
            None,
            None,
            None,
            None,
        )
        .expect("resolve duplicate");

        assert_eq!(result.conflict_id, conf_id);
        assert_eq!(result.object_id, obj_id);
        let dup_id = result.duplicated_object_id.expect("duplicate object id");

        // Verify original note has remote content
        let orig_shown = cmd_show(Some(dir_path), &obj_id, false).expect("show original");
        assert_eq!(orig_shown.title, "Remote Important Idea");
        assert_eq!(orig_shown.body, "Remote revision content");

        // Verify duplicated note has local content and custom title
        let dup_shown = cmd_show(Some(dir_path), &dup_id, false).expect("show duplicate");
        assert_eq!(dup_shown.title, "Important Idea (Branch Copy)");
        assert_eq!(dup_shown.body, "Offline brilliant thought");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_resolve_prefix_matching_and_validations() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::ConflictStore;

        let test_dir = temp_test_dir("resolve_validations");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-validations".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let note = PlaintextNote::new("Title", "Body");
        let env = note.encrypt(&vault_key, &obj_id).expect("enc");

        let conf_id = "abcd-1234-5678-90ef".to_string();
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            1,
            2,
            None,
            env.clone(),
            env,
            None,
            "2026-09-10T02:00:00Z",
        );

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // 1. Multiple mutually exclusive flags error
        let multi_err = cmd_resolve(
            Some(dir_path),
            &conf_id,
            true, // local
            true, // remote
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(multi_err, CliError::Io(_)));

        // 2. Non-existent conflict ID error
        let not_found_err = cmd_resolve(
            Some(dir_path),
            "non-existent-conflict",
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(not_found_err, CliError::ConflictNotFound(_)));

        // 3. Prefix matching: "abcd" matches "abcd-1234-5678-90ef"
        let prefix_res = cmd_resolve(
            Some(dir_path),
            "abcd",
            true, // local
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve by 4-char prefix");
        assert_eq!(prefix_res.conflict_id, conf_id);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_delete_vs_edit_conflict_lifecycle() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::{ConflictStore, ObjectStore};

        let test_dir = temp_test_dir("cli_del_vs_edit");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-del-edit".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("My Offline Edit", "Local edited content");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        // Remote deleted it: tombstone envelope
        let dummy_remote = PlaintextNote::new("Deleted Note", "Old content");
        let env_remote = dummy_remote
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-del-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            9,
            10,
            None,
            env_local.clone(),
            env_remote,
            None,
            "2026-09-10T02:00:00Z",
        )
        .with_deletion_flags(false, true);

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // 1. Verify conflict listing distinguishes deletion
        let items = cmd_conflicts(Some(dir_path), false, false).expect("list conflicts");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].conflict_id, conf_id);
        assert!(items[0].remote_is_deleted);
        assert!(!items[0].local_is_deleted);
        assert!(items[0].is_delete_vs_edit());
        assert_eq!(items[0].conflict_type, "Delete-vs-Edit");
        assert_eq!(items[0].title, "My Offline Edit");

        // 2. Verify merge is rejected on delete conflict
        let merge_err = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false,
            false,
            true, // merge
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(merge_err, CliError::Io(_)));

        // 3. Resolve by explicit restoration (--restore)
        let res = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false,
            false,
            false,
            false,
            true, // restore
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve restore");

        assert_eq!(res.conflict_id, conf_id);
        assert_eq!(res.object_id, obj_id);

        let retry_mut = res.retry_mutation.expect("retry mutation");
        assert_eq!(retry_mut.expected_revision, 10);
        assert_eq!(
            retry_mut.mutation_type,
            zk_storage::models::MutationType::Upsert
        );

        // Verify local object is active (not deleted)
        let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
        let obj = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(obj.revision, 10);
        assert!(!obj.is_deleted);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_delete_vs_edit_keep_remote_accepts_deletion() {
        use zk_storage::models::ConflictRecord;
        use zk_storage::traits::{ConflictStore, ObjectStore};

        let test_dir = temp_test_dir("cli_del_remote");
        let dir_path = test_dir.as_path();
        let pass = "test-passphrase-del-rem".to_string();

        cmd_init(Some(dir_path), Some(pass), true).expect("init vault");
        let sess_file = config::session_file(dir_path);
        let vault_key = session::load_session_key(&sess_file).expect("load key");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("My Offline Edit", "Local edited content");
        let env_local = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let dummy_remote = PlaintextNote::new("Deleted Note", "Old content");
        let env_remote = dummy_remote
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = format!("conf-del-rem-{}", uuid::Uuid::new_v4());
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            9,
            10,
            None,
            env_local,
            env_remote,
            None,
            "2026-09-10T02:00:00Z",
        )
        .with_deletion_flags(false, true);

        {
            let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
            storage.put_conflict(&record).expect("put");
        }

        // Resolve by keeping remote (--remote)
        let res = cmd_resolve(
            Some(dir_path),
            &conf_id,
            false,
            true, // remote
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve keep remote");

        assert!(res.retry_mutation.is_none());

        // Verify local object is marked deleted (tombstone preserved locally)
        let storage = SqliteStorage::open(config::db_file(dir_path)).expect("open db");
        let obj = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(obj.revision, 10);
        assert!(obj.is_deleted);

        let _ = fs::remove_dir_all(&test_dir);
    }
}
