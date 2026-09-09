//! Terminal/CLI client for zero-knowledge notes (`zk-note`).

mod commands;
mod config;
mod edit;
mod error;
mod session;

use clap::{Parser, Subcommand};
use commands::{cmd_edit, cmd_init, cmd_list, cmd_lock, cmd_new, cmd_show, cmd_status, cmd_unlock};
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
    /// List notes (requires unlocked vault)
    List {
        /// Filter by tag
        #[arg(short = 'g', long = "tag")]
        tag: Option<String>,

        /// Output notes in raw JSON format
        #[arg(long)]
        json: bool,
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
        Commands::List { tag, json } => {
            cmd_list(data_dir, tag, json)?;
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
    use zk_storage::traits::{BaseVersionStore, ObjectStore};

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
        let all_notes = cmd_list(Some(dir_path), None, false).expect("list notes");
        assert_eq!(all_notes.len(), 2);
        // Sorted by updated_at descending, note 2 was created after note 1
        assert_eq!(all_notes[0].id, note2_id);
        assert_eq!(all_notes[1].id, note1_id);

        // 8. List notes with tag filter
        let crypto_notes =
            cmd_list(Some(dir_path), Some("crypto".to_string()), false).expect("list crypto notes");
        assert_eq!(crypto_notes.len(), 1);
        assert_eq!(crypto_notes[0].id, note1_id);
        assert_eq!(crypto_notes[0].title, "Architecture Plan");

        let personal_notes = cmd_list(Some(dir_path), Some("personal".to_string()), false)
            .expect("list personal notes");
        assert_eq!(personal_notes.len(), 1);
        assert_eq!(personal_notes[0].id, note2_id);

        let non_existent_tag = cmd_list(Some(dir_path), Some("nonexistent".to_string()), false)
            .expect("list nonexistent tag");
        assert!(non_existent_tag.is_empty());

        // 9. Lock vault -> all note operations fail closed
        cmd_lock(Some(dir_path)).expect("lock");

        let locked_show = cmd_show(Some(dir_path), &note1_id, false).unwrap_err();
        match locked_show {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked on show, got {other:?}"),
        }

        let locked_list = cmd_list(Some(dir_path), None, false).unwrap_err();
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

        let unlocked_list = cmd_list(Some(dir_path), None, false).expect("list unlocked");
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
}
