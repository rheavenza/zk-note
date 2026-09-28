//! Comprehensive test suite for Ratatui TUI components and state machine (ZK-101).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::action::Action;
use super::app::{AccountField, AccountPendingAction, App, AppMode, Focus};
use super::ui::render;
use crate::client::auth::ClientAuthState;
use crate::client::conflicts::ClientConflictSummary;
use crate::client::notes::create_note;
use crate::client::sync::SyncStatus;
use crate::client::vault::unlock_vault;
use crate::commands::cmd_init;
use crate::config::session_file;
use crate::error::CliError;
use crate::session::{get_session_info, update_session_timeout};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::path::{Path, PathBuf};

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zk_note_tui_test_{}_{}",
            name,
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::create_dir_all(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Helper to render an app to a TestBackend terminal and return the buffer string.
fn render_to_string(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal.draw(|f| render(f, app)).expect("draw frame");
    format!("{:?}", terminal.backend().buffer())
}

fn setup_unlocked_vault_in_dir(dir: &Path) {
    cmd_init(Some(dir), Some("test-password-123".to_string()), true).expect("init vault");
    let _key = unlock_vault(Some(dir), "test-password-123", None).expect("unlock vault");
}

/// Helper creating a synthetic unlocked vault and temporary data directory.
fn setup_test_vault() -> (TestDir, App) {
    let temp_dir = TestDir::new("vault");
    cmd_init(
        Some(temp_dir.path()),
        Some("test-password-123".to_string()),
        true,
    )
    .expect("init vault");

    let key = unlock_vault(Some(temp_dir.path()), "test-password-123", None).expect("unlock vault");

    // Add 2 synthetic notes
    create_note(
        Some(temp_dir.path()),
        &key,
        "Alpha Note",
        "Body content for Alpha note.",
        vec!["work".to_string(), "rust".to_string()],
    )
    .expect("create note 1");

    create_note(
        Some(temp_dir.path()),
        &key,
        "Beta Document",
        "Confidential specification for Beta.",
        vec!["personal".to_string()],
    )
    .expect("create note 2");

    let app = App::new(Some(temp_dir.path()), 100, 30);
    (temp_dir, app)
}

// =========================================================================
// 1. Ratatui TestBackend Rendering Tests (AC-01 through AC-10)
// =========================================================================

#[test]
fn test_render_locked_screen() {
    let temp_dir = TestDir::new("locked");
    cmd_init(Some(temp_dir.path()), Some("pass-123".to_string()), true).expect("init vault");
    crate::client::vault::lock_vault(Some(temp_dir.path())).expect("lock vault");

    let mut app = App::new(Some(temp_dir.path()), 100, 30);
    app.passphrase_input = "secret".to_string();

    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Zero-Knowledge Vault Locked"));
    assert!(output.contains("Enter Master Passphrase:"));
    assert!(output.contains("******█"));
    assert!(output.contains("[Enter] Unlock"));
}

#[test]
fn test_render_empty_vault() {
    let temp_dir = TestDir::new("empty");
    cmd_init(Some(temp_dir.path()), Some("pass-123".to_string()), true).expect("init vault");

    let app = App::new(Some(temp_dir.path()), 100, 30);
    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Notes (0)"));
    assert!(output.contains("No notes found"));
    assert!(output.contains("No note selected."));
    assert!(output.contains("[Unlocked]"));
}

#[test]
fn test_render_populated_notes() {
    let (_dir, app) = setup_test_vault();
    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Notes (2)"));
    assert!(output.contains("Alpha Note"));
    assert!(output.contains("Beta Document"));
    assert!(
        output.contains("Body content for Alpha note")
            || output.contains("Confidential specification")
    );
    assert!(output.contains("[NORMAL]"));
    assert!(output.contains("[Unlocked]"));
}

#[test]
fn test_render_active_search() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::EnterSearch);
    app.update(Action::SearchChar('A'));
    app.update(Action::SearchChar('l'));
    app.update(Action::SearchChar('p'));
    app.update(Action::SearchChar('h'));

    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("/ Alph"));
    assert!(output.contains("Alpha Note"));
    assert!(!output.contains("Beta Document"));
    assert!(output.contains("[SEARCH]"));
}

#[test]
fn test_render_delete_confirmation() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::AskDelete);

    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Confirm Deletion"));
    assert!(output.contains("[y] Confirm Delete"));
    assert!(output.contains("[n/Esc] Cancel"));
    assert!(output.contains("[DELETE]"));
}

#[test]
fn test_render_conflict_screen() {
    let (_dir, mut app) = setup_test_vault();
    app.conflicts = vec![ClientConflictSummary {
        conflict_id: "conf-123".to_string(),
        object_id: "note-abc".to_string(),
        object_kind: 1,
        base_revision: 1,
        remote_revision: 2,
        resolved: false,
        remote_is_deleted: false,
        local_is_deleted: false,
        conflict_type: "EditVsEdit".to_string(),
        title: "Conflicted Roadmap Note".to_string(),
        created_at: "2026-09-22T10:00:00Z".to_string(),
        resolved_at: None,
    }];
    app.selected_conflict_index = Some(0);
    app.mode = AppMode::Conflict;

    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Unresolved Synchronization Conflicts"));
    assert!(output.contains("Conflicted Roadmap Note"));
    assert!(output.contains("[1/l] Keep Local"));
    assert!(output.contains("[2/r] Accept Remote"));
    assert!(output.contains("[3/m] Merge Candidate"));
    assert!(output.contains("[4/d] Duplicate"));
}

#[test]
fn test_render_help_overlay() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::ToggleHelp);

    let output = render_to_string(&app, 100, 30);

    assert!(output.contains("Keyboard Shortcut Cheat Sheet"));
    assert!(output.contains("Navigation:"));
    assert!(output.contains("j / Down"));
    assert!(output.contains("Note Operations:"));
    assert!(output.contains("Sync & Vault:"));
}

#[test]
fn test_render_terminal_too_small() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::Resize(70, 20));

    let output = render_to_string(&app, 70, 20);

    assert!(output.contains("Terminal Too Small"));
    assert!(output.contains("70x20"));
    assert!(output.contains("80x24"));
    assert!(output.contains("Please expand your terminal window."));
}

// =========================================================================
// 2. State & Action Tests (AC-03, AC-05, AC-06, AC-07, AC-08)
// =========================================================================

#[test]
fn test_navigation_boundaries_and_jumps() {
    let (_dir, mut app) = setup_test_vault();
    assert_eq!(app.notes.len(), 2);

    app.selected_index = Some(0);

    // Down to 1
    app.update(Action::MoveDown);
    assert_eq!(app.selected_index, Some(1));

    // Down at boundary stays 1
    app.update(Action::MoveDown);
    assert_eq!(app.selected_index, Some(1));

    // Up to 0
    app.update(Action::MoveUp);
    assert_eq!(app.selected_index, Some(0));

    // Up at boundary stays 0
    app.update(Action::MoveUp);
    assert_eq!(app.selected_index, Some(0));

    // JumpBottom ('G')
    app.update(Action::JumpBottom);
    assert_eq!(app.selected_index, Some(1));

    // JumpTop ('g')
    app.update(Action::JumpTop);
    assert_eq!(app.selected_index, Some(0));
}

#[test]
fn test_empty_vault_navigation_safety() {
    let temp_dir = TestDir::new("empty_nav");
    cmd_init(Some(temp_dir.path()), Some("pass-123".to_string()), true).expect("init vault");
    let mut app = App::new(Some(temp_dir.path()), 100, 30);

    assert_eq!(app.notes.len(), 0);
    assert_eq!(app.selected_index, None);

    // Navigation must not panic or set invalid index
    app.update(Action::MoveDown);
    assert_eq!(app.selected_index, None);
    app.update(Action::MoveUp);
    assert_eq!(app.selected_index, None);
    app.update(Action::JumpTop);
    assert_eq!(app.selected_index, None);
    app.update(Action::JumpBottom);
    assert_eq!(app.selected_index, None);
}

#[test]
fn test_focus_cycling() {
    let (_dir, mut app) = setup_test_vault();
    assert_eq!(app.focus, Focus::NotesList);

    // Tab -> Preview
    app.update(Action::NextPane);
    assert_eq!(app.focus, Focus::NotePreview);

    // Tab -> NotesList
    app.update(Action::NextPane);
    assert_eq!(app.focus, Focus::NotesList);

    // Shift+Tab -> Preview
    app.update(Action::PrevPane);
    assert_eq!(app.focus, Focus::NotePreview);
}

#[test]
fn test_mode_transitions() {
    let (_dir, mut app) = setup_test_vault();
    assert_eq!(app.mode, AppMode::Normal);

    // Search
    app.update(Action::EnterSearch);
    assert_eq!(app.mode, AppMode::Search);
    app.update(Action::ExitSearch);
    assert_eq!(app.mode, AppMode::Normal);

    // Create
    app.update(Action::EnterCreate);
    assert_eq!(app.mode, AppMode::Create);
    app.update(Action::CancelEdit);
    assert_eq!(app.mode, AppMode::Normal);

    // InlineEdit
    app.update(Action::EnterInlineEdit);
    assert_eq!(app.mode, AppMode::InlineEdit);
    app.update(Action::CancelEdit);
    assert_eq!(app.mode, AppMode::Normal);

    // Delete confirm
    app.update(Action::AskDelete);
    assert_eq!(app.mode, AppMode::DeleteConfirm);
    app.update(Action::CancelDelete);
    assert_eq!(app.mode, AppMode::Normal);

    // Conflicts
    app.update(Action::OpenConflicts);
    assert_eq!(app.mode, AppMode::Conflict);
    app.update(Action::CloseConflicts);
    assert_eq!(app.mode, AppMode::Normal);

    // Help
    app.update(Action::ToggleHelp);
    assert_eq!(app.mode, AppMode::Help);
    app.update(Action::CloseOverlay);
    assert_eq!(app.mode, AppMode::Normal);

    // Resize below MIN -> TerminalTooSmall -> Restore
    app.update(Action::Resize(60, 20));
    assert_eq!(app.mode, AppMode::TerminalTooSmall);
    app.update(Action::Resize(100, 30));
    assert_eq!(app.mode, AppMode::Normal);
}

#[test]
fn test_search_incremental_filtering() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::EnterSearch);

    // Search 'beta'
    for c in "beta".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.displayed_notes()[0].title, "Beta Document");

    // Backspace
    app.update(Action::SearchBackspace);
    app.update(Action::SearchBackspace);
    app.update(Action::SearchBackspace);
    app.update(Action::SearchBackspace);
    assert_eq!(app.displayed_notes().len(), 2);

    // Exit search
    app.update(Action::ExitSearch);
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.search_query, "");
    assert_eq!(app.displayed_notes().len(), 2);
}

#[test]
fn test_delete_confirmation_and_tombstone() {
    let (_dir, mut app) = setup_test_vault();
    assert_eq!(app.notes.len(), 2);

    app.update(Action::AskDelete);
    assert_eq!(app.mode, AppMode::DeleteConfirm);

    // Confirm deletion
    app.update(Action::ConfirmDelete);
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.notes.len(), 1);
}

#[test]
fn test_manual_sync_dispatch() {
    let (_dir, mut app) = setup_test_vault();
    assert_ne!(app.sync_status, SyncStatus::Syncing);

    app.update(Action::TriggerSync);
    assert_eq!(app.sync_status, SyncStatus::Syncing);
}

// =========================================================================
// 3. Security State Test: Zeroize & Memory Scrubbing on Lock (SEC-003, AC-04)
// =========================================================================

#[test]
fn test_security_locking_and_autolock_clears_all_decrypted_buffers() {
    let (_dir, mut app) = setup_test_vault();

    // Verify app contains decrypted note title and body in memory
    assert!(!app.notes.is_empty());
    assert!(app.preview.is_some());
    let title_canary = app.preview.as_ref().unwrap().title.clone();
    let body_canary = app.preview.as_ref().unwrap().body.clone();

    // Type a search query and draft note inputs
    app.search_query = "search-secret".to_string();
    app.edit_title = "draft-secret".to_string();
    app.edit_body = "draft-body".to_string();

    // Verify rendered output in unlocked mode contains the canaries
    let unlocked_output = render_to_string(&app, 100, 30);
    assert!(unlocked_output.contains(&title_canary));

    // Explicit lock!
    assert!(app.lock_and_clear().is_ok());

    // 1. Verify in-memory buffers are completely zeroized/cleared
    assert!(app.vault_key.is_none());
    assert!(app.notes.is_empty());
    assert!(app.preview.is_none());
    assert!(app.search_query.is_empty());
    assert!(app.search_results.is_empty());
    assert!(app.conflicts.is_empty());
    assert!(app.conflict_detail.is_none());
    assert!(app.edit_title.is_empty());
    assert!(app.edit_tags.is_empty());
    assert!(app.edit_body.is_empty());
    assert!(app.passphrase_input.is_empty());
    assert_eq!(app.mode, AppMode::Locked);

    // 2. Verify subsequent rendering does NOT leak any plaintext
    let locked_output = render_to_string(&app, 100, 30);
    assert!(!locked_output.contains(&title_canary));
    assert!(!locked_output.contains(&body_canary));
    assert!(!locked_output.contains("search-secret"));
    assert!(!locked_output.contains("draft-secret"));
    assert!(!locked_output.contains("draft-body"));
}

#[test]
fn test_idle_autolock_ticks_do_not_extend_session_and_expiry_locks_ui() {
    let (temp_dir, mut app) = setup_test_vault();
    let sess_path = session_file(temp_dir.path());

    // Set 2-second idle timeout
    let _ = update_session_timeout(&sess_path, Some(2)).expect("update timeout");

    let info_before = get_session_info(&sess_path).expect("session info").unwrap();
    let last_active_before = info_before.last_active_at;

    // Simulate repeated 250ms ticks without user input
    for _ in 0..10 {
        app.update(Action::Tick);
    }

    // Prove repeated ticks did NOT extend the session (last_active_at is unchanged)
    let info_after_ticks = get_session_info(&sess_path).expect("session info").unwrap();
    assert_eq!(info_after_ticks.last_active_at, last_active_before);
    assert_eq!(app.mode, AppMode::Normal);

    // Now artificially age the session past the 2-second timeout
    let bytes = std::fs::read(&sess_path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    envelope["last_active_at"] = serde_json::json!(last_active_before - 10);
    let aged_json = serde_json::to_string(&envelope).unwrap();
    std::fs::write(&sess_path, aged_json.as_bytes()).unwrap();

    // Verify tick now detects expiry and locks the UI
    app.update(Action::Tick);

    assert_eq!(app.mode, AppMode::Locked);
    assert!(app.vault_key.is_none());
    assert!(app.notes.is_empty());
    assert!(app.preview.is_none());
    assert!(app.search_query.is_empty());
    assert!(app.search_results.is_empty());
    assert!(app
        .status_message
        .as_deref()
        .unwrap()
        .contains("inactivity auto-lock policy"));
}

#[test]
fn test_idle_autolock_real_input_refreshes_session() {
    let (temp_dir, mut app) = setup_test_vault();
    let sess_path = session_file(temp_dir.path());

    let _ = update_session_timeout(&sess_path, Some(300)).expect("update timeout");

    let info_before = get_session_info(&sess_path).expect("session info").unwrap();

    // Artificially set last_active_at in the past
    let bytes = std::fs::read(&sess_path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    envelope["last_active_at"] = serde_json::json!(info_before.last_active_at - 100);
    let past_json = serde_json::to_string(&envelope).unwrap();
    std::fs::write(&sess_path, past_json.as_bytes()).unwrap();

    let info_past = get_session_info(&sess_path).expect("session info").unwrap();
    assert_eq!(info_past.last_active_at, info_before.last_active_at - 100);

    // Real user key input
    app.handle_key(KeyEvent::from(KeyCode::Char('j')));

    // Session activity timestamp must be refreshed to now
    let info_refreshed = get_session_info(&sess_path).expect("session info").unwrap();
    assert!(info_refreshed.last_active_at > info_past.last_active_at);
}

#[test]
fn test_honest_lock_failure_when_persistent_cleanup_fails() {
    let (temp_dir, mut app) = setup_test_vault();
    let sess_path = session_file(temp_dir.path());
    assert!(sess_path.exists());

    // Inject persistent failure: make directory read-only so .session cannot be removed
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let orig_perms = std::fs::metadata(temp_dir.path()).unwrap().permissions();
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let lock_result = app.lock_and_clear();

        // Restore permissions immediately so drop / cleanup can proceed
        std::fs::set_permissions(temp_dir.path(), orig_perms).unwrap();

        // Must return Err
        assert!(lock_result.is_err());

        // NO false success message
        assert_ne!(app.status_message.as_deref(), Some("Vault locked."));
        assert!(app.status_message.is_none());

        // Truthful error message recorded
        assert!(app.error_message.is_some());
        assert!(app
            .error_message
            .as_deref()
            .unwrap()
            .contains("Failed to invalidate session"));

        // Fail-closed in memory: decrypted state must still be zeroized/cleared
        assert!(app.vault_key.is_none());
        assert!(app.notes.is_empty());
        assert!(app.preview.is_none());
        assert!(app.search_query.is_empty());
        assert_eq!(app.mode, AppMode::Locked);

        // Rendering shows the truthful error message
        let rendered = render_to_string(&app, 100, 30);
        assert!(rendered.contains("Failed to invalidate session"));
        assert!(!rendered.contains("Vault locked."));
    }
}

#[test]
fn test_fulltext_search_title_tag_body_no_match_clear_lock() {
    let temp_dir = TestDir::new("search_fulltext");
    cmd_init(
        Some(temp_dir.path()),
        Some("test-password-123".to_string()),
        true,
    )
    .expect("init vault");

    let key = unlock_vault(Some(temp_dir.path()), "test-password-123", None).expect("unlock vault");

    create_note(
        Some(temp_dir.path()),
        &key,
        "Cooking Recipes",
        "Secret pasta sauce ingredient is basil leaves.",
        vec!["food".to_string()],
    )
    .expect("create note 1");

    create_note(
        Some(temp_dir.path()),
        &key,
        "Rust Guidelines",
        "Always write thorough unit tests and check error cases.",
        vec!["programming".to_string()],
    )
    .expect("create note 2");

    create_note(
        Some(temp_dir.path()),
        &key,
        "Travel Plans",
        "Book train tickets to Kyoto and pack warm clothes.",
        vec!["vacation".to_string()],
    )
    .expect("create note 3");

    let mut app = App::new(Some(temp_dir.path()), 100, 30);
    assert_eq!(app.notes.len(), 3);

    // 1. Title-only match: "Cooking"
    app.update(Action::EnterSearch);
    for c in "Cooking".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.displayed_notes()[0].title, "Cooking Recipes");

    // 2. Tag-only match: "programming"
    app.update(Action::ExitSearch);
    app.update(Action::EnterSearch);
    for c in "programming".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.displayed_notes()[0].title, "Rust Guidelines");

    // 3. Body-only match: "Kyoto" (does NOT appear in title or tags!)
    app.update(Action::ExitSearch);
    app.update(Action::EnterSearch);
    for c in "Kyoto".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.displayed_notes()[0].title, "Travel Plans");

    // 4. Body-only match: "basil" (does NOT appear in title or tags!)
    app.update(Action::ExitSearch);
    app.update(Action::EnterSearch);
    for c in "basil".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.displayed_notes()[0].title, "Cooking Recipes");

    // 5. No-match query: "nonexistentxyz"
    app.update(Action::ExitSearch);
    app.update(Action::EnterSearch);
    for c in "nonexistentxyz".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 0);
    assert!(app.selected_index.is_none());
    assert!(app.preview.is_none());

    // 6. Clear search (ExitSearch) restores full note list
    app.update(Action::ExitSearch);
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.search_query, "");
    assert_eq!(app.displayed_notes().len(), 3);
    assert_eq!(app.selected_index, Some(0));
    assert!(app.preview.is_some());

    // 7. Lock clears search query and results
    app.update(Action::EnterSearch);
    for c in "basil".chars() {
        app.update(Action::SearchChar(c));
    }
    assert_eq!(app.displayed_notes().len(), 1);
    assert_eq!(app.search_query, "basil");
    assert!(!app.search_results.is_empty());

    assert!(app.lock_and_clear().is_ok());
    assert_eq!(app.mode, AppMode::Locked);
    assert!(app.search_query.is_empty());
    assert!(app.search_results.is_empty());
}

#[test]
fn test_render_account_modal() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::OpenAccount);
    assert_eq!(app.mode, AppMode::Account);

    let output = render_to_string(&app, 80, 24);
    assert!(output.contains("Server Connection & Account Authentication"));
    assert!(output.contains("Server Address"));
    assert!(output.contains("Session Token"));
    assert!(output.contains("Connect & Authorize Device"));
    assert!(output.contains("Sign Out & Revoke Session"));
    assert!(output.contains("Active Connection Status"));
    assert!(output.contains("Signing in does NOT link, upload, replace, or restore your vault."));
}

#[test]
fn test_account_masked_input_and_zeroization() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::OpenAccount);
    assert_eq!(app.mode, AppMode::Account);

    // Switch focus to token field if not already
    app.account_focus_field = AccountField::Token;

    // Type a secret token
    for c in "super_secret_token_123".chars() {
        app.update(Action::AccountTokenChar(c));
    }
    assert_eq!(app.account_token_input, "super_secret_token_123");

    // Render output must mask with asterisks and NEVER leak the plaintext token
    let output = render_to_string(&app, 80, 24);
    assert!(output.contains("**********************")); // 22 asterisks
    assert!(!output.contains("super_secret_token_123"));

    // Debug representation of App must also redact the token (SEC-003, AC-03)
    let debug_str = format!("{app:?}");
    assert!(!debug_str.contains("super_secret_token_123"));
    assert!(debug_str.contains("[REDACTED]"));

    // Closing account view must zeroize and clear the token buffer
    app.update(Action::CloseAccount);
    assert_eq!(app.mode, AppMode::Normal);
    assert!(app.account_token_input.is_empty());

    // Re-open and test zeroization on vault lock
    app.update(Action::OpenAccount);
    app.account_focus_field = AccountField::Token;
    for c in "another_secret".chars() {
        app.update(Action::AccountTokenChar(c));
    }
    assert_eq!(app.account_token_input, "another_secret");

    assert!(app.lock_and_clear().is_ok());
    assert_eq!(app.mode, AppMode::Locked);
    assert!(app.account_token_input.is_empty());
}

#[test]
fn test_account_field_navigation_and_actions() {
    let (_dir, mut app) = setup_test_vault();
    app.update(Action::OpenAccount);

    // Initial state
    app.account_focus_field = AccountField::ServerUrl;

    // NextField cycling: ServerUrl -> Token -> ConnectButton -> SignOutButton -> ServerUrl
    app.update(Action::AccountNextField);
    assert_eq!(app.account_focus_field, AccountField::Token);
    app.update(Action::AccountNextField);
    assert_eq!(app.account_focus_field, AccountField::ConnectButton);
    app.update(Action::AccountNextField);
    assert_eq!(app.account_focus_field, AccountField::SignOutButton);
    app.update(Action::AccountNextField);
    assert_eq!(app.account_focus_field, AccountField::ServerUrl);

    // PrevField cycling
    app.update(Action::AccountPrevField);
    assert_eq!(app.account_focus_field, AccountField::SignOutButton);

    // Edit server URL
    app.account_focus_field = AccountField::ServerUrl;
    app.account_server_input.clear();
    for c in "http://127.0.0.1:9090".chars() {
        app.update(Action::AccountServerChar(c));
    }
    assert_eq!(app.account_server_input, "http://127.0.0.1:9090");
    app.update(Action::AccountServerBackspace);
    assert_eq!(app.account_server_input, "http://127.0.0.1:909");

    // Submit with empty token produces error
    app.account_token_input.clear();
    app.update(Action::AccountSubmit);
    assert!(app.error_message.is_some());
    assert!(app.account_pending_action.is_none());

    // Submit with token sets AccountPendingAction::Connect and zeroes in-app token buffer
    for c in "auth_token_xyz".chars() {
        app.update(Action::AccountTokenChar(c));
    }
    app.update(Action::AccountSubmit);
    assert!(app.account_token_input.is_empty());
    match app.account_pending_action.take() {
        Some(AccountPendingAction::Connect { server_url, token }) => {
            assert_eq!(server_url, "http://127.0.0.1:909");
            assert_eq!(token, "auth_token_xyz");
        }
        other => panic!("expected Connect pending action, got {other:?}"),
    }

    // SignOut action sets AccountPendingAction::SignOut
    app.update(Action::AccountSignOut);
    assert_eq!(
        app.account_pending_action.take(),
        Some(AccountPendingAction::SignOut)
    );

    // Refresh action sets AccountPendingAction::RefreshStatus
    app.update(Action::AccountRefresh);
    assert_eq!(
        app.account_pending_action.take(),
        Some(AccountPendingAction::RefreshStatus)
    );
}

#[test]
fn test_account_status_bar_badges() {
    let (_dir, mut app) = setup_test_vault();
    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];

    // 1. Local-only
    app.account_state = ClientAuthState::LocalOnly;
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains("[Local-only]"));

    // 1b. Unverified
    app.account_state = ClientAuthState::Unverified {
        server_url: "http://127.0.0.1:8080".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains(&format!("[Auth: {short_id} (unverified)]")));

    // 2. Authenticated
    app.account_state = ClientAuthState::Authenticated {
        server_url: "http://127.0.0.1:8080".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains(&format!("[Auth: {short_id}]")));

    // 3. Offline
    app.account_state = ClientAuthState::Offline {
        server_url: "http://127.0.0.1:8080".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: None,
        error: "connection refused".to_string(),
    };
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains("[Server: Offline]"));

    // 4. Expired
    app.account_state = ClientAuthState::Expired {
        server_url: "http://127.0.0.1:8080".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: None,
    };
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains("[Server: Expired]"));

    // 5. Revoked
    app.account_state = ClientAuthState::Revoked {
        server_url: "http://127.0.0.1:8080".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: None,
    };
    let out = render_to_string(&app, 80, 24);
    assert!(out.contains("[Server: Revoked]"));
}

#[tokio::test]
async fn test_startup_offline_preserves_offline_first_and_updates_badge() {
    let temp_dir =
        std::env::temp_dir().join(format!("zk_tui_startup_off_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    setup_unlocked_vault_in_dir(&temp_dir);

    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];
    // Point to an unreachable port to simulate offline
    let session = crate::auth::StoredAuthSession {
        server_url: "http://127.0.0.1:1".to_string(),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        token: zk_protocol::auth::AuthToken::new("test_tok"),
        expires_at: None,
    };
    crate::auth::save_auth_session(&crate::config::auth_session_file(&temp_dir), &session).unwrap();

    // 1. App::new initializes with Unverified state and queues StartupVerify
    let mut app = App::new(Some(&temp_dir), 100, 30);
    assert!(app.account_state.is_unverified());
    assert_eq!(
        app.account_pending_action,
        Some(AccountPendingAction::StartupVerify)
    );

    // 2. Initial render shows honest unverified badge, never falsely active
    let initial_render = render_to_string(&app, 100, 30);
    assert!(initial_render.contains(&format!("[Auth: {short_id} (unverified)]")));
    assert!(!initial_render.contains(&format!("[Auth: {short_id}] ")));

    // 3. User can interact offline immediately without blocking
    app.update(Action::MoveDown);
    assert!(!app.should_quit);

    // 4. Dispatch StartupVerify
    match app.account_pending_action.take() {
        Some(AccountPendingAction::StartupVerify) => {
            let st = crate::client::auth::check_auth_state_online(Some(&temp_dir))
                .await
                .unwrap();
            assert!(st.is_offline(), "offline server must yield Offline state");
            app.account_state = st;
        }
        other => panic!("expected StartupVerify, got {other:?}"),
    }

    // 5. Subsequent render shows [Server: Offline]
    let verified_render = render_to_string(&app, 100, 30);
    assert!(verified_render.contains("[Server: Offline]"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_startup_revoked_session_updates_badge() {
    let (server_url, state, _shutdown) = crate::client::auth::tests::start_test_server().await;
    let temp_dir =
        std::env::temp_dir().join(format!("zk_tui_startup_rev_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    setup_unlocked_vault_in_dir(&temp_dir);

    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];
    let (_, authorizer) = state
        .db
        .create_session(account_id, None, None, Some(3600))
        .await
        .unwrap();

    let session = crate::client::auth::authorize_terminal_device(
        Some(&temp_dir),
        &server_url,
        authorizer.expose_secret(),
        Some(account_id),
        Some("Revoked Startup".to_string()),
        None,
    )
    .await
    .expect("auth succeeds");

    // Revoke device on server
    state
        .db
        .revoke_device(account_id, session.device_id)
        .await
        .unwrap();

    let mut app = App::new(Some(&temp_dir), 100, 30);
    assert!(app.account_state.is_unverified());
    let initial_render = render_to_string(&app, 100, 30);
    assert!(initial_render.contains(&format!("[Auth: {short_id} (unverified)]")));

    match app.account_pending_action.take() {
        Some(AccountPendingAction::StartupVerify) => {
            let st = crate::client::auth::check_auth_state_online(Some(&temp_dir))
                .await
                .unwrap();
            assert!(st.is_revoked(), "revoked device must yield Revoked state");
            app.account_state = st;
        }
        other => panic!("expected StartupVerify, got {other:?}"),
    }

    let verified_render = render_to_string(&app, 100, 30);
    assert!(verified_render.contains("[Server: Revoked]"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_startup_expired_session_updates_badge() {
    let (server_url, state, _shutdown) = crate::client::auth::tests::start_test_server().await;
    let temp_dir =
        std::env::temp_dir().join(format!("zk_tui_startup_exp_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    setup_unlocked_vault_in_dir(&temp_dir);

    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];
    let (server_sess, token) = state
        .db
        .create_session(
            account_id,
            None,
            Some("Expired Startup".to_string()),
            Some(-10),
        )
        .await
        .unwrap();

    let session = crate::auth::StoredAuthSession {
        server_url: server_url.clone(),
        account_id,
        device_id: server_sess.device_id.unwrap_or_else(uuid::Uuid::new_v4),
        session_id: Some(server_sess.session_id),
        token,
        expires_at: None,
    };
    crate::auth::save_auth_session(&crate::config::auth_session_file(&temp_dir), &session).unwrap();

    let mut app = App::new(Some(&temp_dir), 100, 30);
    assert!(app.account_state.is_unverified());
    let initial_render = render_to_string(&app, 100, 30);
    assert!(initial_render.contains(&format!("[Auth: {short_id} (unverified)]")));

    match app.account_pending_action.take() {
        Some(AccountPendingAction::StartupVerify) => {
            let st = crate::client::auth::check_auth_state_online(Some(&temp_dir))
                .await
                .unwrap();
            assert!(st.is_expired(), "expired session must yield Expired state");
            app.account_state = st;
        }
        other => panic!("expected StartupVerify, got {other:?}"),
    }

    let verified_render = render_to_string(&app, 100, 30);
    assert!(verified_render.contains("[Server: Expired]"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_startup_with_saved_session_verifies_active() {
    let (server_url, state, _shutdown) = crate::client::auth::tests::start_test_server().await;
    let temp_dir =
        std::env::temp_dir().join(format!("zk_tui_startup_act_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    setup_unlocked_vault_in_dir(&temp_dir);

    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];
    let (server_sess, token) = state
        .db
        .create_session(
            account_id,
            None,
            Some("Active Startup".to_string()),
            Some(3600),
        )
        .await
        .unwrap();

    let session = crate::auth::StoredAuthSession {
        server_url: server_url.clone(),
        account_id,
        device_id: server_sess.device_id.unwrap_or_else(uuid::Uuid::new_v4),
        session_id: Some(server_sess.session_id),
        token,
        expires_at: None,
    };
    crate::auth::save_auth_session(&crate::config::auth_session_file(&temp_dir), &session).unwrap();

    let mut app = App::new(Some(&temp_dir), 100, 30);
    assert!(app.account_state.is_unverified());
    assert_eq!(
        app.account_pending_action,
        Some(AccountPendingAction::StartupVerify)
    );
    let initial_render = render_to_string(&app, 100, 30);
    assert!(initial_render.contains(&format!("[Auth: {short_id} (unverified)]")));

    match app.account_pending_action.take() {
        Some(AccountPendingAction::StartupVerify) => {
            let st = crate::client::auth::check_auth_state_online(Some(&temp_dir))
                .await
                .unwrap();
            assert!(
                st.is_authenticated(),
                "active session must yield Authenticated state"
            );
            app.account_state = st;
        }
        other => panic!("expected StartupVerify, got {other:?}"),
    }

    let verified_render = render_to_string(&app, 100, 30);
    assert!(verified_render.contains(&format!("[Auth: {short_id}]")));
    assert!(!verified_render.contains("(unverified)"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_startup_verification_stalled_server_preserves_offline_first_and_updates_badge() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let local_addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_rx => {},
            res = listener.accept() => {
                if let Ok((mut socket, _)) = res {
                    use tokio::io::AsyncReadExt;
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    // Deliberately stall: never write response bytes
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
    });

    std::env::set_var("ZK_AUTH_TIMEOUT_MS", "200");
    std::env::set_var("ZK_AUTH_CONNECT_TIMEOUT_MS", "200");

    let temp_dir =
        std::env::temp_dir().join(format!("zk_tui_startup_stall_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    setup_unlocked_vault_in_dir(&temp_dir);

    let account_id = uuid::Uuid::new_v4();
    let short_id = &account_id.to_string()[..8];
    let session = crate::auth::StoredAuthSession {
        server_url: format!("http://{}", local_addr),
        account_id,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        token: zk_protocol::auth::AuthToken::new("test_tok"),
        expires_at: None,
    };
    crate::auth::save_auth_session(&crate::config::auth_session_file(&temp_dir), &session).unwrap();

    // 1. App initializes with Unverified state and queues StartupVerify
    let mut app = App::new(Some(&temp_dir), 100, 30);
    assert!(app.account_state.is_unverified());
    assert_eq!(
        app.account_pending_action,
        Some(AccountPendingAction::StartupVerify)
    );

    // 2. Initial render shows honest unverified badge immediately without freeze
    let initial_render = render_to_string(&app, 100, 30);
    assert!(initial_render.contains(&format!("[Auth: {short_id} (unverified)]")));

    // 3. User can interact offline immediately without blocking
    app.update(Action::MoveDown);
    assert!(!app.should_quit);

    // 4. Dispatch bounded request against stalled server (times out quickly)
    match app.account_pending_action.take() {
        Some(AccountPendingAction::StartupVerify) => {
            let st = crate::client::auth::check_auth_state_online(Some(&temp_dir))
                .await
                .unwrap();
            assert!(st.is_offline(), "stalled server must yield Offline state");
            app.account_state = st;
        }
        other => panic!("expected StartupVerify, got {other:?}"),
    }

    std::env::remove_var("ZK_AUTH_TIMEOUT_MS");
    std::env::remove_var("ZK_AUTH_CONNECT_TIMEOUT_MS");

    // 5. Subsequent render shows [Server: Offline]
    let verified_render = render_to_string(&app, 100, 30);
    assert!(verified_render.contains("[Server: Offline]"));

    let _ = shutdown_tx.send(());
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_auth_out_of_order_result_after_sign_out_is_rejected() {
    let (_dir, mut app) = setup_test_vault();
    let account_a = uuid::Uuid::new_v4();
    let device_a = uuid::Uuid::new_v4();
    let server_a = "http://server-a:8080".to_string();

    app.account_state = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: device_a,
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };
    let gen_a = app.current_auth_generation();

    // 1. User signs out in Account modal
    app.mode = AppMode::Account;
    app.update(Action::AccountSignOut);
    assert!(
        app.current_auth_generation() > gen_a,
        "SignOut must invalidate in-flight auth generation"
    );

    // Simulate completion of sign-out in event loop
    app.invalidate_auth_ops();
    app.account_state = ClientAuthState::LocalOnly;
    app.status_message = Some("Session revoked. Signed out successfully.".to_string());
    app.error_message = None;

    // 2. Delayed background completion for Account A arrives
    let delayed_state = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: device_a,
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };

    let applied_stale_gen = app.apply_auth_worker_result(
        gen_a,
        Some(account_a),
        Some(&server_a),
        Ok(delayed_state.clone()),
        false,
    );
    assert!(
        !applied_stale_gen,
        "Stale completion from prior generation must be rejected"
    );
    assert_eq!(
        app.account_state,
        ClientAuthState::LocalOnly,
        "LocalOnly state must not be overwritten by delayed success"
    );
    assert_eq!(
        app.status_message.as_deref(),
        Some("Session revoked. Signed out successfully.")
    );
    assert!(app.error_message.is_none());

    // 3. Even if generation somehow matched, LocalOnly guard must reject server auth results
    let curr_gen = app.current_auth_generation();
    let applied_local_only = app.apply_auth_worker_result(
        curr_gen,
        Some(account_a),
        Some(&server_a),
        Ok(delayed_state),
        false,
    );
    assert!(
        !applied_local_only,
        "LocalOnly state machine guard must reject any background server auth results"
    );
    assert_eq!(app.account_state, ClientAuthState::LocalOnly);

    // 4. Stale background error must also be rejected without modifying error_message
    let applied_err = app.apply_auth_worker_result(
        gen_a,
        Some(account_a),
        Some(&server_a),
        Err(CliError::Network("connection reset".to_string())),
        true,
    );
    assert!(!applied_err, "Stale error must be rejected");
    assert_eq!(app.account_state, ClientAuthState::LocalOnly);
    assert!(
        app.error_message.is_none(),
        "Stale completion must not set error_message"
    );
}

#[test]
fn test_auth_out_of_order_result_after_account_change_is_rejected() {
    let (_dir, mut app) = setup_test_vault();
    let account_a = uuid::Uuid::new_v4();
    let server_a = "http://server-a:8080".to_string();

    app.account_state = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };
    let gen_a = app.current_auth_generation();

    // 1. User connects to a new server and account B
    let account_b = uuid::Uuid::new_v4();
    let server_b = "http://server-b:8080".to_string();
    app.mode = AppMode::Account;
    app.account_server_input = server_b.clone();
    app.account_token_input = "tok-b".to_string();
    app.update(Action::AccountSubmit);
    assert!(
        app.current_auth_generation() > gen_a,
        "AccountSubmit must invalidate in-flight auth generation"
    );

    // Simulate successful authorization of device on server B
    app.invalidate_auth_ops();
    let gen_b = app.current_auth_generation();
    app.account_state = ClientAuthState::Authenticated {
        server_url: server_b.clone(),
        account_id: account_b,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };
    app.status_message = Some("Device authorized on server B.".to_string());
    app.error_message = None;

    // 2. Delayed background result for Account A arrives with old generation
    let delayed_state_a = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };

    let applied_stale_gen = app.apply_auth_worker_result(
        gen_a,
        Some(account_a),
        Some(&server_a),
        Ok(delayed_state_a.clone()),
        false,
    );
    assert!(
        !applied_stale_gen,
        "Stale completion for Account A must be rejected by generation guard"
    );
    assert_eq!(
        app.account_state.account_id(),
        Some(account_b),
        "Account B must remain active"
    );
    assert_eq!(app.account_state.server_url(), Some(server_b.as_str()));
    assert_eq!(
        app.status_message.as_deref(),
        Some("Device authorized on server B.")
    );

    // 3. Even if generation matched gen_b, session identity guard must reject Account A
    let applied_mismatched_id = app.apply_auth_worker_result(
        gen_b,
        Some(account_a),
        Some(&server_a),
        Ok(delayed_state_a),
        true,
    );
    assert!(
        !applied_mismatched_id,
        "Session identity guard must reject result for mismatched account"
    );
    assert_eq!(app.account_state.account_id(), Some(account_b));
    assert_eq!(app.account_state.server_url(), Some(server_b.as_str()));
}

#[test]
fn test_auth_superseded_refresh_is_rejected() {
    let (_dir, mut app) = setup_test_vault();
    let account_a = uuid::Uuid::new_v4();
    let server_a = "http://server-a:8080".to_string();

    app.account_state = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: None,
    };

    // 1. User triggers first refresh (gen1)
    app.mode = AppMode::Account;
    app.update(Action::AccountRefresh);
    let gen1 = app.current_auth_generation();

    // 2. User triggers second refresh (gen2)
    app.update(Action::AccountRefresh);
    let gen2 = app.current_auth_generation();
    assert!(
        gen2 > gen1,
        "Subsequent refresh must advance the generation counter"
    );

    // 3. Second refresh completes first and succeeds
    let refreshed_state = ClientAuthState::Authenticated {
        server_url: server_a.clone(),
        account_id: account_a,
        device_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        expires_at: Some("2026-10-01T00:00:00Z".to_string()),
    };
    let applied2 = app.apply_auth_worker_result(
        gen2,
        Some(account_a),
        Some(&server_a),
        Ok(refreshed_state.clone()),
        true,
    );
    assert!(applied2, "Current generation refresh must be accepted");
    assert_eq!(app.account_state, refreshed_state);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Server status updated.")
    );
    assert!(app.error_message.is_none());

    // 4. First refresh finishes later with an error (e.g. timeout)
    let applied1 = app.apply_auth_worker_result(
        gen1,
        Some(account_a),
        Some(&server_a),
        Err(CliError::Network("timed out".to_string())),
        true,
    );
    assert!(!applied1, "Superseded refresh result must be rejected");
    assert_eq!(
        app.account_state, refreshed_state,
        "Newer auth state must not be overwritten by superseded result"
    );
    assert_eq!(
        app.status_message.as_deref(),
        Some("Server status updated."),
        "Newer status message must not be cleared by superseded result"
    );
    assert!(
        app.error_message.is_none(),
        "Superseded error must not set error_message"
    );
}
