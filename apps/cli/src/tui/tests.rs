//! Comprehensive test suite for Ratatui TUI components and state machine (ZK-101).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::action::Action;
use super::app::{App, AppMode, Focus};
use super::ui::render;
use crate::client::conflicts::ClientConflictSummary;
use crate::client::notes::create_note;
use crate::client::sync::SyncStatus;
use crate::client::vault::unlock_vault;
use crate::commands::cmd_init;
use crate::config::session_file;
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
