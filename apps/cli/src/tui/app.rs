//! State machine and core state for the interactive terminal UI (ZK-101).

use super::action::Action;
use crate::client::auth::{get_local_auth_state, ClientAuthState};
use crate::client::conflicts::{
    get_conflict_detail, list_conflicts, resolve_conflict_item, ClientConflictDetail,
    ClientConflictSummary,
};
use crate::client::notes::{
    create_note, delete_note, get_note, list_notes, update_note, ClientNoteDetail,
    ClientNoteSummary,
};
use crate::client::sync::{get_initial_sync_status, SyncStatus};
use crate::client::vault::{
    get_active_vault_key, get_vault_status, is_session_expired, lock_vault, touch_session_activity,
    unlock_vault, VaultState,
};
use crate::error::CliError;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::fmt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroize;
use zk_crypto::keys::VaultKey;
use zk_sync::ConflictResolutionStrategy;

/// Minimum supported terminal dimensions (AC-02, AC-09).
pub const MIN_COLS: u16 = 80;
pub const MIN_ROWS: u16 = 24;

/// Active UI mode governing key handling and screen composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    Search,
    Create,
    InlineEdit,
    DeleteConfirm,
    Conflict,
    Account,
    Help,
    Locked,
    TerminalTooSmall,
}

/// Focused pane in Normal mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    NotesList,
    NotePreview,
}

/// Field being edited in Create or InlineEdit mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    Title,
    Tags,
    Body,
}

/// Field or interactive control in the Server Connection / Account modal (ZK-101 Addendum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountField {
    ServerUrl,
    Token,
    ConnectButton,
    SignOutButton,
}

/// Pending asynchronous authentication action dispatched to the TUI event loop.
#[derive(Clone, PartialEq, Eq)]
pub enum AccountPendingAction {
    Connect { server_url: String, token: String },
    SignOut,
    RefreshStatus,
    StartupVerify,
}

impl fmt::Debug for AccountPendingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountPendingAction::Connect { server_url, .. } => f
                .debug_struct("Connect")
                .field("server_url", server_url)
                .field("token", &"[REDACTED]")
                .finish(),
            AccountPendingAction::SignOut => write!(f, "AccountPendingAction::SignOut"),
            AccountPendingAction::RefreshStatus => write!(f, "AccountPendingAction::RefreshStatus"),
            AccountPendingAction::StartupVerify => write!(f, "AccountPendingAction::StartupVerify"),
        }
    }
}

/// Main application state for the interactive terminal UI.
///
/// Plaintext note data, passphrases, and search queries are redacted in `Debug` output (SEC-003, AC-10).
pub struct App {
    pub mode: AppMode,
    pub previous_mode: Option<AppMode>,
    pub focus: Focus,
    pub data_dir: Option<PathBuf>,
    pub vault_key: Option<VaultKey>,
    pub notes: Vec<ClientNoteSummary>,
    pub selected_index: Option<usize>,
    pub preview: Option<ClientNoteDetail>,
    pub preview_scroll: u16,

    // Search state (volatile, cleared on lock)
    pub search_query: String,
    pub search_results: Vec<ClientNoteSummary>,

    // Conflict state
    pub conflicts: Vec<ClientConflictSummary>,
    pub selected_conflict_index: Option<usize>,
    pub conflict_detail: Option<ClientConflictDetail>,

    // Note form state (create / inline edit)
    pub edit_title: String,
    pub edit_tags: String,
    pub edit_body: String,
    pub edit_field: EditField,

    // Locked prompt state (masked)
    pub passphrase_input: String,
    pub unlock_error: Option<String>,

    // Server & Account Authentication state (ZK-101 Addendum)
    pub account_state: ClientAuthState,
    pub auth_op_generation: u64,
    pub account_server_input: String,
    pub account_token_input: String,
    pub account_focus_field: AccountField,
    pub account_pending_action: Option<AccountPendingAction>,

    // Status & Feedback
    pub sync_status: SyncStatus,
    pub status_message: Option<String>,
    pub error_message: Option<String>,

    // Dimensions & Lifecycle
    pub terminal_width: u16,
    pub terminal_height: u16,
    pub should_quit: bool,
    pub request_external_editor: bool,
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("mode", &self.mode)
            .field("focus", &self.focus)
            .field("notes_count", &self.notes.len())
            .field("selected_index", &self.selected_index)
            .field("sync_status", &self.sync_status)
            .field("account_state", &self.account_state)
            .field("auth_op_generation", &self.auth_op_generation)
            .field("account_server_input", &self.account_server_input)
            .field("account_token_input", &"[REDACTED]")
            .field("account_focus_field", &self.account_focus_field)
            .field(
                "terminal_size",
                &(self.terminal_width, self.terminal_height),
            )
            .field("passphrase_input", &"[REDACTED]")
            .field("search_query", &"[REDACTED]")
            .field("edit_title", &"[REDACTED]")
            .field("edit_tags", &"[REDACTED]")
            .field("edit_body", &"[REDACTED]")
            .finish()
    }
}

impl App {
    /// Constructs and initializes a new [`App`] state machine.
    pub fn new(data_dir: Option<&Path>, width: u16, height: u16) -> Self {
        let initial_sync = get_initial_sync_status(data_dir);
        let initial_auth = get_local_auth_state(data_dir).unwrap_or(ClientAuthState::LocalOnly);
        let default_server = initial_auth
            .server_url()
            .unwrap_or("http://127.0.0.1:8080")
            .to_string();
        let vault_status = get_vault_status(data_dir).unwrap_or(VaultState::Locked);

        let (initial_mode, vault_key) = match vault_status {
            VaultState::Unlocked { .. } => {
                if let Ok(key) = get_active_vault_key(data_dir) {
                    (AppMode::Normal, Some(key))
                } else {
                    (AppMode::Locked, None)
                }
            }
            VaultState::Locked | VaultState::Uninitialized => (AppMode::Locked, None),
        };

        let mode = if width < MIN_COLS || height < MIN_ROWS {
            AppMode::TerminalTooSmall
        } else {
            initial_mode
        };

        let initial_pending_action = if initial_auth.is_unverified() {
            Some(AccountPendingAction::StartupVerify)
        } else {
            None
        };

        let mut app = Self {
            mode,
            previous_mode: if mode == AppMode::TerminalTooSmall {
                Some(initial_mode)
            } else {
                None
            },
            focus: Focus::NotesList,
            data_dir: data_dir.map(PathBuf::from),
            vault_key,
            notes: Vec::new(),
            selected_index: None,
            preview: None,
            preview_scroll: 0,
            search_query: String::new(),
            search_results: Vec::new(),
            conflicts: Vec::new(),
            selected_conflict_index: None,
            conflict_detail: None,
            edit_title: String::new(),
            edit_tags: String::new(),
            edit_body: String::new(),
            edit_field: EditField::Title,
            passphrase_input: String::new(),
            unlock_error: None,
            account_state: initial_auth,
            auth_op_generation: 1,
            account_server_input: default_server,
            account_token_input: String::new(),
            account_focus_field: AccountField::ServerUrl,
            account_pending_action: initial_pending_action,
            sync_status: initial_sync,
            status_message: None,
            error_message: None,
            terminal_width: width,
            terminal_height: height,
            should_quit: false,
            request_external_editor: false,
        };

        if app.vault_key.is_some() {
            app.reload_notes();
            app.reload_conflicts();
        }

        app
    }

    /// Reloads decrypted notes from the database while unlocked.
    pub fn reload_notes(&mut self) {
        if let Some(key) = &self.vault_key {
            match list_notes(self.data_dir.as_deref(), key, false, None) {
                Ok(notes) => {
                    self.notes = notes;
                    if self.notes.is_empty() {
                        self.selected_index = None;
                        self.preview = None;
                    } else {
                        let new_index = self
                            .selected_index
                            .unwrap_or(0)
                            .min(self.notes.len().saturating_sub(1));
                        self.selected_index = Some(new_index);
                        self.load_selected_preview();
                    }
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to load notes: {e}"));
                }
            }
        }
    }

    /// Loads the decrypted details of the currently selected note into preview.
    pub fn load_selected_preview(&mut self) {
        let current_notes = self.displayed_notes();
        if let Some(idx) = self.selected_index {
            if let Some(item) = current_notes.get(idx) {
                if let Some(key) = &self.vault_key {
                    if let Ok(detail) = get_note(self.data_dir.as_deref(), key, &item.id) {
                        self.preview = Some(detail);
                        self.preview_scroll = 0;
                        return;
                    }
                }
            }
        }
        self.preview = None;
        self.preview_scroll = 0;
    }

    /// Reloads conflict list while unlocked.
    pub fn reload_conflicts(&mut self) {
        match list_conflicts(self.data_dir.as_deref(), self.vault_key.as_ref(), false) {
            Ok(conflicts) => {
                let count = conflicts.len();
                self.conflicts = conflicts;
                if count > 0 {
                    let idx = self
                        .selected_conflict_index
                        .unwrap_or(0)
                        .min(self.conflicts.len().saturating_sub(1));
                    self.selected_conflict_index = Some(idx);
                    self.load_selected_conflict_detail();
                } else {
                    self.selected_conflict_index = None;
                    self.conflict_detail = None;
                }
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to load conflicts: {e}"));
            }
        }
    }

    /// Loads the decrypted detail of the currently selected conflict record.
    pub fn load_selected_conflict_detail(&mut self) {
        if let Some(idx) = self.selected_conflict_index {
            if let Some(item) = self.conflicts.get(idx) {
                if let Some(key) = &self.vault_key {
                    if let Ok(detail) =
                        get_conflict_detail(self.data_dir.as_deref(), key, &item.conflict_id)
                    {
                        self.conflict_detail = Some(detail);
                        return;
                    }
                }
            }
        }
        self.conflict_detail = None;
    }

    /// Returns the currently active notes slice (filtered if in Search mode, or all).
    pub fn displayed_notes(&self) -> &[ClientNoteSummary] {
        if self.mode == AppMode::Search || !self.search_query.is_empty() {
            &self.search_results
        } else {
            &self.notes
        }
    }

    /// Immediately zeroizes and clears all decrypted in-memory buffers and locks the vault.
    ///
    /// Persisted session cleanup is attempted. If persistent cleanup fails, returns the typed
    /// error and sets a truthful error message instead of displaying a false success message.
    /// In-memory buffers are fail-closed zeroized regardless of persistent cleanup outcome.
    pub fn lock_and_clear(&mut self) -> Result<(), CliError> {
        self.vault_key = None;
        self.passphrase_input.zeroize();
        self.passphrase_input.clear();
        self.unlock_error = None;

        self.notes.clear();
        self.selected_index = None;
        self.preview = None;
        self.preview_scroll = 0;

        self.search_query.zeroize();
        self.search_query.clear();
        self.search_results.clear();

        self.conflicts.clear();
        self.selected_conflict_index = None;
        self.conflict_detail = None;

        self.edit_title.zeroize();
        self.edit_title.clear();
        self.edit_tags.zeroize();
        self.edit_tags.clear();
        self.edit_body.zeroize();
        self.edit_body.clear();

        self.account_token_input.zeroize();
        self.account_token_input.clear();

        self.mode = AppMode::Locked;
        self.previous_mode = None;

        match lock_vault(self.data_dir.as_deref()) {
            Ok(()) => {
                self.status_message = Some("Vault locked.".to_string());
                self.error_message = None;
                Ok(())
            }
            Err(e) => {
                self.status_message = None;
                self.error_message = Some(format!("Failed to invalidate session: {e}"));
                Err(e)
            }
        }
    }

    /// Records genuine user activity, refreshing the idle session timer (ZK-076, AC-04).
    pub fn record_user_activity(&mut self) {
        if self.mode != AppMode::Locked && self.vault_key.is_some() {
            let _ = touch_session_activity(self.data_dir.as_deref());
        }
    }

    /// Periodic tick handler: verifies idle auto-lock policy without refreshing activity timer.
    pub fn tick(&mut self) {
        if self.mode != AppMode::Locked && self.vault_key.is_some() {
            match is_session_expired(self.data_dir.as_deref()) {
                Ok(true) => {
                    // Auto-lock idle timer expired!
                    let lock_res = self.lock_and_clear();
                    if lock_res.is_ok() {
                        self.status_message =
                            Some("Vault locked due to inactivity auto-lock policy.".to_string());
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    let _ = self.lock_and_clear();
                    self.error_message = Some(format!("Auto-lock session check failed: {e}"));
                }
            }
        }
    }

    /// Dispatches a semantic action through the UI state machine.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Quit => {
                self.should_quit = true;
            }
            Action::Resize(w, h) => {
                self.terminal_width = w;
                self.terminal_height = h;
                if w < MIN_COLS || h < MIN_ROWS {
                    if self.mode != AppMode::TerminalTooSmall {
                        self.previous_mode = Some(self.mode);
                        self.mode = AppMode::TerminalTooSmall;
                    }
                } else if self.mode == AppMode::TerminalTooSmall {
                    self.mode = self.previous_mode.take().unwrap_or(AppMode::Normal);
                }
            }
            Action::Tick => {
                self.tick();
            }
            Action::ToggleHelp => {
                if self.mode == AppMode::Help {
                    self.mode = self.previous_mode.take().unwrap_or(AppMode::Normal);
                } else if self.mode != AppMode::TerminalTooSmall && self.mode != AppMode::Locked {
                    self.previous_mode = Some(self.mode);
                    self.mode = AppMode::Help;
                }
            }
            Action::CloseOverlay => {
                if self.mode == AppMode::Help || self.mode == AppMode::Conflict {
                    self.mode = self.previous_mode.take().unwrap_or(AppMode::Normal);
                } else if self.mode == AppMode::Account {
                    self.account_token_input.zeroize();
                    self.account_token_input.clear();
                    self.mode = self.previous_mode.take().unwrap_or(AppMode::Normal);
                } else if self.mode == AppMode::DeleteConfirm {
                    self.mode = AppMode::Normal;
                }
            }

            Action::LockVault => {
                let _ = self.lock_and_clear();
            }
            Action::UnlockChar(c) => {
                if self.mode == AppMode::Locked {
                    self.passphrase_input.push(c);
                    self.unlock_error = None;
                }
            }
            Action::UnlockBackspace => {
                if self.mode == AppMode::Locked {
                    self.passphrase_input.pop();
                    self.unlock_error = None;
                }
            }
            Action::SubmitUnlock => {
                if self.mode == AppMode::Locked {
                    match unlock_vault(self.data_dir.as_deref(), &self.passphrase_input, None) {
                        Ok(key) => {
                            self.vault_key = Some(key);
                            self.passphrase_input.zeroize();
                            self.passphrase_input.clear();
                            self.unlock_error = None;
                            self.mode = AppMode::Normal;
                            self.reload_notes();
                            self.reload_conflicts();
                            self.status_message = Some("Vault unlocked.".to_string());
                        }
                        Err(_e) => {
                            self.passphrase_input.zeroize();
                            self.passphrase_input.clear();
                            self.unlock_error = Some(
                                "Unlock failed: incorrect passphrase or corrupted vault."
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            Action::MoveUp => match self.mode {
                AppMode::Normal | AppMode::Search => {
                    let total = self.displayed_notes().len();
                    if total > 0 {
                        let curr = self.selected_index.unwrap_or(0);
                        let next = if curr == 0 { 0 } else { curr - 1 };
                        self.selected_index = Some(next);
                        self.load_selected_preview();
                    }
                }
                AppMode::Conflict => {
                    let total = self.conflicts.len();
                    if total > 0 {
                        let curr = self.selected_conflict_index.unwrap_or(0);
                        let next = if curr == 0 { 0 } else { curr - 1 };
                        self.selected_conflict_index = Some(next);
                        self.load_selected_conflict_detail();
                    }
                }
                _ => {}
            },
            Action::MoveDown => match self.mode {
                AppMode::Normal | AppMode::Search => {
                    let total = self.displayed_notes().len();
                    if total > 0 {
                        let curr = self.selected_index.unwrap_or(0);
                        let next = (curr + 1).min(total.saturating_sub(1));
                        self.selected_index = Some(next);
                        self.load_selected_preview();
                    }
                }
                AppMode::Conflict => {
                    let total = self.conflicts.len();
                    if total > 0 {
                        let curr = self.selected_conflict_index.unwrap_or(0);
                        let next = (curr + 1).min(total.saturating_sub(1));
                        self.selected_conflict_index = Some(next);
                        self.load_selected_conflict_detail();
                    }
                }
                _ => {}
            },
            Action::JumpTop => {
                if self.mode == AppMode::Normal || self.mode == AppMode::Search {
                    if !self.displayed_notes().is_empty() {
                        self.selected_index = Some(0);
                        self.load_selected_preview();
                    }
                } else if self.mode == AppMode::Conflict && !self.conflicts.is_empty() {
                    self.selected_conflict_index = Some(0);
                    self.load_selected_conflict_detail();
                }
            }
            Action::JumpBottom => {
                if self.mode == AppMode::Normal || self.mode == AppMode::Search {
                    let total = self.displayed_notes().len();
                    if total > 0 {
                        self.selected_index = Some(total - 1);
                        self.load_selected_preview();
                    }
                } else if self.mode == AppMode::Conflict && !self.conflicts.is_empty() {
                    self.selected_conflict_index = Some(self.conflicts.len() - 1);
                    self.load_selected_conflict_detail();
                }
            }
            Action::NextPane => {
                if self.mode == AppMode::Normal {
                    self.focus = match self.focus {
                        Focus::NotesList => Focus::NotePreview,
                        Focus::NotePreview => Focus::NotesList,
                    };
                }
            }
            Action::PrevPane => {
                if self.mode == AppMode::Normal {
                    self.focus = match self.focus {
                        Focus::NotesList => Focus::NotePreview,
                        Focus::NotePreview => Focus::NotesList,
                    };
                }
            }
            Action::ScrollPreviewUp => {
                self.preview_scroll = self.preview_scroll.saturating_sub(2);
            }
            Action::ScrollPreviewDown => {
                self.preview_scroll = self.preview_scroll.saturating_add(2);
            }
            Action::Select => {
                if self.mode == AppMode::Normal {
                    self.focus = Focus::NotePreview;
                }
            }
            Action::EnterSearch => {
                if self.mode == AppMode::Normal {
                    self.mode = AppMode::Search;
                    self.search_query.clear();
                    self.search_results = self.notes.clone();
                }
            }
            Action::SearchChar(c) => {
                if self.mode == AppMode::Search {
                    self.search_query.push(c);
                    self.perform_incremental_search();
                }
            }
            Action::SearchBackspace => {
                if self.mode == AppMode::Search {
                    self.search_query.pop();
                    self.perform_incremental_search();
                }
            }
            Action::ExitSearch => {
                if self.mode == AppMode::Search {
                    self.search_query.clear();
                    self.search_results.clear();
                    self.mode = AppMode::Normal;
                    self.selected_index = if self.notes.is_empty() { None } else { Some(0) };
                    self.load_selected_preview();
                }
            }
            Action::EnterCreate => {
                if self.mode == AppMode::Normal {
                    self.mode = AppMode::Create;
                    self.edit_title.clear();
                    self.edit_tags.clear();
                    self.edit_body.clear();
                    self.edit_field = EditField::Title;
                }
            }
            Action::EnterInlineEdit => {
                if self.mode == AppMode::Normal {
                    if let Some(detail) = &self.preview {
                        self.mode = AppMode::InlineEdit;
                        self.edit_title = detail.title.clone();
                        self.edit_tags = detail.tags.join(", ");
                        self.edit_body = detail.body.clone();
                        self.edit_field = EditField::Title;
                    }
                }
            }
            Action::CancelEdit => {
                if self.mode == AppMode::Create || self.mode == AppMode::InlineEdit {
                    self.edit_title.zeroize();
                    self.edit_title.clear();
                    self.edit_tags.zeroize();
                    self.edit_tags.clear();
                    self.edit_body.zeroize();
                    self.edit_body.clear();
                    self.mode = AppMode::Normal;
                }
            }
            Action::SaveEdit => {
                self.save_edit_form();
            }
            Action::EditChar(c) => match self.edit_field {
                EditField::Title => self.edit_title.push(c),
                EditField::Tags => self.edit_tags.push(c),
                EditField::Body => self.edit_body.push(c),
            },
            Action::EditBackspace => match self.edit_field {
                EditField::Title => {
                    self.edit_title.pop();
                }
                EditField::Tags => {
                    self.edit_tags.pop();
                }
                EditField::Body => {
                    self.edit_body.pop();
                }
            },
            Action::EditNewline => {
                if self.edit_field == EditField::Body {
                    self.edit_body.push('\n');
                } else {
                    self.edit_field = match self.edit_field {
                        EditField::Title => EditField::Tags,
                        EditField::Tags => EditField::Body,
                        EditField::Body => EditField::Body,
                    };
                }
            }
            Action::EditNextField => {
                self.edit_field = match self.edit_field {
                    EditField::Title => EditField::Tags,
                    EditField::Tags => EditField::Body,
                    EditField::Body => EditField::Title,
                };
            }
            Action::EditPrevField => {
                self.edit_field = match self.edit_field {
                    EditField::Title => EditField::Body,
                    EditField::Tags => EditField::Title,
                    EditField::Body => EditField::Tags,
                };
            }
            Action::OpenExternalEditor => {
                if self.mode == AppMode::Normal && self.preview.is_some() {
                    self.request_external_editor = true;
                }
            }
            Action::AskDelete => {
                if self.mode == AppMode::Normal && self.preview.is_some() {
                    self.mode = AppMode::DeleteConfirm;
                }
            }
            Action::ConfirmDelete => {
                if self.mode == AppMode::DeleteConfirm {
                    if let Some(detail) = &self.preview {
                        let id = detail.id.clone();
                        match delete_note(self.data_dir.as_deref(), &id, false) {
                            Ok(_) => {
                                self.status_message =
                                    Some("Note deleted (tombstone created).".to_string());
                                self.mode = AppMode::Normal;
                                self.reload_notes();
                            }
                            Err(e) => {
                                self.error_message = Some(format!("Delete failed: {e}"));
                                self.mode = AppMode::Normal;
                            }
                        }
                    }
                }
            }
            Action::CancelDelete => {
                if self.mode == AppMode::DeleteConfirm {
                    self.mode = AppMode::Normal;
                }
            }
            Action::OpenConflicts => {
                if self.mode == AppMode::Normal {
                    self.reload_conflicts();
                    self.previous_mode = Some(AppMode::Normal);
                    self.mode = AppMode::Conflict;
                }
            }
            Action::CloseConflicts => {
                if self.mode == AppMode::Conflict {
                    self.mode = AppMode::Normal;
                }
            }
            Action::ConflictKeepLocal => {
                self.resolve_current_conflict(ConflictResolutionStrategy::KeepLocal);
            }
            Action::ConflictAcceptRemote => {
                self.resolve_current_conflict(ConflictResolutionStrategy::KeepRemote);
            }
            Action::ConflictMerge => {
                if let Some(detail) = &self.conflict_detail {
                    if let Some(cand) = &detail.candidate_note {
                        self.resolve_current_conflict(ConflictResolutionStrategy::Merge(
                            cand.clone(),
                        ));
                    } else {
                        self.error_message =
                            Some("No merge candidate available for this conflict.".to_string());
                    }
                }
            }
            Action::ConflictDuplicate => {
                let new_id = uuid::Uuid::new_v4().to_string();
                self.resolve_current_conflict(ConflictResolutionStrategy::DuplicateAsSeparate {
                    new_object_id: new_id,
                    new_title: None,
                });
            }
            Action::ConflictRestore => {
                self.resolve_current_conflict(ConflictResolutionStrategy::RestoreResurrect);
            }
            Action::TriggerSync => {
                self.status_message = Some("Sync triggered...".to_string());
                self.sync_status = SyncStatus::Syncing;
            }
            Action::OpenAccount => {
                if self.mode != AppMode::TerminalTooSmall {
                    self.previous_mode = Some(self.mode);
                    self.mode = AppMode::Account;
                    self.account_focus_field = if self.account_server_input.is_empty() {
                        AccountField::ServerUrl
                    } else {
                        AccountField::Token
                    };
                }
            }
            Action::CloseAccount => {
                if self.mode == AppMode::Account {
                    self.account_token_input.zeroize();
                    self.account_token_input.clear();
                    self.mode = self.previous_mode.take().unwrap_or(AppMode::Normal);
                }
            }
            Action::AccountServerChar(c) => {
                if self.mode == AppMode::Account {
                    self.account_server_input.push(c);
                }
            }
            Action::AccountServerBackspace => {
                if self.mode == AppMode::Account {
                    self.account_server_input.pop();
                }
            }
            Action::AccountTokenChar(c) => {
                if self.mode == AppMode::Account {
                    self.account_token_input.push(c);
                }
            }
            Action::AccountTokenBackspace => {
                if self.mode == AppMode::Account {
                    self.account_token_input.pop();
                }
            }
            Action::AccountNextField => {
                if self.mode == AppMode::Account {
                    self.account_focus_field = match self.account_focus_field {
                        AccountField::ServerUrl => AccountField::Token,
                        AccountField::Token => AccountField::ConnectButton,
                        AccountField::ConnectButton => AccountField::SignOutButton,
                        AccountField::SignOutButton => AccountField::ServerUrl,
                    };
                }
            }
            Action::AccountPrevField => {
                if self.mode == AppMode::Account {
                    self.account_focus_field = match self.account_focus_field {
                        AccountField::ServerUrl => AccountField::SignOutButton,
                        AccountField::Token => AccountField::ServerUrl,
                        AccountField::ConnectButton => AccountField::Token,
                        AccountField::SignOutButton => AccountField::ConnectButton,
                    };
                }
            }
            Action::AccountSubmit => {
                if self.mode == AppMode::Account {
                    let url = self.account_server_input.trim().to_string();
                    let tok = self.account_token_input.trim().to_string();
                    if tok.is_empty() {
                        self.error_message = Some("Session token cannot be empty.".to_string());
                    } else {
                        self.invalidate_auth_ops();
                        self.account_pending_action = Some(AccountPendingAction::Connect {
                            server_url: url,
                            token: tok,
                        });
                        self.account_token_input.zeroize();
                        self.account_token_input.clear();
                        self.status_message = Some("Authorizing device with server...".to_string());
                        self.error_message = None;
                    }
                }
            }
            Action::AccountSignOut => {
                if self.mode == AppMode::Account {
                    self.invalidate_auth_ops();
                    self.account_pending_action = Some(AccountPendingAction::SignOut);
                    self.status_message = Some("Revoking session with server...".to_string());
                    self.error_message = None;
                }
            }
            Action::AccountRefresh => {
                if self.mode == AppMode::Account {
                    self.invalidate_auth_ops();
                    self.account_pending_action = Some(AccountPendingAction::RefreshStatus);
                    self.status_message = Some("Checking server status...".to_string());
                    self.error_message = None;
                }
            }
        }
    }

    /// Performs incremental search over local in-memory notes (AC-05).
    fn perform_incremental_search(&mut self) {
        if self.search_query.trim().is_empty() {
            self.search_results = self.notes.clone();
        } else if let Some(key) = &self.vault_key {
            match crate::client::notes::search_notes(
                self.data_dir.as_deref(),
                key,
                &self.search_query,
            ) {
                Ok(results) => {
                    let mut matched = Vec::new();
                    for r in results {
                        if let Some(note) = self.notes.iter().find(|n| n.id == r.id) {
                            matched.push(note.clone());
                        }
                    }
                    self.search_results = matched;
                }
                Err(e) => {
                    self.error_message = Some(format!("Search failed: {e}"));
                    self.search_results.clear();
                }
            }
        } else {
            self.search_results.clear();
        }
        self.selected_index = if self.search_results.is_empty() {
            None
        } else {
            Some(0)
        };
        self.load_selected_preview();
    }

    /// Saves the note from Create or InlineEdit form.
    fn save_edit_form(&mut self) {
        if let Some(key) = &self.vault_key {
            let tags: Vec<String> = self
                .edit_tags
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();

            let title = if self.edit_title.trim().is_empty() {
                "Untitled Note".to_string()
            } else {
                self.edit_title.trim().to_string()
            };

            let res = match self.mode {
                AppMode::Create => {
                    create_note(self.data_dir.as_deref(), key, &title, &self.edit_body, tags)
                }
                AppMode::InlineEdit => {
                    if let Some(detail) = &self.preview {
                        update_note(
                            self.data_dir.as_deref(),
                            key,
                            &detail.id,
                            &title,
                            &self.edit_body,
                            tags,
                        )
                        .map(|_| detail.id.clone())
                    } else {
                        Err(crate::error::CliError::Io("no note selected".to_string()))
                    }
                }
                _ => return,
            };

            match res {
                Ok(id) => {
                    self.status_message = Some("Note saved successfully.".to_string());
                    self.mode = AppMode::Normal;
                    self.reload_notes();
                    // Select the saved note
                    if let Some(pos) = self.notes.iter().position(|n| n.id == id) {
                        self.selected_index = Some(pos);
                        self.load_selected_preview();
                    }
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to save note: {e}"));
                }
            }
        }
    }

    /// Resolves the currently selected conflict using the given strategy.
    fn resolve_current_conflict(&mut self, strategy: ConflictResolutionStrategy) {
        if let Some(idx) = self.selected_conflict_index {
            if let Some(conflict) = self.conflicts.get(idx) {
                if let Some(key) = &self.vault_key {
                    match resolve_conflict_item(
                        self.data_dir.as_deref(),
                        key,
                        &conflict.conflict_id,
                        strategy,
                    ) {
                        Ok(res) => {
                            self.status_message =
                                Some(format!("Conflict resolved for note {}.", res.object_id));
                            self.reload_conflicts();
                            self.reload_notes();
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Conflict resolution failed: {e}"));
                        }
                    }
                }
            }
        }
    }

    /// Increments the background authentication operation generation counter,
    /// invalidating any in-flight background operations.
    pub fn invalidate_auth_ops(&mut self) -> u64 {
        self.auth_op_generation = self.auth_op_generation.wrapping_add(1);
        self.auth_op_generation
    }

    /// Returns the current authentication operation generation.
    #[must_use]
    pub fn current_auth_generation(&self) -> u64 {
        self.auth_op_generation
    }

    /// Applies the result of an asynchronous authentication background worker operation.
    ///
    /// Verifies generation and session identity guards:
    /// - Rejects completions whose generation does not match the active generation.
    /// - Rejects completions if the client is currently in LocalOnly mode.
    /// - Rejects completions if the expected account ID does not match current state.
    /// - Rejects completions if the expected server URL does not match current state.
    /// - Rejects completions if the new state account ID conflicts with current state.
    /// - Rejects completions if the new state server URL conflicts with current state.
    ///
    /// Returns `true` if the result was accepted and applied, or `false` if rejected as stale.
    pub fn apply_auth_worker_result(
        &mut self,
        generation: u64,
        expected_account_id: Option<Uuid>,
        expected_server_url: Option<&str>,
        result: Result<ClientAuthState, CliError>,
        is_refresh: bool,
    ) -> bool {
        // 1. Generation guard: must match the active auth operation generation
        if generation != self.auth_op_generation {
            return false;
        }

        // 2. Local-only guard: if the client is currently local-only (e.g. signed out),
        // any background server auth results must be rejected.
        if self.account_state.is_local_only() {
            return false;
        }

        // 3. Account identity guard: if an account ID was expected, current state must match
        if let Some(expected_id) = expected_account_id {
            if self.account_state.account_id() != Some(expected_id) {
                return false;
            }
        }

        // 4. Server URL guard: if a server URL was expected, current state must match
        if let Some(expected_url) = expected_server_url {
            if self.account_state.server_url() != Some(expected_url) {
                return false;
            }
        }

        // 5. Result payload identity guard: if incoming state is Ok(st), ensure it matches current identity
        if let Ok(st) = &result {
            // If incoming state is for a specific account, ensure it does not conflict with current account
            if let (Some(curr_id), Some(new_id)) =
                (self.account_state.account_id(), st.account_id())
            {
                if curr_id != new_id {
                    return false;
                }
            }
            // If incoming state is for a specific server, ensure it does not conflict with current server
            if let (Some(curr_url), Some(new_url)) =
                (self.account_state.server_url(), st.server_url())
            {
                if curr_url != new_url {
                    return false;
                }
            }
        }

        // All guards passed. Apply result to state machine.
        match result {
            Ok(st) => {
                self.account_state = st;
                if is_refresh {
                    self.status_message = Some("Server status updated.".to_string());
                    self.error_message = None;
                }
            }
            Err(e) => {
                if is_refresh {
                    self.error_message = Some(format!("Failed to refresh status: {e}"));
                    self.status_message = None;
                } else {
                    self.account_state = ClientAuthState::Error {
                        server_url: self.account_state.server_url().unwrap_or("").to_string(),
                        error: e.to_string(),
                    };
                }
            }
        }

        true
    }

    /// Translates a Crossterm [`KeyEvent`] to an [`Action`] according to active mode.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Clear transient error messages on any keypress
        self.error_message = None;

        if self.mode != AppMode::Locked && self.mode != AppMode::TerminalTooSmall {
            self.record_user_activity();
        }

        match self.mode {
            AppMode::TerminalTooSmall => {
                if key.code == KeyCode::Char('q') {
                    self.update(Action::Quit);
                }
            }
            AppMode::Locked => match key.code {
                KeyCode::Char('q') | KeyCode::Esc if self.passphrase_input.is_empty() => {
                    self.update(Action::Quit);
                }
                KeyCode::Char(c) => {
                    self.update(Action::UnlockChar(c));
                }
                KeyCode::Backspace => {
                    self.update(Action::UnlockBackspace);
                }
                KeyCode::Enter => {
                    self.update(Action::SubmitUnlock);
                }
                _ => {}
            },
            AppMode::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter => {
                    self.update(Action::CloseOverlay);
                }
                _ => {}
            },
            AppMode::DeleteConfirm => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.update(Action::ConfirmDelete);
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.update(Action::CancelDelete);
                }
                _ => {}
            },
            AppMode::Conflict => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.update(Action::CloseConflicts);
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    self.update(Action::MoveDown);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.update(Action::MoveUp);
                }
                KeyCode::Char('1') | KeyCode::Char('l') => {
                    self.update(Action::ConflictKeepLocal);
                }
                KeyCode::Char('2') | KeyCode::Char('r') => {
                    self.update(Action::ConflictAcceptRemote);
                }
                KeyCode::Char('3') | KeyCode::Char('m') => {
                    self.update(Action::ConflictMerge);
                }
                KeyCode::Char('4') | KeyCode::Char('d') => {
                    self.update(Action::ConflictDuplicate);
                }
                KeyCode::Char('R') => {
                    self.update(Action::ConflictRestore);
                }
                _ => {}
            },
            AppMode::Account => match key.code {
                KeyCode::Esc => {
                    self.update(Action::CloseAccount);
                }
                KeyCode::Tab | KeyCode::Down => {
                    self.update(Action::AccountNextField);
                }
                KeyCode::BackTab | KeyCode::Up => {
                    self.update(Action::AccountPrevField);
                }
                KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.update(Action::AccountSignOut);
                }
                KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.update(Action::AccountRefresh);
                }
                KeyCode::Enter => match self.account_focus_field {
                    AccountField::ServerUrl => self.update(Action::AccountNextField),
                    AccountField::Token | AccountField::ConnectButton => {
                        self.update(Action::AccountSubmit)
                    }
                    AccountField::SignOutButton => self.update(Action::AccountSignOut),
                },
                KeyCode::Backspace => match self.account_focus_field {
                    AccountField::ServerUrl => self.update(Action::AccountServerBackspace),
                    AccountField::Token => self.update(Action::AccountTokenBackspace),
                    _ => {}
                },
                KeyCode::Char(c) => match self.account_focus_field {
                    AccountField::ServerUrl => self.update(Action::AccountServerChar(c)),
                    AccountField::Token => self.update(Action::AccountTokenChar(c)),
                    AccountField::ConnectButton if c == 'c' || c == ' ' => {
                        self.update(Action::AccountSubmit)
                    }
                    AccountField::SignOutButton if c == 'x' || c == ' ' => {
                        self.update(Action::AccountSignOut)
                    }
                    _ => {}
                },
                _ => {}
            },
            AppMode::Search => match key.code {
                KeyCode::Esc => {
                    self.update(Action::ExitSearch);
                }
                KeyCode::Enter => {
                    self.mode = AppMode::Normal;
                }
                KeyCode::Backspace => {
                    self.update(Action::SearchBackspace);
                }
                KeyCode::Char(c) => {
                    self.update(Action::SearchChar(c));
                }
                KeyCode::Down => {
                    self.update(Action::MoveDown);
                }
                KeyCode::Up => {
                    self.update(Action::MoveUp);
                }
                _ => {}
            },
            AppMode::Create | AppMode::InlineEdit => match key.code {
                KeyCode::Esc => {
                    self.update(Action::CancelEdit);
                }
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.update(Action::SaveEdit);
                }
                KeyCode::Tab => {
                    self.update(Action::EditNextField);
                }
                KeyCode::BackTab => {
                    self.update(Action::EditPrevField);
                }
                KeyCode::Enter => {
                    if self.edit_field == EditField::Body {
                        self.update(Action::EditNewline);
                    } else {
                        self.update(Action::EditNextField);
                    }
                }
                KeyCode::Backspace => {
                    self.update(Action::EditBackspace);
                }
                KeyCode::Char(c) => {
                    self.update(Action::EditChar(c));
                }
                _ => {}
            },
            AppMode::Normal => match key.code {
                KeyCode::Char('q') => {
                    self.update(Action::Quit);
                }
                KeyCode::Char('?') => {
                    self.update(Action::ToggleHelp);
                }
                KeyCode::Char('l') => {
                    self.update(Action::LockVault);
                }
                KeyCode::Char('a') => {
                    self.update(Action::OpenAccount);
                }
                KeyCode::Char('/') => {
                    self.update(Action::EnterSearch);
                }
                KeyCode::Char('n') => {
                    self.update(Action::EnterCreate);
                }
                KeyCode::Char('e') => {
                    self.update(Action::EnterInlineEdit);
                }
                KeyCode::Char('E') => {
                    self.update(Action::OpenExternalEditor);
                }
                KeyCode::Char('d') => {
                    self.update(Action::AskDelete);
                }
                KeyCode::Char('c') => {
                    self.update(Action::OpenConflicts);
                }
                KeyCode::Char('s') => {
                    self.update(Action::TriggerSync);
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if self.focus == Focus::NotesList {
                        self.update(Action::MoveDown);
                    } else {
                        self.update(Action::ScrollPreviewDown);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if self.focus == Focus::NotesList {
                        self.update(Action::MoveUp);
                    } else {
                        self.update(Action::ScrollPreviewUp);
                    }
                }
                KeyCode::Char('g') => {
                    self.update(Action::JumpTop);
                }
                KeyCode::Char('G') => {
                    self.update(Action::JumpBottom);
                }
                KeyCode::Tab => {
                    self.update(Action::NextPane);
                }
                KeyCode::BackTab => {
                    self.update(Action::PrevPane);
                }
                KeyCode::Enter => {
                    self.update(Action::Select);
                }
                KeyCode::Esc => {
                    self.status_message = None;
                    self.error_message = None;
                }
                _ => {}
            },
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.passphrase_input.zeroize();
        self.account_token_input.zeroize();
        self.edit_title.zeroize();
        self.edit_tags.zeroize();
        self.edit_body.zeroize();
        self.search_query.zeroize();
    }
}
