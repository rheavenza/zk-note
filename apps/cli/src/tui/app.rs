//! State machine and core state for the interactive terminal UI (ZK-101).

use super::action::Action;
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
    check_and_touch_session, get_active_vault_key, get_vault_status, lock_vault, unlock_vault,
    VaultState,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::fmt;
use std::path::{Path, PathBuf};
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
    pub fn lock_and_clear(&mut self) {
        let _ = lock_vault(self.data_dir.as_deref());

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

        self.mode = AppMode::Locked;
        self.previous_mode = None;
        self.status_message = Some("Vault locked.".to_string());
    }

    /// Periodic tick handler: verifies idle auto-lock policy and refreshes state.
    pub fn tick(&mut self) {
        if self.mode != AppMode::Locked && self.vault_key.is_some() {
            match check_and_touch_session(self.data_dir.as_deref()) {
                Ok(_) => {}
                Err(_) => {
                    // Auto-lock idle timer expired!
                    self.lock_and_clear();
                    self.status_message =
                        Some("Vault locked due to inactivity auto-lock policy.".to_string());
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
                } else if self.mode == AppMode::DeleteConfirm {
                    self.mode = AppMode::Normal;
                }
            }
            Action::LockVault => {
                self.lock_and_clear();
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
        }
    }

    /// Performs incremental search over local in-memory notes (AC-05).
    fn perform_incremental_search(&mut self) {
        if self.search_query.trim().is_empty() {
            self.search_results = self.notes.clone();
        } else {
            let query = self.search_query.to_lowercase();
            self.search_results = self
                .notes
                .iter()
                .filter(|n| {
                    n.title.to_lowercase().contains(&query)
                        || n.tags.iter().any(|t| t.to_lowercase().contains(&query))
                })
                .cloned()
                .collect();
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

    /// Translates a Crossterm [`KeyEvent`] to an [`Action`] according to active mode.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Clear transient error messages on any keypress
        self.error_message = None;

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
