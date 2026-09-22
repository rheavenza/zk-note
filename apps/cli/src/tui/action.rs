//! Semantic actions for the interactive terminal UI (ZK-101).

use std::fmt;

/// Semantic actions dispatched by event handlers and UI interactions.
#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    // Navigation
    MoveUp,
    MoveDown,
    JumpTop,
    JumpBottom,
    NextPane,
    PrevPane,
    ScrollPreviewUp,
    ScrollPreviewDown,
    Select,

    // Search
    EnterSearch,
    SearchChar(char),
    SearchBackspace,
    ExitSearch,

    // Notes
    EnterCreate,
    EnterInlineEdit,
    CancelEdit,
    SaveEdit,
    EditChar(char),
    EditBackspace,
    EditNewline,
    EditNextField,
    EditPrevField,
    OpenExternalEditor,

    // Deletion
    AskDelete,
    ConfirmDelete,
    CancelDelete,

    // Conflicts
    OpenConflicts,
    CloseConflicts,
    ConflictKeepLocal,
    ConflictAcceptRemote,
    ConflictMerge,
    ConflictDuplicate,
    ConflictRestore,

    // Vault & Session
    LockVault,
    UnlockChar(char),
    UnlockBackspace,
    SubmitUnlock,

    // Sync
    TriggerSync,

    // Overlays & Lifecycle
    ToggleHelp,
    CloseOverlay,
    Tick,
    Resize(u16, u16),
    Quit,
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ensure character inputs for unlock or search are not printed directly
        match self {
            Action::UnlockChar(_) => write!(f, "Action::UnlockChar([REDACTED])"),
            Action::UnlockBackspace => write!(f, "Action::UnlockBackspace"),
            Action::SubmitUnlock => write!(f, "Action::SubmitUnlock"),
            Action::SearchChar(_) => write!(f, "Action::SearchChar([REDACTED])"),
            Action::EditChar(_) => write!(f, "Action::EditChar([REDACTED])"),
            other => write!(f, "Action::{other:?}"),
        }
    }
}
