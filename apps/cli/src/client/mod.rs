//! Reusable, non-printing native client services (ZK-101).
//!
//! Separates business and domain logic from Clap CLI printing and TUI rendering.

pub mod conflicts;
pub mod editor;
pub mod notes;
pub mod sync;
pub mod vault;

pub use conflicts::{
    find_conflict_record, get_conflict_detail, list_conflicts, resolve_conflict_item,
    ClientConflictDetail, ClientConflictSummary,
};
pub use editor::edit_note_external;
pub use notes::{
    create_note, delete_note, find_note_object, get_note, list_notes, search_notes, update_note,
    ClientNoteDetail, ClientNoteSummary,
};
pub use sync::{get_initial_sync_status, perform_sync, SyncStatus};
pub use vault::{
    check_and_touch_session, get_active_vault_key, get_vault_status, lock_vault, unlock_vault,
    unlock_with_recovery_key, VaultState,
};
