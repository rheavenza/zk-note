//! Reusable, non-printing native client services (ZK-101).
//!
//! Separates business and domain logic from Clap CLI printing and TUI rendering.

pub mod auth;
pub mod conflicts;
pub mod editor;
pub mod notes;
pub mod sync;
pub mod vault;
pub mod vault_files;
pub mod vault_link;

pub use auth::{
    authorize_terminal_device, check_auth_state_online, force_clear_session, get_local_auth_state,
    sign_out, validate_and_normalize_server_url, ClientAuthState,
};
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
    get_active_vault_key, get_vault_status, is_session_expired, lock_vault, touch_session_activity,
    unlock_vault, unlock_with_recovery_key, VaultState,
};
