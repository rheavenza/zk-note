pub mod error;
pub mod note;
pub mod search;
pub mod time;
pub mod vault;

pub use error::{CoreError, NoteValidationError};
pub use note::{
    Note, NoteBuilder, NoteHistoryItem, PlaintextNote, MAX_ATTACHMENTS_COUNT,
    MAX_ATTACHMENT_ID_LEN, MAX_BODY_LEN, MAX_TAGS_COUNT, MAX_TAG_LEN, MAX_TITLE_LEN,
    NOTE_SCHEMA_VERSION_V1,
};
pub use search::{InMemorySearchIndex, IndexedNote, SearchResult};
pub use time::{now_utc_rfc3339, validate_rfc3339};
pub use vault::{VaultManager, VaultSession};

pub use zk_crypto as crypto;
pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_init() {
        assert_eq!(crate_name(), "zk-core");
        assert_eq!(crypto::crate_name(), "zk-crypto");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }
}
