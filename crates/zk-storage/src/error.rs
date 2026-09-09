//! Typed error definitions for local storage operations.

use std::fmt;

/// Storage errors that can occur across storage backends and test doubles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Record with the given identifier was not found.
    NotFound {
        /// Type or table of the missing entity.
        entity: &'static str,
        /// Identifier that was queried.
        id: String,
    },
    /// A record with the given identifier already exists.
    AlreadyExists {
        /// Type or table of the entity.
        entity: &'static str,
        /// Identifier that collided.
        id: String,
    },
    /// Compare-and-swap revision conflict during a local update.
    RevisionConflict {
        /// Target object identifier.
        object_id: String,
        /// Expected revision that was rejected.
        expected: u64,
        /// Current revision stored locally.
        actual: u64,
    },
    /// Backend storage failure (I/O, database lock, corruption).
    Backend(String),
    /// Serialization or deserialization failure during record persistence.
    Serialization(String),
    /// Invalid input or argument provided to a storage operation.
    InvalidInput(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { entity, id } => {
                write!(f, "{entity} not found: {id}")
            }
            Self::AlreadyExists { entity, id } => {
                write!(f, "{entity} already exists with id: {id}")
            }
            Self::RevisionConflict {
                object_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "revision conflict on object {object_id}: expected revision {expected}, current is {actual}"
                )
            }
            Self::Backend(msg) => write!(f, "storage backend error: {msg}"),
            Self::Serialization(msg) => write!(f, "storage serialization error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid storage input: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}
