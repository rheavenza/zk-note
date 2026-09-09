//! Plaintext note model serialization specification.

use serde::{Deserialize, Serialize};

/// Plaintext note model as serialized before client-side encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextNote {
    /// Note schema version (v1 = 1).
    pub schema_version: u32,
    /// Note title.
    pub title: String,
    /// Note body (Markdown format).
    pub body: String,
    /// Note tags (canonicalized: trimmed, lowercase, sorted, deduplicated).
    pub tags: Vec<String>,
    /// Creation timestamp in RFC 3339 UTC format.
    pub created_at: String,
    /// Last update timestamp in RFC 3339 UTC format.
    pub updated_at: String,
    /// List of attachment identifiers.
    #[serde(default)]
    pub attachments: Vec<String>,
}
