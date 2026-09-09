//! Strongly typed representation of durable encrypted object kinds.

use crate::constants::{
    OBJECT_KIND_ATTACHMENT_MANIFEST, OBJECT_KIND_NOTE, OBJECT_KIND_NOTEBOOK, OBJECT_KIND_RESERVED,
    OBJECT_KIND_USER_SETTINGS,
};
use core::fmt;

/// Error returned when converting an unrecognized integer discriminant to [`ObjectKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownObjectKind(pub u16);

impl fmt::Display for UnknownObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown object kind discriminant: {}", self.0)
    }
}

impl std::error::Error for UnknownObjectKind {}

/// The durable kind of an encrypted object stored on the server.
///
/// Object kinds are protocol-level discriminants and must not be repurposed
/// across protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ObjectKind {
    /// Note object containing encrypted note body, title, and tags.
    Note = OBJECT_KIND_NOTE,
    /// Notebook grouping object.
    Notebook = OBJECT_KIND_NOTEBOOK,
    /// User settings object.
    UserSettings = OBJECT_KIND_USER_SETTINGS,
    /// Attachment manifest object.
    AttachmentManifest = OBJECT_KIND_ATTACHMENT_MANIFEST,
    /// Reserved kind for future protocol expansion.
    Reserved = OBJECT_KIND_RESERVED,
}

impl ObjectKind {
    /// Returns the raw integer discriminant of this object kind.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ObjectKind> for u16 {
    fn from(kind: ObjectKind) -> Self {
        kind.as_u16()
    }
}

impl TryFrom<u16> for ObjectKind {
    type Error = UnknownObjectKind;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            OBJECT_KIND_NOTE => Ok(Self::Note),
            OBJECT_KIND_NOTEBOOK => Ok(Self::Notebook),
            OBJECT_KIND_USER_SETTINGS => Ok(Self::UserSettings),
            OBJECT_KIND_ATTACHMENT_MANIFEST => Ok(Self::AttachmentManifest),
            OBJECT_KIND_RESERVED => Ok(Self::Reserved),
            unknown => Err(UnknownObjectKind(unknown)),
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Note => write!(f, "NOTE"),
            Self::Notebook => write!(f, "NOTEBOOK"),
            Self::UserSettings => write!(f, "USER_SETTINGS"),
            Self::AttachmentManifest => write!(f, "ATTACHMENT_MANIFEST"),
            Self::Reserved => write!(f, "RESERVED"),
        }
    }
}
