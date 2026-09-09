//! Structured three-way merge engine for zero-knowledge notes (ZK-051).
//!
//! In accordance with MASTER_SPEC.md § 10.2:
//! - Field changed only locally → keep local;
//! - Field changed only remotely → keep remote;
//! - Identical local/remote change → keep change;
//! - Divergent change to same scalar field → report explicit conflict;
//! - Tags → set-based three-way merge (deterministic, deduplicated, sorted);
//! - Attachments → set-based three-way merge by stable ID.

use std::collections::BTreeSet;
use std::fmt;
use zk_core::note::PlaintextNote;

/// Detailed classification of a scalar field merge attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldMergeStatus<T> {
    /// Field was unchanged across all three versions.
    Unchanged(T),
    /// Field was modified only by the local client.
    LocalOnly(T),
    /// Field was modified only by the remote client.
    RemoteOnly(T),
    /// Field was modified identically by both local and remote clients.
    Identical(T),
    /// Divergent modification by both sides: cannot be automatically resolved.
    Conflict {
        /// Base value prior to divergent edits.
        base: T,
        /// Local edited value.
        local: T,
        /// Remote conflicting value.
        remote: T,
    },
}

/// A conflict on an individual scalar field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldConflict {
    /// Divergent note title change.
    Title {
        /// Value at base revision.
        base: String,
        /// Local client value.
        local: String,
        /// Remote client value.
        remote: String,
    },
    /// Divergent note body change.
    Body {
        /// Value at base revision.
        base: String,
        /// Local client value.
        local: String,
        /// Remote client value.
        remote: String,
    },
    /// Divergent attachment manifest conflict.
    Attachments {
        /// Attachments at base revision.
        base: Vec<String>,
        /// Local attachments.
        local: Vec<String>,
        /// Remote attachments.
        remote: Vec<String>,
    },
}

impl fmt::Display for FieldConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Title {
                base,
                local,
                remote,
            } => {
                write!(
                    f,
                    "title conflict: base='{base}', local='{local}', remote='{remote}'"
                )
            }
            Self::Body { .. } => write!(f, "body conflict: local and remote bodies diverged"),
            Self::Attachments {
                base,
                local,
                remote,
            } => {
                write!(
                    f,
                    "attachments conflict: base={:?}, local={:?}, remote={:?}",
                    base, local, remote
                )
            }
        }
    }
}

/// The result of a structured three-way merge between BASE, LOCAL, and REMOTE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteMergeOutcome {
    /// Merged note candidate.
    ///
    /// If `is_clean()` is true, this candidate represents the complete, safely resolved note.
    /// If `is_clean()` is false, this candidate contains the non-conflicting fields merged,
    /// while conflicting fields default to local edits pending user or algorithmic resolution.
    pub candidate: PlaintextNote,
    /// List of field conflicts that prevented a fully automatic clean merge.
    pub conflicts: Vec<FieldConflict>,
    /// Field-by-field merge diagnostics.
    pub title_status: FieldMergeStatus<String>,
    /// Field-by-field body diagnostics.
    pub body_status: FieldMergeStatus<String>,
}

impl NoteMergeOutcome {
    /// Returns true if all fields merged cleanly without any divergent conflicts.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// Merges a single scalar field across BASE, LOCAL, and REMOTE.
///
/// Rules:
/// - Unchanged across all three → Keep base
/// - Changed only locally (local != base, remote == base) → Keep local
/// - Changed only remotely (remote != base, local == base) → Keep remote
/// - Changed identically (local != base, local == remote) → Keep local/remote
/// - Divergent (local != base, remote != base, local != remote) → Conflict
pub fn merge_scalar_field<T: PartialEq + Clone>(
    base: &T,
    local: &T,
    remote: &T,
) -> FieldMergeStatus<T> {
    let local_changed = local != base;
    let remote_changed = remote != base;

    match (local_changed, remote_changed) {
        (false, false) => FieldMergeStatus::Unchanged(base.clone()),
        (true, false) => FieldMergeStatus::LocalOnly(local.clone()),
        (false, true) => FieldMergeStatus::RemoteOnly(remote.clone()),
        (true, true) => {
            if local == remote {
                FieldMergeStatus::Identical(local.clone())
            } else {
                FieldMergeStatus::Conflict {
                    base: base.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                }
            }
        }
    }
}

/// Performs a deterministic set-based three-way merge on tag lists.
///
/// Rules:
/// - A tag present in BASE is kept if neither LOCAL nor REMOTE removed it.
/// - A tag absent in BASE is added if either LOCAL or REMOTE added it.
/// - Output is canonicalized: trimmed, lowercase, deduplicated, and sorted.
pub fn merge_tags(base: &[String], local: &[String], remote: &[String]) -> Vec<String> {
    let base_set: BTreeSet<String> = base.iter().map(|s| s.trim().to_lowercase()).collect();
    let local_set: BTreeSet<String> = local.iter().map(|s| s.trim().to_lowercase()).collect();
    let remote_set: BTreeSet<String> = remote.iter().map(|s| s.trim().to_lowercase()).collect();

    let mut merged_set = BTreeSet::new();

    // Union of all candidate tags
    let all_tags: BTreeSet<&String> = base_set
        .iter()
        .chain(local_set.iter())
        .chain(remote_set.iter())
        .collect();

    for tag in all_tags {
        if tag.is_empty() {
            continue;
        }

        let in_base = base_set.contains(tag);
        let in_local = local_set.contains(tag);
        let in_remote = remote_set.contains(tag);

        if in_base {
            // If it was in base, it is preserved UNLESS explicitly removed by local or remote
            // In 3-way set merge, a removal on either side takes precedence over base
            if in_local && in_remote {
                merged_set.insert(tag.clone());
            }
        } else {
            // If it was NOT in base, it is added if added by either local or remote
            if in_local || in_remote {
                merged_set.insert(tag.clone());
            }
        }
    }

    merged_set.into_iter().collect()
}

/// Performs a deterministic set-based three-way merge on attachment ID manifests.
pub fn merge_attachments(base: &[String], local: &[String], remote: &[String]) -> Vec<String> {
    let base_set: BTreeSet<String> = base.iter().cloned().collect();
    let local_set: BTreeSet<String> = local.iter().cloned().collect();
    let remote_set: BTreeSet<String> = remote.iter().cloned().collect();

    let mut merged_set = BTreeSet::new();

    let all_attachments: BTreeSet<&String> = base_set
        .iter()
        .chain(local_set.iter())
        .chain(remote_set.iter())
        .collect();

    for att in all_attachments {
        let in_base = base_set.contains(att);
        let in_local = local_set.contains(att);
        let in_remote = remote_set.contains(att);

        if in_base {
            if in_local && in_remote {
                merged_set.insert(att.clone());
            }
        } else if in_local || in_remote {
            merged_set.insert(att.clone());
        }
    }

    merged_set.into_iter().collect()
}

/// Executes a structured three-way merge between a BASE note, LOCAL note, and REMOTE note.
///
/// Implements all acceptance criteria of ZK-051:
/// - Handles unchanged, local-only, and remote-only fields.
/// - Handles identical concurrent changes safely.
/// - Detects and reports divergent scalar changes as explicit conflicts.
/// - Performs deterministic set-based tag and attachment merging.
pub fn three_way_merge_note(
    base: &PlaintextNote,
    local: &PlaintextNote,
    remote: &PlaintextNote,
) -> NoteMergeOutcome {
    let mut conflicts = Vec::new();

    // 1. Merge Title
    let title_status = merge_scalar_field(&base.title, &local.title, &remote.title);
    let final_title = match &title_status {
        FieldMergeStatus::Unchanged(t)
        | FieldMergeStatus::LocalOnly(t)
        | FieldMergeStatus::RemoteOnly(t)
        | FieldMergeStatus::Identical(t) => t.clone(),
        FieldMergeStatus::Conflict {
            base: b,
            local: l,
            remote: r,
        } => {
            conflicts.push(FieldConflict::Title {
                base: b.clone(),
                local: l.clone(),
                remote: r.clone(),
            });
            l.clone() // Preserve local candidate pending explicit resolution
        }
    };

    // 2. Merge Body
    let body_status = merge_scalar_field(&base.body, &local.body, &remote.body);
    let final_body = match &body_status {
        FieldMergeStatus::Unchanged(b)
        | FieldMergeStatus::LocalOnly(b)
        | FieldMergeStatus::RemoteOnly(b)
        | FieldMergeStatus::Identical(b) => b.clone(),
        FieldMergeStatus::Conflict {
            base: b,
            local: l,
            remote: r,
        } => {
            conflicts.push(FieldConflict::Body {
                base: b.clone(),
                local: l.clone(),
                remote: r.clone(),
            });
            l.clone() // Preserve local candidate pending explicit resolution
        }
    };

    // 3. Merge Tags
    let final_tags = merge_tags(&base.tags, &local.tags, &remote.tags);

    // 4. Merge Attachments
    let final_attachments =
        merge_attachments(&base.attachments, &local.attachments, &remote.attachments);

    // 5. Construct candidate
    let mut candidate = PlaintextNote::new(final_title, final_body);
    candidate.tags = final_tags;
    candidate.attachments = final_attachments;
    candidate.created_at = base.created_at.clone();
    candidate.canonicalize();

    NoteMergeOutcome {
        candidate,
        conflicts,
        title_status,
        body_status,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_note(title: &str, body: &str, tags: &[&str]) -> PlaintextNote {
        let mut note = PlaintextNote::new(title, body);
        note.tags = tags.iter().map(|&s| s.to_string()).collect();
        note.canonicalize();
        note
    }

    #[test]
    fn test_merge_unchanged_case() {
        let base = make_note("Original Title", "Original Body", &["alpha", "beta"]);
        let local = base.clone();
        let remote = base.clone();

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(outcome.is_clean());
        assert_eq!(outcome.candidate.title, "Original Title");
        assert_eq!(outcome.candidate.body, "Original Body");
        assert_eq!(outcome.candidate.tags, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_merge_local_only_change() {
        let base = make_note("Title", "Body", &["tag1"]);
        let local = make_note("Local Title", "Local Body", &["tag1", "local"]);
        let remote = base.clone();

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(outcome.is_clean());
        assert_eq!(outcome.candidate.title, "Local Title");
        assert_eq!(outcome.candidate.body, "Local Body");
        assert_eq!(outcome.candidate.tags, vec!["local", "tag1"]);
    }

    #[test]
    fn test_merge_remote_only_change() {
        let base = make_note("Title", "Body", &["tag1"]);
        let local = base.clone();
        let remote = make_note("Remote Title", "Remote Body", &["remote", "tag1"]);

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(outcome.is_clean());
        assert_eq!(outcome.candidate.title, "Remote Title");
        assert_eq!(outcome.candidate.body, "Remote Body");
        assert_eq!(outcome.candidate.tags, vec!["remote", "tag1"]);
    }

    #[test]
    fn test_merge_identical_concurrent_changes() {
        let base = make_note("Title", "Body", &["tag1"]);
        let local = make_note("Agreed Title", "Agreed Body", &["tag1", "done"]);
        let remote = make_note("Agreed Title", "Agreed Body", &["done", "tag1"]);

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(outcome.is_clean());
        assert_eq!(outcome.candidate.title, "Agreed Title");
        assert_eq!(outcome.candidate.body, "Agreed Body");
        assert_eq!(outcome.candidate.tags, vec!["done", "tag1"]);
    }

    #[test]
    fn test_merge_divergent_title_conflict() {
        let base = make_note("Base Title", "Body unchanged", &["tag1"]);
        let local = make_note("Local Title Edit", "Body unchanged", &["tag1"]);
        let remote = make_note("Remote Title Edit", "Body unchanged", &["tag1"]);

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(!outcome.is_clean());
        assert_eq!(outcome.conflicts.len(), 1);

        match &outcome.conflicts[0] {
            FieldConflict::Title {
                base,
                local,
                remote,
            } => {
                assert_eq!(base, "Base Title");
                assert_eq!(local, "Local Title Edit");
                assert_eq!(remote, "Remote Title Edit");
            }
            other => panic!("expected Title conflict, got {:?}", other),
        }
    }

    #[test]
    fn test_merge_divergent_body_conflict() {
        let base = make_note("Title unchanged", "Original body text", &["tag1"]);
        let local = make_note("Title unchanged", "Local edited body", &["tag1"]);
        let remote = make_note("Title unchanged", "Remote edited body", &["tag1"]);

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(!outcome.is_clean());
        assert_eq!(outcome.conflicts.len(), 1);

        match &outcome.conflicts[0] {
            FieldConflict::Body {
                base,
                local,
                remote,
            } => {
                assert_eq!(base, "Original body text");
                assert_eq!(local, "Local edited body");
                assert_eq!(remote, "Remote edited body");
            }
            other => panic!("expected Body conflict, got {:?}", other),
        }
    }

    #[test]
    fn test_deterministic_tag_three_way_merge() {
        // Base has: a, b, c
        let base = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // Local removed 'b', added 'd'
        let local = vec!["a".to_string(), "c".to_string(), "d".to_string()];
        // Remote removed 'c', added 'e'
        let remote = vec!["a".to_string(), "b".to_string(), "e".to_string()];

        let merged = merge_tags(&base, &local, &remote);
        // 'a': kept by both -> kept
        // 'b': removed by local -> removed
        // 'c': removed by remote -> removed
        // 'd': added by local -> added
        // 'e': added by remote -> added
        assert_eq!(merged, vec!["a", "d", "e"]);
    }

    #[test]
    fn test_non_overlapping_structured_changes_merge_cleanly() {
        let base = make_note("Base Title", "Base Body", &["work"]);
        // Local changed title only
        let local = make_note("Updated Title", "Base Body", &["work"]);
        // Remote changed tags only
        let remote = make_note("Base Title", "Base Body", &["work", "priority"]);

        let outcome = three_way_merge_note(&base, &local, &remote);
        assert!(outcome.is_clean());
        assert_eq!(outcome.candidate.title, "Updated Title");
        assert_eq!(outcome.candidate.body, "Base Body");
        assert_eq!(outcome.candidate.tags, vec!["priority", "work"]);
    }
}
