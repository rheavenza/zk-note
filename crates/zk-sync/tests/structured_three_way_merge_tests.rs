//! Integration tests for Structured Three-Way Merge Engine (ZK-051).
//!
//! Acceptance criteria validated:
//! 1. Unchanged, local-only, and remote-only field cases;
//! 2. Identical concurrent changes merge cleanly;
//! 3. Divergent scalar changes reported as explicit conflicts;
//! 4. Deterministic set-based tag merge.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use zk_core::note::PlaintextNote;
use zk_sync::merge::{
    merge_attachments, merge_scalar_field, merge_tags, three_way_merge_note, FieldConflict,
    FieldMergeStatus,
};

fn make_note(title: &str, body: &str, tags: &[&str], attachments: &[&str]) -> PlaintextNote {
    let mut note = PlaintextNote::new(title, body);
    note.tags = tags.iter().map(|&s| s.to_string()).collect();
    note.attachments = attachments.iter().map(|&s| s.to_string()).collect();
    note.canonicalize();
    note
}

#[test]
fn test_three_way_merge_all_unchanged() {
    let base = make_note(
        "Weekly Standup",
        "Discuss Q3 roadmap",
        &["work"],
        &["doc-1"],
    );
    let local = base.clone();
    let remote = base.clone();

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(outcome.is_clean());
    assert!(outcome.conflicts.is_empty());
    assert_eq!(outcome.candidate.title, "Weekly Standup");
    assert_eq!(outcome.candidate.body, "Discuss Q3 roadmap");
    assert_eq!(outcome.candidate.tags, vec!["work"]);
    assert_eq!(outcome.candidate.attachments, vec!["doc-1"]);
}

#[test]
fn test_three_way_merge_local_only_modifications() {
    let base = make_note("Title", "Body", &["tag1"], &[]);
    let local = make_note(
        "Local Title",
        "Local Body",
        &["tag1", "urgent"],
        &["att-local"],
    );
    let remote = base.clone();

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(outcome.is_clean());
    assert_eq!(outcome.candidate.title, "Local Title");
    assert_eq!(outcome.candidate.body, "Local Body");
    assert_eq!(outcome.candidate.tags, vec!["tag1", "urgent"]);
    assert_eq!(outcome.candidate.attachments, vec!["att-local"]);
    assert_eq!(
        outcome.title_status,
        FieldMergeStatus::LocalOnly("Local Title".to_string())
    );
    assert_eq!(
        outcome.body_status,
        FieldMergeStatus::LocalOnly("Local Body".to_string())
    );
}

#[test]
fn test_three_way_merge_remote_only_modifications() {
    let base = make_note("Title", "Body", &["tag1"], &[]);
    let local = base.clone();
    let remote = make_note(
        "Remote Title",
        "Remote Body",
        &["tag1", "reviewed"],
        &["att-remote"],
    );

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(outcome.is_clean());
    assert_eq!(outcome.candidate.title, "Remote Title");
    assert_eq!(outcome.candidate.body, "Remote Body");
    assert_eq!(outcome.candidate.tags, vec!["reviewed", "tag1"]);
    assert_eq!(outcome.candidate.attachments, vec!["att-remote"]);
    assert_eq!(
        outcome.title_status,
        FieldMergeStatus::RemoteOnly("Remote Title".to_string())
    );
    assert_eq!(
        outcome.body_status,
        FieldMergeStatus::RemoteOnly("Remote Body".to_string())
    );
}

#[test]
fn test_three_way_merge_identical_concurrent_modifications() {
    let base = make_note("Draft Note", "Draft content", &["draft"], &[]);
    let local = make_note("Final Note", "Final content", &["final"], &["att-final"]);
    let remote = make_note("Final Note", "Final content", &["final"], &["att-final"]);

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(outcome.is_clean());
    assert_eq!(outcome.candidate.title, "Final Note");
    assert_eq!(outcome.candidate.body, "Final content");
    assert_eq!(outcome.candidate.tags, vec!["final"]);
    assert_eq!(outcome.candidate.attachments, vec!["att-final"]);
    assert_eq!(
        outcome.title_status,
        FieldMergeStatus::Identical("Final Note".to_string())
    );
    assert_eq!(
        outcome.body_status,
        FieldMergeStatus::Identical("Final content".to_string())
    );
}

#[test]
fn test_three_way_merge_divergent_title_conflict() {
    let base = make_note("Initial Title", "Body text", &["common"], &[]);
    let local = make_note("Alice's Title Edit", "Body text", &["common"], &[]);
    let remote = make_note("Bob's Title Edit", "Body text", &["common"], &[]);

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(!outcome.is_clean());
    assert_eq!(outcome.conflicts.len(), 1);

    match &outcome.conflicts[0] {
        FieldConflict::Title {
            base,
            local,
            remote,
        } => {
            assert_eq!(base, "Initial Title");
            assert_eq!(local, "Alice's Title Edit");
            assert_eq!(remote, "Bob's Title Edit");
        }
        other => panic!("expected Title conflict, got {:?}", other),
    }

    // Body was non-conflicting and merged cleanly
    assert_eq!(outcome.candidate.body, "Body text");
    assert_eq!(
        outcome.body_status,
        FieldMergeStatus::Unchanged("Body text".to_string())
    );
}

#[test]
fn test_three_way_merge_divergent_body_conflict() {
    let base = make_note("Title", "Original body text", &["common"], &[]);
    let local = make_note("Title", "Alice's divergent body", &["common"], &[]);
    let remote = make_note("Title", "Bob's divergent body", &["common"], &[]);

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
            assert_eq!(local, "Alice's divergent body");
            assert_eq!(remote, "Bob's divergent body");
        }
        other => panic!("expected Body conflict, got {:?}", other),
    }

    // Title was non-conflicting and merged cleanly
    assert_eq!(outcome.candidate.title, "Title");
    assert_eq!(
        outcome.title_status,
        FieldMergeStatus::Unchanged("Title".to_string())
    );
}

#[test]
fn test_three_way_merge_simultaneous_title_and_body_conflicts() {
    let base = make_note("Base Title", "Base Body", &["work"], &[]);
    let local = make_note("Local Title", "Local Body", &["work"], &[]);
    let remote = make_note("Remote Title", "Remote Body", &["work"], &[]);

    let outcome = three_way_merge_note(&base, &local, &remote);
    assert!(!outcome.is_clean());
    assert_eq!(outcome.conflicts.len(), 2);

    let has_title = outcome
        .conflicts
        .iter()
        .any(|c| matches!(c, FieldConflict::Title { .. }));
    let has_body = outcome
        .conflicts
        .iter()
        .any(|c| matches!(c, FieldConflict::Body { .. }));
    assert!(has_title);
    assert!(has_body);
}

#[test]
fn test_deterministic_tag_set_merge_scenarios() {
    // Scenario 1: Non-overlapping additions
    let base = vec!["core".to_string()];
    let local = vec!["core".to_string(), "local_tag".to_string()];
    let remote = vec!["core".to_string(), "remote_tag".to_string()];
    let merged = merge_tags(&base, &local, &remote);
    assert_eq!(merged, vec!["core", "local_tag", "remote_tag"]);

    // Scenario 2: One side removes, one side adds
    let base = vec!["keep_me".to_string(), "delete_me".to_string()];
    let local = vec!["keep_me".to_string()]; // deleted 'delete_me'
    let remote = vec![
        "keep_me".to_string(),
        "delete_me".to_string(),
        "added_remote".to_string(),
    ];
    let merged = merge_tags(&base, &local, &remote);
    assert_eq!(merged, vec!["added_remote", "keep_me"]);

    // Scenario 3: Both sides delete same tag
    let base = vec!["tag_a".to_string(), "tag_b".to_string()];
    let local = vec!["tag_a".to_string()];
    let remote = vec!["tag_a".to_string()];
    let merged = merge_tags(&base, &local, &remote);
    assert_eq!(merged, vec!["tag_a"]);

    // Scenario 4: Case normalization, trimming, and sorting
    let base = vec![];
    let local = vec!["  ZETA  ".to_string(), "ALPHA".to_string()];
    let remote = vec!["beta".to_string(), "alpha".to_string()];
    let merged = merge_tags(&base, &local, &remote);
    assert_eq!(merged, vec!["alpha", "beta", "zeta"]);
}

#[test]
fn test_deterministic_attachment_manifest_merge() {
    let base = vec!["att-1".to_string(), "att-2".to_string()];
    let local = vec!["att-1".to_string(), "att-local".to_string()]; // removed att-2, added att-local
    let remote = vec![
        "att-1".to_string(),
        "att-2".to_string(),
        "att-remote".to_string(),
    ]; // added att-remote

    let merged = merge_attachments(&base, &local, &remote);
    assert_eq!(merged, vec!["att-1", "att-local", "att-remote"]);
}

#[test]
fn test_scalar_field_merge_helper() {
    let base = 10u64;
    let local_same = 10u64;
    let local_diff = 20u64;
    let remote_same = 10u64;
    let remote_diff = 30u64;

    assert_eq!(
        merge_scalar_field(&base, &local_same, &remote_same),
        FieldMergeStatus::Unchanged(10)
    );
    assert_eq!(
        merge_scalar_field(&base, &local_diff, &remote_same),
        FieldMergeStatus::LocalOnly(20)
    );
    assert_eq!(
        merge_scalar_field(&base, &local_same, &remote_diff),
        FieldMergeStatus::RemoteOnly(30)
    );
    assert_eq!(
        merge_scalar_field(&base, &local_diff, &local_diff),
        FieldMergeStatus::Identical(20)
    );
    assert_eq!(
        merge_scalar_field(&base, &local_diff, &remote_diff),
        FieldMergeStatus::Conflict {
            base: 10,
            local: 20,
            remote: 30
        }
    );
}
