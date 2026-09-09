//! Integration tests for Markdown body diff3 engine (ZK-052).
//!
//! Validates:
//! 1. Non-overlapping edits auto-merge cleanly;
//! 2. Overlapping edits become explicit conflicts with diff3 markers;
//! 3. No side is silently discarded under any condition;
//! 4. Deterministic behavior and cross-platform line normalization.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use zk_core::note::PlaintextNote;
use zk_sync::diff3::diff3_merge;
use zk_sync::merge::{three_way_merge_note, FieldMergeStatus};

#[test]
fn test_diff3_non_overlapping_sections_auto_merge() {
    let base = r#"# Project Plan

## Section 1: Overview
This is the original overview.

## Section 2: Architecture
This is the original architecture.

## Section 3: Roadmap
This is the original roadmap."#;

    // Alice updates Section 1
    let local = r#"# Project Plan

## Section 1: Overview
This is the updated overview from Alice.

## Section 2: Architecture
This is the original architecture.

## Section 3: Roadmap
This is the original roadmap."#;

    // Bob updates Section 3
    let remote = r#"# Project Plan

## Section 1: Overview
This is the original overview.

## Section 2: Architecture
This is the original architecture.

## Section 3: Roadmap
This is the updated roadmap from Bob."#;

    let res = diff3_merge(base, local, remote);
    assert!(
        res.is_clean,
        "Expected clean auto-merge for non-overlapping section edits"
    );
    assert!(res.conflicts.is_empty());

    let expected = r#"# Project Plan

## Section 1: Overview
This is the updated overview from Alice.

## Section 2: Architecture
This is the original architecture.

## Section 3: Roadmap
This is the updated roadmap from Bob."#;

    assert_eq!(res.merged_text, expected);
}

#[test]
fn test_diff3_non_overlapping_insertions_top_and_bottom() {
    let base = "Line A\nLine B\nLine C";
    let local = "Top Line (Local)\nLine A\nLine B\nLine C";
    let remote = "Line A\nLine B\nLine C\nBottom Line (Remote)";

    let res = diff3_merge(base, local, remote);
    assert!(res.is_clean);
    assert_eq!(
        res.merged_text,
        "Top Line (Local)\nLine A\nLine B\nLine C\nBottom Line (Remote)"
    );
}

#[test]
fn test_diff3_non_overlapping_edit_and_deletion() {
    let base = "Line 1\nLine 2 (to delete)\nLine 3\nLine 4 (to edit)";
    // Local deletes line 2
    let local = "Line 1\nLine 3\nLine 4 (to edit)";
    // Remote modifies line 4
    let remote = "Line 1\nLine 2 (to delete)\nLine 3\nLine 4 (modified by remote)";

    let res = diff3_merge(base, local, remote);
    assert!(res.is_clean);
    assert_eq!(
        res.merged_text,
        "Line 1\nLine 3\nLine 4 (modified by remote)"
    );
}

#[test]
fn test_diff3_identical_concurrent_modifications_merge_cleanly() {
    let base = "Line 1\nLine 2\nLine 3";
    let local = "Line 1\nLine 2 modified by consensus\nLine 3";
    let remote = "Line 1\nLine 2 modified by consensus\nLine 3";

    let res = diff3_merge(base, local, remote);
    assert!(res.is_clean);
    assert_eq!(res.merged_text, local);
    assert!(res.conflicts.is_empty());
}

#[test]
fn test_diff3_overlapping_line_edit_becomes_explicit_conflict() {
    let base = "Title\nBase content line\nFooter";
    let local = "Title\nAlice content line\nFooter";
    let remote = "Title\nBob content line\nFooter";

    let res = diff3_merge(base, local, remote);
    assert!(!res.is_clean);
    assert_eq!(res.conflicts.len(), 1);

    let conflict = &res.conflicts[0];
    assert_eq!(conflict.base_line_start, 2);
    assert_eq!(conflict.base_lines, vec!["Base content line"]);
    assert_eq!(conflict.local_lines, vec!["Alice content line"]);
    assert_eq!(conflict.remote_lines, vec!["Bob content line"]);

    // In accordance with SEC rules and MASTER_SPEC § 10.3:
    // No side silently discarded. Markers clearly identify local, base, and remote.
    let expected = "Title\n<<<<<<< LOCAL\nAlice content line\n||||||| BASE\nBase content line\n=======\nBob content line\n>>>>>>> REMOTE\nFooter";
    assert_eq!(res.merged_text, expected);
}

#[test]
fn test_diff3_overlapping_edit_vs_delete_conflict() {
    let base = "Header\nTarget Line\nFooter";
    // Local deletes Target Line
    let local = "Header\nFooter";
    // Remote modifies Target Line
    let remote = "Header\nTarget Line modified by Remote\nFooter";

    let res = diff3_merge(base, local, remote);
    assert!(!res.is_clean);
    assert_eq!(res.conflicts.len(), 1);

    let conflict = &res.conflicts[0];
    assert_eq!(conflict.base_line_start, 2);
    assert_eq!(conflict.base_lines, vec!["Target Line"]);
    assert!(
        conflict.local_lines.is_empty(),
        "Local deletion should have empty local_lines"
    );
    assert_eq!(
        conflict.remote_lines,
        vec!["Target Line modified by Remote"]
    );

    // Both deletion intent and modification are preserved
    assert!(res.merged_text.contains("<<<<<<< LOCAL"));
    assert!(res.merged_text.contains("||||||| BASE\nTarget Line"));
    assert!(res
        .merged_text
        .contains("=======\nTarget Line modified by Remote\n>>>>>>> REMOTE"));
}

#[test]
fn test_diff3_conflicting_simultaneous_insertions_at_same_line() {
    let base = "Header\nFooter";
    let local = "Header\nInserted by Local\nFooter";
    let remote = "Header\nInserted by Remote\nFooter";

    let res = diff3_merge(base, local, remote);
    assert!(!res.is_clean);
    assert_eq!(res.conflicts.len(), 1);

    let conflict = &res.conflicts[0];
    assert_eq!(conflict.base_lines.len(), 0);
    assert_eq!(conflict.local_lines, vec!["Inserted by Local"]);
    assert_eq!(conflict.remote_lines, vec!["Inserted by Remote"]);

    let expected = "Header\n<<<<<<< LOCAL\nInserted by Local\n||||||| BASE\n=======\nInserted by Remote\n>>>>>>> REMOTE\nFooter";
    assert_eq!(res.merged_text, expected);
}

#[test]
fn test_diff3_mixed_document_clean_and_conflicting_regions() {
    let base = r#"# Title

## Part 1
Base Part 1

## Part 2
Base Part 2

## Part 3
Base Part 3"#;

    // Local changes Part 1 cleanly, and Part 2 with "Local P2"
    let local = r#"# Title

## Part 1
Alice edited Part 1

## Part 2
Alice P2 edit

## Part 3
Base Part 3"#;

    // Remote changes Part 2 with "Remote P2", and Part 3 cleanly
    let remote = r#"# Title

## Part 1
Base Part 1

## Part 2
Bob P2 edit

## Part 3
Bob edited Part 3"#;

    let res = diff3_merge(base, local, remote);
    assert!(!res.is_clean);
    assert_eq!(res.conflicts.len(), 1);

    // Part 1 auto-merged cleanly with Alice's edit
    assert!(res.merged_text.contains("Alice edited Part 1"));
    // Part 3 auto-merged cleanly with Bob's edit
    assert!(res.merged_text.contains("Bob edited Part 3"));
    // Part 2 contains explicit conflict markers
    assert!(res.merged_text.contains("<<<<<<< LOCAL\nAlice P2 edit\n||||||| BASE\nBase Part 2\n=======\nBob P2 edit\n>>>>>>> REMOTE"));
}

#[test]
fn test_diff3_crlf_normalization_determinism() {
    let base_lf = "Line 1\nLine 2\nLine 3";
    let base_crlf = "Line 1\r\nLine 2\r\nLine 3";

    let local_lf = "Line 1 modified\nLine 2\nLine 3";
    let local_crlf = "Line 1 modified\r\nLine 2\r\nLine 3";

    let remote_lf = "Line 1\nLine 2\nLine 3 modified";
    let remote_crlf = "Line 1\r\nLine 2\r\nLine 3 modified";

    let res_lf = diff3_merge(base_lf, local_lf, remote_lf);
    let res_crlf = diff3_merge(base_crlf, local_crlf, remote_crlf);

    assert_eq!(res_lf.merged_text, res_crlf.merged_text);
    assert_eq!(res_lf.is_clean, res_crlf.is_clean);
    assert_eq!(res_lf.conflicts, res_crlf.conflicts);
}

#[test]
fn test_diff3_deterministic_reproducibility() {
    let base = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5";
    let local = "Line 1\nLocal 2\nLine 3\nLocal 4\nLine 5";
    let remote = "Line 1\nRemote 2\nLine 3\nLine 4\nRemote 5";

    let first = diff3_merge(base, local, remote);
    for _ in 0..100 {
        let trial = diff3_merge(base, local, remote);
        assert_eq!(first, trial, "diff3_merge must be 100% deterministic");
    }
}

#[test]
fn test_three_way_merge_note_integration_with_diff3() {
    let base_note = PlaintextNote::new(
        "Project Architecture",
        "# Architecture\n\n## Backend\nBase backend notes.\n\n## Frontend\nBase frontend notes.",
    );

    // Local changes Title and Backend body
    let mut local_note = PlaintextNote::new(
        "Project Architecture v2",
        "# Architecture\n\n## Backend\nLocal backend notes updated.\n\n## Frontend\nBase frontend notes.",
    );
    local_note.tags = vec!["architecture".to_string(), "backend".to_string()];

    // Remote changes Frontend body and adds a tag
    let mut remote_note = PlaintextNote::new(
        "Project Architecture",
        "# Architecture\n\n## Backend\nBase backend notes.\n\n## Frontend\nRemote frontend notes updated.",
    );
    remote_note.tags = vec!["architecture".to_string(), "frontend".to_string()];

    let outcome = three_way_merge_note(&base_note, &local_note, &remote_note);

    assert!(outcome.is_clean(), "Structured note should merge cleanly");
    assert_eq!(outcome.candidate.title, "Project Architecture v2");
    assert_eq!(
        outcome.candidate.tags,
        vec!["architecture", "backend", "frontend"]
    );

    let expected_body = "# Architecture\n\n## Backend\nLocal backend notes updated.\n\n## Frontend\nRemote frontend notes updated.";
    assert_eq!(outcome.candidate.body, expected_body);

    assert_eq!(
        outcome.body_status,
        FieldMergeStatus::Merged(expected_body.to_string())
    );
    assert!(outcome.body_diff.is_some());
    assert!(outcome.body_diff.as_ref().unwrap().is_clean);
}
