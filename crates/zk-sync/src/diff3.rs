//! Line-based three-way text merge (diff3) for Markdown note bodies (ZK-052).
//!
//! In accordance with MASTER_SPEC.md § 10.3:
//! - Non-overlapping line edits auto-merge cleanly;
//! - Identical concurrent edits merge without conflict;
//! - Overlapping divergent line edits become explicit conflicts with diff3 markers;
//! - No side is silently discarded under any condition;
//! - Deterministic behavior across all platforms.

use std::collections::HashMap;

/// An explicit overlapping line-level conflict between local and remote edits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BodyConflict {
    /// Approximate 1-based line number in the base document where the conflict began.
    pub base_line_start: usize,
    /// Conflicting lines from the base revision.
    pub base_lines: Vec<String>,
    /// Conflicting lines from the local revision.
    pub local_lines: Vec<String>,
    /// Conflicting lines from the remote revision.
    pub remote_lines: Vec<String>,
}

/// The result of a line-based three-way diff merge of text bodies.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Diff3Result {
    /// Merged text body. If `is_clean` is true, non-overlapping edits were merged cleanly.
    /// If `is_clean` is false, contains formatted conflict markers preserving all sides.
    pub merged_text: String,
    /// Whether the text body merged cleanly without any overlapping conflicts.
    pub is_clean: bool,
    /// List of explicit overlapping conflicts encountered.
    pub conflicts: Vec<BodyConflict>,
}

/// Computes Longest Common Subsequence (LCS) matched line index pairs between slices `a` and `b`.
///
/// Optimizes common prefix and suffix first, running dynamic programming on the differing core.
fn lcs_matched_pairs(a: &[&str], b: &[&str]) -> Vec<(usize, usize)> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }

    // 1. Trim common prefix
    let mut prefix_len = 0;
    while prefix_len < a.len() && prefix_len < b.len() && a[prefix_len] == b[prefix_len] {
        prefix_len += 1;
    }

    // 2. Trim common suffix
    let mut suffix_len = 0;
    while suffix_len < a.len() - prefix_len
        && suffix_len < b.len() - prefix_len
        && a[a.len() - 1 - suffix_len] == b[b.len() - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let a_mid = &a[prefix_len..a.len() - suffix_len];
    let b_mid = &b[prefix_len..b.len() - suffix_len];

    let mut mid_pairs = Vec::new();

    if !a_mid.is_empty() && !b_mid.is_empty() {
        let n = a_mid.len();
        let m = b_mid.len();

        if n.saturating_mul(m) <= 4_000_000 {
            let mut dp = vec![vec![0u32; m + 1]; n + 1];
            for i in (0..n).rev() {
                for j in (0..m).rev() {
                    if a_mid[i] == b_mid[j] {
                        dp[i][j] = 1 + dp[i + 1][j + 1];
                    } else {
                        dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
                    }
                }
            }

            let mut i = 0;
            let mut j = 0;
            while i < n && j < m {
                if a_mid[i] == b_mid[j] {
                    mid_pairs.push((prefix_len + i, prefix_len + j));
                    i += 1;
                    j += 1;
                } else if dp[i + 1][j] >= dp[i][j + 1] {
                    i += 1;
                } else {
                    j += 1;
                }
            }
        }
    }

    let total_matches = prefix_len + mid_pairs.len() + suffix_len;
    let mut result = Vec::with_capacity(total_matches);

    for k in 0..prefix_len {
        result.push((k, k));
    }

    result.extend(mid_pairs);

    for k in 0..suffix_len {
        result.push((a.len() - suffix_len + k, b.len() - suffix_len + k));
    }

    result
}

/// Performs a deterministic line-based three-way merge (diff3) on text bodies.
///
/// Rules:
/// - Non-overlapping edits auto-merge cleanly.
/// - Identical concurrent edits merge without conflict.
/// - Overlapping divergent edits become explicit conflict blocks demarcated with standard
///   diff3 conflict markers (`<<<<<<< LOCAL`, `||||||| BASE`, `=======`, `>>>>>>> REMOTE`).
/// - No text from any side is silently discarded.
pub fn diff3_merge(base: &str, local: &str, remote: &str) -> Diff3Result {
    // Fast path: if local and remote are identical, return local directly
    if local == remote {
        return Diff3Result {
            merged_text: local.to_string(),
            is_clean: true,
            conflicts: Vec::new(),
        };
    }

    // Fast path: if remote equals base, return local
    if remote == base {
        return Diff3Result {
            merged_text: local.to_string(),
            is_clean: true,
            conflicts: Vec::new(),
        };
    }

    // Fast path: if local equals base, return remote
    if local == base {
        return Diff3Result {
            merged_text: remote.to_string(),
            is_clean: true,
            conflicts: Vec::new(),
        };
    }

    // Normalize newlines to \n to guarantee platform-independent deterministic line splitting
    let base_norm = base.replace("\r\n", "\n").replace('\r', "\n");
    let local_norm = local.replace("\r\n", "\n").replace('\r', "\n");
    let remote_norm = remote.replace("\r\n", "\n").replace('\r', "\n");

    let base_lines: Vec<&str> = if base_norm.is_empty() {
        Vec::new()
    } else {
        base_norm.split('\n').collect()
    };
    let local_lines: Vec<&str> = if local_norm.is_empty() {
        Vec::new()
    } else {
        local_norm.split('\n').collect()
    };
    let remote_lines: Vec<&str> = if remote_norm.is_empty() {
        Vec::new()
    } else {
        remote_norm.split('\n').collect()
    };

    let pairs_bl = lcs_matched_pairs(&base_lines, &local_lines);
    let pairs_br = lcs_matched_pairs(&base_lines, &remote_lines);

    let br_map: HashMap<usize, usize> = pairs_br.into_iter().collect();

    // Common anchors: lines present in base that were matched in both local and remote
    let mut common_anchors: Vec<(usize, usize, usize)> = Vec::new();
    for (b, l) in pairs_bl {
        if let Some(&r) = br_map.get(&b) {
            common_anchors.push((b, l, r));
        }
    }

    let mut output_lines: Vec<String> = Vec::new();
    let mut conflicts: Vec<BodyConflict> = Vec::new();

    let mut prev_b = 0;
    let mut prev_l = 0;
    let mut prev_r = 0;

    let process_chunk = |b_start: usize,
                         b_end: usize,
                         l_start: usize,
                         l_end: usize,
                         r_start: usize,
                         r_end: usize,
                         out: &mut Vec<String>,
                         confs: &mut Vec<BodyConflict>| {
        let chunk_base = &base_lines[b_start..b_end];
        let chunk_local = &local_lines[l_start..l_end];
        let chunk_remote = &remote_lines[r_start..r_end];

        let local_changed = chunk_local != chunk_base;
        let remote_changed = chunk_remote != chunk_base;

        match (local_changed, remote_changed) {
            (false, false) => {
                // Unchanged in both
                for line in chunk_base {
                    out.push((*line).to_string());
                }
            }
            (true, false) => {
                // Changed only locally
                for line in chunk_local {
                    out.push((*line).to_string());
                }
            }
            (false, true) => {
                // Changed only remotely
                for line in chunk_remote {
                    out.push((*line).to_string());
                }
            }
            (true, true) => {
                if chunk_local == chunk_remote {
                    // Identical concurrent change
                    for line in chunk_local {
                        out.push((*line).to_string());
                    }
                } else {
                    // Overlapping divergent conflict
                    confs.push(BodyConflict {
                        base_line_start: b_start + 1,
                        base_lines: chunk_base.iter().map(|s| (*s).to_string()).collect(),
                        local_lines: chunk_local.iter().map(|s| (*s).to_string()).collect(),
                        remote_lines: chunk_remote.iter().map(|s| (*s).to_string()).collect(),
                    });

                    // Format conflict chunk with standard markers
                    out.push("<<<<<<< LOCAL".to_string());
                    for line in chunk_local {
                        out.push((*line).to_string());
                    }
                    out.push("||||||| BASE".to_string());
                    for line in chunk_base {
                        out.push((*line).to_string());
                    }
                    out.push("=======".to_string());
                    for line in chunk_remote {
                        out.push((*line).to_string());
                    }
                    out.push(">>>>>>> REMOTE".to_string());
                }
            }
        }
    };

    for (b, l, r) in common_anchors {
        process_chunk(
            prev_b,
            b,
            prev_l,
            l,
            prev_r,
            r,
            &mut output_lines,
            &mut conflicts,
        );

        // Emit the anchor line itself
        output_lines.push(base_lines[b].to_string());

        prev_b = b + 1;
        prev_l = l + 1;
        prev_r = r + 1;
    }

    // Process final region after last anchor
    process_chunk(
        prev_b,
        base_lines.len(),
        prev_l,
        local_lines.len(),
        prev_r,
        remote_lines.len(),
        &mut output_lines,
        &mut conflicts,
    );

    let merged_text = output_lines.join("\n");
    let is_clean = conflicts.is_empty();

    Diff3Result {
        merged_text,
        is_clean,
        conflicts,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_diff3_all_identical() {
        let text = "Line 1\nLine 2\nLine 3";
        let res = diff3_merge(text, text, text);
        assert!(res.is_clean);
        assert_eq!(res.merged_text, text);
        assert!(res.conflicts.is_empty());
    }

    #[test]
    fn test_diff3_non_overlapping_edits_auto_merge() {
        let base = "Section 1\nIntro\n\nSection 2\nMiddle\n\nSection 3\nOutro";
        let local = "Section 1\nIntro modified by local\n\nSection 2\nMiddle\n\nSection 3\nOutro";
        let remote = "Section 1\nIntro\n\nSection 2\nMiddle\n\nSection 3\nOutro modified by remote";

        let res = diff3_merge(base, local, remote);
        assert!(res.is_clean);
        assert!(res.conflicts.is_empty());

        let expected = "Section 1\nIntro modified by local\n\nSection 2\nMiddle\n\nSection 3\nOutro modified by remote";
        assert_eq!(res.merged_text, expected);
    }

    #[test]
    fn test_diff3_identical_concurrent_edits() {
        let base = "Line 1\nLine 2\nLine 3";
        let local = "Line 1\nLine 2 changed by both\nLine 3";
        let remote = "Line 1\nLine 2 changed by both\nLine 3";

        let res = diff3_merge(base, local, remote);
        assert!(res.is_clean);
        assert_eq!(res.merged_text, local);
    }

    #[test]
    fn test_diff3_overlapping_edits_become_explicit_conflict() {
        let base = "Line 1\nOriginal line 2\nLine 3";
        let local = "Line 1\nAlice line 2\nLine 3";
        let remote = "Line 1\nBob line 2\nLine 3";

        let res = diff3_merge(base, local, remote);
        assert!(!res.is_clean);
        assert_eq!(res.conflicts.len(), 1);

        let conflict = &res.conflicts[0];
        assert_eq!(conflict.base_lines, vec!["Original line 2"]);
        assert_eq!(conflict.local_lines, vec!["Alice line 2"]);
        assert_eq!(conflict.remote_lines, vec!["Bob line 2"]);

        // Verify conflict markers are included and no side is silently discarded
        assert!(res.merged_text.contains("<<<<<<< LOCAL"));
        assert!(res.merged_text.contains("Alice line 2"));
        assert!(res.merged_text.contains("||||||| BASE"));
        assert!(res.merged_text.contains("Original line 2"));
        assert!(res.merged_text.contains("======="));
        assert!(res.merged_text.contains("Bob line 2"));
        assert!(res.merged_text.contains(">>>>>>> REMOTE"));
    }

    #[test]
    fn test_diff3_additions_at_both_ends() {
        let base = "Middle Line";
        let local = "Top Line Added\nMiddle Line";
        let remote = "Middle Line\nBottom Line Added";

        let res = diff3_merge(base, local, remote);
        assert!(res.is_clean);
        assert_eq!(
            res.merged_text,
            "Top Line Added\nMiddle Line\nBottom Line Added"
        );
    }

    #[test]
    fn test_diff3_deletion_on_one_side() {
        let base = "Line 1\nLine 2 to delete\nLine 3";
        let local = "Line 1\nLine 3";
        let remote = "Line 1\nLine 2 to delete\nLine 3";

        let res = diff3_merge(base, local, remote);
        assert!(res.is_clean);
        assert_eq!(res.merged_text, "Line 1\nLine 3");
    }
}
