//! In-memory search indexing and retrieval for decrypted notes.
//!
//! Plaintext content is indexed strictly in volatile process memory while the vault is
//! unlocked. Persistent storage contains only ciphertext, and no plaintext search queries
//! or index structures are ever committed to disk or sent across the network.
//!
//! When the vault is locked or the index is dropped, all indexed content is wiped using
//! cryptographic zeroization.

use crate::note::PlaintextNote;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory indexed representation of a single note.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct IndexedNote {
    /// Note object identifier (UUID v4 string).
    pub id: String,
    /// Plaintext title.
    pub title: String,
    /// Plaintext tags.
    pub tags: Vec<String>,
    /// Plaintext body content.
    pub body: String,
    /// Last update timestamp (RFC 3339 UTC).
    pub updated_at: String,
}

/// Search match result highlighting relevant note metadata and content snippet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    /// Target note identifier (UUID v4 string).
    pub id: String,
    /// Note title.
    pub title: String,
    /// Note tags.
    pub tags: Vec<String>,
    /// Contextual snippet showing matched content.
    pub snippet: String,
    /// Last update timestamp (RFC 3339 UTC).
    pub updated_at: String,
    /// Relevance score (higher is more relevant).
    pub score: u32,
}

/// Volatile in-memory search index over decrypted notes.
#[derive(Default, Debug, Clone)]
pub struct InMemorySearchIndex {
    entries: Vec<IndexedNote>,
}

impl Drop for InMemorySearchIndex {
    fn drop(&mut self) {
        self.clear();
    }
}

impl InMemorySearchIndex {
    /// Creates a new, empty in-memory search index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts or updates a decrypted note in the volatile index.
    pub fn insert(&mut self, id: impl Into<String>, note: &PlaintextNote) {
        let id_str = id.into();
        self.remove(&id_str);
        self.entries.push(IndexedNote {
            id: id_str,
            title: note.title.clone(),
            tags: note.tags.clone(),
            body: note.body.clone(),
            updated_at: note.updated_at.clone(),
        });
    }

    /// Inserts raw note fields directly into the index.
    pub fn insert_raw(
        &mut self,
        id: String,
        title: String,
        tags: Vec<String>,
        body: String,
        updated_at: String,
    ) {
        self.remove(&id);
        self.entries.push(IndexedNote {
            id,
            title,
            tags,
            body,
            updated_at,
        });
    }

    /// Removes a note from the index by its ID.
    pub fn remove(&mut self, id: &str) {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let mut removed = self.entries.remove(pos);
            removed.zeroize();
        }
    }

    /// Clears all entries from the index and scrubs their memory.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }

    /// Returns the number of indexed notes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no notes are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Retrieves an indexed note reference by its ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&IndexedNote> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Searches indexed notes across title, body, and tags.
    ///
    /// - Multi-term queries require all terms to match across title, body, or tags (AND semantics).
    /// - Terms prefixed with `#` explicitly match note tags.
    /// - Results are ranked by relevance score descending, with ties broken by `updated_at` descending.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        let trimmed_query = query.trim();
        if trimmed_query.is_empty() {
            return Vec::new();
        }

        let full_query_lower = trimmed_query.to_lowercase();
        let terms: Vec<SearchTerm> = trimmed_query
            .split_whitespace()
            .map(|t| {
                if let Some(stripped) = t.strip_prefix('#') {
                    SearchTerm {
                        text: stripped.to_lowercase(),
                        tag_only: true,
                    }
                } else {
                    SearchTerm {
                        text: t.to_lowercase(),
                        tag_only: false,
                    }
                }
            })
            .collect();

        if terms.is_empty() {
            return Vec::new();
        }

        let raw_terms: Vec<String> = terms.iter().map(|t| t.text.clone()).collect();
        let mut matches = Vec::new();

        for note in &self.entries {
            if let Some(score) = score_note(note, &full_query_lower, &terms) {
                let snippet = extract_snippet(&note.body, &raw_terms);
                matches.push(SearchResult {
                    id: note.id.clone(),
                    title: note.title.clone(),
                    tags: note.tags.clone(),
                    snippet,
                    updated_at: note.updated_at.clone(),
                    score,
                });
            }
        }

        // Sort by score descending, then updated_at descending
        matches.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| b.updated_at.cmp(&a.updated_at))
        });

        matches
    }
}

#[derive(Debug, Clone)]
struct SearchTerm {
    text: String,
    tag_only: bool,
}

/// Evaluates if a note matches the search terms and computes a relevance score.
/// Returns `None` if any term fails to match.
fn score_note(note: &IndexedNote, full_query: &str, terms: &[SearchTerm]) -> Option<u32> {
    let lower_title = note.title.to_lowercase();
    let lower_body = note.body.to_lowercase();
    let lower_tags: Vec<String> = note.tags.iter().map(|t| t.to_lowercase()).collect();

    // Verify all terms match
    for term in terms {
        let term_str = &term.text;
        if term.tag_only {
            let matched_tag = lower_tags
                .iter()
                .any(|t| t == term_str || t.contains(term_str));
            if !matched_tag {
                return None;
            }
        } else {
            let in_title = lower_title.contains(term_str);
            let in_body = lower_body.contains(term_str);
            let in_tags = lower_tags
                .iter()
                .any(|t| t == term_str || t.contains(term_str));

            if !in_title && !in_body && !in_tags {
                return None;
            }
        }
    }

    // Base score for matching all terms
    let mut score = 10u32;

    // Full query boosts
    if lower_title == full_query {
        score += 200;
    } else if lower_title.contains(full_query) {
        score += 100;
    }

    if lower_body.contains(full_query) {
        score += 40;
    }

    // Per-term scoring
    for term in terms {
        let term_str = &term.text;

        // Title scoring
        if lower_title == *term_str {
            score += 60;
        } else if lower_title
            .split(|c: char| !c.is_alphanumeric())
            .any(|w| w == term_str)
        {
            score += 40;
        } else if lower_title.contains(term_str) {
            score += 20;
        }

        // Tag scoring
        for tag in &lower_tags {
            if tag == term_str {
                score += 50;
            } else if tag.contains(term_str) {
                score += 25;
            }
        }

        // Body scoring
        if !term.tag_only {
            let count = lower_body.matches(term_str).count();
            if count > 0 {
                let occurrences_bonus = std::cmp::min(count as u32 * 2, 20);
                score += 10 + occurrences_bonus;
            }
        }
    }

    Some(score)
}

/// Extracts a clean contextual snippet surrounding matched terms in the body.
fn extract_snippet(body: &str, terms: &[String]) -> String {
    if body.is_empty() {
        return String::new();
    }

    let lower_body = body.to_lowercase();
    let mut earliest_pos = None;

    for term in terms {
        if term.is_empty() {
            continue;
        }
        if let Some(pos) = lower_body.find(term) {
            match earliest_pos {
                Some(p) if pos < p => earliest_pos = Some(pos),
                None => earliest_pos = Some(pos),
                _ => {}
            }
        }
    }

    let char_indices: Vec<(usize, char)> = body.char_indices().collect();
    if char_indices.is_empty() {
        return String::new();
    }

    let (char_start, char_end) = if let Some(byte_pos) = earliest_pos {
        let match_char_idx = char_indices
            .iter()
            .position(|(b, _)| *b >= byte_pos)
            .unwrap_or(0);
        let start = match_char_idx.saturating_sub(20);
        let end = std::cmp::min(char_indices.len(), match_char_idx + 40);
        (start, end)
    } else {
        // No match in body (matched in title/tags) -> snippet is the start of body
        (0, std::cmp::min(char_indices.len(), 60))
    };

    let snippet_str: String = char_indices[char_start..char_end]
        .iter()
        .map(|(_, c)| if *c == '\n' || *c == '\r' { ' ' } else { *c })
        .collect();

    let mut result = String::new();
    if char_start > 0 {
        result.push_str("...");
    }
    result.push_str(snippet_str.trim());
    if char_end < char_indices.len() {
        result.push_str("...");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_index() -> InMemorySearchIndex {
        let mut index = InMemorySearchIndex::new();

        index.insert_raw(
            "note-1".to_string(),
            "Architecture Plan".to_string(),
            vec!["architecture".to_string(), "crypto".to_string()],
            "Client-side encryption details with Argon2id and XChaCha20-Poly1305.".to_string(),
            "2026-09-09T01:00:00.000Z".to_string(),
        );

        index.insert_raw(
            "note-2".to_string(),
            "Shopping List".to_string(),
            vec!["personal".to_string()],
            "Milk, tea, apples, and honey.".to_string(),
            "2026-09-09T02:00:00.000Z".to_string(),
        );

        index.insert_raw(
            "note-3".to_string(),
            "Cryptography Notes".to_string(),
            vec!["crypto".to_string(), "security".to_string()],
            "Zero-knowledge architecture means the server never sees plaintext.".to_string(),
            "2026-09-09T03:00:00.000Z".to_string(),
        );

        index
    }

    #[test]
    fn test_search_by_title() {
        let index = create_test_index();
        let results = index.search("Shopping");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-2");
        assert_eq!(results[0].title, "Shopping List");
    }

    #[test]
    fn test_search_by_tag() {
        let index = create_test_index();
        let results = index.search("personal");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-2");

        let crypto_results = index.search("crypto");
        assert_eq!(crypto_results.len(), 2);
        // Note 3 has "Cryptography" in title + "crypto" in tags, so higher score than Note 1
        assert_eq!(crypto_results[0].id, "note-3");
        assert_eq!(crypto_results[1].id, "note-1");
    }

    #[test]
    fn test_search_by_explicit_hash_tag() {
        let index = create_test_index();
        let results = index.search("#security");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-3");

        // Hash tag not found in tags does not match even if in body
        let no_match = index.search("#server");
        assert!(no_match.is_empty());
    }

    #[test]
    fn test_search_by_body_content() {
        let index = create_test_index();
        let results = index.search("Argon2id");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-1");
        assert!(results[0].snippet.contains("Argon2id"));
    }

    #[test]
    fn test_search_case_insensitive() {
        let index = create_test_index();
        let results = index.search("sHoPpiNg");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-2");
    }

    #[test]
    fn test_search_multi_term_and_semantics() {
        let index = create_test_index();
        // Matches Note 1 (architecture in title, encryption in body)
        let results = index.search("architecture encryption");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "note-1");

        // One matching term and one non-matching term returns empty
        let empty = index.search("architecture nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_empty_query_returns_empty() {
        let index = create_test_index();
        assert!(index.search("").is_empty());
        assert!(index.search("   ").is_empty());
    }

    #[test]
    fn test_remove_and_clear_zeroizes() {
        let mut index = create_test_index();
        assert_eq!(index.len(), 3);

        index.remove("note-2");
        assert_eq!(index.len(), 2);
        assert!(index.search("Shopping").is_empty());

        index.clear();
        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
        assert!(index.search("crypto").is_empty());
    }
}
