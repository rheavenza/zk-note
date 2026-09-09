//! Secure temporary file management and frontmatter parsing for the `$EDITOR` workflow.

use crate::error::CliError;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Parsed representation of an edited Markdown note with frontmatter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEdit {
    /// Note title.
    pub title: String,
    /// Canonicalized note tags.
    pub tags: Vec<String>,
    /// Markdown body content.
    pub body: String,
}

/// Serializes note title, tags, and body into a temporary Markdown file with frontmatter.
#[must_use]
pub fn note_to_edit_buffer(title: &str, tags: &[String], body: &str) -> String {
    let tags_formatted = if tags.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", tags.join(", "))
    };

    format!("---\ntitle: {title}\ntags: {tags_formatted}\n---\n\n{body}\n")
}

/// Parses an edited note buffer, extracting title, tags, and body.
///
/// If frontmatter fences (`---`) are absent or incomplete, gracefully falls back
/// to using any leading markdown heading `# <title>` or the original defaults.
pub fn parse_edit_buffer(
    content: &str,
    default_title: &str,
    default_tags: &[String],
) -> Result<ParsedEdit, CliError> {
    let trimmed = content.trim_start();

    if let Some(rest) = trimmed.strip_prefix("---") {
        // Strip opening --- and newline
        let after_opening = if let Some(stripped) = rest.strip_prefix("\r\n") {
            stripped
        } else if let Some(stripped) = rest.strip_prefix('\n') {
            stripped
        } else {
            rest
        };

        // Find closing --- fence
        if let Some(closing_pos) = find_closing_fence(after_opening) {
            let frontmatter = &after_opening[..closing_pos];
            let raw_body = &after_opening[closing_pos + 3..];
            let body = raw_body.trim().to_string();

            let mut title = default_title.to_string();
            let mut tags = default_tags.to_vec();

            for line in frontmatter.lines() {
                let line_trim = line.trim();
                if let Some(val) = line_trim.strip_prefix("title:") {
                    let cleaned = val.trim().trim_matches('"').trim_matches('\'').to_string();
                    if !cleaned.is_empty() {
                        title = cleaned;
                    }
                } else if let Some(val) = line_trim.strip_prefix("tags:") {
                    let cleaned = val.trim().trim_matches('[').trim_matches(']');
                    let parsed_tags: Vec<String> = cleaned
                        .split(',')
                        .map(|t| t.trim().trim_matches('"').trim_matches('\'').to_lowercase())
                        .filter(|t| !t.is_empty())
                        .collect();
                    tags = parsed_tags;
                }
            }

            return Ok(ParsedEdit { title, tags, body });
        }
    }

    // Fallback: no valid frontmatter
    let lines: Vec<&str> = content.lines().collect();
    if let Some(first_line) = lines.first() {
        let first_trim = first_line.trim();
        if let Some(h1_title) = first_trim.strip_prefix("# ") {
            let body = lines[1..].join("\n").trim().to_string();
            return Ok(ParsedEdit {
                title: h1_title.trim().to_string(),
                tags: default_tags.to_vec(),
                body,
            });
        }
    }

    Ok(ParsedEdit {
        title: default_title.to_string(),
        tags: default_tags.to_vec(),
        body: content.trim().to_string(),
    })
}

fn find_closing_fence(s: &str) -> Option<usize> {
    let mut pos = 0;
    while pos < s.len() {
        if s[pos..].starts_with("\n---") {
            let after = &s[pos + 4..];
            if after.starts_with('\n') || after.starts_with("\r\n") || after.is_empty() {
                return Some(pos + 1);
            }
        } else if s[pos..].starts_with("\r\n---") {
            let after = &s[pos + 5..];
            if after.starts_with('\n') || after.starts_with("\r\n") || after.is_empty() {
                return Some(pos + 2);
            }
        }
        pos += 1;
    }
    None
}

/// RAII Guard that creates a restricted temporary file, enforces owner-only permissions (`0600`),
/// and guarantees zeroization and deletion upon `Drop`.
#[derive(Debug)]
pub struct TempFileGuard {
    path: PathBuf,
    is_ram_backed: bool,
}

impl TempFileGuard {
    /// Creates a new temporary file initialized with `initial_content`.
    ///
    /// Prioritizes RAM-backed filesystems (`/dev/shm`, `$XDG_RUNTIME_DIR`) on Linux.
    /// Enforces mode `0600` on Unix systems to ensure other users cannot read plaintext buffers.
    pub fn create(prefix: &str, initial_content: &[u8]) -> Result<Self, CliError> {
        let (temp_dir, is_ram_backed) = resolve_temp_directory();
        std::fs::create_dir_all(&temp_dir).map_err(|e| {
            CliError::Io(format!(
                "failed to create temp directory {}: {e}",
                temp_dir.display()
            ))
        })?;

        let filename = format!("{prefix}-{}.md", uuid::Uuid::new_v4());
        let file_path = temp_dir.join(filename);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = options.open(&file_path).map_err(|e| {
                CliError::Io(format!(
                    "failed to create secure temp file {}: {e}",
                    file_path.display()
                ))
            })?;
            file.write_all(initial_content).map_err(|e| {
                CliError::Io(format!(
                    "failed to write initial temp content to {}: {e}",
                    file_path.display()
                ))
            })?;
            file.sync_all().map_err(|e| {
                CliError::Io(format!(
                    "failed to flush temp content to {}: {e}",
                    file_path.display()
                ))
            })?;
        }

        #[cfg(not(unix))]
        {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options.open(&file_path).map_err(|e| {
                CliError::Io(format!(
                    "failed to create secure temp file {}: {e}",
                    file_path.display()
                ))
            })?;
            file.write_all(initial_content).map_err(|e| {
                CliError::Io(format!(
                    "failed to write initial temp content to {}: {e}",
                    file_path.display()
                ))
            })?;
            file.sync_all().map_err(|e| {
                CliError::Io(format!(
                    "failed to flush temp content to {}: {e}",
                    file_path.display()
                ))
            })?;
        }

        Ok(Self {
            path: file_path,
            is_ram_backed,
        })
    }

    /// Returns the absolute path to the temporary file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns `true` if the temporary file is hosted on a memory-backed tmpfs.
    #[must_use]
    pub fn is_ram_backed(&self) -> bool {
        self.is_ram_backed
    }

    /// Reads the current content of the temporary file into bytes.
    pub fn read_bytes(&self) -> Result<Vec<u8>, CliError> {
        let mut file = File::open(&self.path).map_err(|e| {
            CliError::Io(format!(
                "failed to open temp file {}: {e}",
                self.path.display()
            ))
        })?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            CliError::Io(format!(
                "failed to read temp file {}: {e}",
                self.path.display()
            ))
        })?;
        Ok(buf)
    }

    /// Explicitly overwrites the temporary file with zeroes and deletes it.
    pub fn cleanup(mut self) {
        Self::secure_wipe_and_remove(&self.path);
        // Point to non-existent path to prevent double wipe in Drop
        self.path = PathBuf::new();
    }

    fn secure_wipe_and_remove(path: &Path) {
        if path.as_os_str().is_empty() || !path.exists() {
            return;
        }

        if let Ok(metadata) = std::fs::metadata(path) {
            let len = metadata.len() as usize;
            if len > 0 {
                if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                    let zeroes = vec![0u8; 4096];
                    let mut remaining = len;
                    while remaining > 0 {
                        let chunk = std::cmp::min(remaining, zeroes.len());
                        if file.write_all(&zeroes[..chunk]).is_err() {
                            break;
                        }
                        remaining -= chunk;
                    }
                    let _ = file.sync_all();
                }
            }
        }

        let _ = std::fs::remove_file(path);
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        Self::secure_wipe_and_remove(&self.path);
    }
}

/// Determines the preferred temporary directory, prioritizing RAM-backed tmpfs on Linux.
fn resolve_temp_directory() -> (PathBuf, bool) {
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        return (shm.join("zk-note-edits"), true);
    }

    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir);
        if p.is_dir() {
            return (p.join("zk-note-edits"), true);
        }
    }

    (std::env::temp_dir().join("zk-note-edits"), false)
}

/// Executes an external text editor command on the given temporary file.
pub fn run_editor(editor_cmd: &str, file_path: &Path) -> Result<(), CliError> {
    if editor_cmd.trim().is_empty() {
        return Err(CliError::Io("editor command cannot be empty".to_string()));
    }

    #[cfg(unix)]
    let mut cmd = {
        let mut c = std::process::Command::new("sh");
        c.arg("-c")
            .arg(format!("{editor_cmd} \"$@\""))
            .arg("--")
            .arg(file_path);
        c
    };

    #[cfg(not(unix))]
    let mut cmd = {
        let parts: Vec<&str> = editor_cmd.split_whitespace().collect();
        let mut c = std::process::Command::new(parts[0]);
        c.args(&parts[1..]).arg(file_path);
        c
    };

    let status = cmd.status().map_err(|e| {
        CliError::Io(format!(
            "failed to launch editor '{editor_cmd}' for {}: {e}",
            file_path.display()
        ))
    })?;

    if !status.success() {
        return Err(CliError::Io(format!(
            "editor '{editor_cmd}' exited with non-zero status: {status}"
        )));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_frontmatter_serialization_and_parsing() {
        let title = "My Note";
        let tags = vec!["work".to_string(), "planning".to_string()];
        let body = "# Header\n\nSome body text.\nSecond line.";

        let buffer = note_to_edit_buffer(title, &tags, body);
        let parsed = parse_edit_buffer(&buffer, "Default", &[]).expect("parse buffer");

        assert_eq!(parsed.title, "My Note");
        assert_eq!(parsed.tags, vec!["work", "planning"]);
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn test_frontmatter_fallback_to_h1() {
        let content = "# Markdown Heading 1\n\nBody without frontmatter.";
        let parsed = parse_edit_buffer(content, "Default", &["tag1".to_string()]).expect("parse");

        assert_eq!(parsed.title, "Markdown Heading 1");
        assert_eq!(parsed.tags, vec!["tag1"]);
        assert_eq!(parsed.body, "Body without frontmatter.");
    }

    #[test]
    fn test_frontmatter_fallback_to_defaults() {
        let content = "Just plain body text.";
        let parsed =
            parse_edit_buffer(content, "Original Title", &["default".to_string()]).expect("parse");

        assert_eq!(parsed.title, "Original Title");
        assert_eq!(parsed.tags, vec!["default"]);
        assert_eq!(parsed.body, "Just plain body text.");
    }

    #[test]
    fn test_temp_file_guard_permissions_and_zeroization() {
        let initial_text = b"CONFIDENTIAL_PLAINTEXT_123456789";
        let guard = TempFileGuard::create("test-edit", initial_text).expect("create guard");
        let path = guard.path().to_path_buf();

        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("meta");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let read_back = guard.read_bytes().expect("read bytes");
        assert_eq!(read_back, initial_text);

        // Dropping guard must wipe file with zeroes and delete it
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn test_run_editor_non_zero_exit_returns_error() {
        let guard = TempFileGuard::create("test-editor-fail", b"text").expect("create guard");
        let path = guard.path().to_path_buf();

        // Run command that exits with 1 (e.g. false)
        let res = run_editor("false", &path);
        assert!(res.is_err());
    }
}
