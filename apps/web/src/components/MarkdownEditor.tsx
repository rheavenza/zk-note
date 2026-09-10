/**
 * Markdown Source Editor Component (ZK-065).
 *
 * Requirements:
 * - Markdown source editor with syntax toolbar.
 * - View modes: Edit (Markdown source), Preview (rendered HTML), and Split view.
 * - Tag management (add/remove tags).
 * - Real-time save status indicator ("Saved", "Saving...", "Unsaved changes").
 * - Offline-first operation.
 */

import React, { useState, useRef, useCallback } from "react";
import { useNotes } from "../context/NotesContext.js";
import { useConflict } from "../context/ConflictContext.js";
import { renderMarkdown } from "../utils/markdown.js";

export type EditorViewMode = "edit" | "preview" | "split";

export interface MarkdownEditorProps {
  className?: string;
  onDelete?: () => void;
}

export const MarkdownEditor: React.FC<MarkdownEditorProps> = ({
  className,
  onDelete,
}) => {
  const {
    selectedNote,
    updateNote,
    saveNoteNow,
    deleteNote,
    saveStatus,
  } = useNotes();
  const { activeConflicts, openModal } = useConflict();

  const [viewMode, setViewMode] = useState<EditorViewMode>("split");
  const [tagInput, setTagInput] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const noteId = selectedNote?.id;

  const handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!noteId) return;
    updateNote(noteId, { title: e.target.value });
  };

  const handleBodyChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    if (!noteId) return;
    updateNote(noteId, { body: e.target.value });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Ctrl+S / Cmd+S manual save shortcut
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      if (noteId) {
        saveNoteNow(noteId).catch(() => {});
      }
      return;
    }

    // Tab key indent support
    if (e.key === "Tab") {
      e.preventDefault();
      const textarea = textareaRef.current;
      if (!textarea || !noteId || !selectedNote) return;

      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const currentBody = selectedNote.body;
      const newBody = currentBody.substring(0, start) + "  " + currentBody.substring(end);

      updateNote(noteId, { body: newBody });

      // Restore cursor position after state update
      setTimeout(() => {
        textarea.selectionStart = textarea.selectionEnd = start + 2;
      }, 0);
    }
  };

  const insertFormatting = useCallback(
    (before: string, after: string = "", defaultText: string = "") => {
      const textarea = textareaRef.current;
      if (!textarea || !noteId || !selectedNote) return;

      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const currentBody = selectedNote.body;
      const selectedText = currentBody.substring(start, end) || defaultText;

      const newBody =
        currentBody.substring(0, start) +
        before +
        selectedText +
        after +
        currentBody.substring(end);

      updateNote(noteId, { body: newBody });

      setTimeout(() => {
        textarea.focus();
        textarea.setSelectionRange(
          start + before.length,
          start + before.length + selectedText.length
        );
      }, 0);
    },
    [noteId, selectedNote, updateNote]
  );

  const handleAddTag = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!noteId || !selectedNote) return;
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      const trimmed = tagInput.trim().replace(/^#/, "");
      if (trimmed && !selectedNote.tags.includes(trimmed)) {
        updateNote(noteId, { tags: [...selectedNote.tags, trimmed] });
      }
      setTagInput("");
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    if (!noteId || !selectedNote) return;
    updateNote(noteId, {
      tags: selectedNote.tags.filter((t) => t !== tagToRemove),
    });
  };

  const handleDelete = async () => {
    if (!noteId) return;
    setShowDeleteConfirm(false);
    await deleteNote(noteId);
    onDelete?.();
  };

  if (!selectedNote) {
    return (
      <div style={emptyContainerStyle} className="zk-editor-empty">
        <span style={{ fontSize: "40px", marginBottom: "16px" }}>📝</span>
        <h3 style={{ margin: "0 0 8px 0", color: "#374151" }}>No Note Selected</h3>
        <p style={{ margin: 0, color: "#6b7280", fontSize: "14px" }}>
          Choose a note from the sidebar or click "+ New Note" to create one.
        </p>
      </div>
    );
  }

  const activeConflictForNote = activeConflicts.find((c) => c.object_id === noteId);
  const renderedHtml = renderMarkdown(selectedNote.body);

  return (
    <div
      className={className || "zk-markdown-editor"}
      style={editorContainerStyle}
      data-testid="markdown-editor"
    >
      {/* Active Conflict Warning Banner */}
      {activeConflictForNote && (
        <div
          style={conflictBannerStyle}
          className="zk-note-conflict-banner"
          data-testid="note-conflict-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "16px" }}>⚠️</span>
            <span>
              <strong>Sync Conflict:</strong> This note has conflicting local and remote edits.
            </span>
          </div>
          <button
            type="button"
            onClick={() => openModal(activeConflictForNote.conflict_id)}
            style={resolveBannerButtonStyle}
            className="zk-resolve-conflict-banner-button"
            data-testid="resolve-conflict-banner-button"
          >
            Resolve Conflict
          </button>
        </div>
      )}

      {/* Top Header: Title and Save status */}
      <div style={topBarStyle}>
        <input
          type="text"
          value={selectedNote.title}
          onChange={handleTitleChange}
          placeholder="Note title..."
          style={titleInputStyle}
          className="zk-note-title-input"
          aria-label="Note title"
        />

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          {/* Autosave Status Badge */}
          <span style={getSaveStatusStyle(saveStatus)} className="zk-save-status">
            {saveStatus === "saving" && "⏳ Saving..."}
            {saveStatus === "saved" && "✓ Saved"}
            {saveStatus === "unsaved" && "● Unsaved"}
            {saveStatus === "error" && "⚠ Save failed"}
          </span>

          {/* Delete Button */}
          <button
            type="button"
            onClick={() => setShowDeleteConfirm(true)}
            style={deleteButtonStyle}
            className="zk-delete-note-btn"
            title="Delete this note"
          >
            🗑
          </button>
        </div>
      </div>

      {/* Tags Bar */}
      <div style={tagsContainerStyle}>
        {selectedNote.tags.map((tag) => (
          <span key={tag} style={tagBadgeStyle} className="zk-tag-badge">
            #{tag}
            <button
              type="button"
              onClick={() => handleRemoveTag(tag)}
              style={removeTagButtonStyle}
              aria-label={`Remove tag ${tag}`}
            >
              ×
            </button>
          </span>
        ))}
        <input
          type="text"
          value={tagInput}
          onChange={(e) => setTagInput(e.target.value)}
          onKeyDown={handleAddTag}
          placeholder="+ Add tag (press Enter)"
          style={tagInputStyle}
          className="zk-tag-input"
        />
      </div>

      {/* Formatting Toolbar */}
      <div style={toolbarStyle}>
        <div style={{ display: "flex", gap: "4px" }}>
          <button
            type="button"
            onClick={() => insertFormatting("**", "**", "bold text")}
            style={toolbarButtonStyle}
            title="Bold (**text**)"
          >
            <strong>B</strong>
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("*", "*", "italic text")}
            style={toolbarButtonStyle}
            title="Italic (*text*)"
          >
            <em>I</em>
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("## ", "", "Heading")}
            style={toolbarButtonStyle}
            title="Heading 2"
          >
            H2
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("`", "`", "code")}
            style={toolbarButtonStyle}
            title="Inline Code (`code`)"
          >
            &lt;/&gt;
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("```\n", "\n```", "code block")}
            style={toolbarButtonStyle}
            title="Code Block (```)"
          >
            [ ]
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("> ", "", "quote")}
            style={toolbarButtonStyle}
            title="Blockquote (> quote)"
          >
            &ldquo;
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("- ", "", "list item")}
            style={toolbarButtonStyle}
            title="Bulleted list (- item)"
          >
            • List
          </button>
          <button
            type="button"
            onClick={() => insertFormatting("[", "](https://)", "link text")}
            style={toolbarButtonStyle}
            title="Link [text](url)"
          >
            🔗
          </button>
        </div>

        {/* View Mode Switcher */}
        <div style={modeSwitcherStyle}>
          <button
            type="button"
            onClick={() => setViewMode("edit")}
            style={viewMode === "edit" ? activeModeButtonStyle : modeButtonStyle}
          >
            Source
          </button>
          <button
            type="button"
            onClick={() => setViewMode("split")}
            style={viewMode === "split" ? activeModeButtonStyle : modeButtonStyle}
          >
            Split
          </button>
          <button
            type="button"
            onClick={() => setViewMode("preview")}
            style={viewMode === "preview" ? activeModeButtonStyle : modeButtonStyle}
          >
            Preview
          </button>
        </div>
      </div>

      {/* Editor Main Content Area */}
      <div style={contentAreaStyle}>
        {(viewMode === "edit" || viewMode === "split") && (
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              borderRight: viewMode === "split" ? "1px solid #e5e7eb" : "none",
            }}
          >
            <textarea
              ref={textareaRef}
              value={selectedNote.body}
              onChange={handleBodyChange}
              onKeyDown={handleKeyDown}
              placeholder="Write Markdown note content here..."
              style={textareaStyle}
              spellCheck={false}
              className="zk-markdown-textarea"
              aria-label="Markdown source content"
            />
          </div>
        )}

        {(viewMode === "preview" || viewMode === "split") && (
          <div
            style={previewContainerStyle}
            className="zk-markdown-preview"
            data-testid="markdown-preview"
          >
            {renderedHtml ? (
              <div
                dangerouslySetInnerHTML={{ __html: renderedHtml }}
                style={previewHtmlContentStyle}
              />
            ) : (
              <p style={{ color: "#9ca3af", fontStyle: "italic" }}>
                Markdown preview will appear here...
              </p>
            )}
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div style={modalOverlayStyle}>
          <div style={modalCardStyle}>
            <h4 style={{ margin: "0 0 8px 0", color: "#111827" }}>Delete Note?</h4>
            <p style={{ margin: "0 0 16px 0", fontSize: "14px", color: "#4b5563" }}>
              Are you sure you want to delete this encrypted note? A revisioned tombstone
              will be created.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button
                type="button"
                onClick={() => setShowDeleteConfirm(false)}
                style={secondaryModalButtonStyle}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDelete}
                style={dangerModalButtonStyle}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Styles
const editorContainerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  height: "100%",
  backgroundColor: "#ffffff",
  position: "relative",
};

const topBarStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "16px 20px",
  borderBottom: "1px solid #f3f4f6",
  gap: "16px",
};

const titleInputStyle: React.CSSProperties = {
  flex: 1,
  fontSize: "20px",
  fontWeight: 600,
  color: "#111827",
  border: "none",
  outline: "none",
  padding: "4px 0",
};

const tagsContainerStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "6px",
  padding: "8px 20px",
  borderBottom: "1px solid #f3f4f6",
};

const tagBadgeStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "3px 8px",
  backgroundColor: "#eff6ff",
  color: "#1d4ed8",
  borderRadius: "12px",
  fontSize: "12px",
  fontWeight: 500,
};

const removeTagButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#1d4ed8",
  marginLeft: "4px",
  cursor: "pointer",
  fontSize: "13px",
  padding: 0,
};

const tagInputStyle: React.CSSProperties = {
  border: "none",
  outline: "none",
  fontSize: "12px",
  color: "#4b5563",
  padding: "4px 8px",
  minWidth: "140px",
};

const toolbarStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "6px 16px",
  borderBottom: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
};

const toolbarButtonStyle: React.CSSProperties = {
  padding: "4px 8px",
  border: "1px solid #e5e7eb",
  backgroundColor: "#ffffff",
  borderRadius: "4px",
  fontSize: "12px",
  color: "#374151",
  cursor: "pointer",
};

const modeSwitcherStyle: React.CSSProperties = {
  display: "flex",
  backgroundColor: "#e5e7eb",
  borderRadius: "6px",
  padding: "2px",
};

const modeButtonStyle: React.CSSProperties = {
  border: "none",
  backgroundColor: "transparent",
  padding: "4px 10px",
  fontSize: "12px",
  color: "#4b5563",
  borderRadius: "4px",
  cursor: "pointer",
};

const activeModeButtonStyle: React.CSSProperties = {
  ...modeButtonStyle,
  backgroundColor: "#ffffff",
  color: "#111827",
  fontWeight: 600,
  boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
};

const contentAreaStyle: React.CSSProperties = {
  flex: 1,
  display: "flex",
  overflow: "hidden",
};

const textareaStyle: React.CSSProperties = {
  flex: 1,
  width: "100%",
  padding: "20px",
  border: "none",
  outline: "none",
  resize: "none",
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  fontSize: "14px",
  lineHeight: 1.6,
  color: "#1f2937",
  boxSizing: "border-box",
};

const previewContainerStyle: React.CSSProperties = {
  flex: 1,
  padding: "20px",
  overflowY: "auto",
  boxSizing: "border-box",
};

const previewHtmlContentStyle: React.CSSProperties = {
  fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  lineHeight: 1.6,
  color: "#1f2937",
};

const emptyContainerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  height: "100%",
  padding: "32px",
  textAlign: "center",
};

const deleteButtonStyle: React.CSSProperties = {
  background: "none",
  border: "1px solid #e5e7eb",
  borderRadius: "6px",
  padding: "6px 10px",
  cursor: "pointer",
  color: "#ef4444",
  fontSize: "14px",
};

function getSaveStatusStyle(status: string): React.CSSProperties {
  const base: React.CSSProperties = {
    fontSize: "12px",
    fontWeight: 500,
    padding: "2px 8px",
    borderRadius: "10px",
  };
  switch (status) {
    case "saved":
      return { ...base, color: "#15803d", backgroundColor: "#f0fdf4" };
    case "saving":
      return { ...base, color: "#a16207", backgroundColor: "#fefce8" };
    case "unsaved":
      return { ...base, color: "#6b7280", backgroundColor: "#f3f4f6" };
    case "error":
      return { ...base, color: "#b91c1c", backgroundColor: "#fef2f2" };
    default:
      return base;
  }
}

const modalOverlayStyle: React.CSSProperties = {
  position: "absolute",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: "rgba(0, 0, 0, 0.4)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 10,
};

const modalCardStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  borderRadius: "8px",
  padding: "20px",
  width: "320px",
  boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1)",
};

const secondaryModalButtonStyle: React.CSSProperties = {
  padding: "6px 12px",
  borderRadius: "6px",
  border: "1px solid #d1d5db",
  backgroundColor: "#ffffff",
  cursor: "pointer",
  fontSize: "13px",
};

const dangerModalButtonStyle: React.CSSProperties = {
  padding: "6px 12px",
  borderRadius: "6px",
  border: "none",
  backgroundColor: "#dc2626",
  color: "#ffffff",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: 600,
};

const conflictBannerStyle: React.CSSProperties = {
  backgroundColor: "#fff7ed",
  borderBottom: "1px solid #fed7aa",
  padding: "8px 16px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  fontSize: "13px",
  color: "#9a3412",
};

const resolveBannerButtonStyle: React.CSSProperties = {
  padding: "4px 10px",
  backgroundColor: "#c2410c",
  color: "#ffffff",
  border: "none",
  borderRadius: "4px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

