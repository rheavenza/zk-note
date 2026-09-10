/**
 * Notes List Sidebar Component (ZK-065).
 *
 * Requirements:
 * - List decrypted notes from in-memory cache.
 * - Create new note button (+ New Note).
 * - Real-time filtering by title, body, or tag.
 * - Active note selection with visual feedback.
 */

import React, { useState, useMemo } from "react";
import { useNotes } from "../context/NotesContext.js";
import { PlaintextNoteDto } from "../worker/protocol.js";

export interface NotesListProps {
  className?: string;
  onSelectNote?: (note: PlaintextNoteDto) => void;
}

export const NotesList: React.FC<NotesListProps> = ({
  className,
  onSelectNote,
}) => {
  const { notes, selectedNoteId, selectNote, createNote, isLoading } = useNotes();
  const [filterQuery, setFilterQuery] = useState("");

  const filteredNotes = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return notes;

    return notes.filter((n) => {
      const titleMatch = n.title.toLowerCase().includes(q);
      const bodyMatch = n.body.toLowerCase().includes(q);
      const tagMatch = n.tags.some((t) => t.toLowerCase().includes(q));
      return titleMatch || bodyMatch || tagMatch;
    });
  }, [notes, filterQuery]);

  const handleCreateNew = async () => {
    try {
      const newNote = await createNote({
        title: "",
        body: "",
        tags: [],
      });
      onSelectNote?.(newNote);
    } catch {
      // Error handled by context
    }
  };

  const handleSelect = (note: PlaintextNoteDto) => {
    selectNote(note.id);
    onSelectNote?.(note);
  };

  return (
    <div
      className={className || "zk-notes-list"}
      style={sidebarContainerStyle}
      data-testid="notes-list"
    >
      {/* Sidebar Header */}
      <div style={sidebarHeaderStyle}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <h3 style={{ margin: 0, fontSize: "18px", fontWeight: 700, color: "#111827" }}>
            Notes
            <span style={countBadgeStyle}>{notes.length}</span>
          </h3>
          <button
            type="button"
            onClick={handleCreateNew}
            style={newNoteButtonStyle}
            className="zk-new-note-btn"
          >
            + New Note
          </button>
        </div>

        {/* Filter Input */}
        <input
          type="text"
          value={filterQuery}
          onChange={(e) => setFilterQuery(e.target.value)}
          placeholder="Filter notes..."
          style={searchInputStyle}
          className="zk-filter-input"
          aria-label="Filter notes"
        />
      </div>

      {/* Loading state */}
      {isLoading && (
        <div style={loadingStyle}>
          <span>Decrypting local notes...</span>
        </div>
      )}

      {/* Notes List Container */}
      <div style={listContainerStyle}>
        {!isLoading && filteredNotes.length === 0 && (
          <div style={emptyMessageStyle} className="zk-notes-empty">
            {filterQuery ? (
              <p>No notes match &ldquo;{filterQuery}&rdquo;</p>
            ) : (
              <div>
                <p style={{ margin: "0 0 8px 0" }}>No notes yet.</p>
                <button
                  type="button"
                  onClick={handleCreateNew}
                  style={emptyStateButtonStyle}
                >
                  Create your first note
                </button>
              </div>
            )}
          </div>
        )}

        {filteredNotes.map((note) => {
          const isSelected = note.id === selectedNoteId;
          const displayTitle = note.title.trim() || "Untitled Note";
          const snippet = note.body.trim().split("\n")[0] || "No content";
          const formattedDate = formatDate(note.updatedAt);

          return (
            <div
              key={note.id}
              onClick={() => handleSelect(note)}
              style={isSelected ? selectedItemStyle : itemStyle}
              className={`zk-note-item ${isSelected ? "selected" : ""}`}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  handleSelect(note);
                }
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <h4
                  style={{
                    margin: "0 0 4px 0",
                    fontSize: "15px",
                    fontWeight: isSelected ? 700 : 600,
                    color: isSelected ? "#1d4ed8" : "#111827",
                    fontStyle: note.title.trim() ? "normal" : "italic",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {displayTitle}
                </h4>
                <span style={dateStyle}>{formattedDate}</span>
              </div>

              <p style={snippetStyle}>{snippet}</p>

              {note.tags.length > 0 && (
                <div style={tagsRowStyle}>
                  {note.tags.slice(0, 3).map((tag) => (
                    <span key={tag} style={tagPillStyle}>
                      #{tag}
                    </span>
                  ))}
                  {note.tags.length > 3 && (
                    <span style={{ ...tagPillStyle, background: "none" }}>
                      +{note.tags.length - 3}
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

function formatDate(isoString: string): string {
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);

    if (diffMinutes < 1) return "Just now";
    if (diffMinutes < 60) return `${diffMinutes}m`;
    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) return `${diffHours}h`;

    return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

// Styles
const sidebarContainerStyle: React.CSSProperties = {
  width: "300px",
  minWidth: "260px",
  height: "100%",
  display: "flex",
  flexDirection: "column",
  borderRight: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
};

const sidebarHeaderStyle: React.CSSProperties = {
  padding: "16px",
  borderBottom: "1px solid #e5e7eb",
  backgroundColor: "#ffffff",
};

const countBadgeStyle: React.CSSProperties = {
  marginLeft: "8px",
  fontSize: "12px",
  fontWeight: 600,
  padding: "2px 6px",
  borderRadius: "10px",
  backgroundColor: "#f3f4f6",
  color: "#6b7280",
};

const newNoteButtonStyle: React.CSSProperties = {
  padding: "6px 12px",
  backgroundColor: "#2563eb",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "13px",
  fontWeight: 600,
  cursor: "pointer",
};

const searchInputStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  borderRadius: "6px",
  border: "1px solid #d1d5db",
  fontSize: "13px",
  outline: "none",
  boxSizing: "border-box",
  backgroundColor: "#f9fafb",
};

const loadingStyle: React.CSSProperties = {
  padding: "16px",
  textAlign: "center",
  color: "#6b7280",
  fontSize: "13px",
};

const listContainerStyle: React.CSSProperties = {
  flex: 1,
  overflowY: "auto",
};

const emptyMessageStyle: React.CSSProperties = {
  padding: "32px 16px",
  textAlign: "center",
  color: "#6b7280",
  fontSize: "14px",
};

const emptyStateButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#2563eb",
  fontWeight: 600,
  cursor: "pointer",
  fontSize: "13px",
  textDecoration: "underline",
};

const itemStyle: React.CSSProperties = {
  padding: "12px 16px",
  borderBottom: "1px solid #f3f4f6",
  cursor: "pointer",
  transition: "background-color 0.1s",
  backgroundColor: "#ffffff",
};

const selectedItemStyle: React.CSSProperties = {
  ...itemStyle,
  backgroundColor: "#eff6ff",
  borderLeft: "3px solid #2563eb",
};

const dateStyle: React.CSSProperties = {
  fontSize: "11px",
  color: "#9ca3af",
  marginLeft: "8px",
  whiteSpace: "nowrap",
};

const snippetStyle: React.CSSProperties = {
  margin: "0 0 6px 0",
  fontSize: "13px",
  color: "#6b7280",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
  lineHeight: 1.4,
};

const tagsRowStyle: React.CSSProperties = {
  display: "flex",
  gap: "4px",
  flexWrap: "wrap",
};

const tagPillStyle: React.CSSProperties = {
  fontSize: "10px",
  fontWeight: 500,
  padding: "1px 5px",
  borderRadius: "4px",
  backgroundColor: "#f3f4f6",
  color: "#4b5563",
};
