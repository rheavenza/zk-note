/**
 * Search Modal / Command Palette Component (ZK-066).
 *
 * Fast, keyboard-navigable local search modal.
 * Queries only in-memory worker index (no server transmission).
 */

import React, { useState, useEffect, useRef } from "react";
import { useSearch } from "../context/SearchContext.js";
import { useNotes } from "../context/NotesContext.js";
import { SearchResultDto } from "../worker/protocol.js";

export interface SearchModalProps {
  className?: string;
  isOpen?: boolean;
  onClose?: () => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({
  className,
  isOpen: propIsOpen,
  onClose: propOnClose,
}) => {
  const { query, setQuery, results, isSearching, isOpen: ctxIsOpen, closeSearch } = useSearch();
  const { selectNote } = useNotes();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const effectiveIsOpen = propIsOpen !== undefined ? propIsOpen : ctxIsOpen;
  const effectiveClose = propOnClose || closeSearch;

  // Auto-focus input when opened
  useEffect(() => {
    if (effectiveIsOpen) {
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [effectiveIsOpen]);

  // Keep selected index within bounds
  useEffect(() => {
    if (selectedIndex >= results.length) {
      setSelectedIndex(Math.max(0, results.length - 1));
    }
  }, [results, selectedIndex]);

  const handleSelect = (result: SearchResultDto) => {
    selectNote(result.noteId);
    effectiveClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      effectiveClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, results.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + results.length) % Math.max(1, results.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const selected = results[selectedIndex];
      if (selected) {
        handleSelect(selected);
      }
    }
  };

  if (!effectiveIsOpen) return null;

  return (
    <div
      style={backdropStyle}
      onClick={closeSearch}
      className="zk-search-backdrop"
      data-testid="search-modal-backdrop"
    >
      <div
        style={modalContainerStyle}
        onClick={(e) => e.stopPropagation()}
        className={className || "zk-search-modal"}
        data-testid="search-modal"
      >
        {/* Search Input Bar */}
        <div style={inputContainerStyle}>
          <span style={{ fontSize: "16px", marginRight: "10px", color: "#9ca3af" }}>
            🔍
          </span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search notes by title, body, or tags..."
            style={modalInputStyle}
            className="zk-modal-search-input"
            autoComplete="off"
            spellCheck={false}
            aria-label="Quick search notes"
          />
          {isSearching && (
            <span style={{ fontSize: "12px", color: "#6b7280" }}>Searching...</span>
          )}
          <kbd style={escBadgeStyle} onClick={closeSearch}>
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div style={resultsListStyle}>
          {query.trim() && !isSearching && results.length === 0 && (
            <div style={emptyResultsStyle}>
              <p style={{ margin: "0 0 4px 0", color: "#4b5563" }}>
                No notes found matching &ldquo;{query}&rdquo;
              </p>
              <span style={{ fontSize: "12px", color: "#9ca3af" }}>
                Searched in-memory client index
              </span>
            </div>
          )}

          {results.map((result, idx) => {
            const isSelected = idx === selectedIndex;
            return (
              <div
                key={result.noteId}
                onClick={() => handleSelect(result)}
                onMouseEnter={() => setSelectedIndex(idx)}
                style={isSelected ? selectedResultItemStyle : resultItemStyle}
                className={`zk-search-result-item ${isSelected ? "selected" : ""}`}
                role="option"
                aria-selected={isSelected}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <h4
                    style={{
                      margin: "0 0 4px 0",
                      fontSize: "14px",
                      fontWeight: 600,
                      color: isSelected ? "#1d4ed8" : "#111827",
                    }}
                  >
                    {result.matchedTitle || "Untitled Note"}
                  </h4>
                  <span style={scoreBadgeStyle}>Score: {result.score}</span>
                </div>
                {result.snippet && (
                  <p style={snippetStyle}>
                    &hellip;{result.snippet}&hellip;
                  </p>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer info */}
        <div style={footerStyle}>
          <span style={{ color: "#059669", fontWeight: 600 }}>🔒 Zero-Knowledge Search</span>
          <span>Queries execute 100% locally in Web Worker</span>
        </div>
      </div>
    </div>
  );
};

// Styles
const backdropStyle: React.CSSProperties = {
  position: "fixed",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: "rgba(0, 0, 0, 0.4)",
  backdropFilter: "blur(2px)",
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-start",
  paddingTop: "12vh",
  zIndex: 100,
};

const modalContainerStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: "560px",
  backgroundColor: "#ffffff",
  borderRadius: "12px",
  boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -6px rgba(0, 0, 0, 0.1)",
  overflow: "hidden",
  display: "flex",
  flexDirection: "column",
  maxHeight: "70vh",
};

const inputContainerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  padding: "14px 18px",
  borderBottom: "1px solid #e5e7eb",
};

const modalInputStyle: React.CSSProperties = {
  flex: 1,
  border: "none",
  outline: "none",
  fontSize: "16px",
  color: "#111827",
  backgroundColor: "transparent",
};

const escBadgeStyle: React.CSSProperties = {
  border: "1px solid #d1d5db",
  borderRadius: "4px",
  backgroundColor: "#f3f4f6",
  color: "#6b7280",
  fontSize: "10px",
  fontWeight: 600,
  padding: "2px 6px",
  cursor: "pointer",
  marginLeft: "8px",
};

const resultsListStyle: React.CSSProperties = {
  flex: 1,
  overflowY: "auto",
  padding: "8px",
  maxHeight: "360px",
};

const emptyResultsStyle: React.CSSProperties = {
  padding: "32px 16px",
  textAlign: "center",
};

const resultItemStyle: React.CSSProperties = {
  padding: "10px 14px",
  borderRadius: "8px",
  cursor: "pointer",
  transition: "background-color 0.1s",
};

const selectedResultItemStyle: React.CSSProperties = {
  ...resultItemStyle,
  backgroundColor: "#eff6ff",
};

const scoreBadgeStyle: React.CSSProperties = {
  fontSize: "10px",
  color: "#6b7280",
  backgroundColor: "#f3f4f6",
  padding: "1px 5px",
  borderRadius: "4px",
};

const snippetStyle: React.CSSProperties = {
  margin: 0,
  fontSize: "12px",
  color: "#4b5563",
  lineHeight: 1.4,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const footerStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  padding: "10px 16px",
  borderTop: "1px solid #f3f4f6",
  backgroundColor: "#f9fafb",
  fontSize: "11px",
  color: "#6b7280",
};
