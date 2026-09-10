/**
 * Search Bar Component (ZK-066).
 *
 * In-memory local search bar with keyboard shortcut hint (⌘K / Ctrl+K).
 * Triggers full-text search directly against local Web Worker.
 */

import React from "react";
import { useSearch } from "../context/SearchContext.js";

export interface SearchBarProps {
  className?: string;
  style?: React.CSSProperties;
}

export const SearchBar: React.FC<SearchBarProps> = ({ className, style }) => {
  const { query, setQuery, openSearch, clearSearch, isSearching } = useSearch();

  const isMac =
    typeof navigator !== "undefined" &&
    /Mac|iPod|iPhone|iPad/.test(navigator.userAgent);

  return (
    <div
      className={className || "zk-search-bar"}
      style={{ ...containerStyle, ...style }}
      data-testid="search-bar"
    >
      <span style={searchIconStyle} onClick={openSearch}>
        🔍
      </span>

      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onFocus={openSearch}
        placeholder="Search notes..."
        style={inputStyle}
        className="zk-search-input"
        autoComplete="off"
        spellCheck={false}
        aria-label="Search notes"
      />

      {isSearching && <span style={spinnerStyle}>⏳</span>}

      {query && (
        <button
          type="button"
          onClick={clearSearch}
          style={clearButtonStyle}
          aria-label="Clear search"
        >
          ×
        </button>
      )}

      <button
        type="button"
        onClick={openSearch}
        style={shortcutBadgeStyle}
        title="Quick search shortcut"
      >
        {isMac ? "⌘K" : "Ctrl+K"}
      </button>
    </div>
  );
};

const containerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  position: "relative",
  width: "280px",
  backgroundColor: "#f3f4f6",
  borderRadius: "8px",
  padding: "4px 8px",
  border: "1px solid #e5e7eb",
};

const searchIconStyle: React.CSSProperties = {
  fontSize: "13px",
  marginRight: "6px",
  color: "#9ca3af",
  cursor: "pointer",
};

const inputStyle: React.CSSProperties = {
  flex: 1,
  border: "none",
  backgroundColor: "transparent",
  outline: "none",
  fontSize: "13px",
  color: "#1f2937",
};

const spinnerStyle: React.CSSProperties = {
  fontSize: "12px",
  marginRight: "6px",
};

const clearButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#9ca3af",
  cursor: "pointer",
  fontSize: "15px",
  padding: "0 4px",
  marginRight: "4px",
};

const shortcutBadgeStyle: React.CSSProperties = {
  border: "1px solid #d1d5db",
  borderRadius: "4px",
  backgroundColor: "#ffffff",
  color: "#6b7280",
  fontSize: "10px",
  fontWeight: 600,
  padding: "2px 5px",
  cursor: "pointer",
};
