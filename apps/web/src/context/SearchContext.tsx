/**
 * Search Context and Local Search State Machine (ZK-066).
 *
 * Requirements:
 * - In-memory local search executing in Web Worker.
 * - No server queries: search terms and results never leave the browser (SEC-001).
 * - Vault lock immediately scrubs query, results, and active search state (SEC-009).
 */

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
} from "react";
import { useVault } from "./VaultContext.js";
import { SearchResultDto } from "../worker/protocol.js";

export interface SearchContextType {
  query: string;
  results: SearchResultDto[];
  isSearching: boolean;
  isOpen: boolean;
  setQuery: (query: string) => void;
  openSearch: () => void;
  closeSearch: () => void;
  clearSearch: () => void;
  searchNow: (query: string) => Promise<SearchResultDto[]>;
}

const SearchContext = createContext<SearchContextType | null>(null);

export interface SearchProviderProps {
  children: React.ReactNode;
}

export const SearchProvider: React.FC<SearchProviderProps> = ({ children }) => {
  const vault = useVault();
  const [query, setQueryState] = useState("");
  const [results, setResults] = useState<SearchResultDto[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  const debounceTimerRef = useRef<NodeJS.Timeout | number | null>(null);

  const clearSearch = useCallback(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    setQueryState("");
    setResults([]);
    setIsSearching(false);
  }, []);

  // SEC-001 / SEC-009: When vault is locked, immediately wipe all search plaintext state
  useEffect(() => {
    if (vault.vaultState !== "UNLOCKED") {
      clearSearch();
      setIsOpen(false);
    }
  }, [vault, clearSearch]);

  const searchNow = useCallback(
    async (q: string): Promise<SearchResultDto[]> => {
      const trimmed = q.trim();
      if (!trimmed || vault.vaultState !== "UNLOCKED") {
        setResults([]);
        setIsSearching(false);
        return [];
      }

      setIsSearching(true);
      try {
        const searchResults = await vault.client.search(trimmed);
        setResults(searchResults);
        return searchResults;
      } catch (err) {
        // Vault may be locked or worker error
        setResults([]);
        return [];
      } finally {
        setIsSearching(false);
      }
    },
    [vault]
  );

  const setQuery = useCallback(
    (newQuery: string) => {
      setQueryState(newQuery);

      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }

      if (!newQuery.trim()) {
        setResults([]);
        setIsSearching(false);
        return;
      }

      setIsSearching(true);
      debounceTimerRef.current = setTimeout(() => {
        searchNow(newQuery);
      }, 150);
    },
    [searchNow]
  );

  const openSearch = useCallback(() => {
    if (vault.vaultState === "UNLOCKED") {
      setIsOpen(true);
    }
  }, [vault]);

  const closeSearch = useCallback(() => {
    setIsOpen(false);
  }, []);

  // Global keyboard shortcut: Cmd+K / Ctrl+K opens quick-search modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (vault.vaultState === "UNLOCKED") {
          setIsOpen((prev) => !prev);
        }
      } else if (e.key === "Escape" && isOpen) {
        e.preventDefault();
        closeSearch();
      }
    };

    if (typeof window !== "undefined") {
      window.addEventListener("keydown", handleKeyDown);
      return () => window.removeEventListener("keydown", handleKeyDown);
    }
    return undefined;
  }, [vault, isOpen, closeSearch]);

  const value: SearchContextType = {
    query,
    results,
    isSearching,
    isOpen,
    setQuery,
    openSearch,
    closeSearch,
    clearSearch,
    searchNow,
  };

  return <SearchContext.Provider value={value}>{children}</SearchContext.Provider>;
};

export function useSearch(): SearchContextType {
  const ctx = useContext(SearchContext);
  if (!ctx) {
    return {
      query: "",
      results: [],
      isSearching: false,
      isOpen: false,
      setQuery: () => {},
      openSearch: () => {},
      closeSearch: () => {},
      clearSearch: () => {},
      searchNow: async () => [],
    };
  }
  return ctx;
}
