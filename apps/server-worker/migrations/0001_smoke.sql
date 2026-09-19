-- Phase 0 compatibility spike: smoke table for validating D1 parameterized queries
CREATE TABLE IF NOT EXISTS worker_smoke (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
