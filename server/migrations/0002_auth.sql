-- Phase 2: accounts and sessions.
-- Uuids are stored as hyphenated TEXT, timestamps as RFC 3339 TEXT.

CREATE TABLE accounts (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    -- NULL for Google-created accounts that have not set a password yet.
    password_hash TEXT,
    -- Google account id (`sub` claim) when Google sign-in is linked.
    google_sub    TEXT UNIQUE,
    created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label      TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX sessions_account_id ON sessions(account_id);
