-- Phase 4: vault file metadata. The bytes live in the blob store (local
-- disk); this table is the source of truth for listings and ETags.

CREATE TABLE vaults (
    id         TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- User-visible file name; unique per account like files in a directory.
    name       TEXT NOT NULL,
    size       INTEGER NOT NULL,
    -- Content hash used as the ETag for optimistic concurrency.
    etag       TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, name)
);
