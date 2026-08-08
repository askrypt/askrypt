-- Vault version history: the bytes a save replaced, kept for a few
-- generations so an overwrite from any device stays recoverable.
--
-- The archived bytes live in their own blob directory keyed by the version
-- id (a *sibling* of the live vault directory, never mixed in with it); this
-- table is the index over them. Rows cascade twice: with the vault they
-- belong to, and with the account.

CREATE TABLE vault_versions (
    id          TEXT NOT NULL,
    vault_id    TEXT NOT NULL,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- The vault's name when these bytes were archived; a later rename does
    -- not rewrite history.
    name        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    -- Content hash of the archived bytes, i.e. the ETag this version was
    -- served under while it was the live vault.
    etag        TEXT NOT NULL,
    -- When these bytes were written as the live vault.
    updated_at  TEXT NOT NULL,
    -- When they were superseded and archived.
    archived_at TEXT NOT NULL,
    -- The archived bytes' own write stamp, copied from the vault row like
    -- `name` and `etag`: history says which device wrote each generation.
    host        TEXT,
    saved_at    TEXT,
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, vault_id) REFERENCES vaults(account_id, id) ON DELETE CASCADE
);

-- The two orders the retention rules read in: newest-first per vault (the
-- 5-generation cap and the listing) and oldest-first per account (the
-- quota trim).
CREATE INDEX vault_versions_by_vault ON vault_versions (account_id, vault_id, archived_at);
CREATE INDEX vault_versions_by_account ON vault_versions (account_id, archived_at);
