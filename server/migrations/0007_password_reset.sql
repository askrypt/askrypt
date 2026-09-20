-- Password reset: a mailed single-use link that sets a new password without
-- knowing the old one.
--
-- The same shape as `email_confirmations` (migration 0006) and a separate
-- table on purpose: the two links mean different things, expire on different
-- clocks, and one must never be spendable as the other.
CREATE TABLE password_resets (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- The expiry sweep runs on every send, so it must not be a table scan.
CREATE INDEX password_resets_expires_at ON password_resets(expires_at);
