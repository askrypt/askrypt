-- Email confirmation: a password account cannot sign in until its owner has
-- followed the link mailed at registration.

-- NULL until confirmed. Accounts that predate this migration are treated as
-- confirmed — nobody is locked out by the upgrade — and so are Google
-- accounts, whose address Google has already verified.
ALTER TABLE accounts ADD COLUMN email_confirmed_at TEXT;
UPDATE accounts SET email_confirmed_at = created_at;

-- The one pending confirmation link per account. Only the SHA-256 of the
-- token is stored, so a leaked database confirms nothing. A resend replaces
-- the row, which is what makes every older link stop working.
CREATE TABLE email_confirmations (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- The expiry sweep runs on every send, so it must not be a table scan.
CREATE INDEX email_confirmations_expires_at ON email_confirmations(expires_at);
