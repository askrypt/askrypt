-- Phase 2: accounts and sessions. Phase 8 added roles and the ban stamp.
-- Uuids are stored as hyphenated TEXT, timestamps as RFC 3339 TEXT.

CREATE TABLE accounts (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    -- NULL for Google-created accounts that have not set a password yet.
    password_hash TEXT,
    -- Google account id (`sub` claim) when Google sign-in is linked.
    google_sub    TEXT UNIQUE,
    created_at    TEXT NOT NULL,
    -- Set when an administrator locks the account out: logins are refused
    -- and live sessions stop resolving. The account's vaults are untouched,
    -- so an unban restores access to them unchanged.
    banned_at     TEXT
);

-- The role vocabulary. ADMIN is embedded in the migration rather than
-- granted at runtime, so its id is the same in every deployment and code
-- may refer to it by name without first having to create it.
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

INSERT INTO roles (id, name, description) VALUES
    ('a0000000-0000-4000-8000-000000000001', 'ADMIN',
     'Full administrative access to the user list.');

CREATE TABLE account_roles (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (account_id, role_id)
);

-- Answering "who holds ADMIN?" is on the path of every page render, and the
-- primary key indexes the other direction only.
CREATE INDEX account_roles_by_role ON account_roles(role_id);

CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label      TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX sessions_account_id ON sessions(account_id);
