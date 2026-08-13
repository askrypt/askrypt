-- Phase 12: server settings — runtime state an administrator edits, as
-- opposed to the ASKRYPT_* environment read once at startup.
-- Timestamps as RFC 3339 TEXT, matching the other tables.
--
-- Deliberately seeded with nothing. An absent key means the built-in default
-- (registration is open), so an existing database keeps behaving exactly as
-- it did and there is no seed row for the two backends to disagree about.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
