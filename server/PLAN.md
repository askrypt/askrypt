# Askrypt Server — Implementation Plan

Server application living in this repo under `server/`, implemented in **Rust**.
It provides user accounts and **cloud storage of vault files**. This document
lists the *steps* to build it — not the implementation.

**Scope rule — the server is a dumb encrypted-blob store.** It never sees
security questions, answers, keys, or vault contents; it stores and serves
`*.askrypt` files as opaque bytes. All crypto stays in the clients
(`core/` desktop, `app/` mobile). A compromise of the server never exposes
plaintext — only encrypted vaults and account metadata.

**Client-access rule — native apps are first-class API clients.** The desktop
app (`src/`) and mobile app (`app/`) must be able to log in with the same
account credentials as the website and manage their vaults *as files*
(upload / download / list / rename / delete) through the same `/api/v1` API.
Consequences for the API design:

- Auth must work headlessly: plain JSON login returning a bearer token — no
  browser, cookies, or CSRF dance required for native clients.
- Long-lived per-device sessions (refresh/re-login story) so apps don't force
  a password prompt on every sync; devices show up in the profile's session
  list and can be revoked there.
- Google sign-in stays native-friendly: apps open the **system browser**
  (authorization-code + PKCE, loopback redirect on desktop, app-scheme /
  App Links on mobile — no embedded web views), then exchange the result at
  the server for the same opaque bearer token used everywhere else.
- Vault endpoints are plain file semantics over HTTP (raw bytes up/down,
  metadata list, ETag conflict detection) so both Rust and Dart clients can
  implement sync with a basic HTTP client — no SPA-only assumptions anywhere
  under `/api/v1`.

## Stack decision

- **Framework: axum** on tokio (tokio is already a workspace dependency).
- **Auth: email + password, plus "Sign in with Google"** — argon2 password
  hashing, opaque session tokens. Google login is OIDC authorization-code +
  PKCE; the server verifies Google's ID token and issues its **own** opaque
  session token — Google tokens are never used as API credentials. Accounts
  are keyed by verified email, so a Google login with the same address links
  to the existing account rather than creating a duplicate. Server auth is
  completely separate from vault security questions.
- **Storage: SQLite + local disk** — accounts/sessions/vault-metadata in SQLite
  (`sqlx`, embedded migrations), vault blobs as files under a data directory.
  Single-binary, self-hostable v1.
- **Frontend: JSON API only** (`/api/v1/...`); the landing/auth/profile UI is a
  **separate SPA** built in a later phase and served by the server as static
  assets. Desktop and mobile apps consume the same API for sync.
- **Architecture rule — traits everywhere, no direct backend coupling.** Every
  external dependency is accessed through a trait defined by the server core;
  concrete backends are pluggable implementations chosen at startup:
  - `AccountStore` (users), `SessionStore` (tokens), `VaultMetaStore`
    (vault metadata) — first impl: SQLite; a PostgreSQL impl can be added
    without touching handlers.
  - `VaultBlobStore` (opaque file bytes) — first impl: local disk; later
    S3-compatible.
  - `Mailer` (verification/reset emails) — first impl: no-op/log; later SMTP
    or a provider API.
  - Handlers and middleware depend only on these traits (trait objects or
    generics in app state); each trait ships with an in-memory fake so
    integration tests run without SQLite or a real filesystem.

### Accepted trade-offs

- **(−) SQLite + local-disk blobs are single-node.** Fine for v1/self-hosting;
  swapping in Postgres / S3 is just new trait impls (see architecture rule),
  deployed when needed.
- **(−) Trait indirection adds a little boilerplate** per backend; paid for by
  testability (in-memory fakes) and backend portability.
- **(−) No server-side vault validation possible** (blobs are opaque) — at most
  a ZIP-magic sanity check on upload.
- **(+) Single static binary, trivial deploy, no external services.**
- **(+) Zero-knowledge design: server code never links the crypto core.**

## Target repo layout

```
askrypt/
├── Cargo.toml                 # [workspace] members += ["server"]
├── core/                      # unchanged — clients only; server does NOT depend on it
├── src/                       # desktop app (unchanged)
├── app/                       # mobile app (unchanged)
└── server/                    # askrypt-server (axum binary)
    ├── PLAN.md                # this file
    ├── Cargo.toml
    ├── migrations/            # sqlx migrations (SQLite backend)
    ├── static/                # built SPA output (placeholder page until Phase 7)
    └── src/                   # handlers depend on traits only; store/ holds the
        └── store/             #   trait definitions + sqlite/, disk/, memory/ impls
# Runtime data dir (configurable, not in repo):
#   <data>/askrypt.db          # SQLite
#   <data>/vaults/<user-id>/<vault-id>.askrypt
```

## Phases

- **Phase 0 — Scaffolding.**
  - Add `server/` crate (`askrypt-server`) to the Cargo workspace.
  - axum app skeleton: router, graceful shutdown, `/healthz`.
  - Configuration (bind address, data dir, secrets) via env vars / config file.
  - Logging/tracing setup; uniform JSON error-response convention.
  - Define the backend **traits** (`AccountStore`, `SessionStore`,
    `VaultMetaStore`, `VaultBlobStore`, `Mailer`, `IdTokenVerifier` — the
    last one validating Google ID tokens) plus in-memory fakes; app state
    holds trait objects, backends selected in `main` from config.
  - SQLite pool + embedded migration runner behind the store traits; initial
    empty migration.
  - Gate: server boots, health check answers, `cargo test`/`clippy` clean;
    handlers compile against traits only (no `sqlx` types in handler code).

- **Phase 1 — Landing page.**
  - Serve static assets at `/` from `server/static/` with SPA fallback routing;
    ship a minimal placeholder landing page until Phase 7.
  - Clean separation: everything dynamic lives under `/api/v1`.
  - Version/about endpoint.
  - Gate: landing reachable in a browser; API namespacing in place.

- **Phase 2 — Auth: register & login.**
  - `AccountStore`: user records (id, email, argon2 password hash, timestamps);
    SQLite impl via migration.
  - Register endpoint with input validation (email format, password policy).
  - Login endpoint → opaque session token via `SessionStore`; logout endpoint.
  - Auth middleware/extractor for protected routes.
  - **Google login**: OAuth config (Google client IDs for web/desktop/mobile)
    via env/config; endpoint(s) under `/api/v1/auth/google` where clients
    exchange the authorization result. The server verifies the Google ID
    token (signature, issuer, audience, expiry, **email verified**) through
    the `IdTokenVerifier` trait, then creates the account or links to the
    existing one by verified email, and issues the normal opaque session
    token via `SessionStore`.
  - Rate limiting on auth endpoints.
  - Later (optional, non-blocking): email verification, password reset (via
    the `Mailer` trait).
  - Gate: register → login → authenticated request → logout flow covered by
    integration tests running against the in-memory store fakes; the flow is
    exercised as a headless client would do it (bearer token, no cookies).
    Google flow (new account + link-to-existing) integration-tested against
    the fake `IdTokenVerifier`.

- **Phase 3 — Profile page (API).**
  - Get current user info, including linked login providers (password /
    Google).
  - Update email; change password (requires current password re-auth).
    Google-created accounts have no password — support **set password**
    there; current-password re-auth applies only to accounts that have one.
  - List active sessions/devices; revoke a session.
  - Delete account — cascades to all stored vault files.
  - Gate: profile CRUD integration-tested.

- **Phase 4 — Vault cloud storage (file operations only).**
  - Per-user vault namespace; metadata (id, name, size, mtime, content
    hash/ETag) in `VaultMetaStore`, bytes in `VaultBlobStore`.
  - Endpoints: upload, download, list (metadata only), rename, delete —
    written against the two traits, never against `sqlx` or `std::fs`.
  - Opaque-bytes contract: no parsing beyond an optional ZIP-magic sanity check.
  - Optimistic concurrency for multi-device sync: ETag / `If-Match` on upload,
    conflict response when the stored version changed.
  - Per-user quota and max-file-size limits; atomic writes (temp file + rename)
    inside the local-disk `VaultBlobStore` impl.
  - Gate: full upload→list→download→rename→delete lifecycle integration-tested;
    conflict behavior verified; the lifecycle also demonstrated end-to-end from
    a plain HTTP client (login → upload a real `vault.askrypt` → download it
    back byte-identical), proving desktop/mobile apps can drive it.

- **Phase 5 — Hardening & deployment.**
  - Security headers; HTTPS story (reverse proxy, e.g. Caddy/nginx).
  - Request body limits, timeouts, backpressure.
  - Structured audit log for auth events (login/failed login/password change).
  - Backup story for the SQLite db + blob directory.
  - Dockerfile and/or systemd unit for self-hosting.
  - Gate: deployment checklist complete; server runs behind TLS end-to-end.

- **Phase 6 — CI/CD.**
  - Extend `.github/workflows/ci.yml`: build, test, clippy for `server/`.
  - Release workflow: Linux server binary artifact.
  - Gate: CI green on push.

- **Phase 7 — SPA frontend (separate track).**
  - Landing, register/login, profile, and vault file-manager pages against the
    `/api/v1` API; built output dropped into `server/static/`.
  - Out of scope for the Rust-server phases above; stack chosen when started.

## Open decisions (not blocking)

- Client-side sync UX: how desktop (`src/`) and mobile (`app/`) integrate the
  storage API (manual upload/download vs automatic sync, conflict UI).
- Email delivery provider for verification / password reset.
- Trigger points for adding the Postgres and S3 trait impls (the trait layer
  makes this additive — no handler changes).
- Multiple vaults per user vs a single primary vault (API assumes multiple).
- More OAuth providers (Apple, GitHub) and a provider unlink flow — additive
  thanks to the `IdTokenVerifier` trait layer.

## Verification commands

```
cargo test -p askrypt-server
cargo clippy -p askrypt-server --all-targets
cargo run -p askrypt-server        # then curl /healthz, /api/v1/... smoke checks
cargo test --workspace             # desktop/core remain green
```
