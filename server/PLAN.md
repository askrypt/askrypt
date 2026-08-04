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
  implement sync with a basic HTTP client — no browser-only assumptions
  anywhere under `/api/v1`.
- The website (Phase 7) is a *second* consumer, not the primary one: it is
  server-rendered HTML with its own cookie session, and it must never force a
  change on `/api/v1` that a headless client would have to work around.

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
- **Frontend: server-rendered HTML + htmx — no SPA, no JavaScript build.**
  The website (landing, auth, profile, vault file manager) is rendered by axum
  itself with **askama** templates (compile-time-checked `.html` files;
  `maud` was the considered alternative — rejected because htmx pages are
  mostly HTML with `hx-*` attributes, which reads better as real HTML than as
  a Rust DSL). Interactivity is htmx returning HTML **fragments**; the only
  static assets are a vendored `htmx.min.js` and a hand-written stylesheet —
  no Node, npm, bundler, or CDN anywhere in the build.
  - The HTML pages live at the root (`/`, `/login`, `/account`, `/vaults`, …)
    and are **separate handlers** from `/api/v1`. The JSON API is unchanged
    and remains the contract for desktop/mobile.
  - Web sessions ride an **HttpOnly, Secure, SameSite=Lax cookie** holding the
    same opaque token the `SessionStore` already issues — the web UI is just
    another session, visible and revocable in the profile session list.
    Browser-only concerns (cookie, CSRF, redirects, flash messages) stay in
    the HTML layer and never leak into `/api/v1`.
  - **The website is a file manager, not a vault client**: it can list,
    upload, download, rename and delete encrypted vaults, but it never
    unlocks one — no crypto in the browser, so the zero-knowledge property is
    structural rather than a promise.
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
- **(−) Two auth surfaces** once the web UI lands: bearer tokens for
  `/api/v1`, a session cookie for the HTML pages. Mitigated by having both
  resolve the *same* `SessionStore` token — the difference is only how the
  token is carried, plus CSRF protection on the cookie side.
- **(−) The web UI can never open a vault** (no client-side crypto without a
  JS/wasm port of `core`). Users unlock vaults in the desktop or mobile app;
  the site only moves files. Accepted deliberately — see the Open decisions.
- **(−) Richer client-side interactions cost server round-trips** (htmx
  fragments) and page state must be rebuilt server-side. Fine for a handful
  of forms and a file table; would hurt for a heavy app-like UI.
- **(+) Single static binary, trivial deploy, no external services** — now
  including the website: templates are compiled into the binary, the only
  loose files are one CSS and one vendored JS.
- **(+) No JavaScript toolchain in CI**; `cargo build` produces the whole
  product, and the UI is covered by the same `cargo test` HTTP tests.
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
    ├── DEPLOY.md              # self-hosting: TLS, config, backups, checklist
    ├── Cargo.toml
    ├── Dockerfile             # multi-stage; build from the repo root
    ├── deploy/                # docker-compose, Caddyfile, systemd unit, backup.sh
    ├── migrations/            # sqlx migrations (SQLite backend)
    ├── templates/             # askama HTML templates (Phase 7): pages + htmx fragments
    ├── static/                # hand-written CSS + vendored htmx.min.js (no build step)
    │                          #   placeholder index.html until Phase 7 replaces it
    └── src/                   # handlers depend on traits only; store/ holds the
        ├── store/             #   trait definitions + sqlite/, disk/, memory/ impls
        └── web/               # Phase 7: HTML handlers, cookie session, CSRF
                               #   (JSON API under src/{auth,profile,vaults}.rs untouched)
# Runtime data dir (configurable, not in repo):
#   <data>/askrypt.db          # SQLite
#   <data>/vaults/<user-id>/<vault-id>.askrypt
```

## Phases

- **Phase 0 — Scaffolding.** ✅ *(done 2026-08-02)*
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

- **Phase 1 — Landing page.** ✅ *(done 2026-08-02)*
  - Serve static assets at `/` from `server/static/` with SPA fallback routing;
    ship a minimal placeholder landing page until Phase 7.
  - Clean separation: everything dynamic lives under `/api/v1`.
  - Version/about endpoint.
  - Gate: landing reachable in a browser; API namespacing in place.
  - ⚠️ *Superseded by the Phase 7 decision (server-rendered HTML, not an SPA):*
    the shipped `fallback_service` serves `index.html` for every unknown path.
    Phase 7 replaces that with explicit HTML routes, `ServeDir` mounted at
    `/assets` for the CSS/htmx files only, and a real 404 page — no
    catch-all-to-index behaviour. Nothing to change before then.

- **Phase 2 — Auth: register & login.** ✅ *(done 2026-08-02; email
  verification / password reset via `Mailer` still open, as planned)*
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

- **Phase 3 — Profile page (API).** ✅ *(done 2026-08-02)*
  - Get current user info, including linked login providers (password /
    Google).
  - Update email; change password (requires current password re-auth).
    Google-created accounts have no password — support **set password**
    there; current-password re-auth applies only to accounts that have one.
  - List active sessions/devices; revoke a session. (Sessions are identified
    to clients by a SHA-256 digest of the bearer token, never the token.)
  - Delete account — cascades to all stored vault files.
  - Gate: profile CRUD integration-tested.

- **Phase 4 — Vault cloud storage (file operations only).** ✅ *(done
  2026-08-02)*
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
  - **API summary** (all under `/api/v1`, bearer token required):

    | Method | Path | Notes |
    |--------|------|-------|
    | `GET` | `/vaults` | list metadata, sorted by name |
    | `POST` | `/vaults?name=<file name>` | upload new; raw bytes body; 201 + `ETag` |
    | `GET` | `/vaults/{id}` | download raw bytes; `ETag`, honors `If-None-Match` (304) |
    | `PUT` | `/vaults/{id}` | overwrite; **requires `If-Match`** (428 without, 412 on mismatch) |
    | `PUT` | `/vaults/{id}/name` | rename (JSON `{"name": …}`); ETag is content-based, so unchanged |
    | `DELETE` | `/vaults/{id}` | delete bytes + metadata |

    ETags are the SHA-256 of the stored bytes, quoted in headers. Limits:
    10 MiB per file (also the route body limit), 100 MiB and 100 files per
    account, answered as 507 `quota_exceeded` / `vault_limit_reached`.

- **Phase 5 — Hardening & deployment.** ✅ *(done 2026-08-04)*
  - Security headers; HTTPS story (reverse proxy, e.g. Caddy/nginx).
    The CSP must be written so the Phase 7 pages fit it without loosening:
    `script-src 'self'` only (htmx is vendored, so no CDN host and no
    `unsafe-inline`) — which means **no inline `<script>` and no `hx-on:`
    handlers** in templates. Cookies are set `Secure`, so the TLS terminator
    is a prerequisite for the web UI, not just a nicety.
  - Request body limits, timeouts, backpressure.
  - Structured audit log for auth events (login/failed login/password change).
  - Backup story for the SQLite db + blob directory.
  - Dockerfile and/or systemd unit for self-hosting.
  - Gate: deployment checklist complete; server runs behind TLS end-to-end.

  **What shipped**, beyond the bullets above:

  - `src/hardening.rs` — hand-rolled `from_fn` middleware (security headers +
    the committed `CSP` const, `no-store` on `/api/v1`, a request timeout, and
    a semaphore-based load shedder) rather than `tower-http` layers, so every
    short-circuit keeps the `{"error": {code, message}}` envelope. Body limit
    is 64 KiB globally, with the vault routes' 10 MiB layered inside it.
  - `src/clientip.rs` — `X-Forwarded-For`/`X-Real-IP` are believed only under
    `ASKRYPT_TRUST_PROXY`, and the **last** XFF element is taken, not the
    first: proxies append, so the first element is client-supplied. This
    closes the spoofing hole the Phase 2 rate limiter shipped with.
  - `src/audit.rs` — events on the `askrypt_server::audit` tracing target,
    with a `ClientInfo` extractor. No tokens, no passwords, and no email on a
    *failed* login (that would build a list of registered addresses).
  - **Login timing equalized**: unknown-email and password-less accounts now
    verify against a fixed dummy argon2 hash, closing the enumeration side
    channel the Phase 2 code documented as deferred.
  - **argon2 concurrency cap** (`ASKRYPT_ARGON2_PARALLELISM`): each hash holds
    ~19 MiB and tokio's blocking pool would run 512 of them. Bounding the
    hashes, not the requests, is what actually caps memory under a flood.
  - ⚠️ **Behaviour change — changing an existing password now revokes every
    other session** (the caller's survives). Desktop and mobile must handle a
    401 after a password change by re-logging in. Setting a *first* password
    on a Google account does not revoke anything.
  - `askrypt-server backup <path>` (`VACUUM INTO`) plus `deploy/backup.sh`,
    which snapshots the database **before** archiving blobs — uploads write
    bytes then metadata, so that order can only orphan a blob, never strand a
    metadata row. Deletes invert the hazard, hence `--quiesce`.
  - `Dockerfile` + `deploy/{docker-compose.yml,Caddyfile,askrypt-server.service,backup.sh}`
    and `DEPLOY.md` (checklist, restore drill, sizing).
  - `server/static/index.html`'s inline `<style>` moved to `style.css`, since
    `style-src 'self'` would otherwise blank the shipped landing page.
  - Gate evidence: `tests/hardening.rs` (8 tests) plus the container run —
    non-root, private data dir, persistence across restart, graceful SIGTERM,
    and an audit record showing the proxy-observed IP rather than the forged
    one.

- **Phase 6 — CI/CD.**
  - Extend `.github/workflows/ci.yml`: build, test, clippy for `server/`.
  - Release workflow: Linux server binary artifact.
  - Gate: CI green on push.

- **Phase 7 — Website: server-rendered HTML + htmx.**
  Rendered by the server itself (askama templates, htmx fragments) rather than
  by a client-side app. New deps: `askama`, a cookie extractor
  (`axum-extra` `cookie` feature or `tower-cookies`), `axum` `multipart` for
  uploads. **No Node, no bundler, no CDN** — `htmx.min.js` is vendored into
  `server/static/`.

  - **7.1 — HTML layer foundations.**
    - `src/web/` module tree: page handlers, a base layout template
      (`templates/layout.html`), and a `WebError` type rendering an HTML error
      page — the JSON `ApiError` envelope stays exclusive to `/api/v1`.
    - Rework the root router: explicit HTML routes, `ServeDir` at `/assets`
      for CSS + vendored JS, plain HTML 404 fallback (drops the Phase 1
      SPA fallback; `/api/*` keeps its JSON 404).
    - Convention: a request with `HX-Request` gets the fragment, a plain
      request gets the full page, so every screen works with JS disabled.
    - Gate: landing page renders from a template; `/assets` serves the
      vendored files; unknown paths give an HTML 404 while `/api/x` stays JSON.

  - **7.2 — Browser sessions & CSRF.**
    - `WebSession` extractor: reads the session token from an `HttpOnly;
      Secure; SameSite=Lax; Path=/` cookie and resolves it through the *same*
      `SessionStore` as the bearer flow — one session model, one revocation
      path, web logins listed in `/account` alongside devices.
    - Login/register/logout **HTML form** handlers that reuse the Phase 2
      account logic (shared functions, not HTTP self-calls), set/clear the
      cookie, and redirect (POST-redirect-GET) with flash messages.
    - **CSRF**: per-session token embedded in every mutating form and sent by
      htmx via `hx-headers`; `Origin`/`Referer` checked as a backstop.
      Applies to cookie-authenticated requests only — bearer requests are not
      CSRF-able and must not be burdened with it.
    - Google sign-in for the browser: server-side authorization-code + PKCE
      with a `/auth/google/callback` redirect URI, ending in the same cookie
      session. This is a *new* web flow beside the native
      `/api/v1/auth/google` token exchange; both converge on the same
      account-link-by-verified-email logic.
    - Reuse the existing rate limiters on the HTML auth routes.
    - Gate: register → login → protected page → logout in a browser and in
      tests; a mutating POST without a valid CSRF token is rejected; the web
      session appears in and can be killed from the session list.

  - **7.3 — Profile pages.**
    - `/account`: current email, linked providers, change email, change/set
      password (current-password re-auth where one exists), session list with
      per-row revoke (htmx `hx-delete` swapping the row out), and account
      deletion behind a typed-confirmation form.
    - Gate: every Phase 3 capability reachable from the browser; revoking the
      *current* session logs the browser out cleanly.

  - **7.4 — Vault file manager.**
    - `/vaults`: table of vault metadata (name, size, modified, short ETag),
      `multipart/form-data` upload (streamed into `VaultBlobStore`, honoring
      `MAX_VAULT_BYTES`), download links, inline rename, delete with
      confirmation, and quota/count usage display.
    - Overwrite from the browser carries the current ETag in the form so the
      Phase 4 `If-Match` conflict path applies; a stale ETag renders a
      "changed on another device" fragment instead of a raw 412.
    - Copy for users: explain that the site stores vaults but cannot open
      them — unlocking happens in the desktop/mobile apps.
    - Gate: upload → list → download (byte-identical) → rename → delete all
      done from a browser; conflict message verified; oversized upload and
      quota exhaustion render friendly errors, not stack traces.

  - **Phase gate (whole phase):** the full product ships from `cargo build`
    with no JS toolchain; HTML routes covered by `server/tests/web.rs` (tower
    `oneshot`, asserting status, `Set-Cookie` attributes, CSRF rejection and
    key markup); every page usable with JavaScript disabled.

## Open decisions (not blocking)

- Client-side sync UX: how desktop (`src/`) and mobile (`app/`) integrate the
  storage API (manual upload/download vs automatic sync, conflict UI).
- Email delivery provider for verification / password reset.
- Trigger points for adding the Postgres and S3 trait impls (the trait layer
  makes this additive — no handler changes).
- Multiple vaults per user vs a single primary vault (API assumes multiple).
- More OAuth providers (Apple, GitHub) and a provider unlink flow — additive
  thanks to the `IdTokenVerifier` trait layer.
- **In-browser vault unlock is out of scope** (decided with the Phase 7 stack:
  the site never decrypts). Revisiting it means compiling `core/` to
  `wasm32-unknown-unknown` and running PBKDF2 in a Web Worker — a genuinely
  separate project, and one that would have to keep parity with the same
  golden vectors as the Dart port. Not a reason to pick a JS framework now.
- Web session cookie lifetime vs the 30-day API session lifetime (shorter,
  with an idle timeout, seems right for a browser).
- How web sessions are labelled in the session list (user agent string vs a
  generic "Web browser") — a privacy/usefulness trade-off.

## Verification commands

```
cargo test -p askrypt-server
cargo clippy -p askrypt-server --all-targets
cargo run -p askrypt-server        # then curl /healthz, /api/v1/... smoke checks
cargo test --workspace             # desktop/core remain green
```
