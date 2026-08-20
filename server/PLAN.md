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
  - `Mailer` (verification/reset emails) — `SmtpMailer` (lettre) when
    `ASKRYPT_SMTP_HOST` is set, otherwise the logging `MemoryMailer`; a
    provider-API impl can be added alongside. No feature calls it yet.
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
    ├── deploy/                # docker-compose + Caddyfile (containers only)
    ├── migrations/            # sqlx migrations (SQLite backend)
    ├── templates/             # askama HTML templates: pages + fragments/
    ├── static/                # served at /assets: style.css + vendored htmx.min.js
    │                          #   (no build step, no index.html — pages are templates)
    └── src/                   # handlers depend on traits only; store/ holds the
        ├── store/             #   trait definitions + sqlite/, disk/, memory/ impls
        └── web/               # HTML handlers, cookie session, CSRF, flashes
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
  - ⚠️ *Superseded by Phase 7.1, which shipped:* the SPA `fallback_service`
    and the placeholder `static/index.html` are gone, replaced by explicit
    HTML routes, `ServeDir` at `/assets`, and an HTML 404.

- **Phase 2 — Auth: register & login.** ✅ *(done 2026-08-02; the `Mailer`
  seam now has an SMTP backend, but email verification / password reset are
  still unbuilt, as planned)*
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
  - Later (optional, non-blocking): email verification, password reset. The
    delivery half is done — `Mailer` has an SMTP impl (`store::smtp`) and is
    configured from `ASKRYPT_SMTP_*`; what is missing is the token issuing,
    storage, expiry and the endpoints that consume them. Nothing calls
    `state.mailer` yet.
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
    | `DELETE` | `/vaults/{id}` | delete bytes + metadata (and the vault's history) |
    | `GET` | `/vaults/{id}/versions` | the generations this vault's saves replaced, newest first |
    | `GET` | `/vaults/{id}/versions/{version_id}` | download archived bytes; `ETag`, honors `If-None-Match` |
    | `POST` | `/vaults/{id}/versions/{version_id}/restore` | make that generation current; `If-Match` honored if sent |

    ETags are the SHA-256 of the stored bytes, quoted in headers. Limits:
    10 MiB per file (also the route body limit) and 100 files per account,
    plus a per-account byte quota — 1 MiB, or 100 MiB for an account holding
    `PAYMENT_USER` (see Phase 9) — answered as 507 `quota_exceeded` /
    `vault_limit_reached`.

  - **Version history** *(added 2026-08-08, after the phase gate)*. Every
    overwrite files the bytes it replaced away as a `VaultVersion`:
    `MAX_VAULT_VERSIONS` = 5 generations per vault, indexed in
    `VaultVersionStore` (table `vault_versions`) with the bytes in a
    **second `VaultBlobStore` instance keyed by version id**, writing to
    `<data>/vaults/<account-id>/versions/` — inside the account's own
    directory, so one tree still holds everything an account has stored. Design points worth keeping:
    - **History never costs a save.** Archiving and trimming are best effort
      — a failure is a `warn!`, not a 5xx — and the trim runs *after* the
      write has landed.
    - **History shares the account quota** rather than adding to it: the trim
      keeps the newest generations that fit in what the live files leave of
      the account's own allowance, so total disk per account is unchanged
      from before the feature. A full account simply keeps no history.
    - **Identical bytes make no generation**, so a client that re-uploads on
      a timer cannot flush the real history out of the window.
    - **A restore is an ordinary overwrite** with old bytes, which archives
      the state it displaces — restoring the wrong generation is undone by
      restoring again.
    - Deleting a vault, and deleting an account, remove the archived bytes
      too; the SQLite rows also cascade both ways.

  - **Write stamps** *(added 2026-08-08, after the phase gate)*. The vault
    format keeps two fields *outside* the encryption — `params.host` and
    `params.updated_at`, the machine that last wrote the file and when — and
    `src/vaultfile.rs` reads exactly those two on the way in, so a listing can
    answer "where and when was this saved?" rather than only "when did the
    server receive it?". They ride along in `VaultMeta`/`VaultVersion`
    (nullable `host` / `saved_at` columns), in `VaultInfo`/`VersionInfo`, and
    in a `Saved` column on the file manager's table. Design points:
    - **It does not weaken the opaque-bytes contract.** The reader knows one
      archive member and two fields in it; nothing encrypted is deserialized,
      and `askrypt-core` stays out of this crate — the scope rule is the
      reason the reader is written here rather than borrowed.
    - **It can never refuse a save.** A file that is not a ZIP, has no
      `askrypt.json`, or predates the stamp simply has none, and the two
      halves are independent: an unparsable timestamp still leaves the host.
    - **Bytes bring their own stamp.** An overwrite replaces both fields
      rather than inheriting them, so a save from a device that writes no
      stamp does not keep showing the previous device's name. Archived
      generations keep the stamp they were saved with.
    - The host name is another machine's text on its way to a table cell:
      control characters are stripped, the length is capped, and the
      templates escape it (`tests/web.rs` guards that).

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
  - Dockerfile + compose stack for self-hosting.
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
  - `askrypt-server backup <path>` (`VACUUM INTO`), documented as a
    `docker compose exec` that snapshots the database **before** archiving
    blobs — uploads write bytes then metadata, so that order can only orphan a
    blob, never strand a metadata row. Deletes invert the hazard, hence the
    stop-first variant for an exact snapshot.
  - `Dockerfile` + `deploy/{docker-compose.yml,Caddyfile}` and `DEPLOY.md`
    (checklist, restore drill, sizing). **Containers are the only supported
    deployment**: the systemd unit and the `backup.sh` wrapper that shipped
    with Phase 5 were removed afterwards.
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

- **Phase 7 — Website: server-rendered HTML + htmx.** ✅ *(7.1–7.4 done;
  browser Google sign-in deferred then shipped in Phase 13)*
  Rendered by the server itself (askama templates, htmx fragments) rather than
  by a client-side app. New deps as built: `askama`, `serde_urlencoded` and
  `axum`'s `multipart` feature — no cookie crate in the end (see 7.2).
  **No Node, no bundler, no CDN** — `htmx.min.js` is vendored into
  `server/static/`.

  - **7.1 — HTML layer foundations.** ✅ *(done 2026-08-04)*
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

  - **7.2 — Browser sessions & CSRF.** ✅ *(done 2026-08-04; browser Google
    sign-in deferred — see below)*
    - `WebSession` extractor: reads the session token from an `HttpOnly;
      Secure; SameSite=Lax; Path=/` cookie and resolves it through the *same*
      `SessionStore` as the bearer flow — one session model, one revocation
      path, web logins listed in `/account` alongside devices.
    - Login/register/logout **HTML form** handlers that reuse the Phase 2
      account logic (shared functions, not HTTP self-calls), set/clear the
      cookie, and redirect (POST-redirect-GET) with flash messages.
    - **CSRF**: token embedded in every mutating form; `Origin`/`Referer`
      checked as a backstop. Applies to cookie-authenticated requests only —
      bearer requests are not CSRF-able and must not be burdened with it.
    - Reuse the existing rate limiters on the HTML auth routes.
    - Gate: register → login → protected page → logout in a browser and in
      tests; a mutating POST without a valid CSRF token is rejected; the web
      session appears in and can be killed from the session list.

  **What shipped in 7.1 + 7.2**, and where it differs from the bullets above:

  - **`src/auth.rs` was split handler-from-logic.** `authenticate`,
    `register_account`, `issue_session`, `resolve_session`,
    `revoke_session_token` and `upsert_google_account` are now `pub(crate)`
    free functions over `AppState`; the `/api/v1` handlers are thin wrappers
    and the HTML handlers call the same functions. No behaviour changed. The
    one that mattered: `authenticate` carries the `DUMMY_PASSWORD_HASH`
    timing equalization, which a second implementation would have quietly
    dropped. `upsert_google_account` was extracted with no second caller yet,
    so the browser code flow lands on the identical link-or-create rules.
  - **CSRF is a random double-submit cookie, not a token derived from the
    session.** The obvious derivation (`sha256(session_token)`) is exactly
    what `profile::session_id` already computes *and publishes* in the device
    list, so it would have handed out valid CSRF tokens. Instead: 256 random
    bits in `askrypt_csrf`, echoed in a hidden field, compared in constant
    time, rotated on sign-in and sign-out. It protects the signed-*out* forms
    too. `web::csrf::CsrfForm<T>` is the only way to read a form body, so a
    mutating route cannot forget the check.
  - **No cookie crate.** `axum-extra`'s `cookie` feature was dropped again
    once it turned out to be one `CookieJar` call: `web::session` reads the
    `Cookie` header and formats its three `Set-Cookie` values directly, which
    keeps the exact attribute string readable and unit-tested. Added deps are
    just `askama` and `serde_urlencoded`.
  - **Web sessions last 7 days** (API: 30) and are labelled `"Web browser"` —
    no user-agent string is stored. Resolves two of the open decisions below.
  - **`no_store` now covers the HTML routes too**, so no signed-in page can
    land in a shared cache; `/assets` sits outside it and caches normally.
  - **The HTML auth routes share the `/api/v1/auth` rate limiter instance**,
    so alternating between the form and the JSON endpoint doesn't double an
    attacker's budget. `web::rate_limit` is an HTML-rendering twin of
    `ratelimit::middleware` over the same `RateLimiter`.
  - **`static/index.html` is gone**; the landing page is a template and
    `static/` now holds only `style.css` and the vendored `htmx.min.js`
    (2.0.10). `ASKRYPT_STATIC_DIR` keeps its name but now means "the
    directory served at `/assets`".
  - **`/account` is a stub**: email, sign-in method, session lifetime, and a
    note that the rest arrives in 7.3/7.4. It exists to prove the session
    round-trip, not to be the profile page.
  - Gate evidence: `tests/web.rs` (17 tests) — cookie attributes, the CSRF
    rejections (missing token, foreign token, foreign `Origin`), the fragment
    vs. full-page split, an unknown address rejected byte-identically to a
    wrong password, and the whole 7.2 gate as one test: register in the
    browser → find the session in `GET /api/v1/me/sessions` → revoke it there
    → the browser is signed out. Plus a test asserting no page carries an
    inline `<script>`, `<style>` or `hx-on:`, so the CSP can't drift.

  **↪ Browser Google sign-in was deferred here and shipped in Phase 13**,
  which is where the design and the reasoning live. It did *not* need the
  authorization-code machinery this section once listed as prerequisites —
  no client secret, no `redirect_uri`, no `OAuthCodeExchanger`, no PKCE — and
  the caveat about `form-action 'self'` blocking a redirect out to
  `accounts.google.com` does not apply either, because nothing redirects out.
  Google Identity Services mints the ID token in the page and the credential
  is posted to *our own* origin, which converges on exactly the seam this
  section predicted: `IdTokenVerifier` then `auth::upsert_google_account`.

  - **7.3 — Profile pages.** ✅ *(done 2026-08-05)*
    - `/account`: current email, linked providers, change email, change/set
      password (current-password re-auth where one exists), session list with
      per-row revoke, and account deletion behind a typed-confirmation form.
    - Gate: every Phase 3 capability reachable from the browser; revoking the
      *current* session logs the browser out cleanly.

  - **7.4 — Vault file manager.** ✅ *(done 2026-08-05)*
    - `/vaults`: table of vault metadata (name, size, modified, short ETag),
      `multipart/form-data` upload honoring `MAX_VAULT_BYTES`, download
      links, inline rename, delete with confirmation, and quota/count usage
      display.
    - Overwrite from the browser carries the current ETag in the form so the
      Phase 4 `If-Match` conflict path applies; a stale ETag renders a
      "changed on another device" fragment instead of a raw 412.
    - Copy for users: explain that the site stores vaults but cannot open
      them — unlocking happens in the desktop/mobile apps.
    - Gate: upload → list → download (byte-identical) → rename → delete all
      done from a browser; conflict message verified; oversized upload and
      quota exhaustion render friendly errors, not stack traces.

  **What shipped in 7.3 + 7.4**, and where it differs from the bullets above:

  - **`src/profile.rs` and `src/vaults.rs` were split handler-from-logic**,
    exactly as `src/auth.rs` was in 7.2, and for the same reason: `web/` must
    never re-derive a rule. `profile::{set_email, set_password,
    active_sessions, revoke_session_id, delete_account_data}` and
    `vaults::{list_for, create, overwrite, set_name, destroy, read}` are
    `pub(crate)` free functions over `AppState`; the `/api/v1` handlers and
    the HTML handlers both call them. The ones that mattered: `set_password`
    carries the re-auth *and* the revoke-every-other-session rule (the
    caller's token is a parameter), and `overwrite` carries the `If-Match`
    comparison — a second copy in `web/` would have quietly become an
    unconditional overwrite.
  - **Revoking a device is a form POST, not `hx-delete`.** htmx 2 does not
    serialize the enclosing form for a request fired from a button inside it,
    and the CSRF token lives in that form. `hx-post` on the form itself keeps
    `CsrfForm` the only door into a mutating route, at the cost of swapping
    the whole device list instead of one row — which is what the vault table
    does too, since a change moves the quota figures as well as the row.
  - **`web::csrf::CsrfMultipart`** is the upload's twin of `CsrfForm`, and the
    only way to read a multipart body. It checks the token *as it walks the
    parts* and requires it to arrive first (the templates put the hidden
    input before the file input), so a forged cross-origin upload is refused
    before its megabytes are buffered. `axum`'s `multipart` feature is the
    only new dependency in these two sub-phases.
  - **`GET /vaults/{id}/download` is a second download route**, cookie-authed,
    beside the API's bearer one: a browser cannot put an `Authorization`
    header on a plain link. Same bytes, plus a `Content-Disposition` filename.
    Its version twin `/vaults/{id}/versions/{version_id}/download` stamps the
    archival date into the file name so several downloaded generations do not
    collide in the downloads folder.
  - **Each row carries a "History" disclosure** listing the generations that
    file's saves replaced, with a download link and a restore form per entry.
    The restore form carries the row's ETag exactly as the replace form does:
    a restore *is* an overwrite and must lose the same race. The page's whole
    history is fetched in one store call (`vaults::versions_by_vault`), not
    per row.
  - **Confirmation steps are `<details>` disclosures**, not scripted dialogs —
    the CSP forbids the inline handler a `confirm()` would need, and a
    disclosure still works with JavaScript off. Account deletion additionally
    requires typing the account's own email address.
  - **Errors are explained, not forwarded.** `web::vaults::explain` rewrites
    the four `ApiError` codes a visitor can actually hit (`precondition_failed`,
    `quota_exceeded`, `vault_limit_reached`, `invalid_vault_file`, plus
    `payload_too_large`) into sentences; anything 5xx goes through `WebError`,
    which replaces the wording wholesale, so no backend detail can reach a
    page.
  - **The web vault routes carry their own `DefaultBodyLimit`**
    (`MAX_VAULT_BYTES` + 64 KiB for the multipart envelope), declared inside
    the router's global limit exactly like the API's vault routes. An
    oversized upload surfaces as a readable HTML 413, not a bodyless one.
  - **The HTML email/password forms share the `/api/v1/me` profile rate
    limiter instance**, as the auth forms already share the auth one.
  - Gate evidence: `tests/web.rs` grew to 30 tests — the two 7.3 gates
    (every profile capability from the browser; revoking the current session
    signs it out cleanly), a browser password change killing an app's bearer
    token, the delete cascade behind the typed confirmation, the 7.4 round
    trip (upload → list → byte-identical download → rename → delete), the
    stale-ETag conflict message, per-account isolation, a multipart upload
    with a missing/foreign/cross-origin token, and the oversize 413 page. The
    CSP-drift test now covers the signed-in pages too.

  - **Phase gate (whole phase):** ✅ *(met 2026-08-05; the deferred Google
    button followed in Phase 13)* the full product ships from `cargo build`
    with no JS toolchain;
    HTML routes covered by `server/tests/web.rs` (tower `oneshot`, asserting
    status, `Set-Cookie` attributes, CSRF rejection and key markup); every
    page usable with JavaScript disabled.

- **Phase 8 — Roles and the admin console.** ✅ *(done 2026-08-09)*
  A self-hosted server had no operator surface at all: no way to see who had
  registered, and no way to lock out or remove an account short of editing
  SQLite by hand.

  - **Roles are tables, not a flag.** `roles` (seeded by the migration, `ADMIN`
    at a fixed uuid) plus the `account_roles`
    many-to-many grant table, both added to `migrations/0002_auth.sql` rather
    than a new numbered script — dev databases get recreated. A second role
    later is a data change, not a schema change; Phase 9 added `PAYMENT_USER`
    to the same `INSERT`.
  - **The first registered account becomes the administrator.**
    `admin::bootstrap_first_admin` runs after both account-creation paths
    (password and Google) and grants `ADMIN` only when no administrator exists
    *and* the new account is the only one. Deliberately narrow: it can never
    promote a later registration because the administrators were deleted. It
    logs and moves on rather than failing a registration.
    `askrypt-server grant-admin <email>` is the documented way back in.
  - **Ban is a reversible lock-out**, not a deletion: `accounts.banned_at`,
    enforced in `auth::authenticate` (403 `account_banned`, **after** the
    argon2 verify so login timing still cannot enumerate accounts),
    `auth::upsert_google_account`, and `auth::resolve_session` — the last
    covering bearer tokens and browser cookies with one check. Banning also
    drops the account's sessions, so it bites immediately. Vault blobs are
    untouched, and lifting the ban restores them unchanged.
  - **The Users page is HTML only** (`/admin/users`, behind the new
    `AdminSession` extractor): no `/api/v1/admin/*`, because no desktop or
    mobile client needs administration and a second surface is a second thing
    to secure. The rules live in `src/admin.rs` as `pub(crate)` free
    functions, the same split `profile.rs`/`web/account.rs` already uses;
    `delete_user` reuses `profile::delete_account_data` rather than repeating
    the cascade.
  - **Guardrails**, all in `src/admin.rs` so htmx and no-JS agree:
    `cannot_target_self` (an administrator's own row offers no destructive
    action and the server refuses one anyway), `last_admin` (the system always
    keeps an administrator), and `confirmation_mismatch` (deleting someone
    else needs their address typed, mirroring self-delete).
  - **Phase gate:** ✅ first account is admin and the second is not; a
    non-administrator gets 403 and a signed-out visitor gets the login
    redirect; a ban kills live sessions *and* fresh logins and is reversible;
    delete cascades the target's vaults; CSRF and htmx-fragment behaviour
    match the rest of the site. `server/tests/admin.rs` (11 tests) plus unit
    tests in `src/admin.rs` and both store backends.

- **Phase 9 — The paid storage tier.** ✅ *(done 2026-08-10)*
  The storage quota was one constant for everybody, which left no way to
  offer more space to some accounts than others. Phase 8's role table was
  built for exactly this, so the tier is a role rather than a column.

  - **`PAYMENT_USER` is the second seeded role**, added to the same
    `INSERT INTO roles` in `migrations/0002_auth.sql` at a fixed uuid, and
    mirrored by hand in `MemoryRoleStore::default`. It grants nothing but
    storage. Because the migration changed, **existing databases have to be
    recreated**: `sqlx::migrate!` checksums what it applied and refuses a
    rewritten script.
  - **The quota became per-account.** `ACCOUNT_QUOTA_BYTES` is now 1 MiB and
    `PAID_ACCOUNT_QUOTA_BYTES` 100 MiB — the figure everyone used to get.
    `vaults::quota_for` picks between them; `create` and `overwrite` fetch it
    once and thread it through `check_quota` and the history trim, so a save
    costs one role lookup. Nothing was backfilled: every existing account
    dropped to the standard tier, and an administrator grants the role.
  - **Only writes are checked.** An account over its quota keeps list,
    download and delete — losing the role cannot strand somebody's data
    behind a paywall, it only stops the next save.
  - **The Users page grew a second toggle** on the existing `/{id}/role`
    route, told apart by a hidden `role` field (absent = `ADMIN`, so the
    older form still works) and whitelisted by `admin::known_role` so a
    hand-made POST cannot name anything else. `set_role` applies the
    self- and last-admin guards **only** to `ADMIN`, so the paid-tier button
    appears on every row including the administrator's own.
  - **Phase gate:** ✅ the same upload is refused at 507 `quota_exceeded` and
    then accepted once the role is granted; revoking it leaves the stored
    file readable but the next save refused; the badge and both toggles
    round-trip through the page; an unknown role name is refused rather than
    granted. `server/tests/vaults.rs`, `server/tests/admin.rs` and unit tests
    in `src/admin.rs`, `src/vaults.rs` and `src/web/vaults.rs`.

- **Phase 10 — Browser sign-in for desktop apps.** ✅ *(done 2026-08-10)*
  The desktop app asked for an account email and password in its own window.
  That put credentials in a client that has no business holding them, and it
  could not offer registration at all — a new user had to find the website
  first. Now the app opens a *device link* and the browser does the signing in.

  - **The shape.** `POST /api/v1/auth/device` opens a link, returning a public
    `link_id` (for the URL), a secret `poll_token` (for the app alone), a
    display-only `user_code`, a 24-hour expiry and the `interval` to poll at.
    The app opens `/link/{link_id}`; the browser signs in and **visiting the
    page approves it** — no confirm button, because the flow the user is
    already in is "open the page, come back signed in".
    `POST /auth/device/poll` then hands over an ordinary 30-day session.
  - **The token is minted on claim, never stored on the link.** Issuing it at
    approval would leave a live credential behind every time somebody approved
    and closed the browser before the app collected it, and would put a second
    bearer token at rest in a second table.
  - **`claim` is one atomic store call** (`DELETE … WHERE status='approved' …
    RETURNING`). `get` + check + `delete` would let two concurrent polls both
    mint a session from one approval.
  - **The poll re-checks the ban.** `issue_session` does not — only
    `authenticate` and `resolve_session` do — and a ban can land between
    approving and claiming, which would otherwise make this the one path a
    banned account still gets a fresh token.
  - **One answer for every dead end.** Unknown, expired and already-claimed
    poll tokens all get `expired`, so the endpoint never confirms that a
    guessed token once existed. The same reasoning as `reject_session`.
  - **The user code is a comparison aid, not a credential.** `start` needs no
    authentication — it cannot, since the point is to obtain some — so anyone
    can open a link and try to talk a signed-in user into visiting it. The app
    and the page show the same code and the page says to compare them. There
    is deliberately **no form that accepts a code**: that would turn it into a
    second, short, guessable secret.
  - **Links do not accumulate.** Cancelling (the app closing its sign-in pane)
    deletes the link at once via `POST /auth/device/cancel`; anything else is
    swept at 24 hours by `delete_expired`, called from the create path. No
    background job — this server has none and should not grow one.
  - **`?link=<uuid>` survives login and registration**, as a uuid rather than a
    general `next=`, so there is no open redirect to get wrong. The
    already-signed-in bounce honours it too, or "Sign in" from the link page
    would dead-end anyone who still had a cookie.
  - **Its own rate limiter** (120/min against auth's 20): a client polling
    every few seconds would otherwise exhaust the login budget in half a
    minute, and several devices can share one NAT address.
  - **Phase gate:** ✅ start → pending → register carrying the link → the page
    approves → the app's poll returns a token that authenticates
    `GET /api/v1/me` and appears in the device list under the `os@host` label
    the app sent; a link collects once; a reload mints no second session; the
    link id is useless as a poll token; deny, CSRF rejection, cancel, the
    24-hour sweep and the banned-account refusal all hold.
    `server/tests/device_link.rs` (15 tests) plus unit tests in
    `src/devicelink.rs` and `src/store/sqlite.rs`, and the client half in
    `core/src/storage/server.rs` (9 tests over the fake server).

- **Phase 11 — reCAPTCHA on the website's auth forms.** ✅ *(done 2026-08-10)*
  The rate limiter is a blunt instrument on `/login` and `/register`: it is
  keyed by address, and a botnet or a NAT'd office defeats or is punished by
  it in turn. Google reCAPTCHA **v3** now scores every submit on those two
  forms, behind `ASKRYPT_RECAPTCHA_SITE_KEY` — unset, nothing changes.

  - **v3, not v2.** No checkbox and no challenge: the page mints a scored
    token and the server decides. The alternative buys a visible widget at the
    cost of a click on every sign-in.
  - **Checked before the credentials.** `web::captcha::check` runs ahead of
    `authenticate`/`register_account`, so a flood of guesses never buys an
    argon2 hash. That ordering is the security property, and it is what
    `tests/captcha.rs` pins.
  - **The action is bound.** A v3 token names the form it was minted for and
    the verifier insists on a match, so a token from the registration page
    cannot be spent on the login one — and neither can one minted on some
    cheap page an attacker copied the site key onto.
  - **It fails closed.** An unreachable Google or a wrong secret refuses
    everyone, logged at `error` as an outage rather than as a caught bot. The
    alternative — waving submits through when the verifier is down — makes
    the protection removable by whoever is attacking it.
  - **Two rules of the website bend, here and nowhere else.** These forms need
    **JavaScript** (a v3 token can only be minted in the page), and they send
    a widened CSP (`hardening::CSP_CAPTCHA`) naming Google's two script hosts
    and allowing inline *styles* for reCAPTCHA's badge. `script-src` still
    carries no `'unsafe-inline'`, and every other route keeps the strict
    policy byte for byte. Opt-in is the `RelaxedCsp` response extension, so
    the header is still written in exactly one place.
  - **The JSON API is deliberately not captcha'd.** Desktop and mobile cannot
    mint a token, and the desktop's browser sign-in already lands on `/login`.
    `/api/v1/auth` keeps its 20/min limiter. This is a **known bypass** for
    anything willing to post JSON — closing it means shipping a token minter
    to the native clients, which is Phase-scale work of its own.
  - **Phase gate:** ✅ the site key and both scripts on the two pages; the CSP
    widened on exactly those two and only with a captcha configured; a missing
    token refused with advice about JavaScript rather than a 4xx; a token from
    the other form refused; a low score refused; the spent token not echoed
    back; the JSON API untouched; and a wrong password with a bad token
    yielding the captcha message, which is how you can see argon2 was never
    reached. `server/tests/captcha.rs` (12 tests) plus unit tests in
    `src/store/recaptcha.rs` and `src/config.rs`.

- **Phase 12 — Server settings and the registration switch.** ✅ *(done
  2026-08-13)*
  Everything about a running server was fixed at startup by the `ASKRYPT_*`
  environment or scoped to one account. An operator had no way to say "this
  server is not taking new accounts" — not on a self-hosted instance, and not
  on the public one — short of a restart with a config that did not exist.

  - **A key/value table, not a column per switch.** `settings (key, value,
    updated_at)` behind a new `SettingsStore` seam (`get`/`set`, no `delete`),
    with the typed reading of each key in `src/settings.rs`. A second setting
    is a `pub const` plus an accessor; the stores stay key-generic, like the
    role stores are name-generic.
  - **An unwritten key means the default.** The migration seeds *nothing* and
    `MemorySettingsStore` starts empty, so an existing database reads exactly
    as it behaved before the key existed. A value this build does not
    understand and a store failure read as the default too — the second is a
    deliberate fail-*open*, since the database that could not answer could not
    have created the account either.
  - **A new numbered migration**, `0005_settings.sql`, not an edit to
    `0002_auth.sql` the way Phase 8 added `roles`. `sqlx::migrate!` validates
    the checksum of every applied migration, and this server is deployed now:
    editing one it has already run would abort its startup.
  - **The gate is in `crate::auth`, once per creation path.**
    `register_account` checks first, before `validate_email`, so a closed
    server neither spends an argon2 hash nor answers differently for an
    address that is taken; that one edit covers the JSON API, the browser form
    and the `?link=` device-link registration that routes through it.
    `upsert_google_account` checks inside its `None` arm only, so signing in
    with an existing Google account and *linking* Google to an existing
    address both stay open.
  - **The register page keeps its form and warns.** Hiding it would leave a
    visitor who actually has an account with nowhere to go, and the warning is
    only a warning: `register_account` is what refuses, so the two cannot
    disagree if the switch is flipped between the GET and the POST.
  - **`/admin/settings` is HTML only**, behind the same `AdminSession` and the
    same shared limiter as the Users page, with no `/api/v1/admin/*` — the
    Phase 8 rule. The switch is a hidden `enabled=true|false` field rather
    than a checkbox: an unchecked checkbox submits nothing, so "off" and "the
    field never arrived" would be the same request, and the CSP forbids the
    script that would paper over it.
  - **Phase gate:** ✅ a server nobody configured is open; the page is
    advertised and reachable only to administrators; the switch survives and
    flips back; the htmx swap and its CSRF rejection; and what "closed"
    refuses — the browser form still rendering but answering 200 with the
    refusal, the JSON API answering 403 `registration_disabled`, Google
    refused for a new address but still linking to an existing one, and
    password sign-in untouched on both surfaces. `server/tests/settings.rs`
    (9 tests) plus unit tests in `src/settings.rs` and both store backends.

- **Phase 13 — "Sign in with Google" on the website.** ✅ *(done 2026-08-14)*
  The one thing Phase 7 deferred. `ASKRYPT_GOOGLE_CLIENT_IDS` turned on a JSON
  endpoint native clients could post an ID token to, and nothing visible: the
  website had no button, so an operator who configured Google sign-in saw no
  difference anywhere they could look.

  - **Google Identity Services, not the authorization-code flow.** GIS mints
    the ID token *in the page*, so the server needs no client secret, no
    `redirect_uri`, no token-endpoint call and no PKCE — and it verifies the
    result with the `IdTokenVerifier` it already had. The whole feature
    converges on `auth::upsert_google_account`, which is where creating,
    linking, the registration switch and the ban check already live; nothing
    about the account rules is re-implemented for the browser.
  - **The credential is posted same-origin.** Google offers to POST it to us
    directly (`ux_mode: redirect`), but that arrives cross-site, where none of
    our `SameSite=Lax` cookies are sent — the CSRF token included. That form
    would have to be exempted from `web::csrf` and re-protected with Google's
    own `g_csrf_token`: a second CSRF scheme guarding the one endpoint that
    hands out sessions. Signing in through a popup and posting the credential
    to `/auth/google` keeps the site at one scheme, and this form goes through
    the same `CsrfForm` as every other mutation.
  - **Two headers widen, on two pages, for what the page actually loads.**
    `RelaxedCsp` grew from a marker into two flags, so `hardening::policy`
    picks among four written-out policies: a page with a captcha and no button
    is not handed the sign-in host, and vice versa. `CSP_GOOGLE` names only
    path-scoped sources out of the list Google publishes for this library,
    and concedes `'unsafe-inline'` in `style-src` alone — Identity Services
    styles the button it draws with inline `style` attributes, and without it
    the button renders unstyled; `script-src` stays as strict as the base
    policy in all four. `Cross-Origin-Opener-Policy` relaxes to
    `same-origin-allow-popups` only there: a popup cannot answer its opener
    under plain `same-origin`, which is a silent failure rather than a
    console error.
  - **The verifier is asked whether there is a button**, not the config —
    `IdTokenVerifier::web_client_id`, the mirror of
    `CaptchaVerifier::site_key`. A page can therefore only ever offer a button
    whose credential this server is able to check.
  - **No new configuration.** The button is rendered with the **first** of
    `ASKRYPT_GOOGLE_CLIENT_IDS`, so a deployment gets it by setting what it
    already set. A variable of its own was written and then removed: it would
    have needed a rule keeping the two in step (a web client id missing from
    the audience list renders a button whose every sign-in is refused for a
    wrong `aud`), and taking the id *from* that list makes the same invariant
    free. It buys nothing else either — nothing in a client id says what kind
    of OAuth client it belongs to, so neither spelling can catch the one real
    mistake, which is naming a native client. That is a documented convention
    instead: list the Web-application id first, and the startup log prints the
    one the button will carry.
  - **The card is a `<div>` now.** It holds two forms — the password one and
    the hidden one the button submits — and HTML forbids nesting them, so
    `hx-target` names `#auth-form` instead of `this`. The password form is
    untouched and still works with scripts off.
  - **Phase gate:** ✅ both pages carry the client id, the library, the helper
    and the credential form; the two forms are siblings inside one card; the
    widened CSP and opener policy land on exactly those two pages and only
    with a button configured; a valid credential creates the account and signs
    in; a second one reuses it; a matching address links to an existing
    password account and leaves the password working; a device link survives
    the round trip; and the refusals — no credential (advice about
    JavaScript), an unverifiable one, an unverified Google address, a banned
    account, a closed server (new addresses only), a missing or forged CSRF
    token, and `GET` refused outright. `server/tests/google_signin.rs`
    (15 tests) plus unit tests in `src/hardening.rs` and `src/config.rs`.

- **Phase 14 — the in-browser vault viewer.** ✅ *(done 2026-08-20)*
  `/open` unlocks and edits a vault in the visitor's browser. It reverses a
  decision this plan recorded twice — the landing page and the footer both
  said the site could not open a vault — and the reversal is worth stating
  plainly rather than burying.

  - **What did not change.** The server stores opaque bytes, never sees an
    answer, a master key or a plaintext entry, and still does not link
    `askrypt-core`. Nothing about the account, quota, versioning or `If-Match`
    rules moved: the page reads through `vaults::download` (cookie-authed
    because a browser cannot set an `Authorization` header) and writes through
    `POST /vaults/{id}/replace`, the file manager's own replace. `web/open.rs`
    has **no POST at all**; a second write door would be a second place for
    those rules to drift.
  - **What is honestly weaker, and said on the page.** The code is JavaScript
    *this server sent*, so a compromised or dishonest server could send
    different JavaScript. A desktop or mobile app was installed once and the
    server has no say in it. The page says so, names the trade, and links its
    two scripts to be read.
  - **Bounded everywhere else.** No CDN, no bundler, no dependency, no inline
    script, and — unlike the captcha and Google-button pages — **no widened
    CSP**: `script-src 'self'` and `connect-src 'self'` already cover it.
    Nothing is persisted in the browser: no `localStorage`, no
    `sessionStorage`, no IndexedDB, no URL fragment, no console. Locking drops
    one state object and there is nowhere else for a secret to be.
  - **A third implementation of the format, not a fourth trust boundary.**
    `static/vault-format.js` is a port of `core/src/lib.rs` following
    `app/lib/crypto/` function for function, over the Web Cryptography API —
    PBKDF2-HMAC-SHA256, AES-256-CBC/PKCS#7, SHA-256, and
    `DecompressionStream("deflate-raw")` for the ZIP — which is why it is a
    few hundred lines rather than a wasm build of `core/`. It is pure by
    contract (no DOM, no `fetch`, no globals) because
    `scripts/vault-js-parity.mjs` imports the *shipped* file unchanged under
    Node and checks it against the same golden vectors the Dart port uses.
    Not wired into CI, for the reason this plan already gives about Node: run
    it by hand alongside `flutter test`.
  - **Two caps the format cannot enforce itself.** `params` is unauthenticated
    (`SPEC.md`, "Integrity: not provided"), so the port bounds the inflated
    JSON at 1 MiB, matching `vaultfile`, and `params.iterations` at 5,000,000
    — production is 600,000, and without the cap a crafted file could park a
    phone in a derivation for the afternoon.
  - **Signed-out visitors get the page.** Opening a `.askrypt` file off the
    device needs no account, and that is the case the page is most useful in
    — someone on a borrowed phone with their vault on a memory stick. So
    `OpenPage.vaults` is an `Option`: `None` is "nobody is signed in",
    `Some(empty)` is "an account with nothing stored", and the two render
    differently.
  - **The picker is re-readable on its own** (`GET /open/vaults`), because a
    save moves the file's ETag and the value the page was rendered with would
    then be refused for a conflict the visitor did not cause. It also backs
    Refresh, for the reason the desktop's wizard refetches every time it
    opens: a listing cached per sign-in hides vaults saved since.
  - **Phase gate:** ✅ the page serves a signed-out visitor with a file input
    and no listing; an empty account renders the list saying it is empty
    rather than omitting it; rows carry id, name and ETag plus the CSRF token
    the save posts with; the picker is re-readable as a bare fragment and not
    by a signed-out visitor; the file manager deep-links each row; a hostile
    vault name cannot inject markup; and `/open` carries no inline script or
    style, signed in or out. `server/tests/web.rs` (48 tests, six of them
    `/open`) plus `scripts/vault-js-parity.mjs` (41 checks) for the crypto.

## Open decisions (not blocking)

- ~~Client-side sync UX for **desktop**~~ — decided and built: manual
  open/save, not background sync. `core/src/storage/server.rs` implements
  `VaultStorage` over `/api/v1/vaults` behind core's default-off
  `server-storage` feature, and the desktop's `src/panes/wizard.rs` server step
  is the sign-in + vault-picker (the same pane serves Open and Save As).
  Conflicts are *detected*, not merged: the `If-Match` ETag
  round trip surfaces a stale write as `StorageError::Conflict`, and the app
  tells the user to reload. Saves are now asynchronous (`Session::save_request`
  → `write_vault` on a worker → `Session::apply_saved`); still open there is a
  real reload/merge affordance.
- Client-side sync UX for **mobile** (`app/`): the Dart client for the same
  endpoints, plus how it interacts with SAF/`recent_vault_store`.
- Which email service to point `ASKRYPT_SMTP_*` at in production (any SMTP
  relay works; a provider-API impl of `Mailer` is the alternative).
- Trigger points for adding the Postgres and S3 trait impls (the trait layer
  makes this additive — no handler changes).
- Multiple vaults per user vs a single primary vault (API assumes multiple).
- More OAuth providers (Apple, GitHub) and a provider unlink flow — additive
  thanks to the `IdTokenVerifier` trait layer.
- ~~In-browser vault unlock is out of scope~~ — **reversed and shipped in
  Phase 14.** The estimate here was wrong in its premise: it assumed the only
  route was compiling `core/` to `wasm32-unknown-unknown` and running PBKDF2
  in a Web Worker, "a genuinely separate project". Every primitive the format
  needs turned out to be native to the Web Cryptography API, so the port is a
  few hundred lines of dependency-free JavaScript
  (`server/static/vault-format.js`) rather than a wasm build — and it keeps
  parity with the same golden vectors as the Dart port, exactly as this entry
  said it would have to. Still no JS framework, no bundler and no Node in the
  build.
- ~~Web session cookie lifetime~~ — **decided in 7.2: 7 days**, against the
  API's 30. An *idle* timeout is still open; `SessionStore` has no
  last-seen column, so it would be a schema change rather than a constant.
- ~~How web sessions are labelled~~ — **decided in 7.2: `"Web browser"`**,
  with no user-agent string stored.

## Verification commands

```
cargo test -p askrypt-server
cargo clippy -p askrypt-server --all-targets
cargo run -p askrypt-server        # then curl /healthz, /api/v1/... smoke checks
cargo test --workspace             # desktop/core remain green

# The live gate: every endpoint, over a real socket, as both an administrator
# and a plain account. Starts and stops its own throwaway server, and refuses
# any host that is not loopback.
scripts/server-roundtrip.sh
scripts/server-roundtrip.sh --backend sqlite   # the real stores, not the fakes
```

`server/tests/` runs against an in-process router with in-memory fakes;
`scripts/server-roundtrip.sh` is the other half — a real process, real sockets,
the SQLite stores and the disk blob store. A phase is not finished until both
are green. The suite lives in `core/examples/server_roundtrip/` because no
crate may link `askrypt-core` and `askrypt-server` at once.
