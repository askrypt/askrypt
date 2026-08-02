# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Askrypt is a cross-platform password manager. It authenticates users via security question answers (normalized and hashed with PBKDF2) rather than a master password, using AES-256-CBC encryption for vault data. The repository is a Cargo workspace holding a **desktop Rust app** plus a **pure-Dart Flutter mobile app** (`app/`) that re-implements the same vault format — see [Mobile app](#mobile-app-app) below.

**Warning**: The project is under active development and has not undergone extensive security testing.

> **Rule — keep this file current.** At the end of any change that alters the
> repository layout, architecture, build/test commands, dependencies, or the
> vault format, update `CLAUDE.md` (and, for mobile work, `app/PLAN.md`) in the
> same change so the docs never drift from the code.

> **Rule — print a short commit when changes are done.** After completing a
> code change, print a short, conventional commit message (a single
> `type: subject` line, ≤ 72 chars) for the change so it's ready to copy. This
> only prints the message — do not run `git commit` unless asked.

## Architecture

The crypto/format engine lives in the **`core/`** crate (`askrypt-core`, lib name `askrypt`) and is the source of truth for the vault format. The desktop Iced app in **`src/`** depends on it, and the Dart mobile core in **`app/lib/crypto/`** re-implements it (kept in lock-step by golden test vectors). Phase 0 extracted the engine into `core/`; older docs may still say it lives in `src/`.

### Core crate — `core/src/` (the security model)

- **`core/src/types.rs`** — Core data types: `SecretEntry`, `Params`, `QuestionsData`, `MasterData`, `AskryptFile`. Re-exported from `lib.rs`.
- **`core/src/lib.rs`** — Crypto core: encryption (AES-256-CBC), key derivation (PBKDF2/SHA-256), ZIP archive handling, serialization, and `to_bytes`/`from_bytes` (in-memory ZIP). `save_to_file`/`load_from_file` are thin conveniences over `LocalFileStorage`. Contains 25+ unit tests. This is the heart of the security model.
- **`core/src/storage/`** — `VaultStorage` trait (`mod.rs`): the backend-agnostic persistence seam over opaque vault bytes (`read`/`write`/`exists`/`location` plus `load_vault`/`save_vault` default methods built on `to_bytes`/`from_bytes`). Sync, object-safe, `Send + Sync`; errors are the dedicated `StorageError` (`Io`/`Format`, `#[non_exhaustive]`). `mod.rs` also holds `MemoryStorage` (tests/fakes); the filesystem impl `LocalFileStorage` lives in `local_file.rs`, and future backends get their own file each (a server backend implements the trait client-side, keeping HTTP deps out of core).
- **`core/src/passgen.rs`** — Password generator with configurable character sets and length.
- **`core/src/translit.rs`** — Russian/Ukrainian-to-English transliteration using BGN/PCGN romanization, QWERTY-only output. ё→yo, е→e, ъ/ь dropped, тс and ц both→ts. Ukrainian: ґ→g, є→ye, і→i, ї→yi.
- **`core/examples/gen_vectors.rs`** — Emits golden test vectors to `app/test/fixtures/vectors.json` for the Dart parity tests. Regenerate whenever the format or normalization changes.

### Desktop app — `src/` (Iced GUI)

The Iced GUI follows an Elm-like architecture, split into a small app shell plus one module per screen. Each screen owns its UI state and message enum and only touches shared state through `&mut Session`; navigation is expressed by returning a `screens::Action` rather than by mutating the active screen directly.

- **`src/main.rs`** — Thin entry point: `iced::application(...)` wiring (window, theme, fonts, subscription) and `load_icon()`. No app logic.
- **`src/app.rs`** — `AskryptApp { session, screen }`, the shell. `update()` clears status messages then dispatches each `Message` to the matching screen's `update`; `update_global()` handles the cross-cutting `GlobalMsg` events (window/keyboard, tray, spinner tick, save, Smart Lock lifecycle, exit); `apply()` turns a screen's `Action` into a screen switch + `Task`. Also holds `view()` dispatch, `title()`, `subscription()`, and the Smart Lock activation/creation helpers. Every PBKDF2-heavy path — first-answer key check, full unlock, and both Smart Lock activation (2M-iteration encrypt) and unlock (2M-iteration recover + full decrypt) — runs off the main thread via `Task::perform` + `tokio::task::spawn_blocking`, showing `ui::spinner_row` (captioned "Decrypting…"/"Locking…") while the work runs; `session.decrypting` guards re-entry.
- **`src/session.rs`** — `Session`: all screen-independent shared state (loaded vault, decrypted secrets, settings, tray, status/error messages, spinner state) plus vault-lifecycle helpers (`save_vault`/`save_vault_as`, `ask_user_about_changes`, activity/timeout checks, `zeroize_secrets`) and the Smart Lock crypto statics (`create_smart_lock_data`/`decrypt_smart_lock_data`). Also defines `SmartLockData`, `SmartUnlockResult`, and the iteration/timeout constants. The vault's whereabouts live in `Session.location: Option<VaultLocation>`; all load/save goes through `location.storage()` (a `Box<dyn VaultStorage>`), never raw paths.
- **`src/message.rs`** — Top-level `Message` wrapping each screen's `Msg` enum, plus `GlobalMsg` for cross-cutting events.
- **`src/screens/`** — One module per screen: `welcome`, `questions` (Edit Questions; includes the "Use transliteration" checkbox), `unlock` (the `FirstQuestion` + `OtherQuestions` layered-unlock screens), `entries`, `entry_editor`, `passgen`, `smart_lock`. Each exposes a `State` struct, a `Msg` enum, `update(state, session, msg) -> Action`, and `view(state, session) -> Element<Message>`. `screens/mod.rs` defines the `Screen` enum (owns each `State`), the `Action` enum, and the shared Session-reading view chrome (`status_bar`, `show_messages_in_column`, `show_vault_path`). The password generator opened from the entry editor carries the editor's `State` in `passgen::State::return_to` so "Copy and use" restores it. Screen states holding secrets wipe on drop: `questions::State` (answers) and `smart_lock::State` (typed answer) have `Drop` impls; `entry_editor::State`'s secret is wiped by `SecretEntry`'s own `ZeroizeOnDrop`.
- **`src/ui.rs`** — Reusable styled UI components and theming helpers, generic over the message type (`title_h1`, `controls_block`, `caption_block`, `container_with_border`, `security_input_with_toggle`, `spinner_row`, buttons, link/border styles).
- **`src/icon.rs`** — Bootstrap icon glyph constants for use in the UI.
- **`src/tray.rs`** — System-tray integration.
- **`src/settings.rs`** — Persistent user settings stored as JSON in platform config directories: `%APPDATA%\askrypt\` (Windows), `~/Library/Application Support/askrypt/` (macOS), `~/.config/askrypt/` (Linux). Also defines `VaultLocation`, the serializable identity of a vault's storage backend (`#[serde(untagged)]`; today only `LocalFile(PathBuf)`, which serializes as a plain path string so old `settings.json` files stay compatible) with the `storage()` factory returning `Box<dyn VaultStorage>` — a future `Server { .. }` variant adds a match arm there.

### Security / Encryption Model

1. User provides answers to security questions.
2. Answers are normalized (lowercased, whitespace/dashes stripped, optionally transliterated from Russian/Ukrainian via `Params.translit`).
3. Each answer is used with PBKDF2 (600,000 iterations by default) to derive a key.
4. A layered encryption scheme: first answer unlocks subsequent questions, all answers together unlock the master key, the master key encrypts the actual secrets.
5. Vault files are ZIP archives containing JSON metadata and encrypted blobs. See `SPEC.md` for the full format specification.

Secret material is wiped from memory with [`zeroize`](https://docs.rs/zeroize): the secret-bearing structs (`SecretEntry`, `MasterData`, `QuestionsData`) derive `ZeroizeOnDrop`, and transient scratch (derived keys, normalized/combined answers, hashed answers, decrypted plaintext buffers) is wrapped in `Zeroizing` in `core/src/lib.rs` and the desktop Smart Lock paths. Note: `core` derives keys via the `derive_key` helper rather than `calc_pbkdf2(..)?.try_into()`, which would free the PBKDF2 `Vec` without wiping it; in the desktop app the lock/Smart-Lock handlers `.zeroize()` secrets instead of `.clear()` (which only truncates). The `aes`/`cbc` cipher's internal key copy is not reachable and stays unwiped. The Dart mobile app has no equivalent (GC'd, immutable strings).

### Mobile app — `app/`

A **pure-Dart Flutter** app for Android + iOS (no Rust on device, no FFI/bridge). It re-implements the vault format in Dart and must stay byte-compatible with `core/`; parity is guaranteed by golden test vectors, not shared code. Full plan and phase status live in **`app/PLAN.md`**.

- **`app/lib/crypto/`** — Dart port of the crypto core (`vault`, `kdf`, `aes`, `normalize`, `translit`, `secret_entry`), mirroring `core/src/*.rs`.
- **`app/lib/session/`** — Riverpod session layer: `UnlockedVault` (in-memory state, secret-free `EntrySummary`, reveal-on-demand CRUD, `toBytes()`) and a sealed `VaultSession` (`VaultLocked`/`VaultUnlocked`) behind `vaultSessionProvider`. The 600k-iteration PBKDF2 work is CPU-bound, so `pbkdf2` (`crypto/kdf.dart`) delegates to native, hardware-accelerated platform crypto via `cryptography_flutter` (Android `javax.crypto` / iOS CommonCrypto), falling back to the `cryptography` Dart impl off-device (tests) — byte-identical output, verified by the golden vectors. Native runs without blocking the Dart event loop, so the crypto entry points are plain `async` and `await`ed on the main isolate (no `Isolate.run`): `AskryptFile.getQuestionsData`/`create`, `UnlockedVault.open`/`toBytes`. The unlock screen shows a progress indicator while a derivation runs.
- **`app/lib/screens/`** — Feature-parity screens (welcome, layered unlock, entries list + search/tags/hidden, entry editor, questions editor, password generator) plus `auto_lock.dart` (lock on background / inactivity).
- **`app/lib/passgen.dart`** — Dart port of `core/src/passgen.rs`.
- **`app/lib/platform/`** — Platform seams, faked in tests: `vault_io.dart` (over `file_picker`); `recent_vault_store.dart` (caches the **encrypted** bytes + name of the last successfully unlocked vault in the app-support dir via `path_provider` — SAF URIs have no persistable path — refreshed on unlock/save, behind the welcome screen's "Open \<name\>" reopen button); and the Phase 4 mobile-security seams `biometric_store.dart` (answers-only biometric quick-unlock via `local_auth` + `flutter_secure_storage`, keyed by `sha256(question0)`; the unlock screen additionally asks one randomly chosen security answer as a knowledge check before opening), `secure_clipboard.dart` (sensitive copy + 30 s auto-clear), and `platform_security.dart` (the `MethodChannel('askrypt/secure')` for `FLAG_SECURE` + sensitive-clipboard, implemented in `MainActivity.kt`/`AppDelegate.swift`).
- **`app/test/`** — Crypto parity tests against `app/test/fixtures/vectors.json`, session tests, passgen tests, and widget tests.

App ID `com.askrypt.app`, display name "Askrypt", `minSdk 26`. The `android/` and `ios/` shells are tracked in git.

**Android toolchain is pinned** (`app/android/settings.gradle.kts` + `gradle-wrapper.properties`) to **AGP 8.11.1 / Gradle 8.14 / Kotlin 2.2.20**, not the `flutter create` default of AGP 9.x: file_picker 11.x doesn't apply the Kotlin Gradle plugin on AGP ≥ 9, so its plugin class fails to compile. Floor is AGP ≥ 8.9.1 + compileSdk 36 (`androidx.core 1.17.0`, pulled by Flutter 3.44.1). `flutter build apk --debug` is green against the SDK at `~/Android/Sdk`. Don't bump AGP to 9 until file_picker supports it.

`MainActivity` extends **`FlutterFragmentActivity`** (not the default `FlutterActivity`) because `local_auth`'s biometric prompt requires a `FragmentActivity` host; it also registers the `askrypt/secure` channel. iOS needs `NSFaceIDUsageDescription` in `Info.plist`.

### Server — `server/` (`askrypt-server`)

A Rust (axum) server providing accounts (email + password, plus Google
sign-in) and cloud storage of vaults as **opaque encrypted files** — it never
handles questions, answers, or vault crypto, and it must **never depend on
`askrypt-core`**. The phased plan lives in **`server/PLAN.md`**; Phases 0
(scaffolding), 1 (landing page + API namespacing), 2 (auth: register, login,
Google sign-in), 3 (profile API) and 4 (vault cloud storage) are done,
Phase 5 (hardening & deployment) is next.

- **`server/src/main.rs`** — Startup: tracing init (`RUST_LOG`), env-var config,
  backend selection, graceful shutdown (Ctrl+C/SIGTERM). The `sqlite` backend
  wires `SqliteAccountStore`/`SqliteSessionStore`/`SqliteVaultMetaStore` plus
  the on-disk `DiskVaultBlobStore` (only the mailer stays in-memory); the
  Google verifier is real when `ASKRYPT_GOOGLE_CLIENT_IDS` is set, else
  `NotConfiguredIdTokenVerifier` (501). Serves with `ConnectInfo` so rate
  limiting can key on peer IPs.
- **`server/src/config.rs`** — `Config::from_env()`: `ASKRYPT_BIND`
  (default `127.0.0.1:8080`), `ASKRYPT_DATA_DIR` (default `data`, gitignored),
  `ASKRYPT_BACKEND` (`sqlite` default | `memory`), `ASKRYPT_STATIC_DIR`
  (default `server/static`, i.e. `cargo run` from the workspace root),
  `ASKRYPT_GOOGLE_CLIENT_IDS` (comma-separated ID-token audiences; empty
  disables Google sign-in).
- **`server/src/error.rs`** — Uniform JSON error convention: every API error is
  `{"error": {"code", "message"}}` via `ApiError` (`IntoResponse`), with
  `From<StoreError>`/`From<IdTokenError>`; internal details are logged, never
  sent to clients. `ApiJson<T>` and `ApiBytes` are the `Json`/`Bytes`
  extractor variants whose rejections keep the envelope.
- **`server/src/routes.rs`** — Router: `/healthz`; `/api/v1` nest (`GET
  /about`, the `/me` profile tree, the `/vaults` tree, and
  `/auth/{register,login,google,logout}` behind a 20 req/min fixed-window
  rate limiter) with a JSON 404 fallback covering everything under `/api`;
  all other paths serve static assets from the configured static dir
  (`tower-http` `ServeDir`) with SPA fallback to `index.html` —
  `server/static/` ships a placeholder landing page until Phase 7. The vault
  routes carry a raised `DefaultBodyLimit` sized to `MAX_VAULT_BYTES`.
- **`server/src/auth.rs`** — Phase 2 auth: register (email normalization +
  validation, ≥8-char passwords, argon2 hashing on `spawn_blocking`), login
  (uniform 401 `invalid_credentials`; 256-bit hex bearer tokens, 30-day
  sessions), Google sign-in (verifies via the `IdTokenVerifier` trait,
  requires `email_verified`, creates or links the account by verified email),
  logout, and the `AuthSession` extractor (`Authorization: Bearer` →
  session + account) used by protected routes.
- **`server/src/profile.rs`** — Phase 3 profile API under `/api/v1/me`:
  `GET /me` (full profile incl. linked providers), `PUT /me/email`,
  `PUT /me/password` (current-password re-auth when one exists; sets the
  first password on Google-created accounts), `GET /me/sessions` +
  `DELETE /me/sessions/{id}` (sessions are identified by a SHA-256 digest of
  the bearer token so listings never leak tokens; `current` flags the
  caller's), and `DELETE /me` (cascades vault blobs → vault metadata →
  sessions → account). The email/password mutations sit behind their own
  20 req/min rate limiter.
- **`server/src/vaults.rs`** — Phase 4 vault file API under `/api/v1/vaults`:
  list, upload (`POST ?name=`), download, overwrite (`PUT /{id}`), rename
  (`PUT /{id}/name`) and delete, all scoped to the authenticated account.
  Bytes stay opaque apart from a ZIP-magic check. ETags are the SHA-256 of
  the stored bytes: downloads honor `If-None-Match` (304), overwrites
  require `If-Match` (428 without it, 412 when stale) so multi-device sync
  detects conflicts. Enforces `MAX_VAULT_BYTES` (10 MiB),
  `ACCOUNT_QUOTA_BYTES` (100 MiB) and `MAX_VAULTS_PER_ACCOUNT` (100).
- **`server/src/ratelimit.rs`** — In-memory fixed-window `RateLimiter` +
  axum middleware, keyed by first `X-Forwarded-For` address, else peer IP.
- **`server/src/state.rs`** — `AppState`: one `Arc<dyn Trait>` per backend
  seam; handlers can only reach the traits.
- **`server/src/store/`** — The backend traits (`mod.rs`): `AccountStore`,
  `SessionStore`, `VaultMetaStore`, `VaultBlobStore`, `Mailer`,
  `IdTokenVerifier` (+ `StoreError`/`MailerError`/`IdTokenError`, all
  `#[non_exhaustive]`); `memory.rs` in-memory fakes for all six (used by tests
  and the `memory` backend); `sqlite.rs` SQLite pool + embedded migration
  runner over `server/migrations/` plus `SqliteAccountStore`/
  `SqliteSessionStore`/`SqliteVaultMetaStore` (uuids as TEXT, timestamps via
  sqlx-chrono, sessions and vault rows cascade on account delete, vault names
  unique per account); `disk.rs` `DiskVaultBlobStore` storing bytes at
  `<data>/vaults/<account-id>/<vault-id>.askrypt` with atomic temp-file +
  rename writes (path components are uuids, so no user string reaches the
  filesystem); `google.rs` `GoogleIdTokenVerifier` (RS256 against Google's
  JWKS, cached with a 60 s refetch floor, issuer/audience/expiry checks) and
  `NotConfiguredIdTokenVerifier`.
- **`server/tests/`** — HTTP-level tests (tower `oneshot`, no socket):
  `http.rs` (routing/static), `auth.rs` (the Phase 2 gate: register →
  login → `/me` → logout, Google new-account + link-to-existing against the
  fake verifier, validation, rate limiting), `profile.rs` (the Phase 3
  gate: providers, email update, change/set password, session list/revoke,
  account-delete cascade incl. the vault stores) and `vaults.rs` (the Phase 4
  gate: upload → list → download → rename → delete, ETag conflict behavior,
  per-account isolation, size/quota/count limits).

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `iced` | Cross-platform GUI (Elm-style) |
| `aes` + `cbc` + `cipher` | AES-256-CBC encryption |
| `pbkdf2` + `sha2` | Key derivation |
| `serde` + `serde_json` | Serialization |
| `zip` | Vault file format (ZIP archive) |
| `rfd` | Native file open/save dialogs |
| `rand` | Random number generation |
| `tokio` | `spawn_blocking` for off-main-thread vault decryption |

### Build & Test

```
# Desktop / core (Rust) — core is the spec source of truth
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p askrypt
# Regenerate Dart parity vectors after any format/normalization change:
cargo run -p askrypt-core --example gen_vectors
# Server (also covered by the --workspace commands above):
cargo run -p askrypt-server      # then curl /healthz

# Mobile (Flutter) — SDK at /home/ruslan/Apps/flutter (add bin to PATH)
cd app && flutter test       # crypto parity + session + passgen + widget tests
cd app && flutter analyze
```

### CI / Release

- `.github/workflows/ci.yml` — Builds and tests on Ubuntu for every push.
- `.github/workflows/release.yml` — Multi-platform release builds (Linux x86_64, macOS ARM64, Windows x86_64 MSVC).
- Windows builds use static C runtime linking (configured in `.cargo/config.toml`).
- `build.rs` embeds the Windows icon resource.
