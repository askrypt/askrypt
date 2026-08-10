# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Askrypt is a cross-platform password manager. It authenticates users via security question answers (normalized and hashed with PBKDF2) rather than a master password, using AES-256-CBC encryption for vault data. The repository is a Cargo workspace holding a **desktop Rust app** plus a **pure-Dart Flutter mobile app** (`app/`) that re-implements the same vault format — see [Mobile app](#mobile-app-app) below. The workspace also carries `gui/`, the new three-pane desktop UI that will replace `src/` — a working client over the same core, not a mock.

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

The dependency arrows only ever point one way: `askrypt` (desktop) and `askrypt-gui` (the new desktop UI) → `askrypt-core`, and **`askrypt-server` depends on neither** — it stores vaults as opaque bytes and must never link the crypto core. Both desktop crates talk to the server through `core`'s `server-storage` backend, which is a *client* of the HTTP API, so that rule is unaffected.

### Core crate — `core/src/` (the security model)

- **`core/src/types.rs`** — Core data types: `SecretEntry`, `Params`, `QuestionsData`, `MasterData`, `AskryptFile`. Re-exported from `lib.rs`. `Params` also carries the optional, **unencrypted** write stamp `host` + `updated_at` (RFC 3339 UTC, second precision), omitted from JSON when absent so pre-stamp vaults round-trip unchanged.
- **`core/src/lib.rs`** — Crypto core: encryption (AES-256-CBC), key derivation (PBKDF2/SHA-256), ZIP archive handling, serialization, and `to_bytes`/`from_bytes` (in-memory ZIP). `save_to_file`/`load_from_file` are thin conveniences over `LocalFileStorage`. `AskryptFile::touch` (called at the end of `create`, i.e. on every save, since saves rebuild the file) stamps `params.host`/`params.updated_at` via the `current_host`/`now_utc_rfc3339` helpers (`gethostname` + `chrono`). Contains 25+ unit tests. This is the heart of the security model.
- **`core/src/storage/`** — `VaultStorage` trait (`mod.rs`): the backend-agnostic persistence seam over opaque vault bytes (`read`/`write`/`exists`/`location` plus `load_vault`/`save_vault` default methods built on `to_bytes`/`from_bytes`). Sync, object-safe, `Send + Sync`; errors are the dedicated `StorageError` (`#[non_exhaustive]`): `Io`/`Format` plus the network variants `Network`/`Auth`/`Conflict`/`Remote { status, code, message }`, all defined **unconditionally** so the error type does not change shape with the feature flags. `mod.rs` also holds `MemoryStorage` (tests/fakes); each backend gets its own file — `local_file.rs` (`LocalFileStorage`) and `server.rs` (`ServerClient` + `ServerStorage`, behind the default-off `server-storage` feature so a plain `cargo build -p askrypt-core` stays free of HTTP/TLS; the desktop crate enables it).
  - `server.rs` is the **client half of the cloud story**: `ServerClient` is one authenticated handle to a server's `/api/v1` (`login`/`with_token`/`logout` + `list`/`create`/`download`/`overwrite`/`rename`/`delete`), and `ServerStorage` is one vault on it, addressed by *name*. Over `ureq` 3 (blocking, rustls/ring), **not** `reqwest::blocking` — the trait is sync and `reqwest::blocking` panics when built inside an async context, which is exactly where the desktop calls it from. The agent sets `http_status_as_error(false)` because the server's `{"error":{"code","message"}}` envelope lives in the body of a 4xx/5xx. ETags are stored unquoted and sent quoted; `read` records the ETag it saw and `write` sends it as `If-Match`, so **a `ServerStorage` instance must live as long as the open vault** — a fresh one would re-resolve the *current* ETag and clobber another device's edit. That invariant is what `Session.storage` exists to hold. `core/examples/server_roundtrip.rs` is the manual end-to-end gate against a running `askrypt-server` (an example, not a test, so no crate ever links both `askrypt-core` and `askrypt-server`).
- **`core/src/passgen.rs`** — Password generator with configurable character sets and length.
- **`core/src/translit.rs`** — Russian/Ukrainian-to-English transliteration using BGN/PCGN romanization, QWERTY-only output. ё→yo, е→e, ъ/ь dropped, тс and ц both→ts. Ukrainian: ґ→g, є→ye, і→i, ї→yi.
- **`core/examples/gen_vectors.rs`** — Emits golden test vectors to `app/test/fixtures/vectors.json` for the Dart parity tests. Regenerate whenever the format or normalization changes.

### Desktop app — `src/` (Iced GUI)

The Iced GUI follows an Elm-like architecture, split into a small app shell plus one module per screen. Each screen owns its UI state and message enum and only touches shared state through `&mut Session`; navigation is expressed by returning a `screens::Action` rather than by mutating the active screen directly.

- **`src/main.rs`** — Thin entry point: `iced::application(...)` wiring (window, theme, fonts, subscription) and `load_icon()`. No app logic.
- **`src/app.rs`** — `AskryptApp { session, screen }`, the shell. `update()` clears status messages then dispatches each `Message` to the matching screen's `update`; `update_global()` handles the cross-cutting `GlobalMsg` events (window/keyboard, tray, spinner tick, save, Smart Lock lifecycle, exit); `apply()` turns a screen's `Action` into a screen switch + `Task`. Also holds `view()` dispatch, `title()`, `subscription()`, and the Smart Lock activation/creation helpers. Every PBKDF2-heavy path — first-answer key check, full unlock, and both Smart Lock activation (2M-iteration encrypt) and unlock (2M-iteration recover + full decrypt) — runs off the main thread via `Task::perform` + `tokio::task::spawn_blocking`, showing `ui::spinner_row` (captioned "Decrypting…"/"Locking…") while the work runs; `session.decrypting` guards re-entry.
- **`src/session.rs`** — `Session`: all screen-independent shared state (loaded vault, decrypted secrets, settings, tray, status/error messages, spinner state) plus vault-lifecycle helpers (`save_vault`/`save_vault_as`, `ask_user_about_changes`, activity/timeout checks, `zeroize_secrets`) and the Smart Lock crypto statics (`create_smart_lock_data`/`decrypt_smart_lock_data`). Also defines `SmartLockData`, `SmartUnlockResult`, and the iteration/timeout constants. The vault's whereabouts live in `Session.location: Option<VaultLocation>` and its **live backend** in `Session.storage: Option<Arc<dyn VaultStorage>>`; all load/save goes through that instance, never raw paths and never a freshly built one — rebuilding per save would throw away a server vault's ETag and silently overwrite another device (`set_vault_location`/`clear_vault_location` keep the pair in step, and `storage_for` is the factory). Also holds the sign-in state `server_client: Option<Arc<ServerClient>>` + `server_email`, with `sign_in`/`sign_out`, `save_vault_to_server(name)`, and `report_storage_error`, which turns a `StorageError` into the sentence shown in the status bar and signs out on `Auth`.
- **`src/message.rs`** — Top-level `Message` wrapping each screen's `Msg` enum, plus `GlobalMsg` for cross-cutting events.
- **`src/screens/`** — One module per screen: `welcome`, `questions` (Edit Questions; includes the "Use transliteration" checkbox), `unlock` (the `FirstQuestion` + `OtherQuestions` layered-unlock screens), `entries`, `entry_editor`, `passgen`, `smart_lock`, `server`. Each exposes a `State` struct, a `Msg` enum, `update(state, session, msg) -> Action`, and `view(state, session) -> Element<Message>`. `screens/mod.rs` defines the `Screen` enum (owns each `State`), the `Action` enum, and the shared Session-reading view chrome (`status_bar`, `show_messages_in_column`, `show_vault_path`, `show_vault_stamp` — the unencrypted `params.host`/`params.updated_at` write stamp, readable before unlock and shown on both unlock screens as "Last saved: \<host\> · \<local time\>"; absent halves simply drop out). The password generator opened from the entry editor carries the editor's `State` in `passgen::State::return_to` so "Copy and use" restores it. Screen states holding secrets wipe on drop: `questions::State` (answers), `smart_lock::State` (typed answer) and `server::State` (typed password) have `Drop` impls; `entry_editor::State`'s secret is wiped by `SecretEntry`'s own `ZeroizeOnDrop`.
  - `server` is the cloud screen, in two `Mode`s: `Open` (reached from Welcome's "Open from Server" — sign in, list the account's vaults, pick one) and `Save` (reached from the entries screen's "Save to Server"). Sign-in, listing and download all run off the main thread via `Task::perform` + `spawn_blocking` under the existing spinner ("Signing in…"/"Loading…"/"Downloading…"). `Msg::VaultOpened` carries the `Arc<ServerStorage>` that did the download, not just the bytes — see the `Session.storage` invariant above. **Saves are still synchronous** (`Session::save_vault` is `&mut self`, called straight from a screen `update`), so a server save briefly blocks the UI; making it async means moving the mutation into a completion message.
- **`src/ui.rs`** — Reusable styled UI components and theming helpers, generic over the message type (`title_h1`, `controls_block`, `caption_block`, `container_with_border`, `security_input_with_toggle`, `spinner_row`, buttons, link/border styles).
- **`src/icon.rs`** — Bootstrap icon glyph constants for use in the UI.
- **`src/tray.rs`** — System-tray integration.
- **`src/settings.rs`** — Persistent user settings stored as JSON in platform config directories (`AppSettings::config_dir`): `%APPDATA%\askrypt\` (Windows), `~/Library/Application Support/askrypt/` (macOS), `~/.config/askrypt/` (Linux). Also defines `VaultLocation`, the serializable identity of a vault's storage backend (`#[serde(untagged)]`): `LocalFile(PathBuf)` serializes as a plain path string so old `settings.json` files stay compatible, and `Server { base_url, email, name }` as an object, which untagged deserialization tells apart — **`LocalFile` must stay the first variant**. Its `storage(client)` factory returns `Arc<dyn VaultStorage>` and fails with `StorageError::Auth` when a server location has no matching signed-in client. A server vault is keyed by *name*, not by the server-assigned id. `ServerSession` (`base_url`/`email`/`token`) is the saved sign-in, deliberately in its own `server_session.json` created `0600` on Unix rather than in `settings.json`: the token is a credential — it authorizes `PUT /me/email` and `DELETE /me`, neither of which re-asks for the password.

### Desktop GUI (new) — `gui/`

`askrypt-gui` is a standalone Iced binary (`cargo run -p askrypt-gui`) carrying the three-pane, Bitwarden-like layout in `uisample.jpg`: a left navigation rail, a middle item list, a right detail pane, a search strip on top and a status bar always pinned to the bottom. **This is the UI that will replace `src/`.** It is a *working* client — real crypto, real local and server vaults, real persistence, over `askrypt-core` with `server-storage`. `src/` remains the shipping app and still builds; swapping the `askrypt` binary over and deleting `src/screens/` is the last open checklist item.

**`gui/README.md` is the port notes** — the state table, the transition table (with the `src/` equivalent of each), the button-visibility table, the invariants and **where each is now enforced**, what is still not real, and the checklist. Keep it current alongside this file.

The **business logic was copied, not shared**: `gui/src/{session,settings,tray}.rs` are ports of `src/{session,settings,tray}.rs`, and `theme.rs`/`icon.rs` copy the helpers from `src/ui.rs`/`src/icon.rs`. `src/` is destined for deletion, so a shared crate would be scaffolding for dead code; the two diverge on purpose. `gui/Cargo.toml` pins the *same* iced feature set as the root package (`image`, `fira-sans`, `tokio`) purely so both builds share one compiled `iced` — cargo unifies features across the packages selected for a build, so a different list means a full iced recompile every time you alternate between the two commands. `include_bytes!` paths are `"../../static/…"` from `gui/src/`.

Files: `main.rs` (`App`/`Section`/`Pane`/`Message`/`VaultMsg`/`GlobalMsg`/`PendingAction`, the `visible()`/`reconcile_selection()` filter pair, `default_pane()`/`effective_pane()`, the subscription, the tray/keyboard handling, and the outer `column![search, row![panes].height(Fill), status_bar]` that keeps the status bar on the bottom edge), `session.rs`, `settings.rs`, `tray.rs`, `vault.rs`, `theme.rs`, `icon.rs` (glyph codepoints read out of the repo's own `bootstrap-icons.ttf` — note the font has no bare `plus`, only `plus-lg`), `data.rs` (pure item helpers over `SecretEntry`: the filter, hash-tags, the unencrypted write stamp, and `DATETIME_FORMAT` — the single local-time rendering, `%b %-d, %Y %H:%M`, that `format_timestamp_local` (Unix seconds) and `format_rfc3339_local` (RFC 3339 text, verbatim when unparseable) both apply, so entry stamps, the write stamp and the server vault listing read alike), and `panes/{mod,sidebar,list,detail,entry_editor,questions,passgen,settings,unlock,wizard,statusbar}.rs`. Selection is an index into `session.entries`, never into the filtered view, so filtering can't invalidate it. Each list row draws `icon::placeholder(&entry.name, ..)` — a stand-in for the favicon or issuer logo a real item would carry, picked from a 16-glyph pool by hashing the name rather than actually randomized, because `view` runs every frame and a random pick would flicker. Unlike `src/app.rs::view`, this crate does **not** wrap its root in a centering container — the panes are full-bleed.

`panes/mod.rs` defines **`Action`** (`None`/`Run`/`Pane`/`PaneRun`) — the same navigation-as-data contract as `src/screens/mod.rs::Action`. A pane's `update(state, &mut Session, msg) -> Action` mutates shared state and *says* where to go; `App::apply` does the switching. The working area right of the rail is **not always two panes**: `view` branches on `Pane`, so `Items` splits it into list + detail (or list + entry editor, when a draft is open) while `Settings`, `Unlock`, `Wizard`, `Questions` and `PassGen` each fill it alone.

`gui/src/session.rs` is the port of `src/session.rs` with one structural change: **saving is asynchronous**. `AskryptFile::create` runs two 600k-iteration derivations, so `Session::save_request()` collects the inputs on the main thread, the free fn `write_vault` re-encrypts and writes on a worker, and `Session::apply_saved()` performs the mutation from the completion message — closing the two paths (`save_vault_as`, `save_vault_to_server`) that still block the UI in `src/`. Failures travel as **`VaultError`**, a `Clone + Debug` classification of `StorageError` (which is neither), logged in full on the worker; `Session::report_vault_error` words it for a save, `describe_sign_in_error`/`describe_open_error` for the server and open paths. `App::guard(PendingAction)` is the unsaved-changes gate: "Yes" starts an async save and replays the queued action from `App.after_save` once it lands, so Lock/Smart Lock/New/Open/Exit all wait for it. Unlike `src/`, **Smart Lock is gated too** — it zeroizes the entries, so an ungated one silently loses unsaved edits — and `App::auto_smart_lock` (the idle timeout, which nobody is present to answer) saves first when the vault has a home and declines to lock when it does not.

`gui/src/vault.rs` holds **`Status::of(&Session)`**, deriving the five vault states (`NoVault`, `Locked`, `PartiallyUnlocked`, `Unlocked`, `SmartLocked`) from `file`/`questions_data`/`unlocked`/`smart_lock_data` rather than storing them, plus the visibility predicates for the rail's vault buttons (New Vault / Open Vault / Unlock / Smart Lock / Lock-Full Lock / Save / Save As / Edit Questions, pinned at the rail's bottom with the password generator, then Quit and Settings
in bands of their own below them) — the sidebar only asks, never matches on the status itself. Buttons are *hidden*, not disabled, when a state disallows them, and the item filters plus the search strip exist only while unlocked (`effective_pane()` also refuses to render the item list over a locked vault; every lock path calls `App::clear_secret_panes`). New Vault is the one action that lands *unlocked* — the questions editor runs and leaves `location: None`, the combination that makes a first Save become a Save As. Open and Save As route through the single `panes::wizard` source picker (Local file via `rfd::AsyncFileDialog`, Askrypt Server via `ServerClient`, and a disabled Cloud-folder placeholder); a plain **Save never reaches the wizard**, because it must write through the backend the vault was opened with (the ETag invariant). Choosing Local file while *saving* opens the native save dialog immediately (`wizard::save_dialog`, prefilled with the vault's name) instead of asking for a file name first — the dialog covers folder and name — so the wizard's file step is Open-only. `gui/src/settings.rs` extends `AppSettings` with `recent_vaults` (a real MRU, feeding the wizard's recent list) plus `theme`/`lock_timeout`/`minimize_to_tray`/`show_hidden_by_default`/`clear_clipboard`/`window`, every one `#[serde(default)]` so a `settings.json` written by `src/` still parses. `window` is a `WindowState` (`size`, optional `position`, `maximized`) restoring the window where the user left it: `main()` reads it *before* building the window, since `boot` runs after. It always stores the geometry the window **unmaximizes** back to — iced has no maximized event, so `App::record_geometry` parks what a move or resize reported and one `window::is_maximized` round trip decides whether `commit_geometry` keeps it, which also debounces a drag to one probe per 250 ms. Values that are nonsense (`WindowState::sane_size`/`sane_position`) are dropped rather than remembered, because Windows reports a minimized window at `-32000, -32000` sized `0 x 0` and this app minimizes to the tray; a stale geometry that fails `is_usable` falls back to the default centered window. The `maximized` flag is re-asserted on `window::Event::Opened`, as some window managers drop `window::Settings::maximized` when a position is given alongside it.

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
- **`app/lib/platform/`** — Platform seams, faked in tests: `vault_io.dart` (over `file_picker`); `host_name.dart` (the `params.host` stamp — OS host name, falling back to the platform name, behind a swappable `hostNameResolver`; `UnlockedVault.toBytes` passes it to `AskryptFile.create`, which stamps `updated_at` itself); `recent_vault_store.dart` (caches the **encrypted** bytes + name of the last successfully unlocked vault in the app-support dir via `path_provider` — SAF URIs have no persistable path — refreshed on unlock/save, behind the welcome screen's "Open \<name\>" reopen button); and the Phase 4 mobile-security seams `biometric_store.dart` (answers-only biometric quick-unlock via `local_auth` + `flutter_secure_storage`, keyed by `sha256(question0)`; the unlock screen additionally asks one randomly chosen security answer as a knowledge check before opening), `secure_clipboard.dart` (sensitive copy + 30 s auto-clear), and `platform_security.dart` (the `MethodChannel('askrypt/secure')` for `FLAG_SECURE` + sensitive-clipboard, implemented in `MainActivity.kt`/`AppDelegate.swift`).
- **`app/test/`** — Crypto parity tests against `app/test/fixtures/vectors.json`, session tests, passgen tests, and widget tests.

App ID `com.askrypt.app`, display name "Askrypt", `minSdk 26`. The `android/` and `ios/` shells are tracked in git.

**Android toolchain is pinned** (`app/android/settings.gradle.kts` + `gradle-wrapper.properties`) to **AGP 8.11.1 / Gradle 8.14 / Kotlin 2.2.20**, not the `flutter create` default of AGP 9.x: file_picker 11.x doesn't apply the Kotlin Gradle plugin on AGP ≥ 9, so its plugin class fails to compile. Floor is AGP ≥ 8.9.1 + compileSdk 36 (`androidx.core 1.17.0`, pulled by Flutter 3.44.1). `flutter build apk --debug` is green against the SDK at `~/Android/Sdk`. Don't bump AGP to 9 until file_picker supports it.

`MainActivity` extends **`FlutterFragmentActivity`** (not the default `FlutterActivity`) because `local_auth`'s biometric prompt requires a `FragmentActivity` host; it also registers the `askrypt/secure` channel. iOS needs `NSFaceIDUsageDescription` in `Info.plist`.

### Server — `server/` (`askrypt-server`)

A Rust (axum) server providing accounts (email + password, plus Google
sign-in), cloud storage of vaults as **opaque encrypted files**, and a
server-rendered website — it never handles questions, answers, or vault
crypto, and it must **never depend on `askrypt-core`**. The phased plan lives
in **`server/PLAN.md`**; Phases 0 (scaffolding), 1 (landing page + API
namespacing), 2 (auth: register, login, Google sign-in), 3 (profile API), 4
(vault cloud storage), 5 (hardening & deployment), 7 (the website: 7.1
foundations, 7.2 browser sessions/CSRF, 7.3 profile pages, 7.4 vault file
manager) and 8 (roles + the admin Users page) are done. Still open: Phase 6
(CI/CD) and browser Google sign-in.
Self-hosting is documented in **`server/DEPLOY.md`**.

**Roles and the first account.** The `roles` table is seeded by the migration
with exactly one role, `ADMIN` (fixed uuid, so both backends name the same
row); `account_roles` is the many-to-many grant table. `admin::bootstrap_first_admin`
grants `ADMIN` to the **first account ever registered** — the rule is narrow
on purpose (no administrator exists *and* `accounts.count() == 1`), so a later
registration can never be promoted just because the administrators were
deleted; `askrypt-server grant-admin <email>` is the recovery path. Banning is
an `accounts.banned_at` stamp, checked in `auth::authenticate` (after the
password verify, to keep login timing non-enumerable),
`auth::upsert_google_account`, and `auth::resolve_session` — the last of which
covers bearer tokens and browser cookies alike, so a ban bites on the very
next request.

- **`server/src/main.rs`** — Startup: tracing init (`RUST_LOG`), env-var config,
  backend selection, graceful shutdown (Ctrl+C/SIGTERM). The `sqlite` backend
  wires `SqliteAccountStore`/`SqliteRoleStore`/`SqliteSessionStore`/
  `SqliteVaultMetaStore`/
  `SqliteVaultVersionStore` plus **two** on-disk `DiskVaultBlobStore`s over
  the *same* root — `new` for the live vaults, `versions` for the archived
  generations — with `vaults_dir()` created at startup so a backup script
  never tars a path no upload has made yet; the
  Google verifier is real when `ASKRYPT_GOOGLE_CLIENT_IDS` is set, else
  `NotConfiguredIdTokenVerifier` (501), and the mailer is a real `SmtpMailer`
  when `ASKRYPT_SMTP_HOST` is set, else `MemoryMailer` behind a `warn!` (built
  once for both backends, before the `AppState` match, so a bad relay or
  sender address aborts startup rather than the first send). Serves with
  `ConnectInfo` so rate
  limiting and the audit log can key on peer IPs. `std::env::args()` is parsed
  *first* (so `--help` works whatever the environment says) into `Command`,
  then config (it selects `ASKRYPT_LOG_FORMAT`), then `init_tracing`; the
  `grant-admin <email>` subcommand grants `ADMIN` to an existing account (the
  way back in when a server has no administrator); the
  `backup <path>` subcommand is `VACUUM INTO` and refuses to clobber or to run
  on the `memory` backend — no `clap` dependency. `init_tracing` builds a
  `registry` with an `EnvFilter` plus one boxed `fmt` layer per sink: the
  console always, and — for `Command::Serve` only — a `tracing-appender`
  daily-rotating file in `ASKRYPT_LOG_DIR` (`askrypt-server.<date>.log`,
  `open_log_file`, ANSI off, pruned to `ASKRYPT_LOG_MAX_FILES`). `backup`
  deliberately does *not* write files — run from cron as root it would create
  the day's file unwritable by the service user. The returned `WorkerGuard`
  flushes the non-blocking writer on drop, so every `process::exit` path
  drops it by hand first.
- **`server/src/config.rs`** — `Config::from_env()`, layered over
  `Config::default()` (which tests use directly): `ASKRYPT_BIND`
  (default `127.0.0.1:8080`), `ASKRYPT_DATA_DIR` (default `data`, gitignored),
  `ASKRYPT_BACKEND` (`sqlite` default | `memory`), `ASKRYPT_STATIC_DIR`
  (default `server/static`, i.e. `cargo run` from the workspace root),
  `ASKRYPT_GOOGLE_CLIENT_IDS` (comma-separated ID-token audiences; empty
  disables Google sign-in), plus the Phase 5 knobs `ASKRYPT_TRUST_PROXY`
  (default **false** — fail closed), `ASKRYPT_HSTS` (default false),
  `ASKRYPT_REQUEST_TIMEOUT_SECS` (60), `ASKRYPT_MAX_CONCURRENT` (256),
  `ASKRYPT_MAX_BODY_BYTES` (64 KiB) and `ASKRYPT_LOG_FORMAT` (`text`|`json`).
  File logging is `log_dir: Option<PathBuf>` — `ASKRYPT_LOG_DIR`, default
  `logs` (gitignored, a *sibling* of the data dir so backups don't sweep it
  up), an explicitly empty value meaning console-only — plus
  `ASKRYPT_LOG_MAX_FILES` (14 daily files; `0` keeps all). Rotation is daily,
  full stop: there is no knob for it.
  Email lives in `smtp: Option<SmtpConfig>`, parsed by `smtp_from` from the
  `ASKRYPT_SMTP_*` cluster (`HOST` `PORT` `ENCRYPTION` `FROM` `USERNAME`
  `PASSWORD` `TIMEOUT_SECS`): `HOST` is the switch, `FROM` is then required,
  the port defaults per encryption mode (587/465/25), and username/password
  must appear together. `smtp_from` takes a variable *lookup* rather than
  reading the process environment, so its cross-field rules are testable
  without racing over global env state.
  The same table lives in `README.md` and `server/DEPLOY.md` — keep all three
  in sync.
- **`server/src/error.rs`** — Uniform JSON error convention: every API error is
  `{"error": {"code", "message"}}` via `ApiError` (`IntoResponse`), with
  `From<StoreError>`/`From<IdTokenError>`; internal details are logged, never
  sent to clients. `ApiJson<T>` and `ApiBytes` are the `Json`/`Bytes`
  extractor variants whose rejections keep the envelope (413s get
  `payload_too_large`). `ApiError::with_retry_after` adds the `Retry-After`
  header used by the 429/503 responses. **`ApiError::new` is also the single
  logging funnel** — every other constructor goes through it, so one `api
  error` event covers all ~40 raising sites, including the errors that never
  become a response (`web::session::lookup` discards one to redirect).
  Everything client-facing is `#[track_caller]`, so the event carries
  `caller=<file>:<line>` of the *raising* site; 5xx logs at `warn`, 4xx at
  `debug`. Two blind spots by construction: a constructor passed as a function
  pointer (`ok_or_else(ApiError::unauthorized)`) resolves through a shim, and
  the `From` impls raise from inside `error.rs` — their own `tracing::error!`
  lines name the cause there.
- **`server/src/routes.rs`** — `router(state, &Config)`: `/healthz`; `/api/v1`
  nest (`GET /about`, the `/me` profile tree, the `/vaults` tree, and
  `/auth/{register,login,google,logout}` behind a 20 req/min fixed-window
  rate limiter) with a JSON 404 fallback covering everything under `/api`;
  the HTML routes from `web::routes(auth_limiter, profile_limiter)` at the
  root (both limiters shared with their `/api/v1` twins); the configured static dir
  mounted at `/assets` (`tower-http` `ServeDir`, under `hardening::revalidate`
  so an edited `style.css` can't linger in a browser cache); and an HTML 404
  fallback.
  The Phase 1 SPA fallback (`index.html` for every unknown path) is gone. The
  vault routes carry a raised `DefaultBodyLimit` sized to `MAX_VAULT_BYTES`, which
  overrides the outer global limit because it is layered *inside* it (the
  website's `/vaults` routes do the same in `web::routes`, with 64 KiB extra
  for the multipart envelope). The
  Phase 5 layer stack is declared innermost-first at the bottom of `router`
  (body limit → `ClientIpPolicy` extension → timeout → shedding → security
  headers), since the last `.layer()` call is the first middleware to run.
- **`server/src/hardening.rs`** — Phase 5 cross-cutting middleware, written as
  plain `from_fn` handlers returning `ApiError` so short-circuits keep the
  JSON envelope (`tower-http`'s `TimeoutLayer` returns a bodyless 408;
  `tower`'s load-shed needs `HandleErrorLayer`): `security_headers` (the
  exported `CSP` const + nosniff/Referrer-Policy/X-Frame-Options/
  Permissions-Policy/COOP/CORP, HSTS when configured), `no_store`
  (`or_insert`, so `vaults::download`'s `private, no-cache` survives for ETag
  revalidation), `revalidate` (the `/assets` twin: `no-cache`, because
  `ServeDir` sets no directive at all and the browser's heuristic freshness
  then serves a stale stylesheet from a URL that never changes),
  `request_timeout` (`tokio::time::timeout` → 504; does not
  bound streaming response bodies — that's the proxy's job) and
  `concurrency_limit` (`Semaphore::try_acquire_owned` → 503 + `Retry-After`,
  `/healthz` exempt). **The `CSP` is a commitment to Phase 7**: no inline
  `<script>`/`<style>`, no `hx-on:`, no `js:`-prefixed htmx attributes.
- **`server/src/clientip.rs`** — Shared client-address resolution for
  `ratelimit` and `audit`. Proxy headers are trusted only under
  `ASKRYPT_TRUST_PROXY` (installed as a `ClientIpPolicy` request extension),
  preferring `X-Real-IP` and otherwise taking the **last** `X-Forwarded-For`
  element — proxies append, so the first element is client-supplied.
- **`server/src/audit.rs`** — Structured account-security events on the
  `askrypt_server::audit` tracing target (register/login/Google/logout,
  password set/change + failed re-auth, email change, session revocation,
  account deletion, and the Phase 8 admin actions — ban/unban, role
  grant/revoke, admin-initiated deletion, where the `account` field names the
  account acted *on* and the acting administrator goes in `detail`), plus the
  infallible `ClientInfo` extractor (IP + capped
  user agent). Never logs tokens, passwords, or the email on a *failed* login.
- **`server/src/auth.rs`** — Phase 2 auth: register (email normalization +
  validation, ≥8-char passwords, argon2 hashing on `spawn_blocking`), login
  (uniform 401 `invalid_credentials`; 256-bit hex bearer tokens, 30-day
  sessions), Google sign-in (verifies via the `IdTokenVerifier` trait,
  requires `email_verified`, creates or links the account by verified email),
  logout, and the `AuthSession` extractor (`Authorization: Bearer` →
  session + account) used by protected routes. Phase 5 added: unknown-email
  and password-less logins verify against the fixed `DUMMY_PASSWORD_HASH` so
  login timing can't enumerate accounts (a unit test guards its argon2 cost
  params), and `ARGON2_SLOTS` caps concurrent hashes
  (`ASKRYPT_ARGON2_PARALLELISM`, default = CPU count) because each holds
  ~19 MiB and tokio's blocking pool would otherwise run 512 of them. Phase 7
  split logic out of the handlers: `authenticate`, `register_account`,
  `issue_session` (TTL is a parameter — browser sessions are shorter),
  `resolve_session`, `revoke_session_token` and `upsert_google_account` are
  `pub(crate)` free functions over `AppState`, and both the JSON handlers and
  `web/` call them. **Never re-implement a rule in `web/`** — in particular
  `authenticate` is where the login timing equalization lives. Phase 8 hung
  three things off those same functions: both account-creation paths call
  `admin::bootstrap_first_admin`, and the banned check lives in
  `authenticate` (403 `account_banned`, **after** the argon2 verify — moving
  it earlier would make the endpoint an existence oracle),
  `upsert_google_account`, and `resolve_session`. All four of
  `resolve_session`'s rejections answer with the *same* opaque 401 and are told
  apart only in the log: `reject_session` names the `reason`
  (`unknown_token`/`expired`/`account_missing`/`banned`) and identifies the
  session by `session_fingerprint` — 12 hex chars of `profile::session_id`'s
  digest (`pub(crate)` for exactly this), so a log line matches a device-list
  row while **the token itself is never logged**. The happy path logs at
  `trace`, not `debug`: it fires on every authenticated request and the crate
  defaults to `debug`.
- **`server/src/admin.rs`** — Phase 8 administrative rules, the same
  handlers-are-wrappers split as `profile.rs`: `list_users` (two store calls
  and a count, never one per row), `set_banned` (which also drops the target's
  sessions), `set_admin`, `delete_user` (reusing `profile::delete_account_data`
  rather than a second cascade) and `bootstrap_first_admin`. The three guards
  live here, so the htmx and no-JS paths cannot drift: `cannot_target_self`,
  `last_admin`, `confirmation_mismatch`. **There is no JSON admin API** —
  administration is a website capability, and no desktop or mobile client
  needs it.
- **`server/src/profile.rs`** — Phase 3 profile API under `/api/v1/me`
  (handlers are wrappers; the rules are the `pub(crate)` free functions
  `set_email`, `set_password`, `active_sessions`, `revoke_session_id`,
  `delete_account_data`, which the Phase 7.3 pages call):
  `GET /me` (full profile incl. linked providers), `PUT /me/email`,
  `PUT /me/password` (current-password re-auth when one exists; sets the
  first password on Google-created accounts), `GET /me/sessions` +
  `DELETE /me/sessions/{id}` (sessions are identified by a SHA-256 digest of
  the bearer token so listings never leak tokens; `current` flags the
  caller's), and `DELETE /me` (cascades archived version bytes → version
  index → vault blobs → vault metadata →
  sessions → account). The email/password mutations sit behind their own
  20 req/min rate limiter. **Changing an existing password revokes every
  other session** (`revoke_other_sessions`, the caller's survives) — desktop
  and mobile must re-login on the other devices; setting a *first* password
  on a Google account revokes nothing.
- **`server/src/vaults.rs`** — Phase 4 vault file API under `/api/v1/vaults`:
  list, upload (`POST ?name=`), download, overwrite (`PUT /{id}`), rename
  (`PUT /{id}/name`), delete and the `/{id}/versions` subtree (list, download
  one, `POST /{version_id}/restore`), all scoped to the authenticated
  account. Same split as `auth`/`profile`: `list_for`, `create`, `overwrite`,
  `set_name`, `destroy`, `read`, `versions_for`, `versions_by_vault`,
  `read_version` and `restore_version` are the `pub(crate)` free functions the
  Phase 7.4 file manager drives.
  **Version history**: every content-changing overwrite archives the bytes it
  replaced (`MAX_VAULT_VERSIONS` = 5 per vault). Archiving and trimming are
  deliberately *best effort* — they log a `warn!` and never fail a save — and
  the trim runs after the write lands. `trim` walks the account's versions
  newest-first and keeps each only while its vault is under the cap **and**
  it fits in what the live files leave of `ACCOUNT_QUOTA_BYTES`, so history
  shares the existing quota instead of multiplying disk use; re-uploading
  identical bytes makes no generation; a restore is an ordinary `overwrite`
  with old bytes, so it archives what it displaces and is itself undoable.
  Bytes stay opaque apart from the ZIP-magic check and the write stamp
  `vaultfile::read_stamp` lifts off them in `create`/`overwrite` (see
  `server/src/vaultfile.rs`); `archive` copies the live row's stamp onto the
  generation it files away. ETags are the SHA-256 of
  the stored bytes: downloads honor `If-None-Match` (304), overwrites
  require `If-Match` (428 without it, 412 when stale) so multi-device sync
  detects conflicts. Enforces `MAX_VAULT_BYTES` (10 MiB),
  `ACCOUNT_QUOTA_BYTES` (100 MiB) and `MAX_VAULTS_PER_ACCOUNT` (100).
  Downloads set `Cache-Control: private, no-cache` so they opt out of the
  blanket `no-store` without losing ETag revalidation.
- **`server/src/vaultfile.rs`** — The one look the server takes inside a
  vault: `read_stamp` opens the ZIP, reads `askrypt.json`, and lifts the two
  fields the format leaves *unencrypted* — `params.host` and
  `params.updated_at` — into a `VaultStamp`. Written here rather than
  borrowed from `askrypt-core`, which this crate must never link; it
  deserializes nothing else, is read-only (`zip` is pulled in
  `default-features = false, features = ["deflate-flate2-zlib-rs"]`), caps the
  inflated JSON at 1 MiB, and **cannot fail a save** — a non-ZIP, a missing
  entry or a pre-stamp file simply has no stamp, and the host/time halves are
  independent. Host names are foreign text bound for a table cell: control
  characters stripped, 128 chars max, escaped by askama at render time.
- **`server/src/ratelimit.rs`** — In-memory fixed-window `RateLimiter` +
  axum middleware, keyed via `clientip::client_ip` (`client_key` is
  `pub(crate)` so `web` can bucket identically); 429s carry `Retry-After`.
- **`server/src/web/`** — The website (Phase 7): server-rendered HTML with
  askama templates from `server/templates/`, htmx as a progressive
  enhancement. `mod.rs` builds the HTML router and holds `rate_limit`, an
  HTML-rendering twin of `ratelimit::middleware` sharing the *same*
  `RateLimiter` instances as `/api/v1/auth` and the `/api/v1/me` mutations;
  `render.rs` has `Page<T>` (askama 0.16 has no axum integration), `is_htmx`,
  `redirect_either_way` (303, or `HX-Redirect` for htmx), `timestamp`, and
  `Chrome`/`Shell` (the layout's data plus the cookies a response owes);
  `error.rs` `WebError` with `From<ApiError>` — 5xx messages are replaced,
  never forwarded; `session.rs` the `WebSession`/`MaybeWebSession` cookie
  extractors (7-day sessions labelled `"Web browser"`, rejecting with a 303
  to `/login` or an `HX-Redirect`) plus `AdminSession`, which layers on
  `WebSession` so a signed-*out* visitor still gets the redirect while a
  signed-in non-administrator gets a 403 page instead of a login loop; plus
  hand-formatted `Set-Cookie` values
  (`HttpOnly; Secure; SameSite=Lax; Path=/`); `csrf.rs` a random
  double-submit cookie — **deliberately not derived from the session token,
  because `profile::session_id` is `sha256(token)` and is published in the
  device list** — enforced by `CsrfForm<T>` and, for uploads,
  `CsrfMultipart` (which verifies the token *before* buffering the file, so
  the hidden input must come first in every multipart form); these two are
  the only ways to read a form body; `flash.rs` one-shot messages stored as
  *codes*, never text; `auth.rs` the login/register/logout forms;
  `account.rs` the 7.3 profile pages (email, password, device list with
  per-row revoke, typed-confirmation delete); `vaults.rs` the 7.4 file
  manager (multipart upload, cookie-authed download route, inline rename,
  replace carrying the row's ETag through the `If-Match` path, delete, quota
  display, a `Saved` column carrying the file's own `host`/`saved_at` stamp
  next to the server's own "last change" time (`saved_stamp` formats the pair,
  `None` when the file records neither), and a per-row history disclosure
  whose download route stamps the
  archival date into the filename and whose restore form carries the row's
  ETag like replace does). The table is ordered **newest change first** —
  `listing` re-sorts by `updated_at` descending, and since the sort is stable
  over the name-sorted list `list_for` returns, files stored in the same
  instant stay in name order; the JSON `/api/v1/vaults` listing keeps the
  plain name order. Plus `explain`, which turns the handful of reachable `ApiError`
  codes into sentences; `pages.rs` landing and the HTML 404; and `admin.rs`
  the Phase 8 Users page (`/admin/users` behind `AdminSession`, with per-row
  suspend/lift, promote/demote and typed-confirmation delete, paged 50 at a
  time). Every admin action re-renders the **whole** `#user-list` fragment,
  not the row: each one moves the account total and the administrator count
  the guards depend on. `Chrome` carries `is_admin` (set by `Shell::as_admin`,
  defaulting to *off*) so the nav can offer the Users link on every page —
  hiding it is decoration, `AdminSession` is the gate. Templates must
  not contain inline `<script>`/`<style>`, `hx-on:` or `js:` htmx
  expressions — the CSP forbids them and `tests/web.rs` guards it.
- **`server/src/state.rs`** — `AppState`: one `Arc<dyn Trait>` per backend
  seam; handlers can only reach the traits. Two of them are the same trait:
  `vault_blobs` (live files) and `vault_version_blobs` (archived generations,
  keyed by version id, under each account's `versions/` subdirectory).
- **`server/src/store/`** — The backend traits (`mod.rs`): `AccountStore`,
  `RoleStore`,
  `SessionStore`, `VaultMetaStore`, `VaultVersionStore`, `VaultBlobStore`,
  `Mailer`,
  `IdTokenVerifier` (+ `StoreError`/`MailerError`/`IdTokenError`, all
  `#[non_exhaustive]`, and the `ADMIN_ROLE` name constant); `memory.rs`
  in-memory fakes for all of them (used by tests
  and the `memory` backend — `MemoryRoleStore::default` seeds `ADMIN` with the
  *same fixed uuid* the migration writes, so the two backends agree);
  `sqlite.rs` SQLite pool + embedded migration
  runner over `server/migrations/` plus `SqliteAccountStore`/`SqliteRoleStore`/
  `SqliteSessionStore`/`SqliteVaultMetaStore`/`SqliteVaultVersionStore`
  (uuids as TEXT, timestamps via sqlx-chrono, sessions, vault and
  `account_roles` rows cascade
  on account delete, version rows cascade on *both* vault and account delete,
  vault names unique per account, the nullable `host`/`saved_at` stamp
  columns on `vaults` + `vault_versions`, and the nullable `banned_at` on
  `accounts`. `AccountStore::list` is bounded (`limit`/`offset`, ordered
  `created_at, id` — the id tiebreak is what keeps paging stable) because the
  admin page must never load every account at once. Adding an `accounts`
  column means touching six places in `sqlite.rs`; `ACCOUNT_COLUMNS` covers
  the three SELECTs, the INSERT and UPDATE lists are separate); `disk.rs` `DiskVaultBlobStore` storing
  bytes at `<root>/<account-id>/<blob-id>.askrypt` with atomic temp-file +
  rename writes (path components are uuids, so no user string reaches the
  filesystem) — instantiated **twice** over `<data>/vaults`: `new` keyed by
  vault id, and `versions` keyed by version id, which nests them at
  `<account-id>/versions/`. History therefore shares no namespace with the
  live files while everything one account stores stays under one directory,
  so deleting that directory takes the history with it; `google.rs` `GoogleIdTokenVerifier` (RS256 against Google's
  JWKS, cached with a 60 s refetch floor, issuer/audience/expiry checks) and
  `NotConfiguredIdTokenVerifier`; `smtp.rs` `SmtpMailer` — `lettre` over
  rustls (never native-tls: it would drag OpenSSL in, and `ring` must stay
  the only rustls crypto provider or the provider lookup panics at connect
  time), pooled, with `SmtpConfig`/`SmtpCredentials`/`SmtpEncryption`
  (`StartTls` default | `ImplicitTls` | `None`) defined here and merely
  *parsed* by `config.rs`. `SmtpMailer::new` validates the sender and relay
  up front so failures land at startup, and it logs recipient + subject only.
  The relay password is redacted from every `Debug` impl (`SmtpCredentials`,
  and `SmtpMailer` itself, whose transport holds the credentials) because
  `Config` derives `Debug`. Its tests include a loopback fake relay that
  speaks real SMTP — it must stop at the end of `DATA` instead of waiting for
  `QUIT`, since the pooled transport keeps the socket rather than closing it.
  **`MemoryMailer` is not "email off"** — it logs the full body, tokens
  included, which is why `main` warns when it is selected.
- **`server/tests/`** — HTTP-level tests (tower `oneshot`, no socket):
  `http.rs` (routing/static), `auth.rs` (the Phase 2 gate: register →
  login → `/me` → logout, Google new-account + link-to-existing against the
  fake verifier, validation, rate limiting), `profile.rs` (the Phase 3
  gate: providers, email update, change/set password, session list/revoke,
  account-delete cascade incl. the vault stores), `vaults.rs` (the Phase 4
  gate: upload → list → download → rename → delete, ETag conflict behavior,
  per-account isolation, size/quota/count limits, and the write stamp a
  real stamped archive puts in the listing) and `hardening.rs` (the
  Phase 5 gate: security headers on every response shape, HSTS per config,
  cache directives, the 64 KiB/10 MiB body-limit split — the regression test
  for the layer ordering — `Retry-After`, and forged-vs-trusted
  `X-Forwarded-For` bucketing) and `web.rs` (the Phase 7 gate, 34 tests:
  template rendering, `/assets`, the HTML-404-vs-JSON-404 split, cookie
  attributes, the CSRF rejections for both form and multipart, fragment vs.
  full page, register-in-browser → find the session in
  `GET /api/v1/me/sessions` → revoke → signed out, the 7.3 profile round trip
  incl. self-revocation and the typed-confirmation delete, and the 7.4
  upload → list → byte-identical download → rename → delete with the
  stale-ETag conflict, the oversize 413 page, and the `Saved` column —
  including that a host name out of a file cannot inject markup) and
  `admin.rs` (the Phase 8 gate, 9 tests: first-account-is-admin and the nav
  link that follows, 403-vs-redirect for non-admin and signed-out visitors,
  suspend → old session dies *and* a fresh JSON login is refused → lift
  restores both, the self-guard, grant/revoke of ADMIN, the typed-confirmation
  delete taking the target's vaults with it, CSRF rejection, and the htmx
  fragment swap). Middleware needing a slow
  or parked handler (timeout, shedding) is unit-tested inside
  `src/hardening.rs` instead. The `last_admin` guard is unreachable through
  the website — only the sole administrator can act on themselves, and the
  self-guard fires first — so it is covered by `src/admin.rs`'s unit tests.
- **`server/templates/` + `server/static/`** — The website's markup and its
  only loose files. Templates (`layout.html`, `landing.html`,
  `auth_page.html`, `account.html`, `vaults.html`, `admin_users.html`,
  `error.html`, and
  `fragments/` — `auth_form`, `email_form`, `password_form`, `devices`,
  `delete_account`, `vault_upload`, `vault_list`, `user_list`) compile into
  the binary;
  every page template carries a `chrome: Chrome` field because `layout.html`
  reads it, and each fragment is a self-contained element with an id its
  forms name as `hx-target`. Confirmation steps are `<details>` disclosures,
  not scripted dialogs — the CSP forbids the inline handler. `static/` holds
  just `style.css` and the vendored `htmx.min.js` (2.0.10), served at
  `/assets` — there is no `index.html` any more. No Node, no bundler, no CDN.
- **`server/Dockerfile` + `server/deploy/`** — Self-hosting artifacts.
  **Containers are the only supported deployment** — there is no systemd unit
  and no backup wrapper script; `server/DEPLOY.md` drives everything through
  `docker compose`. Multi-stage image (build from the **repo root** — cargo
  validates every workspace member's target paths, and `sqlx::migrate!`
  embeds `server/migrations/`); `docker-build.sh` is the one that gets that
  right, and passes `GIT_HASH`/`GIT_COMMIT_MSG` build args that become image
  labels plus the `ASKRYPT_BUILD_REV`/`_MSG` env `main::log_build_revision`
  reports at startup. `Caddyfile` (TLS; *overwrites* `X-Forwarded-For`/
  `X-Real-IP` rather than appending) takes its site address from
  `{$ASKRYPT_DOMAIN}`, so it carries no hostname and every deploy can
  overwrite it.
  **Deployment is `./deploy.sh dev|prod`** → `spot.yml` (a
  [spot](https://github.com/umputun/spot) playbook): build locally, ship the
  image as a `docker save | gzip` tarball, `docker load`, `docker compose
  up -d` from `/opt/askrypt`, then wait on the container *and* on `/healthz`
  answering — probed with `docker exec askrypt-caddy wget`, since the runtime
  image has no HTTP client. The server needs only docker: no source checkout,
  no toolchain, no registry. `docker-compose.yml` (server + Caddy) therefore
  has **no `build:` section** and `pull_policy: never`; its project name is
  pinned (`name: askrypt`, so volumes are `askrypt_askrypt-data`/`-logs` +
  Caddy's three wherever the file sits), and host-specific values come from
  `/opt/askrypt/.env` on the server — required `ASKRYPT_DOMAIN` plus the SMTP
  secrets, templated by `env.example`, never uploaded, only checked for.
  Checklist, backup and
  restore drill in `server/DEPLOY.md`; backups are `askrypt-server backup`
  (a `VACUUM INTO` snapshot) **before** tarring the blobs — uploads write
  bytes then metadata, so that order can only orphan a blob — with the server
  stopped when an exact snapshot matters. The image puts log files in
  `/var/log/askrypt` via its own `mkdir`/`chown` plus a second `VOLUME`,
  because `ASKRYPT_LOG_DIR`'s default is relative to a working directory it
  cannot write; the snapshot does not archive them.

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `iced` | Cross-platform GUI (Elm-style) |
| `aes` + `cbc` + `cipher` | AES-256-CBC encryption |
| `pbkdf2` + `sha2` | Key derivation |
| `serde` + `serde_json` | Serialization |
| `zip` | Vault file format (ZIP archive); in the server, read-only, for the write stamp |
| `rfd` | Native file open/save dialogs |
| `rand` | Random number generation |
| `tokio` | `spawn_blocking` for off-main-thread vault decryption and server requests |
| `ureq` | Blocking HTTP for core's `server-storage` backend (rustls/ring, no OpenSSL) |
| `askama` | Server-rendered HTML templates, compiled into the server binary |
| `lettre` | SMTP delivery for the server's `Mailer` seam (rustls, no OpenSSL) |
| `tracing-appender` | The server's daily-rotating log files under `ASKRYPT_LOG_DIR` |

### Build & Test

```
# Desktop / core (Rust) — core is the spec source of truth
# (both desktop crates enable core's `server-storage` feature, so a workspace
#  build already covers it; `cargo build -p askrypt-core` alone must NOT pull
#  in ureq/rustls — that is the point of the feature gate)
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p askrypt                       # the shipping app (src/)
# The new three-pane UI, optionally opening a vault straight away. The
# `--workspace` commands above cover it; CI's bare `cargo build`/`cargo test`
# select only the root package (no `default-members`) and skip it.
cargo run -p askrypt-gui -- ~/vaults/MyVault.askrypt
# Regenerate Dart parity vectors after any format/normalization change:
cargo run -p askrypt-core --example gen_vectors
# Server (also covered by the --workspace commands above):
cargo run -p askrypt-server      # then curl /healthz
# Manual end-to-end check of the client backend against a running server:
cargo run -p askrypt-core --features server-storage --example server_roundtrip \
  -- http://localhost:8080 me@example.com correct-horse
cargo run -p askrypt-server -- backup /path/snap.db   # VACUUM INTO snapshot
docker build -f server/Dockerfile -t askrypt-server . # from the repo root

# Mobile (Flutter) — SDK at /home/ruslan/Apps/flutter (add bin to PATH)
cd app && flutter test       # crypto parity + session + passgen + widget tests
cd app && flutter analyze
```

The root `Cargo.toml` raises `opt-level` for `pbkdf2`/`sha2`/`aes` (and
`argon2`/`blake2`, for the server's tests) **in the dev profile**: 600,000
PBKDF2 iterations built unoptimized take minutes rather than a second, which
makes a debug desktop build unusable and `cargo test` crawl. Keep those
overrides when touching profiles.

### CI / Release

- `.github/workflows/ci.yml` — Builds and tests on Ubuntu for every push.
- `.github/workflows/release.yml` — Multi-platform release builds (Linux x86_64, macOS ARM64, Windows x86_64 MSVC).
- Windows builds use static C runtime linking (configured in `.cargo/config.toml`).
- `build.rs` embeds the Windows icon resource.
