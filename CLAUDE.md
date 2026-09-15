# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

Askrypt is a cross-platform password manager. Users authenticate with security-question answers (normalized, PBKDF2-hashed) instead of a master password; vault data — entries and **file attachments** — is AES-256-CBC encrypted.

Cargo workspace with three clients of one vault format:
- **`core/`** (`askrypt-core`, lib name `askrypt`) — crypto/format engine, **source of truth**.
- **`src/`** — desktop Iced app (`askrypt`), depends on `core`.
- **`app/`** — pure-Dart Flutter mobile app, re-implements the format in Dart.
- **`server/`** (`askrypt-server`) — axum server; its `/open` page is a browser client re-implementing the format in JS (`server/static/vault-format.js`).

**Warning**: under active development, not extensively security-tested.

> **Rule — keep this file current.** Any change to layout, architecture,
> build/test commands, dependencies or the vault format updates `CLAUDE.md`
> (and `app/PLAN.md` / `server/PLAN.md` / `UI.md` where relevant) in the same change.

> **Rule — print a short commit when changes are done.** After a code change,
> print a single conventional `type: subject` line (≤ 72 chars). Do not run
> `git commit` unless asked.

## Cross-cutting invariants

- **Format changes touch four places**: `core/`, `app/lib/crypto/`, `server/static/vault-format.js`, and `SPEC.md` (normative). Regenerate vectors (`gen_vectors`) and run both parity gates: `cd app && flutter test` and `node scripts/vault-js-parity.mjs`.
- **Every client must carry every key it doesn't understand-by-UI** (card fields, `custom_fields` incl. unknown `type` strings, `attachments`, `files/` members). A save rebuilds the whole archive, so a port dropping `attachments` deletes every attached file. The golden fixture holds a card entry and an attachment precisely so such a port fails the gates.
- **`version` stays `"0.9"`**: `from_bytes` rejects other values. New fields are optional + omitted when empty so old files round-trip.
- **Dependency direction**: desktop → core. **`askrypt-server` never depends on `askrypt-core`** (stores opaque bytes). No crate links both — hence the conformance runner is an *example*, not a test.
- **Master key lifetime** (`SPEC.md`): rotate on every write **unless the vault holds an attachment** (blobs are sealed under it and copied verbatim). `master_for_write` is the whole rule, ported as `masterForWrite` in Dart and JS. Entries decide (dangling reference keeps the key). Every save of a vault with attachments — including a questions change — must pass the recovered key. `salt0`/`salt1`/data IV are regenerated every write; attachments get a fresh IV per encryption.
- **No integrity**: CBC without MAC; `params` (incl. `host`/`updated_at` stamp) is unauthenticated — a hint, never evidence. Fix = AES-GCM + breaking `version = "1.0"` (see `SPEC.md` "TODO: authenticated encryption"; GCM nonces must be fresh 96-bit per write; never report decryption outcomes over the network — padding oracle).
- **Zeroize**: `SecretEntry`/`MasterData`/`QuestionsData`/`MasterSecret` derive `ZeroizeOnDrop`; transient keys/buffers use `Zeroizing`; derive keys via `derive_key`, not `calc_pbkdf2(..)?.try_into()`; use `.zeroize()` not `.clear()`. Types that must be destructured (or used with `..Default::default()`) must **not** implement `Drop` (E0509) — e.g. `CardFields`, `Attachment`, desktop typestates, worker result types.

## Core crate — `core/src/`

- **`types.rs`** — `SecretEntry`, `CardFields`, `CustomField`, `CustomFieldType`, `Attachment`, `Attachments`, `Params`, `QuestionsData`, `MasterData`, `MasterSecret`, `AskryptFile`.
  - `SecretEntry.custom_fields: Vec<CustomField>` (`{name, value, type}`, skipped when empty, any entry type). `type` stays a `String` so unknown types round-trip; `kind()` parses case-insensitively (unknown → `Text`); `is_checked()` = value `"true"`. Types `text`/`hidden`/`checkbox`/`link`. Editor caps `MAX_CUSTOM_FIELD_NAME_CHARS` (100) / `MAX_CUSTOM_FIELD_VALUE_CHARS` (5000) chars; readers accept longer. `CustomField` must not implement `Drop`.
  - `CardFields` is `#[serde(flatten)]`: six sibling keys `card_holder/brand/number/expiry/cvv/pin`, each skipped when empty; meaningful only for type `"Card"` (case-insensitive).
  - `Params` has optional unencrypted write stamp `host` (`os@host`, opaque display text, may be a bare host in old vaults) + `updated_at` (RFC 3339 UTC).
  - `MasterSecret`: 32-byte key, `ZeroizeOnDrop`, `Debug` prints `<redacted>` (it rides in `Message` enums).
  - **Attachments split**: `Attachment` metadata (`id`, `name`, `size`, `added`, `iv`) lives in the encrypted entry list (`SecretEntry.attachments`, skipped when empty). Blobs are ZIP members `files/<id>` (id = 32 random hex chars; count and sizes leak, names don't). `Attachments` (`#[serde(skip)]` on `AskryptFile`) maps id → `AttachmentSource` (`Carried` from `origin` archive, or `Sealed(PathBuf)` scratch ciphertext) — **never bytes**. `retain_referenced` (GC in `create`), `adopt` (repoint at newly written archive), `sealed_paths`. `origin: None` (parsed from a slice) → `write_archive` **refuses** rather than silently dropping members.
- **`lib.rs`** — AES-256-CBC, PBKDF2/SHA-256, ZIP, serialization. Holds no attachment bytes.
  - `write_archive(W: Write + Seek)` is the one writer: `Sealed` deflated in, `Carried` copied by `raw_copy_file` (no crypto). `to_bytes` buffers it.
  - `from_path` (desktop reader) lists `files/` without opening; `from_bytes` buffered twin. ~4 MiB peak RSS for a 1 GiB attachment. Bomb guard: `MAX_JSON_BYTES` (1 MiB on `askrypt.json`). Dart/JS ports still inflate and keep their own ceiling.
  - `create(…, master: Option<&MasterSecret>, attachments: &Attachments)` — `None` mints (new vault); attachments is a parameter so forgetting it is a compile error. `decrypt_with_master` returns the key; `decrypt` drops it.
  - `seal_attachment`/`open_attachment` (one-shot, test oracle) and streaming `seal_attachment_to_file`/`open_attachment_to_file` (64 KiB chunks, byte-identical); `extract_attachment`.
  - `AskryptFile::touch` (end of `create`) stamps `host`/`updated_at` via `current_host` (`<os>@<host>`; Linux OS from `/etc/os-release` `ID=`, validated `[a-z0-9._-]`) and `now_utc_rfc3339`.
- **`storage/`** — `VaultStorage` trait (sync, object-safe, `Send + Sync`): `read`/`write`/`exists`/`location`, `load_vault`/`save_vault`; path door `archive_path`/`read_to_path`/`write_from_path` (`archive_path` `Some` only for a file backend); `acquire_lock` (granted by default); revision trio `revision` (cached, no I/O) / `current_revision` (probe, worker only, returns `RemoteRevision`) / `adopt_revision`. **`current_revision` must never update the cached revision** (it is the next `If-Match`; test `probing_leaves_the_conflict_check_armed`). `revision() == None` means unfollowable, not unchanged. Errors: `StorageError` (`#[non_exhaustive]`, all variants unconditional): `Io`/`Format`/`Locked`/`Network`/`Auth`/`Conflict`/`Remote`. `MemoryStorage` for tests.
  - `local_file.rs` — `LocalFileStorage` stages + renames (never truncates in place). Holds an advisory lock on sidecar `<vault>.lock` for its lifetime (the vault file is replaced on save, and Windows locks are mandatory). Only a lock held by someone else errors; unlockable/read-only locations proceed without one.
  - `server.rs` (feature `server-storage`, default off; `cargo build -p askrypt-core` must not pull ureq/rustls) — `ServerClient` (`begin_browser_login`/`login`/`with_token`/`logout`, list/create/download/overwrite/rename/delete) and `ServerStorage` (one vault by *name*). `BrowserLogin` `Debug` redacts the poll token; server's `verification_path` validated as a plain path; poll response parsed flat so unknown statuses mean "keep waiting". `login` exists but no client calls it. `RemoteVault` has optional `updated_at`, `host`, `saved_at`. Uses `ureq` 3 (not `reqwest::blocking`, which panics in async contexts), `http_status_as_error(false)`. ETags stored unquoted, sent quoted. **A `ServerStorage` must live as long as the open vault** (a fresh one would clobber other devices' edits). `normalize_base_url` is public.
- **`passgen.rs`** — password generator. **`translit.rs`** — RU/UK → Latin (BGN/PCGN, QWERTY-only).
- **`examples/gen_vectors.rs`** — writes `app/test/fixtures/vectors.json` (login with one custom field of each type plus an unknown `totp` type, card + `File` entry with attachment, via `insert_sealed`). `vault_b64` is not byte-stable (stamps), so diffing proves nothing — run the gates. In `scripts/vault-js-parity.mjs`, `serialized()` is a **whitelist** (add new per-entry keys; includes `custom_fields`), and `group()` fails a group that ran no checks.
- **`examples/server_roundtrip/`** — live-server conformance runner over every API/web/admin endpoint; entry point `scripts/server-roundtrip.sh`. Refuses non-loopback hosts; probes role via `GET /admin/users`; mutates only throwaway accounts it registered and tears down as reported checks; follows no redirects and never sends `HX-Request` (303 = success, 200 re-render = refusal); treats 429 as wait; reports skips separately.

## Desktop app — `src/` (Iced)

Three-pane layout: left rail, item list, detail pane, search strip on top, status bar pinned at bottom. **`UI.md`** is the design doc (layout, state/transition/button tables, invariants and where enforced) — keep it current. `include_bytes!` paths are `"../static/…"`.

Files: `main.rs` (App, `Message`, `visible()`/`reconcile_selection()`, panes, subscription, tray/keyboard), `manager.rs`, `session.rs`, `settings.rs`, `smartlock.rs`, `tray.rs`, `theme.rs`, `scratch.rs`, `confirm.rs`, `follow.rs`, `link.rs`, `icon.rs`, `data.rs`, `panes/{mod,sidebar,list,detail,entry_editor,questions,passgen,settings,unlock,wizard,statusbar}.rs`.

- **`panes/mod.rs` `Action`** (`None`/`Run`/`Pane`/`PaneRun`): a pane's `update` mutates state and returns where to go; `App::apply` switches. `Items` = list + detail/editor; other panes fill the working area. `set_pane` returns a `Task` (leaving Wizard/Settings abandons an in-flight browser sign-in).
- **`manager.rs` — the vault typestate** `Vault<S>`, `S` ∈ `Locked`/`PartiallyUnlocked`/`Unlocked`/`SmartLocked`; each state struct carries only its own data. All states hold `file` and `home: Option<VaultHome>` (location + **live** backend instance; `None` ⇒ first Save becomes Save As). `VaultState` is the type-erased enum on `Session`; panes match it for handles exposing only allowed ops. Locking = dropping the state. `Unlocked.master` is not an `Option`; opens return `OpenedVault`, writes `SavedVault`. `RekeyInputs::run` is the only place that mints a key.
  - **No derivation on the main thread**: each transition is inputs-struct (`RevealInputs`, `UnlockInputs`, `SmartLockInputs`, `SmartUnlockInputs`, `RekeyInputs`, `SaveRequest`, `AttachInputs`, `ExtractInputs`, `ReloadInputs`) → `run` on a worker (errors → `String`/`VaultError`) → `self`-consuming `apply_*` from the success message; wrong-state applies return `false`. Answers never ride in messages.
  - Custom fields: editor section for every type (per-row type picker, caps applied in `update`, blank-name rows dropped, value without name refused); detail card under the main card. Hidden fields reveal individually via `App.revealed_fields` / editor `State.revealed_fields`, reset with `revealed`.
  - Attachments: `attachments()`/`add_attachment` on `Unlocked`; **no `remove_attachment`** (drop the reference; next `create` prunes). `add_attachment` doesn't set `modified`. Attach streams to scratch (`Attached { attachment, sealed: PathBuf }`); extract streams from source to destination.
  - `read_vault` is the only open path: `acquire_lock`, then read in place or spill a copy to scratch (server vaults). `write_vault`: `master_for_write` → `create` → `write_archive` into staging (beside destination) → `write_from_path` → `adopt`, delete folded sealed files, `retire_origin` (only removes scratch it created). Cloud saves then copy to `AppSettings::local_backup_dir()` (after success, never fails the save; `backup_file_name` keeps only the last path component).
  - Reload (following): `reload_inputs` → `ReloadInputs::run` → `apply_reloaded`/`apply_refreshed`/`apply_requestioned`/`relock_with`; `Unlocked` rebuilds silently; `ReloadOutcome::Rekeyed` relocks onto the new bytes.
  - Button rules live on `VaultState` (`can_create`, `can_open`, `can_close`, `can_unlock`, `can_smart_lock`, `can_lock`, `lock_label`, `can_save`, `can_save_as`, `can_edit_questions`, `can_cancel_wizard`, `is_open`, `is_unlocked`, `label`). The sidebar only asks. Buttons are hidden, not disabled. Item list/filters/search exist only while unlocked; lock paths call `App::clear_secret_panes`.
- **`session.rs`** — shell state around `vault: VaultState`: settings, tray, messages, spinner, activity, sticky follow fields (`follow`/`dismissed_revision`/`last_reload`, spared by `clear_messages`; reset via `settle_follow`/`reset_follow`), sign-in (`server_client`, `server_email`), `scratch: Option<Arc<Scratch>>`. `remember_vault`, `close_vault`, `entries()`. `VaultError` is the `Clone` classification of `StorageError` (`Locked` = "already open in another Askrypt window").
  - `App::guard(PendingAction)` = unsaved-changes gate (async `confirm::Kind::UnsavedChanges`; Save replays from `App.after_save`). Lock/Smart Lock/New/Open/Exit are gated. `App::auto_smart_lock` saves first if the vault has a home, else declines. Dirty flag lives in `Unlocked`.
- **`confirm.rs`** — in-app dialog (rfd is file pickers only). Opaque scrim + card over the whole window. Escape/backdrop always Cancel; Enter bound only where the affirmative is safe (not Delete, not *Save mine*); raising one unfocuses via `operation::focus(confirm::NO_FOCUS)`; `resolve_confirm` `take`s before acting. `App.confirm` cleared by `set_pane`/`clear_secret_panes`. Deleting an entry uses `Kind::DeleteEntry`.
- **`follow.rs`** — 60 s + focus probe of the stored vault, pure `decide` policy. Clean vault reloads silently; unsaved work (`is_modified()` or open editor/questions draft) asks. Probe never sets `busy`; the reload does. `install_reload` re-checks for unsaved work; declining paths roll back with `adopt_revision`. Status line names who saved via `data::format_stamp`.
- **`link.rs`** — browser sign-in shared by wizard and Settings; state on `Session`. Replies are generation-tagged (drop late ones). Doesn't hold `busy`. Polls at server `interval`, 429 retryable, gives up after 15 min. Device label = `askrypt::current_host()`.
- **`scratch.rs`** — `<cache>/session-<pid>/` holding sealed attachments and spilled cloud archives. Holds a lock on its `.lock`; startup sweeps sibling dirs whose lock can be taken. `clear` on close; removed on drop. `open_vault` over another retires the old files by name (`manager::retire_working_files`). Not `/tmp` (often RAM-backed).
- **`data.rs`** — entry types `Login`/`Card`/`File` (`is_card`/`is_file`, case-insensitive), filter (includes attachment names, cardholder, custom field names and non-hidden values; not card secrets or hidden values), hash-tags with `tag_key`/`same_tag` case-folding (mobile and browser fold identically), `format_size`, write stamp, `DATETIME_FORMAT` = `%b %-d, %Y %H:%M` (`format_timestamp_local`, `format_rfc3339_local`).
- **`icon.rs`** — glyph codepoints from bundled `bootstrap-icons.ttf` (no bare `plus`; no `apple`) + `KEYWORDS`. Matching: fields lowercased, split on non-alphanumerics, romanized via core `translit`. **Tags first** (each tag separately, first match wins), then name/URL. `Any` = substring, `Word` = whole token (short keywords must be `Word`). **Longest match wins**, ties → earlier row. No match → `icon::placeholder` hashed from name only (stable across frames). Cards use `icon::card` (fallback `credit_card`); `File` entries use the paperclip. Eyeball new glyphs in the app (unmapped = tofu).
- Selection is an index into `session.entries`, not the filtered view. The root isn't centered — panes are full-bleed.
- **Wizard** (`panes/wizard`): single source picker for Open and Save As (Local file via `rfd::AsyncFileDialog`, Askrypt Server, disabled Cloud-folder placeholder). Plain Save never goes through it. Local save opens the native save dialog directly. Server step holds no credentials (browser sign-in only); signs out if signed into a different server than configured; **always refetches the listing** on entry (`State::listing` distinguishes loading from empty). Save direction shows a read-only listing with the replaced row marked and a `NameStatus` (`Empty`/`Checking`/`Unknown`/`Free`/`Replaces(i)`); collision check is `eq_ignore_ascii_case` though the server is byte-exact.
- **`settings.rs`** — `AppSettings` (JSON in platform config dir: `%APPDATA%\askrypt\`, `~/Library/Application Support/askrypt/`, `~/.config/askrypt/`), every field `#[serde(default)]` and also set in manual `Default`: `recent_vaults`, `theme`, `lock_timeout`, `minimize_to_tray`, `show_hidden_by_default`, `clear_clipboard`, `server_url` (default `https://askrypt.com`; read via `server_url()`, normalized with core's `normalize_base_url`), `backup_to_local_dir` + `backup_dir` (read via `local_backup_dir()`), `window`.
  - `WindowState` stores unmaximized geometry (`record_geometry` + debounced `is_maximized` probe in `commit_geometry`); drops nonsense values (Windows minimized `-32000`); re-asserts `maximized` on `Opened`. Read in `main()` before building the window.
  - `cache_dir`: `%LOCALAPPDATA%\askrypt\cache\`, `~/Library/Caches/askrypt/`, `$XDG_CACHE_HOME/askrypt`.
  - `VaultLocation` (`#[serde(untagged)]`, **`LocalFile` must stay first**): `LocalFile(PathBuf)` | `Server { base_url, email, name }`; `storage(client)` errs `Auth` without a matching client.
  - `ServerSession` token lives in separate `server_session.json` (0600 on Unix) — it is a credential.

## Encryption model

1. Answers normalized (lowercase, strip whitespace/dashes, optional RU/UK transliteration via `Params.translit`).
2. Two PBKDF2 derivations (600,000 iterations each by default), not one per answer: first answer → first key; remaining answers concatenated → second key.
3. Layered: first key unlocks remaining questions; second key unlocks the master key; master key encrypts entries and attachments.
4. Vault = ZIP of `askrypt.json` + encrypted blobs. See `SPEC.md`.

## Mobile app — `app/`

Pure-Dart Flutter (Android + iOS, no Rust/FFI). Byte-compatible with `core/` via golden vectors. Plan and status: **`app/PLAN.md`**.

- `lib/crypto/` — Dart port (`vault`, `kdf`, `aes`, `normalize`, `translit`, `secret_entry` incl. `CustomField`/`CustomFieldType`). Carries card keys, `custom_fields`, `attachments` and `files/` members (written with `compress = false`) though it cannot add/remove attachments.
- `lib/session/` — Riverpod: `UnlockedVault` (secret-free `EntrySummary`, reveal-on-demand, `toBytes()` via `masterForWrite`), sealed `VaultSession` (`VaultLocked`/`VaultUnlocked`) behind `vaultSessionProvider`. PBKDF2 is native via `cryptography_flutter` (Dart fallback in tests), `await`ed on the main isolate — no `Isolate.run`.
- `lib/screens/` — welcome, layered unlock, entries (search/tags/hidden), entry editor (custom fields editor with per-row `_FieldRow` controllers; read-only attachments + save-out via `VaultIo.saveAttachment`), questions editor, passgen, `auto_lock.dart`.
- `lib/passgen.dart` — port of `passgen.rs`.
- `lib/platform/` — seams faked in tests: `vault_io.dart` (`file_picker`); `host_name.dart` (`formatHostStamp` → `os@host`, drops blank/`localhost`); `recent_vault_store.dart` (caches encrypted bytes of last vault); `biometric_store.dart` (answers-only biometric unlock, keyed by `sha256(question0)`, plus one random answer as knowledge check); `secure_clipboard.dart` (30 s clear); `platform_security.dart` (`MethodChannel('askrypt/secure')`, `FLAG_SECURE`).
- `test/` — parity (`test/fixtures/vectors.json`), session, passgen, widget tests.

App ID `com.askrypt.app`, `minSdk 26`; `android/` and `ios/` shells tracked. **Android toolchain pinned** to AGP 8.11.1 / Gradle 8.14 / Kotlin 2.2.20 — don't bump to AGP 9 until file_picker supports it (floor AGP ≥ 8.9.1, compileSdk 36). `MainActivity` extends `FlutterFragmentActivity` (required by `local_auth`). iOS needs `NSFaceIDUsageDescription`.

## Server — `server/` (`askrypt-server`)

Axum server: accounts (email+password, Google), opaque vault storage, server-rendered website (askama + htmx). Never handles questions/answers/vault crypto. Plan: **`server/PLAN.md`** (Phases 0–5, 7–14 done; Phase 6 CI/CD open). Self-hosting: **`server/DEPLOY.md`**.

### Server-wide rules

- **Types live in `types.rs`** per module tree (`src/types.rs`, `src/store/types.rs`, `src/web/types.rs`), re-exported by the owning module. `impl` blocks stay with their module; derives (incl. every `impl Template`) moved with the types, so templates can only name types in scope in `web/types.rs`; formerly private fields are `pub(crate)`. Shared `TokenOnly`/`DeleteInput`/`Notice`. Exception: `main.rs`'s `Command`.
- **Handlers are thin wrappers**; rules are `pub(crate)` free functions (`auth`, `profile`, `vaults`, `admin`, `settings`, `devicelink`) called by both JSON API and `web/`. **Never re-implement a rule in `web/`** (e.g. login timing equalization in `auth::authenticate`).
- **CSP**: no inline `<script>`/`<style>`, no `hx-on:`, no `js:` htmx attrs; `tests/web.rs` guards it. Values reach scripts via `data-` attributes. Confirmations are `<details>`. Relaxed policies (`CSP_CAPTCHA`, `CSP_GOOGLE`, `CSP_CAPTCHA_GOOGLE`) only on `/login`/`/register`, never `'unsafe-inline'` scripts; selected by `hardening::policy()` from the `RelaxedCsp` response extension — **attach once per response** (`AuthForm::relaxed_csp` gathers both flags). The Google flag also sets COOP `same-origin-allow-popups`.
- **Schema changes to tables an applied migration created need a new numbered script** (sqlx checksums). Bump the migration-count unit test in `sqlite.rs`. Adding an `accounts` column touches six places in `sqlite.rs`.
- **Adding a role** = migration `INSERT` + `MemoryRoleStore::default` (same fixed uuid) + `pub const` in `store/mod.rs` + `admin::known_role`.
- **Config tables** for `ASKRYPT_*` vars live in `config.rs`, `README.md` and `server/DEPLOY.md` — keep all three in sync.

### Modules

- **`main.rs`** — parses args first (`--help`, `grant-admin <email>`, `backup <path>` = `VACUUM INTO`, refuses clobber/memory backend; no clap), then config, then tracing (console + daily-rotating file in `ASKRYPT_LOG_DIR` for serve only; `WorkerGuard` dropped before `process::exit`). Wires sqlite stores + two `DiskVaultBlobStore`s (`new` live, `versions` archived) or memory. Google verifier real iff `ASKRYPT_GOOGLE_CLIENT_IDS`; `SmtpMailer` iff `ASKRYPT_SMTP_HOST` (else `MemoryMailer` + `warn!` — it logs full bodies incl. tokens); `RecaptchaVerifier` iff site key (else `DisabledCaptchaVerifier` + `info!`). Startup asset check: `google.js`/`captcha.js` when configured; `landing.js` and viewer modules always. After bind, spawns `startup::notify_started`.
- **`startup.rs`** — "server is up" email (restart alarm): domain, bind, backend, data dir, build rev, clocks, memory/disk. Only via a real relay; cannot delay/fail startup; no account data. Recipient `ASKRYPT_ADMIN_EMAIL` or SMTP sender. `compose` is pure.
- **`sysinfo.rs`** — `memory()` (`/proc/meminfo`, `MemAvailable` preferred), `disk()` (`statvfs`, `f_bavail`, nearest existing ancestor), `format_bytes`; `None` when unreadable.
- **`config.rs`** — `Config::from_env()` over `Config::default()`: `ASKRYPT_BIND` (127.0.0.1:8080), `ASKRYPT_DOMAIN`, `ASKRYPT_ADMIN_EMAIL` (blank = unset), `ASKRYPT_DATA_DIR` (`data`), `ASKRYPT_BACKEND` (`sqlite`|`memory`), `ASKRYPT_STATIC_DIR` (`server/static`), `ASKRYPT_GOOGLE_CLIENT_IDS` (first = website button client — list the Web client first), `ASKRYPT_TRUST_PROXY` (false), `ASKRYPT_HSTS` (false), `ASKRYPT_REQUEST_TIMEOUT_SECS` (60), `ASKRYPT_MAX_CONCURRENT` (256), `ASKRYPT_MAX_BODY_BYTES` (64 KiB), `ASKRYPT_LOG_FORMAT` (`text`|`json`), `ASKRYPT_PASSWORD_API` (false), `ASKRYPT_LOG_DIR` (`logs`, empty = console only), `ASKRYPT_LOG_MAX_FILES` (14, 0 = keep all), `ASKRYPT_ARGON2_PARALLELISM`, `ASKRYPT_SMTP_{HOST,PORT,ENCRYPTION,FROM,USERNAME,PASSWORD,TIMEOUT_SECS}` (HOST enables, FROM required, user/pass together), `ASKRYPT_RECAPTCHA_{SITE_KEY,SECRET,MIN_SCORE}` (key enables, secret required, score in 0..=1). `smtp_from`/`recaptcha_from` take a lookup fn for testability.
- **`error.rs`** — `{"error":{"code","message"}}` via `ApiError`; `ApiJson`/`ApiBytes` extractors keep the envelope; `with_retry_after`. `ApiError::new` is the single logging funnel (`#[track_caller]`; 5xx `warn`, 4xx `debug`). Internals never sent to clients.
- **`routes.rs`** — `/healthz`; `/api/v1` (`/about`, `/me`, `/vaults`, `/auth/{google,logout}` + opt-in `/auth/{register,login}` on a 20/min limiter, `/auth/device{,/poll,/cancel}` on a separate 120/min limiter) with JSON 404 fallback; web routes; `/assets` (`ServeDir` + `revalidate`); `/favicon.ico`; HTML 404. **`register`/`login` API routes are not registered unless `ASKRYPT_PASSWORD_API`** (no client uses them; they'd bypass reCAPTCHA — enabling in prod reopens that). Vault routes raise `DefaultBodyLimit` to `MAX_VAULT_BYTES` inside the global limit. Layers declared innermost-first: body limit → `ClientIpPolicy` → timeout → shedding → security headers.
- **`hardening.rs`** — `security_headers` (`CSP` + nosniff/Referrer/XFO/Permissions/COOP/CORP, HSTS if configured), `no_store` (`or_insert`), `revalidate`, `request_timeout` (504), `concurrency_limit` (503 + `Retry-After`, `/healthz` exempt).
- **`clientip.rs`** — proxy headers trusted only under `ASKRYPT_TRUST_PROXY`; `X-Real-IP` else **last** `X-Forwarded-For`.
- **`audit.rs`** — account-security events on `askrypt_server::audit` (auth, `CAPTCHA_FAILED`, password/email changes, session revocation, deletion, admin actions with target in `account` and actor in `detail`, `SETTING_CHANGED`). Never logs tokens, passwords, or email on failed login. `ClientInfo` extractor. `testlog.rs` (`#[cfg(test)]`) captures events.
- **`auth.rs`** — register (argon2 on `spawn_blocking`, ≥8 chars), login (uniform 401; unknown users verify against `DUMMY_PASSWORD_HASH`), 256-bit hex bearer tokens, 30-day sessions, Google (verified email, create or link), logout, `AuthSession` extractor. `ARGON2_SLOTS` caps concurrent hashes. Free fns: `authenticate`, `register_account`, `issue_session`, `resolve_session`, `revoke_session_token`, `upsert_google_account`. Ban check **after** argon2 verify; also in `upsert_google_account` and `resolve_session` (all rejections the same 401; log `reason` + `session_fingerprint`, never the token; happy path at `trace`). Registration switch: checked first in `register_account`; in `upsert_google_account` only for new accounts. Both creation paths call `admin::bootstrap_first_admin`.
- **`devicelink.rs`** — desktop browser sign-in. `start` (public `link_id`, secret `poll_token`, display-only `user_code`, 24 h TTL, `interval`), `poll` (claim), `cancel`; `approve`/`deny` for the website. Rules: **bearer minted on claim, never stored**; `claim` is one atomic `DELETE … RETURNING`; poll re-checks ban; unknown/expired/claimed all answer `expired`; lazy `delete_expired` sweep on create. **Never accept `user_code` as input** (it's a comparison aid only).
- **`admin.rs`** — `list_users` (fixed store calls), `set_banned` (drops sessions), `set_role`, `delete_user` (via `profile::delete_account_data`), `bootstrap_first_admin` (grants `ADMIN` only if no admin exists and `accounts.count() == 1`; recovery: `grant-admin`). Guards `cannot_target_self`, `last_admin`, `confirmation_mismatch` (first two only for `ADMIN`). `has_role` is the single role check. **No JSON admin API.** Roles: `ADMIN`, `PAYMENT_USER` (paid quota only).
- **`settings.rs`** — runtime admin settings over string `SettingsStore`; typed accessors here (`registration_enabled`, `set_registration_enabled`). Unwritten/unknown/store-failure all read as the default (open).
- **`profile.rs`** — `/api/v1/me`: profile, `PUT /me/email`, `PUT /me/password` (re-auth if one exists; **changing** revokes other sessions, setting a first one doesn't), sessions list/revoke (id = SHA-256 of token), `DELETE /me` (cascade: version bytes → version index → blobs → meta → sessions → account). Own 20/min limiter.
- **`vaults.rs`** — `/api/v1/vaults`: list, upload `POST ?name=`, download, overwrite `PUT /{id}`, rename, delete, `/{id}/versions` (list, download, restore). ETag = SHA-256; downloads honor `If-None-Match` and set `private, no-cache`; overwrites require `If-Match` (428/412). Limits: `MAX_VAULT_BYTES` 10 MiB, `MAX_VAULTS_PER_ACCOUNT` 100, quota via `quota_for` (1 MiB, 100 MiB for `PAYMENT_USER`), writes only. Versions: `MAX_VAULT_VERSIONS` 5, archive/trim best-effort (never fail a save), trim keeps history within quota, identical bytes make no generation, restore = overwrite. Validates only ZIP magic + lifts stamp. Logs every op on `askrypt_server::vaults` via `log_op`/`log_version_op`/`log_list` — **ids and sizes only** (never names, bytes, ETags, stamps); reads logged in `blob_of`.
- **`vaultfile.rs`** — `read_stamp` lifts `params.host`/`updated_at` from `askrypt.json` (read-only zip, 1 MiB cap, never fails a save, host sanitized to 128 chars); `is_vault` checks for `askrypt.json` presence — used only by the website upload form.
- **`ratelimit.rs`** — fixed-window `RateLimiter` + middleware; `client_key` shared with `web`; 429 + `Retry-After`.
- **`state.rs`** — `AppState` of `Arc<dyn Trait>` seams (`vault_blobs` + `vault_version_blobs` same trait, `settings`, `captcha` whose `site_key()` is the source of truth). `in_memory()` uses `DisabledCaptchaVerifier`.
- **`store/`** — traits in `mod.rs`: `AccountStore` (`list` paged by `created_at, id`), `RoleStore`, `SessionStore`, `SettingsStore` (get/set only), `DeviceLinkStore`, `VaultMetaStore`, `VaultVersionStore`, `VaultBlobStore`, `Mailer`, `IdTokenVerifier` (+ `web_client_id`), `CaptchaVerifier`; `#[non_exhaustive]` errors; role/setting name constants. `memory.rs` fakes (same role uuids; empty settings; `FakeCaptchaVerifier`). `sqlite.rs` pool, embedded migrations, stores (cascades on account/vault delete, unique vault names per account, nullable `host`/`saved_at`/`banned_at`). `disk.rs` `<root>/<account>/<blob>.askrypt` (versions under `<account>/versions/`), atomic writes. `google.rs` RS256 JWKS verifier (60 s refetch floor). `recaptcha.rs` v3 verifier — checks `success`, **action match**, score; `assess` is pure; `Rejected` vs `Backend`; redacted `Debug`. `smtp.rs` `lettre` over rustls (never native-tls; `ring` must be the only provider), pooled, validated at startup, redacted `Debug`.
- **`web/`** — website.
  - `mod.rs`: HTML router, `rate_limit` (shares limiter instances with the API), `relax_csp`, `htmx_error_fragment` (outermost: re-renders `WebError` for htmx requests as `fragments/error_notice.html` at 200 with `HX-Retarget: main`; non-htmx keeps real status).
  - `render.rs`: `Page<T>`, `is_htmx`, `redirect_either_way` (303 / `HX-Redirect`), `timestamp`, `Chrome`/`Shell` (`is_admin` via `Shell::as_admin`).
  - `error.rs`: `WebError` from `ApiError`; 5xx text replaced — gated on `is_backend_failure`, **not** `is_server_error` (507 over-quota is user-actionable).
  - `session.rs`: `WebSession`/`MaybeWebSession` (7-day, `"Web browser"`, 303 to `/login`), `AdminSession` (403 for non-admins); cookies `HttpOnly; Secure; SameSite=Lax; Path=/`.
  - `csrf.rs`: random double-submit cookie (**not** derived from session token — `sha256(token)` is public in the device list); `CsrfForm<T>` and `CsrfMultipart` (verifies before buffering — hidden input must be first) are the only form-body readers. `flash.rs`: codes, not text.
  - `auth.rs`: login/register/logout; optional `?link=<uuid>` carried through (uuid, not a general `next=`, to avoid open redirects). `AuthForm` chains `with_captcha`, `with_google`, `registration_closed`.
  - `captcha.rs`: reCAPTCHA v3 on login/register; fixed per-form actions; `check` runs **before** argon2; generic message; backend errors fail closed; refused submit re-renders the token field empty. JSON auth API is not captcha'd.
  - `google.rs`: `POST /auth/google` (same limiter), credential minted in page by GIS and posted same-origin under normal CSRF; re-renders sign-in form on refusal; no `GET`.
  - `devicelink.rs`: `/link/{id}` — **visiting while signed in approves**; `POST /link/{id}/deny`.
  - `account.rs`: profile pages. `pages.rs`: landing, 404.
  - `vaults.rs`: file manager (multipart upload, download, rename, replace via row ETag, delete, quota, `Saved` column via `saved_stamp`, history with restore). Listing newest-change first (API keeps name order). `check_upload` (upload + replace): picked file must end `.askrypt` and pass `is_vault` (`invalid_vault_extension` vs `invalid_vault_file`). `download_filename` appends `.askrypt` when absent (`vault_extension_stem`). Rows link `/open?vault={id}`. `explain` maps error codes to sentences.
  - `admin.rs`: `/admin/users` (paged 50; suspend, promote/demote, paid tier, typed delete); both role toggles POST `/{id}/role` with hidden `role` (absent = `ADMIN`); actions re-render the whole `#user-list`. `settings.rs`: `/admin/settings`, `#server-settings` card; switch is hidden `enabled=true|false` (not a checkbox).
  - `open.rs`: viewer's server half — `GET /open` (signed-out allowed; `OpenPage.vaults: Option`) and `GET /open/vaults` fragment. **No POST**: reads via `vaults::download`, saves via `POST /vaults/{id}/replace`, new vaults via `POST /vaults`. Picker rows are buttons with `data-vault-id/-name/-etag` (ETag is the save's `If-Match`, hence re-readable fragment). No rate limiter.
- **`templates/`** — `layout.html`, `landing.html`, `auth_page.html`, `account.html`, `vaults.html`, `admin_users.html`, `admin_settings.html`, `link.html`, `open.html`, `error.html`, `fragments/` (`auth_form` — root is `<div id="auth-form">` holding two sibling forms — `email_form`, `password_form`, `devices`, `delete_account`, `vault_upload`, `vault_list`, `open_vault_list`, `user_list`, `settings_form`, `error_notice`). Every page template has `chrome: Chrome`. `{% block head %}` users: landing, auth_page, open (module script).
- **`static/`** — `style.css`, `favicon.ico`, vendored `htmx.min.js` (2.0.10), `captcha.js`, `google.js`, `landing.js`, viewer modules. No Node, bundler or CDN.
  - `captcha.js` keeps the token field fresh (load, 90 s, `htmx:afterSwap` on `document`). `google.js` draws the GIS button from `data-` attrs, re-draws on swap.
  - `landing.js` — hero typing demo; markup already has full text; skipped under `prefers-reduced-motion`; sets `aria-hidden` once running; fixed line heights; pauses when hidden/off-screen.
  - **Phase 14 viewer (`/open`)**: decrypts and creates vaults in the browser via WebCrypto. Server still sees no secrets; CSP not widened; nothing persisted (no storage APIs, URL fragment, console). Weakness stated on the page: the JS comes from this server.
  - `vault-format.js` — port of core, **pure** (no DOM/fetch/globals; parity script imports it unchanged). `createVault` requires a master key (`generateMasterKey` or `masterForWrite`). `DEFAULT_ITERATIONS`; hardening caps `MAX_JSON_BYTES` (1 MiB) and `MAX_ITERATIONS` (5,000,000). Multi-member ZIP: `readZipIndex` + `readZipMember(bytes, index, name, limit)`, `readZipEntry`; async `writeZip([name, contents, deflate])` — watch **local-header offsets** and EOCD sums. Attachments deflated via `CompressionStream` (`deflateRaw` → `null` falls back to stored). `sealAttachment`/`openAttachment`; `createVault` prunes blobs. `CUSTOM_FIELD_TYPES`, `customFieldKind`, `isChecked`, `MAX_CUSTOM_FIELD_*`; `custom_fields` omitted when empty.
  - `vault-smartlock.js` — port of `src/smartlock.rs`, not part of the format; 2,000,000 iterations, key answer never the first, IV per ciphertext, 8 h ceiling, no master key in bundle; pure. Parity script checks shape.
  - `vault-passgen.js` — port of `passgen.rs`, pure; defaults 20 chars/all sets, `clampLength` 8..=100; `randomIndex` uses rejection sampling (no `% n` bias).
  - `vault-open.js` — DOM only, no crypto. Flow: pick (stored or local file) → questions → entries (search/tags/hidden) → entry → save. Create flow (≥2 Q/A, same rules as `panes::questions::save`) sets `source.kind === "new"` until uploaded. Save re-encrypts under held answers + `masterForWrite`; stamps host `<os>@web`. **Save verdict reads the redirect destination** (`saveVerdict`: redirected to `/vaults` = saved, `/login` = session ended, 200 unredirected = refusal with sentence lifted from HTML). `requireSession` re-reads `GET /open` for a fresh CSRF token (never a fresh ETag). Text via `textContent` only. Attachments read-only (blob URL download), carried across saves. Custom fields editable (`customFieldRow`/`readCustomFields`; raw type in `data-type`; link `href` only for `http(s)`; hidden masked, not searched). Masking via `.masked` CSS (`-webkit-text-security`) instead of `type="password"` where supported (avoid browser password saving). Locks on Lock, 3 min idle, 60 s hidden; clipboard clears after 30 s. **Smart Lock**: arming re-encrypts page contents (loses nothing; refuses one-question vaults); only the button arms it — automatic locks keep nothing, except a session that came from a Smart Lock (`state.smartDeadline`) re-arms (best effort, else full lock). Ceiling restarts each transition; `smart` lives outside the state object.
- **`tests/`** — tower `oneshot` HTTP tests. `common/mod.rs`: `config()`, `password_api_config()` (most suites use it for bearer tokens). Suites: `http`, `auth` (incl. password API absent by default), `profile`, `vaults`, `hardening`, `web` (incl. `/open` — save-landed vs no-session are both 303 to different places), `admin`, `device_link`, `captcha` (`FakeCaptchaVerifier`; captcha checked before argon2), `settings`, `google_signin`. Slow-handler middleware is unit-tested in `src/hardening.rs`; `last_admin` in `src/admin.rs`.
- **Deployment — `server/Dockerfile` + `server/deploy/`** — containers only. Build image from **repo root** (`docker-build.sh`, passes `GIT_HASH`/`GIT_COMMIT_MSG` → `ASKRYPT_BUILD_REV`/`_MSG`). `./deploy.sh dev|prod` → `spot.yml`: build locally, ship `docker save | gzip`, `docker load`, `run.sh`, wait for container + `/healthz` via `docker exec askrypt-caddy wget`. `docker-compose.yml` (server + Caddy; project `askrypt`; no `build:`, `pull_policy: never`). Everything in `/home/askrypt-server` (`.env` from `env.example`, never uploaded; `data/`, `logs/` bind mounts matching image paths). `run.sh` fixes dir ownership (uid 10001, 0700), `compose up -d --remove-orphans`, prunes images. `Caddyfile` uses `{$ASKRYPT_DOMAIN}`, overwrites `X-Forwarded-For`/`X-Real-IP`. Backups: `askrypt-server backup` snapshot **before** tarring blobs; `backup.sh` (cron, uploaded not run) snapshots via `docker exec` into data dir, copies the deployment dir, removes live `askrypt.db`/`-wal`/`-shm` from the copy, tars to spool.

## Key dependencies

| Crate | Purpose |
|-------|---------|
| `iced` | GUI |
| `aes` + `cbc` + `cipher` | AES-256-CBC |
| `pbkdf2` + `sha2` | Key derivation |
| `serde` + `serde_json` | Serialization |
| `zip` | Vault format; server read-only for the stamp |
| `rfd` | Native file pickers only (confirmations are `src/confirm.rs`) |
| `rand` | RNG |
| `tokio` | `spawn_blocking` for crypto and server requests |
| `ureq` | Blocking HTTP for `server-storage` (rustls/ring) |
| `askama` | Server templates |
| `lettre` | SMTP (rustls) |
| `tracing-appender` | Server rotating logs |
| `libc` | `statvfs` (unix) |

## Build & Test

```
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p askrypt                              # desktop
cargo run -p askrypt -- ~/vaults/MyVault.askrypt    # optionally open a vault
cargo run -p askrypt-core --example gen_vectors     # after format changes; then run both gates
cargo run -p askrypt-server                         # then curl /healthz
scripts/server-roundtrip.sh [--backend sqlite]      # live conformance run (local only)
cargo run -p askrypt-core --features server-storage --example server_roundtrip \
  -- http://localhost:8080 me@example.com correct-horse
cargo run -p askrypt-server -- backup /path/snap.db
docker build -f server/Dockerfile -t askrypt-server .   # from repo root
node scripts/vault-js-parity.mjs                    # browser port parity (not in CI)

# Mobile — Flutter SDK at /home/ruslan/Apps/flutter
cd app && flutter test
cd app && flutter analyze
```

The root `Cargo.toml` raises `opt-level` for `pbkdf2`/`sha2`/`aes`/`argon2`/`blake2` in the **dev profile** (600k unoptimized PBKDF2 iterations take minutes). Keep those overrides.

## CI / Release

- `.github/workflows/ci.yml` — Ubuntu build + test on every push.
- `.github/workflows/release.yml` — Linux x86_64, macOS ARM64, Windows MSVC + win-gnu zip, Windows installer, `.deb`.
- Windows: static CRT (`.cargo/config.toml`); `build.rs` embeds the icon.
- `installer/windows/askrypt.iss` — Inno Setup (`iscc /DMyAppVersion=0.7.1 installer\windows\askrypt.iss`); per-user, fixed `AppId` (upgrades in place), leaves `%APPDATA%\askrypt\` on uninstall.
