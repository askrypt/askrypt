# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Askrypt is a cross-platform password manager. It authenticates users via security question answers (normalized and hashed with PBKDF2) rather than a master password, using AES-256-CBC encryption for vault data — entries and **file attachments** alike. The repository is a Cargo workspace holding a **desktop Rust app**, a **pure-Dart Flutter mobile app** (`app/`) and an **axum server** (`server/`) whose website carries a third client — the in-browser viewer at `/open`. The mobile app and the browser viewer each re-implement the same vault format, in Dart and in JavaScript — see [Mobile app](#mobile-app-app) and the server's `web/open.rs` below.

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

The crypto/format engine lives in the **`core/`** crate (`askrypt-core`, lib name `askrypt`) and is the source of truth for the vault format. The desktop Iced app in **`src/`** depends on it, and there are now **two re-implementations**, both kept in lock-step with it by the same golden test vectors and neither sharing a line of code with it: the Dart mobile core in **`app/lib/crypto/`** and the browser port in **`server/static/vault-format.js`**, which the server's `/open` page runs (Phase 14). A format change is therefore a change in three places plus `SPEC.md`, and the two parity gates — `cd app && flutter test` and `node scripts/vault-js-parity.mjs` — are what catch a missed one. **File attachments raised the stakes of that rule.** A save rebuilds the whole archive from the entry list, so a client that did not know about the `attachments` key would not merely ignore it — it would drop the references *and* the `files/` members, deleting every attached file in the vault. That is why all three implementations carry attachments even though only the desktop can add or remove one, and why the golden vault fixture now holds an attachment: like the card entry beside it, it exists so that a port which silently dropped the key still fails the gate. Phase 0 extracted the engine into `core/`; older docs may still say it lives in `src/`.

The dependency arrows only ever point one way: `askrypt` (desktop) → `askrypt-core`, and **`askrypt-server` depends on neither** — it stores vaults as opaque bytes and must never link the crypto core. The desktop crate talks to the server through `core`'s `server-storage` backend, which is a *client* of the HTTP API, so that rule is unaffected.

### Core crate — `core/src/` (the security model)

- **`core/src/types.rs`** — Core data types: `SecretEntry`, `CardFields`, `Attachment`, `Attachments`, `Params`, `QuestionsData`, `MasterData`, `MasterSecret`, `AskryptFile`. Re-exported from `lib.rs`. `SecretEntry` carries the six card fields in a `CardFields` sub-struct that is **`#[serde(flatten)]`ed**, so the wire format is six sibling keys — `card_holder`, `card_brand`, `card_number`, `card_expiry`, `card_cvv`, `card_pin` — and there is no `card` object in the JSON. They are grouped on the Rust side only because `SecretEntry` zeroizes on drop and Rust forbids `..Default::default()` on a `Drop` type (E0509): six loose fields would have to be spelled out in all fifteen-odd literals that build an entry, one grouped field costs each of them a single `card: Default::default()`. Every one is `skip_serializing_if = "String::is_empty"`, so an entry that is not a card serializes exactly as it did before they existed and an older file parses with all six blank — which is why **`version` stays `"0.9"`**: `from_bytes` hard-rejects any other value, so a bump would make new files unreadable by every shipped build. They carry meaning only for entries whose `type` is `"Card"` (compared case-insensitively — the three clients spell types differently). `CardFields` derives `Zeroize` but deliberately not `ZeroizeOnDrop`: `SecretEntry`'s own reaches in and wipes `number`/`cvv`/`pin` with the rest, and staying `Drop`-free keeps `..Default::default()` usable on *it*. `Params` also carries the optional, **unencrypted** write stamp `host` (`os@host`, e.g. `ubuntu@mypc`) + `updated_at` (RFC 3339 UTC, second precision), omitted from JSON when absent so pre-stamp vaults round-trip unchanged. `host` is opaque display text, never parsed: older vaults hold a bare host name with no OS half. **`MasterSecret`** is the vault's 32-byte master key in the clear (`generate`/`from_slice`/`as_bytes`, `Zeroize` + `ZeroizeOnDrop`, and a hand-written `Debug` that prints `<redacted>` because it rides inside the desktop app's `Message` enums, every one of which derives `Debug`). It is what makes the key a property of the *vault* rather than of a particular write — see the `create`/`decrypt_with_master` note below.

  **File attachments** are the second thing living under that key, and they are split in two on purpose. `Attachment` is the *metadata* — `id`, `name`, `size`, `added`, `iv` — and rides inside the encrypted entry list as `SecretEntry.attachments` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so an entry with no files serializes exactly as it did before, which is again why `version` stays `"0.9"`; `Zeroize` but not `ZeroizeOnDrop`, for `CardFields`' E0509 reason). `Attachments` is **where each blob can be read from, and never the blob** — a `BTreeMap<String, AttachmentSource>` plus the `origin` archive those sources are relative to — and hangs off `AskryptFile` as a `#[serde(skip)]` field, because each blob is a **ZIP member of its own**, `files/<id>`. `AttachmentSource` is `Carried` (a member of `origin`) or `Sealed(PathBuf)` (a ciphertext file the caller wrote, which is what a freshly attached file is until the next save folds it in). It used to be a `BTreeMap<String, Vec<u8>>`, which put every attachment in memory for the life of the open vault and made a vault with a few large files unopenable; the shape is what fixed that, and everything in it is now cheap to clone, compare and print, so it rides inside the desktop's `Message` enums for free. Putting it on `AskryptFile` is what leaves `VaultStorage` untouched and what carries attachments through every desktop typestate: they are ciphertext, so even a `Locked` vault holds them. `retain_referenced` is the garbage collection `create` runs on every write; `adopt` is what re-points every source at the archive a save just wrote, and `sealed_paths` is what tells the caller which scratch files that made redundant. **`origin: None` is the one failure case**: `from_bytes` has nowhere to read a blob from a second time, so a vault parsed from a slice lists and decrypts its attachments but `write_archive` **refuses** rather than emitting an archive with the members missing — `SPEC.md` rule 4 makes silent deletion the worst outcome. The `id` is 32 random hex characters and is the *whole* of the member's name, so an archive listing says how many files a vault holds but never what they are called — the count and the sizes do leak, and `SPEC.md` says so rather than padding them.
- **`core/src/lib.rs`** — Crypto core: encryption (AES-256-CBC), key derivation (PBKDF2/SHA-256), ZIP archive handling, serialization, and the readers and writers below. **Nothing here ever holds an attachment's bytes.** `write_archive(W: Write + Seek)` is the one writer: it writes `askrypt.json`, then streams each referenced attachment from its source — a `Sealed` file is copied in and deflated like every other member, a `Carried` one is copied across **verbatim** by `ZipWriter::raw_copy_file`, same compressed bytes, method and CRC, no inflate and no crypto at all (legal because the master key never rotates, and now `SPEC.md` rule 5). `to_bytes` is the buffered convenience over it, for the server backend and the tests. `from_path` is the reader the desktop uses: it parses `askrypt.json` and *lists* the `files/` members without opening one, so a vault holding a gigabyte of attachments opens in the memory an empty one does; `from_bytes` is its buffered twin, with the `origin: None` caveat above. `seal_attachment_to_file` / `open_attachment_to_file` are the streaming crypto pair (64 KiB chunks over an incremental CBC chain, byte-identical to the one-shot `seal_attachment`/`open_attachment`, which stay as the oracle the tests check them against), and `extract_attachment` pairs the opener with the archive layout. Measured: **~4 MiB peak RSS for a 1 GiB attachment**, through attach, save, re-save and extract. **`MAX_ATTACHMENT_BYTES` is gone** — it bounded an allocation that no longer happens, and would only have stopped legitimate vaults opening; the bomb guard moved to `MAX_JSON_BYTES` (1 MiB on `askrypt.json`, the one member a reader must hold whole, matching `server/src/vaultfile.rs` and the browser port). The Dart and JS ports still inflate, so they keep their own ceiling; that is a property of a reader, not of the format. `save_to_file`/`load_from_file` are thin conveniences over `LocalFileStorage`. **The master key is minted once, at vault creation, and preserved for the life of the vault**: `create`'s sixth parameter is `master: Option<&MasterSecret>` and `decrypt_with_master` hands the key back out of the same derivation that opens the vault (`decrypt` is the wrapper that drops it). Every save — including a change of questions and answers — must pass the recovered key, so that the blobs living under it (the file attachments) are not orphaned; `None` is for a brand-new vault only. **`create`'s seventh parameter is `attachments: &Attachments`**, and it exists as a parameter rather than a field you assign afterwards for exactly one reason: forgetting it is then a compile error at every call site instead of a save that silently deletes every attached file. It writes only the blobs the entries being written still refer to (`retain_referenced`), which is what makes deleting an attachment shrink the vault and what makes an orphan self-healing. `seal_attachment`/`open_attachment` are the pair around `encrypt_with_aes`/`decrypt_with_aes` — no new primitive — minting a random id and a **fresh IV per encryption**, the latter load-bearing under a key that never rotates. `salt0`, `salt1` and the `data` IV are still regenerated on every write, and the IV must be: AES-CBC under a repeated key *and* IV would let anyone holding two versions of a vault read off how long a prefix of the entry list went unchanged. `SPEC.md`'s "Master key lifetime" section is the normative statement. `AskryptFile::touch` (called at the end of `create`, i.e. on every save, since saves rebuild the file) stamps `params.host`/`params.updated_at` via the `current_host`/`now_utc_rfc3339` helpers (`gethostname` + `chrono`). `current_host` writes `<os>@<host name>` — the OS half comes from `current_os`, which on Linux prefers the `ID=` value out of `/etc/os-release` (`parse_os_release_id`, cached in a `OnceLock`, rejecting anything that is not `[a-z0-9._-]` since this lands unencrypted and then in a web table cell) and otherwise `std::env::consts::OS`; a missing host name yields the OS name alone, never a dangling `ubuntu@`. Contains 25+ unit tests. This is the heart of the security model.
- **`core/src/storage/`** — `VaultStorage` trait (`mod.rs`): the backend-agnostic persistence seam over opaque vault bytes (`read`/`write`/`exists`/`location` plus `load_vault`/`save_vault` default methods built on `to_bytes`/`from_bytes`; the defaulted **path door** `archive_path`/`read_to_path`/`write_from_path`, which is how a caller streams instead of buffering — `archive_path` is `Some` only for a backend that *is* a file, and `None` means the caller must spill a copy before an attachment can be read out of it; the defaulted `acquire_lock`, granted by default because a remote backend has no local file to guard and already detects a concurrent write through its revision; and the defaulted **revision trio** `revision`/`current_revision`/`adopt_revision` that lets a caller *follow* a vault for outside changes). A `Revision` is an opaque token naming one version of the bytes — the ETag for `ServerStorage`, mtime+length for `LocalFileStorage` — and nothing outside a backend may interpret one; `revision()` is what this instance last read or wrote (cheap, no I/O) while `current_revision()` asks the backend what it holds *now* (worker-thread only, `Ok(None)` meaning the vault is gone) and answers a `RemoteRevision`, which carries the write stamp too when the backend already knew it (the server's listing does; a local file would have to be opened, so it answers `None`). **`current_revision` must not touch the cached revision**: that value is the `If-Match` the next write sends, and a probe that adopted what it found would silently convert the change it just detected into a licence to overwrite it — `adopt_revision` is the separate, deliberate act, and `probing_leaves_the_conflict_check_armed` guards the split. A backend answering `None` from `revision()` is *unfollowable*, which callers must not read as unchanged. Sync, object-safe, `Send + Sync`; errors are the dedicated `StorageError` (`#[non_exhaustive]`): `Io`/`Format`/`Locked` plus the network variants `Network`/`Auth`/`Conflict`/`Remote { status, code, message }`, all defined **unconditionally** so the error type does not change shape with the feature flags. `mod.rs` also holds `MemoryStorage` (tests/fakes); each backend gets its own file — `local_file.rs` (`LocalFileStorage`, which now **stages and renames rather than truncating in place** — a save reads the archive it is replacing, so it cannot write over it, and the old bare `fs::write` also meant a crash mid-save left neither the old vault nor the new one — and takes an advisory **write lock for as long as it lives**. The lock is on a *sidecar*, `<vault>.lock`, not on the vault file, and the decisive reason is portable rather than Windows-specific: **a save replaces the file**, renaming the new archive over the old one (it must — writing it reads the one it replaces), so a lock on the vault would end up held on an inode nothing points at, and the next process to ask would take one on the new file and get it. One save and the guarantee is gone; the sidecar is never renamed. The Windows reason is secondary but real: `LockFileEx` is mandatory and `File::try_lock` takes the whole 64-bit range, so locking the vault's own bytes would stop our *own* second handle from reading a carried member — on Unix `flock` is advisory and this does not arise. **Only a lock someone else holds is an error**: if the sidecar cannot be created (read-only directory) or the filesystem does not do locks (some network mounts), `acquire_lock` succeeds *without* one, because the lock stops two apps writing one archive and neither case is one this app could write in — refusing would make a vault on read-only media unopenable, which it never was. `Arc<dyn VaultStorage>` already lives exactly as long as the open vault — the ETag invariant — so the lock's lifetime is right for free, and dropping the handle releases it) and `server.rs` (`ServerClient` + `ServerStorage`, behind the default-off `server-storage` feature so a plain `cargo build -p askrypt-core` stays free of HTTP/TLS; the desktop crate enables it).
  - `server.rs` is the **client half of the cloud story**: `ServerClient` is one authenticated handle to a server's `/api/v1` (`begin_browser_login`/`login`/`with_token`/`logout` + `list`/`create`/`download`/`overwrite`/`rename`/`delete`), and `ServerStorage` is one vault on it, addressed by *name*.
    `begin_browser_login` is how the desktop signs in now: it opens a device link and returns a `BrowserLogin` carrying the URL to open, the code to display, and `poll`/`cancel` (`BrowserLoginStatus` = `Pending`/`Approved { client, email }`/`Denied`/`Expired`). Three details are load-bearing: its `Debug` **redacts the poll token**, which is bearer-equivalent for the session it will claim and rides inside UI message enums; the server's `verification_path` is **validated as a plain path** before a URL is built from it, because handing it to `open::that` makes a hostile server a redirect primitive; and the poll response is deserialized **flat**, so a status this build has never heard of degrades to "keep waiting" rather than a parse error. `login` (email + password) is still exported and unit-tested, but **no client in this repo calls it any more** — the desktop signs in through the browser link, and the old screen-per-step UI that used the password form is gone. `RemoteVault`, the listing row, carries the server's own `updated_at` **and** the file's `host`/`saved_at` — the unencrypted write stamp the server lifts off the bytes — both `Option` + `#[serde(default)]` so an unstamped file (nulls) and an older server (keys absent) parse alike. `normalize_base_url` is public for callers that must compare server URLs exactly (see `VaultLocation::Server`). Over `ureq` 3 (blocking, rustls/ring), **not** `reqwest::blocking` — the trait is sync and `reqwest::blocking` panics when built inside an async context, which is exactly where the desktop calls it from. The agent sets `http_status_as_error(false)` because the server's `{"error":{"code","message"}}` envelope lives in the body of a 4xx/5xx. ETags are stored unquoted and sent quoted; `read` records the ETag it saw and `write` sends it as `If-Match`, so **a `ServerStorage` instance must live as long as the open vault** — a fresh one would re-resolve the *current* ETag and clobber another device's edit. That invariant is what `Session.storage` exists to hold. `core/examples/server_roundtrip/` is the manual end-to-end gate against a running `askrypt-server` (an example, not a test, so no crate ever links both `askrypt-core` and `askrypt-server`) — see [Conformance runner](#conformance-runner--coreexamplesserver_roundtrip) below.
- **`core/src/passgen.rs`** — Password generator with configurable character sets and length.
- **`core/src/translit.rs`** — Russian/Ukrainian-to-English transliteration using BGN/PCGN romanization, QWERTY-only output. ё→yo, е→e, ъ/ь dropped, тс and ц both→ts. Ukrainian: ґ→g, є→ye, і→i, ї→yi.
- **`core/examples/gen_vectors.rs`** — Emits golden test vectors to `app/test/fixtures/vectors.json`. The fixture vault carries a card entry *and* a `File` entry with a real attachment, both there for the same reason: to make a port that silently dropped a key it has no UI for fail the gate rather than pass it. The blob reaches the archive as a *sealed file* (`insert_sealed`), like every freshly attached one, with the ciphertext still pinned to a fixed key and IV. Note the emitted `vault_b64` is **not** byte-stable across runs — `touch` stamps `params.updated_at` and `host` on every write — so "regenerate and diff" is not a check; running the two gates is. Two things about `scripts/vault-js-parity.mjs` bear repeating, because both hide a failure behind an `ok`: its `serialized()` is a **whitelist**, so a new per-entry key is invisible to the gate until it is added there; and `group()` now *forwards its callback's return value* and **fails a group that ran no checks at all**. It did neither before, which meant `const opened = await group(...)` was always `undefined` and the entire "save and reopen (round trip)" group — the half that pins the writer — returned at its own `if (!opened) return;` while printing `ok`. Adding attachments is what surfaced it: the check count went 68 → 79 when it was fixed. Read by **both** ports: the Dart parity tests and `scripts/vault-js-parity.mjs`, which imports `server/static/vault-format.js` unchanged under Node's built-in WebCrypto. Regenerate whenever the format or normalization changes, then run both gates.

#### Conformance runner — `core/examples/server_roundtrip/`

The live-server gate: it walks **every** endpoint `askrypt-server` exposes — the JSON API, the website, and the administrator's pages — and reports a pass/fail table with a non-zero exit code. It lives in `core/examples/` rather than in a test crate for the reason its module doc gives: a test linking both `askrypt-core` and `askrypt-server` would put the crypto core in the server's build graph, which is the one thing the server's premise forbids. `scripts/server-roundtrip.sh` is the entry point — it starts a throwaway server, registers an administrator (the *first* account registered, per `admin::bootstrap_first_admin`) plus a plain account, and runs the suite as both.

Six things about it are load-bearing:

- **It refuses any host that is not loopback** (`main::guard_local`, no override flag). It bans accounts, deletes accounts and flips the registration switch; pointed at a deployment it would be destructive.
- **It branches on the account's role rather than being told.** `GET /admin/users` answers 200 for an administrator and 403 for anyone else, and that is the probe. The *refusal* half — every admin route answering 403, rendering no table, and changing nothing — runs on **every** invocation: as the given account when it is not an administrator, and as throwaway A when it is. One run always covers both halves.
- **Mutations only ever land on throwaway accounts** it registered itself (`roundtrip-<pid>-{a,b}@roundtrip.invalid`); the account named on the command line never has its email or password touched. Teardown deletes them, deletes the vaults, restores the registration switch and signs out — and every step is itself a reported check, so a leak is visible.
- **`http.rs` follows no redirects and never sends `HX-Request`.** On the website a successful mutation is a **303** and a *refused* one re-renders at **200** (`web::auth::rejected`, `web::admin::finish`), so the status alone is the verdict; following redirects would erase it, and `web::htmx_error_fragment` would turn every 4xx into a 200.
- **429 is expected, not a failure.** Every `/admin/*` route shares one 20/minute bucket with the profile mutations, and every identity in the run comes from one address, so the admin group stops to wait. `Retry-After` is honoured where the API sends one; the website's HTML twin states the window in its sentence instead, which is where the wait comes from there.
- **Unrunnable groups are skipped with a reason, and skips are reported separately from passes.** With reCAPTCHA configured no scriptless client can sign in, so the website and admin groups cannot run; with registration closed there are no throwaways (an administrator opens it for the run and restores it, anyone else does without).

### Desktop app — `src/` (Iced GUI)

`askrypt` is an Iced binary (`cargo run -p askrypt`) carrying a three-pane layout (drawn in `UI.md` §1): a left navigation rail, a middle item list, a right detail pane, a search strip on top and a status bar always pinned to the bottom. It replaced a screen-per-step UI — one screen per stage of the vault lifecycle, with Open reachable only from a Welcome screen — which lived in `src/{app,message,ui}.rs` + `src/screens/` and was deleted once this one took over the binary; older docs and commits still describe it.

**`UI.md` is the design notes** — the layout and module map, the state table, the transition table, the button-visibility table, the invariants and **where each is enforced**, what is still not real, and what is still open. Keep it current alongside this file.

`include_bytes!` paths are `"../static/…"` from `src/`.

Files: `main.rs` (`App`/`Section`/`Pane`/`Message`/`VaultMsg`/`GlobalMsg`/`PendingAction`, the `visible()`/`reconcile_selection()` filter pair, `default_pane()`/`effective_pane()`, the subscription, the tray/keyboard handling, and the outer `column![search, row![panes].height(Fill), status_bar]` that keeps the status bar on the bottom edge; `set_pane` returns a `Task` because leaving the Wizard or Settings **abandons a browser sign-in in flight** — closing the pane says the user no longer wants it), `manager.rs`, `smartlock.rs`, `session.rs`, `settings.rs`, `tray.rs`, `theme.rs`,
`scratch.rs` (this run's working directory, `<cache>/session-<pid>/` under `AppSettings::cache_dir`: a freshly attached file's ciphertext and, for a cloud vault, a copy of its archive — both ciphertext, so nothing in there is a secret in the clear, but both *working files* that must not outlive the process. It holds an exclusive lock on its own `.lock` for the life of the run, which is what makes the startup sweep exact rather than a guess: a sibling `session-*` directory whose lock can be **taken** belongs to a process that has exited, so age heuristics and pid probing — either of which could delete a live instance's sealed attachments — are unnecessary. Removed on drop, and emptied before that by `clear`, which `Session::close_vault` calls: closing leaves nothing that can read a spilled cloud archive or an attachment sealed for a cancelled editor, and waiting for the drop would keep both on disk for the rest of the run. Opening a vault *over* another cannot empty the directory — the incoming vault's own copy is already in it — so `Session::open_vault` retires the outgoing one's files by name instead (`manager::retire_working_files`, `retire_origin`'s did-we-make-it test applied to the origin and every sealed path). Not the system temp directory, because `/tmp` is memory-backed on many Linux installs, which would put an attachment straight back in RAM),
`follow.rs` (following the stored vault: the 60 s + window-focus probe, the pure `decide` policy, `Notice`/`Kind` and the banner the shell renders above the working area. Not a pane, for `link.rs`'s reason — the vault it is about is open whichever pane is showing, so its state lives on the `Session`, in three fields `clear_messages` deliberately spares. A clean vault reloads silently, since `Unlocked` still holds every answer and needs to ask for nothing; anything unsaved — `is_modified()` **or** an open entry-editor or questions draft — raises the banner instead. Every reload writes a status line naming who saved the bytes and when, off the vault's own unencrypted stamp via `data::format_stamp`. The probe never sets `session.busy` — it runs every minute and would otherwise make the app look permanently busy — but the *reload* it may lead to does, because reading moves the backend onto the version being fetched and a save squeezed in alongside would inherit that revision and replace the other device's work with no banner ever shown. `busy` does not stop *typing*, so `App::install_reload` re-checks for unsaved work at the moment of applying, and every path that declines rolls the backend's revision back with `adopt_revision`), `link.rs` (browser sign-in: `LinkState`/`LinkPoll`/`Msg`, `update`, `abandon`, and the `waiting_card`/`sign_in_button` both the wizard and Settings render. Not a pane, because two panes start one and it outlives either; the in-flight link lives on the `Session`. Every reply is **generation-tagged** — cancelling cannot abort a request already in flight, so a late reply from a cancelled sign-in must be dropped rather than installed. The wait deliberately does **not** hold `session.busy`: that hides the very controls, Cancel among them, the user needs while waiting, and the spinner only animates while busy — so the waiting card is static. Polling uses the server's own `interval`, treats a 429 as retryable rather than terminal, and stops after 15 minutes with "open the page again" (the link itself stays valid on the server for 24 hours, so Reopen resumes the same one). The device label is `askrypt::current_host()` — the same `os@host` string the vault write stamp uses), `icon.rs` (glyph codepoints read out of the repo's own `bootstrap-icons.ttf` — note the font has no bare `plus`, only `plus-lg`), `data.rs` (pure item helpers over `SecretEntry`: the entry types — now three, `Login`/`Card`/**`File`**, with `is_card`/`is_file` the two case-insensitive predicates the whole UI branches on — the filter (which reaches attachment *file names*, visible metadata like the cardholder, unlike the card secrets it deliberately skips), hash-tags, `format_size`, the unencrypted write stamp, and `DATETIME_FORMAT` — the single local-time rendering, `%b %-d, %Y %H:%M`, that `format_timestamp_local` (Unix seconds) and `format_rfc3339_local` (RFC 3339 text, verbatim when unparseable) both apply, so entry stamps, the write stamp and the server vault listing read alike), and `panes/{mod,sidebar,list,detail,entry_editor,questions,passgen,settings,unlock,wizard,statusbar}.rs`. Selection is an index into `session.entries`, never into the filtered view, so filtering can't invalidate it. Each list row draws `icon::placeholder(&entry.name, ..)` — a stand-in for the favicon or issuer logo a real item would carry, picked from a 16-glyph pool by hashing the name rather than actually randomized, because `view` runs every frame and a random pick would flicker. The root is **not** wrapped in a centering container — the panes are full-bleed.

`panes/mod.rs` defines **`Action`** (`None`/`Run`/`Pane`/`PaneRun`), the navigation-as-data contract between a pane and the shell. A pane's `update(state, &mut Session, msg) -> Action` mutates shared state and *says* where to go; `App::apply` does the switching. The working area right of the rail is **not always two panes**: `view` branches on `Pane`, so `Items` splits it into list + detail (or list + entry editor, when a draft is open) while `Settings`, `Unlock`, `Wizard`, `Questions` and `PassGen` each fill it alone.

`src/manager.rs` is **the vault, as a typestate**: `Vault<S>` where `S` is one of `Locked` / `PartiallyUnlocked` / `Unlocked` / `SmartLocked`, and **the state struct carries that state's data** — a locked vault has no `master: Option<…>` that happens to be `None`, it has no master-key field at all. Every state also holds `file` (the ciphertext, never absent while a vault is open) and `home: Option<VaultHome>`, where `VaultHome` pairs the `VaultLocation` with the **live backend instance** so the two can never be half-set; all load/save goes through that instance, never a freshly built one — rebuilding per save would throw away a server vault's ETag and silently overwrite another device. `home: None` means "never written anywhere", which is exactly what makes a first Save become a Save As. Attachments ride on `Vault<S>.file` rather than on any state, because they are ciphertext: every state carries them, a lock keeps them, and nothing has to be decrypted to preserve them. `Vault<Unlocked>` exposes `attachments()` and `add_attachment`, and there is deliberately **no** `remove_attachment` — dropping an attachment is dropping the *reference* on the entry, and the source goes when the next `create` prunes, which is also what makes a cancelled removal put the file back. For the same reason `add_attachment` does not set `modified`: what makes the vault dirty is applying the entry, so attaching a file and then cancelling the editor leaves an orphan rather than a phantom unsaved change. `AttachInputs`/`ExtractInputs` are the two worker triples, and **neither carries bytes any more**: `AttachInputs` streams the picked file through `seal_attachment_to_file` into a scratch path, answering an `Attached { attachment, sealed: PathBuf }` (a path, so the iced `Message` it rides in is cheap to clone rather than a multi-megabyte copy), and `ExtractInputs` takes an `AttachmentSource` plus the `origin` and streams straight to the destination, opening its own handle on the archive so two extracts never contend. Both still have hand-written `Debug` impls like `SaveRequest`'s. **`read_vault` is now the single way the app opens a vault** — `load_vault` is not used by the desktop at all: it claims the file via `acquire_lock`, then either reads it in place (`archive_path`) or spills a copy to the scratch directory (a server vault, which has no local archive to stream carried attachments out of). `write_vault` correspondingly assembles the replacement with `write_archive` into a staging file — beside the destination when there is one, so the hand-over is an atomic rename within one filesystem — hands it over with `write_from_path`, and only *then* `adopt`s the new archive, deletes the sealed files it folded in and `retire_origin`s the one it superseded. `retire_origin`'s test is **did the scratch make it**, not anything about the backend: a Save As moves a vault between homes, so the superseded archive is quite often a local vault file the *user* owns. `back_up_locally` is now a `fs::copy` of what just landed rather than a second full run of the writer. Because a typestate cannot live in a fixed-type struct field, **`VaultState` is the erasure** — one variant per state plus `None` — and `Session` holds one of those; a pane matches on it and gets back a handle carrying only the operations that state allows (`save_request` is on `Vault<Unlocked>` and nowhere else). Three consequences are load-bearing: **locking is dropping the state** (`Zeroizing` answers plus core's `ZeroizeOnDrop` on `QuestionsData`/`SecretEntry`/`MasterSecret`, so there is no `zeroize_secrets` to forget to call); the states and the worker-result types must **not** derive `ZeroizeOnDrop`, since it implies `Drop` and a `Drop` type cannot be destructured (E0509) — which is what `with_state` and every transition do, the same constraint `core`'s `CardFields` documents; and **`Unlocked.master` is not an `Option`** — every path in has a key, so the save path has no mint-on-write branch and a *write* returns a `SavedVault` while an *open* returns an `OpenedVault`, two types rather than one whose `master: None` could be mistaken for "the key is gone". `RekeyInputs::run` is the single place in the app that mints one. `write_vault` is also where the **local copy of a cloud save** is made, from `AppSettings::local_backup_dir()`: *after* the real write lands (so no copy exists of a version the server never accepted), *only* for a `VaultLocation::Server` home (a local vault is already a file here), and never able to fail the save — the outcome rides back in `SavedVault.backup` as a path or a sentence and becomes one status line. `backup_file_name` treats the vault's name as the untrusted server-stored text it is, keeping only the last path component so nothing can name a file outside the chosen directory. Following the stored vault adds one more triple — `VaultState::reload_inputs` → `ReloadInputs::run` on a worker → one of `apply_reloaded`/`apply_refreshed`/`apply_requestioned`/`relock_with` — whose shape follows from the states: a `Locked` or `SmartLocked` vault only needs the bytes, a `Partial` one re-runs `get_questions_data`, and an `Unlocked` one rebuilds outright *without asking the user anything*, because it still holds every answer. `ReloadOutcome::Rekeyed` is the case where the bytes arrived but those answers no longer open them — the other device changed the questions — and it carries the new file so the vault can relock onto the *current* bytes rather than sit on a version known to be superseded. `ReloadInputs` deliberately has no `Drop` impl (the `Zeroizing` in `ReloadKeys` wipes itself, and `run` destructures it — E0509 again). **No derivation runs on the main thread**, so each transition is a triple: a method producing owned `Send` inputs (`RevealInputs`/`UnlockInputs`/`SmartLockInputs`/`SmartUnlockInputs`/`RekeyInputs`/`SaveRequest`), that struct's `run` on a worker (converting core's non-`Send` `Box<dyn Error>` into a `String` or a `VaultError`), and a `self`-consuming `apply_*` on `VaultState` called from the completion message. The answers never ride in a message — the pane already holds what the user typed — and an apply is only reached from the *success* arm, so a wrong answer leaves the vault untouched; an apply arriving in the wrong state returns `false` and drops the stale result. `src/smartlock.rs` holds the 2M-iteration `create`/`recover` pair, moved off `Session`; the bundle itself is the `SmartLocked` **state** — like every other state it carries its own fields (the two ciphertexts, the salt, an IV each and `armed_at`) rather than wrapping a separate data struct, so `create` returns one and `recover` reads one.

`src/session.rs` is now only the shell's own shared state around one `vault: VaultState`: settings, tray, status/error messages, spinner, `last_user_activity`, the three **sticky** follow fields (`follow`/`dismissed_revision`/`last_reload` — sticky because `clear_messages` wipes the transient three on every non-passive message, and both a standing question about the stored copy and the line naming who last reloaded it have to outlive the next keystroke; `status_line` reads `last_reload` below error/success/status and above the vault's own line, and `settle_follow`/`reset_follow` are the two resets, the first for edges that *answer* the question — a save, a lock — and the second for edges that end it), the sign-in (`server_client: Option<Arc<ServerClient>>` + `server_email`, with `sign_in`/`sign_out`), and `scratch: Option<Arc<Scratch>>` — an `Arc` because every worker that touches an attachment needs it and a `spawn_blocking` closure must own what it captures; `None` means the platform offered no cache directory, which costs only the ability to attach a file. It keeps the few lifecycle bits that touch the settings file (`remember_vault`, `close_vault`) and the read-only `entries()` projection panes share. Failures travel as **`VaultError`**, a `Clone + Debug` classification of `StorageError` (which is neither), logged in full on the worker — including `Locked`, "that vault is already open in another Askrypt window", which is what the sidecar lock surfaces as; `Session::report_vault_error` words it for a save, `describe_sign_in_error`/`describe_open_error` for the server and open paths. `App::guard(PendingAction)` is the unsaved-changes gate: "Yes" starts an async save and replays the queued action from `App.after_save` once it lands, so Lock/Smart Lock/New/Open/Exit all wait for it. **Smart Lock is gated too** — arming it drops the `Unlocked` state, entries and all, so an ungated one silently loses unsaved edits — and `App::auto_smart_lock` (the idle timeout, which nobody is present to answer) saves first when the vault has a home and declines to lock when it does not. The dirty flag lives *in* `Unlocked` (`VaultState::is_modified()` is false in every other state), so it cannot outlive the edits it describes.

`VaultState` also carries the **button-visibility rules** — `label`, `can_create`/`can_open`/`can_close`/`can_unlock`/`can_smart_lock`/`can_lock`/`lock_label`/`can_save`/`can_save_as`/`can_edit_questions`/`can_cancel_wizard`, plus `is_open`/`is_unlocked`. There used to be a separate `src/vault.rs` holding a `Status` enum re-derived from the session's fields; it had exactly the same five values, so it was a copy of `VaultState`'s discriminant kept in step by hand, and it is gone. The predicates cover the rail's vault buttons (New Vault / Open Vault / Close Vault / Unlock / Smart Lock / Lock-Full Lock / Save / Save As / Edit Questions, pinned at the rail's bottom with the password generator, then Quit and Settings
in bands of their own below them) — the sidebar only asks, never matches on the variants itself. Buttons are *hidden*, not disabled, when a state disallows them, and the item filters plus the search strip exist only while unlocked (`effective_pane()` also refuses to render the item list over a locked vault; every lock path calls `App::clear_secret_panes`). New Vault is the one action that lands *unlocked* — the questions editor runs and leaves `home: None`, which is what makes a first Save become a Save As. Open and Save As route through the single `panes::wizard` source picker (Local file via `rfd::AsyncFileDialog`, Askrypt Server via `ServerClient`, and a disabled Cloud-folder placeholder); a plain **Save never reaches the wizard**, because it must write through the backend the vault was opened with (the ETag invariant). Choosing Local file while *saving* opens the native save dialog immediately (`wizard::save_dialog`, prefilled with the vault's name) instead of asking for a file name first — the dialog covers folder and name — so the wizard's file step is Open-only. The wizard's server step holds **no credentials at all** — it offers "Sign in with your browser" (or the waiting card), and the Settings pane's Account group carries the same button beside the one server field. Entering the server step while signed in to a *different* server than the configured one signs out first; that check lives there rather than in the settings handler because that pane saves on every keystroke and would otherwise sign the user out mid-word. Entering it **always refetches the account's vault listing** — a listing cached per sign-in hides vaults saved since, both as a missing row when opening and as a missing "will be replaced" warning when saving — so `Refresh` is an explicit re-fetch, not the only one; the old rows stay up while the request runs, and `wizard::State::listing` is what stops a first, still-running listing from reading as "No vaults on this account yet." The **save** direction renders that listing too, read-only (`info_row`, a container not a button, showing size, the server's `updated_at` and the file's own `host`/`saved_at` stamp) with the row that would be replaced marked, and its name field reports a full `NameStatus` — `Empty`/`Checking`/`Unknown`/`Free`/`Replaces(i)` — rather than only speaking up on a collision: an unfetched or failed listing used to render as silence, which reads exactly like a name checked and found free. The collision test is `eq_ignore_ascii_case` while the server's uniqueness is byte-exact, a known inaccuracy the marked row is there to expose. `src/settings.rs` carries `AppSettings`: `recent_vaults` (a real MRU, feeding the wizard's recent list) plus `theme`/`lock_timeout`/`minimize_to_tray`/`show_hidden_by_default`/`clear_clipboard`/`server_url`/`backup_to_local_dir` + `backup_dir`/`window`, every one `#[serde(default)]` so a `settings.json` written by an older release still parses. `server_url` is the one server the app talks to (default `https://askrypt.com`, `DEFAULT_SERVER_URL`); read it through `AppSettings::server_url()`, which normalizes via **core's own** `normalize_base_url` — a saved `VaultLocation::Server` is matched to a signed-in client by exact string, so a second normalization here would leave vaults unopenable. The manual `Default` impl must set it too; `#[serde(default = …)]` only covers parsing. `window` is a `WindowState` (`size`, optional `position`, `maximized`) restoring the window where the user left it: `main()` reads it *before* building the window, since `boot` runs after. It always stores the geometry the window **unmaximizes** back to — iced has no maximized event, so `App::record_geometry` parks what a move or resize reported and one `window::is_maximized` round trip decides whether `commit_geometry` keeps it, which also debounces a drag to one probe per 250 ms. Values that are nonsense (`WindowState::sane_size`/`sane_position`) are dropped rather than remembered, because Windows reports a minimized window at `-32000, -32000` sized `0 x 0` and this app minimizes to the tray; a stale geometry that fails `is_usable` falls back to the default centered window. The `maximized` flag is re-asserted on `window::Event::Opened`, as some window managers drop `window::Settings::maximized` when a position is given alongside it. `backup_to_local_dir` (default **false**) + `backup_dir` are the *local copy of every cloud save*, and they are one setting in two fields — read them through `AppSettings::local_backup_dir()`, which answers `None` unless both are set, since a switch with nowhere to write is not a place to write to. The Settings pane keeps the pair in step (turning the switch on opens the folder picker, and cancelling it leaves the switch off), so "on" always means a directory was chosen; a hand-edited `settings.json` need not have, which is why the accessor and not the flag is what the save path asks.

`src/settings.rs` also holds the on-disk shapes around those values. `AppSettings` is JSON in the platform config directory (`AppSettings::config_dir`): `%APPDATA%\askrypt\` (Windows), `~/Library/Application Support/askrypt/` (macOS), `~/.config/askrypt/` (Linux). `AppSettings::cache_dir` is its throwaway counterpart — `%LOCALAPPDATA%\askrypt\cache\`, `~/Library/Caches/askrypt/`, `$XDG_CACHE_HOME/askrypt` — and is where `scratch.rs` works: what goes there is a vault's working files, which a backup of the user's settings has no business sweeping up and which the platform may delete at will. `VaultLocation` is the serializable identity of a vault's storage backend (`#[serde(untagged)]`): `LocalFile(PathBuf)` serializes as a plain path string so old `settings.json` files stay compatible, and `Server { base_url, email, name }` as an object, which untagged deserialization tells apart — **`LocalFile` must stay the first variant**. Its `storage(client)` factory returns `Arc<dyn VaultStorage>` and fails with `StorageError::Auth` when a server location has no matching signed-in client. A server vault is keyed by *name*, not by the server-assigned id. `ServerSession` (`base_url`/`email`/`token`) is the saved sign-in, deliberately in its own `server_session.json` created `0600` on Unix rather than in `settings.json`: the token is a credential — it authorizes `PUT /me/email` and `DELETE /me`, neither of which re-asks for the password.

### Security / Encryption Model

1. User provides answers to security questions.
2. Answers are normalized (lowercased, whitespace/dashes stripped, optionally transliterated from Russian/Ukrainian via `Params.translit`).
3. Each answer is used with PBKDF2 (600,000 iterations by default) to derive a key.
4. A layered encryption scheme: first answer unlocks subsequent questions, all answers together unlock the master key, the master key encrypts the actual secrets.
5. Vault files are ZIP archives containing JSON metadata and encrypted blobs. See `SPEC.md` for the full format specification.

**Known gap — the format provides confidentiality but no integrity.** `qs`, `master` and `data` are unauthenticated AES-256-CBC: no MAC, no AEAD, and `params` (including the `host`/`updated_at` write stamp) is neither encrypted nor authenticated, so it is a hint and never evidence. Well-formed padding, valid UTF-8 and parsable JSON are the only things a reader can check, and they are heuristics rather than integrity checks. Fixing it means AES-256-GCM and a **breaking bump to `version = "1.0"`** — see `SPEC.md`, "Integrity: not provided" and the "TODO: authenticated encryption" section, which is the normative write-up. Two things there bear on anything built in the meantime: a GCM nonce must be 96 fresh random bits per write (nonce reuse under the long-lived master key is far worse than CBC IV reuse — it forfeits unforgeability), and any future feature that reports a decryption outcome back over the network would create the padding oracle the current design happens not to have.

Secret material is wiped from memory with [`zeroize`](https://docs.rs/zeroize): the secret-bearing structs (`SecretEntry`, `MasterData`, `QuestionsData`) derive `ZeroizeOnDrop`, and transient scratch (derived keys, normalized/combined answers, hashed answers, decrypted plaintext buffers) is wrapped in `Zeroizing` in `core/src/lib.rs` and the desktop Smart Lock paths. Note: `core` derives keys via the `derive_key` helper rather than `calc_pbkdf2(..)?.try_into()`, which would free the PBKDF2 `Vec` without wiping it; in the desktop app the lock/Smart-Lock handlers `.zeroize()` secrets instead of `.clear()` (which only truncates). The `aes`/`cbc` cipher's internal key copy is not reachable and stays unwiped. The Dart mobile app has no equivalent (GC'd, immutable strings).

### Mobile app — `app/`

A **pure-Dart Flutter** app for Android + iOS (no Rust on device, no FFI/bridge). It re-implements the vault format in Dart and must stay byte-compatible with `core/`; parity is guaranteed by golden test vectors, not shared code. Full plan and phase status live in **`app/PLAN.md`**.

- **`app/lib/crypto/`** — Dart port of the crypto core (`vault`, `kdf`, `aes`, `normalize`, `translit`, `secret_entry`), mirroring `core/src/*.rs`. `SecretEntry` carries the `attachments` key and `AskryptFile` the `files/` members (written with `compress = false`, since `ArchiveFile.compress` defaults to *true* and ciphertext must not be deflated) for the same reason it already carried the six `card_*` keys, only more so: this app cannot add or remove an attachment, and a save that dropped them would delete every attached file in the vault.
- **`app/lib/session/`** — Riverpod session layer: `UnlockedVault` (in-memory state, secret-free `EntrySummary`, reveal-on-demand CRUD, `toBytes()`) and a sealed `VaultSession` (`VaultLocked`/`VaultUnlocked`) behind `vaultSessionProvider`. The 600k-iteration PBKDF2 work is CPU-bound, so `pbkdf2` (`crypto/kdf.dart`) delegates to native, hardware-accelerated platform crypto via `cryptography_flutter` (Android `javax.crypto` / iOS CommonCrypto), falling back to the `cryptography` Dart impl off-device (tests) — byte-identical output, verified by the golden vectors. Native runs without blocking the Dart event loop, so the crypto entry points are plain `async` and `await`ed on the main isolate (no `Isolate.run`): `AskryptFile.getQuestionsData`/`create`, `UnlockedVault.open`/`toBytes`. `UnlockedVault` holds the vault's master key (`_masterKey`, set by `open` via `AskryptFile.decryptWithMaster`, carried through `withQuestions`, minted by the first `toBytes` when the vault is brand new) and passes it to `AskryptFile.create`'s `masterKey` parameter on every save — the Dart half of the preservation rule in `SPEC.md`. The unlock screen shows a progress indicator while a derivation runs.
- **`app/lib/screens/`** — Feature-parity screens (welcome, layered unlock, entries list + search/tags/hidden, entry editor — which lists an entry's attachments read-only and can save one out through `VaultIo.saveAttachment`, but not add or remove one — questions editor, password generator) plus `auto_lock.dart` (lock on background / inactivity).
- **`app/lib/passgen.dart`** — Dart port of `core/src/passgen.rs`.
- **`app/lib/platform/`** — Platform seams, faked in tests: `vault_io.dart` (over `file_picker`); `host_name.dart` (the `params.host` stamp — `formatHostStamp` joins `Platform.operatingSystem` and `Platform.localHostname` into the same `os@host` label the Rust core writes, e.g. `android@pixel-8`, dropping either half when it is missing, blank or the `localhost` placeholder Android reports; behind a swappable `hostNameResolver`, and `UnlockedVault.toBytes` passes it to `AskryptFile.create`, which stamps `updated_at` itself. No `/etc/os-release` read here, so a Flutter desktop build says `linux` where the Rust core says `ubuntu` — the field is cosmetic and feeds no derivation); `recent_vault_store.dart` (caches the **encrypted** bytes + name of the last successfully unlocked vault in the app-support dir via `path_provider` — SAF URIs have no persistable path — refreshed on unlock/save, behind the welcome screen's "Open \<name\>" reopen button); and the Phase 4 mobile-security seams `biometric_store.dart` (answers-only biometric quick-unlock via `local_auth` + `flutter_secure_storage`, keyed by `sha256(question0)`; the unlock screen additionally asks one randomly chosen security answer as a knowledge check before opening), `secure_clipboard.dart` (sensitive copy + 30 s auto-clear), and `platform_security.dart` (the `MethodChannel('askrypt/secure')` for `FLAG_SECURE` + sensitive-clipboard, implemented in `MainActivity.kt`/`AppDelegate.swift`).
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
manager), 8 (roles + the admin Users page), 9 (the paid storage tier), 10
(the browser device link that signs desktop apps in), 11 (reCAPTCHA v3 on
the website's auth forms), 12 (server settings + the registration switch) and
13 ("Sign in with Google" on the website) and 14 (the in-browser vault
viewer) are done. Still open: Phase 6 (CI/CD).
Self-hosting is documented in **`server/DEPLOY.md`**.

**Phase 14 reversed a Phase 7 decision, and the reversal is the design.** The
site used to say, on the landing page and in the footer, that it could not
open a vault; `/open` now does, entirely in the visitor's browser over the Web
Cryptography API, and it **creates** one there too — questions, answers and a
freshly minted master key, none of which leave the page. What did *not*
change: the server still stores opaque bytes,
still never sees an answer, a master key or a plaintext entry, and still does
not link `askrypt-core` — the browser port is its own file. What is genuinely
weaker than an app, and what the page says in as many words: the code is
JavaScript **this server sent**, so a compromised or dishonest server could
send different JavaScript, where a desktop or mobile app was installed once
and the server has no say in it. Everything else is bounded on purpose — no
CDN, no bundler, no dependency, no inline script, **no widened CSP** (the base
`script-src 'self'` / `connect-src 'self'` already covers it, unlike the
captcha and Google-button pages), and nothing persisted in the browser at all
(no `localStorage`, no `sessionStorage`, no IndexedDB, no URL fragment, no
console).

**Types live apart from behaviour.** Every struct, enum and type alias the
crate declares sits in a `types.rs` for its module tree — `server/src/types.rs`
(the API envelope and extractors, request/response bodies, `Config`,
`AppState`, the middleware's marker types), `server/src/store/types.rs` (the
records the seams move, the error enums, the concrete backend handles and the
`sqlx` row structs) and `server/src/web/types.rs` (every askama template, form
input, cookie-session extractor and the flash vocabulary). Each module then
**re-exports what it owns**, so `auth::LoginRequest`, `error::ApiJson`,
`store::Account`, `store::memory::MemoryAccountStore` and
`web::render::Chrome` all resolve exactly as before — nothing outside the
crate learned a new path. Three rules follow, and each has bitten already:
`impl` blocks stay with their module (Rust only wants them in the same
*crate*), so `impl Config` is still beside the `ASKRYPT_*` constants and the
hand-written `Debug` impls that redact the SMTP and reCAPTCHA secrets are
still in `store/smtp.rs` and `store/recaptcha.rs`; **derives moved with their
struct**, which puts every `impl Template` in `web/types.rs` and means a
template may only name types in scope *there* (today just `Outcome`, which
`link.html` writes out); and fields that were module-private are now
`pub(crate)`, since the handlers that build them are no longer in the same
module — the *types* kept the visibility they had. Adding a type means
declaring it in the right `types.rs` and re-exporting it from the module whose
behaviour it belongs to. Three names that had been copied per module —
`TokenOnly`, `DeleteInput` and `Notice` — were byte-identical and are now
single types re-exported by each of their old homes. The one thing left in
place is `main.rs`'s `Command`: the binary is its own crate, and `mod types;`
there would resolve to the *library's* `src/types.rs`.

**Desktop sign-in is browser-driven** (`server/src/devicelink.rs` +
`server/src/web/devicelink.rs`, `BrowserLogin` in `core`, `src/link.rs`).
The app never asks for an account password: it opens a *device link*, launches
`/link/{id}` in the browser, and polls until the server hands it a bearer
token. Registration therefore works from the app too, which no password prompt
could offer. Two invariants hold the design together: **no session token is
stored on the link row** — the bearer is minted when the app *claims* the link,
so an approval nobody collects leaves no live session — and **the claim is one
atomic store call**, so two polls racing cannot both mint one. `src/` keeps the
old `ServerClient::login` form and is unaffected.

**Google sign-in has two surfaces, one set of rules.** `POST
/api/v1/auth/google` takes an ID token a native client minted; the website's
own button (`server/src/web/google.rs`, Phase 13) posts one to `/auth/google`.
Both verify through the `IdTokenVerifier` seam and then call
`auth::upsert_google_account`, which is where creating, linking, the
registration switch and the ban check live — **never re-implement any of it in
`web/`**. Three things are specific to the browser half. The credential is
minted **in the page** by Google Identity Services and posted **same-origin**,
so the form is covered by the site's ordinary `CsrfForm` double-submit check
rather than by Google's `g_csrf_token`; a redirect-mode POST would arrive
cross-site with no `SameSite=Lax` cookie attached, which is what would force a
second CSRF scheme onto the one endpoint that hands out sessions. It costs one
relaxed header, `Cross-Origin-Opener-Policy: same-origin-allow-popups` — a
popup cannot answer its opener under plain `same-origin`, and it fails
silently. And **whether there is a button is the verifier's answer**
(`IdTokenVerifier::web_client_id`, the mirror of `CaptchaVerifier::site_key`),
not the config's, so a page can only offer a button whose credential this
server can check. That id is **the first of `ASKRYPT_GOOGLE_CLIENT_IDS`** —
there is deliberately no variable of its own, since taking it from the
audience list makes "the id the button mints for is an accepted audience" true
by construction. The cost is a convention to document: list the
Web-application client first, because nothing in a client id says what kind it
is and a native one there renders a button Google itself refuses.

**Roles and the first account.** The `roles` table is seeded by the migration
with two roles at fixed uuids, so both backends name the same rows: `ADMIN`
(the Users page) and `PAYMENT_USER` (the paid storage tier — it grants
`vaults::PAID_ACCOUNT_QUOTA_BYTES` instead of `ACCOUNT_QUOTA_BYTES` and
nothing else). `account_roles` is the many-to-many grant table. Adding a role
means four places: the migration's `INSERT`, `MemoryRoleStore::default` (which
copies the uuid and description by hand), a `pub const` in `store/mod.rs`, and
`admin::known_role`, the whitelist that keeps a hand-made POST to
`/admin/users/{id}/role` from naming anything the page does not offer.
`admin::bootstrap_first_admin`
grants `ADMIN` to the **first account ever registered** — the rule is narrow
on purpose (no administrator exists *and* `accounts.count() == 1`), so a later
registration can never be promoted just because the administrators were
deleted; `askrypt-server grant-admin <email>` is the recovery path. Banning is
an `accounts.banned_at` stamp, checked in `auth::authenticate` (after the
password verify, to keep login timing non-enumerable),
`auth::upsert_google_account`, and `auth::resolve_session` — the last of which
covers bearer tokens and browser cookies alike, so a ban bites on the very
next request.

- **`server/src/types.rs`** — Every type the crate root declares, grouped by
  the module that owns the behaviour over it: `ApiError`/`ApiResult`/`ApiJson`/
  `ApiBytes` and the serialized `ErrorBody`, `ClientIpPolicy`, `ClientInfo`,
  `Config`/`Backend`/`LogFormat`/`ConfigError`, `AppState`, `RateLimiter`,
  `RelaxedCsp`/`SecurityHeaders`, the auth/devicelink/profile/vaults request
  and response bodies, `AuthSession`, `AdminUser`, `VaultStamp`,
  `MemoryUsage`/`DiskUsage`, and the
  `#[cfg(test)]` tracing-capture types. See the "Types live apart from
  behaviour" note above before adding one. `crate::settings` declares none of
  its own — it is constants and free functions over the store seam.
- **`server/src/main.rs`** — Startup: tracing init (`RUST_LOG`), env-var config,
  backend selection, graceful shutdown (Ctrl+C/SIGTERM). The `sqlite` backend
  wires `SqliteAccountStore`/`SqliteRoleStore`/`SqliteSessionStore`/
  `SqliteSettingsStore`/`SqliteVaultMetaStore`/
  `SqliteVaultVersionStore` plus **two** on-disk `DiskVaultBlobStore`s over
  the *same* root — `new` for the live vaults, `versions` for the archived
  generations — with `vaults_dir()` created at startup so a backup script
  never tars a path no upload has made yet; the
  Google verifier is real when `ASKRYPT_GOOGLE_CLIENT_IDS` is set, else
  `NotConfiguredIdTokenVerifier` (501) — configured means the *website*
  renders a sign-in button too, so `google.js` joins the startup asset check
  and the id that button will carry is logged as `website_button=`, which is
  where an operator sees they listed their Android client first — and the
  mailer is a real `SmtpMailer`
  when `ASKRYPT_SMTP_HOST` is set, else `MemoryMailer` behind a `warn!` (built
  once for both backends, before the `AppState` match, so a bad relay or
  sender address aborts startup rather than the first send). The captcha is a
  real `RecaptchaVerifier` when `ASKRYPT_RECAPTCHA_SITE_KEY` is set, else
  `DisabledCaptchaVerifier` behind an `info!` (not a `warn!` — a self-hosted
  server behind the rate limiter alone is legitimate, and it keeps the auth
  forms working without JavaScript); `captcha.js` joins the startup asset
  check only then, since without it nobody can sign in at all. The four
  viewer modules (`vault-format.js`, `vault-smartlock.js`,
  `vault-passgen.js`, `vault-open.js`) are checked **unconditionally** —
  `/open` is linked from the nav on every page, so
  without them it is a page that does nothing. Serves with
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
  drops it by hand first. Once the listener is bound it spawns
  `startup::notify_started` on its own task — **after** the bind, so the mail
  only goes out for a server that is actually up, and detached, so a relay
  that takes ten seconds to answer does not hold serving back.
- **`server/src/startup.rs`** — The "server is up" email: which deployment
  (`ASKRYPT_DOMAIN`), where it listens, the backend, the data dir, the build
  revision, the server's own wall clock *and* its UTC reading, plus the host's
  free/used memory and the free/used space on the data directory's
  filesystem. It exists as a **restart alarm** — a deploy explains one, an OOM
  kill or a recycling container does not. Three rules: it sends only through a
  real relay (with none configured the mailer *logs* messages in full, so a
  notice there would be console noise and no delivery); it cannot delay or
  fail startup (spawned after the bind, a refused delivery is a `warn!`); and
  the body carries no account data, counts or secrets, so a shared operations
  mailbox is a fine destination. `recipient` is `ASKRYPT_ADMIN_EMAIL` or, unset,
  the SMTP sender — configuring a relay is enough. `compose` is pure and takes
  the probes and the timestamp as arguments (a `DateTime<FixedOffset>`, so the
  offset is in the test rather than in the test machine's timezone).
- **`server/src/sysinfo.rs`** — The two host probes that notice feeds on, and
  nothing else in the server reads: `memory()` parses `/proc/meminfo`
  (`MemAvailable`, falling back to `MemFree` on pre-3.14 kernels — never
  `MemFree` when both exist, or a healthy server reads as nearly out of
  memory), `disk()` is `statvfs` via `libc` (`f_bavail`, the unprivileged
  figure, walking up to the nearest existing ancestor so the data directory
  need not have been created yet), and `format_bytes` is the binary-unit
  rendering. Every probe answers `None` rather than zero when it cannot read —
  "0 free" would be an emergency, "unavailable" is the truth. In a container
  the memory figures are the *host's*; the disk figures are real, the data
  directory being a bind mount.
- **`server/src/config.rs`** — `Config::from_env()`, layered over
  `Config::default()` (which tests use directly): `ASKRYPT_BIND`
  (default `127.0.0.1:8080`), `ASKRYPT_DOMAIN` and `ASKRYPT_ADMIN_EMAIL` (both
  `Option<String>` via `non_empty`, where a blank value means unset because the
  compose file passes them through as `"${VAR:-}"`; neither is routed on —
  they only address and name the startup notice), `ASKRYPT_DATA_DIR` (default
  `data`, gitignored),
  `ASKRYPT_BACKEND` (`sqlite` default | `memory`), `ASKRYPT_STATIC_DIR`
  (default `server/static`, i.e. `cargo run` from the workspace root),
  `ASKRYPT_GOOGLE_CLIENT_IDS` (comma-separated ID-token audiences; empty
  disables Google sign-in, and the **first** is also what the website's own
  sign-in button is rendered with), plus the Phase 5 knobs
  `ASKRYPT_TRUST_PROXY`
  (default **false** — fail closed), `ASKRYPT_HSTS` (default false),
  `ASKRYPT_REQUEST_TIMEOUT_SECS` (60), `ASKRYPT_MAX_CONCURRENT` (256),
  `ASKRYPT_MAX_BODY_BYTES` (64 KiB) and `ASKRYPT_LOG_FORMAT` (`text`|`json`).
  `ASKRYPT_PASSWORD_API` (default **false** — fail closed) exposes
  `POST /api/v1/auth/{register,login}`; see `routes.rs` for why they are off.
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
  Bot protection is `recaptcha: Option<RecaptchaConfig>`, parsed the same way
  by `recaptcha_from` out of `ASKRYPT_RECAPTCHA_{SITE_KEY,SECRET,MIN_SCORE}`:
  the site key is the switch, the secret is then **required** (a key without
  one would render the field and verify nothing, which is worse than no
  captcha because it looks protected), and the score is range-checked to
  `0.0..=1.0`, so `0.5` fat-fingered as `5` fails at startup rather than
  locking every visitor out.
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
  rate limiter, plus `/auth/device{,/poll,/cancel}` on a **separate** 120/min
  limiter — a desktop app polls every few seconds and would eat the login
  budget in half a minute, and several devices can share one NAT address)
  with a JSON 404 fallback covering everything under `/api`;
  the HTML routes from `web::routes(auth_limiter, profile_limiter,
  device_limiter)` at the
  root (all three limiters shared with their `/api/v1` twins); the configured static dir
  mounted at `/assets` (`tower-http` `ServeDir`, under `hardening::revalidate`
  so an edited `style.css` can't linger in a browser cache); and an HTML 404
  fallback.
  **`POST /api/v1/auth/{register,login}` are opt-in** (`ASKRYPT_PASSWORD_API`,
  default off) and are *not registered* when disabled rather than answering
  from a stub — the `/api/v1` fallback already renders a JSON 404 in the
  standard envelope, and an absent route tells a prober nothing. Three facts
  make this free: no client in this repo calls either one (the desktop signs
  in through the browser device link, mobile has no server code), the
  website's own forms call `auth::authenticate`/`auth::register_account`
  directly rather than going through the JSON handlers, and those two routes
  were the one password surface reCAPTCHA cannot cover, since a v3 token can
  only be minted in a page. `/google` and `/logout` stay on unconditionally —
  the desktop calls logout, and a Google credential is not a guessable
  password — and the conditional routes are added **before** `route_layer`,
  so all four share the 20/min limiter. The test suites and
  `scripts/server-roundtrip.sh` turn the flag on, since they take their bearer
  tokens from `/login`.
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
  The documented exceptions are the other three policies, sent only by
  `/login` and `/register` and only for the widget the page actually
  rendered: `CSP_CAPTCHA` (naming `www.google.com`/`www.gstatic.com` and
  allowing inline **styles**, for reCAPTCHA's injected badge stylesheet),
  `CSP_GOOGLE` (the sign-in button — every host path-scoped, out of the
  source list Google publishes for `accounts.google.com/gsi/`, plus inline
  **styles**: Identity Services styles the button with inline `style`
  attributes on elements it writes into the page, and without the concession
  the button renders unstyled) and
  `CSP_CAPTCHA_GOOGLE`, their union. `script-src` is free of
  `'unsafe-inline'` in all four, and `POLICIES` + the unit tests hold every
  new one to that. `policy()` is the whole selection; a page opts in with the
  `RelaxedCsp` **response extension** — now two flags rather than a marker,
  so a captcha page is not handed the sign-in host or the other way round —
  read by `security_headers`, the same trick `web`'s `ErrorInfo` uses and
  necessary because this layer is the outermost one and would otherwise
  overwrite anything an inner layer set. Google's alternative is a
  per-request nonce, which would make the policy a per-response value. The
  `google` flag also swaps `Cross-Origin-Opener-Policy` to
  `same-origin-allow-popups`: the sign-in popup answers its opener, and under
  plain `same-origin` it silently cannot. **Attach `RelaxedCsp` once per
  response** — a second insert replaces the first, which is why
  `web::auth::AuthForm::relaxed_csp` gathers both flags before anything is
  built.
- **`server/src/clientip.rs`** — Shared client-address resolution for
  `ratelimit` and `audit`. Proxy headers are trusted only under
  `ASKRYPT_TRUST_PROXY` (installed as a `ClientIpPolicy` request extension),
  preferring `X-Real-IP` and otherwise taking the **last** `X-Forwarded-For`
  element — proxies append, so the first element is client-supplied.
- **`server/src/audit.rs`** — Structured account-security events on the
  `askrypt_server::audit` tracing target (register/login/Google/logout,
  the captcha refusals ahead of them (`CAPTCHA_FAILED`, naming the form and
  no account — none has been resolved that early, and the submitted address
  is exactly what a failed login must not log),
  password set/change + failed re-auth, email change, session revocation,
  account deletion, and the Phase 8 admin actions — ban/unban, role
  grant/revoke, admin-initiated deletion, where the `account` field names the
  account acted *on* and the acting administrator goes in `detail`; plus
  Phase 12's `SETTING_CHANGED`, the one admin event with no account it was
  done *to*, so `account` is the administrator themselves), plus the
  infallible `ClientInfo` extractor (IP + capped
  user agent). Never logs tokens, passwords, or the email on a *failed* login.
  Vault *file* operations are not audit events — they log from `vaults.rs` on
  its own target. `server/src/testlog.rs` (`#[cfg(test)]` only) is the
  thread-local `Capture` both modules' tests use to assert on what was
  emitted, and on what was not.
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
  defaults to `debug`. Phase 12 hung the **registration switch** off the same
  two account-creation paths: `register_account` checks
  `settings::registration_enabled` **first**, before `validate_email`, so a
  closed server neither spends an argon2 hash nor answers differently for an
  address that happens to be taken, and `upsert_google_account` checks it
  **inside the `None` arm only** — signing in with an existing Google account,
  and *linking* Google to an existing address, both stay open. Both raise the
  same `registration_disabled()` 403. Gating there rather than in `web/` is
  what gives the browser form its rendered message for free.
- **`server/src/devicelink.rs`** — Phase 10: the desktop sign-in a browser
  completes. `POST /api/v1/auth/device` opens a link (public `link_id` for the
  URL, secret `poll_token` for the app, a display-only `user_code`, a
  **24-hour** TTL, and the `interval` the client must poll at, handed over so
  the cadence and the rate limit cannot drift apart);
  `POST /auth/device/poll` claims it; `POST /auth/device/cancel` drops it when
  the app closes its sign-in pane, so an abandoned link stops being approvable
  at once rather than at the end of its day. `approve`/`deny` are the
  `pub(crate)` functions the website drives.
  Four rules carry the security of the flow: **the bearer is minted on claim,
  never stored on the row** (an approval nobody collects leaves no live
  session, and this table holds no second credential); **`claim` is one atomic
  store call** (`DELETE … RETURNING`), since `get` + check + `delete` would let
  two polls mint two sessions; the poll **re-checks the ban**, because
  `issue_session` does not and a ban can land between approving and claiming —
  without it this would be the one path a banned account still gets a token;
  and unknown, expired and already-claimed links all answer the *same*
  `expired`, so a poll token is never confirmed to have existed. Expiry is
  swept lazily from the create path (`delete_expired`) — this server has no GC
  task and should not grow one. The `user_code` is a **comparison aid only**:
  `start` needs no authentication, so anyone can open a link and try to talk a
  signed-in user into approving it, and the code is what defeats that. Never
  add a form that accepts one — that would turn it into a second short
  credential.
- **`server/src/admin.rs`** — Phase 8 administrative rules, the same
  handlers-are-wrappers split as `profile.rs`: `list_users` (a fixed number of
  store calls — one `accounts_with` per role, folded into a lookup, never one
  per row), `set_banned` (which also drops the target's
  sessions), `set_role`, `delete_user` (reusing `profile::delete_account_data`
  rather than a second cascade) and `bootstrap_first_admin`. The three guards
  live here, so the htmx and no-JS paths cannot drift: `cannot_target_self`,
  `last_admin`, `confirmation_mismatch` — and `set_role` applies the first two
  **only to `ADMIN`**, since losing `PAYMENT_USER` locks nobody out, which is
  why the paid-tier button appears on the administrator's own row and the
  destructive ones do not. `has_role` is the single read-side role check
  (`is_admin` and `vaults::quota_for` are both wrappers over it).
  **There is no JSON admin API** —
  administration is a website capability, and no desktop or mobile client
  needs it.
- **`server/src/settings.rs`** — Phase 12 server settings: runtime state an
  administrator edits, as opposed to the `ASKRYPT_*` environment `config.rs`
  reads once at startup. Same split as `admin.rs` — `pub(crate)` free
  functions (`registration_enabled`, `set_registration_enabled`) over
  `AppState`, no HTML, and no JSON surface. `store::SettingsStore` moves plain
  strings; the *typed* reading of each key lives here, so a second setting is
  a `pub const` in `store/mod.rs` plus an accessor rather than a schema
  change. **An unwritten key means the default** — nothing seeds the table, so
  an upgraded database reads exactly as it behaved before the key existed —
  and three cases all read as "registration open": absent, a value this build
  does not understand (a hand-edited row must not quietly close a server), and
  a store failure. That last is a deliberate fail-*open*: the same database
  that could not answer could not have created the account either.
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
  it fits in what the live files leave of the account's quota, so history
  shares the existing quota instead of multiplying disk use; re-uploading
  identical bytes makes no generation; a restore is an ordinary `overwrite`
  with old bytes, so it archives what it displaces and is itself undoable.
  Bytes stay opaque apart from the ZIP-magic check and the write stamp
  `vaultfile::read_stamp` lifts off them in `create`/`overwrite` (see
  `server/src/vaultfile.rs`); `archive` copies the live row's stamp onto the
  generation it files away. ETags are the SHA-256 of
  the stored bytes: downloads honor `If-None-Match` (304), overwrites
  require `If-Match` (428 without it, 412 when stale) so multi-device sync
  detects conflicts. Enforces `MAX_VAULT_BYTES` (10 MiB) and
  `MAX_VAULTS_PER_ACCOUNT` (100) globally, plus a **per-account** byte quota:
  `quota_for` returns `PAID_ACCOUNT_QUOTA_BYTES` (100 MiB) for an account
  holding `PAYMENT_USER`, otherwise `ACCOUNT_QUOTA_BYTES` (1 MiB). It is the
  one role lookup on the write path, so `overwrite` fetches it once and hands
  it to both `check_quota` and the trim; `restore_version` inherits it by
  delegating to `overwrite`. Only *writes* are checked — an account that drops
  off the paid tier keeps full read, download and delete access to what it
  already stored, it simply cannot save more until it is back under the line.
  Downloads set `Cache-Control: private, no-cache` so they opt out of the
  blanket `no-store` without losing ETag revalidation.
  **Every operation logs**, on the module's own `askrypt_server::vaults`
  target, through the `log_op`/`log_version_op`/`log_list` funnel: create,
  overwrite, download, rename, delete, archive, trim, version download and
  restore, each as `op="vault.<verb>"` plus `account_id`, `vault_id`
  (`version_id` where there is one) and a byte count. **Ids and sizes only**
  — never the name (user text that says what the vault is for), the bytes,
  the ETag (a content hash: it would tell a log reader when two files match
  or when a save rolled one back) or the write stamp. Mutations and byte
  transfers log at `info`, the listing at `debug` since the file manager
  re-renders it after every change. A read is logged where the bytes are
  actually fetched (`blob_of`, so a 304 logs nothing, and `version_bytes` is
  the unlogged twin `restore_version` uses — those bytes never leave the
  server).
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
  `is_vault` is the module's other export and its only opinion: does the
  archive hold an `askrypt.json` member at all. Presence only — the entry's
  contents stay none of the server's business — and it is used **by the
  website's upload form alone** (`web::vaults::check_upload`), never on the
  JSON API, whose callers are the apps that wrote the bytes and whose contract
  stays the ZIP magic and nothing further.
- **`server/src/ratelimit.rs`** — In-memory fixed-window `RateLimiter` +
  axum middleware, keyed via `clientip::client_ip` (`client_key` is
  `pub(crate)` so `web` can bucket identically); 429s carry `Retry-After`.
- **`server/src/web/`** — The website (Phase 7): server-rendered HTML with
  askama templates from `server/templates/`, htmx as a progressive
  enhancement. `types.rs` declares every page and fragment template (so all
  the `#[derive(Template)]`s expand there), every form input, the three
  cookie-session extractors, the CSRF wrappers and the `Flash` vocabulary;
  each module below re-exports its own. `mod.rs` builds the HTML router and holds `rate_limit`, an
  HTML-rendering twin of `ratelimit::middleware` sharing the *same*
  `RateLimiter` instances as `/api/v1/auth` and the `/api/v1/me` mutations,
  `relax_csp` (attaches `hardening::RelaxedCsp`, once per response — it lives
  here rather than in `captcha` because two features now widen the policy),
  plus `htmx_error_fragment`, the outermost layer: htmx refuses to swap a
  4xx/5xx, so an error page answering an `hx-post` is received and thrown
  away and the visitor watches the form do nothing. The layer re-renders any
  `WebError` (which labels its response with an `ErrorInfo` extension, the
  only channel — `IntoResponse` cannot see the request) as
  `fragments/error_notice.html` at **200**, with `HX-Retarget: main` +
  `HX-Reswap: innerHTML`; the "reload" link comes from htmx's
  `HX-Current-URL`, reduced to a path since it is client-supplied and lands
  in an `href`. Requests without `HX-Request` — the no-JS path, the JSON API
  — pass through with their real status untouched;
  `render.rs` has `Page<T>` (askama 0.16 has no axum integration), `is_htmx`,
  `redirect_either_way` (303, or `HX-Redirect` for htmx), `timestamp`, and
  `Chrome`/`Shell` (the layout's data plus the cookies a response owes);
  `error.rs` `WebError` with `From<ApiError>` — 5xx messages are replaced,
  never forwarded — gated on `is_backend_failure`, **not**
  `StatusCode::is_server_error`: 507 is in the 5xx range but says the account
  is out of room, which is the visitor's to act on, and reading it as a
  backend failure is what turned an over-quota upload into a 500 page. The
  same predicate guards `vaults::refused`; `session.rs` the `WebSession`/`MaybeWebSession` cookie
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
  *codes*, never text; `auth.rs` the login/register/logout forms — which also
  carry an optional **`?link=<uuid>`** through sign-in and registration
  (hidden field + `AuthForm.link`, and the already-signed-in bounce honours it),
  so a visitor who arrives from a desktop sign-in lands back on it instead of
  on `/account`; a *uuid* rather than a general `next=` precisely so there is
  no open redirect to get wrong; `captcha.rs` the reCAPTCHA v3 gate on those
  two forms — `LOGIN_ACTION`/`REGISTER_ACTION` (fixed per form, which is what
  stops one form's token being spent on the other), `check` (called **before**
  `authenticate`/`register_account`, since keeping a flood of guesses from
  buying an argon2 hash each is the whole point; one generic sentence to the
  visitor whatever went wrong, the real reason to the log and to
  `audit::CAPTCHA_FAILED`; a `CaptchaError::Backend` fails **closed**).
  `relax_csp` used to live here and is now `web::relax_csp`, since two
  features need it. The exceptions to the website's own rules live on these
  two pages and nowhere else: with a site key configured these forms **need
  JavaScript** (a v3 token can only be minted in the page) and send
  `CSP_CAPTCHA`. `AuthForm` carries `captcha_action` +
  `captcha_key`, the key filled by the chained `with_captcha(&state)` so the
  action and the key cannot be set out of step; a refused submit re-renders
  the field **empty**, because a v3 token is single-use and the spent one
  would only fail again. **`/api/v1/auth/*` is deliberately not captcha'd** —
  native clients cannot mint a token, and the desktop's browser sign-in
  already lands on `/login`; the JSON endpoints keep the rate limiter alone.
  That used to be a standing bypass for anything willing to post JSON, and it
  is closed the only way it can be: the password half of that tree is off
  unless `ASKRYPT_PASSWORD_API` says otherwise (see `routes.rs`), leaving
  `/google` (which needs a Google-signed credential) and `/logout`. **Turning
  that flag on in production re-opens the bypass** — it is for tests;
  `google.rs` the website's "Sign in with Google" (Phase 13):
  `POST /auth/google` on the *same* limiter as the two forms, taking an ID
  token Google Identity Services minted in the page and handing it to
  `IdTokenVerifier` then `auth::upsert_google_account` — see "Google sign-in
  has two surfaces" above for why the credential is posted same-origin, and
  `hardening` for the two headers that widen. It re-renders the *sign-in*
  form on every refusal whichever page the button was on (Google already knows
  the address, so a register form has nothing left to collect), splitting a
  refusal-with-a-sentence from a backend failure on the same
  `is_backend_failure` predicate `web::vaults::refused` uses. There is
  deliberately **no `GET`**: a sign-in a link can trigger is one a prefetcher
  can trigger. `AuthForm` carries `google_client_id` (chained on by
  `with_google(&state)`, from the verifier, so a page cannot offer a button
  the server would refuse) + the cosmetic `google_text`;
  `devicelink.rs` the `/link/{id}` page, where
  **visiting while signed in approves** (no confirm button — the flow is "open
  the page, come back signed in") next to the device label, the code and a
  `POST /link/{id}/deny`. Approving on a GET is safe against link checkers and
  prefetchers because it needs the session cookie, which they do not carry;
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
  plain name order. `check_upload` is the one rule this module owns rather
  than borrows, run by **both** upload and replace before anything is stored:
  the *uploaded file's* name must end in `.askrypt` (case-insensitively, and
  it is the picked file's name, not the name the vault is stored under — the
  desktop stores server vaults under a bare name) and the bytes must pass
  `vaultfile::is_vault`. It lives here because the difference is the browser:
  an API upload was written by the app sending it, a page upload was picked
  out of a folder by hand. The two refusals are told apart on purpose —
  `invalid_vault_extension` (the wrong file entirely) and `invalid_vault_file`
  (an archive with no `askrypt.json`, which the ZIP magic happily admits).
  `download_filename` is the mirror of that rule on the way out: a stored name
  is not required to carry `.askrypt` (the desktop's are bare), and a browser
  saves exactly what `Content-Disposition` says, so the extension is appended
  when absent — case-insensitively, via the shared `vault_extension_stem`, so
  nothing ever lands as `.askrypt.askrypt` — and `version_filename` normalizes
  through it before slotting the archival stamp in ahead of the extension.
  The JSON API sends no `Content-Disposition` at all and is unaffected: its
  callers name the file themselves. Each row also links to
  `/open?vault={id}`, the Phase 14 viewer, and `saved_stamp` is
  `pub(crate)` so the viewer's own picker formats the pair identically.
  Plus `explain`, which turns the handful of reachable `ApiError`
  codes into sentences; `pages.rs` landing and the HTML 404; and `admin.rs`
  the Phase 8 Users page (`/admin/users` behind `AdminSession`, with per-row
  suspend/lift, promote/demote, paid-tier grant/revoke and typed-confirmation
  delete, paged 50 at a
  time). Both role toggles POST to the **same** `/{id}/role` route, differing
  only in a hidden `role` field (absent means `ADMIN`, so the older
  promote/demote form still works) — one CSRF-checked door per row action
  rather than a route per role. Every admin action re-renders the **whole**
  `#user-list` fragment,
  not the row: each one moves the account total and the administrator count
  the guards depend on. `settings.rs` is the Phase 12 twin — `/admin/settings`
  behind the same `AdminSession`, one `#server-settings` card that renders and
  swaps itself, and a `finish` shaped exactly like `admin.rs`'s minus the
  paging (plain POST redirects with a flash; htmx cannot, since the flash
  cookie is only read by the *next* page render, so the confirmation rides in
  the fragment). Its switch is a hidden `enabled=true|false` field rather than
  a checkbox: an unchecked checkbox submits nothing, so "off" and "the field
  never arrived" would be the same request, and the CSP forbids the script
  that would paper over it. `Chrome` carries `is_admin` (set by `Shell::as_admin`,
  defaulting to *off*) so the nav can offer the Users and Settings links on
  every page — hiding them is decoration, `AdminSession` is the gate. The
  register form carries `AuthForm.registration_closed` (chained on like
  `with_captcha`, and only ever by the two register handlers), which draws a
  warning **above a form that still renders**: the refusal itself is
  `auth::register_account`'s, so the two cannot disagree if the switch is
  flipped between the GET and the POST. `open.rs` is the Phase 14 viewer's
  **server half, and it is deliberately tiny**: `GET /open` renders the page
  (offered to a signed-*out* visitor too — opening a `.askrypt` file off the
  device needs no account, and that is the case the page is most useful in,
  so `OpenPage.vaults` is an `Option`, where `None` means "nobody is signed
  in" and `Some(empty)` means "an account with nothing stored") and
  `GET /open/vaults` re-serves the picker fragment on its own. **There is no
  POST in this module at all.** Reading a stored vault is `vaults::download`,
  the cookie-authed route that already exists because a browser cannot set an
  `Authorization` header; saving one is `POST /vaults/{id}/replace`, which
  runs the same `If-Match`, quota, versioning and `check_upload` gates as the
  file manager's own replace, and storing a vault the page *created* is `POST
  /vaults`, that same manager's upload, which is where the name rules and the
  per-account count live. A second write door would be a second place for
  those rules to drift. Neither route carries a rate limiter — both are reads,
  and neither is worth guessing at. The picker's rows are **buttons** carrying
  `data-vault-id`/`-name`/`-etag`, since picking one starts an in-page flow
  that never navigates; the ETag on the row is load-bearing, not decoration —
  it is what the save sends as `If-Match`, which is why the fragment is
  re-readable at all (a save moves the ETag, so the value the page was
  rendered with would be refused for a conflict the visitor did not cause).
  Rows are sorted newest change first, like the file manager's. Templates must
  not contain inline `<script>`/`<style>`, `hx-on:` or `js:` htmx
  expressions — the CSP forbids them and `tests/web.rs` guards it (`/open`
  included, signed in and out).
- **`server/src/state.rs`** — `AppState`: one `Arc<dyn Trait>` per backend
  seam; handlers can only reach the traits. Two of them are the same trait:
  `vault_blobs` (live files) and `vault_version_blobs` (archived generations,
  keyed by version id, under each account's `versions/` subdirectory).
  `settings` is the runtime-switch seam every account-creation path reads
  through `crate::settings`.
  `captcha` is also the single source of truth for *whether* there is a
  captcha — its `site_key()` is what the templates and the CSP decision both
  read. `in_memory()` wires `DisabledCaptchaVerifier`, not the fake: a
  captcha nothing asked for would make every existing sign-in test carry a
  token, so suites that want one override the seam.
- **`server/src/store/`** — The backend traits (`mod.rs`): `AccountStore`,
  `RoleStore`,
  `SessionStore`, `SettingsStore` (a string key/value seam — `get`/`set`, no
  `delete`, since a key is either unwritten or explicitly set and a third
  state would only drift; the typed reading of each key lives in
  `crate::settings`), `DeviceLinkStore` (the short-lived browser sign-ins, with
  the atomic `claim` and the `delete_expired` sweep),
  `VaultMetaStore`, `VaultVersionStore`, `VaultBlobStore`,
  `Mailer`,
  `IdTokenVerifier` (`verify`, plus the defaulted `web_client_id` the website
  reads to decide whether to render a Google button — `None` never disables
  the JSON API, which only needs an audience), `CaptchaVerifier` (+
  `StoreError`/`MailerError`/
  `IdTokenError`/`CaptchaError`, all
  `#[non_exhaustive]`, and the `ADMIN_ROLE`/`PAYMENT_USER_ROLE` name
  constants — the stores themselves are name-generic, so a new role needs no
  code in either backend — plus the `REGISTRATION_ENABLED` setting key, named
  for the same reason). `mod.rs` keeps the traits, the constants and the
  inherent impls; every *type* — `Account`, `Session`, `VaultMeta`, the id
  aliases, the error enums, and each backend's own handle and `sqlx` row
  struct — is declared in `types.rs` and re-exported by the module that
  implements over it. `memory.rs`
  in-memory fakes for all of them (used by tests
  and the `memory` backend — `MemoryRoleStore::default` seeds both roles with
  the *same fixed uuids* the migration writes, so the two backends agree, while
  `MemorySettingsStore::default` starts **empty**, because the migration seeds
  no settings either and absence is what a default means there;
  `FakeCaptchaVerifier` is the exception nothing defaults to, see below);
  `sqlite.rs` SQLite pool + embedded migration
  runner over `server/migrations/` plus `SqliteAccountStore`/`SqliteRoleStore`/
  `SqliteSessionStore`/`SqliteSettingsStore`/`SqliteDeviceLinkStore`/
  `SqliteVaultMetaStore`/`SqliteVaultVersionStore`
  (uuids as TEXT, timestamps via sqlx-chrono, sessions, vault, `device_links`
  and
  `account_roles` rows cascade
  on account delete, version rows cascade on *both* vault and account delete,
  vault names unique per account, the nullable `host`/`saved_at` stamp
  columns on `vaults` + `vault_versions`, and the nullable `banned_at` on
  `accounts`. `AccountStore::list` is bounded (`limit`/`offset`, ordered
  `created_at, id` — the id tiebreak is what keeps paging stable) because the
  admin page must never load every account at once. Adding an `accounts`
  column means touching six places in `sqlite.rs`; `ACCOUNT_COLUMNS` covers
  the three SELECTs, the INSERT and UPDATE lists are separate). **A schema
  change to a table an applied migration created is a new numbered script,
  not an edit** — `sqlx::migrate!` validates the checksum of every migration
  already applied, so editing one a deployed server has run aborts its
  startup. Phase 8 could still fold `roles` into `0002_auth.sql` because
  nothing was deployed yet; Phase 12's `settings` table is
  `0005_settings.sql`. A `sqlite.rs` unit test asserts the migration count,
  so adding a script means bumping it; `disk.rs` `DiskVaultBlobStore` storing
  bytes at `<root>/<account-id>/<blob-id>.askrypt` with atomic temp-file +
  rename writes (path components are uuids, so no user string reaches the
  filesystem) — instantiated **twice** over `<data>/vaults`: `new` keyed by
  vault id, and `versions` keyed by version id, which nests them at
  `<account-id>/versions/`. History therefore shares no namespace with the
  live files while everything one account stores stays under one directory,
  so deleting that directory takes the history with it; `google.rs` `GoogleIdTokenVerifier` (RS256 against Google's
  JWKS, cached with a 60 s refetch floor, issuer/audience/expiry checks) and
  `NotConfiguredIdTokenVerifier`; `recaptcha.rs` `RecaptchaVerifier` (Google
  reCAPTCHA **v3** over `siteverify`, plus `RecaptchaConfig`, defined here and
  merely *parsed* by `config.rs` — its `Debug` is hand-written to redact the
  secret, since `Config` derives `Debug`) and `DisabledCaptchaVerifier`. Three
  things are checked and all three matter: `success`, that the **action
  matches** (a v3 token names the form it was minted for, without which a
  token from any other page would open `/login`), and that the score clears
  the floor. `assess` is split out of the request so the rules are unit-tested
  without a network; it tells `Rejected` (a visitor failed) from `Backend` (a
  bad secret or an unreachable Google, which refuses *everyone* and should
  read as an outage). `smtp.rs` `SmtpMailer` — `lettre` over
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
- **`server/tests/`** — HTTP-level tests (tower `oneshot`, no socket).
  `common/mod.rs` is the one thing every suite shares (each integration test
  is its own crate, so it is compiled once per suite — hence its blanket
  `dead_code` allowance): `common::config()` is the defaults pointed at the
  real `server/static/`, and `common::password_api_config()` adds
  `password_api: true`. Everything else — `send`, the request builders, the
  sign-in helpers — is deliberately still per-suite. The suites:
  `http.rs` (routing/static), `auth.rs` (the Phase 2 gate: register →
  login → `/me` → logout, Google new-account + link-to-existing against the
  fake verifier, validation, rate limiting, plus the one test that runs with
  `password_api` at its default and asserts the two routes are **absent**
  rather than refused, while `/google` and `/logout` stay routed —
  every other suite here builds its router from
  `common::password_api_config()`, because that is where their bearer tokens
  come from),
  `profile.rs` (the Phase 3
  gate: providers, email update, change/set password, session list/revoke,
  account-delete cascade incl. the vault stores), `vaults.rs` (the Phase 4
  gate: upload → list → download → rename → delete, ETag conflict behavior,
  per-account isolation, size/quota/count limits, and the write stamp a
  real stamped archive puts in the listing) and `hardening.rs` (the
  Phase 5 gate: security headers on every response shape, HSTS per config,
  cache directives, the 64 KiB/10 MiB body-limit split — the regression test
  for the layer ordering — `Retry-After`, and forged-vs-trusted
  `X-Forwarded-For` bucketing) and `web.rs` (the Phase 7 gate plus Phase 14's server half, 51 tests:
  template rendering, `/assets`, the HTML-404-vs-JSON-404 split, cookie
  attributes, the CSRF rejections for both form and multipart, fragment vs.
  full page, register-in-browser → find the session in
  `GET /api/v1/me/sessions` → revoke → signed out, the 7.3 profile round trip
  incl. self-revocation and the typed-confirmation delete, and the 7.4
  upload → list → byte-identical download → rename → delete with the
  stale-ETag conflict, the oversize 413 page, and the `Saved` column —
  including that a host name out of a file cannot inject markup. The two
  refusals a "big file" actually hits get both paths each: over quota (the
  1–10 MiB band, which the API suite never exercises through `refused`) as
  the listing plus its notice, and over the body limit as the retargeted
  error fragment, in each case next to the plain no-JS request that still
  carries the real status. The upload gate gets all three of its cases: the
  wrong extension, a ZIP with no `askrypt.json` (which the API's magic check
  admits), and a refused *replace* leaving the stored bytes untouched — each
  asserting the file was not stored, since a readable message over a stored
  file would be the worse bug; and the nine `/open` tests, which assert what
  the *server* owes the viewer and nothing about the decrypting: the page
  serves a signed-out visitor with a file input and no listing, the create
  form is offered signed in and out alike (creating one needs no account; with
  one, the CSRF token the upload posts with is on the page), an empty
  account renders the list saying it is empty rather than omitting it, rows
  carry the id/name/ETag the controller reads plus the CSRF token the save
  posts with, the picker is re-readable as a bare fragment but not by a
  signed-out visitor, the file manager deep-links each row to it, the Smart
  Lock card and its controls ship on every visitor's page and start hidden
  (the server has no route for the feature and never sees a bundle, so the
  markup is all it owes), the password generator's panel does the same and
  every button in it carries `type="button"` (it lives inside the entry form,
  and a defaulted one would apply the entry instead), and a
  hostile vault name cannot inject markup into the `data-` attribute it lands
  in) and
  `admin.rs` (the Phase 8 gate, 11 tests: first-account-is-admin and the nav
  link that follows, 403-vs-redirect for non-admin and signed-out visitors,
  suspend → old session dies *and* a fresh JSON login is refused → lift
  restores both, the self-guard, grant/revoke of ADMIN, grant/revoke of the
  paid tier and its badge, an unknown role name refused rather than granted,
  the typed-confirmation
  delete taking the target's vaults with it, CSRF rejection, and the htmx
  fragment swap) and
  `device_link.rs` (the Phase 10 gate, 15 tests, both halves at once because the
  point of the feature is where they meet: start → pending → register carrying
  `?link=` → the page approves → the app's poll returns a token that
  authenticates `GET /api/v1/me` and shows up in the device list under the
  `os@host` label the app sent; then the properties that make it safe — a link
  collected only once, a reload minting no second session, the link id useless
  as a poll token, an unknown poll token indistinguishable from an expired one,
  deny (and its CSRF rejection), cancel removing the link at once, the 24-hour
  sweep taking pending *and* uncollected-approved links, and a banned account
  unable to claim an approval it made before the ban) and
  `captcha.rs` (the reCAPTCHA gate, 12 tests, over `FakeCaptchaVerifier`
  since the real one is a network call whose rules are unit-tested in
  `store/recaptcha.rs`: the site key and both scripts on the two pages, the
  CSP widened on exactly those two and only with a captcha configured, a
  missing token answered with advice about JavaScript rather than a 4xx, a
  token minted for the other form refused, a low score refused, the spent
  token *not* echoed back into the re-rendered field, the JSON auth API still
  working untouched, and — the ordering guarantee — a wrong password *and* a
  bad token yielding the captcha message, which is how you can tell argon2
  was never reached) and
  `settings.rs` (the Phase 12 gate, 9 tests, both halves at once for the same
  reason `device_link.rs` is: a server nobody configured is open, the page is
  advertised and reachable only to administrators, the switch survives and
  flips back, the htmx swap, its CSRF rejection, and then what "closed"
  actually refuses — the browser form still rendering but answering 200 with
  the refusal, the JSON API answering 403 `registration_disabled`, Google
  refused for a *new* address but still linking to an existing one, and
  password sign-in untouched on both surfaces) and
  `google_signin.rs` (the Phase 13 gate, 15 tests, both halves at once because
  the page has to offer a button the handler will accept a credential from:
  the client id, both scripts and the credential form on the two pages, the
  two forms as *siblings* inside one card, the widened CSP and opener policy
  on exactly those pages and only with a button configured, then create →
  sign in again reusing the account → link to an existing password account
  with the password still working → a device link surviving the round trip,
  and the refusals — no credential (advice about JavaScript), an unverifiable
  one, an unverified Google address, a banned account, a closed server for
  *new* addresses only, a missing and a forged CSRF token, and `GET` answered
  405). Middleware needing a slow
  or parked handler (timeout, shedding) is unit-tested inside
  `src/hardening.rs` instead. The `last_admin` guard is unreachable through
  the website — only the sole administrator can act on themselves, and the
  self-guard fires first — so it is covered by `src/admin.rs`'s unit tests.
- **`server/templates/` + `server/static/`** — The website's markup and its
  only loose files. Templates (`layout.html`, `landing.html`,
  `auth_page.html`, `account.html`, `vaults.html`, `admin_users.html`,
  `admin_settings.html`,
  `link.html` (the device-link page, in its four states), `open.html` (the
  Phase 14 viewer — eight `hidden` `<section class="card">`s that
  `vault-open.js` reveals a step at a time, the armed Smart Lock among them, plus a closing card stating what
  the page can and cannot promise and linking its two scripts to be read),
  `error.html`, and
  `fragments/` — `auth_form`, `email_form`, `password_form`, `devices`,
  `delete_account`, `vault_upload`, `vault_list`, `open_vault_list`,
  `user_list`,
  `settings_form`,
  `error_notice` — the htmx twin of `error.html`, one element rather than a
  document, because it is swapped into `<main>`) compile into
  the binary;
  every page template carries a `chrome: Chrome` field because `layout.html`
  reads it, and each fragment is a self-contained element with an id its
  forms name as `hx-target`. `auth_form` is the exception that proves the
  rule: its root is a `<div id="auth-form">` rather than the form, because
  the card holds *two* forms — the password one and the hidden one the Google
  button submits — and HTML forbids nesting them; `hx-target` names the id.
  `layout.html`'s `{% block head %}` has two callers now:
  `auth_page.html` loading Google's `api.js` plus
  `/assets/captcha.js` when a site key is configured, and `/assets/google.js`
  plus `accounts.google.com/gsi/client` when a web client id is; and
  `open.html` loading `/assets/vault-open.js` as `type="module"` (which defers
  by itself and is what makes its static `import`s of `vault-format.js`,
  `vault-smartlock.js` and `vault-passgen.js` resolve). All **external**, since
  even the widened CSP forbids inline script, which is why the site key, the
  client id and every value the viewer reads off a row reach the scripts as
  `data-` attributes. Confirmation steps are `<details>` disclosures,
  not scripted dialogs — the CSP forbids the inline handler. `static/` holds
  `style.css`, the vendored `htmx.min.js` (2.0.10), `captcha.js`,
  `google.js` and the four viewer modules, served at
  `/assets` — there is no `index.html` any more. No Node, no bundler, no CDN,
  and the viewer keeps it that way: it is four hand-written ES modules with no
  dependencies and no build step.

  **`vault-format.js`** is the browser port of the vault format — a port of
  `core/src/lib.rs` + `core/src/types.rs`, following `app/lib/crypto/`
  function for function, with `SPEC.md` normative. Every primitive the format
  needs is native (PBKDF2-HMAC-SHA256, AES-256-CBC with PKCS#7, SHA-256 over
  `crypto.subtle`; `DecompressionStream("deflate-raw")` for the ZIP), which is
  why it is a few hundred lines rather than a wasm build of `core/`. It is
  **pure by contract** — no DOM, no `fetch`, no globals, nothing persisted —
  because `scripts/vault-js-parity.mjs` imports the shipped file *unchanged*
  under Node, so a reach for `window` or `document` would break the gate.
  `createVault` **refuses to write without a master key**, unlike the Rust and
  Dart cores, whose `create` mints one when handed none: the mint is
  `generateMasterKey`, called from `vault-open.js` at the one moment a vault
  comes into existence, so no save can mint a key by accident (`SPEC.md`,
  "Master key lifetime"). `DEFAULT_ITERATIONS` is what a vault born here
  declares; one that already exists keeps its own.
  It hardens two things the format leaves unauthenticated: `MAX_JSON_BYTES`
  (1 MiB, matching `vaultfile`) caps what a crafted archive can inflate, and
  `MAX_ITERATIONS` (5,000,000) caps the PBKDF2 work a crafted `params` can
  demand — production is 600,000, and without the cap a hostile file could
  park a phone in a derivation for the afternoon.

  **File attachments made the ZIP layer multi-member, and that is the riskiest
  code in the file.** The reader split into `readZipIndex` (walk the central
  directory once) + `readZipMember(bytes, index, name, limit)`, the limit being
  the caller's because the vault JSON and an attachment differ by three orders
  of magnitude; `readZipEntry` is the one-member wrapper. The writer became
  `writeZip(members)` — **async**, and taking `[name, contents, deflate]` — and
  two of its fields are silent when wrong: each member's **relative local-header
  offset** (central-directory offset 42), which the old single-member writer got
  right only by leaving it zero, and the EOCD's counts and sizes, which are now
  sums. A vault carrying an attachment is the only thing that exercises either,
  which is why the parity gate grew a save-and-reopen check over one.
  Attachments are written **deflated**, matching the Rust and Dart cores, via
  `CompressionStream("deflate-raw")` — the exact mirror of the
  `DecompressionStream` the reader already needs, so it costs **no library, no
  CDN and no CSP change**; `deflateRaw` answers `null` on a platform without it
  and the member is stored instead, since the method is per member and refusing
  to save would be far worse than saving 0.03% larger.
  `sealAttachment`/`openAttachment` mirror core's pair, and `createVault` takes
  the blob `Map` and applies the same prune.

  **`vault-smartlock.js`** is the browser port of `src/smartlock.rs`, and like
  that module it is **not part of the format**: nothing it produces is ever
  written to a file and no other implementation reads it, which is why it sits
  beside `vault-format.js` rather than inside it and why there are no golden
  vectors for it. The bundle is every answer encrypted under one of them,
  chosen at random and never the first, at **2,000,000** PBKDF2 iterations
  (`SMART_LOCK_ITERATIONS`, far above the vault's own work factor because a
  single answer has less entropy behind it than the layered unlock does), with
  an IV per ciphertext and an eight-hour ceiling. It holds the same
  no-DOM/no-`fetch`/nothing-persisted contract as `vault-format.js`, so
  `scripts/vault-js-parity.mjs` runs the shipped file unchanged; what that
  gate checks is the *shape* — the key answer is never the first, the two
  ciphertexts do not share an IV, no answer appears in the clear, and no
  master key is in the bundle at all — since the derivation under it is the
  format's own answer key at a different work factor and every primitive in it
  is already pinned by the vectors.

  **`vault-passgen.js`** is the browser port of `core/src/passgen.rs`, and it
  is **not part of the format** either — nothing it produces is written to a
  file and no other implementation reads it — so it sits beside
  `vault-format.js` under the same no-DOM/no-`fetch`/nothing-persisted
  contract, which is what lets `scripts/vault-js-parity.mjs` run the shipped
  file unchanged. Its output is random, so there are no golden vectors: what
  the gate checks is the rules — the defaults (20 characters, all four sets),
  `clampLength`'s 8..=100, that each set draws only from its own characters,
  and that no set selected raises core's own sentence rather than returning an
  empty string. One thing the port has to do that the Rust gets for free:
  `rand`'s `random_range` is unbiased, so `randomIndex` draws 32 fresh bits
  from `crypto.getRandomValues` and **rejects** anything at or above the
  largest multiple of the set size that fits in them — `% n` would put a thumb
  on the scale of every password the page produces. The panel around it lives
  in `vault-open.js`, opened by a Generate button beside Show/Copy on the entry
  editor's Secret field; there is no counterpart to the desktop's rail button,
  since the field being edited is the only place a generated password is
  wanted here.

  **`vault-open.js`** is the DOM around them and holds no crypto: pick (a stored
  vault, or a local file that is never uploaded) → the first question → the
  rest → the entry list with search/tags/hidden → one entry → save. A second
  way in **creates** a vault instead — a name, two or more question/answer
  pairs and the transliteration switch, held to the same rules as
  `panes::questions::save` — and it derives *nothing* at that point: the entry
  list is empty and a save re-encrypts everything anyway, so the only thing
  settled there and never again is the master key. Such a vault carries
  `source.kind === "new"` until a save lands, which is what picks the upload
  route over the replace one and what makes the save card say the vault exists
  only in this page; once uploaded it adopts the new row's id and ETag, found
  by name, and carries on as an ordinary stored one. A save
  re-encrypts the whole vault in the page under the **same master key**
  (re-wrapped, never rotated — `SPEC.md`, "Master key lifetime"), the same
  answers, work factor and normalization setting, which is why the answers are
  held for the life of the unlock. It stamps `params.host` as `<os>@web` — a
  browser cannot know the machine's name — omitting the field entirely rather
  than writing a dangling `@web` when the platform admits to nothing. Two
  saves: to the account (multipart to `/vaults/{id}/replace`, CSRF part first
  because `CsrfMultipart` verifies before buffering the file, `redirect:
  "manual"` because on that route the *status* is the verdict — a 303 landed,
  a 200 is `web::vaults::refused` re-rendering, whose sentence is lifted out
  of the returned HTML rather than reinvented) and a downloaded copy (a
  browser cannot write back over the file you picked). All rendered text goes
  through `textContent`, never `innerHTML`: an entry name — or an attachment's
  file name — comes out of a file anybody could have written. **Attachments are
  read-only here**: the page lists them (name, size, when added), decrypts one
  on demand and hands it to the browser as a blob URL, and carries every blob
  across a save; adding and removing is the desktop's job. `state.attachments`
  holds the ciphertexts and is cleared by `lock` with everything else. **No field on the page is `type="password"`
  in a browser that can mask a text one**: masking is the `.masked` class
  (`-webkit-text-security`), applied through `maskable`/`setMasked` and
  feature-detected once in `CSS_MASKING`. A password field being submitted is
  what makes a browser offer to save what was typed into it, and a security
  answer sitting in the browser's own password store is precisely what this
  page promises to leave nowhere — `autocomplete="off"` is advice a password
  manager ignores, and `preventDefault` cancels the navigation, not the
  heuristic. Without the property the fields stay password fields, a secret
  rendered in the clear being the worse outcome, which is why the template
  declares them that way and startup converts them. It locks on an explicit
  Lock, on 3 minutes idle
  (matching the mobile app's `kInactivityTimeout`) and 60 s after the tab is
  hidden — not instantly like the mobile app, because a browser fires the same
  event when you merely switch tabs and locking there would make it impossible
  to paste a password anywhere. Copies clear the clipboard after 30 s, like
  `secure_clipboard.dart`. Locking drops every field of one state object;
  there is nowhere else for a secret to be.

  **Smart Lock** (`armSmartLock`/`smartUnlock`) is the desktop feature ported,
  with two deliberate differences, each of which follows from the page rather
  than from taste. The desktop re-opens the bundle against the file the vault
  was read from, which is why arming there loses unsaved edits and why
  `App::auto_smart_lock` saves first or refuses; a tab has no file to re-read
  (a local file cannot be written back to, and a created vault may never have
  been written at all), so arming **re-encrypts what is in the page** — one
  save's worth of derivation, after which arming loses nothing and refuses
  nothing but a one-question vault. The security property is unchanged: the
  bundle still carries answers and no master key, so on its own it opens
  nothing, and coming back in is the ordinary layered unlock run against those
  bytes. The second difference is *who* may arm it. Only the button does: the
  **automatic** locks keep nothing, because "nothing is kept after a lock" is
  the promise this page makes and the desktop does not have to. The one
  exception is a session that came out of a Smart Lock — `state.smartDeadline`
  is what marks it — where an automatic lock re-arms instead, since the user
  already asked for exactly that and the ceiling they started is still
  running. Arming is best effort in that path: a failure still locks fully,
  because a timeout that leaves a vault open is the one outcome that must not
  happen. The eight-hour ceiling is restarted at each transition, as
  `Vault::smart_unlock` restarts it, and it outlives the bundle — a vault
  re-opened from one carries the ceiling too, so being reachable from a single
  answer stays time-limited however often it is re-armed. `smart` lives
  *outside* the state object precisely because arming runs the whole of
  `lock()`, which replaces that object; a full lock clears it as well.
  `captcha.js` keeps the hidden field **freshly populated** rather than
  minting on submit: htmx serializes the form synchronously and
  `grecaptcha.execute` is a promise, so no hook can await one and still let
  the request go out. It re-mints on load, on a 90 s timer (tokens last two
  minutes) and on `htmx:afterSwap` (a refused submit spends its token *and*
  replaces the whole form) — the listener is on `document` precisely because
  the form it would otherwise bind to is the element htmx replaces.
  `google.js` is the same shape and there for the same reason: it initializes
  Google Identity Services from the container's `data-` attributes, draws the
  button, and on a credential fills the hidden field and submits the form
  beside it. It re-draws on `htmx:afterSwap` (a refused submit replaces the
  whole card) and polls briefly for the library, which is deferred like it is.
- **`server/Dockerfile` + `server/deploy/`** — Self-hosting artifacts.
  **Containers are the only supported deployment** — there is no systemd unit;
  `server/DEPLOY.md` drives everything through
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
  image as a `docker save | gzip` tarball, `docker load`, run `run.sh` in
  `/home/askrypt-server`, then wait on the container *and* on `/healthz`
  answering — probed with `docker exec askrypt-caddy wget`, since the runtime
  image has no HTTP client. The server needs only docker: no source checkout,
  no toolchain, no registry. `docker-compose.yml` (server + Caddy) therefore
  has **no `build:` section** and `pull_policy: never`; its project name is
  pinned (`name: askrypt`, so Caddy's three volumes keep their names wherever
  the file sits), and host-specific values come from
  `/home/askrypt-server/.env` on the server — required `ASKRYPT_DOMAIN` plus
  the SMTP secrets, templated by `env.example`, never uploaded, only checked
  for.
  **The whole deployment is one directory, `/home/askrypt-server`**, and the
  image's paths mirror it: the service user's home is `/home/askrypt-server`
  (`WORKDIR` too), with `ASKRYPT_DATA_DIR=/home/askrypt-server/data` and
  `ASKRYPT_LOG_DIR=/home/askrypt-server/logs` created by the Dockerfile's own
  `mkdir`/`chown` and bind-mounted from the **host** directories of the same
  name — so a path in a log line is also a path on the server. The compose
  file writes those two mounts *relatively* (`./data`, `./logs`), which
  resolve against the compose file's own directory and so keep a local run
  inside `server/deploy/` (both gitignored). Only Caddy still uses named
  volumes. **`run.sh` is the compose entry point**, shared by `spot.yml` and
  by hand: a bind mount keeps the host directory's ownership instead of
  inheriting the image's, so it creates `data/`/`logs/`, repairs them to uid
  `10001` mode `0700` when they are wrong (guarded by a `stat`, so the
  recursive walk skips the `vaults/` tree on an ordinary deploy), then
  `compose up -d --remove-orphans` and the label-filtered image prune.
  Checklist, backup, restore drill and the one-off migration off the old
  `askrypt_askrypt-data` volume are in `server/DEPLOY.md`; backups are
  `askrypt-server backup` (a `VACUUM INTO` snapshot) **before** tarring the
  blobs — uploads write bytes then metadata, so that order can only orphan a
  blob — with the server stopped when an exact snapshot matters. The snapshot
  does not archive the log files. `backup.sh` is the cron-side convenience the
  playbook uploads (and `chmod +x`es) next to `run.sh` but never runs: it takes
  that snapshot through `docker exec` into the running container, **into the
  data directory** so the bind mount hands it to the host at the same path,
  then `cp -a`s the whole `/home/askrypt-server` directory — logs, `.env`,
  compose file and all — tars it through `/tmp` and drops the archive in the
  off-host spool. The live `askrypt.db` and its `-wal`/`-shm` are deleted from
  the *copy*, so the archive carries exactly one database and it is the
  consistent one.

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
| `libc` | `statvfs` for the free-space figure in the server's startup notice (unix only) |

### Build & Test

```
# Desktop / core (Rust) — core is the spec source of truth
# (the desktop crate enables core's `server-storage` feature, so a workspace
#  build already covers it; `cargo build -p askrypt-core` alone must NOT pull
#  in ureq/rustls — that is the point of the feature gate)
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p askrypt                       # the desktop app (src/)
# Run it, optionally opening a vault straight away. CI's bare `cargo build`/
# `cargo test` select only the root package, i.e. exactly this crate.
cargo run -p askrypt -- ~/vaults/MyVault.askrypt
# Regenerate the golden parity vectors after any format/normalization change.
# BOTH ports read them — run `flutter test` and the JS gate below afterwards.
# Note the emitted `vault_b64` is NOT byte-stable across runs (`touch` stamps
# `updated_at`/`host` on every write), so diffing it proves nothing; the gates do:
cargo run -p askrypt-core --example gen_vectors
# Server (also covered by the --workspace commands above):
cargo run -p askrypt-server      # then curl /healthz
# Manual end-to-end conformance run against a *local* server. The script starts
# a throwaway one, seeds an admin and a plain account, and runs both roles:
scripts/server-roundtrip.sh                    # both roles, memory backend
scripts/server-roundtrip.sh --backend sqlite   # against the real stores
# Or by hand, against a server already running:
cargo run -p askrypt-core --features server-storage --example server_roundtrip \
  -- http://localhost:8080 me@example.com correct-horse
cargo run -p askrypt-server -- backup /path/snap.db   # VACUUM INTO snapshot
docker build -f server/Dockerfile -t askrypt-server . # from the repo root
# Byte-parity gate for the browser crypto the /open page runs, against the same
# golden vectors the Dart port uses. Zero npm deps — Node's built-in WebCrypto
# and DecompressionStream run the shipped file unchanged. Not in CI (there is no
# Node anywhere in the build), so run it by hand like `flutter test`:
node scripts/vault-js-parity.mjs

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
- `.github/workflows/release.yml` — Multi-platform release builds (Linux x86_64, macOS ARM64, Windows x86_64 MSVC + win-gnu zip, plus a Windows installer) and the `.deb` package.
- Windows builds use static C runtime linking (configured in `.cargo/config.toml`).
- `build.rs` embeds the Windows icon resource.
- `installer/windows/askrypt.iss` — Inno Setup script for a Windows installer (`askrypt-<version>-setup.exe`), built by the `build-release-installer` job against the win-msvc target and uploaded to the GitHub release alongside the zip archives. Build locally with `iscc /DMyAppVersion=0.7.0 installer\windows\askrypt.iss` (needs [Inno Setup](https://jrsoftware.org/isinfo.php) installed; defaults to packaging `target\x86_64-pc-windows-msvc\release\askrypt.exe`). Per-user install (no admin rights), fixed `AppId` so re-running the installer upgrades in place, and leaves `%APPDATA%\askrypt\` (settings, vaults) untouched on uninstall.
