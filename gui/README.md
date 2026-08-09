# `askrypt-gui` — the new desktop UI

The three-pane, Bitwarden-like layout (`uisample.jpg`) that will replace the
screen-per-step Iced app in `src/`. It is built here first, on **fake data**:

- no `askrypt-core` dependency, **no crypto, no vault I/O, nothing persisted**;
- `data.rs` holds a hard-coded `Entry` mirroring `SecretEntry`'s field names —
  a plain struct with no `zeroize` and no `serde`, because deriving
  `ZeroizeOnDrop` on fake data would falsely imply a security posture;
- the vault *lifecycle* is modelled (`vault.rs`) so the controls that depend on
  it can be laid out, but every transition is a field assignment;
- controls with no meaning here write one line into the status bar.

```
cargo run -p askrypt-gui
```

This file is the **port notes**: what the shipping app in `src/` actually does,
where, and which of its invariants a redesign can quietly break. Keep it current
as the prototype grows — it is what the port will be written from.

---

## 1. Layout

```
┌─────────────────────────────────────────────────────────┐
│ search strip                    (only when unlocked)    │
├────────────┬────────────────────────────────────────────┤
│            │                                            │
│  nav rail  │   working area                             │
│            │     Items  = list │ detail                 │
│  filters   │     Settings / Unlock / Wizard = one pane   │
│  ───────   │                                            │
│  vault     │                                            │
│  actions   │                                            │
│  ───────   │                                            │
│  Settings  │                                            │
├────────────┴────────────────────────────────────────────┤
│ status bar                              (always pinned) │
└─────────────────────────────────────────────────────────┘
```

The outer `column![search, row![panes].height(Fill), status_bar]` is what keeps
the status bar on the bottom edge. Unlike `src/app.rs::view`, the root is *not*
wrapped in a centering container — the panes are full-bleed.

### Module map

| File | Holds |
|---|---|
| `main.rs` | `App`, `Section`, `Pane`, `Message`/`VaultMsg`, the `visible()`/`reconcile_selection()` filter pair, `default_pane()`/`effective_pane()`, and the root layout |
| `vault.rs` | `Status`, `Source`, `Vault` — the state machine **and** the button-visibility rules |
| `theme.rs` | helpers copied from `src/ui.rs` plus pane styles and layout constants |
| `icon.rs` | glyph codepoints read out of `static/bootstrap-icons.ttf` |
| `data.rs` | the fake entries, questions, recent files and server vaults |
| `panes/sidebar.rs` | the nav rail: filters, Settings, the vault actions |
| `panes/list.rs`, `panes/detail.rs` | the item split |
| `panes/settings.rs` | the settings screen (its theme picker really does repaint the window) |
| `panes/unlock.rs` | the layered unlock screen |
| `panes/wizard.rs` | the Open / Save / Save As source picker |
| `panes/statusbar.rs` | the bottom bar |

Two rules that are easy to undo by accident:

- **Selection is an index into `entries`, never into the filtered view**, so
  filtering cannot invalidate it; `reconcile_selection` falls back to the first
  visible row when a filter hides the selection.
- **Every pane style is palette-derived**, which is why the Settings theme
  picker works. Hard-coding a color breaks the dark theme.
- **Anything drawn per item must be deterministic.** `view` runs every frame, so
  the list row's icon is *derived* from the entry name (`icon::placeholder`)
  rather than actually randomized — a real random pick would flicker.

---

## 2. The vault lifecycle

The shipping app has no `VaultState` enum — the state is *derived* from three
`Session` fields plus the active `Screen`. `vault.rs` names the five states that
combination can produce.

| State | Real app: `file` / `questions_data` / `unlocked` / `smart_lock_data` | Screen |
|---|---|---|
| `NoVault` | none / none / false / none | `Welcome` |
| `Locked` | **some** / none / false / none | `FirstQuestion` |
| `PartiallyUnlocked` | some / **some** / false / none | `OtherQuestions` |
| `Unlocked` | some / some / **true** / none | `Entries` |
| `SmartLocked` | some / none / false / **some** | `SmartLock` |

The real app has a sixth, transient shape the model folds away: *composing* a
new vault on the `Questions` screen, where `file` is still `None`. Here that
collapses into `Unlocked` with `source: None` — which is exactly what the user
sees once the questions are typed, and what makes the first Save a Save As.

`PartiallyUnlocked` is **not a UI step** — it is a property of the vault format.
The first answer decrypts only the *question list*
(`file.get_questions_data(answer0)`, `src/screens/unlock.rs:69`); all the answers
together decrypt the entries (`file.decrypt(&data, answers)`,
`src/screens/unlock.rs:186`). That is why the unlock pane shows one field, then
the rest.

### Transitions, and where they live in `src/`

| Transition | Real implementation |
|---|---|
| create a new vault → `Unlocked`, no location | `src/screens/welcome.rs:67` → `src/screens/questions.rs` (type the questions and answers) → Save |
| open a local file → `Locked` | `src/screens/welcome.rs:26-54` (synchronous `rfd::FileDialog::pick_file`, blocks the UI) |
| open from the server → `Locked` | `src/screens/server.rs`, `Mode::Open`: sign-in form → vault list → `Msg::OpenVault` → `Msg::VaultOpened` |
| auto-open at startup | `src/app.rs:30-68` (argv, else `settings.last_opened_file`; a server location is skipped when not signed in) |
| answer 0 → `PartiallyUnlocked` | `src/screens/unlock.rs:69` |
| all answers → `Unlocked` | `src/screens/unlock.rs:186` |
| `Unlocked` → `Locked` ("Lock Vault") | `src/screens/entries.rs:126-139` — prompts about unsaved changes first, **Cancel aborts the lock** |
| `Unlocked` → `SmartLocked` | `src/app.rs:339-354`, after a 2M-iteration encrypt on a background thread |
| `SmartLocked` → `Unlocked` | `src/screens/smart_lock.rs`, 2M-iteration recover + full decrypt |
| `SmartLocked` → `Locked` ("Full Lock") | `src/app.rs:211-221` (`GlobalMsg::CancelSmartLock`) — no prompt: Smart Lock had already zeroized |
| anything → `NoVault` ("Close") | `src/app.rs:183-196` (`GlobalMsg::BackToWelcome`) — also clears the location and `last_opened_file` |
| idle 10 min → `SmartLocked`; 8 h → `Locked` | `INACTIVITY_TIMEOUT` / `SMART_LOCK_TIMEOUT`, `src/session.rs:27-29`, driven from `src/app.rs:222-230` |
| save | `src/session.rs:294-333` — re-encrypts from scratch and writes through the **existing** storage; falls back to Save As when there is none |
| save as (file) | `src/session.rs:336-387` — `rfd::FileDialog::save_file`, adopts the new location, writes `last_opened_file` |
| save to server | `src/session.rs:394-456` — needs a signed-in client; builds `VaultLocation::Server { base_url, email, name }` |

There are three lock *depths*, and the prototype keeps all three:
**Smart Lock** (one answer to return), **Lock** (all answers), **Close** (must
re-open the file first).

`zeroize_secrets` (`src/session.rs:601-605`) wipes exactly `answer0`, `answers`
and `entries`. It deliberately **keeps** `file`, `location`, `storage` and
`question0` — which is why a locked vault can still show its path and its first
question without touching the disk.

---

## 3. The controls

Every vault action lives at the bottom of the nav rail, with **Settings pinned
below them on the very bottom edge** — the one row that is never about the vault
in front of you. Each action is **hidden** rather than disabled when the state
does not allow it. The predicates are on `vault::Vault`; `panes/sidebar.rs` only
asks.

| Button | Shown in | Predicate |
|---|---|---|
| New Vault | every state | `can_create()` |
| Open Vault… | every state | `can_open()` |
| Unlock | `Locked`, `PartiallyUnlocked`, `SmartLocked` | `can_unlock()` |
| Smart Lock | `Unlocked` | `can_smart_lock()` |
| Lock / **Full Lock** | `Unlocked` / `SmartLocked` | `can_lock()` + `lock_label()` |
| Save | `Unlocked` | `can_save()` |
| Save As… | `Unlocked` | `can_save_as()` |

The item filters (All Items, Hidden, TYPES, TAGS) and the search strip only
exist while the vault is unlocked. `effective_pane()` additionally refuses to
render the item list over a locked vault, so a stale rail selection cannot leak
rows.

**New Vault** is the one action that lands *unlocked*: the user has just typed
the questions and answers, so there is nothing to unlock — but there is also no
location yet, which is why `Vault::create()` sets `source: None` and
`modified: true`. That combination is the whole reason `Session::save_vault`
falls back to Save As when there is no storage (`src/session.rs:328-329`), and
it is the only way to reach the "Untitled vault\*" status line and the list
pane's empty state. Here it skips straight to an empty vault; the real flow
runs the questions editor first (`src/screens/welcome.rs:67` →
`src/screens/questions.rs` → Save), which is step 6 of the checklist below.
Opening a vault afterwards puts the sample entries back — they are what
unlocking reveals.

### What the wizard replaces

The shipping app splits this work by *screen*, not by intent: Open lives only on
Welcome (`src/screens/welcome.rs:67-69`), Save/Save As/Save to Server only on the
entries screen (`src/screens/entries.rs:165-176`), and "Save As" means two
different UIs depending on the destination — a native file dialog for a path, a
whole screen with a text field for a server name. You cannot Open while a vault
is already open without going back to Welcome, and you cannot pick a file path
from inside the server screen.

`panes/wizard.rs` collapses that into **pick a source, then fill it in**, driven
by a `Purpose` (`Open` / `Save` / `SaveAs`) rather than by which screen you came
from. Sources: **Local file**, **Askrypt Server**, and a disabled **Cloud
folder** card that reserves the slot.

---

## 4. Invariants a real port must not break

These are the ones a UI redesign is most likely to violate, all of them load-
bearing in the shipping app:

1. **`location` and `storage` are set together, and the storage instance lives
   as long as the open vault.** `src/session.rs:66-72`, `:207-210`. A
   `ServerStorage` records the ETag it saw when it *read*, and sends it as
   `If-Match` when it writes. Rebuilding the backend before each save re-resolves
   whatever ETag the server holds *now* and silently overwrites another device's
   edit. So the wizard must hand the session the **same instance that performed
   the download** — see `OpenedVault { name, file, storage }` in
   `src/screens/server.rs`, and note `Msg::VaultOpened` carries the
   `Arc<ServerStorage>`, not just the bytes.
2. **`VaultLocation::LocalFile` must stay the first variant** of the `untagged`
   enum (`src/settings.rs:8-25`) or existing `settings.json` files — which store
   a plain path string — stop parsing.
3. **A server vault is keyed by name**, not by the server-assigned id, and needs
   a signed-in client whose `base_url` matches; otherwise `VaultLocation::storage`
   fails with `StorageError::Auth` (`src/settings.rs:33-51`). That is also why
   saving to an existing name overwrites, and why the wizard warns about it.
4. **Sign-in and vault source are independent axes.** `sign_out`
   (`src/session.rs:240-244`) deliberately leaves an open server vault alone —
   the user keeps what they decrypted; only saving asks them to sign in again.
   The wizard therefore keeps its sign-in across runs rather than treating it as
   a step of one flow.
5. **Every PBKDF2 path runs off the main thread** — `Task::perform` +
   `tokio::task::spawn_blocking`, behind `ui::spinner_row`, with
   `session.decrypting` guarding re-entry. That covers the first-answer check,
   the full unlock, and both Smart Lock directions (2M iterations each). The two
   that still block the UI today are `save_vault_as` and `save_vault_to_server`
   (`src/session.rs:392-393`); making them async means moving the mutation into a
   completion message, since `Session::save_vault` is `&mut self` and is called
   straight from a screen `update`.
6. **Lock and Close must prompt about unsaved changes**
   (`Session::ask_user_about_changes`), and Cancel there aborts the transition.
7. **Screen states that hold secrets wipe on drop.** `questions::State`,
   `smart_lock::State` and `server::State` have `Drop` impls; the entry editor's
   secret is wiped by `SecretEntry`'s own `ZeroizeOnDrop`. Any new pane that
   holds a typed answer or password needs the same.
8. **`AppSettings.last_opened_file` is a single slot**, not a list
   (`src/settings.rs:158`). The wizard's recent-vaults list needs a real MRU
   before it can be backed by anything.

---

## 5. What is deliberately fake

| Here | Really |
|---|---|
| any non-empty answer unlocks; no delay, no spinner | 600k-iteration PBKDF2 per answer, off-thread, ~a second each |
| each item's icon is `icon::placeholder(name)` — one of 16 glyphs picked by hashing the name | a real per-item icon: a site favicon, a card issuer's logo. Nothing derives one yet; replace the whole function, not the pool |
| New Vault jumps straight to an empty unlocked vault | Welcome → the questions editor → Save, and only then an empty entries list |
| New Vault replaces the open one without asking | `ask_user_about_changes` prompts, and Cancel aborts |
| `data::sample_recent_files()` | a real MRU that does not exist yet (see invariant 8) |
| `data::sample_server_vaults()` | `ServerClient::list()` over HTTP |
| sign-in succeeds on any input and never expires | `ServerClient::login`, 30-day bearer sessions, 401 → signed out |
| the cloud-folder card | nothing at all — a reserved slot |
| Save writes nothing | re-encrypt from scratch → `storage.save_vault()` |
| `Vault::lock()` just assigns | `zeroize_secrets()` + screen switch |
| Settings are in-memory | `AppSettings` JSON in the platform config dir |

---

## 6. Port checklist

Roughly in dependency order. The crate must stay free of in-repo dependencies
until step 1 is actually started.

1. Add `askrypt-core` (with `server-storage`) and replace `data::Entry` with
   `SecretEntry`; delete the fake sample data.
2. Introduce a real `Session` — or reuse `src/session.rs` — and make
   `vault::Vault` a *view* over it rather than the source of truth. The
   predicates in `vault.rs` stay; only what they read changes.
3. Wire the unlock pane to `AskryptFile::get_questions_data` / `decrypt`, each
   through `spawn_blocking` with the spinner and the `decrypting` re-entry guard.
4. Wire the wizard's file step to `rfd` and its server step to `ServerClient`,
   keeping invariant 1: pass the `Arc<ServerStorage>` that did the read.
5. Wire Save / Save As through `VaultStorage`, and make the two synchronous
   paths async (invariant 5).
6. Add the missing screens the prototype does not have yet: entry editor,
   questions editor, password generator.
7. Persist Settings, and add the tray, the timeouts and the keyboard shortcuts
   (Ctrl+S) from `src/app.rs::update_global`.
8. Swap `src/main.rs` over, and delete the old `src/screens/`.
