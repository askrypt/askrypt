# `askrypt-gui` — the new desktop UI

The three-pane, Bitwarden-like layout (`uisample.jpg`) that will replace the
screen-per-step Iced app in `src/`. It is a **working Askrypt client**: real
crypto, real local and server vaults, real persistence, all over `askrypt-core`.

```
cargo run -p askrypt-gui            # optionally: … -- /path/to/MyVault.askrypt
```

`src/` still builds and still ships (`cargo build -p askrypt`); swapping the
`askrypt` binary over and deleting `src/screens/` is the last checklist item
below.

This file is the **port notes**: what the shipping app in `src/` does, where,
and which of its invariants a redesign can quietly break. Keep it current.

---

## 1. Layout

```
┌─────────────────────────────────────────────────────────┐
│ search strip                    (only when unlocked)    │
├────────────┬────────────────────────────────────────────┤
│            │                                            │
│  nav rail  │   working area                             │
│            │     Items  = list │ detail-or-editor       │
│  filters   │     Settings / Unlock / Wizard /           │
│  ───────   │     Questions / PassGen = one pane         │
│  vault     │                                            │
│  actions   │                                            │
│  ───────   │                                            │
│  Settings  │                                            │
│  ───────   │                                            │
│  Quit      │                                            │
├────────────┴────────────────────────────────────────────┤
│ status bar + spinner                    (always pinned) │
└─────────────────────────────────────────────────────────┘
```

The outer `column![search, row![panes].height(Fill), status_bar]` is what keeps
the status bar on the bottom edge. Unlike `src/app.rs::view`, the root is *not*
wrapped in a centering container — the panes are full-bleed.

### Module map

| File | Holds |
|---|---|
| `main.rs` | `App`, `Section`, `Pane`, `Message`/`VaultMsg`/`GlobalMsg`, `PendingAction`, the `visible()`/`reconcile_selection()` filter pair, `default_pane()`/`effective_pane()`, the subscription, the tray and keyboard handling, and the root layout |
| `session.rs` | `Session` — all shared state and every lifecycle transition — plus `SmartLockData`, `VaultError`, `SaveRequest`/`VaultHandle` and `write_vault` |
| `settings.rs` | `VaultLocation`, `ServerSession`, `AppSettings`, `ThemeChoice`, `LockTimeout`, `WindowState` — the on-disk shapes |
| `tray.rs` | `AppTray`/`TrayEvent`, polled from the subscription |
| `vault.rs` | `Status` — derived from `Session`, **and** the button-visibility rules |
| `theme.rs` | helpers copied from `src/ui.rs` plus pane styles, the spinner and layout constants |
| `icon.rs` | glyph codepoints read out of `static/bootstrap-icons.ttf` |
| `data.rs` | pure item helpers over `SecretEntry`: the filter, tags, the write stamp, the card helpers (`is_card`, `card_digits`, `card_last4`, `mask_card_number`, `group_card_number`, `card_subtitle`, `CARD_BRANDS`), and `DATETIME_FORMAT` — the one date/time rendering (`format_timestamp_local` for Unix seconds, `format_rfc3339_local` for RFC 3339 text) every pane uses |
| `panes/mod.rs` | `Action` — the pane → shell navigation contract |
| `panes/sidebar.rs` | the nav rail: filters, the vault actions, Quit, Settings |
| `panes/list.rs`, `panes/detail.rs` | the item split |
| `panes/entry_editor.rs` | the item draft, drawn in the detail slot |
| `panes/questions.rs` | the security questions — the only pane that can create a vault |
| `panes/passgen.rs` | the password generator |
| `panes/settings.rs` | the settings screen, writing through to `AppSettings` |
| `panes/unlock.rs` | the layered unlock screen |
| `panes/wizard.rs` | the Open / Save As source picker |
| `panes/statusbar.rs` | the bottom bar and the spinner |

Rules that are easy to undo by accident:

- **Selection is an index into `session.entries`, never into the filtered view**,
  so filtering cannot invalidate it; `reconcile_selection` falls back to the
  first visible row when a filter hides the selection.
- **Every pane style is palette-derived**, which is why the Settings theme
  picker works. Hard-coding a color breaks the dark theme.
- **Anything drawn per item must be deterministic.** `view` runs every frame, so
  the list row's icon is *derived* from the entry name (`icon::placeholder`)
  rather than actually randomized — a real random pick would flicker.
- **Panes never switch the working area themselves.** They return a
  `panes::Action`, and `App::apply` does the switching — the same contract
  `src/screens/mod.rs::Action` has.
- **The editor's form is chosen by the Type picker, and switching it clears
  nothing.** `Card` draws Cardholder / Brand / Number / Expiry / CVV / PIN where
  `Login` draws Username / Password / Website; Name, Type, Tags, Notes and
  Hidden are common to both. The draft is a whole `SecretEntry` and `save`
  writes all of it, so what was typed into the *other* set survives a round trip
  through the picker — tidying the hidden fields on a type change would be a
  silent data loss. `detail.rs` and `list.rs` branch on the same
  `data::is_card`, and one `revealed` flag covers the number, the CVV and the
  PIN together: they are three halves of one secret.

---

## 2. The vault lifecycle

There is no `VaultState` field. `vault::Status::of(&Session)` *derives* the
state from four session fields, so the rail's buttons and the pane router can
never disagree about which state the app is in.

| State | `file` / `questions_data` / `unlocked` / `smart_lock_data` | Pane |
|---|---|---|
| `NoVault` | none / none / false / none | `Wizard` |
| `Locked` | **some** / none / false / none | `Unlock` |
| `PartiallyUnlocked` | some / **some** / false / none | `Unlock` |
| `Unlocked` | some / some / **true** / none | `Items` |
| `SmartLocked` | some / none / false / **some** | `Unlock` |

`unlocked` is checked first, so a session restored from Smart Lock — which keeps
`smart_lock_data` and slides its 8-hour clock — reads as `Unlocked`.

There is a sixth, transient shape the model folds away: *composing* a new vault
in the questions editor, where `file` is still `None`. It collapses into
`Unlocked` with `location: None`, which is exactly what makes its first Save a
Save As.

`PartiallyUnlocked` is **not a UI step** — it is a property of the vault format.
The first answer decrypts only the *question list*
(`file.get_questions_data(answer0)`); all the answers together decrypt the
entries (`file.decrypt(&data, answers)`). That is why the unlock pane shows one
field, then the rest. A wrong answer is not *detected*: the decryption fails,
and that failure is the signal.

### Transitions

Every one is a `Session` method (`gui/src/session.rs`), started from
`App::perform` or a pane. The `src/` column is where the shipping app does the
same thing, for comparison.

| Transition | Here | In `src/` |
|---|---|---|
| create a new vault → `Unlocked`, no location | `close_vault()` → `panes::questions` → `Built` | `welcome.rs:67` → `questions.rs` → Save |
| open a local file → `Locked` | wizard `Browse…`/recent → `open_location` → `open_vault()` | `welcome.rs:26-54` (blocking dialog) |
| open from the server → `Locked` | wizard server step → `download` → `open_vault()` | `server.rs`, `Mode::Open` |
| sign in to a server | `link::Msg::Start` → browser → poll → `session.sign_in` | `server.rs` email + password form |
| auto-open at startup | `App::boot` (argv, else `settings.last_opened_file`) | `app.rs:30-68` |
| answer 0 → `PartiallyUnlocked` | `panes::unlock::start_first_answer` | `unlock.rs:69` |
| all answers → `Unlocked` | `panes::unlock::start_full_unlock` → `apply_unlock()` | `unlock.rs:186` |
| `Unlocked` → `Locked` ("Lock") | `guard(Lock)` → `lock()` | `entries.rs:126-139` |
| `Unlocked` → `SmartLocked` | `guard(SmartLock)` → `start_smart_lock` → `apply_smart_lock()` | `app.rs:339-354` |
| `SmartLocked` → `Unlocked` | `panes::unlock::start_smart_unlock` → `apply_smart_unlock()` | `smart_lock.rs` |
| `SmartLocked` → `Locked` ("Full Lock") | `guard(Lock)` → `lock()` (clears `smart_lock_data`) | `app.rs:211-221` |
| anything → `NoVault` ("Close Vault") | `guard(CloseVault)` → `close_vault()` → the wizard, armed | `app.rs:183-196` |
| idle → `SmartLocked`; 8 h → `Locked` | `auto_smart_lock` / `smart_lock_timed_out`, from `InactivityTick` | `session.rs:27-29`, `app.rs:222-230` |
| save | `save_now()` → `write_vault` on a worker → `apply_saved()` | `session.rs:294-333` (**blocking**) |
| save as / save to server | wizard → `Message::SaveTo(VaultLocation)` → same worker | `session.rs:336-456` (**blocking**) |

Three lock *depths*, all kept: **Smart Lock** (one answer to return), **Lock**
(all answers), **Close** (must re-open the file first).

`zeroize_secrets` wipes exactly `answer0`, `answers` and `entries`. It
deliberately **keeps** `file`, `location`, `storage` and `question0` — which is
why a locked vault can still show its path, its first question and its write
stamp without touching the disk.

---

## 3. The controls

Every vault action lives at the bottom of the nav rail, with **Settings and then
Quit pinned below them on the very bottom edge** — the two rows that are
never about the vault in front of you, each in a band of its own. Quit is
`GlobalMsg::QuitRequested`, which **confirms first** (`App::confirm_quit`, a
Yes/No dialog) and then goes through `guard(PendingAction::Exit)` like the
window close does. The tray's Quit takes the same confirmed path; a *modified*
vault skips the extra question, because the unsaved-changes dialog it gets
instead is already a confirmation. Each action is **hidden** rather than
disabled when the state does not allow it. The predicates are on `vault::Status`; `panes/sidebar.rs`
only asks.

| Button | Shown in | Predicate |
|---|---|---|
| New Vault | every state | `can_create()` |
| Open Vault… | every state | `can_open()` |
| Close Vault | every state but `NoVault` | `can_close()` |
| Unlock | `Locked`, `PartiallyUnlocked`, `SmartLocked` | `can_unlock()` |
| Smart Lock | `Unlocked` | `can_smart_lock()` |
| Lock / **Full Lock** | `Unlocked` / `SmartLocked` | `can_lock()` + `lock_label()` |
| Save | `Unlocked` | `can_save()` |
| Save As… | `Unlocked` | `can_save_as()` |
| Edit Questions | `Unlocked` | `can_edit_questions()` |
| Password Generator | every state | — (needs no vault) |
| Quit | every state | — (confirmed, then guarded by the unsaved-changes gate) |
| Cancel (the wizard's footer, not the rail) | every state but `NoVault` | `can_cancel_wizard()` |

The item filters (All Items, Hidden, TYPES, TAGS) and the search strip only
exist while the vault is unlocked. `effective_pane()` additionally refuses to
render the item list over a locked vault, so a stale rail selection cannot leak
rows, and every lock path calls `clear_secret_panes()` so a pane holding typed
answers cannot survive one either.

**New Vault** is the one action that lands *unlocked*: the questions editor
runs, and a successful build leaves `location: None` — which is why `save_now()`
falls back to Save As, and the only way to reach the "Untitled vault\*" status
line and the list pane's empty state.

**Delete takes two presses.** The first arms the button (`App.pending_delete`),
the second commits. The shipping app deletes with no confirmation at all
(`src/screens/entries.rs:65-80`).

### What the wizard replaces

The shipping app splits this work by *screen*, not by intent: Open lives only on
Welcome, Save/Save As/Save to Server only on the entries screen, and "Save As"
means two different UIs depending on the destination — a native file dialog for
a path, a whole screen with a text field for a server name. You cannot Open
while a vault is already open without going back to Welcome, and you cannot pick
a file path from inside the server screen.

`panes/wizard.rs` collapses that into **pick a source, then fill it in**, driven
by a `Purpose` (`Open` / `SaveAs`) rather than by which screen you came from.
Sources: **Local file**, **Askrypt Server**, and a disabled **Cloud folder**
card that reserves the slot. A plain Save never reaches the wizard — it goes
straight to the backend the vault was opened with, which is invariant 1.

The "fill it in" half is skipped where the system can do it better: picking
**Local file** while saving opens `rfd`'s save dialog straight away, prefilled
with the vault's name, because that dialog already asks for the folder *and* the
name. So the file step exists only in the Open direction (the recent list plus
`Browse…`), and only the server step asks the save direction for a name. That
recent list is **filtered to `VaultLocation::LocalFile`** — the MRU records both
kinds of home, and a server vault offered by the local-file step would open over
a backend that step does not offer. It is filtered after `enumerate`, so a row
still carries the index into `settings.recent_vaults` that `RecentPicked` looks
up.

Its footer follows the same hide-rather-than-disable rule as the rail: **Cancel
appears only when there is somewhere to cancel to.** It dismisses the pane to
`App::default_pane`, which *is* the wizard while the status is `NoVault`, so
with no vault open the button would re-arm the pane already on screen. The test
is `vault::Status::can_cancel_wizard`, next to the rail's predicates; Back
already covers stepping out of a source, and when neither applies the footer
renders nothing at all rather than an empty row.

**The wizard is a pane that outlives its own runs, so it must be armed, never
merely navigated to.** `State::begin` is what resets the step, the picks and the
prefilled names for a `Purpose`; landing on `Pane::Wizard` without it shows
whatever the last run was left on — a server listing, or the recent-files step.
That is why closing a vault is the *shell's* job (`PendingAction::CloseVault`,
which closes and then calls `start_wizard`) and the "Close Vault" button on the
unlock pane delegates to it rather than closing the vault itself: a pane cannot
reach `App.wizard`. `App::return_to_default` and `Message::PaneSelected` arm it
for the same reason.

The server step also no longer asks for an address, an email or a password: the
address is a setting and the sign-in happens in a browser (see invariant 4), so
that step is one button, the shared waiting card, the account's vault list
(Open), or — saving — a name field over that same list, rendered read-only.

**Everything the listing cannot do is a link to the website.** Both directions
render the same account row, and it carries a `Manage vaults` link beside
`Refresh` and `Sign out` that opens `<server>/vaults` (`manage_vaults_url`, over
the existing `Message::OpenUrl`) in the browser. Renaming, deleting, the quota
and version history all live in the server's own file manager, and this pane is
deliberately not growing a second one. The URL comes from the *signed-in
client's* `base_url()`, not `settings.server_url()` — the "signed in elsewhere"
check at the top of the step can leave the two divergent for a frame — and the
link is absent while signed out, where `/vaults` would only bounce to `/login`.

**Entering the server step always refetches that list.** Caching it per sign-in
(which is what `src/screens/server.rs` does, and what this pane used to do)
hides every vault saved since — by this app or another device — from the open
direction as a missing row, and from the save direction as a missing or false
"will be replaced" warning. The previous rows stay up while the request runs, so
there is no flicker; `Refresh` is now an explicit re-fetch rather than the only
one. `State::listing` is what keeps a first, still-running listing from
rendering as "No vaults on this account yet."

**The save direction says what it knows, including that it knows nothing.** A
server vault is addressed by name (invariant 3), so a typed name that an account
already holds replaces that vault in place. `name_status` reduces the typed name
plus the listing to a `NameStatus`, and every value renders a line:

| `NameStatus` | when | line |
|---|---|---|
| `Empty` | nothing typed | — |
| `Checking` | no listing yet, one in flight | "Checking your vaults…" |
| `Unknown` | no listing, none in flight (the fetch failed) | "Could not check this account's vaults…" |
| `Free` | listed, no match | "This will create a new vault on the server." |
| `Replaces(i)` | listed, row `i` matches | "…already exists and will be replaced." |

`Checking` and `Unknown` are the point of the enum. The pane used to compute one
boolean off `Option<Vec<_>>`, so a listing that was in flight, had failed, or had
never run all rendered as *silence* — indistinguishable from a name it had
checked and found free, which is the one reading that invites an accidental
overwrite. A refresh over rows already held keeps answering off those rows;
going blank on every refresh would be the worse lie.

Below the field, the same rows the Open direction offers are rendered read-only
(`info_row`, a container rather than a button — these name what is there, they
are not a pick), and the row `Replaces(i)` matched is marked `WILL BE REPLACED`,
so the warning points at something the user can see. Each row carries the
server's `updated_at` **and** the file's own `host`/`saved_at` write stamp, which
`RemoteVault` now keeps (the server has always sent both; the client dropped
them). The two timestamps differ after a restore, or when an older file is
uploaded from another device.

One known inaccuracy, deliberate: the match is `eq_ignore_ascii_case` while the
server's uniqueness is byte-exact (`UNIQUE (account_id, name)` with no `COLLATE
NOCASE`, and `ServerStorage::resolve` compares with `==`). Typing `work` when
`Work` exists therefore warns about a replacement that would in fact create a
second vault. The marked row is the mitigation — it spells the existing name out
next to what was typed — and a unit test pins the behavior so it stays a choice.

**Opening never has a confirm button.** A vault row — a recent file or one of
the account's server vaults — is a destination, not a setting, so clicking it
starts the open right there; that is why every such row ends in a chevron and
why `picked_*` only highlights the row whose open is under way. The one thing
left to confirm is naming a server vault to *save* to, so `footer` shows its
`Save` button only for `Step::Server` in the `SaveAs` direction, and that is the
only case `confirm()` acts on.

---

## 4. Invariants, and where they are enforced

1. **`location` and `storage` are set together, and the storage instance lives
   as long as the open vault.** A `ServerStorage` records the ETag it saw when
   it *read*, and sends it as `If-Match` when it writes; rebuilding the backend
   before each save re-resolves whatever ETag the server holds *now* and
   silently overwrites another device's edit.
   → `Session::set_vault_location` is the only way to set either;
   `Session::save_target()` hands back the pair; `wizard::load_task` carries the
   instance that performed the read inside a `VaultHandle`, never a description
   of it.
2. **`VaultLocation::LocalFile` must stay the first variant** of the `untagged`
   enum or existing `settings.json` files — which store a plain path string —
   stop parsing. → `settings.rs`, guarded by
   `settings_json_distinguishes_a_path_from_a_server`.
3. **A server vault is keyed by name**, not by the server-assigned id, and needs
   a signed-in client whose `base_url` matches; otherwise
   `VaultLocation::storage` fails with `StorageError::Auth`. That is also why
   saving to an existing name overwrites, and why the wizard warns about it.
   → guarded by `server_storage_requires_a_client_for_the_same_server`.
4. **Sign-in and vault source are independent axes.** `Session::sign_out`
   deliberately leaves an open server vault alone — the user keeps what they
   decrypted; only saving asks them to sign in again. → the wizard reads
   `session.is_signed_in()` rather than keeping a flag of its own, so the
   sign-in survives every run of it.
   **The app never asks for an account password.** Signing in opens the
   server's own page in a browser and polls for the token (`link.rs`), so
   registration works from the app too and no credential passes through this
   process. The server is a *setting* (`settings.server_url`, default
   `https://askrypt.com`), not a field on a form; the wizard and the Settings
   pane share one `waiting_card`, and the in-flight link lives on the
   `Session` because either pane can start it and it outlives both. Leaving
   those panes cancels the link server-side — closing the pane means the user
   no longer wants it. The wait must **not** hold `Session::busy`: that hides
   the Cancel button the user needs, which is why this is the one long-running
   task in the crate without a spinner.
5. **Every PBKDF2 path and every vault read or write runs off the main thread**
   — `Task::perform` + `tokio::task::spawn_blocking`, behind
   `theme::spinner_row`, with `Session::busy` guarding re-entry. → the two paths
   the shipping app still runs inline (`save_vault_as`, `save_vault_to_server`)
   are async here: `save_request()` collects on the main thread, `write_vault`
   works, `apply_saved()` mutates.
6. **Lock, Smart Lock, New, Open and Exit must prompt about unsaved changes**,
   and Cancel aborts. → `App::guard`, which routes "Yes" through an async save
   and replays the queued `PendingAction` from `after_save` once it lands. The
   shipping app does not gate Smart Lock, which silently loses unsaved edits
   because `apply_smart_lock` zeroizes the entries.
7. **Pane state that holds secrets wipes on drop.** → `Drop` impls on
   `unlock::State` (answers), `questions::State` (answers), `passgen::State`
   (the generated password) and `session::SaveRequest`; the editor's draft is
   wiped by `SecretEntry`'s own `ZeroizeOnDrop` — **except the notes**, which
   are a multi-line `text_editor` and live in cosmic-text's own buffer until
   `entry_editor::save` folds them back into the entry. `wizard::State` needs none —
   it has held no password since sign-in moved to the browser. Any new pane
   holding a typed answer or password needs the same.
8. **The idle timeout must not destroy work.** An automatic Smart Lock wipes the
   decrypted entries with nobody at the keyboard to be asked about it, so
   `App::auto_smart_lock` saves first when the vault has a home — and declines
   to lock at all when it does not, because a never-saved vault exists only in
   this process.
9. **`settings.window` holds the geometry the window *unmaximizes* back to**,
   never the maximized box, or a window maximized at exit would come back
   maximized and shrink to the whole screen. Iced reports moves and resizes but
   has no maximized event, so `App::record_geometry` parks what it saw and one
   `window::is_maximized` round trip (`GlobalMsg::ProbeWindow` →
   `WindowMaximized`) decides whether `App::commit_geometry` keeps it. The same
   path drops nonsense geometry — Windows reports a minimized window at
   `-32000, -32000` sized `0 x 0`, and this app minimizes to the tray, so that
   would otherwise be the last value seen. Restoring is `main()` reading
   `AppSettings::load().window` before the window is built; the `maximized`
   flag is re-asserted on `window::Event::Opened`, because some window managers
   drop the creation-time hint when a position is given with it.

---

## 5. What is still not real

| Here | Would be |
|---|---|
| each item's icon is `icon::placeholder(name)` — one of 16 glyphs picked by hashing the name, except a `Card`, which gets `icon::credit_card` | a real per-item icon: a site favicon, a card issuer's logo. Nothing derives one yet; replace the whole function, not the pool |
| the cloud-folder card | nothing at all — a reserved slot for Dropbox/Drive sync |

Everything else — unlock, Smart Lock, save, Save As, the server, settings, the
tray, the timeouts — is wired to `askrypt-core` and the platform.

---

## 6. Port checklist

1. ~~Add `askrypt-core` (with `server-storage`) and replace `data::Entry` with
   `SecretEntry`; delete the fake sample data.~~ **done**
2. ~~Introduce a real `Session` and make `vault.rs` a *view* over it rather than
   the source of truth.~~ **done** — `Status::of(&Session)`; the predicates
   moved onto `Status` and the table test came with them.
3. ~~Wire the unlock pane to `AskryptFile::get_questions_data` / `decrypt`
   through `spawn_blocking`, with the spinner and the re-entry guard.~~ **done**
4. ~~Wire the wizard's file step to `rfd` and its server step to
   `ServerClient`, keeping invariant 1.~~ **done** — `rfd::AsyncFileDialog`, so
   the dialog does not block the runtime either.
5. ~~Wire Save / Save As through `VaultStorage`, and make the two synchronous
   paths async.~~ **done**
6. ~~Add the missing screens: entry editor, questions editor, password
   generator.~~ **done**
7. ~~Persist Settings, and add the tray, the timeouts and the keyboard
   shortcuts.~~ **done** — `lock_timeout` now really drives the idle check and
   `clear_clipboard` really wipes the clipboard.
8. Swap `src/main.rs` over, and delete the old `src/screens/`. **not started** —
   `src/` is untouched and still ships.

Things worth doing before step 8:

- A real per-item icon (see §5).
- Reload-on-conflict: `VaultError::Conflict` currently only reports; there is no
  "reload and merge" path.
- `Session::new()` builds the tray and reads `server_session.json` inline, and
  `App::boot` opens the last vault inline — a server location makes that a
  network call before the window appears, exactly as `src/app.rs` does today.
