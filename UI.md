# `src/` — the desktop UI

The three-pane layout the `askrypt` binary draws: real crypto,
real local and server vaults, real persistence, all over `askrypt-core`.

```
cargo run -p askrypt                # optionally: … -- /path/to/MyVault.askrypt
```

It replaced a screen-per-step Iced app — one screen per stage of the vault
lifecycle, with Open reachable only from a Welcome screen — which was deleted
once this one shipped.

This file is the **design notes**: what the UI does, where, and which of its
invariants a redesign can quietly break. Keep it current.

---

## 1. Layout

```
┌─────────────────────────────────────────────────────────┐
│ search strip                    (only when unlocked)    │
├─────────────────────────────────────────────────────────┤
│ follow banner              (only when there is a choice)│
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

The outer `column![search, banner, row![panes].height(Fill), status_bar]` is
what keeps the status bar on the bottom edge. The root is *not* wrapped in a centering
container — the panes are full-bleed.

### Module map

| File | Holds |
|---|---|
| `main.rs` | `App`, `Section`, `Pane`, `Message`/`VaultMsg`/`GlobalMsg`, `PendingAction`, the `visible()`/`reconcile_selection()` filter pair, `default_pane()`/`effective_pane()`, the subscription, the tray and keyboard handling, and the root layout |
| `manager.rs` | `Vault<S>` — the vault as a typestate — its four states, the `VaultState` enum that holds one, the worker-input/result types, `SaveRequest`/`OpenedVault`/`SavedVault`/`ReloadInputs`/`ReloadOutcome` and `write_vault` |
| `smartlock.rs` | the 2M-iteration `create`/`recover` pair over `manager::SmartLocked` |
| `session.rs` | `Session` — the shell's own shared state (settings, tray, messages, spinner, sign-in, and the **sticky** follow fields `follow`/`dismissed_revision`/`last_reload`) around one `vault: VaultState` — plus `VaultError` |
| `settings.rs` | `VaultLocation`, `ServerSession`, `AppSettings`, `ThemeChoice`, `LockTimeout`, `WindowState` — the on-disk shapes |
| `tray.rs` | `AppTray`/`TrayEvent`, polled from the subscription |
| `theme.rs` | the styled-widget helpers plus pane styles, the spinner and layout constants |
| `icon.rs` | glyph codepoints read out of `static/bootstrap-icons.ttf` |
| `data.rs` | pure item helpers over `SecretEntry`: the filter, tags, the write stamp, the card helpers (`is_card`, `card_digits`, `card_last4`, `mask_card_number`, `group_card_number`, `card_subtitle`, `CARD_BRANDS`), and `DATETIME_FORMAT` — the one date/time rendering (`format_timestamp_local` for Unix seconds, `format_rfc3339_local` for RFC 3339 text) every pane uses |
| `follow.rs` | following the stored vault: the probe, the `decide` policy, `Notice` and the banner. Not a pane, for `link.rs`'s reason — the banner sits above the working area, over whichever pane is showing |
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
  `panes::Action`, and `App::apply` does the switching.
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

The vault is a **typestate**, `manager::Vault<S>`, and the state carries its own
data — so a locked vault does not have a master key field that happens to be
`None`, it has no master key field at all. `Session` holds one
`vault: VaultState`, the enum that lets a typestate live in a struct field and
that the rail's buttons and the pane router both ask about directly.

| `VaultState` | State struct | What it holds | Pane |
|---|---|---|---|
| `None` | — | — | `Wizard` |
| `Locked` | `Locked` | — | `Unlock` |
| `Partial` | `PartiallyUnlocked` | `answer0`, `questions_data` | `Unlock` |
| `Unlocked` | `Unlocked` | `answer0`, `answers`, `questions_data`, `entries`, `master`, `modified`, `smart_lock_deadline` | `Items` |
| `Smart` | `SmartLocked` | `key_answer_index`, `key_question`, `encrypted_answer0`, `encrypted_answers`, `salt`, `iv_answer0`, `iv_answers`, `armed_at` | `Unlock` |

Every state also carries `file` (the ciphertext, never absent while a vault is
open) and `home: Option<VaultHome>` — the location **and** the live backend as
one value, so the pair cannot be half-set and a `ServerStorage`'s ETag cannot be
lost. `home: None` is exactly "never written anywhere", which is what makes a
vault composed in the questions editor land in `Unlocked` with its first Save
becoming a Save As.

There used to be a second enum, `vault::Status`, re-derived from the session's
loose fields and carrying exactly these five values — a copy of this enum's
discriminant kept in step by hand. Its rules moved onto `VaultState` and it is
gone, so "which state are we in" is one `match` the compiler checks rather than
an ordered ladder of `Option` tests. There is no longer an
`unlocked && smart_lock_data.is_some()` overlap to disambiguate either:
reopening from Smart Lock consumes the bundle and carries only its 8-hour
deadline into `Unlocked`.

`PartiallyUnlocked` is **not a UI step** — it is a property of the vault format.
The first answer decrypts only the *question list*
(`file.get_questions_data(answer0)`); all the answers together decrypt the
entries (`file.decrypt(&data, answers)`). That is why the unlock pane shows one
field, then the rest. A wrong answer is not *detected*: the decryption fails,
and that failure is the signal.

### Transitions

Every derivation is 600,000 PBKDF2 iterations (2,000,000 for Smart Lock), so
none of them runs on the main thread. Each transition is a **triple**: a method
on the current state producing owned, `Send` inputs; that struct's `run` on a
worker, which converts core's non-`Send` `Box<dyn Error>` into a `String` or a
`VaultError`; and a `self`-consuming apply on `Vault`, called from the
completion message. The answers never ride in a message — the pane already holds
what the user typed and hands it to the apply.

| Transition | Path |
|---|---|
| create a new vault → `Unlocked`, no home | `close_vault()` → `panes::questions` → `RekeyInputs::run` → `adopt_built()` |
| open a local file → `Locked` | wizard `Browse…`/recent → `open_location` → `OpenedVault` → `vault.open()` |
| open from the server → `Locked` | wizard server step → `download` → `OpenedVault` → `vault.open()` |
| sign in to a server | `link::Msg::Start` → browser → poll → `session.sign_in` |
| auto-open at startup | `App::boot` (argv, else `settings.last_opened_file`) |
| answer 0 → `PartiallyUnlocked` | `start_first_answer` → `RevealInputs::run` → `apply_reveal()` |
| all answers → `Unlocked` | `start_full_unlock` → `UnlockInputs::run` → `apply_unlock()` |
| `Unlocked` → `Locked` ("Lock") | `guard(Lock)` → `vault.lock()` |
| `Unlocked` → `SmartLocked` | `guard(SmartLock)` → `SmartLockInputs::run` → `apply_smart_lock()` |
| `SmartLocked` → `Unlocked` | `start_smart_unlock` → `SmartUnlockInputs::run` → `apply_smart_unlock()` |
| `SmartLocked` → `Locked` ("Full Lock") | `guard(Lock)` → `vault.lock()` (drops the bundle) |
| anything → `NoVault` ("Close Vault") | `guard(CloseVault)` → `close_vault()` → the wizard, armed |
| idle → `SmartLocked`; 8 h → `Locked` | `auto_smart_lock` / `smart_lock_timed_out`, from `InactivityTick` |
| save | `save_now()` → `write_vault` on a worker → `apply_saved()` |
| the stored copy changed → reload | `FollowTick`/window focus → `follow::probe` → `follow::decide` → `ReloadInputs::run` → `apply_reloaded()` (or `apply_refreshed`/`apply_requestioned`, per state) |
| the stored copy changed, but it no longer opens | same, → `ReloadOutcome::Rekeyed` → banner → `relock_with()` onto the *new* bytes |
| save as / save to server | wizard → `Message::SaveTo(VaultLocation)` → same worker |

Three lock *depths*, all kept: **Smart Lock** (one answer to return), **Lock**
(all answers), **Close** (must re-open the file first).

**Locking is dropping the state.** `Zeroizing` answers plus core's
`ZeroizeOnDrop` on `QuestionsData`, `SecretEntry` and `MasterSecret` mean
`pm.lock()` wipes everything the state held; there is no `zeroize_secrets` to
call and nothing to forget. `file` and `home` cross to the new state, which is
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
disabled when the state does not allow it. The predicates are on `VaultState`; `panes/sidebar.rs`
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
the second commits.

### The wizard

Splitting this work by *screen* is what the old app did, and it put Open only on
its Welcome screen, Save/Save As/Save to Server only on its entries screen, and
gave "Save As" two different UIs depending on the destination — a native file
dialog for a path, a whole screen with a text field for a server name. You could
not Open while a vault was already open without going back to Welcome, and could
not pick a file path from inside the server screen.

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
is `VaultState::can_cancel_wizard`, next to the rail's predicates; Back
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
(which is what this pane used to do) hides every vault saved since — by this app or another device — from the open
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

### Following the stored vault

A vault on a server — or in a synced folder — can be written by another device
while it is open here. `follow.rs` checks every **60 s** (`FOLLOW_INTERVAL`) and
again whenever the window regains focus, comparing what the backend holds now
against what this app's storage instance is on. A backend that reports no
revision is *unfollowable*, which is not the same as unchanged: it is left
alone rather than assumed still.

The probe is one `GET /api/v1/vaults` for a server vault and one `stat` for a
file. It never reads the vault, never raises the spinner, never stamps user
activity (that would hold the idle lock open forever), and is skipped while
`session.busy` or while one is already in flight. The *reload* it may lead to
is behind `busy` like any other work — it only runs when something actually
changed, and it must block a save, since reading moves the backend onto the
version being fetched and a save squeezed in between would inherit it. Failures are silent — a
network blip says nothing about the stored copy — except an `Auth` failure,
which signs out and stops following.

`follow::decide` is the whole policy, kept a pure function so this table is
testable without a UI or a network:

| State | Unsaved work? | The stored copy changed |
|---|---|---|
| `Locked` | impossible | silent refresh of the bytes (`apply_refreshed`); the unlock pane re-renders `question0` |
| `PartiallyUnlocked` | impossible | re-read, then re-run `get_questions_data(answer0)` → `apply_requestioned`; a failure means the questions moved, so `Rekeyed` |
| `Unlocked` | no | silent reload — `Unlocked` still holds every answer, so nothing is asked (`apply_reloaded`) |
| `Unlocked` | **yes** | **the banner**: *Save mine* / *Discard mine & reload* / *Keep editing*. Nothing is touched until a button is pressed |
| `SmartLocked` | impossible (arming is gated on saving) | silent refresh; the answer bundle is keyed off itself, not off the file |

"Unsaved work" is `is_modified()` **or** `App::has_draft()` — an entry open in
the editor and the questions editor open both count, and neither sets the dirty
flag.

Three details carry the rest:

- **Every reload writes a status line naming who wrote the bytes and when** —
  `follow::reload_line` over `data::format_stamp`, off the vault's own
  unencrypted `params.host`/`params.updated_at`. It lives in
  `Session.last_reload`, which `clear_messages` deliberately spares: the
  transient three are wiped by the next keystroke, and a reload nobody asked
  for is worth still seeing afterwards. `status_line` reads it below
  error/success/status and above the vault's own line.
- **A dismissal is per revision.** *Keep editing* records
  `Session.dismissed_revision`; a *further* change mints a new revision and so
  raises the banner again. A save or a lock calls `Session::settle_follow`,
  which spends the dismissal along with the edits it covered.
- **Reloading uses the storage instance the vault was opened with**, never a
  fresh one — the same reason a save does (invariant 1) — so the reload also
  leaves the backend on the version it just took.

## 4. Invariants, and where they are enforced

0. **A state's data lives in the state.** Most of the invariants below used to
   be prose about which loose `Option`s had to agree; they are now the shape of
   `manager::Vault<S>`. A method exists only where it is legal —
   `save_request` is on `Vault<Unlocked>` and nowhere else — and
   dropping a state wipes it. The states and the worker-result types must
   **not** derive `ZeroizeOnDrop`: it implies `Drop`, and a type with `Drop`
   cannot be destructured (E0509), which is exactly what `with_state` and every
   transition do. Compose the wiping from the leaves instead, as `core` does
   for `CardFields`.
1. **A vault's location and its storage instance are one value, and it lives as
   long as the open vault.** A `ServerStorage` records the ETag it saw when
   it *read*, and sends it as `If-Match` when it writes; rebuilding the backend
   before each save re-resolves whatever ETag the server holds *now* and
   silently overwrites another device's edit.
   → `manager::VaultHome` pairs them, so there is no half-set combination to
   get wrong; `wizard::load_task` puts the instance that performed the read
   inside an `OpenedVault`, never a description of it.
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
   `theme::spinner_row`, with `Session::busy` guarding re-entry. → every
   transition is split across that seam as an inputs/`run`/apply triple; see
   §2. **A transition is applied only from the success arm**, so a wrong answer
   leaves the vault exactly where it was and never stores what was typed — and
   an apply that arrives in the wrong state (the vault was closed or locked
   while the worker ran) returns `false` and drops the stale result rather than
   installing it.
6. **Lock, Smart Lock, New, Open and Exit must prompt about unsaved changes**,
   and Cancel aborts. → `App::guard`, which routes "Yes" through an async save
   and replays the queued `PendingAction` from `after_save` once it lands.
   Smart Lock belongs on that list because arming it drops the `Unlocked`
   state, entries and all — an ungated one loses unsaved edits silently. The
   dirty flag lives *in* that state (`VaultState::is_modified()` is false in every
   other one), so it cannot survive the edits it describes.
7. **Pane state that holds secrets wipes on drop.** → `Drop` impls on
   `unlock::State` (answers), `questions::State` (answers), `passgen::State`
   (the generated password) and `manager::SaveRequest`; the editor's draft is
   wiped by `SecretEntry`'s own `ZeroizeOnDrop` — **except the notes**, which
   are a multi-line `text_editor` and live in cosmic-text's own buffer until
   `entry_editor::save` folds them back into the entry. `wizard::State` needs none —
   it has held no password since sign-in moved to the browser. Any new pane
   holding a typed answer or password needs the same.
8. **A background event must not destroy work.** Two of them can: the idle
   timeout and following the stored vault, both firing with nobody at the
   keyboard to be asked.
   - An automatic Smart Lock wipes the decrypted entries, so
     `App::auto_smart_lock` saves first when the vault has a home — and
     declines to lock at all when it does not, because a never-saved vault
     exists only in this process.
   - A reload replaces them, so `follow::decide` returns `Ask` rather than
     `Reload` whenever `is_modified()` or `App::has_draft()` holds. `busy`
     stops another *task* starting during the wait but not typing, so
     `App::install_reload` **re-checks both at the moment of applying** and
     raises the banner instead — editing during those two derivations is
     otherwise exactly the window in which a reload eats what was typed.
9. **A vault's master key is minted once and never rotated.** It is a property
   of the *vault*, not of a write, and it is what the coming file attachments
   will be encrypted under — rotating it per save would mean re-encrypting all
   of them each time. → `Unlocked.master`, which is **not** an `Option`: every
   path into that state has a key, from `AskryptFile::decrypt_with_master` or
   from the one place in the app that mints one, `RekeyInputs::run`. It is
   carried in `SaveRequest.master` and handed to `AskryptFile::create`, so the
   save path has no mint-on-write branch at all — and because a *write* returns
   a `SavedVault` while an *open* returns an `OpenedVault`, there is no single
   handle type whose `master: None` could be mistaken for "the key is gone".
   Guarded by `saving_preserves_the_master_key` and
   `changing_the_questions_keeps_the_master_key`. What is *not* preserved: the
   salts and the `data` IV rotate on every write, and the IV must — see
   `SPEC.md`, "Master key lifetime".
10. **A probe never disarms the conflict check.** The backend's remembered
   revision is what the next save sends as `If-Match`, so
   `VaultStorage::current_revision` is specified not to touch it, and
   `probing_leaves_the_conflict_check_armed` guards that in `core`. Reading,
   though, *does* move it — which is right when the reload is applied and wrong
   when it is not, so `App::finish_reload` rolls it back with
   `adopt_revision` on every path that declines. Deliberately replacing another
   device's version is the one thing allowed to move it forward, and only from
   the banner's *Save mine*.
11. **`settings.window` holds the geometry the window *unmaximizes* back to**,
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

## 6. Still open

The port is finished: this UI *is* the `askrypt` binary, and the screen-per-step
app it grew out of (`src/app.rs`, `src/message.rs`, `src/ui.rs` and
`src/screens/`) is deleted. What it did not bring along:

- A real per-item icon (see §5).
- Merging: a reload is all-or-nothing. When both sides changed, the user picks
  one — there is no per-entry merge, and the vault format carries no per-entry
  id to build one on.
- `Session::new()` builds the tray and reads `server_session.json` inline, and
  `App::boot` opens the last vault inline — a server location therefore makes a
  network call before the window appears, which the app it replaced did too.
