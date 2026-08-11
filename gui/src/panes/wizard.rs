//! The vault source wizard: one pane serving Open, Save and Save As.
//!
//! The shipping app splits this work across a native `rfd` dialog (local files,
//! `src/screens/welcome.rs` and `src/session.rs::save_vault_as`) and a whole
//! screen of its own (the server, `src/screens/server.rs`), so Open is reachable
//! only from Welcome and Save only from the entries screen. Here both directions
//! run through the same two steps — pick a source, then fill it in — which is
//! the point of the redesign.
//!
//! Opening hands the shell the [`VaultHandle`] carrying the storage instance
//! that performed the read, never a rebuilt one: a `ServerStorage` records the
//! ETag it saw and sends it back as `If-Match`, so a fresh instance would
//! silently overwrite another device's edit.

use std::path::PathBuf;
use std::sync::Arc;

use askrypt::{RemoteVault, ServerClient, ServerStorage, VaultStorage};
use iced::widget::{button, column, container, row, rule, scrollable, text, text_input};
use iced::{Element, Length, Task, alignment::Vertical};

use crate::data;
use crate::panes::Action;
use crate::session::{
    Session, VaultError, VaultHandle, describe_open_error, describe_sign_in_error,
};
use crate::settings::VaultLocation;
use crate::{App, Message, icon, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Open,
    /// Choosing a *new* home for the vault. A plain Save never reaches the
    /// wizard — it goes straight to the backend the vault was opened with — so
    /// there is no separate `Save` purpose.
    SaveAs,
}

impl Purpose {
    fn caption(self) -> &'static str {
        match self {
            Purpose::Open => "OPEN VAULT",
            Purpose::SaveAs => "SAVE VAULT AS",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Purpose::Open => "Where is the vault?",
            Purpose::SaveAs => "Where should the vault go?",
        }
    }

    fn is_save(self) -> bool {
        matches!(self, Purpose::SaveAs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    PickSource,
    File,
    Server,
    Cloud,
}

/// The account's vaults, refetched every time the server step is entered (and
/// on demand from `Refresh`). `None` means "not listed yet" — paired with
/// `State::listing` it tells a fetch in flight from a genuinely empty account.
type Listing = Option<Vec<RemoteVault>>;

pub struct State {
    purpose: Purpose,
    step: Step,
    error: Option<String>,

    // File step.
    file_name: String,
    picked_recent: Option<usize>,

    // Server step. Neither the sign-in nor the credentials for one live here:
    // signing in happens in the browser ([`crate::link`]), and the resulting
    // session lives on the `Session`, outlasting any one run of the wizard.
    vaults: Listing,
    /// A listing is in flight. Only the body needs this — the footer reads
    /// `Session::busy` — so that "Loading…" does not read "No vaults".
    listing: bool,
    vault_name: String,
    picked_vault: Option<usize>,
}

impl Default for State {
    fn default() -> Self {
        State {
            purpose: Purpose::Open,
            step: Step::PickSource,
            error: None,
            file_name: String::new(),
            picked_recent: None,
            vaults: None,
            listing: false,
            vault_name: String::new(),
            picked_vault: None,
        }
    }
}

impl State {
    /// Arm the wizard for a purpose, prefilling the names from the open vault
    /// and the server fields from the remembered sign-in.
    ///
    /// The sign-in itself survives across runs of the wizard: the token outlives
    /// the vault (`Session::sign_out` deliberately leaves an open vault alone),
    /// so signing in is not part of any one flow.
    pub fn begin(&mut self, purpose: Purpose, session: &Session) {
        // A vault with no home yet has no name to suggest either.
        let name = match &session.location {
            Some(location) => location.display_name(),
            None => "MyVault.askrypt".to_string(),
        };

        self.purpose = purpose;
        self.step = Step::PickSource;
        self.error = None;
        self.picked_recent = None;
        self.picked_vault = None;
        self.file_name = if name.ends_with(".askrypt") {
            name.clone()
        } else {
            format!("{name}.askrypt")
        };
        self.vault_name = name.trim_end_matches(".askrypt").to_string();

        // A stale listing from a previous sign-in would be misleading.
        if !session.is_signed_in() {
            self.vaults = None;
        }
    }
}

/// A successful sign-in: the authenticated client plus the listing fetched in
/// the same round trip.
#[derive(Debug, Clone)]
pub struct SignInResult {
    pub client: Arc<ServerClient>,
    pub email: String,
    pub vaults: Vec<RemoteVault>,
}

#[derive(Debug, Clone)]
pub enum Msg {
    SourcePicked(Step),
    Back,
    Cancel,
    Confirm,
    RecentPicked(usize),
    /// The Open direction's native file dialog closed.
    Browse,
    FilePicked(Option<PathBuf>),
    /// The Save direction's native save dialog closed.
    SaveFilePicked(Option<PathBuf>),
    /// A browser sign-in landed and brought the account's vaults with it.
    /// Sent by [`crate::link`], which may have been driven from another pane.
    AdoptListing(Vec<RemoteVault>),
    SignOut,
    Refresh,
    Listed(Result<Vec<RemoteVault>, VaultError>),
    ServerVaultPicked(usize),
    VaultNameChanged(String),
    /// A vault finished downloading (or failed to).
    Opened(Box<Result<VaultHandle, VaultError>>),
}

pub fn update(state: &mut State, session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::SourcePicked(step) => {
            state.error = None;
            // Saving to a local file needs nothing the system dialog does not
            // already ask for, so the wizard has no file step in that
            // direction: picking the source *is* the dialog.
            if step == Step::File && state.purpose.is_save() {
                return Action::Run(save_dialog(&state.file_name));
            }
            state.step = step;
            if step == Step::Server {
                // A sign-in to some *other* server is worse than none: saving
                // would sync the vault to a server the settings no longer name.
                // Checked here rather than when the address is edited, because
                // the settings pane saves on every keystroke and would sign the
                // user out mid-word.
                let elsewhere = session
                    .server_client
                    .as_ref()
                    .is_some_and(|client| client.base_url() != session.settings.server_url());
                if elsewhere {
                    session.sign_out();
                    state.vaults = None;
                }
                // Every entry refetches, rather than only the first one: this
                // app saves to the account, other devices do too, and a cached
                // listing would hide both — from the open direction as a
                // missing row, and from the save direction as a missing (or
                // false) "will be replaced" warning. The previous rows stay on
                // screen while the request runs, so there is no flicker, and
                // the index they were picked by may not survive it.
                state.picked_vault = None;
                if session.is_signed_in() {
                    return list_vaults(state, session);
                }
            }
            Action::None
        }
        Msg::Back => {
            state.error = None;
            state.step = Step::PickSource;
            Action::None
        }
        Msg::Cancel => Action::Run(Task::done(Message::ReturnToDefaultPane)),
        Msg::Confirm => {
            state.error = None;
            confirm(state, session)
        }
        // A recent vault is a destination, not a setting: clicking one opens it
        // straight away rather than arming a confirm button.
        Msg::RecentPicked(index) => {
            state.error = None;
            let Some(location) = session.settings.recent_vaults.get(index).cloned() else {
                return Action::None;
            };
            state.picked_recent = Some(index);
            open_location(state, session, location)
        }
        Msg::Browse => Action::Run(Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                    .map(|handle| handle.path().to_path_buf())
            },
            |picked| Message::Wizard(Msg::FilePicked(picked)),
        )),
        Msg::FilePicked(Some(path)) => {
            open_location(state, session, VaultLocation::LocalFile(path))
        }
        Msg::FilePicked(None) => Action::None,
        Msg::SaveFilePicked(Some(path)) => {
            // The shell owns the save task, because it also owns what happens
            // after one (the pending lock/close/exit).
            Action::Run(Task::done(Message::SaveTo(VaultLocation::LocalFile(path))))
        }
        Msg::SaveFilePicked(None) => Action::None,
        Msg::AdoptListing(vaults) => {
            state.error = None;
            state.vaults = Some(vaults);
            Action::None
        }
        Msg::SignOut => {
            session.sign_out();
            state.vaults = None;
            state.picked_vault = None;
            session.status_message = Some("Signed out".into());
            Action::None
        }
        Msg::Refresh => list_vaults(state, session),
        Msg::Listed(result) => {
            state.listing = false;
            session.finish_work();
            match result {
                Ok(vaults) => {
                    state.vaults = Some(vaults);
                    Action::None
                }
                Err(error) => {
                    state.error = Some(describe_sign_in_error(&error));
                    Action::None
                }
            }
        }
        // Like a recent file, a server vault is a destination rather than a
        // setting: clicking one downloads it instead of arming a confirm
        // button. Only the save direction still has something to confirm, and
        // it shows a name field rather than this list.
        Msg::ServerVaultPicked(index) => {
            state.error = None;
            let Some(client) = session.server_client.clone() else {
                state.error = Some("Sign in first.".to_string());
                return Action::None;
            };
            let Some(vault) = state
                .vaults
                .as_ref()
                .and_then(|vaults| vaults.get(index))
                .cloned()
            else {
                return Action::None;
            };
            state.picked_vault = Some(index);
            download(state, session, client, vault)
        }
        Msg::VaultNameChanged(value) => {
            state.vault_name = value;
            Action::None
        }
        Msg::Opened(result) => {
            session.finish_work();
            match *result {
                Ok(handle) => {
                    let name = handle.location.display_name();
                    session.open_vault(handle.location, handle.storage, handle.file);
                    session.status_message = Some(format!("Opened {name}"));
                    Action::Run(Task::done(Message::Vault(crate::VaultMsg::Unlock)))
                }
                Err(error) => {
                    state.error = Some(describe_open_error(&error));
                    Action::None
                }
            }
        }
    }
}

fn confirm(state: &mut State, session: &mut Session) -> Action {
    match state.step {
        // The cloud card is a reserved slot; it can never confirm. Neither can
        // the file step: saving never lands there (the source card opens the
        // dialog), and opening acts on the click — a recent row or `Browse…` —
        // so it carries no confirm button.
        Step::PickSource | Step::Cloud | Step::File => Action::None,
        // Opening acts on the click too: picking a vault row downloads it, so
        // only the save direction reaches here.
        Step::Server if !state.purpose.is_save() => Action::None,
        Step::Server => {
            let Some(client) = session.server_client.clone() else {
                state.error = Some("Sign in first.".to_string());
                return Action::None;
            };

            let name = state.vault_name.trim();
            if name.is_empty() {
                state.error = Some("Enter a name for the vault.".to_string());
                return Action::None;
            }
            // Addressed by *name*: saving over an existing one replaces it,
            // which is what the collision warning below is about.
            Action::Run(Task::done(Message::SaveTo(VaultLocation::Server {
                base_url: client.base_url().to_string(),
                email: session.server_email.clone().unwrap_or_default(),
                name: name.to_string(),
            })))
        }
    }
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// The native save dialog, prefilled with the vault's current name. It asks for
/// the folder and the file name in one step, which is why the wizard asks for
/// neither.
fn save_dialog(suggested: &str) -> Task<Message> {
    let name = suggested.trim();
    let name = if name.is_empty() {
        "MyVault.askrypt".to_string()
    } else {
        name.to_string()
    };

    Task::perform(
        async move {
            rfd::AsyncFileDialog::new()
                .add_filter("Askrypt Files", &["askrypt"])
                .add_filter("All files", &["*"])
                .set_file_name(name)
                .save_file()
                .await
                .map(|handle| handle.path().to_path_buf())
        },
        |picked| Message::Wizard(Msg::SaveFilePicked(picked)),
    )
}

/// Read a local vault off the main thread. Not a key derivation, but still a
/// file read and a ZIP parse — and for a server location, a download.
fn open_location(state: &mut State, session: &mut Session, location: VaultLocation) -> Action {
    if session.busy {
        return Action::None;
    }

    let storage = match session.storage_for(&location) {
        Ok(storage) => storage,
        Err(e) => {
            state.error = Some(describe_open_error(&VaultError::log(
                "Failed to reach the vault",
                &e,
            )));
            return Action::None;
        }
    };

    session.begin_work("Opening…");
    Action::Run(load_task(location, storage))
}

/// Download a server vault through the instance pre-seeded with its id and
/// ETag, so opening costs one request and the ETag is the one we then write
/// against.
fn download(
    state: &mut State,
    session: &mut Session,
    client: Arc<ServerClient>,
    vault: RemoteVault,
) -> Action {
    if session.busy {
        return Action::None;
    }
    let _ = state;

    let location = VaultLocation::Server {
        base_url: client.base_url().to_string(),
        email: session.server_email.clone().unwrap_or_default(),
        name: vault.name.clone(),
    };
    let storage: Arc<dyn VaultStorage> = Arc::new(ServerStorage::existing(client, &vault));

    session.begin_work("Downloading…");
    Action::Run(load_task(location, storage))
}

fn load_task(location: VaultLocation, storage: Arc<dyn VaultStorage>) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                storage
                    .load_vault()
                    .map(|file| VaultHandle {
                        file,
                        location,
                        storage: Arc::clone(&storage),
                    })
                    .map_err(|e| VaultError::log("Failed to open vault", &e))
            })
            .await
            .expect("load vault task panicked")
        },
        |result| Message::Wizard(Msg::Opened(Box::new(result))),
    )
}

fn list_vaults(state: &mut State, session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }
    let Some(client) = session.server_client.clone() else {
        state.error = Some("Not signed in to a server.".to_string());
        return Action::None;
    };

    state.listing = true;
    session.begin_work("Loading…");
    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                client
                    .list()
                    .map_err(|e| VaultError::log("Failed to list vaults", &e))
            })
            .await
            .expect("list vaults task panicked")
        },
        |result| Message::Wizard(Msg::Listed(result)),
    ))
}

/// What the typed save name means against the account's current listing.
///
/// The absence of a collision is not the same as a free name: with no listing to
/// check against, nothing is known, and a pane that only speaks up on a
/// collision reports "unknown" and "free" as the same silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameStatus {
    /// Nothing typed yet, so there is nothing to say.
    Empty,
    /// A first listing is in flight.
    Checking,
    /// No listing at all: never fetched, or the fetch failed.
    Unknown,
    /// No vault carries this name; saving creates one.
    Free,
    /// Index into `State::vaults` of the vault this name would replace.
    Replaces(usize),
}

/// [`NameStatus`] for what is currently typed. Pure, so the rule is tested
/// rather than inferred from the rendering.
///
/// A *refresh* over an existing listing keeps answering off the rows already
/// held — those stay on screen while the request runs, and going blank on every
/// refresh would be a worse lie than a listing a few seconds old.
fn name_status(state: &State) -> NameStatus {
    let typed = state.vault_name.trim();
    if typed.is_empty() {
        return NameStatus::Empty;
    }

    let Some(vaults) = state.vaults.as_deref() else {
        return if state.listing {
            NameStatus::Checking
        } else {
            NameStatus::Unknown
        };
    };

    // Case-insensitive on purpose, though the server's uniqueness is byte-exact
    // (`UNIQUE (account_id, name)`, no `COLLATE NOCASE`, and `ServerStorage`
    // resolves by `==`). So a case-only difference warns about a replacement
    // that would in fact be a second vault; the listing below names the row it
    // matched, which is what makes that visible.
    vaults
        .iter()
        .position(|vault| vault.name.eq_ignore_ascii_case(typed))
        .map_or(NameStatus::Free, NameStatus::Replaces)
}

/// Human-readable byte size for the vault listing.
fn human_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let bytes = bytes as f64;
    if bytes < KIB {
        format!("{} B", bytes as u64)
    } else if bytes < KIB * KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{:.1} MiB", bytes / (KIB * KIB))
    }
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.wizard;
    let session = &app.session;

    let mut body = column![
        text(state.purpose.caption())
            .size(11)
            .style(text::secondary),
    ]
    .spacing(12)
    .padding(20)
    .max_width(620)
    .width(Length::Fill);

    body = match state.step {
        Step::PickSource => body
            .push(text(state.purpose.heading()).size(20).font(theme::bold()))
            .push(pick_source(state)),
        Step::File => body
            .push(text("Local file").size(20).font(theme::bold()))
            .push(file_step(state, session)),
        Step::Server => body
            .push(text("Askrypt Server").size(20).font(theme::bold()))
            .push(server_step(state, session)),
        Step::Cloud => body
            .push(text("Cloud folder").size(20).font(theme::bold()))
            .push(theme::card(
                container(
                    text("Syncing through Dropbox or Google Drive is not implemented.")
                        .size(13)
                        .style(text::secondary),
                )
                .padding(14),
            )),
    };

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    body = body.push(footer(state, session));

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn pick_source(state: &State) -> Element<'_, Message> {
    let (file_copy, server_copy) = if state.purpose.is_save() {
        (
            "Write the vault to a file on this computer.",
            "Upload the vault to your account.",
        )
    } else {
        (
            "Open a .askrypt file on this computer.",
            "Sign in and pick one of your cloud vaults.",
        )
    };

    column![
        source_card(
            icon::file_earmark_lock(18),
            "Local file",
            file_copy,
            Some(Msg::SourcePicked(Step::File)),
        ),
        source_card(
            icon::server(18),
            "Askrypt Server",
            server_copy,
            Some(Msg::SourcePicked(Step::Server)),
        ),
        // No `on_press`: the row is a reserved slot in the layout, not an
        // option. It fades rather than disappearing so the shape is visible.
        source_card(
            icon::cloud(18),
            "Cloud folder",
            "Dropbox, Google Drive, … — not available yet.",
            None,
        ),
    ]
    .spacing(10)
    .into()
}

fn source_card<'a>(
    glyph: iced::widget::Text<'a>,
    title: &'a str,
    description: &'a str,
    message: Option<Msg>,
) -> Element<'a, Message> {
    button(
        row![
            glyph,
            column![
                text(title).size(15).font(theme::bold()),
                text(description).size(12).style(text::secondary),
            ]
            .spacing(3)
            .width(Length::Fill),
            icon::chevron_right(12),
        ]
        .spacing(12)
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding(14)
    .style(theme::wizard_card)
    .on_press_maybe(message.map(Message::Wizard))
    .into()
}

fn file_step<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    // The MRU mixes both kinds of home, but this is the *local file* step —
    // a server vault listed here would open over a backend the step does not
    // offer. The enumeration runs before the filter, so each row keeps the
    // index into `recent_vaults` that `Msg::RecentPicked` looks up.
    let recent: Vec<(usize, &VaultLocation)> = session
        .settings
        .recent_vaults
        .iter()
        .enumerate()
        .filter(|(_, location)| matches!(location, VaultLocation::LocalFile(_)))
        .collect();
    let mut column = column![].spacing(10);

    if recent.is_empty() {
        column = column.push(
            text("No vaults opened yet — browse for one.")
                .size(12)
                .style(text::secondary),
        );
    } else {
        let mut rows = iced::widget::column![].width(Length::Fill);
        for (position, (index, location)) in recent.into_iter().enumerate() {
            if position > 0 {
                rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
            }
            rows = rows.push(picker_row(
                location.display_name(),
                location.display_location(),
                state.picked_recent == Some(index),
                icon::chevron_right(12).into(),
                Message::Wizard(Msg::RecentPicked(index)),
            ));
        }
        column = column
            .push(text("RECENT VAULTS").size(11).style(text::secondary))
            .push(theme::card(rows));
    }

    column
        .push(
            button(
                row![icon::folder2_open(14), text("Browse…").size(14)]
                    .spacing(8)
                    .align_y(Vertical::Center),
            )
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::Wizard(Msg::Browse)),
        )
        .into()
}

/// One clickable row — a recent file or a server vault. Reuses the item list's
/// row styling so a pick reads the same way everywhere. Both kinds open on the
/// click, so both point ahead with a chevron like the source cards do; the
/// `selected` highlight only marks the row whose open is under way.
fn picker_row<'a>(
    title: String,
    subtitle: String,
    selected: bool,
    mark: Element<'a, Message>,
    message: Message,
) -> Element<'a, Message> {
    button(
        row![
            column![
                text(title).size(14).font(theme::bold()),
                text(subtitle).size(12).style(text::secondary),
            ]
            .spacing(2)
            .width(Length::Fill),
            mark,
        ]
        .spacing(10)
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding([10, 14])
    .style(move |t, s| theme::list_row(t, s, selected))
    .on_press(message)
    .into()
}

/// One read-only listing row. The save direction shows what the account already
/// holds without offering it as a choice, so unlike [`picker_row`] this is a
/// container rather than a button and carries no chevron.
///
/// Two timestamps, deliberately: the first line is when the *server* stored the
/// bytes, the second is what the file says about itself (`params.host` /
/// `params.updated_at`, the two fields the vault format leaves unencrypted). A
/// restore, or an upload of an older file from another device, moves one and not
/// the other.
fn info_row<'a>(vault: &RemoteVault, replaced: bool) -> Element<'a, Message> {
    let mut heading = row![
        text(vault.name.clone())
            .size(14)
            .font(theme::bold())
            .width(Length::Fill),
    ]
    .spacing(10)
    .align_y(Vertical::Center);

    if replaced {
        heading = heading.push(text("WILL BE REPLACED").size(11).style(text::danger));
    }

    let mut lines = column![
        heading,
        text(format!(
            "{} · {}",
            human_size(vault.size),
            data::format_rfc3339_local(&vault.updated_at)
        ))
        .size(12)
        .style(text::secondary),
    ]
    .spacing(2)
    .width(Length::Fill);

    if let Some(stamp) = data::format_stamp(vault.host.as_deref(), vault.saved_at.as_deref()) {
        lines = lines.push(
            text(format!("Last saved: {stamp}"))
                .size(11)
                .style(text::secondary),
        );
    }

    container(lines)
        .padding([10, 14])
        .width(Length::Fill)
        .into()
}

fn server_step<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    if !session.is_signed_in() {
        // Waiting on the browser: one card, shared with the Settings pane.
        if let Some(link) = &session.link {
            return crate::link::waiting_card(link);
        }

        let server = session.settings.server_url();
        let server = if server.is_empty() {
            "no server set".to_string()
        } else {
            server
        };

        return theme::card(
            container(
                column![
                    text("Sign in to save and open vaults on your account.").size(14),
                    // No password field, on purpose: signing in — and signing
                    // *up* — happens on the server's own pages, so this app
                    // never handles an account password.
                    text(format!(
                        "Your browser opens {server}, where you can sign in or \
                         create an account."
                    ))
                    .size(12)
                    .style(text::secondary),
                    crate::link::sign_in_button("Sign in with your browser"),
                    text("Change the server in Settings.")
                        .size(11)
                        .style(text::secondary),
                ]
                .spacing(8),
            )
            .padding(14),
        )
        .into();
    }

    let account = row![
        text(format!(
            "Signed in as {}",
            session.server_email.clone().unwrap_or_default()
        ))
        .size(12)
        .style(text::secondary)
        .width(Length::Fill),
        theme::button_link("Refresh", "Fetch the vault list again", None)
            .on_press(Message::Wizard(Msg::Refresh)),
        theme::button_link("Sign out", "Forget this sign-in", None)
            .on_press(Message::Wizard(Msg::SignOut)),
    ]
    .spacing(12)
    .align_y(Vertical::Center);

    if state.purpose.is_save() {
        let status = name_status(state);

        let mut fields = column![
            text("Vault name").size(13),
            text_input("MyVault", &state.vault_name)
                .on_input(|value| Message::Wizard(Msg::VaultNameChanged(value)))
                .on_submit(Message::Wizard(Msg::Confirm))
                .padding(8)
                .size(14),
        ]
        .spacing(8);

        // A server vault is addressed by name, so an existing one is replaced in
        // place rather than duplicated. Every state says something: silence here
        // would read as "the name is free" even when nothing has been checked.
        match status {
            NameStatus::Empty => {}
            NameStatus::Replaces(_) => {
                fields = fields.push(
                    text("A vault with this name already exists and will be replaced.")
                        .size(12)
                        .style(text::danger),
                );
            }
            NameStatus::Checking => {
                fields = fields.push(
                    text("Checking your vaults…")
                        .size(12)
                        .style(text::secondary),
                );
            }
            NameStatus::Unknown => {
                fields = fields.push(
                    text(
                        "Could not check this account's vaults — a vault with this name \
                         may be replaced.",
                    )
                    .size(12)
                    .style(text::danger),
                );
            }
            NameStatus::Free => {
                fields = fields.push(
                    text("This will create a new vault on the server.")
                        .size(12)
                        .style(text::secondary),
                );
            }
        }

        let name_card = theme::card(container(fields).padding(14));

        // The read-only listing: what is on the account, so "will be replaced"
        // names something the user can actually see.
        let listed = state.vaults.as_deref().unwrap_or_default();
        if listed.is_empty() {
            let caption = match (state.vaults.is_none(), state.listing) {
                (true, true) => "Loading your vaults…",
                (true, false) => "Could not load your vaults.",
                _ => "No vaults on this account yet.",
            };
            return column![
                account,
                name_card,
                text(caption).size(12).style(text::secondary)
            ]
            .spacing(10)
            .into();
        }

        let replaced = match status {
            NameStatus::Replaces(index) => Some(index),
            _ => None,
        };

        let mut rows = iced::widget::column![].width(Length::Fill);
        for (index, vault) in listed.iter().enumerate() {
            if index > 0 {
                rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
            }
            rows = rows.push(info_row(vault, replaced == Some(index)));
        }

        return column![
            account,
            name_card,
            text("YOUR VAULTS ON THE SERVER")
                .size(11)
                .style(text::secondary),
            theme::card(rows),
        ]
        .spacing(10)
        .into();
    }

    let listed = state.vaults.as_deref().unwrap_or_default();
    if listed.is_empty() {
        // Entering the step always starts a listing, so an account with no
        // listing *yet* must not be reported as an account with no vaults.
        let caption = if state.vaults.is_none() && state.listing {
            "Loading your vaults…"
        } else {
            "No vaults on this account yet."
        };
        return column![account, text(caption).size(12).style(text::secondary)]
            .spacing(10)
            .into();
    }

    let mut rows = iced::widget::column![].width(Length::Fill);
    for (index, vault) in listed.iter().enumerate() {
        if index > 0 {
            rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
        }
        // The writing machine when the file records one, so both directions of
        // the wizard identify the device a vault last came from.
        let mut subtitle = format!(
            "{} · {}",
            human_size(vault.size),
            data::format_rfc3339_local(&vault.updated_at)
        );
        if let Some(host) = &vault.host {
            subtitle.push_str(" · ");
            subtitle.push_str(host);
        }

        rows = rows.push(picker_row(
            vault.name.clone(),
            subtitle,
            state.picked_vault == Some(index),
            icon::chevron_right(12).into(),
            Message::Wizard(Msg::ServerVaultPicked(index)),
        ));
    }

    column![
        account,
        text("YOUR VAULTS").size(11).style(text::secondary),
        theme::card(rows),
    ]
    .spacing(10)
    .into()
}

fn footer<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    // While a sign-in, listing or download is running the controls give way to
    // the spinner, so the same request cannot be fired twice.
    if session.busy {
        return theme::spinner_row(session.spinner_frame, session.spinner_label).into();
    }

    let mut buttons = row![].spacing(10);

    if state.step != Step::PickSource {
        buttons = buttons.push(
            button(
                row![icon::arrow_left(12), text("Back").size(14)]
                    .spacing(8)
                    .align_y(Vertical::Center),
            )
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::Wizard(Msg::Back)),
        );
    }

    buttons = buttons.push(
        button(text("Cancel").size(14))
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::Wizard(Msg::Cancel)),
    );

    // Naming a server vault to save to is the only thing left to confirm;
    // every open acts on the click (a recent vault, a listed vault, or the
    // native dialog).
    if state.step == Step::Server && state.purpose.is_save() {
        buttons = buttons.push(
            button(text("Save").size(14))
                .padding([8, 16])
                .on_press(Message::Wizard(Msg::Confirm)),
        );
    }

    buttons.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }

    fn remote(name: &str) -> RemoteVault {
        RemoteVault {
            id: format!("id-{name}"),
            name: name.to_string(),
            size: 42,
            etag: "aaaa".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: Some("ubuntu@mypc".to_string()),
            saved_at: Some("2026-08-07T09:59:00Z".to_string()),
        }
    }

    fn armed(typed: &str, vaults: Listing, listing: bool) -> State {
        State {
            purpose: Purpose::SaveAs,
            vault_name: typed.to_string(),
            vaults,
            listing,
            ..State::default()
        }
    }

    #[test]
    fn an_empty_name_says_nothing() {
        let state = armed("   ", Some(vec![remote("Work")]), false);
        assert_eq!(name_status(&state), NameStatus::Empty);
    }

    #[test]
    fn a_listing_in_flight_reads_as_checking_not_as_free() {
        let state = armed("Work", None, true);
        assert_eq!(name_status(&state), NameStatus::Checking);
    }

    #[test]
    fn no_listing_and_nothing_in_flight_is_unknown() {
        // The case the old code rendered as silence, which was indistinguishable
        // from a name it had actually checked and found free.
        let state = armed("Work", None, false);
        assert_eq!(name_status(&state), NameStatus::Unknown);
    }

    #[test]
    fn an_unused_name_is_free() {
        let state = armed("Backup", Some(vec![remote("Work")]), false);
        assert_eq!(name_status(&state), NameStatus::Free);
    }

    #[test]
    fn a_taken_name_names_the_row_it_would_replace() {
        let state = armed(
            " Personal ",
            Some(vec![remote("Work"), remote("Personal")]),
            false,
        );
        assert_eq!(name_status(&state), NameStatus::Replaces(1));
    }

    #[test]
    fn a_case_only_difference_still_reads_as_a_replacement() {
        // Pinned as a decision, not an accident: the server's uniqueness is
        // byte-exact, so this save would in fact create a second vault. The
        // marked row spells the existing name out next to what was typed.
        let state = armed("work", Some(vec![remote("Work")]), false);
        assert_eq!(name_status(&state), NameStatus::Replaces(0));
    }

    #[test]
    fn a_refresh_answers_off_the_rows_already_held() {
        // `listing` is true while a re-fetch runs, but the previous rows are
        // still on screen and still the best answer available.
        let state = armed("Work", Some(vec![remote("Work")]), true);
        assert_eq!(name_status(&state), NameStatus::Replaces(0));
    }
}
