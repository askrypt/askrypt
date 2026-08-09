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
use zeroize::Zeroize;

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

/// The account's vaults, fetched once per sign-in and refreshed on demand.
/// `None` means "not listed yet", which is what shows the empty server step.
type Listing = Option<Vec<RemoteVault>>;

pub struct State {
    purpose: Purpose,
    step: Step,
    error: Option<String>,

    // File step.
    file_name: String,
    picked_recent: Option<usize>,

    // Server step. Whether the user is *signed in* is not kept here — that lives
    // on the session and deliberately outlives any one run of the wizard.
    base_url: String,
    email: String,
    password: String,
    vaults: Listing,
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
            base_url: "https://".to_string(),
            email: String::new(),
            password: String::new(),
            vaults: None,
            vault_name: String::new(),
            picked_vault: None,
        }
    }
}

/// The typed password never needs to outlive the sign-in it is for.
impl Drop for State {
    fn drop(&mut self) {
        self.password.zeroize();
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
        self.password.zeroize();
        self.password.clear();
        self.file_name = if name.ends_with(".askrypt") {
            name.clone()
        } else {
            format!("{name}.askrypt")
        };
        self.vault_name = name.trim_end_matches(".askrypt").to_string();

        if let Some(email) = &session.server_email {
            self.email = email.clone();
        }
        if let Some(client) = &session.server_client {
            self.base_url = client.base_url().to_string();
        }
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
    BaseUrlChanged(String),
    EmailChanged(String),
    PasswordChanged(String),
    SignIn,
    SignedIn(Box<Result<SignInResult, VaultError>>),
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
            // Entering the server step while already signed in should show the
            // account's vaults, not an empty list.
            if step == Step::Server && session.is_signed_in() && state.vaults.is_none() {
                return list_vaults(state, session);
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
        Msg::BaseUrlChanged(value) => {
            state.base_url = value;
            Action::None
        }
        Msg::EmailChanged(value) => {
            state.email = value;
            Action::None
        }
        Msg::PasswordChanged(value) => {
            state.password.zeroize();
            state.password = value;
            Action::None
        }
        Msg::SignIn => sign_in(state, session),
        Msg::SignedIn(result) => {
            session.finish_work();
            match *result {
                Ok(signed_in) => {
                    state.password.zeroize();
                    state.password.clear();
                    state.vaults = Some(signed_in.vaults);
                    let email = signed_in.email.clone();
                    session.sign_in(signed_in.client, &email);
                    session.status_message = Some(format!("Signed in as {email}"));
                    Action::None
                }
                Err(error) => {
                    state.error = Some(describe_sign_in_error(&error));
                    Action::None
                }
            }
        }
        Msg::SignOut => {
            session.sign_out();
            state.vaults = None;
            state.picked_vault = None;
            state.password.zeroize();
            state.password.clear();
            session.status_message = Some("Signed out".into());
            Action::None
        }
        Msg::Refresh => list_vaults(state, session),
        Msg::Listed(result) => {
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

/// Sign in and list in one round trip, the way `src/screens/server.rs` does.
fn sign_in(state: &mut State, session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }
    if state.base_url.trim().is_empty() || state.email.trim().is_empty() {
        state.error = Some("Enter a server address and an email.".to_string());
        return Action::None;
    }
    if state.password.is_empty() {
        state.error = Some("Enter your password.".to_string());
        return Action::None;
    }

    let base_url = state.base_url.trim().to_string();
    let email = state.email.trim().to_string();
    let password = state.password.clone();

    session.begin_work("Signing in…");
    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let client =
                    ServerClient::login(&base_url, &email, &password, Some("Askrypt desktop"))
                        .map_err(|e| VaultError::log("Failed to sign in", &e))?;
                let client = Arc::new(client);
                let vaults = client
                    .list()
                    .map_err(|e| VaultError::log("Failed to list vaults", &e))?;
                Ok::<_, VaultError>(SignInResult {
                    client,
                    email,
                    vaults,
                })
            })
            .await
            .expect("sign in task panicked")
        },
        |result| Message::Wizard(Msg::SignedIn(Box::new(result))),
    ))
}

fn list_vaults(state: &mut State, session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }
    let Some(client) = session.server_client.clone() else {
        state.error = Some("Not signed in to a server.".to_string());
        return Action::None;
    };

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
    let recent = &session.settings.recent_vaults;
    let mut column = column![].spacing(10);

    if recent.is_empty() {
        column = column.push(
            text("No vaults opened yet — browse for one.")
                .size(12)
                .style(text::secondary),
        );
    } else {
        let mut rows = iced::widget::column![].width(Length::Fill);
        for (index, location) in recent.iter().enumerate() {
            if index > 0 {
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

fn server_step<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    if !session.is_signed_in() {
        return theme::card(
            container(
                column![
                    text("Server address").size(13),
                    text_input("https://askrypt.example.com", &state.base_url)
                        .on_input(|value| Message::Wizard(Msg::BaseUrlChanged(value)))
                        .padding(8)
                        .size(14),
                    text("Email").size(13),
                    text_input("me@example.com", &state.email)
                        .on_input(|value| Message::Wizard(Msg::EmailChanged(value)))
                        .padding(8)
                        .size(14),
                    text("Password").size(13),
                    text_input("", &state.password)
                        .on_input(|value| Message::Wizard(Msg::PasswordChanged(value)))
                        .on_submit(Message::Wizard(Msg::SignIn))
                        .secure(true)
                        .padding(8)
                        .size(14),
                    button(text("Sign in").size(14))
                        .padding([8, 16])
                        .on_press(Message::Wizard(Msg::SignIn)),
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
        let typed = state.vault_name.trim();
        let collides = state.vaults.as_ref().is_some_and(|vaults| {
            vaults
                .iter()
                .any(|vault| vault.name.eq_ignore_ascii_case(typed))
        });

        let mut fields = column![
            text("Vault name").size(13),
            text_input("MyVault", &state.vault_name)
                .on_input(|value| Message::Wizard(Msg::VaultNameChanged(value)))
                .on_submit(Message::Wizard(Msg::Confirm))
                .padding(8)
                .size(14),
        ]
        .spacing(8);

        // A server vault is addressed by name, so an existing one is replaced
        // in place rather than duplicated.
        if collides {
            fields = fields.push(
                text("A vault with this name already exists and will be replaced.")
                    .size(12)
                    .style(text::danger),
            );
        }

        return column![account, theme::card(container(fields).padding(14))]
            .spacing(10)
            .into();
    }

    let listed = state.vaults.as_deref().unwrap_or_default();
    if listed.is_empty() {
        return column![
            account,
            text("No vaults on this account yet.")
                .size(12)
                .style(text::secondary),
        ]
        .spacing(10)
        .into();
    }

    let mut rows = iced::widget::column![].width(Length::Fill);
    for (index, vault) in listed.iter().enumerate() {
        if index > 0 {
            rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
        }
        rows = rows.push(picker_row(
            vault.name.clone(),
            format!(
                "{} · {}",
                human_size(vault.size),
                data::format_rfc3339_local(&vault.updated_at)
            ),
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
}
